//! This module is shared by sunnyquic and shadowquic
//! It handles the general tcp/udp proxying logic over quic connection
//! It contains an optional authentication feature for sunnyquic only

use std::{
    collections::{
        HashMap,
        hash_map::{self, Entry},
    },
    io::Cursor,
    mem::replace,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{
        Mutex, RwLock, SetOnce,
        watch::{Receiver, Sender, channel},
    },
};
use tracing::{Instrument, Level, debug, error, event, info, trace, warn};

use crate::{
    AnyUdpRecv, AnyUdpSend, UdpSend, UdpSendExt,
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        socks5::SocksAddr,
        squic::{ConnStats, SQPacketDatagramHeader, SQReq, SQUdpControlHeader, SunnyCredential},
    },
    quic::QuicConnection,
};

pub(crate) mod early;
pub mod inbound;
pub mod outbound;
#[cfg(all(test, feature = "shadowquic-quinn"))]
mod udp_send_tests;
mod uni_pool;

#[cfg(test)]
mod udp_recv_tests;
#[cfg(test)]
mod udp_robustness_tests;

/// SQuic connection, it is shared by shadowquic and sunnyquic and is a wrapper of quic connection.
/// It contains a connection object and two ID store for managing UDP sockets.
/// The IDStore stores the mapping between ids and the destionation addresses as well as associated sockets
#[derive(Clone)]
pub struct SQConn<T: QuicConnection>(Arc<SQConnInner<T>>);

pub struct SQConnInner<T: QuicConnection> {
    pub(crate) conn: T,
    pub authed: SetOnce<SResult<String>>,
    pub(crate) send_id_store: IDStore<()>,
    pub(crate) recv_id_store: IDStore<(AnyUdpSend, SocksAddr)>,
    /// The streams udp over stream is sent on.
    uni_pool: uni_pool::UniPool<T::SendStream>,
    /// Latest successful peer stats response and the time it was received.
    pub stats: Mutex<Option<SQConnStats>>,
    /// Serialize remote refreshes without blocking readers of the cached sample.
    pub(crate) stats_refresh: Mutex<()>,
    /// Instant the connection established.
    pub birth_time: Instant,
}

impl<T: QuicConnection> SQConn<T> {
    pub(crate) fn new(conn: T, authed: SetOnce<SResult<String>>) -> SQConn<T> {
        SQConn(Arc::new(SQConnInner {
            conn,
            authed,
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
                pending_packets: Default::default(),
            },
            uni_pool: Default::default(),
            stats: Default::default(),
            stats_refresh: Default::default(),
            birth_time: Instant::now(),
        }))
    }
}

impl<T: QuicConnection> Deref for SQConn<T> {
    type Target = SQConnInner<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: QuicConnection> Deref for SQConnInner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

#[derive(Clone)]
pub struct SQConnStats {
    pub uplink: ConnStats,
    pub downlink: ConnStats,
    pub time: Instant,
    pub birth_time: Instant,
}

async fn wait_sunny_auth<T: QuicConnection>(conn: &SQConn<T>) -> SResult<String> {
    match tokio::time::timeout(Duration::from_millis(3200), conn.authed.wait()).await {
        Ok(Ok(name)) => Ok(name.clone()),
        Ok(Err(SError::SunnyAuthError(_))) => {
            Err(SError::SunnyAuthError("Wrong password/username".into()))
        }
        Err(_) => Err(SError::SunnyAuthError("timeout".into())),
        _ => unreachable!(),
    }
}

pub(crate) async fn auth_sunny<T: QuicConnection>(
    conn: &SQConn<T>,
    username: &str,
    user_hash: SunnyCredential,
) -> SResult<()> {
    if conn.authed.get().is_none() {
        let request = SQReq::SQAuthenticate(user_hash);
        let (mut send, _recv, _id) = conn.conn.open_bi().await?;
        let early = conn.conn.early_data_outcome(&send);
        let sent = request.encode(&mut send).await;
        // A server that rejects 0-RTT discards the request with the rest of
        // the early data and would never learn who this is: send it again.
        let rejected = match early {
            Some(outcome) if sent.is_err() => outcome.await?,
            Some(outcome) => {
                // Set already when another task authenticated in the meantime.
                let _ = conn.authed.set(Ok(username.to_string()));
                outcome.await?
            }
            None => false,
        };
        if rejected {
            let (mut send, _recv, _id) = conn.conn.open_bi().await?;
            request.encode(&mut send).await?;
        } else {
            sent?;
        }
        debug!(
            event = "security:authentication_request_sent",
            "authentication request sent"
        );
        let _ = conn.authed.set(Ok(username.to_string()));
    }
    Ok(())
}

pub(crate) struct NotifyBuffer {
    pub(crate) notify: Sender<()>,
    pub(crate) buffer: Vec<Bytes>,
    /// When this pending slot was created or last restarted.
    pub(crate) created: tokio::time::Instant,
}

/// A datagram or unistream can overtake the control header that announces its
/// context id, so input for an unknown id is kept for a short time. The peer
/// decides how much of it arrives, so the backlog is bounded: at most
/// `PENDING_MAX_PACKETS` datagrams per connection, none older than `PENDING_TTL`.
const PENDING_MAX_PACKETS: usize = 2048;
const PENDING_TTL: Duration = Duration::from_secs(5);

impl NotifyBuffer {
    fn new(notify: Sender<()>) -> Self {
        Self {
            notify,
            buffer: Vec::new(),
            created: tokio::time::Instant::now(),
        }
    }
    fn expired(&self) -> bool {
        self.created.elapsed() > PENDING_TTL
    }
    /// The backlog to deliver once the id is announced. An expired backlog
    /// belongs to an earlier use of the id and is dropped.
    fn into_fresh_buffer(self) -> (Sender<()>, Vec<Bytes>) {
        let buffer = if self.expired() {
            Vec::new()
        } else {
            self.buffer
        };
        (self.notify, buffer)
    }
}

// Use watch channel here. Notify is not suitable here
// see https://github.com/tokio-rs/tokio/issues/3757
type IDStoreVal<T> = Result<T, NotifyBuffer>;
/// IDStore is a thread-safe store for managing UDP sockets and their associated ids.
/// It uses a HashMap to store the mapping between ids and the destination addresses as well as associated sockets.
/// It also uses an atomic counter to generate unique ids for new sockets.
#[derive(Clone, Default)]
pub(crate) struct IDStore<T = (AnyUdpSend, SocksAddr)> {
    pub(crate) id_counter: Arc<AtomicU16>,
    pub(crate) inner: Arc<RwLock<HashMap<u16, IDStoreVal<T>>>>,
    /// Datagrams held for unannounced ids, see `PENDING_MAX_PACKETS`.
    pending_packets: Arc<AtomicUsize>,
}

impl<T> IDStore<T>
where
    T: Clone,
{
    async fn get_socket_or_notify(&self, id: u16) -> Result<T, Receiver<()>> {
        if let Some(r) = self.inner.read().await.get(&id) {
            r.as_ref().map_err(|x| x.notify.subscribe()).cloned()
        } else {
            // Need to recheck
            // During change from read lock to write lock, hashmap may be modified
            match self.inner.write().await.entry(id) {
                Entry::Occupied(occupied_entry) => occupied_entry
                    .get()
                    .as_ref()
                    .map_err(|x| x.notify.subscribe())
                    .cloned(),
                Entry::Vacant(vacant_entry) => {
                    let (s, r) = channel(());
                    vacant_entry.insert(Err(NotifyBuffer::new(s)));
                    Err(r)
                }
            }
        }
    }
    async fn try_get_socket(&self, id: u16) -> Option<T> {
        if let Some(r) = self.inner.read().await.get(&id) {
            match r {
                Ok(s) => Some(s.clone()),
                Err(_) => None,
            }
        } else {
            None
        }
    }
    async fn get_socket_or_wait(&self, id: u16) -> Result<T, SError> {
        match self.get_socket_or_notify(id).await {
            Ok(r) => Ok(r),
            Err(mut n) => {
                // This may fail is UDP session is closed right at this moment.
                match tokio::time::timeout(PENDING_TTL, n.changed()).await {
                    Ok(changed) => changed.map_err(|_| {
                        SError::UDPSessionClosed("notify sender dropped".to_string())
                    })?,
                    Err(_) => {
                        self.forget_pending(id).await;
                        return Err(SError::UDPSessionClosed(
                            "context id not announced in time".to_string(),
                        ));
                    }
                }
                //
                let ret = self
                    .try_get_socket(id)
                    .await
                    .ok_or(SError::UDPSessionClosed("UDP session closed".to_string()))?;
                Ok(ret)
            }
        }
    }
    /// Drops the slot of an id nobody announced, unless datagrams wait in it.
    async fn forget_pending(&self, id: u16) {
        let mut h = self.inner.write().await;
        if matches!(h.get(&id), Some(Err(n)) if n.buffer.is_empty()) {
            h.remove(&id);
        }
    }
    fn release_pending(&self, packets: usize) {
        let _ = self
            .pending_packets
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(packets))
            });
    }
    #[allow(dead_code)]
    async fn store_socket(&self, id: u16, val: T) -> Option<Vec<Bytes>> {
        let mut h = self.inner.write().await;
        trace!(
            event = "squic:receive_socket_count",
            "receiving side alive socket number: {}",
            h.len()
        );
        let r = h.get_mut(&id);
        if let Some(s) = r {
            match s {
                Ok(_) => {
                    error!(
                        event = "squic:context_id_conflict",
                        "id:{} already exists", id
                    );
                }
                Err(_) => {
                    let notify = replace(s, Ok(val));
                    //let _ = notify.map_err(|x| x.notify_one());
                    match notify {
                        Ok(_) => {
                            panic!("should be notify"); // should never happen
                        }
                        Err(n) => {
                            self.release_pending(n.buffer.len());
                            let (notify, buffer) = n.into_fresh_buffer();
                            notify.send(()).unwrap_or_else(|_| {
                                debug!(
                                    event = "squic:context_subscriber_missing",
                                    "id:{} notifier without subscriber", id
                                )
                            });
                            event!(
                                Level::TRACE,
                                event = "squic:context_notified",
                                "notify socket id:{}",
                                id
                            );
                            return Some(buffer);
                        }
                    }
                }
            }
        } else {
            h.insert(id, Ok(val));
        }
        None
    }
    async fn fetch_new_id(&self, val: T) -> SResult<u16> {
        let mut inner = self.inner.write().await;
        // Every id is taken: searching for a free one would never end.
        if inner.len() > u16::MAX as usize {
            return Err(SError::UDPSessionClosed(
                "all udp context ids of this connection are in use".into(),
            ));
        }
        trace!(
            event = "squic:send_socket_count",
            "sending side socket number: {}",
            inner.len()
        );
        let mut r;
        loop {
            r = self
                .id_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst); // Wrapping occured if overflow
            if let Entry::Vacant(e) = inner.entry(r) {
                e.insert(Ok(val));
                break;
            }
        }
        Ok(r)
    }
}

impl IDStore {
    /// Delivers a datagram to its association. Returns `true` when the id is
    /// not announced yet and the datagram waits in the bounded backlog.
    async fn feed_datagram(&self, id: u16, packet: Bytes) -> SResult<bool> {
        let lock = self.inner.read().await;
        if let Some(Ok((socket, addr))) = lock.get(&id) {
            let (socket, addr) = (socket.clone(), addr.clone());
            drop(lock);
            // Nonblocking sender
            socket.try_send_to(packet, addr.clone()).await?;
            Ok(false)
        } else {
            drop(lock);
            let mut lock = self.inner.write().await;
            // Need to recheck
            // During change from read lock to write lock, hashmap may be modified
            if let Some(Ok((socket, addr))) = lock.get(&id) {
                let (socket, addr) = (socket.clone(), addr.clone());
                drop(lock);
                // Use nonblocking style incase it blocks quic datagram dispatcher.
                socket.try_send_to(packet, addr).await?;
                return Ok(false);
            }
            if let Some(Err(pending)) = lock.get_mut(&id)
                && pending.expired()
            {
                // Left over from an earlier use of this id.
                self.release_pending(pending.buffer.len());
                pending.buffer.clear();
                pending.created = tokio::time::Instant::now();
            }
            if self.pending_packets.load(Ordering::Relaxed) >= PENDING_MAX_PACKETS {
                debug!(
                    event = "squic:datagram_dropped",
                    context_id = id,
                    "backlog for unannounced context ids is full, dropping datagram"
                );
                return Ok(lock.contains_key(&id));
            }
            self.pending_packets.fetch_add(1, Ordering::Relaxed);
            match lock.entry(id) {
                Entry::Occupied(mut entry) => {
                    if let Err(pending) = entry.get_mut() {
                        pending.buffer.push(packet);
                    }
                }
                Entry::Vacant(entry) => {
                    let (s, _r) = channel(());
                    let mut pending = NotifyBuffer::new(s);
                    pending.buffer.push(packet);
                    entry.insert(Err(pending));
                }
            }
            Ok(true)
        }
    }
    /// Frees the slots of unannounced ids that are older than `PENDING_TTL`.
    /// Returns whether younger ones remain.
    async fn purge_expired(&self) -> bool {
        let mut h = self.inner.write().await;
        h.retain(|_, slot| !matches!(slot, Err(n) if n.expired()));
        let mut packets = 0;
        let mut pending = false;
        for slot in h.values() {
            if let Err(n) = slot {
                pending = true;
                packets += n.buffer.len();
            }
        }
        self.pending_packets.store(packets, Ordering::Relaxed);
        pending
    }
    async fn store_socket_with_prelude(
        &self,
        id: u16,
        val: (Arc<dyn UdpSend>, SocksAddr),
    ) -> SResult<()> {
        let mut h = self.inner.write().await;
        trace!(
            event = "squic:receive_socket_count",
            "receiving side alive socket number: {}",
            h.len()
        );
        let r = h.get_mut(&id);
        if let Some(s) = r {
            match s {
                Ok(_) => {
                    error!(
                        event = "squic:context_id_conflict",
                        "id:{} already exists", id
                    );
                }
                Err(_) => {
                    let (socket, addr) = val.clone();
                    let notify = replace(s, Ok(val));
                    // Do not drop here, socket may be release
                    // too early and udp packet order may be changed
                    // drop(h);
                    //let _ = notify.map_err(|x| x.notify_one());
                    match notify {
                        Ok(_) => {
                            panic!("should be notify"); // should never happen
                        }
                        Err(n) => {
                            self.release_pending(n.buffer.len());
                            let (notify, buffer) = n.into_fresh_buffer();
                            for bytes in buffer {
                                socket.send_to(bytes, addr.clone()).await?;
                            }

                            notify.send(()).unwrap_or_else(|_| {
                                debug!(
                                    event = "squic:context_subscriber_missing",
                                    "id:{} notifier without subscriber", id
                                )
                            });
                            event!(
                                Level::TRACE,
                                event = "squic:context_notified",
                                "notify socket id:{}",
                                id
                            );
                        }
                    }
                }
            }
        } else {
            h.insert(id, Ok(val));
        }
        Ok(())
    }
}

/// AssociateSendSession is a session for sending UDP packets.
/// It is created for each association task
/// The local dst_map works as a inverse map from destination to id
/// When session ended, the ids created by this session will be removed from the IDStore.
struct AssociateSendSession<C: QuicConnection> {
    id_store: IDStore<()>,
    dst_map: HashMap<SocksAddr, u16>,
    conn: SQConn<C>,
    /// Key of this association's streams in the connection's stream pool.
    association: u64,
}
impl<C: QuicConnection> AssociateSendSession<C> {
    pub async fn get_id_or_insert(&mut self, addr: &SocksAddr) -> SResult<(u16, bool)> {
        if let Some(id) = self.dst_map.get(addr) {
            Ok((*id, false))
        } else {
            let id = self.id_store.fetch_new_id(()).await?;
            self.dst_map.insert(addr.clone(), id);
            debug!(event = "squic:send_context_id_created", context_id = id, dst = %addr, "send session insert");
            Ok((id, true))
        }
    }
}

impl<C: QuicConnection> Drop for AssociateSendSession<C> {
    fn drop(&mut self) {
        // Dropping a stream finishes it.
        drop(self.conn.uni_pool.remove_association(self.association));
        let id_store = self.id_store.inner.clone();
        let id_remove = self.dst_map.clone();
        tokio::spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();
                id_remove.values().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    event = "squic:send_context_ids_removed",
                    "AssociateSendSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}
/// AssociateRecvSession is a session for receiving UDP ctrl stream.
/// It is created for each association task
/// There are two usages for id_map
/// First, it works as local cache avoiding using global store repeatedly which is more expensive
/// Second. it records ids created by this session and clean those ids when session ended.
struct AssociateRecvSession {
    id_store: IDStore<(AnyUdpSend, SocksAddr)>,
    id_map: HashMap<u16, SocksAddr>,
}
impl AssociateRecvSession {
    pub async fn store_socket(
        &mut self,
        id: u16,
        dst: SocksAddr,
        socks: AnyUdpSend,
    ) -> SResult<()> {
        if let hash_map::Entry::Vacant(e) = self.id_map.entry(id) {
            self.id_store
                .store_socket_with_prelude(id, (socks, dst.clone()))
                .await?;
            debug!(event = "squic:receive_context_id_created", context_id = id, dst = %dst, "recv session insert");
            e.insert(dst);
        }
        Ok(())
    }
}

impl Drop for AssociateRecvSession {
    fn drop(&mut self) {
        let id_store = self.id_store.inner.clone();
        let id_remove = self.id_map.clone();
        tokio::spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();

                id_remove.keys().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    event = "squic:receive_context_ids_removed",
                    "AssociateRecvSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}

/// Handle udp packets send
/// It watches the udp socket and sends the packets to the quic connection.
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_send<C: QuicConnection>(
    mut send: C::SendStream,
    udp_recv: AnyUdpRecv,
    conn: SQConn<C>,
    over_stream: bool,
) -> Result<(), SError> {
    let mut down_stream = udp_recv;
    let mut session = AssociateSendSession {
        id_store: conn.send_id_store.clone(),
        dst_map: Default::default(),
        association: conn.uni_pool.new_association(),
        conn: conn.clone(),
    };
    let quic_conn = conn.conn.clone();
    let mut trace_seq = 0_u64;
    loop {
        let (bytes, dst) = down_stream.recv_from().await?;
        if !dst.is_encodable() {
            // Only this datagram is lost: the association carries other
            // destinations too.
            static LIMIT: crate::utils::log::LogRateLimit = crate::utils::log::LogRateLimit::new();
            if let Some(held_back) = LIMIT.allow() {
                warn!(
                    event = "squic:datagram_dropped",
                    held_back, "udp datagram dropped: its destination name is too long"
                );
            }
            continue;
        }
        let should_trace = tracing::enabled!(target: "shadowquic::squic::udp", Level::TRACE) && {
            let n = trace_seq;
            trace_seq = trace_seq.wrapping_add(1);
            n & 1023 == 0 // Trace the first packet, then every 1,024 packets.
        };
        if should_trace {
            trace!(target: "shadowquic::squic::udp", event = "squic:downstream_datagram_received", dst = %dst, "udp datagram received from down_stream");
        }
        let (id, is_new) = session.get_id_or_insert(&dst).await?;
        if should_trace {
            trace!(target: "shadowquic::squic::udp", event = "squic:context_id_resolved", context_id = id, dst = %dst, "session id resolved,is_new_id:{}", is_new);
        }
        //let span = trace_span!("udp", id = id);
        let ctl_header = SQUdpControlHeader {
            dst: dst.clone(),
            id,
        };
        let dg_header = SQPacketDatagramHeader { id };
        // A destination without a stream gets a new one, which starts with
        // the context id, whether the id is new or not.
        let uni = if over_stream {
            match conn.uni_pool.take(session.association, &dst) {
                Some(uni) => Some((uni, false)),
                None => Some((open_uni_making_room(&conn).await?, true)),
            }
        } else {
            None
        };

        if is_new {
            // Need to be sent first to make it cancel safe
            // A lonely datagram without sending the control header will causing
            // memoryleak in the peer.
            ctl_header.encode(&mut send).await?;
            tracing::trace!(event = "squic:control_header_sent", context_id = id, dst = %dst, "udp control header sent");
        }
        {
            let mut head = Vec::<u8>::new();
            if let Some((mut uni, fresh)) = uni {
                if fresh {
                    dg_header.encode(&mut head).await?
                }
                (bytes.len() as u16).encode(&mut head).await?;
                uni.write_all(&head).await?;
                uni.write_all(&bytes).await?;
                for unused in conn.uni_pool.put(session.association, &dst, uni) {
                    close_uni(unused).await;
                }
            } else {
                dg_header.encode(&mut head).await?;
                let mut content = BytesMut::with_capacity(2000);
                content.put(Bytes::from(head));
                content.put(bytes);
                let content = content.freeze();
                quic_conn.send_datagram(content).await?;
                if should_trace {
                    trace!(target: "shadowquic::squic::udp", event = "squic:datagram_sent", context_id = id, dst = %dst, "quic unreliable datagram sent to upstream");
                }
            }
        };
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Opens a unidirectional stream. While the peer allows no more streams, room
/// is made by closing streams of the connection, the least recently used first.
async fn open_uni_making_room<C: QuicConnection>(conn: &SQConn<C>) -> SResult<C::SendStream> {
    let open = QuicConnection::open_uni(&conn.conn);
    tokio::pin!(open);
    let mut patience = uni_pool::RoomPatience::new();
    loop {
        tokio::select! {
            biased;
            opened = &mut open => return Ok(opened?.0),
            _ = patience.wait() => {
                for unused in conn.uni_pool.take_room() {
                    close_uni(unused).await;
                }
            }
        }
    }
}

/// Finishes a stream: the peer sees its end and allows a new one in its place.
async fn close_uni<S: AsyncWrite + Unpin>(mut stream: S) {
    let _ = stream.shutdown().await;
}

/// Handle udp ctrl stream receive task
/// it retrieves the dst id pair from the bistream and records related socket and address
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_recv_ctrl<C: QuicConnection>(
    mut recv: C::RecvStream,
    udp_socket: AnyUdpSend,
    conn: SQConn<C>,
) -> Result<(), SError> {
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    loop {
        let SQUdpControlHeader { id, dst } = SQUdpControlHeader::decode(&mut recv).await?;
        info!(event = "squic:control_header_received", context_id = id, dst = %dst, "udp control header received");
        let _ = session
            .store_socket(id, dst, udp_socket.clone())
            .await
            .map_err(|e| {
                error!(
                    event = "squic:datagram_write_failed",
                    "failed to writing data to udp socket:{e}"
                )
            });
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle udp packet receive task
/// It watches udp packets from quic connection and sends them to the udp socket.
/// The udp socket could be downstream(inbound) or upstream(outbound)
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_packet_recv<C: QuicConnection>(conn: SQConn<C>) -> Result<(), SError> {
    let id_store = conn.recv_id_store.clone();
    wait_sunny_auth(&conn).await?;
    let mut trace_seq = 0_u64;
    // Armed while datagrams wait for an unannounced id, so that an idle
    // connection has no timer.
    let mut sweep_at: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            _ = async { tokio::time::sleep_until(sweep_at.unwrap_or_else(tokio::time::Instant::now)).await }, if sweep_at.is_some() => {
                sweep_at = id_store
                    .purge_expired()
                    .await
                    .then(|| tokio::time::Instant::now() + PENDING_TTL);
            }
            b = conn.read_datagram() => {
                let b = b?;
                let b = BytesMut::from(b);
                let mut cur = Cursor::new(b);
                // A datagram too short for its header is the peer's mistake, not
                // a reason to stop UDP reception for the whole connection.
                let Ok(SQPacketDatagramHeader{id}) = SQPacketDatagramHeader::decode(&mut cur).await else {
                    debug!(event = "squic:datagram_dropped", "dropping malformed quic datagram");
                    continue;
                };

                let should_trace = tracing::enabled!(target: "shadowquic::squic::udp", Level::TRACE) && {
                    let n = trace_seq;
                    trace_seq = trace_seq.wrapping_add(1);
                    n & 1023 == 0 // Trace the first packet, then every 1,024 packets.
                };
                if should_trace {
                    trace!(target: "shadowquic::squic::udp", event = "squic:datagram_received", context_id = id, "quic unreliable datagram received");
                }

                let pos = cur.position() as usize;
                match id_store.feed_datagram(id, cur.into_inner().split_off(pos).freeze()).await {
                    Ok(buffered) => {
                        if buffered && sweep_at.is_none() {
                            sweep_at = Some(tokio::time::Instant::now() + PENDING_TTL);
                        }
                    }
                    // A failed association must not stop UDP reception for the
                    // other associations sharing this QUIC connection.
                    Err(error @ SError::UdpSenderBusy(_)) => {
                        tracing::warn!(event = "squic:datagram_dropped", context_id = id, %error, "dropping UDP datagram due to sender busy");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(event = "squic:datagram_delivery_failed", context_id = id, %error, "dropping UDP datagram after delivery failure");
                        continue;
                    }
                }
                if should_trace {
                    trace!(target: "shadowquic::squic::udp", event = "squic:datagram_forwarded", context_id = id, "quic unreliable datagram received sent to upstream");
                }
            }

            r = conn.accept_uni() => {
                let (mut uni_stream, _id) = r?;
                trace!(event = "squic:unidirectional_stream_accepted", "unistream accepted");
                let id_store = id_store.clone();
                let peer_addr = conn.remote_address();
                // Each unistream gets its own task: one that never names its
                // context id, or names one that is never announced, must not
                // stall the datagrams and unistreams behind it.
                tokio::spawn(async move {
                    let SQPacketDatagramHeader{id} = tokio::time::timeout(PENDING_TTL, SQPacketDatagramHeader::decode(&mut uni_stream))
                        .await
                        .map_err(|_| SError::UDPSessionClosed("udp stream sent no context id".to_string()))??;
                    trace!(event = "squic:context_resolution_started", context_id = id, "resolving datagram id");
                    // Gives up after `PENDING_TTL` if the id is never announced.
                    let (udp, addr) = id_store.get_socket_or_wait(id).await?;
                    info!(event = "squic:udp_stream_started", context_id = id, peer_addr = %peer_addr, dst = %addr, "udp over stream");
                    loop {
                        let l: usize = u16::decode(&mut uni_stream).await? as usize;
                        let mut b = BytesMut::with_capacity(l);
                        b.resize(l,0);
                        uni_stream.read_exact(&mut b).await?;
                        udp.send_to(b.freeze(), addr.clone()).await?;
                    }
                    #[allow(unreachable_code)]
                    (Ok(()) as Result<(), SError>)
                }.in_current_span());
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}
