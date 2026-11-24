//! A peer must not be able to stop, stall or bloat the UDP relay of a connection
//! with malformed or unannounced input.
use super::*;
use crate::quic::QuicErrorRepr;
use async_trait::async_trait;
use std::{
    future::pending,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::mpsc;

#[derive(Clone)]
struct MockConn {
    dg_in: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    uni_in: Arc<Mutex<mpsc::Receiver<tokio::io::DuplexStream>>>,
    dg_out: Arc<AtomicUsize>,
}

#[async_trait]
impl QuicConnection for MockConn {
    type SendStream = tokio::io::DuplexStream;
    type RecvStream = tokio::io::DuplexStream;
    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        pending().await
    }
    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        pending().await
    }
    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr> {
        pending().await
    }
    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr> {
        match self.uni_in.lock().await.recv().await {
            Some(s) => Ok((s, 0)),
            None => pending().await,
        }
    }
    async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr> {
        match self.dg_in.lock().await.recv().await {
            Some(b) => Ok(b),
            None => pending().await,
        }
    }
    async fn send_datagram(&self, _: Bytes) -> Result<(), QuicErrorRepr> {
        self.dg_out.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn close(&self, _: u64, _: &[u8]) {}
    fn close_reason(&self) -> Option<QuicErrorRepr> {
        None
    }
    fn remote_address(&self) -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }
    fn peer_id(&self) -> u64 {
        0
    }
}

type Mock = (
    SQConn<MockConn>,
    mpsc::Sender<Bytes>,
    mpsc::Sender<tokio::io::DuplexStream>,
    Arc<AtomicUsize>,
);

fn mock() -> Mock {
    let (ds, dr) = mpsc::channel(100_000);
    let (us, ur) = mpsc::channel(16);
    let sent = Arc::new(AtomicUsize::new(0));
    let conn = MockConn {
        dg_in: Arc::new(Mutex::new(dr)),
        uni_in: Arc::new(Mutex::new(ur)),
        dg_out: sent.clone(),
    };
    (
        SQConn::new(conn, SetOnce::new_with(Some(Ok("test".into())))),
        ds,
        us,
        sent,
    )
}

async fn datagram(id: u16, payload: &[u8]) -> Bytes {
    let mut v = Vec::new();
    SQPacketDatagramHeader { id }.encode(&mut v).await.unwrap();
    v.extend_from_slice(payload);
    Bytes::from(v)
}

/// Registers context id 6 and returns the receiver its packets are delivered to.
async fn announced(conn: &SQConn<MockConn>) -> mpsc::Receiver<(Bytes, SocksAddr)> {
    let (s, r) = mpsc::channel::<(Bytes, SocksAddr)>(64);
    conn.recv_id_store
        .store_socket(
            6,
            (Arc::new(s) as AnyUdpSend, "1.1.1.1:53".parse().unwrap()),
        )
        .await;
    r
}

async fn delivered(r: &mut mpsc::Receiver<(Bytes, SocksAddr)>) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_secs(2), r.recv())
        .await
        .ok()
        .flatten()
        .map(|x| x.0)
}

#[tokio::test]
async fn short_datagram_does_not_stop_the_receiver() {
    let (conn, ds, _us, _) = mock();
    let mut r = announced(&conn).await;
    let h = tokio::spawn(handle_udp_packet_recv(conn));
    ds.send(Bytes::from_static(&[0x00])).await.unwrap();
    ds.send(datagram(6, b"after").await).await.unwrap();
    assert_eq!(delivered(&mut r).await, Some(Bytes::from_static(b"after")));
    h.abort();
}

#[tokio::test]
async fn empty_unistream_does_not_stop_the_receiver() {
    let (conn, ds, us, _) = mock();
    let mut r = announced(&conn).await;
    let h = tokio::spawn(handle_udp_packet_recv(conn));
    // The peer finishes a unistream before writing its context id.
    let (w, rd) = tokio::io::duplex(64);
    drop(w);
    us.send(rd).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ds.send(datagram(6, b"after").await).await.unwrap();
    assert_eq!(delivered(&mut r).await, Some(Bytes::from_static(b"after")));
    h.abort();
}

#[tokio::test]
async fn unistream_with_unannounced_id_does_not_block_other_unistreams() {
    let (conn, _ds, us, _) = mock();
    let mut r = announced(&conn).await;
    let h = tokio::spawn(handle_udp_packet_recv(conn));
    // Stream 1 names context id 5, which is never announced.
    let (mut w1, r1) = tokio::io::duplex(4096);
    let mut head = Vec::new();
    SQPacketDatagramHeader { id: 5 }
        .encode(&mut head)
        .await
        .unwrap();
    w1.write_all(&head).await.unwrap();
    us.send(r1).await.unwrap();
    // Stream 2 carries a packet for the announced id 6.
    let (mut w2, r2) = tokio::io::duplex(4096);
    let mut head = Vec::new();
    SQPacketDatagramHeader { id: 6 }
        .encode(&mut head)
        .await
        .unwrap();
    5u16.encode(&mut head).await.unwrap();
    head.extend_from_slice(b"hello");
    w2.write_all(&head).await.unwrap();
    us.send(r2).await.unwrap();
    assert_eq!(delivered(&mut r).await, Some(Bytes::from_static(b"hello")));
    h.abort();
}

async fn pending_bytes_and_ids(conn: &SQConn<MockConn>) -> (usize, usize) {
    let store = conn.recv_id_store.inner.read().await;
    let mut bytes = 0;
    let mut ids = 0;
    for slot in store.values() {
        if let Err(pending) = slot {
            ids += 1;
            bytes += pending.buffer.iter().map(|b| b.len()).sum::<usize>();
        }
    }
    (bytes, ids)
}

#[tokio::test]
async fn datagrams_for_unannounced_ids_are_buffered_with_a_bound() {
    let (conn, ds, _us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    let payload = vec![0u8; 1200];
    // Many packets for a few ids, then one packet for each of many ids.
    for i in 0..20_000u32 {
        ds.send(datagram((i % 4) as u16 + 100, &payload).await)
            .await
            .unwrap();
    }
    for id in 1000..9000u16 {
        ds.send(datagram(id, &payload).await).await.unwrap();
    }
    ds.send(datagram(99, b"last").await).await.unwrap();
    // Wait until the receiver has drained its input.
    for _ in 0..200 {
        if ds.capacity() == ds.max_capacity() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (bytes, ids) = pending_bytes_and_ids(&conn).await;
    assert!(
        bytes <= 4 * 1024 * 1024,
        "{bytes} bytes buffered for unannounced context ids"
    );
    assert!(ids <= PENDING_MAX_PACKETS, "{ids} pending context ids");
    h.abort();
}

#[tokio::test]
async fn early_datagrams_are_still_delivered_once_the_id_is_announced() {
    let (conn, ds, _us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    for i in 0..8u8 {
        ds.send(datagram(7, &[i]).await).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (s, mut r) = mpsc::channel::<(Bytes, SocksAddr)>(64);
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    session
        .store_socket(7, "1.1.1.1:53".parse().unwrap(), Arc::new(s))
        .await
        .unwrap();
    for i in 0..8u8 {
        assert_eq!(delivered(&mut r).await, Some(Bytes::copy_from_slice(&[i])));
    }
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn stale_datagrams_are_not_delivered_to_a_later_association() {
    let (conn, ds, _us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    let (s1, mut r1) = mpsc::channel::<(Bytes, SocksAddr)>(64);
    {
        let mut session = AssociateRecvSession {
            id_store: conn.recv_id_store.clone(),
            id_map: Default::default(),
        };
        session
            .store_socket(7, "1.1.1.1:53".parse().unwrap(), Arc::new(s1))
            .await
            .unwrap();
        ds.send(datagram(7, b"in-session").await).await.unwrap();
        assert_eq!(
            delivered(&mut r1).await,
            Some(Bytes::from_static(b"in-session"))
        );
    }
    // The association is gone; a late reply for its id arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    ds.send(datagram(7, b"late-reply").await).await.unwrap();
    // Much later the peer's id counter wraps and id 7 names another destination.
    tokio::time::sleep(Duration::from_secs(600)).await;
    let (s2, mut r2) = mpsc::channel::<(Bytes, SocksAddr)>(64);
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    session
        .store_socket(7, "9.9.9.9:443".parse().unwrap(), Arc::new(s2))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        r2.try_recv().is_err(),
        "a packet of the old association was delivered under the new destination"
    );
    h.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn context_id_exhaustion_ends_the_association_instead_of_hanging() {
    let (conn, _ds, _us, sent) = mock();
    let store = conn.send_id_store.inner.clone();
    let (tx, rx) = mpsc::channel::<(Bytes, SocksAddr)>(1024);
    let (ctl, mut ctl_peer) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        while ctl_peer.read(&mut b).await.unwrap_or(0) != 0 {}
    });
    let sender = tokio::spawn(handle_udp_send::<MockConn>(ctl, Box::new(rx), conn, false));
    let feeder = tokio::spawn(async move {
        for i in 0..65_537u32 {
            let ip = [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
            let addr = SocksAddr {
                addr: crate::msgs::socks5::AddrOrDomain::V4(ip),
                port: 53,
            };
            if tx.send((Bytes::from_static(b"x"), addr)).await.is_err() {
                break;
            }
        }
        tx
    });
    let result = tokio::time::timeout(Duration::from_secs(60), sender)
        .await
        .expect("the sender must not hang once every context id is in use")
        .unwrap();
    assert!(result.is_err());
    assert_eq!(sent.load(Ordering::SeqCst), 65_536);
    // The ids of the ended association are released.
    let _tx = feeder.await.unwrap();
    for _ in 0..100 {
        if store.read().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(store.read().await.is_empty());
}

async fn drained(ds: &mpsc::Sender<Bytes>) {
    for _ in 0..200 {
        if ds.capacity() == ds.max_capacity() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(start_paused = true)]
async fn expired_backlog_is_freed_without_further_input() {
    let (conn, ds, _us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    let payload = vec![0u8; 1200];
    for i in 0..1000u32 {
        ds.send(datagram((i % 100) as u16 + 100, &payload).await)
            .await
            .unwrap();
    }
    drained(&ds).await;
    assert!(pending_bytes_and_ids(&conn).await.0 > 0);
    // The peer goes quiet.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(pending_bytes_and_ids(&conn).await, (0, 0));
    h.abort();
}

#[tokio::test(start_paused = true)]
async fn unistream_naming_an_unannounced_id_leaves_nothing_behind() {
    let (conn, _ds, us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    let mut writers = Vec::new();
    for id in 500..520u16 {
        let (mut w, r) = tokio::io::duplex(64);
        let mut head = Vec::new();
        SQPacketDatagramHeader { id }
            .encode(&mut head)
            .await
            .unwrap();
        w.write_all(&head).await.unwrap();
        us.send(r).await.unwrap();
        writers.push(w);
    }
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(pending_bytes_and_ids(&conn).await, (0, 0));
    h.abort();
}

#[tokio::test]
async fn long_burst_of_early_datagrams_is_delivered() {
    let (conn, ds, _us, _) = mock();
    let h = tokio::spawn(handle_udp_packet_recv(conn.clone()));
    // A lost control header can let a few hundred datagrams of a flow arrive first.
    for i in 0..300u16 {
        ds.send(datagram(7, &i.to_be_bytes()).await).await.unwrap();
    }
    drained(&ds).await;
    let (s, mut r) = mpsc::channel::<(Bytes, SocksAddr)>(512);
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    session
        .store_socket(7, "1.1.1.1:53".parse().unwrap(), Arc::new(s))
        .await
        .unwrap();
    for i in 0..300u16 {
        assert_eq!(
            delivered(&mut r).await,
            Some(Bytes::copy_from_slice(&i.to_be_bytes()))
        );
    }
    h.abort();
}
