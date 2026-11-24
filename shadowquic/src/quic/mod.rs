use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use crate::{Stoppable, error::SResult, msgs::squic::ConnStats, utils::socket_opt::SocketFactory};
use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

// 4 times larger than quinn default value
// Better decrease the size for portable device
pub const MAX_WINDOW_BASE: u64 = 4 * 12_500_000 * 100 / 1000; // 100ms RTT
pub const MAX_STREAM_WINDOW: u64 = MAX_WINDOW_BASE;
pub const MAX_SEND_WINDOW: u64 = MAX_WINDOW_BASE * 8;
pub const MAX_DATAGRAM_WINDOW: u64 = MAX_WINDOW_BASE * 2;

// #[cfg(feature = "gm-quic")]
// mod gm_quic_wrapper;
// #[cfg(feature = "gm-quic")]
// pub use gm_quic_wrapper::{Connection, EndClient, EndServer, QuicErrorRepr};

#[async_trait]
pub trait QuicClient: Send + Sync {
    type C: QuicConnection;
    type SC: Clone + Send + Sync + 'static;
    async fn new(cfg: &Self::SC) -> SResult<Self>
    where
        Self: Sized;
    async fn new_with_socket_factory(
        cfg: &Self::SC,
        socket_factory: Arc<dyn SocketFactory>,
    ) -> SResult<Self>
    where
        Self: Sized;
    async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Self::C, QuicErrorRepr>;
    /// Whether the endpoint's socket can send to `addr`: a socket of one
    /// address family cannot reach the other one.
    fn can_reach(&self, _addr: &SocketAddr) -> bool {
        true
    }
}

/// The address families a socket can send to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reach {
    V4,
    V6,
    Both,
}

impl Reach {
    pub fn of(socket: &socket2::Socket) -> Self {
        match socket.local_addr().ok().and_then(|addr| addr.as_socket()) {
            Some(SocketAddr::V4(_)) => Reach::V4,
            // Only a wildcard IPv6 socket that is not IPv6-only carries IPv4.
            Some(SocketAddr::V6(local))
                if !local.ip().is_unspecified() || socket.only_v6().unwrap_or(true) =>
            {
                Reach::V6
            }
            _ => Reach::Both,
        }
    }

    pub fn reaches(self, addr: &SocketAddr) -> bool {
        let v4 = addr.ip().to_canonical().is_ipv4();
        match self {
            Reach::V4 => v4,
            Reach::V6 => !v4,
            Reach::Both => true,
        }
    }

    /// `addr` in the form the socket takes: an IPv4 socket knows an
    /// IPv4-mapped IPv6 address only as the IPv4 address it stands for.
    pub fn form_of(self, addr: SocketAddr) -> SocketAddr {
        match self {
            Reach::V4 => SocketAddr::new(addr.ip().to_canonical(), addr.port()),
            Reach::V6 | Reach::Both => addr,
        }
    }
}

/// The endpoint of a client, created on first use. The server name is resolved
/// for every connection, and the answer may no longer hold an address that the
/// endpoint's socket can reach; the endpoint is then replaced by a new one
/// that reaches one.
pub struct ClientEndpoint<E>(tokio::sync::Mutex<Option<Arc<E>>>);

impl<E> Default for ClientEndpoint<E> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<E: QuicClient> ClientEndpoint<E> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Connects to the first of `addrs` that the endpoint can reach. `create`
    /// makes an endpoint for the addresses the server has now.
    pub async fn connect<F>(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        create: impl Fn() -> F,
    ) -> SResult<E::C>
    where
        F: Future<Output = SResult<E>>,
    {
        let (endpoint, addr) = {
            let mut current = self.0.lock().await;
            let reachable =
                |endpoint: &E| addrs.iter().copied().find(|addr| endpoint.can_reach(addr));
            let mut addr = match &*current {
                Some(endpoint) => reachable(endpoint),
                None => None,
            };
            if addr.is_none() {
                let endpoint = create().await?;
                addr = reachable(&endpoint);
                // An endpoint that reaches none of them either is of no more
                // use than the one in use, which holds the session tickets.
                if addr.is_some() || current.is_none() {
                    *current = Some(Arc::new(endpoint));
                }
            }
            let endpoint = current.as_ref().unwrap().clone();
            // Left to the endpoint to refuse when it reaches none of them.
            let addr = addr.or(addrs.first().copied()).ok_or_else(|| {
                crate::error::SError::DomainResolveFailed(server_name.to_string())
            })?;
            (endpoint, addr)
        };
        Ok(endpoint.connect(addr, server_name).await?)
    }
}
#[async_trait]
pub trait QuicServer: Send + Sync {
    type C: QuicConnection;
    type SC: Clone + Send + Sync + 'static;
    async fn new(cfg: &Self::SC) -> SResult<Self>
    where
        Self: Sized;
    async fn accept(&self) -> Result<Self::C, QuicErrorRepr>;
    async fn update_config(&self, cfg: &Self::SC) -> SResult<()>;
}

/// Resolves when the handshake has finished: `true` when the peer rejected the
/// early (0-RTT) data, so that nothing sent before that moment reached it.
pub type EarlyDataOutcome = Pin<Box<dyn Future<Output = Result<bool, QuicErrorRepr>> + Send>>;

#[async_trait]
pub trait QuicConnection: Send + Sync + Clone + 'static {
    type SendStream: AsyncWrite + Unpin + Send + Sync + 'static;
    type RecvStream: AsyncRead + Unpin + Send + Sync + 'static;
    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr>;
    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr>;
    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr>;
    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr>;
    async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr>;
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), QuicErrorRepr>;
    fn close(&self, error_code: u64, reason: &[u8]);
    fn close_reason(&self) -> Option<QuicErrorRepr>;
    fn remote_address(&self) -> SocketAddr;
    fn peer_id(&self) -> u64;
    fn get_conn_stats(&self) -> Option<ConnStats> {
        None
    }
    /// For a stream opened before the handshake has finished, how its early
    /// data fares. `None` for a stream that is not early data.
    fn early_data_outcome(&self, _stream: &Self::SendStream) -> Option<EarlyDataOutcome> {
        None
    }
}

impl<T: QuicConnection> Stoppable for T {
    fn stop(&self) {
        self.close(0, b"stopped by user");
    }
}

pub trait AuthedConn {
    fn authed_user(&self) -> Option<String>;
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum QuicErrorRepr {
    // gm-quic errors
    #[error("QUIC IO Error:{0}")]
    QuicIoError(String),
    #[error("QUIC Error:{0}")]
    QuicBaseError(String),
    #[error("Failed to build Quic Listener:{0}")]
    QuicListenerBuilderError(String),

    // quinn errors
    #[error("QUIC Connect Error:{0}")]
    QuicConnect(String),
    #[error("QUIC Connection Error:{0}")]
    QuicConnection(String),
    #[error("QUIC Write Error:{0}")]
    QuicWrite(String),
    #[error("QUIC ReadExact Error:{0}")]
    QuicReadExactError(String),
    #[error("QUIC SendDatagramError:{0}")]
    QuicSendDatagramError(String),
    #[error("JLS Authentication failed")]
    JlsAuthFailed,
}

#[cfg(all(test, feature = "shadowquic-quinn"))]
mod endpoint_test;
