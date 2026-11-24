pub(crate) mod copy;
pub mod dual_socket;
pub mod log;
pub mod platform;
pub mod socket_opt;
pub mod user_store;

#[cfg(any(feature = "router-db", feature = "restful-api"))]
pub(crate) mod download;
#[cfg(any(feature = "router-db", feature = "restful-api"))]
pub(crate) mod http;
#[cfg(any(feature = "router-db", feature = "restful-api", feature = "dns-server"))]
pub(crate) mod proxy;
#[cfg(any(feature = "router-db", feature = "dns-server", feature = "restful-api"))]
pub(crate) mod tls;

#[cfg(target_os = "android")]
pub mod protect_socket;

pub mod replay_stream;

thread_local! {
    /// Scratch space large enough for any UDP datagram, one per runtime thread.
    static UDP_RECV_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; 65_535]);
}

/// Receives one datagram whole, whatever its size, without keeping a
/// full-size buffer per socket.
pub(crate) async fn recv_udp_datagram(
    socket: &tokio::net::UdpSocket,
) -> std::io::Result<(bytes::Bytes, std::net::SocketAddr)> {
    loop {
        socket.readable().await?;
        let received = UDP_RECV_BUF.with_borrow_mut(|buf| {
            socket
                .try_recv_from(buf)
                .map(|(len, src)| (bytes::Bytes::copy_from_slice(&buf[..len]), src))
        });
        match received {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            received => return received,
        }
    }
}

/// Polls a future once: its output if it is ready now.
pub(crate) fn poll_now<F: std::future::Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(output) => Some(output),
        std::task::Poll::Pending => None,
    }
}

/// Whether a send failed because the datagram is larger than the socket can send.
pub(crate) fn is_datagram_too_large(error: &std::io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const EMSGSIZE: i32 = 90;
    #[cfg(windows)]
    const EMSGSIZE: i32 = 10040;
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    const EMSGSIZE: i32 = 40;
    error.raw_os_error() == Some(EMSGSIZE)
}
