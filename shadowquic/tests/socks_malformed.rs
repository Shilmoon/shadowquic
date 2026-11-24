//! Malformed input from a local SOCKS client must not take the proxy down.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use shadowquic::{
    Manager, config::SocksServerCfg, direct::outbound::DirectOut, socks::inbound::SocksServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

fn unused_tcp_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Starts a SOCKS inbound with a direct outbound and a TCP echo server.
async fn proxy() -> (SocketAddr, u16) {
    // Request spans format the destination only when a subscriber enables them,
    // as the binary's logger does at every log level.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::sink)
        .try_init();
    let socks_addr = unused_tcp_addr();
    let socks_server = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    let manager = Manager::single(Box::new(socks_server), Arc::new(DirectOut::default()));
    tokio::spawn(manager.run());

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (socks_addr, echo_port)
}

async fn echo_works(socks_addr: SocketAddr, echo_port: u16) -> Result<(), String> {
    let attempt = async {
        let mut s = Socks5Stream::connect(
            socks_addr.to_string(),
            "127.0.0.1".into(),
            echo_port,
            Config::default(),
        )
        .await
        .map_err(|e| format!("socks connect: {e}"))?;
        s.write_all(b"ping")
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

#[tokio::test]
async fn non_utf8_domain_does_not_stop_the_inbound() {
    let (socks_addr, echo_port) = proxy().await;
    echo_works(socks_addr, echo_port).await.unwrap();

    let mut s = TcpStream::connect(socks_addr).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    // CONNECT to a 2-byte domain that is not valid UTF-8, port 80.
    s.write_all(&[0x05, 0x01, 0x00, 0x03, 0x02, 0xff, 0xfe, 0x00, 0x50])
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
    drop(s);

    echo_works(socks_addr, echo_port)
        .await
        .expect("the SOCKS inbound must keep serving after a malformed request");
}

async fn udp_echo_server() -> u16 {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], src).await;
        }
    });
    echo_port
}

/// Opens a UDP association; returns the control stream and the client's UDP
/// socket connected to the relay.
async fn open_association(socks_addr: SocketAddr) -> (TcpStream, UdpSocket) {
    open_association_from(socks_addr, &[0x01, 0, 0, 0, 0, 0, 0]).await
}

/// `client_addr` is the address (type, address, port) the request names as
/// the one the client will send its datagrams from.
async fn open_association_from(
    socks_addr: SocketAddr,
    client_addr: &[u8],
) -> (TcpStream, UdpSocket) {
    let mut ctl = TcpStream::connect(socks_addr).await.unwrap();
    ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    ctl.read_exact(&mut method).await.unwrap();
    ctl.write_all(&[0x05, 0x03, 0x00]).await.unwrap();
    ctl.write_all(client_addr).await.unwrap();
    let mut reply = [0u8; 10];
    ctl.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "udp associate refused");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(("127.0.0.1", relay_port)).await.unwrap();
    (ctl, udp)
}

async fn associate(socks_addr: SocketAddr) -> (TcpStream, UdpSocket, u16) {
    let (ctl, udp) = open_association(socks_addr).await;
    (ctl, udp, udp_echo_server().await)
}

fn socks_udp(frag: u8, atyp: u8, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0, 0, frag, atyp, 127, 0, 0, 1];
    d.extend_from_slice(&port.to_be_bytes());
    d.extend_from_slice(payload);
    d
}

/// Sends `payload` to the echo server through the association and returns the
/// echoed payload, if a reply arrives.
async fn udp_echo(udp: &UdpSocket, echo_port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    udp.send(&socks_udp(0, 1, echo_port, payload))
        .await
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(2), udp.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[10..n].to_vec())
}

#[tokio::test]
async fn bad_udp_datagrams_are_dropped_and_the_association_continues() {
    let (socks_addr, _) = proxy().await;
    let (_ctl, udp, echo_port) = associate(socks_addr).await;
    assert_eq!(udp_echo(&udp, echo_port, b"one").await.unwrap(), b"one");

    // Too short for a header, fragmented, unknown address type.
    udp.send(&[0, 0, 0, 1]).await.unwrap();
    udp.send(&socks_udp(1, 1, echo_port, b"frag"))
        .await
        .unwrap();
    udp.send(&socks_udp(0, 9, echo_port, b"atyp"))
        .await
        .unwrap();

    assert_eq!(
        udp_echo(&udp, echo_port, b"two").await.as_deref(),
        Some(&b"two"[..]),
        "the association must survive datagrams it has to drop"
    );
}

#[tokio::test]
async fn short_first_udp_datagram_is_dropped() {
    let (socks_addr, _) = proxy().await;
    let (_ctl, udp, echo_port) = associate(socks_addr).await;
    udp.send(&[0, 0, 0, 1]).await.unwrap();
    assert_eq!(
        udp_echo(&udp, echo_port, b"next").await.as_deref(),
        Some(&b"next"[..])
    );
}

#[tokio::test]
async fn large_udp_payload_is_not_truncated() {
    let (socks_addr, _) = proxy().await;
    let (_ctl, udp, echo_port) = associate(socks_addr).await;
    let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let echoed = udp_echo(&udp, echo_port, &payload).await.unwrap();
    assert_eq!(echoed.len(), payload.len());
    assert_eq!(echoed, payload);
}

/// Largest datagram this host lets a socket send on loopback.
async fn max_datagram() -> usize {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = b.local_addr().unwrap();
    let mut size = 65_507;
    while a.send_to(&vec![0u8; size], dst).await.is_err() {
        size -= 1;
        assert!(size > 1024, "cannot find the datagram size limit");
    }
    size
}

/// A reply that no longer fits a datagram once the SOCKS header is added is
/// dropped; the association goes on.
#[tokio::test]
async fn oversized_reply_is_dropped_and_the_association_continues() {
    let (socks_addr, _) = proxy().await;
    let limit = max_datagram().await;
    // Replies to "big" with the largest datagram the host can send, echoes the rest.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = server.recv_from(&mut buf).await {
            if &buf[..n] == b"big" {
                let _ = server.send_to(&vec![7u8; limit], src).await;
            } else {
                let _ = server.send_to(&buf[..n], src).await;
            }
        }
    });
    let (_ctl, udp) = open_association(socks_addr).await;
    assert_eq!(udp_echo(&udp, server_port, b"one").await.unwrap(), b"one");
    assert_eq!(udp_echo(&udp, server_port, b"big").await, None);
    assert_eq!(
        udp_echo(&udp, server_port, b"two").await.as_deref(),
        Some(&b"two"[..]),
        "one reply that cannot be relayed must not end the association"
    );
}

/// Anything the client sends on the control connection ends the association,
/// before the first datagram just as after it.
#[tokio::test]
async fn data_on_the_control_stream_ends_a_new_association() {
    let (socks_addr, _) = proxy().await;
    let (mut ctl, _udp) = open_association(socks_addr).await;
    ctl.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(2), ctl.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "the control connection should have been closed, got {closed:?}"
    );
}

/// Reads what the server sends until it closes the connection.
async fn reply_to(socks_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(socks_addr).await.unwrap();
    s.write_all(request).await.unwrap();
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut reply)).await;
    reply
}

/// A client that offers no method the server accepts is told so (RFC 1928,
/// section 3) instead of seeing the connection drop without an answer.
#[tokio::test]
async fn unsupported_auth_method_is_answered() {
    let (socks_addr, _) = proxy().await;
    // Offers user/password only; the server has no users and wants "none".
    assert_eq!(reply_to(socks_addr, &[5, 1, 2]).await, [5, 0xff]);
}

/// BIND and unknown commands get a "command not supported" reply (RFC 1928,
/// section 6).
#[tokio::test]
async fn unsupported_command_is_answered() {
    let (socks_addr, _) = proxy().await;
    for cmd in [2u8, 9] {
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&[5, cmd, 0, 1, 127, 0, 0, 1, 0, 80]);
        assert_eq!(
            reply_to(socks_addr, &request).await,
            [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0],
            "command {cmd}"
        );
    }
}

/// A wrong password gets a failure status (RFC 1929, section 2).
#[tokio::test]
async fn failed_password_auth_is_answered() {
    let socks_addr = unused_tcp_addr();
    let socks_server = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![shadowquic::config::AuthUser {
            username: "u".into(),
            password: "p".into(),
        }],
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(socks_server), Arc::new(DirectOut::default())).run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = reply_to(socks_addr, &[5, 1, 2, 1, 1, b'u', 1, b'x']).await;
    assert_eq!(reply[..2], [5, 2], "method selection");
    assert_eq!(
        reply[2..],
        [1, 1],
        "a failure status, then the connection closes"
    );
}

/// The address in a UDP ASSOCIATE request is the client's own (RFC 1928,
/// section 6): it is not an address for the proxy's outgoing socket, and not
/// a name for the proxy to look up.
#[tokio::test]
async fn association_naming_the_clients_own_address_works() {
    let (socks_addr, _) = proxy().await;
    let echo_port = udp_echo_server().await;

    // 192.0.2.7:4000 is not an address of this host.
    let (_ctl, udp) = open_association_from(socks_addr, &[0x01, 192, 0, 2, 7, 0x0f, 0xa0]).await;
    assert_eq!(
        udp_echo(&udp, echo_port, b"ip").await.as_deref(),
        Some(&b"ip"[..])
    );

    let mut named = vec![0x03, 14];
    named.extend_from_slice(b"client.invalid");
    named.extend_from_slice(&4000u16.to_be_bytes());
    let (_ctl, udp) = open_association_from(socks_addr, &named).await;
    assert_eq!(
        udp_echo(&udp, echo_port, b"name").await.as_deref(),
        Some(&b"name"[..])
    );
}
