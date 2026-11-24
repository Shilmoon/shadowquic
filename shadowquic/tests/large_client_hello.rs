//! A ClientHello that does not fit one Initial packet (post-quantum key shares,
//! long ALPN lists, other QUIC stacks) must still authenticate against a server
//! that accepts 0-RTT. Upstream issue #191.
use std::net::SocketAddr;

use fast_socks5::client::{Config, Socks5Stream};
use shadowquic::config::{
    AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
    SocksServerCfg, default_initial_mtu,
};
use shadowquic::{
    Manager,
    direct::outbound::DirectOut,
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    socks::inbound::SocksServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpListener, time::Duration};

fn unused_udp_addr() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn unused_tcp_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Forwards datagrams between the client and `server`, holding back the client's
/// second datagram for `delay` so the server sees the rest of a multi-packet
/// ClientHello only after it has accepted the connection.
async fn delaying_relay(server: SocketAddr, delay: Duration) -> SocketAddr {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let mut from_client = 0u32;
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if src == server {
                if let Some(c) = client {
                    let _ = sock.send_to(&buf[..n], c).await;
                }
                continue;
            }
            client = Some(src);
            from_client += 1;
            if from_client == 2 && !delay.is_zero() {
                let (sock, pkt) = (sock.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&pkt, server).await;
                });
            } else {
                let _ = sock.send_to(&buf[..n], server).await;
            }
        }
    });
    addr
}

async fn echo_through(
    alpn: Vec<String>,
    server_zero_rtt: bool,
    second_packet_delay: Duration,
) -> Result<(), String> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let server_addr = unused_udp_addr();
    let socks_addr = unused_tcp_addr();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let sq_server = ShadowQuicServer::new(ShadowQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: server_addr,
        users: vec![AuthUser {
            username: "user".into(),
            password: "pass".into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        zero_rtt: server_zero_rtt,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    })
    .await
    .unwrap();
    let server = Manager::single(
        Box::new(sq_server),
        std::sync::Arc::new(DirectOut::default()),
    );
    tokio::spawn(server.run());

    let socks_server = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    let sq_client = ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            username: "user".into(),
            password: "pass".into(),
            addr: delaying_relay(server_addr, second_packet_delay)
                .await
                .to_string(),
            server_name: "localhost".into(),
            alpn,
            initial_mtu: 1200,
            congestion_control: CongestionControl::Bbr,
            zero_rtt: false,
            ..Default::default()
        },
        std::sync::Arc::new(shadowquic::dns::ResolverManager::new()),
    );
    let client = Manager::single(Box::new(socks_server), std::sync::Arc::new(sq_client));
    tokio::spawn(client.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

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
        if &buf == b"ping" {
            Ok(())
        } else {
            Err(format!("echo mismatch: {buf:?}"))
        }
    };
    tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

/// Enough ALPN bytes to push the ClientHello past one 1200-byte Initial.
fn large_alpn() -> Vec<String> {
    let mut alpn: Vec<String> = (0..6).map(|i| format!("{i}").repeat(250)).collect();
    alpn.push("h3".into());
    alpn
}

#[tokio::test]
async fn single_packet_client_hello_with_server_zero_rtt() {
    echo_through(vec!["h3".into()], true, Duration::ZERO)
        .await
        .unwrap();
}

#[tokio::test]
async fn multi_packet_client_hello_with_server_zero_rtt() {
    echo_through(large_alpn(), true, Duration::ZERO)
        .await
        .unwrap();
}

#[tokio::test]
async fn delayed_multi_packet_client_hello_with_server_zero_rtt() {
    echo_through(large_alpn(), true, Duration::from_millis(100))
        .await
        .unwrap();
}

#[tokio::test]
async fn delayed_multi_packet_client_hello_without_server_zero_rtt() {
    echo_through(large_alpn(), false, Duration::from_millis(100))
        .await
        .unwrap();
}
