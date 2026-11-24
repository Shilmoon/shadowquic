//! UDP over stream uses one unidirectional stream per destination. An
//! association that talks to more destinations than the peer allows streams
//! must keep working, and must not starve the associations next to it.
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use fast_socks5::client::Socks5Datagram;
use shadowquic::{
    Manager,
    config::{
        AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
        SocksServerCfg,
    },
    direct::outbound::DirectOut,
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    socks::inbound::SocksServer,
};
use tokio::net::{TcpStream, UdpSocket};

/// Streams each side allows the other to have open at once.
const STREAM_LIMIT: u32 = 8;
const DESTINATIONS: usize = 3 * STREAM_LIMIT as usize;

fn unused_udp_addr() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    port
}

async fn associate(socks_addr: SocketAddr) -> Socks5Datagram<TcpStream> {
    let control = TcpStream::connect(socks_addr).await.unwrap();
    Socks5Datagram::bind(
        control,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .await
    .unwrap()
}

/// Sends one datagram to every port and waits for all the echoes.
async fn echo_all(socks: &Socks5Datagram<TcpStream>, ports: &[u16], what: &str) {
    let exchange = async {
        for port in ports {
            socks
                .send_to(&port.to_be_bytes(), ("127.0.0.1", *port))
                .await
                .unwrap();
        }
        let mut missing: HashSet<u16> = ports.iter().copied().collect();
        let mut buf = [0u8; 16];
        while !missing.is_empty() {
            let (n, _) = socks.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 2);
            missing.remove(&u16::from_be_bytes([buf[0], buf[1]]));
        }
    };
    tokio::time::timeout(Duration::from_secs(20), exchange)
        .await
        .unwrap_or_else(|_| panic!("{what}: echoes missing"));
}

/// A client behind a SOCKS inbound and a server, each allowing the other
/// `stream_limit` streams. Returns the address of the SOCKS inbound.
async fn start(stream_limit: u32) -> SocketAddr {
    let server_addr = unused_udp_addr();
    let server = ShadowQuicServer::new(ShadowQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: server_addr,
        users: vec![AuthUser {
            username: "user".into(),
            password: "pass".into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "127.0.0.1:9".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        congestion_control: CongestionControl::Bbr,
        max_concurrent_uni_streams: stream_limit,
        ..Default::default()
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(server), Arc::new(DirectOut::default())).run());

    let sq_client = ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            username: "user".into(),
            password: "pass".into(),
            addr: server_addr.to_string(),
            server_name: "localhost".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1200,
            congestion_control: CongestionControl::Bbr,
            over_stream: true,
            max_concurrent_uni_streams: stream_limit,
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    );
    let socks_addr: SocketAddr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let socks = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(socks), Arc::new(sq_client)).run());
    tokio::time::sleep(Duration::from_millis(200)).await;
    socks_addr
}

#[tokio::test]
async fn more_destinations_than_the_peer_allows_streams() {
    let socks_addr = start(STREAM_LIMIT).await;
    let mut ports = Vec::new();
    for _ in 0..DESTINATIONS {
        ports.push(spawn_udp_echo().await);
    }

    let first = associate(socks_addr).await;
    echo_all(&first, &ports, "first association").await;

    // The first association is still open and has used every stream.
    let second = associate(socks_addr).await;
    echo_all(&second, &ports[..2], "second association").await;

    // Destinations whose stream was closed to make room are reached again.
    echo_all(&first, &ports, "first association, second round").await;
}

/// The peer allows new streams only once more than an eighth of its limit has
/// ended, so room has to be made for several streams at once: one stream at a
/// time, a new destination would wait through nine rounds of it here.
#[tokio::test]
async fn a_destination_past_the_stream_limit_is_not_kept_waiting() {
    const LIMIT: u32 = 64;
    let socks_addr = start(LIMIT).await;
    let socks = associate(socks_addr).await;
    let mut slowest = Duration::ZERO;
    for _ in 0..LIMIT + 24 {
        let port = spawn_udp_echo().await;
        let sent = std::time::Instant::now();
        echo_all(&socks, &[port], "new destination").await;
        slowest = slowest.max(sent.elapsed());
    }
    assert!(
        slowest < Duration::from_millis(600),
        "a new destination waited {slowest:?}"
    );
}
