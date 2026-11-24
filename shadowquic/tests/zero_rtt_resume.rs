//! A client that reconnects with 0-RTT must not have its first request fail
//! because other clients connected to the server in the meantime.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use fast_socks5::client::{Config, Socks5Stream};
use shadowquic::{
    Manager,
    config::{
        AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
        SocksServerCfg,
    },
    direct::outbound::DirectOut,
    quic::QuicConnection,
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    socks::inbound::SocksServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

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

fn client(server_addr: SocketAddr) -> ShadowQuicClient {
    client_with(server_addr, false)
}

fn client_with(server_addr: SocketAddr, over_stream: bool) -> ShadowQuicClient {
    ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            username: "user".into(),
            password: "pass".into(),
            addr: server_addr.to_string(),
            server_name: "localhost".into(),
            alpn: vec!["h3".into()],
            zero_rtt: true,
            over_stream,
            initial_mtu: 1200,
            congestion_control: CongestionControl::Bbr,
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    )
}

async fn echo(socks_addr: SocketAddr, echo_port: u16) -> Result<(), String> {
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
    tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

async fn close_cached_connection(client: &ShadowQuicClient) {
    let cached = client.quic_conn.lock().await;
    QuicConnection::close(&***cached.as_ref().unwrap(), 0, b"");
    drop(cached);
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn resumption_survives_connections_of_other_clients() {
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = tcp_echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

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
        zero_rtt: true,
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(server), Arc::new(DirectOut::default())).run());

    let socks_addr = unused_tcp_addr();
    let sq_client = Arc::new(client(server_addr));
    let socks = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(socks), sq_client.clone()).run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // First connection: full handshake, then the session ticket arrives.
    echo(socks_addr, echo_port).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Reconnect: resumed with 0-RTT.
    close_cached_connection(&sq_client).await;
    echo(socks_addr, echo_port).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 150 other clients connect; each is issued session tickets of its own.
    for _ in 0..150 {
        let other = client(server_addr);
        let conn = other.get_conn().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        QuicConnection::close(&**conn, 0, b"");
    }

    close_cached_connection(&sq_client).await;
    echo(socks_addr, echo_port)
        .await
        .expect("the first request after reconnecting with 0-RTT must succeed");
}

fn server_cfg(server_addr: SocketAddr) -> ShadowQuicServerCfg {
    ShadowQuicServerCfg {
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
        zero_rtt: true,
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    }
}

/// A server in a runtime of its own: shutting the runtime down stops the
/// server the way a process restart does, losing its resumption state.
fn start_server(server_addr: SocketAddr) -> tokio::runtime::Runtime {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.spawn(async move {
        let server = ShadowQuicServer::new(server_cfg(server_addr))
            .await
            .unwrap();
        let _ = Manager::single(Box::new(server), Arc::new(DirectOut::default()))
            .run()
            .await;
    });
    rt
}

async fn restart_server(
    old: tokio::runtime::Runtime,
    server_addr: SocketAddr,
) -> tokio::runtime::Runtime {
    old.shutdown_background();
    let freed = async {
        while std::net::UdpSocket::bind(server_addr).is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), freed)
        .await
        .expect("the stopped server must free its port");
    let rt = start_server(server_addr);
    tokio::time::sleep(Duration::from_millis(300)).await;
    rt
}

async fn start_socks(sq_client: Arc<ShadowQuicClient>) -> SocketAddr {
    let socks_addr = unused_tcp_addr();
    let socks = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(socks), sq_client).run());
    tokio::time::sleep(Duration::from_millis(200)).await;
    socks_addr
}

async fn udp_echo(socks_addr: SocketAddr, echo_port: u16) -> Result<(), String> {
    let attempt = async {
        let control = tokio::net::TcpStream::connect(socks_addr)
            .await
            .map_err(|e| format!("socks connect: {e}"))?;
        let socks =
            fast_socks5::client::Socks5Datagram::bind(control, SocketAddr::from(([0, 0, 0, 0], 0)))
                .await
                .map_err(|e| format!("associate: {e}"))?;
        // One datagram only: a lost first packet must not be hidden by a retry.
        socks
            .send_to(b"ping", ("127.0.0.1", echo_port))
            .await
            .map_err(|e| format!("send: {e}"))?;
        let mut buf = [0u8; 16];
        let (n, _) = socks
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("recv: {e}"))?;
        if &buf[..n] != b"ping" {
            return Err(format!("unexpected reply {:?}", &buf[..n]));
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

async fn spawn_tcp_echo() -> u16 {
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn spawn_udp_echo() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    port
}

/// A restarted server no longer knows the client's session and rejects its
/// 0-RTT data. The request that was sent as early data must then be repeated
/// by the client, not lost.
#[tokio::test]
async fn first_tcp_request_survives_a_server_restart() {
    let echo_port = spawn_tcp_echo().await;
    let server_addr = unused_udp_addr();
    let server = start_server(server_addr);
    let sq_client = Arc::new(client(server_addr));
    let socks_addr = start_socks(sq_client.clone()).await;

    echo(socks_addr, echo_port).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let server = restart_server(server, server_addr).await;
    close_cached_connection(&sq_client).await;
    echo(socks_addr, echo_port)
        .await
        .expect("the first request after a server restart must succeed");
    server.shutdown_background();
}

async fn first_udp_packet_survives_a_server_restart(over_stream: bool) {
    let echo_port = spawn_udp_echo().await;
    let server_addr = unused_udp_addr();
    let server = start_server(server_addr);
    let sq_client = Arc::new(client_with(server_addr, over_stream));
    let socks_addr = start_socks(sq_client.clone()).await;

    udp_echo(socks_addr, echo_port).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let server = restart_server(server, server_addr).await;
    close_cached_connection(&sq_client).await;
    udp_echo(socks_addr, echo_port)
        .await
        .expect("the first datagram after a server restart must be delivered");
    server.shutdown_background();
}

#[tokio::test]
async fn first_udp_datagram_survives_a_server_restart() {
    first_udp_packet_survives_a_server_restart(false).await;
}

#[tokio::test]
async fn first_udp_over_stream_packet_survives_a_server_restart() {
    first_udp_packet_survives_a_server_restart(true).await;
}

/// Control-plane calls open their own connection, with 0-RTT when a ticket is
/// cached, and must survive the rejection as well.
#[tokio::test]
async fn api_call_survives_a_server_restart() {
    use shadowquic::squic::inbound::UserManager;
    let server_addr = unused_udp_addr();
    let server = start_server(server_addr);
    let sq_client = client(server_addr);

    let before = sq_client.list_users().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let server = restart_server(server, server_addr).await;
    let after = sq_client.list_users().await;
    assert_eq!(
        format!("{before:?}"),
        format!("{after:?}"),
        "the call after a server restart must get the same answer"
    );
    server.shutdown_background();
}
