//! What a SOCKS server answers is outside input: a refusal is an error, and no
//! answer may panic the outbound.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};

use super::outbound::SocksClient;
use crate::{
    Outbound, ProxyRequest, UdpSession,
    config::SocksClientCfg,
    dns::ResolverManager,
    error::SError,
    msgs::{SDecode, socks5::CmdReq, socks5::SocksAddr},
};

type Packet = (Bytes, SocksAddr);

/// A SOCKS server that selects `method` and answers the request with `reply`.
async fn upstream(method: u8, reply: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        s.write_all(&[5, method]).await.unwrap();
        if CmdReq::decode(&mut s).await.is_ok() {
            s.write_all(&reply).await.unwrap();
        }
        // The association lives as long as its control connection.
        let _ = s.read_u8().await;
    });
    addr
}

fn client(server: SocketAddr, username: Option<&str>) -> SocksClient {
    SocksClient::new(
        SocksClientCfg {
            half_close_timeout: 0,
            #[cfg(feature = "dns-server")]
            dns: None,
            #[cfg(feature = "dns-server")]
            addr_resolver: None,
            tag: "outbound".into(),
            addr: server.to_string(),
            username: username.map(Into::into),
            password: None,
            socket_opt: Default::default(),
        },
        Arc::new(ResolverManager::new()),
    )
}

fn association() -> (ProxyRequest, mpsc::Sender<Packet>, mpsc::Receiver<Packet>) {
    let (to_proxy, from_app) = mpsc::channel::<Packet>(4);
    let (to_app, from_proxy) = mpsc::channel::<Packet>(4);
    let unspecified: SocksAddr = "0.0.0.0:0".parse().unwrap();
    let session = UdpSession {
        recv: Box::new(from_app) as crate::AnyUdpRecv,
        send: Arc::new(to_app) as crate::AnyUdpSend,
        stream: None,
        bind_addr: unspecified.clone(),
        dst: unspecified,
        src_addr: None,
        user_context: Default::default(),
    };
    (ProxyRequest::Udp(session), to_proxy, from_proxy)
}

/// Runs the outbound in a task of its own, so that a panic is seen as one.
async fn outcome(client: SocksClient, request: ProxyRequest) -> Option<Result<(), SError>> {
    let task = tokio::spawn(async move { client.handle(request).await });
    match tokio::time::timeout(Duration::from_secs(10), task).await {
        Ok(joined) => Some(joined.expect("the outbound panicked")),
        Err(_) => None,
    }
}

fn reply(rep: u8, relay: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(relay) = relay else {
        unreachable!()
    };
    let mut reply = vec![5, rep, 0, 1];
    reply.extend_from_slice(&relay.ip().octets());
    reply.extend_from_slice(&relay.port().to_be_bytes());
    reply
}

#[tokio::test]
async fn refused_udp_associate_is_an_error() {
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 7: command not supported.
    let server = upstream(0, reply(7, relay.local_addr().unwrap())).await;
    let (request, _to_proxy, _from_proxy) = association();
    let result = outcome(client(server, None), request).await;
    assert!(
        matches!(result, Some(Err(SError::SocksError(_)))),
        "{result:?}"
    );
}

#[tokio::test]
async fn unresolvable_relay_address_is_an_error() {
    let mut reply = vec![5, 0, 0, 3, 13];
    reply.extend_from_slice(b"relay.invalid");
    reply.extend_from_slice(&53u16.to_be_bytes());
    let server = upstream(0, reply).await;
    let (request, _to_proxy, _from_proxy) = association();
    let result = outcome(client(server, None), request).await;
    assert!(matches!(result, Some(Err(_))), "{result:?}");
}

#[tokio::test]
async fn username_without_password_is_an_error() {
    let server = upstream(2, Vec::new()).await;
    let (request, _to_proxy, _from_proxy) = association();
    let result = outcome(client(server, Some("user")), request).await;
    assert!(
        matches!(result, Some(Err(SError::SocksError(_)))),
        "{result:?}"
    );
}

/// A server listening on every address answers with the wildcard address and
/// means the address it was reached at.
#[tokio::test]
async fn wildcard_relay_address_means_the_server_itself() {
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = relay.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = relay.recv_from(&mut buf).await {
            let _ = relay.send_to(&buf[..n], peer).await;
        }
    });
    // [::]:port
    let mut reply = vec![5, 0, 0, 4];
    reply.extend_from_slice(&[0u8; 16]);
    reply.extend_from_slice(&port.to_be_bytes());
    let server = upstream(0, reply).await;

    let (request, to_proxy, mut from_proxy) = association();
    let socks = client(server, None);
    tokio::spawn(async move { socks.handle(request).await });
    let dst: SocksAddr = "192.0.2.1:7".parse().unwrap();
    to_proxy
        .send((Bytes::from_static(b"ping"), dst.clone()))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), from_proxy.recv())
        .await
        .expect("no datagram came back through the relay")
        .unwrap();
    assert_eq!(echoed, (Bytes::from_static(b"ping"), dst));
}
