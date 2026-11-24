//! A client that opens a UDP association and closes it without sending a
//! datagram must not leave sockets behind. Alone in this binary: it counts the
//! descriptors of the whole process.
#![cfg(unix)]
use std::{net::SocketAddr, sync::Arc, time::Duration};

use shadowquic::{
    Manager, config::SocksServerCfg, direct::outbound::DirectOut, socks::inbound::SocksServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

#[tokio::test]
async fn association_closed_before_first_datagram_is_released() {
    let socks_addr: SocketAddr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let socks_server = SocksServer::new(SocksServerCfg {
        tag: "inbound".into(),
        default_outbound: None,
        bind_addr: socks_addr,
        users: vec![],
    })
    .await
    .unwrap();
    tokio::spawn(Manager::single(Box::new(socks_server), Arc::new(DirectOut::default())).run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let before = open_fds();
    for _ in 0..50 {
        let mut ctl = TcpStream::connect(socks_addr).await.unwrap();
        ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        ctl.read_exact(&mut method).await.unwrap();
        ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        ctl.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "udp associate refused");
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(("127.0.0.1", relay_port)).await.unwrap();
        drop(udp);
        drop(ctl);
    }
    let mut after = open_fds();
    for _ in 0..100 {
        if after <= before + 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        after = open_fds();
    }
    assert!(
        after <= before + 10,
        "{} descriptors leaked by 50 closed associations",
        after.saturating_sub(before)
    );
}
