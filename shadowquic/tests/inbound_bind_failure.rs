//! An inbound that cannot bind its address reports an error to its caller,
//! which decides what to do, instead of panicking inside the library.
use shadowquic::{
    config::{AuthUser, JlsUpstream, ShadowQuicServerCfg, SunnyQuicServerCfg},
    shadowquic::inbound::ShadowQuicServer,
    sunnyquic::inbound::SunnyQuicServer,
};

/// TEST-NET-1 (RFC 5737) is never a local address.
const NOT_LOCAL: &str = "192.0.2.1:4433";

fn users() -> Vec<AuthUser> {
    vec![AuthUser {
        username: "user".into(),
        password: "pass".into(),
    }]
}

#[tokio::test]
async fn shadowquic_inbound_returns_the_bind_error() {
    let result = ShadowQuicServer::new(ShadowQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: NOT_LOCAL.parse().unwrap(),
        users: users(),
        jls_upstream: JlsUpstream {
            addr: "127.0.0.1:9".into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    assert!(matches!(result, Err(shadowquic::error::SError::Io(_))));
}

#[tokio::test]
async fn sunnyquic_inbound_returns_the_bind_error() {
    let result = SunnyQuicServer::new(SunnyQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: NOT_LOCAL.parse().unwrap(),
        users: users(),
        server_name: "localhost".into(),
        cert_path: "../assets/certs/localhost.crt".into(),
        key_path: "../assets/certs/localhost.key".into(),
        ..Default::default()
    })
    .await;
    assert!(matches!(result, Err(shadowquic::error::SError::Io(_))));
}
