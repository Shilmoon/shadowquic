use std::{path::PathBuf, time::Duration};

use shadowquic::{
    Inbound, Manager,
    config::{
        AuthUser, CongestionControl, JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg,
        default_initial_mtu,
    },
    direct::outbound::DirectOut,
    msgs::socks5::SocksAddr,
    shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    squic::{inbound::UserManager, outbound::connect_tcp},
    utils::user_store::{PersistedUser, UserStore, load_store, save_store},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const RESTORE_SERVER_ADDR: &str = "127.0.0.1:24458";
const FLUSH_SERVER_ADDR: &str = "127.0.0.1:24468";
const TCP_BYTES: usize = 4096;

fn store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "shadowquic-user-store-{}-{}.yaml",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn server_cfg(addr: &str, store: PathBuf, flush_interval: u64) -> ShadowQuicServerCfg {
    ShadowQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: addr.parse().unwrap(),
        users: vec![
            AuthUser {
                username: "admin".into(),
                password: "admin-pass".into(),
            },
            AuthUser {
                username: "bob".into(),
                password: "bob-pass".into(),
            },
        ],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        zero_rtt: false,
        gso: false,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        user_store: Some(store),
        store_flush_interval: flush_interval,
        ..Default::default()
    }
}

fn client_at(addr: &str, username: &str, password: &str) -> ShadowQuicClient {
    ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            username: username.into(),
            password: password.into(),
            addr: addr.into(),
            server_name: "localhost".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1200,
            congestion_control: CongestionControl::Bbr,
            zero_rtt: false,
            gso: false,
            over_stream: true,
            ..Default::default()
        },
        std::sync::Arc::new(shadowquic::dns::ResolverManager::new()),
    )
}

#[tokio::test]
async fn user_store_restores_users_and_stats_and_persists_api_changes() {
    let path = store_path("restore");

    // Simulate a previous run: a user added via API with accumulated traffic.
    save_store(
        &path,
        &UserStore {
            users: vec![PersistedUser {
                username: "carol".into(),
                password: "carol-pass".into(),
                tcp_sent: 111,
                tcp_recv: 222,
                udp_sent: 333,
                udp_recv: 444,
            }],
        },
    )
    .unwrap();

    let server = ShadowQuicServer::new(server_cfg(RESTORE_SERVER_ADDR, path.clone(), 0))
        .await
        .unwrap();
    server.init().await.expect("server init failed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let admin = client_at(RESTORE_SERVER_ADDR, "admin", "admin-pass");

    // Store-only user is merged into the auth set.
    let mut users = admin.list_users().await.unwrap();
    users.sort();
    assert_eq!(users, vec!["admin", "bob", "carol"]);
    client_at(RESTORE_SERVER_ADDR, "carol", "carol-pass")
        .get_conn()
        .await
        .expect("restored user should connect");

    // Persisted traffic counters are restored.
    let stats = admin.get_user_stats("carol").await.unwrap();
    assert_eq!(stats.tcp_sent, 111);
    assert_eq!(stats.tcp_recv, 222);
    assert_eq!(stats.udp_sent, 333);
    assert_eq!(stats.udp_recv, 444);

    // add-user via API is flushed to disk immediately.
    admin
        .add_user(AuthUser {
            username: "alice".into(),
            password: "alice-pass".into(),
        })
        .await
        .unwrap();
    let store = load_store(&path).unwrap().expect("store file should exist");
    let mut stored: Vec<_> = store.users.iter().map(|u| u.username.as_str()).collect();
    stored.sort();
    assert_eq!(stored, vec!["admin", "alice", "bob", "carol"]);
    let carol = store
        .users
        .iter()
        .find(|u| u.username == "carol")
        .expect("carol should be persisted");
    assert_eq!(carol.tcp_sent, 111);
    assert_eq!(carol.udp_recv, 444);

    // remove-user via API is flushed to disk immediately.
    admin.remove_user("carol").await.unwrap();
    let store = load_store(&path).unwrap().expect("store file should exist");
    assert!(!store.users.iter().any(|u| u.username == "carol"));

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn user_store_periodic_flush_writes_traffic_stats() {
    let path = store_path("flush");

    let tcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp echo listener should bind");
    let tcp_addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        let mut buf = vec![0; TCP_BYTES];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
    });

    let sq_server = ShadowQuicServer::new(server_cfg(FLUSH_SERVER_ADDR, path.clone(), 1))
        .await
        .unwrap();
    let server = Manager::single(Box::new(sq_server), std::sync::Arc::<DirectOut>::default());
    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let bob = client_at(FLUSH_SERVER_ADDR, "bob", "bob-pass");
    let bob_conn = bob.get_conn().await.expect("bob should connect");
    let payload = vec![0x5a; TCP_BYTES];
    let mut tcp_stream = connect_tcp(&bob_conn, SocksAddr::from(tcp_addr))
        .await
        .expect("tcp request should open");
    tcp_stream.write_all(&payload).await.unwrap();
    tcp_stream.flush().await.unwrap();
    let mut echo = vec![0; TCP_BYTES];
    tcp_stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo, payload);

    // The periodic flush (1s interval) should persist bob's traffic to disk.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Some(store)) = load_store(&path)
                && let Some(bob) = store.users.iter().find(|u| u.username == "bob")
                && bob.tcp_sent == TCP_BYTES as u64
                && bob.tcp_recv == TCP_BYTES as u64
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("periodic flush should persist traffic stats");

    let _ = std::fs::remove_file(&path);
}

/// Saves that overlap (an API call and the periodic flush) must each succeed,
/// and a reader must never see a half-written store.
#[test]
fn overlapping_saves_all_succeed_and_readers_see_whole_stores() {
    const USERS: usize = 200;
    let path = store_path("overlapping");
    let store = |writer: usize| UserStore {
        users: (0..USERS)
            .map(|i| PersistedUser {
                username: format!("user-{writer}-{i}"),
                password: "password".repeat(8),
                ..Default::default()
            })
            .collect(),
    };
    save_store(&path, &store(0)).unwrap();
    let writers: Vec<_> = (0..8)
        .map(|writer| {
            let path = path.clone();
            let store = store(writer);
            std::thread::spawn(move || {
                for _ in 0..200 {
                    save_store(&path, &store).expect("save failed");
                    let seen = load_store(&path).expect("unreadable store").unwrap();
                    assert_eq!(seen.users.len(), USERS, "half-written store");
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let left_over: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().into_string().unwrap())
        })
        .filter(|name| {
            name.starts_with(path.file_stem().unwrap().to_str().unwrap()) && name.ends_with(".tmp")
        })
        .collect();
    assert!(left_over.is_empty(), "temporary files left: {left_over:?}");
    let _ = std::fs::remove_file(&path);
}

/// A save that was cut short, by a crash or a kill, leaves its temporary file
/// behind, with the users' passwords in it. The next start removes it.
#[test]
fn temporary_files_of_an_earlier_run_are_removed_on_load() {
    let path = store_path("stale-tmp");
    let sibling = |suffix: &str| {
        let mut name = path.file_name().unwrap().to_os_string();
        name.push(suffix);
        path.with_file_name(name)
    };
    let orphan = sibling(".4000000000.3.tmp");
    let own = sibling(&format!(".{}.4000000000.tmp", std::process::id()));
    let unrelated = sibling(".notes.tmp");
    for file in [&orphan, &own, &unrelated] {
        std::fs::write(file, "users: []").unwrap();
    }

    assert!(load_store(&path).unwrap().is_none());
    assert!(!orphan.exists(), "the file of an earlier run stays");
    assert!(own.exists(), "a save of this process may be under way");
    assert!(unrelated.exists(), "not a file of ours");
    for file in [&own, &unrelated] {
        let _ = std::fs::remove_file(file);
    }
}
