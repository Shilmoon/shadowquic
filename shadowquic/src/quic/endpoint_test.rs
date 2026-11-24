//! `ClientEndpoint` replaces its endpoint only by one that is of more use.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use super::{ClientEndpoint, QuicClient, QuicErrorRepr};
use crate::{error::SResult, utils::socket_opt::SocketFactory};

/// Reaches IPv4 only and records on which endpoint a connection was asked for.
struct Fake {
    id: usize,
    asked: Arc<Mutex<Vec<usize>>>,
}

#[async_trait]
impl QuicClient for Fake {
    type C = crate::shadowquic::Connection;
    type SC = ();
    async fn new(_cfg: &()) -> SResult<Self> {
        unreachable!()
    }
    async fn new_with_socket_factory(_cfg: &(), _f: Arc<dyn SocketFactory>) -> SResult<Self> {
        unreachable!()
    }
    async fn connect(&self, _addr: SocketAddr, _name: &str) -> Result<Self::C, QuicErrorRepr> {
        self.asked.lock().unwrap().push(self.id);
        Err(QuicErrorRepr::JlsAuthFailed)
    }
    fn can_reach(&self, addr: &SocketAddr) -> bool {
        addr.is_ipv4()
    }
}

#[tokio::test]
async fn endpoint_is_kept_when_a_new_one_reaches_no_address_either() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let created = Arc::new(Mutex::new(0));
    let create = || {
        let (asked, created) = (asked.clone(), created.clone());
        async move {
            let mut created = created.lock().unwrap();
            *created += 1;
            Ok(Fake {
                id: *created,
                asked,
            })
        }
    };
    let endpoint = ClientEndpoint::<Fake>::new();
    let v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let v6: SocketAddr = "[::1]:443".parse().unwrap();

    let _ = endpoint.connect(&[v4], "name", create).await;
    // No endpoint reaches this one: the first endpoint, which holds the
    // session tickets of the server, stays.
    let _ = endpoint.connect(&[v6], "name", create).await;
    let _ = endpoint.connect(&[v4], "name", create).await;
    assert_eq!(*asked.lock().unwrap(), [1, 1, 1]);
}
