use std::{io::Cursor, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::OnceCell};
use tracing::debug;

use crate::{
    UdpRecv, UdpSend,
    error::SError,
    msgs::socks5::{self, SocksAddr, UdpReqHeader},
};

use crate::msgs::{SDecode, SEncode};
pub mod inbound;
pub mod outbound;
#[cfg(test)]
mod outbound_tests;

#[derive(Clone)]
pub struct UdpSocksWrap(Arc<UdpSocket>, OnceCell<SocketAddr>); // remote addr
#[async_trait]
impl UdpRecv for UdpSocksWrap {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        // A datagram that is truncated, fragmented or carries an unknown address
        // type is dropped (RFC 1928 section 7); the association goes on.
        loop {
            let (datagram, dst) = crate::utils::recv_udp_datagram(&self.0).await?;
            let mut cur = Cursor::new(&datagram[..]);
            let Ok(mut req) = socks5::UdpReqHeader::decode(&mut cur).await else {
                debug!(
                    event = "socks:malformed_datagram_dropped",
                    "dropping malformed udp datagram"
                );
                continue;
            };
            req.dst.canonicalize_ip();
            if req.frag != 0 {
                debug!(
                    event = "socks:fragmented_datagram_dropped",
                    "dropping fragmented udp datagram "
                );
                continue;
            }
            let headsize: usize = cur.position().try_into().unwrap();
            self.1
                .get_or_init(|| async {
                    let _ = self.0.connect(dst).await;
                    dst
                })
                .await;
            return Ok((datagram.slice(headsize..), req.dst));
        }
    }
}
#[async_trait]
impl UdpSend for UdpSocksWrap {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let payload_len = buf.len();
        let reply = UdpReqHeader {
            rsv: 0,
            frag: 0,
            dst: addr,
        };
        let mut buf_new = BytesMut::with_capacity(1600);
        let header = Vec::new();
        let mut cur = Cursor::new(header);
        reply.encode(&mut cur).await?;
        let header = cur.into_inner();
        buf_new.put(Bytes::from(header));
        buf_new.put(buf);

        match self.0.send(&buf_new).await {
            Ok(_) => Ok(payload_len),
            // Does not fit a datagram once the header is added: drop it, as a
            // UDP relay does, instead of ending the association.
            Err(error) if crate::utils::is_datagram_too_large(&error) => {
                debug!(
                    event = "socks:oversized_datagram_dropped",
                    "dropping udp datagram of {} bytes", payload_len
                );
                Ok(0)
            }
            Err(error) => Err(error.into()),
        }
    }
}
