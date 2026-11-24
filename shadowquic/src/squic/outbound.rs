use bytes::Bytes;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender, channel};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;
use tracing::{debug, error, info, trace};

use crate::config::AuthUser;
use crate::error::SResult;
use crate::msgs::squic::{
    ConnStats, ExtOpcodeConn, ExtOpcodeUser, SQExtError, SQExtOpcode, UserStats,
};
use crate::{
    AnyTcp, AnyUdpRecv, AnyUdpSend, ProxyRequest,
    error::SError,
    msgs::{SDecode, SEncode, socks5::SocksAddr, squic::SQReq},
    quic::{EarlyDataOutcome, QuicConnection},
    squic::{handle_udp_recv_ctrl, handle_udp_send},
    utils::{copy::copy_bidirectional, poll_now},
};

use super::{
    SQConn, SQConnStats,
    early::{RecordedRead, RecordedUdpRecv, TcpRecord, UdpRecord},
    inbound::Unsplit,
};

/// Handling a proxy request and starting proxy task with given squic connection
#[hotpath::measure]
pub async fn handle_request<C: QuicConnection>(
    req: ProxyRequest,
    conn: SQConn<C>,
    over_stream: bool,
    half_close_timeout: u64,
) -> Result<(), SError> {
    let (send, recv, _id) = QuicConnection::open_bi(&conn.conn).await?;
    let early = conn.conn.early_data_outcome(&send);
    let conn_clone = conn.clone();
    tokio::spawn(
        async move {
            let _ = print_stats(&conn_clone).await;
        }
        .in_current_span(),
    );
    match req {
        crate::ProxyRequest::Tcp(mut tcp_session) => {
            info!(event = "squic:bidirectional_stream_opened", dst = %tcp_session.dst, "bistream opened for tcp");
            let header = SQReq::SQConnect(tcp_session.dst.clone());
            let u = relay_tcp(
                &conn,
                (send, recv),
                early,
                &header,
                &mut tcp_session.stream,
                half_close_timeout,
            )
            .await?;

            info!(
                upload = %format!("{} bytes", u.1),
                download = %format!("{} bytes", u.0),
                event = "squic:tcp_request_completed",
                "request finished",

            );
        }

        crate::ProxyRequest::Udp(udp_session) => {
            info!(event = "squic:bidirectional_stream_opened", bind_addr = %udp_session.bind_addr, "bistream opened for udp association");
            let header = if over_stream {
                SQReq::SQAssociatOverStream(udp_session.bind_addr.clone())
            } else {
                SQReq::SQAssociatOverDatagram(udp_session.bind_addr.clone())
            };
            let relay = relay_udp(
                &conn,
                (send, recv),
                early,
                &header,
                udp_session.recv,
                udp_session.send.clone(),
                over_stream,
            );

            let control = async {
                if udp_session.stream.is_none() {
                    return Ok(());
                }
                let mut buf = [0u8];
                udp_session
                    .stream
                    .unwrap()
                    .read_exact(&mut buf)
                    .await
                    .map_err(|x| SError::UDPSessionClosed(x.to_string()))?;
                error!(
                    event = "squic:unexpected_control_data",
                    "unexpected data received from socks control stream"
                );
                Err(SError::UDPSessionClosed(
                    "unexpected data received from socks control stream".into(),
                )) as Result<(), SError>
            };

            tokio::try_join!(relay, control)?;
            info!(
                event = "squic:udp_association_closed",
                "udp association to {} ended",
                udp_session.bind_addr.clone()
            );
        }
    }
    Ok(())
}

/// Waits for the first of the two: the early data outcome, or the end of the
/// request that was started as early data. `Ok(rejected)` when the handshake
/// has finished and `request` is still to be driven or replaced.
async fn early_data_rejected<T>(
    outcome: &mut EarlyDataOutcome,
    request: &mut (impl Future<Output = Result<T, SError>> + Unpin),
) -> Result<Result<bool, T>, SError> {
    tokio::select! {
        biased;
        rejected = &mut *outcome => Ok(Ok(rejected?)),
        ended = &mut *request => match ended {
            Ok(done) => Ok(Err(done)),
            // A rejected stream fails as soon as the handshake finishes, which
            // can be seen here before the outcome was polled again.
            Err(error) => match poll_now(&mut *outcome) {
                Some(Ok(true)) => Ok(Ok(true)),
                _ => Err(error),
            },
        },
    }
}

/// Sends `header` and relays `local` over the stream. A request sent as early
/// data that the server rejected is sent again on a new stream, together with
/// what was read from `local` so far.
async fn relay_tcp<C: QuicConnection>(
    conn: &SQConn<C>,
    (mut send, recv): (C::SendStream, C::RecvStream),
    early: Option<EarlyDataOutcome>,
    header: &SQReq,
    local: &mut AnyTcp,
    half_close_timeout: u64,
) -> Result<(u64, u64), SError> {
    const BUFFER: usize = 8 * 1024;
    let Some(mut outcome) = early else {
        header.encode(&mut send).await?;
        trace!(
            event = "squic:tcp_request_sent",
            "tcp connect req header sent"
        );
        let mut remote = Unsplit { s: send, r: recv };
        return Ok(
            copy_bidirectional(&mut remote, local, BUFFER, BUFFER, half_close_timeout).await?,
        );
    };
    let record = TcpRecord::new();
    let mut first = Box::pin(async {
        header.encode(&mut send).await?;
        let mut remote = Unsplit { s: send, r: recv };
        let mut local = RecordedRead {
            inner: &mut *local,
            record: record.clone(),
        };
        Ok(copy_bidirectional(&mut remote, &mut local, BUFFER, BUFFER, half_close_timeout).await?)
    });
    match early_data_rejected(&mut outcome, &mut first).await? {
        Err(done) => return Ok(done),
        Ok(false) => {
            record.stop();
            return first.await;
        }
        Ok(true) => drop(first),
    }
    debug!(
        event = "squic:early_data_rejected",
        "0-RTT rejected, sending the tcp request again"
    );
    let (mut send, recv, _id) = QuicConnection::open_bi(&conn.conn).await?;
    header.encode(&mut send).await?;
    send.write_all(&record.take()).await?;
    let mut remote = Unsplit { s: send, r: recv };
    Ok(copy_bidirectional(&mut remote, local, BUFFER, BUFFER, half_close_timeout).await?)
}

/// Sends `header` and runs the udp association over the stream. An
/// association started as early data that the server rejected is started
/// again on a new stream, beginning with the datagrams received so far.
async fn relay_udp<C: QuicConnection>(
    conn: &SQConn<C>,
    (mut send, recv): (C::SendStream, C::RecvStream),
    early: Option<EarlyDataOutcome>,
    header: &SQReq,
    udp_recv: AnyUdpRecv,
    udp_send: AnyUdpSend,
    over_stream: bool,
) -> Result<(), SError> {
    let Some(mut outcome) = early else {
        header.encode(&mut send).await?;
        trace!(
            event = "squic:udp_associate_request_sent",
            "udp associate req header sent"
        );
        tokio::try_join!(
            handle_udp_send(send, udp_recv, conn.clone(), over_stream),
            handle_udp_recv_ctrl(recv, udp_send, conn.clone()),
        )?;
        return Ok(());
    };
    let udp_recv = Arc::new(tokio::sync::Mutex::new(udp_recv));
    let record = UdpRecord::new();
    let recorded: AnyUdpRecv = Box::new(RecordedUdpRecv {
        inner: udp_recv.clone(),
        record: record.clone(),
        backlog: Default::default(),
    });
    let first_udp_send = udp_send.clone();
    let mut first = Box::pin(async {
        header.encode(&mut send).await?;
        tokio::try_join!(
            handle_udp_send(send, recorded, conn.clone(), over_stream),
            handle_udp_recv_ctrl(recv, first_udp_send, conn.clone()),
        )?;
        Ok(())
    });
    match early_data_rejected(&mut outcome, &mut first).await? {
        Err(()) => return Ok(()),
        Ok(false) => {
            record.stop();
            return first.await;
        }
        Ok(true) => drop(first),
    }
    debug!(
        event = "squic:early_data_rejected",
        "0-RTT rejected, starting the udp association again"
    );
    let (mut send, recv, _id) = QuicConnection::open_bi(&conn.conn).await?;
    header.encode(&mut send).await?;
    let backlog = record.take();
    let replayed: AnyUdpRecv = Box::new(RecordedUdpRecv {
        inner: udp_recv,
        record,
        backlog,
    });
    tokio::try_join!(
        handle_udp_send(send, replayed, conn.clone(), over_stream),
        handle_udp_recv_ctrl(recv, udp_send, conn.clone()),
    )?;
    Ok(())
}

/// Sends `req` on a new stream and decodes the reply. A request sent as early
/// data that the server rejected is sent once more.
async fn request_reply<C: QuicConnection, R: SDecode>(
    sq_conn: &SQConn<C>,
    req: &SQReq,
) -> SResult<R> {
    let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
    let early = sq_conn.conn.early_data_outcome(&send);
    let first = async {
        req.encode(&mut send).await?;
        R::decode(&mut recv).await
    };
    let error = match first.await {
        Ok(reply) => return Ok(reply),
        Err(error) => error,
    };
    let rejected = match early {
        Some(outcome) => matches!(outcome.await, Ok(true)),
        None => false,
    };
    if !rejected {
        return Err(error);
    }
    let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
    req.encode(&mut send).await?;
    R::decode(&mut recv).await
}

/// Helper function to create new stream for proxy dstination
#[allow(dead_code)]
pub async fn connect_tcp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
) -> Result<Unsplit<C::SendStream, C::RecvStream>, crate::error::SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!(event = "squic:bidirectional_stream_opened", dst = %dst, "bistream opened for tcp");
    let req = SQReq::SQConnect(dst.clone());
    req.encode(&mut send).await?;
    trace!(
        event = "proxy:tcp_request_sent",
        "tcp connect req header sent"
    );

    Ok(Unsplit { s: send, r: recv })
}

pub async fn get_peer_conn_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<ConnStats, SQExtError>> {
    let req = SQReq::SQExtension(SQExtOpcode::Conn(ExtOpcodeConn::GetConnStats));
    request_reply(sq_conn, &req).await
}

pub async fn add_user<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
    password: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(
        sq_conn,
        ExtOpcodeUser::AddUser(AuthUser {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
    )
    .await
}

pub async fn remove_user<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::RemoveUser(username.to_owned())).await
}

pub async fn list_users<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<Vec<String>, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ListUsers).await
}

pub async fn get_user_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<UserStats, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::GetUserStats(username.to_owned())).await
}

pub async fn get_all_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<Vec<UserStats>, SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::GetAllStats).await
}

pub async fn kill_user_conns<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::KillUserConn(username.to_owned())).await
}

pub async fn clear_user_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    username: &str,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ClearUserStats(username.to_owned())).await
}

pub async fn clear_all_stats<C: QuicConnection>(
    sq_conn: &SQConn<C>,
) -> SResult<Result<(), SQExtError>> {
    send_user_extension(sq_conn, ExtOpcodeUser::ClearAllStats).await
}

async fn send_user_extension<C: QuicConnection, R: SDecode>(
    sq_conn: &SQConn<C>,
    opcode: ExtOpcodeUser,
) -> SResult<Result<R, SQExtError>> {
    let req = SQReq::SQExtension(SQExtOpcode::User(opcode));
    request_reply(sq_conn, &req).await
}

async fn print_stats<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<()> {
    let Ok(_refresh) = sq_conn.stats_refresh.try_lock() else {
        return Ok(()); // if we can't get the lock, it means another task is already printing stats, so we skip this one.
    };
    if sq_conn
        .stats
        .lock()
        .await
        .as_ref()
        .is_some_and(|stats| stats.time.elapsed() < Duration::from_secs(10))
    {
        return Ok(());
    }

    let uplink = sq_conn.get_conn_stats().ok_or(SError::ProtocolUnimpl)?;
    log_conn_stats(&uplink, "uplink");

    let downlink =
        match tokio::time::timeout(Duration::from_secs(10), get_peer_conn_stats(sq_conn)).await {
            Ok(Ok(Ok(stats))) => stats,
            _ => {
                trace!(
                    event = "recovery:peer_metrics_unavailable",
                    "failed to get peer conn stats. Api may not be implemented"
                );
                return Err(SError::ProtocolUnimpl);
            }
        };
    log_conn_stats(&downlink, "downlink");

    *sq_conn.stats.lock().await = Some(SQConnStats {
        uplink,
        downlink,
        time: Instant::now(),
        birth_time: sq_conn.birth_time,
    });
    Ok(())
}

fn log_conn_stats(stats: &ConnStats, direction: &'static str) {
    info!(event = "recovery:metrics_updated",
        packet_loss_rate=%format!("{:.2}%", stats.lost_packets as f32 / (stats.sent_packets + 1) as f32 * 100.0),
        rtt = %format!("{:.1}ms", stats.rtt),
        mtu = stats.current_mtu,
        "{} connection stats",
        direction
    );
}

/// associate a udp socket in the remote server
/// return a socket-like send, recv handle.
#[allow(dead_code)]
pub async fn associate_udp<C: QuicConnection>(
    sq_conn: &SQConn<C>,
    dst: SocksAddr,
    over_stream: bool,
) -> Result<(Sender<(Bytes, SocksAddr)>, Receiver<(Bytes, SocksAddr)>), SError> {
    let conn = sq_conn;

    let (mut send, recv, _id) = conn.open_bi().await?;

    info!(event = "squic:bidirectional_stream_opened", bind_addr = %dst, "bistream opened for udp association");

    let req = if over_stream {
        SQReq::SQAssociatOverStream(dst.clone())
    } else {
        SQReq::SQAssociatOverDatagram(dst.clone())
    };
    req.encode(&mut send).await?;
    let (local_send, udp_recv) = channel::<(Bytes, SocksAddr)>(10);
    let (udp_send, local_recv) = channel::<(Bytes, SocksAddr)>(10);
    let local_send = Arc::new(local_send);
    let fut2 = handle_udp_recv_ctrl(recv, local_send, conn.clone());
    let fut1 = handle_udp_send(send, Box::new(local_recv), conn.clone(), over_stream);

    tokio::spawn(
        async {
            match tokio::try_join!(fut1, fut2) {
                Err(e) => error!(
                    event = "squic:udp_association_failed",
                    "udp association ended due to {}", e
                ),
                Ok(_) => trace!(
                    event = "squic:udp_association_closed",
                    "udp association ended"
                ),
            }
        }
        .in_current_span(),
    );

    Ok((udp_send, udp_recv))
}
