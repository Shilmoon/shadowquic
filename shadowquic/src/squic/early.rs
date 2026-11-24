//! Requests sent before the handshake has finished travel as 0-RTT data, which
//! the server may reject, for instance after a restart that lost its
//! resumption state. The stream the request was opened on is then gone, along
//! with what was written to it. The types here keep a copy of what a request
//! read from its local side during that window, so that the request can be
//! sent again on a new stream instead of failing.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{AnyUdpRecv, UdpRecv, error::SError, msgs::socks5::SocksAddr};

/// How much is kept for a replay. The early data itself is limited to the
/// initial congestion window, so this is never the bottleneck.
const EARLY_RECORD_LIMIT: usize = 64 * 1024;

#[derive(Default)]
struct TcpRecordState {
    data: Vec<u8>,
    /// A reader that reached the limit and waits for the handshake to finish.
    parked: Option<Waker>,
}

/// What a [`RecordedRead`] has read so far.
#[derive(Clone)]
pub(crate) struct TcpRecord {
    recording: Arc<AtomicBool>,
    state: Arc<Mutex<TcpRecordState>>,
}

impl TcpRecord {
    pub(crate) fn new() -> Self {
        Self {
            recording: Arc::new(AtomicBool::new(true)),
            state: Default::default(),
        }
    }
    /// The early data was accepted: stop keeping copies.
    pub(crate) fn stop(&self) {
        self.recording.store(false, Relaxed);
        let mut state = self.state.lock().unwrap();
        state.data = Vec::new();
        if let Some(waker) = state.parked.take() {
            waker.wake();
        }
    }
    /// The bytes to send again.
    pub(crate) fn take(&self) -> Vec<u8> {
        self.recording.store(false, Relaxed);
        std::mem::take(&mut self.state.lock().unwrap().data)
    }
}

/// A stream whose reads are copied into a [`TcpRecord`] while it records.
/// Reading pauses at the limit until the record is stopped.
pub(crate) struct RecordedRead<'a, S: ?Sized> {
    pub(crate) inner: &'a mut S,
    pub(crate) record: TcpRecord,
}

impl<S: AsyncRead + Unpin + ?Sized> AsyncRead for RecordedRead<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.record.recording.load(Relaxed) {
            return Pin::new(&mut *self.inner).poll_read(cx, buf);
        }
        {
            let mut state = self.record.state.lock().unwrap();
            // Checked again under the lock: `stop` wakes whoever is parked.
            if self.record.recording.load(Relaxed) && state.data.len() >= EARLY_RECORD_LIMIT {
                state.parked = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut *self.inner).poll_read(cx, buf))?;
        if self.record.recording.load(Relaxed) {
            let mut state = self.record.state.lock().unwrap();
            state.data.extend_from_slice(&buf.filled()[before..]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin + ?Sized> AsyncWrite for RecordedRead<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct UdpRecordState {
    packets: VecDeque<(Bytes, SocksAddr)>,
    bytes: usize,
}

/// The datagrams a [`RecordedUdpRecv`] has received so far. Datagrams beyond
/// the limit are not kept: losing them on a rejection is ordinary UDP loss.
#[derive(Clone)]
pub(crate) struct UdpRecord {
    recording: Arc<AtomicBool>,
    state: Arc<Mutex<UdpRecordState>>,
}

impl UdpRecord {
    pub(crate) fn new() -> Self {
        Self {
            recording: Arc::new(AtomicBool::new(true)),
            state: Default::default(),
        }
    }
    /// The early data was accepted: stop keeping copies.
    pub(crate) fn stop(&self) {
        self.recording.store(false, Relaxed);
        *self.state.lock().unwrap() = Default::default();
    }
    /// The datagrams to send again.
    pub(crate) fn take(&self) -> VecDeque<(Bytes, SocksAddr)> {
        self.recording.store(false, Relaxed);
        std::mem::take(&mut self.state.lock().unwrap().packets)
    }
}

/// A datagram source that survives the association reading from it: the
/// source is shared, so a second association can take over, starting with the
/// datagrams in `backlog`.
pub(crate) struct RecordedUdpRecv {
    pub(crate) inner: Arc<tokio::sync::Mutex<AnyUdpRecv>>,
    pub(crate) record: UdpRecord,
    pub(crate) backlog: VecDeque<(Bytes, SocksAddr)>,
}

#[async_trait]
impl UdpRecv for RecordedUdpRecv {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        if let Some(packet) = self.backlog.pop_front() {
            return Ok(packet);
        }
        let packet = self.inner.lock().await.recv_from().await?;
        if self.record.recording.load(Relaxed) {
            let mut state = self.record.state.lock().unwrap();
            if state.bytes + packet.0.len() <= EARLY_RECORD_LIMIT {
                state.bytes += packet.0.len();
                state.packets.push_back(packet.clone());
            }
        }
        Ok(packet)
    }
}
