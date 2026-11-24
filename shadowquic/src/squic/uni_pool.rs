//! UDP over stream sends each destination of an association on a
//! unidirectional stream of its own. The peer allows only so many streams at
//! once, and it is the sender that closes them, so the streams of a connection
//! are kept here with a limit: the one unused for the longest time is closed
//! to make room. A destination whose stream was closed gets a new one with
//! its next datagram.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use crate::msgs::socks5::SocksAddr;

/// Streams kept open per connection. Far enough below the default limits of
/// both sides (500 towards a client, 1000 towards a server) that opening a
/// stream never waits for them; a peer configured with less is handled when
/// opening a stream blocks.
pub(crate) const UNI_POOL_LIMIT: usize = 256;

/// How long opening a stream may wait for the peer before a stream that is
/// already open is closed to make room for it.
const OPEN_PATIENCE: Duration = Duration::from_millis(100);

/// How long the room made by closing streams may take to arrive before more
/// streams are closed. The peer gives it only once it has seen the streams
/// end, a round trip later, so this is above any usual round trip.
const ROOM_PATIENCE: Duration = Duration::from_secs(1);

/// Paces the closing of streams while the peer allows no new one.
pub(crate) struct RoomPatience(Duration);

impl RoomPatience {
    pub(crate) fn new() -> Self {
        Self(OPEN_PATIENCE)
    }

    /// Returns when it is time to close streams that are open.
    pub(crate) async fn wait(&mut self) {
        tokio::time::sleep(self.0).await;
        self.0 = ROOM_PATIENCE;
    }
}

struct Slot<S> {
    /// `None` while the association is writing to the stream.
    stream: Option<S>,
    used: u64,
}

struct Inner<S> {
    associations: HashMap<u64, HashMap<SocksAddr, Slot<S>>>,
    next_association: u64,
    clock: u64,
    len: usize,
}

pub(crate) struct UniPool<S> {
    inner: Mutex<Inner<S>>,
    limit: usize,
}

impl<S> Default for UniPool<S> {
    fn default() -> Self {
        Self::with_limit(UNI_POOL_LIMIT)
    }
}

impl<S> UniPool<S> {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                associations: HashMap::new(),
                next_association: 0,
                clock: 0,
                len: 0,
            }),
            limit,
        }
    }

    /// A key for the streams of one association.
    pub(crate) fn new_association(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.next_association += 1;
        inner.next_association
    }

    /// Lends out the stream of a destination, if it has one.
    pub(crate) fn take(&self, association: u64, dst: &SocksAddr) -> Option<S> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .associations
            .get_mut(&association)?
            .get_mut(dst)?
            .stream
            .take()
    }

    /// Takes a stream back, or in for the first time. Returns the streams that
    /// are over the limit, for the caller to close.
    pub(crate) fn put(&self, association: u64, dst: &SocksAddr, stream: S) -> Vec<S> {
        let mut inner = self.inner.lock().unwrap();
        inner.clock += 1;
        let used = inner.clock;
        let slots = inner.associations.entry(association).or_default();
        match slots.get_mut(dst) {
            Some(slot) => {
                slot.stream = Some(stream);
                slot.used = used;
            }
            None => {
                slots.insert(
                    dst.clone(),
                    Slot {
                        stream: Some(stream),
                        used,
                    },
                );
                inner.len += 1;
            }
        }
        let mut closed = Vec::new();
        while inner.len > self.limit {
            match inner.remove_oldest() {
                Some(stream) => closed.push(stream),
                None => break,
            }
        }
        closed
    }

    /// Removes the streams unused for the longest time, for the caller to
    /// close, when the peer allows no new stream. A peer allows new ones only
    /// once more than an eighth of its limit has ended (quinn and noq hold
    /// the update back until then), and every stream it allows is in here.
    pub(crate) fn take_room(&self) -> Vec<S> {
        let mut inner = self.inner.lock().unwrap();
        let wanted = inner.len / 8 + 1;
        let mut closed = Vec::with_capacity(wanted);
        while closed.len() < wanted {
            match inner.remove_oldest() {
                Some(stream) => closed.push(stream),
                None => break,
            }
        }
        closed
    }

    /// Removes the streams of an association that has ended.
    pub(crate) fn remove_association(&self, association: u64) -> Vec<S> {
        let mut inner = self.inner.lock().unwrap();
        let slots = inner.associations.remove(&association).unwrap_or_default();
        inner.len -= slots.len();
        slots.into_values().filter_map(|slot| slot.stream).collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap().len
    }
}

impl<S> Inner<S> {
    fn remove_oldest(&mut self) -> Option<S> {
        let (association, dst) = self
            .associations
            .iter()
            .flat_map(|(association, slots)| {
                slots
                    .iter()
                    .filter(|(_, slot)| slot.stream.is_some())
                    .map(move |(dst, slot)| (slot.used, *association, dst))
            })
            .min_by_key(|(used, _, _)| *used)
            .map(|(_, association, dst)| (association, dst.clone()))?;
        let slots = self.associations.get_mut(&association)?;
        let slot = slots.remove(&dst)?;
        if slots.is_empty() {
            self.associations.remove(&association);
        }
        self.len -= 1;
        slot.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dst(port: u16) -> SocksAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn the_stream_unused_for_the_longest_time_is_closed_first() {
        let pool = UniPool::<u16>::with_limit(3);
        let a = pool.new_association();
        let b = pool.new_association();
        assert!(pool.put(a, &dst(1), 1).is_empty());
        assert!(pool.put(b, &dst(2), 2).is_empty());
        assert!(pool.put(a, &dst(3), 3).is_empty());
        // Using a stream makes it the newest.
        let stream = pool.take(a, &dst(1)).unwrap();
        assert!(pool.put(a, &dst(1), stream).is_empty());

        assert_eq!(pool.put(b, &dst(4), 4), vec![2]);
        assert_eq!(pool.put(b, &dst(5), 5), vec![3]);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.take(a, &dst(3)), None, "closed streams are gone");
        assert_eq!(pool.take_room(), vec![1]);
    }

    /// How many times room is made while an open that takes `wait` is pending.
    async fn closed_while_opening(wait: Duration) -> u32 {
        let open = tokio::time::sleep(wait);
        tokio::pin!(open);
        let mut patience = RoomPatience::new();
        let mut closed = 0;
        loop {
            tokio::select! {
                biased;
                _ = &mut open => return closed,
                _ = patience.wait() => closed += 1,
            }
        }
    }

    /// The peer allows a new stream only once it has seen streams end, a
    /// round trip later: closing more of them meanwhile gains nothing.
    #[tokio::test(start_paused = true)]
    async fn room_is_made_once_per_stream_opened_on_a_slow_path() {
        assert_eq!(closed_while_opening(Duration::from_millis(50)).await, 0);
        assert_eq!(closed_while_opening(Duration::from_millis(450)).await, 1);
        // Room that does not come is asked for again.
        assert_eq!(closed_while_opening(Duration::from_millis(2500)).await, 3);
    }

    /// The peer allows new streams only once more than an eighth of its
    /// limit has ended: room is made for that many at once.
    #[test]
    fn room_is_made_for_more_than_an_eighth_of_the_streams_at_once() {
        let pool = UniPool::<u16>::with_limit(64);
        let a = pool.new_association();
        for stream in 0..16 {
            pool.put(a, &dst(stream), stream);
        }
        let lent = pool.take(a, &dst(1)).unwrap();
        assert_eq!(pool.take_room(), vec![0, 2, 3], "the oldest not in use");
        assert_eq!(pool.len(), 13);
        pool.put(a, &dst(1), lent);

        let one = UniPool::<u16>::with_limit(64);
        one.put(a, &dst(1), 1);
        assert_eq!(one.take_room(), vec![1]);
        assert!(one.take_room().is_empty());
    }

    #[test]
    fn a_stream_in_use_is_not_closed() {
        let pool = UniPool::<u16>::with_limit(1);
        let a = pool.new_association();
        assert!(pool.put(a, &dst(1), 1).is_empty());
        let lent = pool.take(a, &dst(1)).unwrap();
        // Over the limit, but the only other stream is being written to.
        assert_eq!(pool.put(a, &dst(2), 2), vec![2]);
        assert!(pool.put(a, &dst(1), lent).is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn an_ended_association_takes_its_streams_along() {
        let pool = UniPool::<u16>::with_limit(8);
        let a = pool.new_association();
        let b = pool.new_association();
        pool.put(a, &dst(1), 1);
        pool.put(a, &dst(2), 2);
        pool.put(b, &dst(1), 3);
        let mut removed = pool.remove_association(a);
        removed.sort();
        assert_eq!(removed, vec![1, 2]);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.take(b, &dst(1)), Some(3));
        assert!(pool.remove_association(a).is_empty());
    }
}
