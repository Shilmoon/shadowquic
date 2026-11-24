use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static REQ_CNT: AtomicU32 = AtomicU32::new(0);

pub(crate) fn fetch_add_req_cnt() -> u32 {
    REQ_CNT.fetch_add(1, Ordering::Relaxed)
}

tokio::task_local! {
    pub(crate) static REQ_ID: u32;
}

/// At most one log line per 100 ms, for lines that anyone on the network can
/// provoke, such as failed handshakes. Each place that logs has a limit of its
/// own, so that a flood in one place does not silence another.
pub(crate) struct LogRateLimit {
    next_ms: AtomicU64,
    held_back: AtomicU64,
}

impl LogRateLimit {
    pub(crate) const fn new() -> Self {
        Self {
            next_ms: AtomicU64::new(0),
            held_back: AtomicU64::new(0),
        }
    }

    /// `Some(n)` when a line may be logged now, where `n` lines were held
    /// back since the last one.
    pub(crate) fn allow(&self) -> Option<u64> {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        self.allow_at(
            START
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_millis() as u64,
        )
    }

    fn allow_at(&self, now_ms: u64) -> Option<u64> {
        let next = self.next_ms.load(Ordering::Relaxed);
        if now_ms >= next
            && self
                .next_ms
                .compare_exchange(next, now_ms + 100, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.held_back.swap(0, Ordering::Relaxed))
        } else {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LogRateLimit;

    #[test]
    fn lines_held_back_are_counted_and_limits_are_independent() {
        let (a, b) = (LogRateLimit::new(), LogRateLimit::new());
        assert_eq!(a.allow_at(0), Some(0));
        assert_eq!(a.allow_at(50), None);
        assert_eq!(a.allow_at(99), None);
        // A flood in one place leaves the other free to log.
        assert_eq!(b.allow_at(50), Some(0));
        assert_eq!(a.allow_at(100), Some(2));
        assert_eq!(a.allow_at(200), Some(0));
    }
}
