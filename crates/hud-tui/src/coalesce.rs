//! Streaming text coalescer (DR-20 §2.4).
//!
//! Per-token `TextDelta` bytes are buffered here and flushed at most every
//! 30 ms (the data tick), so the transcript pane redraws once per batch
//! rather than once per token.
//!
//! §16.1 seam: the coalescer counts 16 ms UI ticks, not `Instant`s, so
//! tests drive it by playing `Msg::Tick` — no real time passes.

/// Buffers streamed text and flushes on a tick interval.
#[derive(Debug)]
#[allow(dead_code)] // wired in PR-B (backend bridge)
pub struct Coalescer {
    buffer: String,
    last_flush: u64,
    /// Flush every N ticks (2 ticks ≈ 32 ms for the 30 ms data cadence).
    flush_every: u64,
}

impl Coalescer {
    /// Create a coalescer that flushes every `flush_every` UI ticks.
    #[allow(dead_code)] // wired in PR-B (backend bridge)
    pub fn new(flush_every: u64) -> Self {
        Self {
            buffer: String::new(),
            last_flush: 0,
            flush_every: flush_every.max(1),
        }
    }

    /// Append streamed text (already valid UTF-8 from the bridge).
    #[allow(dead_code)] // wired in PR-B
    pub fn push(&mut self, bytes: &[u8]) {
        // Use from_utf8 (not from_utf8_lossy) to avoid silent corruption of
        // multi-byte characters split across chunks. The bridge already
        // ensures valid UTF-8; if somehow invalid, skip rather than corrupt.
        if let Ok(s) = std::str::from_utf8(bytes) {
            self.buffer.push_str(s);
        }
    }

    /// True if the buffer is non-empty AND enough ticks have elapsed.
    /// `now` is the App's tick count (one tick = 16 ms).
    #[allow(dead_code)] // wired in PR-B
    pub fn should_flush(&self, now: u64) -> bool {
        !self.buffer.is_empty() && now.saturating_sub(self.last_flush) >= self.flush_every
    }

    /// Drain the buffer. Returns `Some(text)` if there was content, `None` if empty.
    /// Resets `last_flush` to `now`.
    #[allow(dead_code)] // wired in PR-B
    pub fn flush(&mut self, now: u64) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let text = std::mem::take(&mut self.buffer);
        self.last_flush = now;
        Some(text)
    }

    /// True if no buffered text is pending.
    #[allow(dead_code)] // wired in PR-B
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_flush() {
        let mut c = Coalescer::new(2);
        c.push(b"hello ");
        c.push(b"world");
        // Force flush regardless of ticks.
        let out = c.flush(10).unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn should_flush_tick_based() {
        let mut c = Coalescer::new(2);
        c.push(b"data");
        // One tick after the last flush point — not enough.
        assert!(!c.should_flush(1), "1 tick < 2-tick interval");
        // At the interval — flushes.
        assert!(c.should_flush(2), "2 ticks = interval");
        // Empty buffer never flushes.
        let empty = Coalescer::new(2);
        assert!(!empty.should_flush(100), "empty buffer never flushes");
    }

    #[test]
    fn flush_empty_returns_none() {
        let mut c = Coalescer::new(2);
        assert!(c.flush(10).is_none());
    }

    #[test]
    fn flush_clears_buffer() {
        let mut c = Coalescer::new(2);
        c.push(b"temp");
        let _ = c.flush(10);
        assert!(c.is_empty());
        assert!(c.flush(10).is_none());
    }

    #[test]
    fn push_utf8_lossy() {
        let mut c = Coalescer::new(2);
        c.push(&[0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
        assert_eq!(c.flush(10).unwrap(), "hello");
    }
}
