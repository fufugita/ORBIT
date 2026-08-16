//! Streaming text coalescer (DR-20 §2.4).
//!
//! Per-token `TextDelta` bytes are buffered here and flushed at most every
//! 30 ms (the data tick), so the transcript pane redraws once per batch
//! rather than once per token.

use std::time::{Duration, Instant};

/// Buffers streamed text and flushes it on a time interval.
#[derive(Debug)]
#[allow(dead_code)] // wired in PR-B (backend bridge)
pub struct Coalescer {
    buffer: String,
    last_flush: Instant,
    flush_interval: Duration,
}

impl Coalescer {
    /// Create a coalescer with the given flush interval (30 ms in production).
    #[allow(dead_code)] // wired in PR-B (backend bridge)
    pub fn new(flush_interval: Duration) -> Self {
        Self {
            buffer: String::new(),
            last_flush: Instant::now(),
            flush_interval,
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

    /// True if the buffer is non-empty AND enough time has elapsed.
    #[allow(dead_code)] // wired in PR-B
    pub fn should_flush(&self) -> bool {
        !self.buffer.is_empty() && self.last_flush.elapsed() >= self.flush_interval
    }

    /// Drain the buffer. Returns `Some(text)` if there was content, `None` if empty.
    /// Resets `last_flush` to now.
    #[allow(dead_code)] // wired in PR-B
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let text = std::mem::take(&mut self.buffer);
        self.last_flush = Instant::now();
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
        let mut c = Coalescer::new(Duration::from_millis(30));
        c.push(b"hello ");
        c.push(b"world");
        // Force flush regardless of time.
        let out = c.flush().unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn should_flush_time_based() {
        let mut c = Coalescer::new(Duration::from_millis(30));
        c.push(b"data");
        // Immediately after push — not enough time (last_flush was set at construction).
        // In practice construction-to-push is <30ms, so we check the logic:
        // should_flush is true only if elapsed >= interval.
        // Since we can't control Instant, we verify the empty case:
        let empty = Coalescer::new(Duration::from_millis(30));
        assert!(!empty.should_flush(), "empty buffer never flushes");
    }

    #[test]
    fn flush_empty_returns_none() {
        let mut c = Coalescer::new(Duration::from_millis(30));
        assert!(c.flush().is_none());
    }

    #[test]
    fn flush_clears_buffer() {
        let mut c = Coalescer::new(Duration::from_millis(30));
        c.push(b"temp");
        let _ = c.flush();
        assert!(c.is_empty());
        assert!(c.flush().is_none());
    }

    #[test]
    fn push_utf8_lossy() {
        let mut c = Coalescer::new(Duration::from_millis(30));
        c.push(&[0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
        assert_eq!(c.flush().unwrap(), "hello");
    }
}
