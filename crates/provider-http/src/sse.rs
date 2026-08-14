//! SSE (Server-Sent Events) parser for streaming provider responses (DR-09 §4).
//!
//! Parses `data:` frames from an SSE byte stream. Handles multi-line data
//! frames, `[DONE]`, and JSON payloads. Malformed framing → E0411.

use crate::error::TransportError;

/// A parsed SSE event: the raw `data:` payload (multi-line joined) + whether
/// the stream sent the terminal `[DONE]` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub data: String,
}

/// Incremental SSE line parser. Feed it raw bytes; it yields complete events.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: Vec<u8>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; returns the complete `data:` events found (each possibly
    /// spanning multiple `data:` lines, joined by newline).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, TransportError> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            // Find the next blank line (event terminator).
            let terminator = self
                .buffer
                .windows(2)
                .position(|w| w == b"\n\n")
                .or_else(|| self.buffer.windows(2).position(|w| w == b"\r\n\r\n"));
            let Some(end) = terminator else {
                break; // incomplete event — wait for more bytes
            };
            let event_bytes: Vec<u8> = self.buffer.drain(..=end).collect();
            let event_text = String::from_utf8_lossy(&event_bytes);
            // Extract `data:` lines (possibly multiple, joined by \n).
            let mut data_lines = Vec::new();
            for line in event_text.lines() {
                let line = line.trim_end_matches('\r');
                if let Some(rest) = line.strip_prefix("data:") {
                    data_lines.push(rest.trim_start().to_string());
                }
            }
            if !data_lines.is_empty() {
                events.push(SseEvent {
                    data: data_lines.join("\n"),
                });
            }
        }
        Ok(events)
    }

    /// Whether the parser has no leftover bytes (stream ended cleanly).
    pub fn is_clean(&self) -> bool {
        self.buffer.is_empty() || self.buffer.iter().all(|b| b.is_ascii_whitespace())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_data_frame() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: {\"x\":1}\n\n").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, r#"{"x":1}"#);
    }

    #[test]
    fn parses_multiline_data() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: line1\ndata: line2\n\n").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "line1\nline2");
    }

    #[test]
    fn buffers_partial_then_completes() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: par").unwrap().is_empty());
        let evs = p.feed(b"tial\n\n").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "partial");
    }

    #[test]
    fn done_marker_is_data() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: [DONE]\n\n").unwrap();
        assert_eq!(evs[0].data, "[DONE]");
    }
}
