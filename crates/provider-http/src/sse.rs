//! Bounded incremental Server-Sent Events framing.

use crate::error::TransportError;
use crate::stream::{MAX_FRAME_BYTES, MAX_RESPONSE_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub data: String,
}

#[derive(Debug)]
pub struct SseParser {
    line: Vec<u8>,
    data: String,
    has_data: bool,
    first_line: bool,
    skip_lf: bool,
    frame_bytes: usize,
    total_bytes: usize,
}

impl Default for SseParser {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            data: String::new(),
            has_data: false,
            first_line: true,
            skip_lf: false,
            frame_bytes: 0,
            total_bytes: 0,
        }
    }
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, TransportError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_RESPONSE_BYTES)
            .ok_or_else(|| TransportError::Protocol("SSE response exceeds byte limit".into()))?;
        let mut events = Vec::new();
        for &byte in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            self.frame_bytes += 1;
            if self.frame_bytes > MAX_FRAME_BYTES {
                return Err(TransportError::Protocol(
                    "SSE frame exceeds byte limit".into(),
                ));
            }
            if byte == b'\r' || byte == b'\n' {
                self.finish_line(&mut events)?;
                self.skip_lf = byte == b'\r';
            } else {
                self.line.push(byte);
            }
        }
        Ok(events)
    }

    fn finish_line(&mut self, events: &mut Vec<SseEvent>) -> Result<(), TransportError> {
        let line = std::str::from_utf8(&self.line)
            .map_err(|_| TransportError::Protocol("invalid SSE UTF-8".into()))?;
        let line = if self.first_line {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        self.first_line = false;
        if line.is_empty() {
            if self.has_data {
                events.push(SseEvent {
                    data: std::mem::take(&mut self.data),
                });
                self.has_data = false;
            }
            self.frame_bytes = 0;
        } else if !line.starts_with(':') {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            if field == "data" {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
        }
        self.line.clear();
        Ok(())
    }

    /// EOF never dispatches pending data. A final CR already ended its line;
    /// skip_lf only suppresses the optional second half of a CRLF delimiter.
    pub fn is_clean(&self) -> bool {
        self.line.is_empty() && !self.has_data
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
