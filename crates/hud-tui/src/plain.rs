//! The plain grammar (docs/tui/DESIGN.md §11.4) — one event per line, words
//! instead of glyphs, no box drawing, a timestamp on each line.
//!
//! Copy mode (z y), the REPL and non-TTY output all render through this one
//! module so the three surfaces can never drift apart. Screen readers and
//! log greps read the same words.
//!
//! Grammar:
//! ```text
//! 14:02 you: orbit verify-ledger fails right after orbit restore …
//! 14:02 orbit: The restored namespace starts a brand-new chain …
//! 14:02 tool read_file crates/export/src/restore.rs: done, 212 lines, 0.1s
//! 14:06 approval needed: shell scripts/e2e.sh (medium risk). y allow once, R allow shell this session, n deny
//! 14:06 tool shell rm -rf target/: denied by you
//! ```

use crate::state::{App, PendingApproval, TranscriptLine};

/// Render the whole transcript + live state as plain lines.
///
/// `now` stamps the lines that have no recorded time (the transcript does
/// not carry per-turn timestamps yet — every line gets the session clock;
/// per-turn times arrive with the backend's structured events).
pub fn transcript_lines(app: &App, now: &str) -> Vec<String> {
    let mut out = Vec::new();
    for entry in &app.transcript {
        match entry {
            TranscriptLine::User { text, .. } => {
                for line in text.lines() {
                    out.push(format!("{now} you: {line}"));
                }
            }
            TranscriptLine::Assistant { text, .. } => {
                for line in text.lines() {
                    out.push(format!("{now} orbit: {line}"));
                }
            }
            TranscriptLine::Stripped {
                tool_name, summary, ..
            } => {
                if summary.is_empty() {
                    out.push(format!("{now} tool {tool_name}: ran"));
                } else {
                    out.push(format!("{now} tool {tool_name} {summary}: ran"));
                }
            }
            TranscriptLine::System(text) => {
                out.push(format!("{now} {text}"));
            }
            TranscriptLine::Redacted(kind) => {
                // D7: chip in plain words (screen-reader safe, no glyphs).
                out.push(format!("{now} redacted: {}", kind.label()));
            }
            TranscriptLine::Evidence { checks, note, rows } => {
                out.push(format!("{now} verified {checks} {note}"));
                for (name, result) in rows {
                    out.push(format!("{now} {name}: {result}"));
                }
            }
            TranscriptLine::Sources(srcs) => {
                let list = srcs
                    .iter()
                    .map(|(i, p)| format!("[{i}] {p}"))
                    .collect::<Vec<_>>()
                    .join("   ");
                out.push(format!("{now} sources {list}"));
            }
        }
    }
    if !app.in_flight.is_empty() {
        for line in app.in_flight.lines() {
            out.push(format!("{now} orbit: {line}"));
        }
    }
    out
}

/// One approval request as a plain line (words, no glyphs, risk in words).
pub fn approval_line(req: &PendingApproval, now: &str) -> String {
    let risk = match req.risk {
        0 => "no",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "unknown",
    };
    format!(
        "{now} approval needed: {} ({} risk). y allow once, R allow {} this session, n deny",
        req.summary, risk, req.tool_name
    )
}

/// A tool verdict as a plain line.
pub fn verdict_line(tool_name: &str, summary: &str, allowed: bool, by: &str, now: &str) -> String {
    if allowed {
        format!("{now} tool {tool_name} {summary}: allowed by {by}")
    } else {
        format!("{now} tool {tool_name} {summary}: denied by {by}")
    }
}

/// The status line as a plain line (for non-TTY tails).
pub fn status_line(app: &App, now: &str) -> String {
    let conn = match app.connection {
        crate::state::ConnectionState::Online => "online",
        crate::state::ConnectionState::Reconnecting => "reconnecting",
        crate::state::ConnectionState::Offline => "offline",
    };
    let tool = match &app.tool_state {
        crate::state::ToolState::Idle => "idle".to_string(),
        crate::state::ToolState::Streaming => "streaming".to_string(),
        crate::state::ToolState::AwaitingApproval => "approval needed".to_string(),
        crate::state::ToolState::Running(name) => format!("running {name}"),
        crate::state::ToolState::AutoGranted(name) => format!("auto {name}"),
    };
    format!(
        "{now} status: {} on {}, {}, {}",
        app.model, app.provider, tool, conn
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{App, PendingApproval, TranscriptLine};

    #[test]
    fn plain_lines_have_timestamps_and_words() {
        let mut app = App::new();
        app.transcript.push(TranscriptLine::User { text: "hello".into(), time: None });
        app.transcript
            .push(TranscriptLine::Assistant { text: "hi there".into(), time: None });
        let lines = transcript_lines(&app, "14:02");
        assert_eq!(lines[0], "14:02 you: hello");
        assert_eq!(lines[1], "14:02 orbit: hi there");
    }

    #[test]
    fn plain_approval_uses_words_not_glyphs() {
        let req = PendingApproval {
            call_id: "c1".into(),
            tool_name: "shell".into(),
            summary: "shell rm -rf target/".into(),
            risk: 2,
        };
        let line = approval_line(&req, "14:06");
        assert!(line.starts_with("14:06 approval needed:"));
        assert!(line.contains("medium risk"));
        assert!(line.contains("y allow once"));
        // No box-drawing or state glyphs anywhere.
        assert!(!line.contains('▰'));
        assert!(!line.contains('✦'));
    }

    #[test]
    fn plain_verdict_words() {
        let denied = verdict_line("shell", "rm -rf target/", false, "you", "14:06");
        assert_eq!(denied, "14:06 tool shell rm -rf target/: denied by you");
        let allowed = verdict_line("read_file", "x.rs", true, "you", "14:07");
        assert!(allowed.ends_with("allowed by you"));
    }

    #[test]
    fn plain_status_words() {
        let app = App::new();
        let line = status_line(&app, "09:00");
        assert!(line.starts_with("09:00 status:"));
        assert!(line.contains("idle"));
    }
}
