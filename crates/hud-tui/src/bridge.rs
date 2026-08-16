#![allow(dead_code)] // bridge functions wired into the live loop in PR-C/PR-D

//! Backend bridge — maps provider stream events to TUI messages (DR-20 §2.2, §2.9).
//!
//! This is the seam between the existing `run_turn` / `StreamObserver` pipeline
//! and the TUI's `Bus<Msg>`. It applies two non-bypassable gates before any
//! bytes reach the reducer:
//!
//! 1. **display_safe (H-3)** — scrubs secrets, URLs, control chars.
//! 2. **CoT stripping (§2.9)** — removes `</think>`/`<reasoning>`/`<analysis>`/
//!    `<scratchpad>`/`<internal>`/`<thinking>` blocks and paired all-caps tags
//!    *before* the bytes become a `Msg::TextDelta`. Panel-side regex is
//!    insufficient; the bridge is the only path model bytes take into the TUI.

use crate::bus::BusSender;
use crate::msg::Msg;

/// Emoji → ASCII fallback map (DR-21 L15). Default ON; disable with
/// `ORBIT_ASCII_EMOJI=0`. These replacements are guaranteed to render in
/// any terminal with any monospace font.
const ASCII_EMOJI_MAP: &[(&str, &str)] = &[
    ("👋", "(wave)"),
    ("✨", "*"),
    ("🛠️", "[tool]"),
    ("🛠", "[tool]"),
    ("✅", "[ok]"),
    ("❌", "[x]"),
    ("⚠️", "!"),
    ("⚠", "!"),
    ("🎉", "!"),
    ("🔥", "!"),
    ("👍", "+1"),
    ("👎", "-1"),
    ("💡", "!"),
    ("🚀", ">>"),
    ("📦", "pkg"),
    ("❤️", "<3"),
    ("❤", "<3"),
    ("💔", "</3"),
    ("🤔", "?"),
    ("👀", "oo"),
    ("💪", "++"),
    ("⭐", "*"),
    ("🌟", "*"),
    ("✏️", "[edit]"),
    ("📝", "[note]"),
    ("🔧", "[fix]"),
    ("🔨", "[build]"),
    ("🎯", "*"),
    ("🎨", "*"),
    ("🌈", "~"),
    ("💫", "*"),
    ("💯", "100"),
    ("🆗", "OK"),
    ("😀", ":)"),
    ("😄", ":)"),
    ("😊", ":)"),
    ("😎", "B)"),
    ("🙂", ":)"),
    ("😉", ";)"),
    ("😢", ":("),
    ("😭", ":'("),
    ("😡", ">:("),
    ("🤯", "O_o"),
    ("😱", "D:"),
    ("😴", "zz"),
    ("🥱", "~_~"),
    ("🙏", "++"),
    ("👏", "++"),
    ("🙌", "++"),
    ("🫡", "o7"),
    ("💀", "skull"),
    ("🤖", "bot"),
    ("👻", "spook"),
    ("✊", "++"),
    ("☕", "coffee"),
    ("🧠", "brain"),
    ("💭", "o"),
    ("🗣️", "talk"),
    ("🫵", "you"),
    ("🫂", "hug"),
    ("😅", "^_^;"),
    ("😂", "XD"),
    ("🤣", "XD"),
    ("😆", "XD"),
    ("😜", ";P"),
    ("🤪", ":P"),
    ("😈", "}>:)"),
    ("🔒", "[lock]"),
    ("💬", "\""),
    ("🔍", "?"),
    ("🧪", "lab"),
    ("📊", "stats"),
    ("🔑", "key"),
    ("🌐", "net"),
    ("💾", "save"),
    ("📁", "dir"),
    ("📄", "doc"),
    ("🌙", "*"),
    ("☀️", "*"),
    ("🐛", "bug"),
    ("🪲", "bug"),
    ("🦀", "rs"),
    ("🐍", "py"),
    ("🐧", "lnx"),
    ("🍎", "mac"),
    ("🪟", "win"),
];

/// Sanitize emoji to ASCII fallback. Non-emoji text passes through untouched.
/// Disabled when `ORBIT_ASCII_EMOJI=0` is set in the environment.
pub fn sanitize_glyphs(text: &str) -> String {
    if std::env::var("ORBIT_ASCII_EMOJI").as_deref() == Ok("0") {
        return text.to_string();
    }
    let mut result = text.to_string();
    for (emoji, replacement) in ASCII_EMOJI_MAP {
        if result.contains(emoji) {
            result = result.replace(emoji, replacement);
        }
    }
    result
}

/// Tags that wrap chain-of-thought / private reasoning. Stripped at the bridge,
/// never reaching the reducer. The content between tags is discarded entirely.
const COT_TAGS: &[&str] = &[
    "antml:thinking",
    "reasoning",
    "analysis",
    "scratchpad",
    "internal",
    "thinking",
];

/// Strip chain-of-thought blocks from a text chunk. Removes everything between
/// opening and closing tags (inclusive), including paired all-caps variants.
/// This is a **bridge-level** defense — the Verbose panel never sees raw CoT.
///
/// Iterates over **chars** (not bytes) to preserve multi-byte UTF-8 sequences.
/// The previous byte-level implementation corrupted accented characters by
/// converting each byte to a char independently (e.g. `á` = `0xC3 0xA1` →
/// `Ã` + `¡` → double-encoded when written back as UTF-8).
pub fn strip_cot(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '<' {
            // Reconstruct the substring from this position for tag matching.
            let rest: String = chars[i..].iter().collect();
            if let Some(_tag_len) = match_cot_open(&rest) {
                // tag_len is in bytes (from the &str), but we need it in chars.
                // Reconstruct the tag to get its char length.
                let tag_str: String = chars[i..].iter().take_while(|&&c| c != '>').collect();
                let tag_char_len = tag_str.len() + 1; // include the '>'
                                                      // Extract the tag name (without < >).
                let tag_name: String = chars[i + 1..i + tag_char_len - 1].iter().collect();
                let close = format!("</{tag_name}>");
                let close_lower = close.to_lowercase();
                // Search for the closing tag in the rest of the text.
                let after_tag: String = chars[i + tag_char_len..].iter().collect();
                if let Some(close_byte_pos) = after_tag.to_lowercase().find(&close_lower) {
                    // Convert byte position to char position.
                    let close_char_pos = after_tag[..close_byte_pos].chars().count();
                    i = i + tag_char_len + close_char_pos + close.chars().count();
                    continue;
                }
                // No closing tag found — drop the rest (fail closed).
                return out;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Check if the text starts with a CoT opening tag. Returns the length of the
/// match (including `<` and `>`) if so.
fn match_cot_open(text: &str) -> Option<usize> {
    for tag in COT_TAGS {
        let open = format!("<{tag}>");
        if text.to_lowercase().starts_with(&open.to_lowercase()) {
            return Some(open.len());
        }
    }
    None
}

/// Apply display_safe (H-3) to a text chunk. If the gate rejects, return a
/// safe placeholder — never crash, never leak.
pub fn safe_text(text: &str) -> String {
    match orbit_hud::display_safe(text) {
        Ok(clean) => clean,
        Err(_) => "[redacted]".to_string(),
    }
}

/// The full bridge pipeline: strip CoT → emoji-sanitize → display_safe → emit TextDelta.
pub fn emit_text(sender: &BusSender, bytes: &[u8]) {
    // The bytes come from serde_json's &str → as_bytes(), so they ARE valid
    // UTF-8. Use from_utf8 (not from_utf8_lossy) to avoid silent corruption.
    let raw = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return, // skip invalid UTF-8 rather than corrupting it
    };
    let stripped = strip_cot(&raw);
    let sanitized = sanitize_glyphs(&stripped);
    let safe = safe_text(&sanitized);
    if !safe.is_empty() {
        sender.send(Msg::TextDelta(safe));
    }
}

/// Emit a status one-liner (model change, session loaded, etc.).
pub fn emit_status(sender: &BusSender, text: &str) {
    let sanitized = sanitize_glyphs(text);
    let safe = safe_text(&sanitized);
    sender.send(Msg::Status(safe));
}

/// Emit a tool-call-started event with a display-safe summary.
pub fn emit_tool_started(sender: &BusSender, name: &str, summary: &str) {
    let safe_summary = safe_text(summary);
    sender.send(Msg::ToolCallStarted {
        name: name.to_string(),
        summary: safe_summary,
    });
}

/// Emit a tool-call-finished event.
pub fn emit_tool_finished(sender: &BusSender, name: &str, ok: bool) {
    sender.send(Msg::ToolCallFinished {
        name: name.to_string(),
        ok,
    });
}

/// Emit a response-finished event with usage + cost.
pub fn emit_response_finished(
    sender: &BusSender,
    output: &str,
    input_tokens: u64,
    output_tokens: u64,
    cost_microcents: u64,
) {
    let safe_output = safe_text(output);
    sender.send(Msg::ResponseFinished {
        output: safe_output,
        input_tokens,
        output_tokens,
        cost_microcents,
    });
}

/// Emit a backend error.
pub fn emit_error(sender: &BusSender, error: &str) {
    let safe = safe_text(error);
    sender.send(Msg::BackendError(safe));
}

/// Emit a cumulative cost update to the status bar.
pub fn emit_cost(sender: &BusSender, cost_microcents: u64) {
    sender.send(Msg::CostUpdated(cost_microcents));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::Bus;
    use crate::msg::Msg;

    fn drain(bus: &Bus) -> Vec<Msg> {
        let mut out = Vec::new();
        while let Some(msg) = bus.try_recv() {
            out.push(msg);
        }
        out
    }

    #[test]
    fn strip_cot_removes_thinking_block() {
        let input = "before<antml:thinking>secret reasoning</antml:thinking>after";
        assert_eq!(strip_cot(input), "beforeafter");
    }

    #[test]
    fn strip_cot_removes_reasoning_block() {
        let input = "hi<reasoning>plan: do evil</reasoning>bye";
        assert_eq!(strip_cot(input), "hibye");
    }

    #[test]
    fn strip_cot_case_insensitive() {
        let input = "hi<REASONING>plan</REASONING>bye";
        assert_eq!(strip_cot(input), "hibye");
    }

    #[test]
    fn strip_cot_removes_analysis_block() {
        let input = "a<analysis>deep thoughts</analysis>b";
        assert_eq!(strip_cot(input), "ab");
    }

    #[test]
    fn strip_cot_removes_scratchpad_block() {
        let input = "a<scratchpad>notes</scratchpad>b";
        assert_eq!(strip_cot(input), "ab");
    }

    #[test]
    fn strip_cot_removes_internal_block() {
        let input = "a<internal>hidden</internal>b";
        assert_eq!(strip_cot(input), "ab");
    }

    #[test]
    fn strip_cot_removes_plain_thinking_block() {
        let input = "a<thinking>thoughts</thinking>b";
        assert_eq!(strip_cot(input), "ab");
    }

    #[test]
    fn strip_cot_no_tags_passes_through() {
        assert_eq!(strip_cot("just text"), "just text");
    }

    #[test]
    fn strip_cot_unclosed_tag_drops_rest() {
        let input = "before<reasoning>never closed";
        assert_eq!(strip_cot(input), "before");
    }

    #[test]
    fn strip_cot_multiple_blocks() {
        let input = "a<reasoning>x</reasoning>b<analysis>y</analysis>c";
        assert_eq!(strip_cot(input), "abc");
    }

    #[test]
    fn safe_text_passes_clean_text() {
        assert_eq!(safe_text("hello world"), "hello world");
    }

    #[test]
    fn safe_text_redacts_secrets() {
        assert_eq!(safe_text("api_key=secret"), "[redacted]");
    }

    #[test]
    fn safe_text_redacts_urls() {
        assert_eq!(safe_text("https://evil.com"), "[redacted]");
    }

    #[test]
    fn emit_text_strips_cot_and_gates() {
        let (bus, sender) = Bus::new();
        emit_text(
            &sender,
            b"hello<antml:thinking>secret</antml:thinking>world",
        );
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::TextDelta(t) => assert_eq!(t, "helloworld"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn emit_text_redacts_secrets() {
        let (bus, sender) = Bus::new();
        emit_text(&sender, b"api_key=leaked");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::TextDelta(t) => assert_eq!(t, "[redacted]"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn emit_status_gates() {
        let (bus, sender) = Bus::new();
        emit_status(&sender, "model → glm-5.2");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::Status(s) => assert_eq!(s, "model → glm-5.2"),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn emit_tool_started_gates_summary() {
        let (bus, sender) = Bus::new();
        emit_tool_started(&sender, "calculator", "calculator(expression)");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::ToolCallStarted { name, summary } => {
                assert_eq!(name, "calculator");
                assert_eq!(summary, "calculator(expression)");
            }
            other => panic!("expected ToolCallStarted, got {other:?}"),
        }
    }

    #[test]
    fn emit_response_finished_carries_usage() {
        let (bus, sender) = Bus::new();
        emit_response_finished(&sender, "done", 100, 50, 500);
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::ResponseFinished {
                input_tokens,
                output_tokens,
                cost_microcents,
                ..
            } => {
                assert_eq!(*input_tokens, 100);
                assert_eq!(*output_tokens, 50);
                assert_eq!(*cost_microcents, 500);
            }
            other => panic!("expected ResponseFinished, got {other:?}"),
        }
    }

    #[test]
    fn emit_error_gates() {
        let (bus, sender) = Bus::new();
        emit_error(&sender, "provider unreachable");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::BackendError(e) => assert_eq!(e, "provider unreachable"),
            other => panic!("expected BackendError, got {other:?}"),
        }
    }

    #[test]
    fn emit_text_empty_after_strip_sends_nothing() {
        let (bus, sender) = Bus::new();
        emit_text(&sender, b"<reasoning>all cot</reasoning>");
        let msgs = drain(&bus);
        assert!(msgs.is_empty());
    }
}
