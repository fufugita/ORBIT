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

/// D7: probe the display-safe gate without coercing — `true` = the chunk is
/// clean (use as-is); `false` = rejected (caller emits a Redacted msg).
pub fn safe_text_probe(text: &str) -> bool {
    orbit_hud::display_safe(text).is_ok()
}

/// D6: stateful CoT stripper for streaming deltas. Owns two pieces of
/// cross-delta state:
///
/// 1. `inside` — an opening tag was seen with no closing tag yet; everything
///    is suppressed until the close arrives (fail closed).
/// 2. `pending` — a partial tag prefix (`<thi`) at a buffer boundary; held
///    back until the next delta either completes or disproves it.
#[derive(Default)]
pub struct CotStripper {
    inside: Option<String>, // the open tag name, e.g. "think"
    pending: String,        // trailing partial-tag bytes
}

impl CotStripper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one delta; returns the displayable remainder.
    pub fn push(&mut self, delta: &str) -> String {
        // Fast path: mid-block. Scan only for the closing tag.
        if let Some(tag) = self.inside.clone() {
            let close = format!("</{tag}>");
            let hay = format!("{}{}", self.pending, delta);
            self.pending.clear();
            if let Some(pos) = hay.to_lowercase().find(&close.to_lowercase()) {
                // Close found: resume AFTER it, re-entering normal mode for
                // the remainder of this delta.
                let after = hay[pos + close.len()..].to_string();
                self.inside = None;
                return self.push(&after);
            }
            // Still inside: keep a tail only if a partial `</...` prefix
            // straddles the boundary. Inclusive range — the longest tail
            // (i == hay.len()) must be reachable, else a delta that IS
            // entirely a close-prefix would be dropped instead of held.
            let mut keep = String::new();
            let max_tail = hay.len().min(close.len());
            for i in (1..=max_tail).rev() {
                if !hay.is_char_boundary(hay.len() - i) {
                    continue;
                }
                let tail = &hay[hay.len() - i..];
                if close.to_lowercase().starts_with(&tail.to_lowercase()) {
                    keep = tail.to_string();
                    break;
                }
            }
            self.pending = keep;
            return String::new();
        }

        // Normal mode: not inside a block. Prepend any held-back partial tag.
        let hay = format!("{}{}", self.pending, delta);
        self.pending.clear();
        let lower = hay.to_lowercase();
        let chars: Vec<char> = hay.chars().collect();

        // Look for a complete opening tag.
        for tag in COT_TAGS {
            let open = format!("<{tag}>");
            if let Some(pos) = lower.find(&open.to_lowercase()) {
                // Emit what precedes it, then enter the block and recurse on
                // the remainder (which may itself contain the close).
                let pos_ch = lower[..pos].chars().count();
                let open_ch = open.chars().count();
                let before: String = chars[..pos_ch].iter().collect();
                let rest: String = chars[pos_ch + open_ch..].iter().collect();
                self.inside = Some(tag.to_string());
                return before + &self.push(&rest);
            }
        }

        // No complete tag. Hold back a trailing partial open-tag prefix
        // (`<thi`) so a tag split across deltas is still caught.
        let mut hold = String::new();
        for i in (1..hay.len().min(8).saturating_sub(0)).rev() {
            if !hay.is_char_boundary(hay.len() - i) {
                continue;
            }
            let tail = &hay[hay.len() - i..];
            if COT_TAGS.iter().any(|t| {
                format!("<{t}>")
                    .to_lowercase()
                    .starts_with(&tail.to_lowercase())
                    && tail.starts_with('<')
            }) {
                hold = tail.to_string();
                break;
            }
        }
        let emit_len = hay.len() - hold.len();
        let out = hay[..emit_len].to_string();
        self.pending = hold;
        out
    }
}

/// The full bridge pipeline: strip CoT → emoji-sanitize → display_safe → emit TextDelta.
/// D6: CoT stripping is STATEFUL across deltas — the stripper is owned by the
/// caller (one per stream) so a `<think>` that arrives alone in one delta
/// suppresses everything until its `</think>` lands, in whatever later delta.
pub fn emit_text(stripper: &mut CotStripper, sender: &BusSender, bytes: &[u8]) {
    // The bytes come from serde_json's &str → as_bytes(), so they ARE valid
    // UTF-8. Use from_utf8 (not from_utf8_lossy) to avoid silent corruption.
    let raw = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // D7: name the gate; never render the rejected bytes.
            sender.send(Msg::Redacted {
                kind: crate::state::RedactionKind::InvalidUtf8,
            });
            return;
        }
    };
    let stripped = stripper.push(&raw);
    let sanitized = sanitize_glyphs(&stripped);
    let match_before = safe_text_probe(&sanitized);
    if !match_before {
        // D7: rejected by the display-safe gate — emit the chip, not the text.
        sender.send(Msg::Redacted {
            kind: crate::state::RedactionKind::Secret,
        });
        return;
    }
    if !sanitized.is_empty() {
        sender.send(Msg::TextDelta(sanitized));
    }
}

/// Emit a status one-liner (model change, session loaded, etc.).
pub fn emit_status(sender: &BusSender, text: &str) {
    let sanitized = sanitize_glyphs(text);
    let safe = safe_text(&sanitized);
    sender.send(Msg::Status(safe));
}

/// Emit a permission-mode change (S5): the mode pill flips without a
/// full redraw. `mode` is the config name (default, acceptEdits, ...).
pub fn emit_mode_changed(sender: &BusSender, mode: &str) {
    sender.send(Msg::ModeChanged(mode.to_string()));
}

/// Emit a tool-call-started event with a display-safe summary.
pub fn emit_tool_started(sender: &BusSender, name: &str, summary: &str) {
    let safe_summary = safe_text(summary);
    sender.send(Msg::ToolCallStarted {
        name: name.to_string(),
        summary: safe_summary,
    });
}

/// Emit a tool-call-finished event. The outcome distinguishes an operator
/// denial and a pre-run block from a genuine tool failure (§11.5 rule 4:
/// a `Denied` outcome keeps `⊘`, never a red `✕`).
pub fn emit_tool_finished(sender: &BusSender, name: &str, outcome: crate::state::ToolOutcome) {
    sender.send(Msg::ToolCallFinished {
        name: name.to_string(),
        outcome,
    });
}

/// Emit a changed file: path, line counts, and — for a checkpointed
/// write — the real bounded hunks (M11).
pub fn emit_file_changed(
    sender: &BusSender,
    path: &str,
    added: u32,
    removed: u32,
    hunks: Option<Vec<orbit_frontend_protocol::DiffHunk>>,
) {
    sender.send(Msg::FileChanged {
        path: safe_text(path),
        added,
        removed,
        hunks,
    });
}

/// Emit a subagent lifecycle event.
pub fn emit_subagent_started(sender: &BusSender, id: &str, name: &str, task: &str) {
    sender.send(Msg::SubagentStarted {
        id: id.to_string(),
        name: safe_text(name),
        task: safe_text(task),
    });
}

pub fn emit_subagent_progress(sender: &BusSender, id: &str, action: &str) {
    sender.send(Msg::SubagentProgress {
        id: id.to_string(),
        action: safe_text(action),
    });
}

pub fn emit_subagent_finished(sender: &BusSender, id: &str, report: &str) {
    sender.send(Msg::SubagentFinished {
        id: id.to_string(),
        report: safe_text(report),
    });
}

/// Emit context usage (tokens in use, the model's window).
pub fn emit_usage(sender: &BusSender, used_tokens: u64, window_tokens: u64) {
    sender.send(Msg::Usage {
        used_tokens,
        window_tokens,
    });
}

/// Emit the ledger's record count after an append.
pub fn emit_ledger_appended(sender: &BusSender, record_count: u64) {
    sender.send(Msg::LedgerAppended { record_count });
}

/// Emit a workspace update (the right rail's live state).
pub fn emit_workspace(sender: &BusSender, w: crate::state::Workspace) {
    sender.send(Msg::WorkspaceUpdate(w));
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

/// Emit a plan-mode result: the plan text is held for operator approval
/// (y runs it, n discards) — Claude Code plan-mode parity.
pub fn emit_plan_ready(sender: &BusSender, plan: &str) {
    let safe = safe_text(plan);
    sender.send(Msg::PlanReady(safe));
}

/// Emit a backend error.
pub fn emit_error(sender: &BusSender, error: &str) {
    let safe = safe_text(error);
    sender.send(Msg::BackendError(safe));
}

/// Emit the cumulative cost update (legacy bridge path — Go bridge).
pub fn emit_cost(sender: &BusSender, cost_microcents: u64) {
    sender.send(Msg::CostUpdated(cost_microcents));
}

/// D5: emit the CURRENT turn's running cost (microcents). The worker calls
/// this after each provider round; the final number is committed by
/// ResponseFinished, not here.
pub fn emit_turn_cost(sender: &BusSender, cost_microcents: u64) {
    sender.send(Msg::TurnCostUpdated(cost_microcents));
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
    fn safe_text_passes_words_and_urls() {
        // Value-based gate: the WORD "api_key" and URLs are ordinary
        // content (the old keyword rejection blanked them; real keys
        // without the word passed).
        assert_eq!(safe_text("api_key=secret"), "api_key=secret");
        assert_eq!(safe_text("https://evil.com"), "https://evil.com");
    }

    #[test]
    fn safe_text_redacts_real_secret_values() {
        let out = safe_text("token = sk-abc123def456ghi789jkl012mno");
        assert!(out.contains("[redacted:api token]"), "got: {out}");
    }

    #[test]
    fn emit_text_strips_cot_and_gates() {
        let (bus, sender) = Bus::new();
        emit_text(
            &mut CotStripper::new(),
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
    fn emit_text_redacts_cot_markers() {
        // D7: a rejected chunk emits a Redacted chip naming the gate — the
        // text itself never reaches the bus. CoT markers remain hard
        // rejects; the word "api_key" alone no longer is one.
        let (bus, sender) = Bus::new();
        emit_text(
            &mut CotStripper::new(),
            &sender,
            b"chain_of_thought: leaked",
        );
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::Redacted { kind } => {
                assert_eq!(*kind, crate::state::RedactionKind::Secret)
            }
            other => panic!("expected Redacted, got {other:?}"),
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
        emit_text(
            &mut CotStripper::new(),
            &sender,
            b"<reasoning>all cot</reasoning>",
        );
        let msgs = drain(&bus);
        assert!(msgs.is_empty());
    }

    // ── D6: stateful cross-delta CoT stripping ───────────────────────────

    #[test]
    fn cot_split_open_and_close_across_deltas() {
        let mut s = CotStripper::new();
        // Delta 1 ends mid-open-tag; delta 2 completes it and ends mid-close.
        assert_eq!(s.push("clean text <thin"), "clean text ");
        assert_eq!(s.push("king>hidden reasoning"), "");
        assert_eq!(s.push("</thin"), "");
        assert_eq!(s.push("king> visible"), " visible");
    }

    #[test]
    fn cot_suppresses_forever_without_close() {
        // Fail closed: an open tag with no close suppresses the rest of the
        // stream, not just the first delta.
        let mut s = CotStripper::new();
        assert_eq!(s.push("before <thinking>"), "before ");
        assert_eq!(s.push("secret one"), "");
        assert_eq!(s.push("secret two"), "");
        // Still no close — still suppressed.
        assert_eq!(s.push("still secret"), "");
    }

    #[test]
    fn cot_partial_tag_held_not_lost() {
        // A lone `<` at a boundary is held, then released when disproven.
        let mut s = CotStripper::new();
        assert_eq!(s.push("a <"), "a ");
        assert_eq!(s.push(" b"), "< b");
    }

    #[test]
    fn cot_normal_text_unaffected() {
        let mut s = CotStripper::new();
        assert_eq!(s.push("math: 1 < 2 and 3 > 2"), "math: 1 < 2 and 3 > 2");
        assert_eq!(s.push("no tags here"), "no tags here");
    }

    #[test]
    fn emit_text_utf8_reject_emits_chip() {
        // D7: invalid UTF-8 emits a Redacted(InvalidUtf8) chip, not silence.
        let (bus, sender) = Bus::new();
        emit_text(&mut CotStripper::new(), &sender, &[0xff, 0xfe]);
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::Redacted { kind } => {
                assert_eq!(*kind, crate::state::RedactionKind::InvalidUtf8)
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
    }
}
