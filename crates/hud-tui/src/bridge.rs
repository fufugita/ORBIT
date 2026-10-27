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
pub use orbit_hud::{CotStripper, safe_text, strip_cot};

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

/// D7: probe the display-safe gate without coercing — `true` = the chunk is
/// clean (use as-is); `false` = rejected (caller emits a Redacted msg).
pub fn safe_text_probe(text: &str) -> bool {
    orbit_hud::display_safe(text).is_ok()
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
                kind: crate::model::RedactionKind::InvalidUtf8,
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
            kind: crate::model::RedactionKind::Secret,
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
pub fn emit_tool_started(sender: &BusSender, call_id: &str, name: &str, summary: &str) {
    let safe_summary = safe_text(summary);
    sender.send(Msg::ToolCallStarted {
        call_id: call_id.to_string(),
        name: name.to_string(),
        summary: safe_summary,
    });
}

/// Emit the start or end of a context compaction (`tokens`: the
/// conversation's estimated size before it starts, after it ends).
pub fn emit_compaction(sender: &BusSender, running: bool, tokens: u64) {
    sender.send(Msg::Compaction { running, tokens });
}

/// Emit one Activity row (display-safe): a ledger record (with its
/// digest) or a notable runtime event.
pub fn emit_activity(
    sender: &BusSender,
    kind: &str,
    target: &str,
    fact: &str,
    digest: Option<&str>,
) {
    sender.send(Msg::Activity {
        kind: kind.to_string(),
        target: terminal_safe(target),
        fact: terminal_safe(fact),
        digest: digest.map(str::to_string),
    });
}

/// Emit extra readiness rows for the welcome screen (display-safe).
pub fn emit_readiness(sender: &BusSender, rows: Vec<(bool, String)>) {
    sender.send(Msg::Readiness(
        rows.into_iter()
            .map(|(ok, label)| (ok, safe_text(&label)))
            .collect(),
    ));
}

/// Emit the facts and preview of the approval about to be requested
/// (display-safe: secret values redacted, control sequences removed).
pub fn emit_approval_detail(
    sender: &BusSender,
    call_id: &str,
    facts: Vec<(String, String)>,
    preview: Vec<String>,
    grant: Option<crate::msg::ApprovalGrant>,
) {
    // The rule is shown as written, or not at all: if display-safety would
    // change a character of it, the card would name a different rule than
    // the one `s` grants.
    let grant = grant.filter(|g| safe_text(&g.rule) == g.rule && terminal_safe(&g.rule) == g.rule);
    sender.send(Msg::ApprovalDetail {
        grant,
        call_id: call_id.to_string(),
        facts: facts
            .into_iter()
            .map(|(k, v)| (safe_text(&k), safe_text(&v)))
            .collect(),
        preview: preview.iter().map(|l| terminal_safe(l)).collect(),
    });
}

/// Emit the session's task list for the Plan panel (titles display-safe).
pub fn emit_tasks(sender: &BusSender, tasks: Vec<(String, String)>) {
    let tasks = tasks
        .into_iter()
        .map(|(title, status)| (safe_text(&title), status))
        .collect();
    sender.send(Msg::TasksUpdate(tasks));
}

/// Emit one line of a running command's live output (display-safe).
pub fn emit_tool_output(sender: &BusSender, call_id: &str, line: &str) {
    sender.send(Msg::ToolOutput {
        call_id: call_id.to_string(),
        line: terminal_safe(line),
    });
}

/// Display-safe form of one line of command output, for the Terminal
/// panel. Secret VALUES are redacted (the line stays); ANSI escape
/// sequences are removed whole — dropping only the ESC byte would leave
/// `[1;31m` on screen; tabs become spaces; other control characters go.
/// Unlike [`safe_text`] it does not reject chat-shaped markers such as
/// `prompt:` — a build log may legitimately say anything.
pub fn terminal_safe(line: &str) -> String {
    terminal_safe_with_newlines(line, false)
}

/// Display-safe terminal text that retains line feeds for a multiline pane.
/// Escape sequences are consumed from the whole stream, including any line
/// feeds inside an OSC. Callers that require the content gate still apply it.
pub(crate) fn terminal_safe_multiline(text: &str) -> String {
    terminal_safe_with_newlines(text, true)
}

fn terminal_safe_with_newlines(text: &str, keep_newlines: bool) -> String {
    let redacted = orbit_hud::redact_secret_values(text);
    let mut out = String::with_capacity(redacted.len());
    let mut chars = redacted.chars();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                // CSI: parameter and intermediate bytes, then one final
                // byte in 0x40..=0x7E.
                Some('[') => {
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or the string terminator (ESC \).
                Some(']') => {
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            chars.next();
                            break;
                        }
                    }
                }
                // Any other escape is a two-byte sequence.
                _ => {}
            },
            '\t' => out.push_str("    "),
            '\n' if keep_newlines => out.push('\n'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Emit a tool-call-finished event. The outcome distinguishes an operator
/// denial and a pre-run block from a genuine tool failure (§11.5 rule 4:
/// a `Denied` outcome keeps `⊘`, never a red `✕`).
pub fn emit_tool_finished(
    sender: &BusSender,
    call_id: &str,
    name: &str,
    outcome: crate::model::ToolOutcome,
    fact: &str,
) {
    sender.send(Msg::ToolCallFinished {
        call_id: call_id.to_string(),
        name: name.to_string(),
        outcome,
        fact: safe_text(fact),
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
    emit_subagent_started_with_model(sender, id, name, task, "");
}

/// Emit a subagent start with the model selected by its runtime.
pub fn emit_subagent_started_with_model(
    sender: &BusSender,
    id: &str,
    name: &str,
    task: &str,
    model: &str,
) {
    sender.send(Msg::SubagentStarted {
        id: id.to_string(),
        name: safe_text(name),
        task: safe_text(task),
        model: safe_text(model),
    });
}

pub fn emit_subagent_progress(sender: &BusSender, id: &str, action: &str) {
    sender.send(Msg::SubagentProgress {
        id: id.to_string(),
        action: safe_text(action),
    });
}

pub fn emit_subagent_finished(sender: &BusSender, id: &str, report: &str, ok: bool) {
    sender.send(Msg::SubagentFinished {
        id: id.to_string(),
        report: safe_text(report),
        ok,
    });
}

/// Emit context usage (tokens in use, the model's window).
pub fn emit_usage(
    sender: &BusSender,
    used_tokens: u64,
    window_tokens: u64,
    breakdown: Option<orbit_frontend_protocol::ContextBreakdown>,
) {
    sender.send(Msg::Usage {
        used_tokens,
        window_tokens,
        breakdown,
    });
}

/// Emit the ledger's record count after an append.
pub fn emit_ledger_appended(sender: &BusSender, record_count: u64) {
    sender.send(Msg::LedgerAppended { record_count });
}

/// Emit a workspace update (the right rail's live state).
pub fn emit_workspace(sender: &BusSender, w: crate::model::Workspace) {
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

/// Emit a settings, startup or publication warning without failing a turn.
pub fn emit_notice(sender: &BusSender, notice: &str) {
    sender.send(Msg::BackendNotice(safe_text(&terminal_safe(notice))));
}

/// Emit one scoped execution/publication fact before ResponseFinished.
pub fn emit_ordinary_turn_ended(
    sender: &BusSender,
    operation: crate::worker::ForegroundOperation,
    end: crate::msg::OrdinaryEnd,
    publication: crate::msg::OrdinaryPublication,
) {
    let end = match end {
        crate::msg::OrdinaryEnd::Failed(reason) => {
            crate::msg::OrdinaryEnd::Failed(safe_text(&terminal_safe(&reason)))
        }
        other => other,
    };
    sender.send(Msg::OrdinaryTurnEnded {
        operation,
        end,
        publication,
    });
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
    fn subagent_start_preserves_the_selected_model_and_profile() {
        let (bus, sender) = Bus::new();
        emit_subagent_started_with_model(
            &sender,
            "a1",
            "Explore",
            "find add()",
            "test-child-model\u{7}",
        );
        assert_eq!(
            drain(&bus),
            vec![Msg::SubagentStarted {
                id: "a1".into(),
                name: "Explore".into(),
                task: "find add()".into(),
                model: "test-child-model".into(),
            }]
        );
    }

    #[test]
    fn legacy_subagent_start_leaves_the_model_unspecified() {
        let (bus, sender) = Bus::new();
        emit_subagent_started(&sender, "a1", "Explore", "find add()");
        assert_eq!(
            drain(&bus),
            vec![Msg::SubagentStarted {
                id: "a1".into(),
                name: "Explore".into(),
                task: "find add()".into(),
                model: String::new(),
            }]
        );
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
                assert_eq!(*kind, crate::model::RedactionKind::Secret)
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
    }

    #[test]
    fn emit_status_gates() {
        let (bus, sender) = Bus::new();
        emit_status(&sender, "model → fixture-model");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::Status(s) => assert_eq!(s, "model → fixture-model"),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn terminal_safe_strips_whole_escape_sequences_and_keeps_chat_words() {
        // The colour codes go entirely (not just the ESC byte).
        assert_eq!(terminal_safe("\u{1b}[1;31merror\u{1b}[0m: no"), "error: no");
        // An OSC title is dropped whole, BEL- or ST-terminated.
        assert_eq!(terminal_safe("\u{1b}]0;title\u{7}ok"), "ok");
        assert_eq!(terminal_safe("\u{1b}]0;title\u{1b}\\ok"), "ok");
        // Tabs line up as spaces; carriage returns vanish.
        assert_eq!(terminal_safe("a\tb\r"), "a    b");
        // A build log may say "prompt:" and print URLs.
        assert_eq!(
            terminal_safe("prompt: fetching https://example.com/x"),
            "prompt: fetching https://example.com/x"
        );
    }

    #[test]
    fn terminal_safe_redacts_secret_values_but_keeps_the_line() {
        let out = terminal_safe("token=ghp_0123456789abcdef0123456789abcdef0123 done");
        assert!(!out.contains("ghp_0123"), "{out}");
        assert!(out.contains("done"), "{out}");
    }

    #[test]
    fn terminal_safe_multiline_preserves_only_line_feeds() {
        let input = "first\n\nsecond\tcell\r\u{7}\u{85}\u{9f}\n";
        assert_eq!(terminal_safe_multiline(input), "first\n\nsecond    cell\n");
        assert_eq!(terminal_safe(input), "firstsecond    cell");
    }

    #[test]
    fn terminal_safe_multiline_consumes_escapes_across_line_feeds() {
        let input = concat!(
            "first\n\u{1b}]0;hidden\nOSC title\u{7}",
            "\u{1b}[31\nmred\u{1b}[0m\n",
            "\u{1b}]8;;https://example.com/hidden\npath\u{1b}\\last\n"
        );
        assert_eq!(terminal_safe_multiline(input), "first\nred\nlast\n");
        assert_eq!(terminal_safe(input), "firstredlast");
        assert_eq!(
            terminal_safe_multiline("kept\n\u{1b}]unterminated\nsecret"),
            "kept\n"
        );
    }

    #[test]
    fn terminal_safe_multiline_redacts_secrets_without_joining_rows() {
        let out = terminal_safe_multiline(
            "first\ntoken=ghp_0123456789abcdef0123456789abcdef0123 done\nlast\n",
        );
        assert!(!out.contains("ghp_0123"), "{out}");
        assert!(out.starts_with("first\n"), "{out}");
        assert!(out.ends_with(" done\nlast\n"), "{out}");
    }

    #[test]
    fn emit_tool_started_gates_summary() {
        let (bus, sender) = Bus::new();
        emit_tool_started(&sender, "call-1", "calculator", "calculator(expression)");
        let msgs = drain(&bus);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::ToolCallStarted {
                call_id,
                name,
                summary,
            } => {
                assert_eq!(call_id, "call-1");
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
                assert_eq!(*kind, crate::model::RedactionKind::InvalidUtf8)
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_end_and_notice_emitters_keep_safe_text_and_variant_identity() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        use crate::worker::{ForegroundKind, ForegroundOperation, SessionBinding};
        let (bus, sender) = Bus::new();
        let operation = ForegroundOperation::new(
            SessionBinding {
                session_id: "session-emitter".into(),
                generation: 1,
            },
            ForegroundKind::Prompt,
            1,
        )
        .unwrap();
        let unsafe_text =
            "\u{1b}[31mwarning\u{1b}[0m token=ghp_0123456789abcdef0123456789abcdef0123 done";
        emit_ordinary_turn_ended(
            &sender,
            operation.clone(),
            OrdinaryEnd::Failed(unsafe_text.into()),
            OrdinaryPublication::Saved,
        );
        emit_notice(&sender, unsafe_text);
        emit_error(&sender, "legacy diagnostic");
        let messages = drain(&bus);
        let Msg::OrdinaryTurnEnded {
            operation: actual,
            end: OrdinaryEnd::Failed(reason),
            publication,
        } = &messages[0]
        else {
            panic!("typed ordinary result");
        };
        assert_eq!(actual, &operation);
        assert_eq!(*publication, OrdinaryPublication::Saved);
        assert!(reason.contains("warning") && reason.contains("done"));
        assert!(!reason.contains("ghp_0123") && !reason.chars().any(char::is_control));
        let Msg::BackendNotice(notice) = &messages[1] else {
            panic!("separate notice");
        };
        assert!(!notice.contains("ghp_0123") && !notice.chars().any(char::is_control));
        assert_eq!(messages[2], Msg::BackendError("legacy diagnostic".into()));
    }
}
