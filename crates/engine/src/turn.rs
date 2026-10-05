//! The engine's turn loop — one prompt, many rounds, one place.
//!
//! Replaces the four per-front-end loops (REPL, TUI worker, web bridge,
//! Go bridge), each of which had its own 8-round cap and quirks. The
//! loop runs until the model stops calling tools, a stop reason ends
//! the turn, the operator cancels, or the round guard fires.

use crate::{
    assistant_message, dispatch::TurnConfig, user_message, EventSink, ToolExecutor, TurnReport,
};
use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_frontend_protocol::FrontendEvent;
use std::time::Duration;

/// Guard against a runaway turn (roadmap default: 100).
pub const DEFAULT_MAX_ROUNDS: u32 = 100;

/// Retry budget for rate-limit/server refusals (roadmap: 8).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

/// Configuration for one engine turn.
#[derive(Debug, Clone)]
pub struct TurnOptions {
    pub max_rounds: u32,
    pub max_attempts: u32,
    /// Tools advertised to the model this turn. `/compact` passes an
    /// EMPTY list: a summarization request must not advertise tools.
    pub tools: Vec<orbit_adapter::types::ToolDefinition>,
    /// The frozen system prompt (phase 4: built once per session by
    /// the context builder — base instructions, tools, environment,
    /// memory files, mods). Sent as the System message; never
    /// re-inserted per request (that broke caching and edited-history
    /// replay). Plan mode appends its read-only posture here.
    pub system_directive: Option<String>,
    /// Request-id stem for ledger records (e.g. "orbit-tui", "orbit-p").
    pub request_stem: String,
    /// The model's context window (phase 4: compaction threshold =
    /// 90% of window minus the output reserve).
    pub window_tokens: Option<u64>,
    /// Output reserve subtracted from the window before the compaction
    /// threshold (the model needs room to answer).
    pub output_reserve_tokens: u64,
    /// True inside a compaction request itself: never compact while
    /// compacting (the recursion loops when the window is small — the
    /// summary request alone can cross the threshold).
    pub compacting: bool,
}

/// Rough token estimate for a transcript: ~4 chars per token across
/// message text. Good enough to decide WHEN to compact (the provider's
/// own usage refines it later in the turn). Tool-call arguments and
/// tool results count too — they ride the request just as text does.
pub fn estimate_transcript_tokens(transcript: &[ChatMessage]) -> u64 {
    let chars: usize = transcript
        .iter()
        .map(|m| {
            let base = m.content.len() + m.content.len() / 8;
            let calls = m
                .tool_calls
                .as_ref()
                .map(|cs| cs.iter().map(|c| c.arguments.len()).sum::<usize>())
                .unwrap_or(0);
            let result = m.tool_result.as_ref().map(|r| r.len()).unwrap_or(0);
            base + calls + result
        })
        .sum();
    (chars as u64) / 4
}

/// The compaction threshold: compact when the next request would pass
/// 90% of (window − output reserve).
fn should_compact(used_tokens: u64, window: Option<u64>, reserve: u64) -> bool {
    match window {
        Some(w) => {
            let usable = w.saturating_sub(reserve);
            used_tokens >= usable / 10 * 9
        }
        None => false,
    }
}

impl Default for TurnOptions {
    fn default() -> Self {
        TurnOptions {
            max_rounds: DEFAULT_MAX_ROUNDS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            // No tools by default: the caller passes its tool set
            // explicitly (every front-end resolves its own today).
            // Phase 3 moves the tool runtime into the engine.
            tools: Vec::new(),
            system_directive: None,
            request_stem: "orbit-engine".into(),
            window_tokens: None,
            output_reserve_tokens: 8_192,
            compacting: false,
        }
    }
}

/// Run one prompt through the engine loop, updating `transcript` in
/// place (the caller owns persistence). `cancel` is checked between
/// rounds and during streaming (the provider layer aborts mid-stream).
/// Tool calls are executed by `executor` (caller-injected until phase
/// 3 moves the tool runtime into the engine).
#[allow(clippy::too_many_arguments)]
pub fn run_turn(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    executor: &mut dyn ToolExecutor,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
) -> Result<TurnReport, String> {
    transcript.push(user_message(prompt));

    let mut report = TurnReport::default();
    let mut round: u32 = 0;
    // Compaction latch: once this turn has compacted, do not compact
    // again until the transcript grows past the threshold by NEW
    // content (the summary itself is near the threshold when the
    // window is small; re-checking immediately would loop forever).
    let mut compacted_at: Option<u64> = None;

    loop {
        if cancel.is_cancelled() {
            report.interrupted = true;
            report.ok = false;
            emit_turn_ended(events, &report, round);
            return Ok(report);
        }

        events(FrontendEvent::RoundStarted { round });

        // Phase 4: auto-compaction — when the next request would pass
        // 90% of (window − output reserve), compact first. The size is
        // ESTIMATED from the transcript (~chars/4), not taken from the
        // last response's usage: a resumed or continued session starts
        // with a long transcript and zero reported input tokens, and
        // the first request of such a turn must compact too.
        let est_tokens = estimate_transcript_tokens(transcript);
        let mut est_now = est_tokens;
        if round == 0 && report.input_tokens > 0 {
            // Later rounds in this same turn: trust the provider's own
            // count when we have one (more accurate than the estimate).
            est_now = report.input_tokens;
        }
        let grown = match compacted_at {
            Some(at) => est_now > at,
            None => true,
        };
        if !options.compacting
            && grown
            && should_compact(
                est_now,
                options.window_tokens,
                options.output_reserve_tokens,
            )
        {
            events(FrontendEvent::Compacting {
                used_tokens: est_now,
                window_tokens: options.window_tokens.unwrap_or(0),
            });
            if let Some(summary) = compact_transcript(home, config, options, transcript, cancel) {
                // B6: keep the tail verbatim (the current prompt is the
                // last message) and let the summary stand in for older
                // history. The system prompt rides `options`, not the
                // transcript, so it is untouched here.
                let keep_from = transcript.len().saturating_sub(COMPACT_KEEP_TAIL);
                let tail: Vec<ChatMessage> = transcript.split_off(keep_from);
                transcript.push(user_message(format!(
                    "[context compacted from {keep_from} older messages]\n\n{summary}"
                )));
                transcript.extend(tail);
                events(FrontendEvent::Compacted {
                    summary: summary.clone(),
                });
                compacted_at = Some(estimate_transcript_tokens(transcript));
            }
        }

        // One dispatch, with retry on rate-limit-class refusals.
        let outcome = dispatch_with_retry(
            home, config, options, prompt, transcript, cancel, round, events,
        );

        let o = match outcome {
            Ok(o) => o,
            Err(e) => {
                if e == "cancelled" {
                    report.interrupted = true;
                    report.ok = false;
                    emit_turn_ended(events, &report, round);
                    return Ok(report);
                }
                events(FrontendEvent::Error { message: e.clone() });
                emit_turn_ended(events, &report, round);
                return Err(e);
            }
        };

        report.rounds = round + 1;
        report.input_tokens += o.input_tokens;
        report.output_tokens += o.output_tokens;
        report.cost_microcents += o.cost_microcents;
        events(FrontendEvent::CostUpdated {
            total_microcents: report.cost_microcents,
        });
        // The context meter (M18): tokens in use vs the window.
        if let Some(w) = options.window_tokens {
            events(FrontendEvent::Usage {
                used_tokens: report.input_tokens,
                window_tokens: w,
            });
        }

        if o.tool_calls.is_empty() {
            // Terminal text round. A `length` stop means the reply was
            // cut off by the output-token limit — end the turn with a
            // visible note instead of silently treating it as done.
            let truncated = matches!(
                o.finish_reason.as_deref(),
                Some("length") | Some("max_tokens")
            );
            if truncated {
                events(FrontendEvent::OutputTruncated {
                    limit: config.max_output_tokens,
                });
            }
            transcript.push(assistant_message_with_thinking(
                o.output.clone(),
                o.thinking.clone(),
                o.thinking_signature.clone(),
            ));
            report.final_text = o.output.clone();
            report.ok = true;
            events(FrontendEvent::ResponseFinished {
                output: o.output.clone(),
                input_tokens: report.input_tokens,
                output_tokens: report.output_tokens,
                cost_microcents: report.cost_microcents,
            });
            emit_turn_ended(events, &report, report.rounds);
            return Ok(report);
        }

        // Tool round: append the assistant call message, execute each
        // call, append the results.
        let assistant_calls: Vec<orbit_adapter::types::ToolCallMessage> = o
            .tool_calls
            .iter()
            .map(|tc| orbit_adapter::types::ToolCallMessage {
                id: tc.id.clone(),
                name: tc.name.clone(),
                arguments: String::from_utf8_lossy(&tc.arguments).into_owned(),
            })
            .collect();
        transcript.push(assistant_with_calls_and_thinking(
            o.output.clone(),
            assistant_calls,
            o.thinking.clone(),
            o.thinking_signature.clone(),
        ));

        // The TUI's tool-line motion (M07/M08/M09/M10): the full
        // start (kind + target) before execution, the finish with a
        // result fact after. Targets are display-safe (the CLI
        // executor's summaries pass the secret scanner before this).
        for tc in &o.tool_calls {
            let target = String::from_utf8_lossy(&tc.arguments)
                .parse::<serde_json::Value>()
                .ok()
                .and_then(|a| {
                    a.get("command")
                        .or_else(|| a.get("file_path"))
                        .or_else(|| a.get("path"))
                        .or_else(|| a.get("pattern"))
                        .or_else(|| a.get("prompt"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_default();
            events(FrontendEvent::ToolStartedFull {
                call_id: tc.id.clone(),
                kind: tc.name.clone(),
                target,
            });
        }
        // Esc (MD §The agent loop): install the turn's cancel-checker
        // so long-running tool children (Bash) die with the stream.
        // Cleared after the round so a later turn starts clean.
        let cancel_for_tools = cancel.clone();
        orbit_tools::interrupt::set_cancel_check(Some(std::sync::Arc::new(move || {
            cancel_for_tools.is_cancelled()
        })));
        let results = executor.execute(&o.tool_calls, round);
        orbit_tools::interrupt::set_cancel_check(None);
        for r in &results {
            // A result fact for the settle animation: first small
            // truth in the payload (lines, tests, exit code).
            let fact = serde_json::from_str::<serde_json::Value>(&r.content)
                .ok()
                .and_then(|v| {
                    v.get("lines")
                        .or_else(|| v.get("tests_passed"))
                        .or_else(|| v.get("exit_code"))
                        .or_else(|| v.get("count"))
                        .map(|f| f.to_string())
                })
                .unwrap_or_default();
            let ok = !r.content.contains("\"ok\":false") && !r.content.contains("\"ok\": false");
            events(FrontendEvent::ToolFinishedFull {
                call_id: r.call_id.clone(),
                ok,
                result_fact: fact,
            });
        }
        for r in results {
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: r.content.clone(),
                tool_calls: None,
                tool_call_id: Some(r.call_id.clone()),
                tool_result: Some(r.content),
                blocks: None,
            });
        }

        round += 1;
        if round >= options.max_rounds {
            let msg = format!(
                "turn stopped by the round guard: {} rounds (the model kept calling tools)",
                options.max_rounds
            );
            events(FrontendEvent::Status { text: msg.clone() });
            report.final_text = o.output;
            emit_turn_ended(events, &report, round);
            return Ok(report);
        }
    }
}

fn emit_turn_ended(events: EventSink<'_>, report: &TurnReport, rounds: u32) {
    events(FrontendEvent::TurnEnded {
        ok: report.ok,
        interrupted: report.interrupted,
        rounds,
        input_tokens: report.input_tokens,
        output_tokens: report.output_tokens,
        cost_microcents: report.cost_microcents,
    });
}

// ── dispatch + retry ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn dispatch_with_retry(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &[ChatMessage],
    cancel: &orbit_provider_http::CancelToken,
    _round: u32,
    events: EventSink<'_>,
) -> Result<crate::dispatch::TurnOutcome, String> {
    let mut attempt: u32 = 1;
    loop {
        // Mods directive: a System message at the FRONT of the provider
        // transcript (never persisted to the session file — it's rebuilt
        // from the enabled set every turn).
        let mut wire_transcript = transcript.to_vec();
        if let Some(directive) = &options.system_directive {
            if !directive.is_empty() {
                wire_transcript.insert(
                    0,
                    ChatMessage {
                        role: ChatRole::System,
                        content: directive.clone(),
                        tool_calls: None,
                        tool_call_id: None,
                        tool_result: None,
                        blocks: None,
                    },
                );
            }
        }
        // Live stream: forward TextDelta bytes to the front-end as
        // protocol events. The observer borrows `events` for the
        // duration of the dispatch call only.
        let mut observer = |ev: &orbit_adapter::types::ProviderStreamEvent| {
            if let orbit_adapter::types::ProviderEventKind::TextDelta { bytes } = &ev.event {
                events(FrontendEvent::TextDelta {
                    text: String::from_utf8_lossy(bytes).into_owned(),
                });
            }
        };
        let result = crate::dispatch::run_dispatch(
            home,
            config,
            prompt,
            Some(wire_transcript),
            Some(&mut observer),
            cancel.clone(),
            options.tools.clone(),
            &options.request_stem,
        );
        match result {
            Ok(o) => return Ok(o),
            Err((code, msg)) if is_retryable(code) && attempt < options.max_attempts => {
                // Exponential backoff with jitter: 1s, 2s, 4s, … capped
                // at 32s; ~8 attempts span about two minutes.
                let base = 1000u64.saturating_mul(1 << (attempt - 1).min(5));
                let jitter = ulid::Ulid::new().timestamp_ms() % 250;
                let delay = base + jitter;
                events(FrontendEvent::Retrying {
                    attempt,
                    retry_in_ms: delay,
                    reason: format!("{code}: {msg}"),
                });
                // Abort the backoff wait when cancelled.
                let deadline = std::time::Instant::now() + Duration::from_millis(delay);
                while std::time::Instant::now() < deadline {
                    if cancel.is_cancelled() {
                        return Err("cancelled".into());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                attempt += 1;
            }
            Err((code, msg)) => return Err(format!("{code}: {msg}")),
        }
    }
}

/// Rate-limit and server-overload classes retry; authentication and
/// 400-class request errors never do (roadmap §The agent loop).
fn is_retryable(code: &str) -> bool {
    matches!(
        code,
        "ORBIT-E0407" | "ORBIT-E0503" | "ORBIT-E0504" | "ORBIT-E0529"
    ) || code.starts_with("E0407")
        || code.starts_with("E0503")
        // E2: provider capacity (500/502/503/504/529 → E0408) and
        // transport failures (E0410, incl. connection resets) are
        // transient — retry with the same backoff as 429.
        || code.starts_with("E0408")
        || code.starts_with("E0410")
}

// The CLI's tool definitions are reused, not copied: a thin re-export
// shim keeps the engine free of a circular dependency (cli → engine
// for the loop; engine → cli's tools via this alias). In phase 3 the
// tool runtime moves bodily into the engine and the shim inverts.

/// Build the opaque thinking block for replay. The signature (when the
/// provider sent one) is replayed verbatim — the API rejects unsigned
/// replayed thinking.
fn thinking_block_json(thinking: &str, signature: Option<&str>) -> String {
    let mut v = serde_json::json!({ "type": "thinking", "thinking": thinking });
    if let Some(s) = signature.filter(|s| !s.is_empty()) {
        v["signature"] = serde_json::json!(s);
    }
    v.to_string()
}

/// An assistant message carrying replay-only thinking as an opaque block.
/// The thinking JSON is stored verbatim; the adapter replays it unchanged.
pub(crate) fn assistant_message_with_thinking(
    text: String,
    thinking: Option<String>,
    signature: Option<String>,
) -> ChatMessage {
    let mut m = assistant_message(text);
    if let Some(t) = thinking.filter(|t| !t.is_empty()) {
        m.blocks = Some(vec![orbit_adapter::types::ContentBlock::Opaque {
            json: thinking_block_json(&t, signature.as_deref()),
        }]);
    }
    m
}

/// An assistant tool-call message with replay-only thinking attached.
pub(crate) fn assistant_with_calls_and_thinking(
    text: String,
    calls: Vec<orbit_adapter::types::ToolCallMessage>,
    thinking: Option<String>,
    signature: Option<String>,
) -> ChatMessage {
    let mut m = ChatMessage {
        role: ChatRole::Assistant,
        content: text,
        tool_calls: Some(calls),
        tool_call_id: None,
        tool_result: None,
        blocks: None,
    };
    if let Some(t) = thinking.filter(|t| !t.is_empty()) {
        m.blocks = Some(vec![orbit_adapter::types::ContentBlock::Opaque {
            json: thinking_block_json(&t, signature.as_deref()),
        }]);
    }
    m
}

/// An executor that never runs anything (compaction dispatch carries
/// no tools, so nothing can be called).
struct NoopExecutor;

impl ToolExecutor for NoopExecutor {
    fn execute(
        &mut self,
        calls: &[crate::dispatch::PendingToolCall],
        _round: u32,
    ) -> Vec<crate::ToolRoundResult> {
        calls
            .iter()
            .map(|c| crate::ToolRoundResult {
                call_id: c.id.clone(),
                content: r#"{"ok":false,"error":"compaction dispatch advertises no tools"}"#.into(),
            })
            .collect()
    }
}

/// Run one no-tools summarization dispatch over the transcript and
/// return the summary. Simple compaction (roadmap: the whole history
/// becomes one summary + the latest user message; server-side
/// compaction arrives with the live Anthropic leg).
/// How many trailing messages survive compaction verbatim. The current
/// prompt is always among them (it is the transcript's tail); the rest
/// keep the newest exchanges in their own words.
const COMPACT_KEEP_TAIL: usize = 6;

fn compact_transcript(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    transcript: &[ChatMessage],
    cancel: &orbit_provider_http::CancelToken,
) -> Option<String> {
    // Split: the newest COMPACT_KEEP_TAIL messages survive verbatim;
    // only what precedes them is summarised (B6: never summarise the
    // in-flight prompt — it sits at the tail).
    let keep_from = transcript.len().saturating_sub(COMPACT_KEEP_TAIL);
    let digest: String = transcript[..keep_from]
        .iter()
        .map(|m| match m.role {
            ChatRole::User | ChatRole::Assistant => format!(
                "{}: {}\n",
                m.role.as_str(),
                truncate(m.content.as_str(), 400)
            ),
            ChatRole::Tool => format!(
                "tool result: {}\n",
                truncate(m.tool_result.as_deref().unwrap_or(""), 200)
            ),
            ChatRole::System => String::new(),
        })
        .collect();
    let prompt = format!(
        "Summarize this conversation for continuation. Keep: the task, decisions made, files touched, open questions, and the current plan. Be concise.\n\n{digest}"
    );
    let mut opts = TurnOptions {
        tools: Vec::new(),
        system_directive: None,
        request_stem: format!("{}-compact", options.request_stem),
        window_tokens: options.window_tokens,
        output_reserve_tokens: options.output_reserve_tokens,
        compacting: true,
        ..Default::default()
    };
    opts.max_rounds = 1;
    opts.max_attempts = 2;
    let mut scratch: Vec<ChatMessage> = Vec::new();
    let mut noop = NoopExecutor;
    // Private sink (B6): the summary turn is housekeeping, not a turn
    // the front-end should see. Its deltas, usage and turn_ended would
    // land mid-turn on the real stream — swallow everything.
    let mut private_sink = |_ev: FrontendEvent| {};
    let report = run_turn(
        home,
        config,
        &opts,
        &prompt,
        &mut scratch,
        &mut noop,
        cancel,
        &mut private_sink,
    )
    .ok()?;
    (!report.final_text.is_empty()).then_some(report.final_text)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_codes() {
        assert!(is_retryable("ORBIT-E0407"));
        assert!(!is_retryable("ORBIT-E0402")); // auth: never retry
        assert!(!is_retryable("ORBIT-E0401")); // bad url: never retry
    }
}
