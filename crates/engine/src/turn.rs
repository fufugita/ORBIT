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
    /// A system directive prepended to the wire transcript (mods /
    /// plan mode). Never persisted to the session file — the caller
    /// rebuilds it from the enabled set every turn.
    pub system_directive: Option<String>,
    /// Request-id stem for ledger records (e.g. "orbit-tui", "orbit-p").
    pub request_stem: String,
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

    loop {
        if cancel.is_cancelled() {
            report.interrupted = true;
            report.ok = false;
            emit_turn_ended(events, &report, round);
            return Ok(report);
        }

        events(FrontendEvent::RoundStarted { round });

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
            transcript.push(assistant_message(o.output.clone()));
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
        transcript.push(ChatMessage {
            role: ChatRole::Assistant,
            content: o.output.clone(),
            tool_calls: Some(assistant_calls),
            tool_call_id: None,
            tool_result: None,
        });

        let results = executor.execute(&o.tool_calls, round);
        for r in results {
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: r.content.clone(),
                tool_calls: None,
                tool_call_id: Some(r.call_id.clone()),
                tool_result: Some(r.content),
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
}

// The CLI's tool definitions are reused, not copied: a thin re-export
// shim keeps the engine free of a circular dependency (cli → engine
// for the loop; engine → cli's tools via this alias). In phase 3 the
// tool runtime moves bodily into the engine and the shim inverts.
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
