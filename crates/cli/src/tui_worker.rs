//! TUI worker thread — drives `run_turn` + tool execution for the TUI front-end.
//!
//! The worker receives user prompts via `Msg::TextSubmitted` and runs the
//! four-gate pipeline. Stream events flow through the TUI bridge (display_safe
//! + CoT stripping). Tool approvals resolve via the `ApprovalRegistry`.
//!
//! This is the TUI-specific counterpart to the REPL loop — the REPL's inline
//! logic in `cmd_chat` is untouched.

use orbit_adapter::types::{ChatMessage, ChatRole, ProviderEventKind, ProviderStreamEvent};
use orbit_hud_tui::bus::BusSender;
use orbit_hud_tui::msg::Msg;
use orbit_hud_tui::worker::{PromptSink, WorkerCtx};
use orbit_hud_tui::{ApprovalRegistry, ApprovalResponse};
use std::path::PathBuf;
use std::sync::mpsc;

/// The per-turn state the worker needs to run one prompt.
#[derive(Clone)]
pub struct TuiTurnConfig {
    pub home: PathBuf,
    pub session_id: String,
    pub gate: String,
    pub model: String,
    pub provider_id: String,
    pub auto_tools: bool,
}

/// Build the worker spawner closure for the TUI. The CLI owns `run_turn`;
/// this closure captures the turn config and spawns a thread that drives it.
pub fn make_spawner(config: TuiTurnConfig) -> orbit_hud_tui::WorkerSpawner {
    Box::new(move |ctx: WorkerCtx, _prompt_sink: PromptSink| {
        std::thread::Builder::new()
            .name("orbit-tui-worker".into())
            .spawn(move || worker_main(ctx, config))
            .map(|_| ())
            .map_err(|e| format!("spawn worker: {e}"))
    })
}

/// The worker's event loop — waits for prompts, runs turns, reports results.
fn worker_main(ctx: WorkerCtx, config: TuiTurnConfig) {
    let mut transcript: Vec<ChatMessage> = Vec::new();

    // Send identity to the TUI so the status bar shows model/provider/session.
    ctx.sender.send(Msg::Identity {
        model: config.model.clone(),
        provider: config.provider_id.clone(),
        session_prefix: config.session_id.chars().take(8).collect(),
    });

    while let Ok(prompt) = ctx.prompt_rx.recv() {
        let (ok, input, output, cost) = match run_tui_turn(
            &config,
            &mut transcript,
            &prompt,
            &ctx.sender,
            &ctx.approvals,
        ) {
            Ok(x) => x,
            Err(e) => {
                orbit_hud_tui::emit_error(&ctx.sender, &e);
                continue;
            }
        };
        if ok {
            orbit_hud_tui::emit_response_finished(&ctx.sender, "", input, output, cost);
        }
    }
}

/// A TUI-aware approval channel. Implements the CLI's `ApprovalChannel` trait
/// by posting a request to the bus and parking on a oneshot channel registered
/// in the `ApprovalRegistry`.
pub struct TuiApprovalChannel {
    sender: BusSender,
    approvals: ApprovalRegistry,
}

impl TuiApprovalChannel {
    pub fn new(sender: BusSender, approvals: ApprovalRegistry) -> Self {
        Self { sender, approvals }
    }
}

impl crate::tool_runtime::ApprovalChannel for TuiApprovalChannel {
    fn ask(
        &mut self,
        req: &crate::tool_runtime::ApprovalRequest,
        _auto_tools: bool,
    ) -> crate::tool_runtime::ApprovalVerdict {
        // Register a oneshot channel for this call.
        let (tx, rx) = mpsc::channel();
        self.approvals.register(&req.call_id, tx);
        // Post the request to the bus — the reducer renders an approval card.
        self.sender.send(Msg::ApprovalRequested {
            call_id: req.call_id.clone(),
            tool_name: req.tool_name.clone(),
            summary: req.summary.clone(),
        });
        // Park until the operator responds (y/n/R). Esc handled as deny.
        match rx.recv() {
            Ok(ApprovalResponse::Allow) => crate::tool_runtime::ApprovalVerdict::AllowOnce,
            Ok(ApprovalResponse::AllowSession) => {
                crate::tool_runtime::ApprovalVerdict::AllowSession
            }
            Ok(ApprovalResponse::Deny) | Err(_) => crate::tool_runtime::ApprovalVerdict::Deny,
        }
    }
}

/// Run one user turn against the gateway, streaming through the TUI bridge.
/// Returns (turn_ok, input_tokens, output_tokens, cost_microcents).
#[allow(clippy::too_many_arguments)]
pub fn run_tui_turn(
    config: &TuiTurnConfig,
    transcript: &mut Vec<ChatMessage>,
    prompt: &str,
    sender: &BusSender,
    approvals: &ApprovalRegistry,
) -> Result<(bool, u64, u64, u64), String> {
    let mut input_tokens = 0u64;
    let mut output_tokens = 0u64;
    let mut cost = 0u64;

    // Observer: map stream events to TUI messages via the bridge.
    let mut observer = |ev: &ProviderStreamEvent| {
        if let ProviderEventKind::TextDelta { bytes } = &ev.event {
            orbit_hud_tui::emit_text(sender, bytes);
        }
    };

    // Resolve provider / pricing from config (same as REPL).
    let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
    let provider = cfg.provider_for_model(&config.model);
    let pricing = cfg.pricing_for_model(&config.model);
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or(config.provider_id.as_str());
    let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&config.gate);
    let credential_env = provider.and_then(|p| p.env.as_deref());

    // Build the transcript for this user turn.
    transcript.push(ChatMessage {
        role: ChatRole::User,
        content: prompt.to_string(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
    });

    let mut turn_ok = false;
    for round in 0..8u32 {
        let outcome = crate::run_turn(
            &config.home,
            provider_id,
            resolved_gate,
            &config.model,
            credential_env,
            pricing,
            prompt,
            Some(transcript.clone()),
            Some(&mut observer),
        );
        let o = match outcome {
            Ok(o) => o,
            Err((code, msg)) => {
                orbit_hud_tui::emit_error(sender, &format!("{code}: {msg}"));
                return Ok((false, input_tokens, output_tokens, cost));
            }
        };
        input_tokens += o.input_tokens;
        output_tokens += o.output_tokens;
        cost += o.cost_microcents;
        orbit_hud_tui::emit_cost(sender, cost);

        if o.tool_calls.is_empty() {
            // Normal text terminal.
            transcript.push(ChatMessage {
                role: ChatRole::Assistant,
                content: o.output.clone(),
                tool_calls: None,
                tool_call_id: None,
                tool_result: None,
            });
            turn_ok = true;
            break;
        }

        if o.tool_calls.len() > 16 {
            orbit_hud_tui::emit_error(
                sender,
                "ORBIT-E0200: provider requested more than 16 tools in one round",
            );
            break;
        }

        // Append the assistant tool-call message.
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

        // Execute each tool call via the TUI approval channel.
        let mut approval_channel = TuiApprovalChannel::new(sender.clone(), approvals.clone());
        let mut auto_grants = crate::tool_runtime::AutoGrants::new();
        for call in &o.tool_calls {
            // Display-safe summary first.
            let args =
                crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
            let summary = crate::tools::safe_call_summary(&call.name, &args);
            orbit_hud_tui::emit_tool_started(sender, &call.name, &summary);

            let decision_id = format!("tool-round-{round}-{}", call.index);
            let result = crate::tool_runtime::execute_call(
                &config.home,
                &config.session_id,
                &decision_id,
                call,
                config.auto_tools,
                true,
                &mut approval_channel,
                &mut auto_grants,
            )
            .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e }).to_string());
            let ok = result.contains("\"ok\":true");
            orbit_hud_tui::emit_tool_finished(sender, &call.name, ok);
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: result.clone(),
                tool_calls: None,
                tool_call_id: Some(call.id.clone()),
                tool_result: Some(result),
            });
        }
        // The next provider round receives the assistant call + tool results.
    }

    if !turn_ok {
        orbit_hud_tui::emit_error(
            sender,
            "ORBIT-E0406: tool loop ended without a final assistant response",
        );
    } else {
        // Save the session (same as REPL).
        let sf = crate::sessions::SessionFile::from_chat(
            &config.session_id,
            &config.model,
            &config.gate,
            &config.provider_id,
            transcript,
            0,
            input_tokens,
            output_tokens,
            cost,
        );
        if let Err(e) = crate::sessions::save_session(&config.home, &sf) {
            orbit_hud_tui::emit_error(sender, &format!("warning: session not saved: {e}"));
        }
    }

    Ok((turn_ok, input_tokens, output_tokens, cost))
}
