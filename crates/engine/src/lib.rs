//! orbit-engine — THE agent loop (phase 2 of the roadmap).
//!
//! One loop behind every front-end. Until now four copies existed
//! (REPL, TUI worker, web bridge, Go bridge), each with its own
//! round caps and quirks; a feature landed four times or only in one
//! front-end. This crate is the single place a turn runs.
//!
//! What the engine owns:
//! - The dispatch core (moved bodily from orbit-cli in phase 2): one
//!   provider round through the four-gate pipeline — route binding,
//!   egress allowlist, ledger write, stream assembly.
//! - The round loop: no fixed 8-round cap; runs until the model stops
//!   calling tools, a stop reason ends the turn, or the operator
//!   cancels. A configurable guard (default 100) stops a runaway turn
//!   and says why.
//! - Stop reasons: `end_turn`/`stop` ends the turn; `tool_calls` runs
//!   them; `length`/`max_tokens` inside text ends the turn with a
//!   visible cut-off note (the old loops treated it as done).
//! - Retry with backoff on 429/529-class refusals: up to 8 attempts,
//!   exponential with jitter, each attempt a fresh dispatch.
//! - Turn events in `orbit-frontend-protocol` v2: the same stream the
//!   TUI, REPL, web and `orbit -p` consume.
//!
//! Tool execution stays caller-injected until phase 3 moves the tool
//! runtime into the engine (see [`ToolExecutor`]); the system prompt
//! and context builder are phase-4 work.

pub mod context;
pub mod dispatch;
pub mod transcript;
pub mod turn;

pub use dispatch::{run_dispatch, PendingToolCall, ProviderKind, TurnConfig, TurnOutcome};
pub use turn::{run_turn, TurnOptions, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_ROUNDS};

use orbit_adapter::types::ChatMessage;
use orbit_frontend_protocol::FrontendEvent;

/// How the engine reports progress. Every front-end maps this onto its
/// own UI; `orbit -p` serialises them verbatim as stream-json.
pub type EventSink<'a> = &'a mut dyn FnMut(FrontendEvent);

/// The result of a completed engine turn.
#[derive(Debug, Clone, Default)]
pub struct TurnReport {
    pub ok: bool,
    pub interrupted: bool,
    pub rounds: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
    pub final_text: String,
}

/// Executes tool calls decided by the engine. Injected by the caller
/// until phase 3 moves the tool runtime into the engine. The executor
/// owns approval policy, grants and the ledger's tool records; the
/// engine appends each returned result to the transcript.
pub trait ToolExecutor {
    /// Run the calls produced by round `round`. Returns the tool
    /// results in the model's order.
    fn execute(&mut self, calls: &[PendingToolCall], round: u32) -> Vec<ToolRoundResult>;
}

/// One executed tool call: the provider call id + the JSON payload
/// returned to the model.
#[derive(Debug, Clone)]
pub struct ToolRoundResult {
    pub call_id: String,
    pub content: String,
}

/// A user message.
pub fn user_message(text: impl Into<String>) -> ChatMessage {
    ChatMessage {
        role: orbit_adapter::types::ChatRole::User,
        content: text.into(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        blocks: None,
    }
}

/// An assistant message.
pub fn assistant_message(text: impl Into<String>) -> ChatMessage {
    ChatMessage {
        role: orbit_adapter::types::ChatRole::Assistant,
        content: text.into(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        blocks: None,
    }
}
