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
//! - Request accounting precedes each dispatch. Opaque failures stop with
//!   uncertainty; another attempt requires positive non-admission evidence.
//! - Turn events in `orbit-frontend-protocol` v2: the same stream the
//!   TUI, REPL, web and `orbit -p` consume.
//!
//! Tool execution stays caller-injected until phase 3 moves the tool
//! runtime into the engine (see [`ToolExecutor`]); the system prompt
//! and context builder are phase-4 work.

pub mod agent_store;
pub mod automation;
pub mod compaction;
pub mod context;
pub mod context_budget;
pub mod diff;
pub mod dispatch;
pub mod hooks;
pub mod plugin_hooks;
pub mod retry;
pub mod routing;
pub mod skills;
pub mod transcript;
pub mod turn;

static BARE_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Select minimal configuration for this process before starting workers.
/// Once selected, bare mode remains enabled for the process's lifetime.
pub fn enable_bare_mode() {
    BARE_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Shared by configuration discovery and hook execution across worker threads.
pub fn bare_mode() -> bool {
    BARE_MODE.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var("ORBIT_BARE").is_ok_and(|value| value == "1")
}

pub use compaction::{
    AccountingBaseline, AccountingCheckpoint, AccountingDelta, AccountingKnownness,
    AccountingRevision, AccountingTotals, AttemptIntent, AttemptPurpose, AttemptRef,
    CompactionAttempt, CompactionCandidate, CompactionCoverage, CompactionJournal,
    CompactionReceipt, CompactionRecordRef, CompactionStatus, HistoryError, KnownPricedSubtotals,
    ManualCompactionCompletion, MessageRange, PendingAttempt, RequestAccountingReceipt,
    SettledAttempt, compact_context, compact_context_detailed,
};
pub use dispatch::{
    BudgetedDispatchFailure, BudgetedTurnOutcome, PendingToolCall, ProviderKind, TurnConfig,
    TurnOutcome, run_budgeted_dispatch, run_dispatch,
};
pub use turn::{
    DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_ROUNDS, MAX_TURN_ACCOUNTING_ATTEMPTS, SpendAllowance,
    SubagentTurn, TurnCompletion, TurnEnd, TurnFailure, TurnOptions, run_turn, run_turn_detailed,
};

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
    /// Earlier tool results dropped from this turn to fit its context budget.
    pub dropped_tool_results: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Micro-dollars (1,000,000 is $1). The name is historical and is kept
    /// because saved sessions and the CLI's JSON carry it.
    pub cost_microcents: u64,
    pub final_text: String,
    /// Current-turn deltas, separate from occupancy and historical checkpoints.
    pub accounting: AccountingDelta,
    /// At most MAX_TURN_ACCOUNTING_ATTEMPTS actual request receipts. These are
    /// already included in accounting and must never be applied a second time.
    pub attempts: Vec<RequestAccountingReceipt>,
}

/// Executes tool calls decided by the engine. Injected by the caller
/// until phase 3 moves the tool runtime into the engine. The executor
/// owns approval policy, grants and the ledger's tool records; the
/// engine appends each returned result to the transcript.
pub trait ToolExecutor {
    /// Run the calls produced by round `round`. Returns the tool
    /// results in the model's order.
    fn execute(&mut self, calls: &[PendingToolCall], round: u32) -> Vec<ToolRoundResult>;

    /// The turn is starting with this provider configuration (gateway,
    /// model, credential, pricing). A tool that starts a nested turn — a
    /// subagent — must run on the SAME provider as the session; the
    /// executor keeps the configuration where its tools can reach it. The
    /// default ignores it.
    fn begin_turn(&mut self, _config: &TurnConfig) {}

    /// The turn (or a nested round of tools) is starting: its cancel token
    /// is now current, including while lifecycle hooks run. The default
    /// ignores it.
    fn begin_cancel_scope(&mut self, _token: &orbit_provider_http::CancelToken) {}

    /// The cancellation scope is done; restore its previous token.
    fn end_cancel_scope(&mut self) {}

    /// The handler runner for this invocation's context. A subagent must
    /// supply its own context rather than using the installed session's.
    fn hook_handler_runner(&self) -> Option<std::sync::Arc<crate::hooks::HandlerRunner>> {
        None
    }
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
        origin_model: None,
        origin_provider: None,
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
        origin_model: None,
        origin_provider: None,
    }
}
