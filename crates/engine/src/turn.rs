//! The engine's turn loop — one prompt, many rounds, one place.
//!
//! Replaces the four per-front-end loops (REPL, TUI worker, web bridge,
//! Go bridge), each of which had its own 8-round cap and quirks. The
//! loop runs until the model stops calling tools, a stop reason ends
//! the turn, the operator cancels, or the round guard fires.

use crate::compaction::{
    AccountingKnownness, AccountingTotals, AttemptIntent, AttemptPurpose, RequestAccountingReceipt,
};
use crate::{
    EventSink, ToolExecutor, TurnReport, assistant_message, dispatch::TurnConfig, user_message,
};
use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_frontend_protocol::FrontendEvent;
use std::time::Duration;

/// Guard against a runaway turn (roadmap default: 100).
pub const DEFAULT_MAX_ROUNDS: u32 = 100;

/// Compatibility retry setting; opaque dispatch errors cannot prove safe replay.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

/// Bounded current-turn metadata, independent of operator round/retry settings.
pub const MAX_TURN_ACCOUNTING_ATTEMPTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendAllowance {
    /// Admission policy over prepared token estimates, not a provider-enforced
    /// monetary reservation. The caller supplies this namespace's remaining sum.
    pub remaining_microcents: u64,
    pub allow_unpriced_housekeeping: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnFailure {
    pub message: String,
}
impl std::fmt::Display for TurnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for TurnFailure {}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnEnd {
    Completed,
    Cancelled,
    Failed(TurnFailure),
}
#[derive(Debug, Clone)]
pub struct TurnCompletion {
    pub report: TurnReport,
    pub end: TurnEnd,
}

/// Invocation-local final rejections, kept separate from measured receipts.
#[derive(Debug, Clone)]
pub struct RetryTurnCompletion {
    completion: TurnCompletion,
    refusals: Vec<crate::retry::RefusalRecord>,
}
impl RetryTurnCompletion {
    pub fn completion(&self) -> &TurnCompletion {
        &self.completion
    }
    pub fn refusals(&self) -> &[crate::retry::RefusalRecord] {
        &self.refusals
    }
    pub fn into_parts(self) -> (TurnCompletion, Vec<crate::retry::RefusalRecord>) {
        (self.completion, self.refusals)
    }
    pub fn into_completion(self) -> TurnCompletion {
        self.completion
    }
}

fn remaining_accounting_metadata(
    report: &TurnReport,
    refusals: &[crate::retry::RefusalRecord],
) -> Result<usize, &'static str> {
    report
        .attempts
        .len()
        .checked_add(refusals.len())
        .and_then(|used| MAX_TURN_ACCOUNTING_ATTEMPTS.checked_sub(used))
        .ok_or("turn accounting metadata limit reached; start a new turn (ORBIT-E0411)")
}

fn record_accounting_with_refusals(
    report: &mut TurnReport,
    refusals: &[crate::retry::RefusalRecord],
    receipts: &[RequestAccountingReceipt],
) -> Result<bool, &'static str> {
    if receipts.len() > remaining_accounting_metadata(report, refusals)? {
        return Err("turn accounting metadata limit reached; start a new turn (ORBIT-E0411)");
    }
    record_accounting(report, receipts)
}

fn accumulate_accounting(
    report: &mut TurnReport,
    outcome: &crate::dispatch::TurnOutcome,
) -> Result<(), &'static str> {
    let input_tokens = report
        .input_tokens
        .checked_add(outcome.input_tokens)
        .ok_or("provider input accounting overflow (ORBIT-E0411)")?;
    let output_tokens = report
        .output_tokens
        .checked_add(outcome.output_tokens)
        .ok_or("provider output accounting overflow (ORBIT-E0411)")?;
    let cost_microcents = report
        .cost_microcents
        .checked_add(outcome.cost_microcents)
        .ok_or("provider cost accounting overflow (ORBIT-E0411)")?;
    report.input_tokens = input_tokens;
    report.output_tokens = output_tokens;
    report.cost_microcents = cost_microcents;
    Ok(())
}

/// Preserve only validated summary subtotals in the legacy numeric report.
/// Missing usage or pricing is separately visible, never a fabricated zero bill.
fn record_accounting(
    report: &mut TurnReport,
    receipts: &[RequestAccountingReceipt],
) -> Result<bool, &'static str> {
    if receipts.len() > MAX_TURN_ACCOUNTING_ATTEMPTS.saturating_sub(report.attempts.len()) {
        return Err("turn accounting metadata limit reached; start a new turn (ORBIT-E0411)");
    }
    for receipt in receipts {
        receipt
            .validate()
            .map_err(|_| "provider request accounting is invalid (ORBIT-E0411)")?;
    }
    // Every receipt describes work that has already happened. Retain the full
    // bounded batch before a subtotal overflow can stop arithmetic progress.
    report.attempts.extend_from_slice(receipts);
    let mut incomplete = false;
    let mut delta_overflow = false;
    let mut numeric_overflow = false;
    for receipt in receipts {
        if !delta_overflow {
            match report.accounting.checked_with(receipt) {
                Ok(delta) => report.accounting = delta,
                Err(_) => delta_overflow = true,
            }
        }
        if !numeric_overflow && receipt.knownness == AccountingKnownness::Known {
            numeric_overflow = accumulate_accounting(
                report,
                &crate::TurnOutcome {
                    input_tokens: receipt.totals.input_tokens,
                    output_tokens: receipt.totals.output_tokens,
                    cost_microcents: receipt.totals.cost_microcents.unwrap_or(0),
                    ..Default::default()
                },
            )
            .is_err();
        }
        incomplete |= receipt.knownness != AccountingKnownness::Known
            || receipt.totals.cost_microcents.is_none();
    }
    if delta_overflow || numeric_overflow {
        report.accounting.knownness = AccountingKnownness::Uncertain;
        report.accounting.ordinary.cost_microcents = None;
        report.accounting.housekeeping.cost_microcents = None;
        return Err("provider accounting overflow; inspect request receipts (ORBIT-E0411)");
    }
    Ok(incomplete)
}

fn remaining_allowance(
    options: &TurnOptions,
    report: &TurnReport,
) -> Result<Option<SpendAllowance>, String> {
    let Some(mut allowance) = options.spend_allowance else {
        return Ok(None);
    };
    if report.accounting.knownness != AccountingKnownness::Known
        || report.attempts.iter().any(|receipt| {
            receipt.knownness != AccountingKnownness::Known
                || (receipt.totals.cost_microcents.is_none()
                    && (receipt.purpose == AttemptPurpose::Ordinary
                        || !allowance.allow_unpriced_housekeeping))
        })
    {
        return Err("spend allowance cannot continue with unknown request costs".into());
    }
    allowance.remaining_microcents = allowance
        .remaining_microcents
        .checked_sub(report.cost_microcents)
        .ok_or_else(|| "spend allowance exhausted before another provider request".to_string())?;
    Ok(Some(allowance))
}

struct OccupancyAnchor {
    before: crate::context_budget::RequestEstimate,
    identity: crate::context_budget::BudgetIdentity,
    prefix_len: usize,
    observed_context_tokens: Option<u64>,
}

impl OccupancyAnchor {
    fn observed_after(
        &self,
        probe: &crate::dispatch::MeasurementProbe,
        budget: &crate::context_budget::SelectedBudget,
        messages: &[ChatMessage],
        after: &crate::context_budget::RequestEstimate,
    ) -> Option<u64> {
        use crate::context_budget::EstimateStatus;
        if self.identity != budget.identity
            || self.before.status != EstimateStatus::Approximate
            || after.status != EstimateStatus::Approximate
        {
            return None;
        }
        // Re-render the unchanged prefix with this round's frozen system,
        // tools, selection and effort. A replaced prefix or changed renderer
        // must not inherit an observation from a different request.
        let before = probe
            .estimate_messages(messages.get(..self.prefix_len)?, budget)
            .ok()?;
        if before != self.before {
            return None;
        }
        let growth = after
            .estimated_input_tokens
            .checked_sub(before.estimated_input_tokens)?;
        self.observed_context_tokens?.checked_add(growth)
    }
}

struct OrdinaryDispatch {
    outcome: crate::dispatch::TurnOutcome,
    occupancy: OccupancyAnchor,
}

// Accounting publication errors must survive a concurrent cancellation token.
enum OrdinaryDispatchError {
    Failure(String),
    Accounting(String),
    Cancelled,
}
impl From<String> for OrdinaryDispatchError {
    fn from(message: String) -> Self {
        Self::Failure(message)
    }
}
impl From<&str> for OrdinaryDispatchError {
    fn from(message: &str) -> Self {
        Self::Failure(message.into())
    }
}
impl OrdinaryDispatchError {
    fn accounting(error: impl std::fmt::Display) -> Self {
        Self::Accounting(error.to_string())
    }
    fn into_message(self) -> String {
        match self {
            Self::Failure(message) | Self::Accounting(message) => message,
            Self::Cancelled => "cancelled".into(),
        }
    }
}

fn emit_context_usage(
    context: &crate::dispatch::RequestPreparationContext,
    options: &TurnOptions,
    budget: Option<&crate::context_budget::SelectedBudget>,
    messages: &[ChatMessage],
    anchor: Option<&OccupancyAnchor>,
    events: EventSink<'_>,
) {
    let Some(budget) = budget else {
        return;
    };
    let measured = crate::dispatch::measurement_probe(context)
        .ok()
        .and_then(|probe| {
            probe
                .estimate_messages(messages, budget)
                .ok()
                .map(|after| (probe, after))
        });
    let Some((probe, after)) = measured else {
        events(FrontendEvent::Status {
            text: "Current context usage is unknown because the updated request could not be measured."
                .into(),
        });
        return;
    };
    let used_tokens = anchor
        .and_then(|anchor| anchor.observed_after(&probe, budget, messages, &after))
        .unwrap_or(after.estimated_input_tokens)
        .max(after.estimated_input_tokens);
    if after.status == crate::context_budget::EstimateStatus::UnknownMedia {
        events(FrontendEvent::Status {
            text: "Current context usage includes a text estimate; media or opaque request cost remains unknown."
                .into(),
        });
    }
    if let (Some(window_tokens), reserve) = budget.meter_window(after.requested_output_tokens) {
        let memory = (options.memory_bytes as u64).min(after.system_bytes) / 4;
        let system = after.system_bytes / 4 - memory;
        let tools = after.tools_bytes / 4;
        events(FrontendEvent::Usage {
            used_tokens,
            window_tokens,
            breakdown: Some(orbit_frontend_protocol::ContextBreakdown {
                system,
                memory,
                tools,
                messages: after.estimated_input_tokens - system - memory - tools,
                compact_at: budget
                    .compaction_threshold(after.requested_output_tokens)
                    .unwrap_or(0),
                reserve,
            }),
        });
    }
}

fn compaction_display(summary: &str) -> String {
    fn bounded(text: &str) -> &str {
        let mut end = text.len().min(8192);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    }
    // Scan the entire transport-bounded value before cutting its public
    // preview: a cut through a token must not hide it from the scanner.
    let scanned = orbit_tools::scan::scan_result(summary);
    bounded(&scanned.text).to_string()
}

/// Configuration for one engine turn.
#[derive(Debug, Clone)]
pub struct TurnOptions {
    pub max_rounds: u32,
    pub max_attempts: u32,
    /// The session this turn belongs to (E7): the ledger session id,
    /// the checkpoint owner, and the tie between rounds and turns.
    /// Front-ends mint one ULID session at startup and reuse it.
    pub session_id: String,
    /// Tools advertised to the model this turn. `/compact` passes an
    /// EMPTY list: a summarization request must not advertise tools.
    pub tools: Vec<orbit_adapter::types::ToolDefinition>,
    /// Optional structured content for the user message that starts this
    /// turn. Callers supply the prompt's Text block alongside attachments;
    /// the flattened message content remains `prompt` for text consumers.
    /// None keeps the ordinary text-only message behavior.
    pub user_blocks: Option<Vec<orbit_adapter::types::ContentBlock>>,
    /// The frozen system prompt (phase 4: built once per session by
    /// the context builder — base instructions, tools, environment,
    /// memory files, mods). Sent as the System message; never
    /// re-inserted per request (that broke caching and edited-history
    /// replay). Plan mode appends its read-only posture here.
    pub system_directive: Option<String>,
    /// How many bytes of `system_directive` are project instructions (the
    /// memory files), so the context meter can name them apart from the
    /// rest. 0 = not separated.
    pub memory_bytes: usize,
    /// Request-id stem for ledger records (e.g. "orbit-tui", "orbit-p").
    pub request_stem: String,
    /// Legacy caller-supplied input-policy ceiling when selected_budget is absent.
    /// A typed selected_budget takes precedence; this is not a provider-capacity fact.
    pub window_tokens: Option<u64>,
    /// Reserve used by the legacy context_breakdown display helper.
    /// Turn admission reserves actual requested output against combined ceilings.
    pub output_reserve_tokens: u64,
    /// True inside a compaction request itself: never compact while
    /// compacting (the recursion loops when the window is small — the
    /// summary request alone can cross the threshold).
    pub compacting: bool,
    /// An alternate TurnConfig for the compaction dispatch only (the
    /// `compaction` role in providers.toml: a cheap model summarizing
    /// while the conversation keeps its own). None = the conversation's
    /// own config also summarizes. The front-end sets this; the engine
    /// never invents one.
    pub compaction_config: Option<TurnConfig>,
    /// Exact selected capacity policy. None plus window=None is unmanaged legacy.
    pub selected_budget: Option<crate::context_budget::SelectedBudget>,
    /// Independently resolved policy for the selected summarizer.
    pub compaction_budget: Option<crate::context_budget::SelectedBudget>,
    /// Owner-qualified durable compaction/accounting storage. Registration only;
    /// callers inject the implementation when the shared service is activated.
    pub journal: Option<std::sync::Arc<dyn crate::compaction::CompactionJournal>>,
    /// Explicit namespace-local allowance; never inherited as a global cap.
    pub spend_allowance: Option<SpendAllowance>,
}

/// Legacy transcript-only display estimate retained for API compatibility.
/// Uses window_tokens/output_reserve_tokens and approximate text/tool sizes.
/// run_turn admission and Usage events use the prepared dialect request and
/// selected budget, including actual output reservation for combined ceilings.
pub fn context_breakdown(
    options: &TurnOptions,
    transcript: &[ChatMessage],
) -> Option<orbit_frontend_protocol::ContextBreakdown> {
    let window = options.window_tokens?;
    let directive_bytes = options.system_directive.as_deref().map_or(0, str::len);
    let memory_bytes = options.memory_bytes.min(directive_bytes);
    // What a definition costs on the wire: its name, description and schema.
    let tool_bytes: usize = options
        .tools
        .iter()
        .map(|t| t.name.len() + t.description.len() + t.parameters.to_string().len())
        .sum();
    let usable = window.saturating_sub(options.output_reserve_tokens);
    Some(orbit_frontend_protocol::ContextBreakdown {
        system: ((directive_bytes - memory_bytes) / 4) as u64,
        tools: (tool_bytes / 4) as u64,
        memory: (memory_bytes / 4) as u64,
        messages: estimate_transcript_tokens(transcript),
        compact_at: usable / 10 * 9,
        reserve: options.output_reserve_tokens,
    })
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

impl Default for TurnOptions {
    fn default() -> Self {
        TurnOptions {
            max_rounds: DEFAULT_MAX_ROUNDS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            // No tools by default: the caller passes its tool set
            // explicitly (every front-end resolves its own today).
            // Phase 3 moves the tool runtime into the engine.
            tools: Vec::new(),
            user_blocks: None,
            system_directive: None,
            memory_bytes: 0,
            session_id: format!("s-{}", ulid::Ulid::new()),
            request_stem: "orbit-engine".into(),
            window_tokens: None,
            output_reserve_tokens: 8_192,
            compacting: false,
            compaction_config: None,
            selected_budget: None,
            compaction_budget: None,
            journal: None,
            spend_allowance: None,
        }
    }
}

/// The one-line target a front-end shows for a call: the command, the
/// path, the pattern — or, for a subagent, who and what. It reaches the
/// screen and the stream (`stream-json` lands in CI logs), so it passes the
/// secret scanner first, like every other summary of a call.
fn call_target(name: &str, arguments: &[u8]) -> String {
    let Ok(args) = serde_json::from_slice::<serde_json::Value>(arguments) else {
        return String::new();
    };
    let get = |key: &str| args.get(key).and_then(|v| v.as_str());
    let raw = if matches!(name, "Task" | "Agent") {
        let who = get("agent")
            .or_else(|| get("agent_type"))
            .or_else(|| get("subagent_type"))
            .unwrap_or("");
        let task = get("prompt")
            .and_then(|p| p.lines().map(str::trim).find(|l| !l.is_empty()))
            .unwrap_or("");
        match (who.is_empty(), task.is_empty()) {
            (false, false) => format!("{who} · {task}"),
            (false, true) => who.to_string(),
            (true, _) => task.to_string(),
        }
    } else {
        get("command")
            .or_else(|| get("file_path"))
            .or_else(|| get("path"))
            .or_else(|| get("pattern"))
            .or_else(|| get("prompt"))
            .map(String::from)
            .unwrap_or_default()
    };
    orbit_tools::scan::scan_result(&raw).text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    CompleteText,
    CompleteTools,
    Truncated,
    Filtered,
    Cancelled,
    Incomplete,
}

impl StopReason {
    fn classify(outcome: &crate::dispatch::TurnOutcome) -> Self {
        match outcome.finish_reason.as_deref() {
            Some("cancelled") => Self::Cancelled,
            Some("length" | "max_tokens") => Self::Truncated,
            Some("content_filter" | "filter" | "refusal") => Self::Filtered,
            Some("stop" | "end_turn" | "stop_sequence") if outcome.tool_calls.is_empty() => {
                Self::CompleteText
            }
            Some("tool_calls" | "tool_use")
                if !outcome.tool_calls.is_empty() && valid_tool_set(&outcome.tool_calls) =>
            {
                Self::CompleteTools
            }
            _ => Self::Incomplete,
        }
    }
}

fn valid_tool_set(calls: &[crate::dispatch::PendingToolCall]) -> bool {
    if calls.len() > 128 {
        return false;
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut indexes = std::collections::BTreeSet::new();
    calls.iter().all(|call| {
        !call.id.trim().is_empty()
            && call.id.len() <= 512
            && !call.name.trim().is_empty()
            && call.name.len() <= 256
            && call.arguments.len() <= 8 * 1024 * 1024
            && ids.insert(call.id.as_str())
            && indexes.insert(call.index)
            && serde_json::from_slice::<serde_json::Value>(&call.arguments)
                .is_ok_and(|arguments| arguments.is_object())
    })
}

struct ObservedCall {
    id: String,
    name: String,
    finished: bool,
}

#[derive(Default)]
struct ToolLifecycle {
    calls: std::collections::BTreeMap<u32, ObservedCall>,
    invalid: bool,
}

impl ToolLifecycle {
    fn observe(&mut self, event: &orbit_adapter::types::ProviderEventKind) {
        use orbit_adapter::types::ProviderEventKind;
        match event {
            ProviderEventKind::ToolCallStarted {
                call_index,
                provider_call_id,
                name,
            } => {
                let Some(id) = provider_call_id.as_ref().filter(|id| !id.trim().is_empty()) else {
                    self.invalid = true;
                    return;
                };
                if self.calls.len() >= 128
                    || self.calls.contains_key(call_index)
                    || id.len() > 512
                    || name.trim().is_empty()
                    || name.len() > 256
                {
                    self.invalid = true;
                    return;
                }
                self.calls.insert(
                    *call_index,
                    ObservedCall {
                        id: id.clone(),
                        name: name.clone(),
                        finished: false,
                    },
                );
            }
            ProviderEventKind::ToolCallArgumentsDelta { call_index, .. } => {
                if self.calls.get(call_index).is_none_or(|call| call.finished) {
                    self.invalid = true;
                }
            }
            ProviderEventKind::ToolCallFinished { call_index } => {
                match self.calls.get_mut(call_index) {
                    Some(call) if !call.finished => call.finished = true,
                    _ => self.invalid = true,
                }
            }
            _ => {}
        }
    }

    fn matches(&self, calls: &[crate::dispatch::PendingToolCall]) -> bool {
        !self.invalid
            && self.calls.len() == calls.len()
            && calls.iter().all(|call| {
                self.calls.get(&call.index).is_some_and(|observed| {
                    observed.finished && observed.id == call.id && observed.name == call.name
                })
            })
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
    let mut report = TurnReport::default();
    let mut refusals = Vec::new();
    run_turn_observed(
        home,
        config,
        options,
        prompt,
        transcript,
        executor,
        cancel,
        events,
        &mut report,
        None,
        &mut refusals,
    )?;
    Ok(report)
}

/// Retain request accounting and valid partial history on every terminal path.
#[allow(clippy::too_many_arguments)]
pub fn run_turn_detailed(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    executor: &mut dyn ToolExecutor,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
) -> TurnCompletion {
    run_turn_detailed_with_retry_policy(
        home, config, options, prompt, transcript, executor, cancel, events, None,
    )
    .into_completion()
}

/// Run with an explicitly selected policy; stored metadata never enables retry.
#[allow(clippy::too_many_arguments)]
pub fn run_turn_detailed_with_retry_policy(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    executor: &mut dyn ToolExecutor,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
    policy: Option<&crate::retry::RetryPolicyBinding>,
) -> RetryTurnCompletion {
    let mut report = TurnReport::default();
    let mut refusals = Vec::new();
    let result = run_turn_observed(
        home,
        config,
        options,
        prompt,
        transcript,
        executor,
        cancel,
        events,
        &mut report,
        policy,
        &mut refusals,
    );
    let end = if report.interrupted {
        TurnEnd::Cancelled
    } else if let Err(message) = result {
        TurnEnd::Failed(TurnFailure {
            message: safe_failure(&message),
        })
    } else if report.ok {
        TurnEnd::Completed
    } else {
        TurnEnd::Failed(TurnFailure {
            message: "turn ended before a complete response".into(),
        })
    };
    RetryTurnCompletion {
        completion: TurnCompletion { report, end },
        refusals,
    }
}

fn safe_failure(message: &str) -> String {
    let plain: String = message
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    compaction_display(&plain)
}

#[allow(clippy::too_many_arguments)]
fn run_turn_observed(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    executor: &mut dyn ToolExecutor,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
    report: &mut TurnReport,
    policy: Option<&crate::retry::RetryPolicyBinding>,
    refusals: &mut Vec<crate::retry::RefusalRecord>,
) -> Result<(), String> {
    let mut ended = false;
    let result = run_turn_inner(
        home,
        config,
        options,
        prompt,
        transcript,
        executor,
        cancel,
        &mut |event| {
            let event = match event {
                FrontendEvent::TurnEnded { .. } if ended => return,
                event @ FrontendEvent::TurnEnded { .. } => {
                    ended = true;
                    event
                }
                FrontendEvent::Error { message } => FrontendEvent::Error {
                    message: safe_failure(&message),
                },
                event => event,
            };
            events(event);
        },
        report,
        policy,
        refusals,
    );
    if !ended {
        if let Err(message) = &result {
            events(FrontendEvent::Error {
                message: safe_failure(message),
            });
        }
        emit_turn_ended(events, report, report.rounds);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn run_turn_inner(
    home: &std::path::Path,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    executor: &mut dyn ToolExecutor,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
    report: &mut TurnReport,
    policy: Option<&crate::retry::RetryPolicyBinding>,
    refusals: &mut Vec<crate::retry::RefusalRecord>,
) -> Result<(), String> {
    // Reject retry-ineligible turns before hooks, transcript mutation or summaries.
    if policy.is_some() {
        if options.journal.is_none() {
            return Err("final-rejection retry requires a context journal".into());
        }
        if options.spend_allowance.is_some() {
            return Err("final-rejection retry cannot use a spend allowance".into());
        }
        if options.compacting {
            return Err("final-rejection retry is unavailable for context summaries".into());
        }
        if options.max_attempts == 0 {
            return Err("final-rejection retry has a zero provider-send limit".into());
        }
    }
    // Reject invalid selections before hooks, transcript mutation or tools.
    config.validate_effort()?;
    // E9: hooks — the prompt enters the session before the turn runs.
    let hooks = crate::hooks::Hooks::load(home, crate::hooks::project_trusted(home));
    let _ = hooks.fire(
        crate::hooks::HookEvent::UserPromptSubmit,
        &serde_json::json!({ "prompt": prompt }),
    );

    executor.begin_turn(config);
    let mut user = user_message(prompt);
    if let Some(blocks) = &options.user_blocks {
        user.blocks = Some(blocks.clone());
    }
    let mut current_user_index = transcript.len();
    transcript.push(user);

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
            emit_turn_ended(events, report, round);
            return Ok(());
        }

        events(FrontendEvent::RoundStarted { round });

        use crate::context_budget::{
            BudgetDecision, EstimateStatus, assess_request, estimate_prepared_request, fits,
        };
        let context = crate::dispatch::request_preparation_context(
            config,
            options.system_directive.as_deref(),
            &options.tools,
        )
        .map_err(|(code, message)| {
            local_turn_error(events, report, round, format!("{code}: {message}"))
        })?;
        let mut prepared = crate::dispatch::prepare_provider_request(
            &context,
            prompt,
            Some(transcript.clone()),
            &options.request_stem,
            &options.session_id,
        )
        .map_err(|(code, message)| {
            local_turn_error(events, report, round, format!("{code}: {message}"))
        })?;
        let budget = options.selected_budget.clone().or_else(|| {
            options.window_tokens.and_then(|window| {
                crate::context_budget::SelectedBudget::legacy_input(config, window).ok()
            })
        });
        if let Some(budget) = &budget {
            let before = estimate_prepared_request(&prepared, budget)
                .map_err(|e| local_turn_error(events, report, round, e.to_string()))?;
            let decision = assess_request(&before, budget);
            if matches!(decision, BudgetDecision::Refuse | BudgetDecision::Unknown) {
                return Err(local_turn_error(events, report, round, "context budget policy refuses this request; check selected limits or media policy".into()));
            }
            if decision == BudgetDecision::Compact
                && !options.compacting
                && compacted_at.is_none_or(|at| before.estimated_input_tokens > at)
            {
                use crate::compaction::{CompactionContexts, CompactionStatus};
                if transcript
                    .iter()
                    .rposition(|message| message.role == ChatRole::User)
                    != Some(current_user_index)
                {
                    return Err(local_turn_error(
                        events,
                        report,
                        round,
                        "context compaction current intent no longer matches the source".into(),
                    ));
                }
                let summary_config = options.compaction_config.as_ref().unwrap_or(config);
                let summary_context =
                    crate::dispatch::request_preparation_context(summary_config, None, &[])
                        .map_err(|_| {
                            local_turn_error(
                                events,
                                report,
                                round,
                                "context summary configuration is invalid".into(),
                            )
                        })?;
                let mut summary_options = options.clone();
                summary_options.spend_allowance = remaining_allowance(options, report)
                    .map_err(|message| local_turn_error(events, report, round, message))?;
                let attempt = crate::compaction::compact_with_contexts(
                    home,
                    config,
                    &summary_options,
                    transcript,
                    CompactionContexts {
                        conversation: &context,
                        summary: &summary_context,
                        remaining_attempts: remaining_accounting_metadata(report, refusals)
                            .map_err(|message| {
                                local_turn_error(events, report, round, message.into())
                            })?,
                    },
                    cancel,
                    &mut |estimate| {
                        let _ = hooks.fire(
                            crate::hooks::HookEvent::PreCompact,
                            &serde_json::json!({ "estimated_tokens": estimate.estimated_input_tokens }),
                        );
                        events(FrontendEvent::Compacting {
                            used_tokens: estimate.estimated_input_tokens,
                            window_tokens: budget
                                .meter_window(estimate.requested_output_tokens)
                                .0
                                .unwrap_or(0),
                        });
                    },
                );
                let incomplete =
                    record_accounting_with_refusals(report, refusals, &attempt.attempts).map_err(
                        |message| local_turn_error(events, report, round, message.into()),
                    )?;
                if !attempt.attempts.is_empty() {
                    events(FrontendEvent::CostUpdated {
                        total_microcents: report.cost_microcents,
                    });
                }
                if incomplete {
                    events(FrontendEvent::Status {
                        text: "Context summary usage or pricing is incomplete; displayed totals include only validated subtotals.".into(),
                    });
                }
                if cancel.is_cancelled() || attempt.status == CompactionStatus::Cancelled {
                    report.interrupted = true;
                    report.ok = false;
                    emit_turn_ended(events, report, round);
                    return Ok(());
                }
                if attempt.status == CompactionStatus::PublishedReady {
                    let candidate = attempt.candidate.ok_or_else(|| {
                        local_turn_error(
                            events,
                            report,
                            round,
                            "context history publication is incomplete".into(),
                        )
                    })?;
                    let application = match crate::compaction::prepare_compaction_application(
                        candidate,
                        transcript,
                        &context,
                        budget,
                        options,
                        current_user_index,
                        cancel,
                    ) {
                        Ok(value) => value,
                        Err(CompactionStatus::Cancelled) => {
                            report.interrupted = true;
                            report.ok = false;
                            emit_turn_ended(events, report, round);
                            return Ok(());
                        }
                        Err(status) => {
                            return Err(local_turn_error(
                                events,
                                report,
                                round,
                                status.to_string(),
                            ));
                        }
                    };
                    // The caller owns this mutable source for the entire final
                    // digest/coverage check and this single working assignment.
                    if cancel.is_cancelled() {
                        report.interrupted = true;
                        report.ok = false;
                        emit_turn_ended(events, report, round);
                        return Ok(());
                    }
                    *transcript = application.messages;
                    prepared = application.prepared;
                    current_user_index = application.current_user;
                    compacted_at = Some(application.after_tokens);
                    let _ = hooks.fire(
                        crate::hooks::HookEvent::PostCompact,
                        &serde_json::json!({ "summary_bytes": application.summary.len() }),
                    );
                    events(FrontendEvent::Compacted {
                        summary: compaction_display(&application.summary),
                        after_tokens: application.after_tokens,
                    });
                } else if attempt.status != CompactionStatus::NothingToCompact
                    || !fits(&before, budget)
                {
                    return Err(local_turn_error(
                        events,
                        report,
                        round,
                        attempt.status.to_string(),
                    ));
                }
            }
            if cancel.is_cancelled() {
                report.interrupted = true;
                report.ok = false;
                emit_turn_ended(events, report, round);
                return Ok(());
            }
            let final_estimate = estimate_prepared_request(&prepared, budget)
                .map_err(|e| local_turn_error(events, report, round, e.to_string()))?;
            if !fits(&final_estimate, budget) {
                return Err(local_turn_error(
                    events,
                    report,
                    round,
                    "context budget exceeded; ordinary request was not sent".into(),
                ));
            }
            if final_estimate.status == EstimateStatus::UnknownMedia {
                events(FrontendEvent::Status { text: "Media or opaque request cost is unknown; text policy passed, provider capacity is unverified.".into() });
            }
        }

        // Each actual dispatch has its own intent and accounting disposition.
        // Only checked final-rejection evidence permits managed retry.
        let mut partial_text = String::new();
        let outcome = dispatch_with_retry(
            home,
            config,
            options,
            prompt,
            transcript,
            cancel,
            round,
            Some(prepared),
            report,
            policy,
            refusals,
            &mut |event| {
                if let FrontendEvent::TextDelta { text } = &event {
                    partial_text.push_str(text);
                }
                events(event);
            },
        );

        let OrdinaryDispatch {
            outcome: o,
            occupancy,
        } = match outcome {
            Ok(outcome) => outcome,
            Err(e) => {
                if !partial_text.is_empty() {
                    transcript.push(assistant_message(partial_text.clone()));
                    report.final_text = partial_text;
                    emit_context_usage(
                        &context,
                        options,
                        budget.as_ref(),
                        transcript,
                        None,
                        events,
                    );
                }
                if matches!(&e, OrdinaryDispatchError::Cancelled)
                    || (matches!(&e, OrdinaryDispatchError::Failure(_)) && cancel.is_cancelled())
                {
                    report.interrupted = true;
                    report.ok = false;
                    emit_turn_ended(events, report, round);
                    return Ok(());
                }
                let e = e.into_message();
                events(FrontendEvent::Error { message: e.clone() });
                emit_turn_ended(events, report, round);
                return Err(e);
            }
        };

        report.rounds = round + 1;
        let stop_reason = StopReason::classify(&o);
        if cancel.is_cancelled() || stop_reason == StopReason::Cancelled {
            if !o.output.is_empty() {
                transcript.push(assistant_message(o.output.clone()));
            }
            emit_context_usage(
                &context,
                options,
                budget.as_ref(),
                transcript,
                Some(&occupancy),
                events,
            );
            report.final_text = o.output;
            report.interrupted = true;
            report.ok = false;
            emit_turn_ended(events, report, report.rounds);
            return Ok(());
        }
        events(FrontendEvent::CostUpdated {
            total_microcents: report.cost_microcents,
        });
        if matches!(
            stop_reason,
            StopReason::Truncated | StopReason::Filtered | StopReason::Incomplete
        ) {
            // Preserve useful visible text, never unfinished tool metadata
            // or signed thinking from a reply that did not complete.
            if !o.output.is_empty() {
                transcript.push(assistant_message(o.output.clone()));
            }
            emit_context_usage(
                &context,
                options,
                budget.as_ref(),
                transcript,
                Some(&occupancy),
                events,
            );
            report.final_text = o.output;
            report.ok = false;
            if stop_reason == StopReason::Truncated {
                let _ = hooks.fire(
                    crate::hooks::HookEvent::Notification,
                    &serde_json::json!({
                        "kind": "output_truncated",
                        "limit": config.max_output_tokens,
                    }),
                );
                events(FrontendEvent::OutputTruncated {
                    limit: config.max_output_tokens,
                });
            } else {
                let message = if stop_reason == StopReason::Filtered {
                    "provider filtered or refused the response before completion"
                } else {
                    "E0411: provider response has an incomplete terminal state or invalid tool calls"
                };
                events(FrontendEvent::Error {
                    message: message.into(),
                });
            }
            emit_turn_ended(events, report, report.rounds);
            return Ok(());
        }

        if stop_reason == StopReason::CompleteText {
            let mut m = assistant_message_with_thinking(
                o.output.clone(),
                o.thinking.clone(),
                o.thinking_signature.clone(),
            );
            // Routing: opaque blocks are model-bound — record who made
            // them so a later switched-model dispatch can strip them.
            if m.blocks.is_some() {
                m.origin_model = Some(config.model.clone());
                m.origin_provider = Some(config.provider_id.clone());
            }
            transcript.push(m);
            emit_context_usage(
                &context,
                options,
                budget.as_ref(),
                transcript,
                Some(&occupancy),
                events,
            );
            report.final_text = o.output.clone();
            report.ok = true;
            events(FrontendEvent::ResponseFinished {
                output: o.output.clone(),
                input_tokens: report.input_tokens,
                output_tokens: report.output_tokens,
                cost_microcents: report.cost_microcents,
            });
            // E9: Stop fires when the turn ends its reply — the
            // main loop's natural pause point.
            let _ = hooks.fire(
                crate::hooks::HookEvent::Stop,
                &serde_json::json!({ "final_text_bytes": o.output.len() }),
            );
            emit_turn_ended(events, report, report.rounds);
            return Ok(());
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
        let mut m = assistant_with_calls_and_thinking(
            o.output.clone(),
            assistant_calls,
            o.thinking.clone(),
            o.thinking_signature.clone(),
        );
        // Routing: same origin tag on the tool-call message's thinking.
        if m.blocks.is_some() {
            m.origin_model = Some(config.model.clone());
            m.origin_provider = Some(config.provider_id.clone());
        }
        transcript.push(m);

        // The TUI's tool-line motion (M07/M08/M09/M10): the full
        // start (kind + target) before execution, the finish with a
        // result fact after.
        for tc in &o.tool_calls {
            events(FrontendEvent::ToolStartedFull {
                call_id: tc.id.clone(),
                kind: tc.name.clone(),
                target: call_target(&tc.name, &tc.arguments),
            });
        }
        // Esc (MD §The agent loop): install the turn's cancel-checker
        // so long-running tool children (Bash) die with the stream.
        // Cleared after the round so a later turn starts clean.
        // The turn's token is current for the round's tools, then the
        // previous one (a parent turn's) is again.
        executor.begin_cancel_scope(cancel);
        let results = executor.execute(&o.tool_calls, round);
        executor.end_cancel_scope();
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
            // E4: the typed verdict — top-level ok, parsed once. A
            // result whose *content* happens to contain the text
            // "ok":false (a Read of a JSON fixture) is not an error.
            let ok = !orbit_tools::result_is_error(&r.content);
            events(FrontendEvent::ToolFinishedFull {
                call_id: r.call_id.clone(),
                ok,
                result_fact: fact,
            });
            // C4: a policy refusal is its own event — the tool and the
            // reason travel with it, so a headless consumer (and the
            // exit-code path) never substring-hunts the payload.
            if orbit_tools::result_is_denial(&r.content) {
                events(FrontendEvent::ToolDenied {
                    call_id: r.call_id.clone(),
                    tool: o
                        .tool_calls
                        .iter()
                        .find(|tc| tc.id == r.call_id)
                        .map(|tc| tc.name.clone())
                        .unwrap_or_default(),
                    reason: orbit_tools::denial_reason(&r.content).unwrap_or_default(),
                });
            }
        }
        for r in results {
            // An image Read carries its data in the result JSON; the
            // block rides on the Tool message for providers that speak
            // blocks (Anthropic's tool_result accepts image content).
            // A provider that does not — the OpenAI-compatible tool
            // role is a string — ignores the block and keeps the
            // honest `content` line, the same contract as thinking.
            let blocks = image_block_of(&r.content);
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: r.content.clone(),
                tool_calls: None,
                tool_call_id: Some(r.call_id.clone()),
                tool_result: Some(r.content),
                blocks,
                origin_model: None,
                origin_provider: None,
            });
        }
        emit_context_usage(
            &context,
            options,
            budget.as_ref(),
            transcript,
            Some(&occupancy),
            events,
        );

        round += 1;
        if round >= options.max_rounds {
            let msg = format!(
                "turn stopped by the round guard: {} rounds (the model kept calling tools)",
                options.max_rounds
            );
            events(FrontendEvent::Status { text: msg.clone() });
            report.final_text = o.output;
            emit_turn_ended(events, report, round);
            return Ok(());
        }
    }
}

/// The image block of a tool result, when the result carries one: the
/// Read tool puts `image_base64` + `image_media_type` in its payload
/// for an image file. `None` for every other result (the common case).
fn image_block_of(content: &str) -> Option<Vec<orbit_adapter::types::ContentBlock>> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    let data = v.get("image_base64")?.as_str()?.to_string();
    let media_type = v
        .get("image_media_type")
        .and_then(|m| m.as_str())
        .unwrap_or("image/png")
        .to_string();
    Some(vec![orbit_adapter::types::ContentBlock::Image {
        data,
        media_type,
    }])
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

fn local_turn_error(
    events: EventSink<'_>,
    report: &TurnReport,
    round: u32,
    message: String,
) -> String {
    events(FrontendEvent::Error {
        message: message.clone(),
    });
    let failed = TurnReport {
        ok: false,
        ..report.clone()
    };
    emit_turn_ended(events, &failed, round);
    message
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
    mut prepared: Option<crate::dispatch::PreparedProviderRequest>,
    report: &mut TurnReport,
    policy: Option<&crate::retry::RetryPolicyBinding>,
    refusals: &mut Vec<crate::retry::RefusalRecord>,
    events: EventSink<'_>,
) -> Result<OrdinaryDispatch, OrdinaryDispatchError> {
    let mut attempt = 1u32;
    let max_attempts = policy.map_or(options.max_attempts, |policy| {
        options.max_attempts.min(policy.max_attempts())
    });
    loop {
        if cancel.is_cancelled() {
            return Err(OrdinaryDispatchError::Cancelled);
        }
        require_accounting_slot(report, refusals)?;
        let request = match prepared.take() {
            Some(request) => request,
            None => {
                let context = crate::dispatch::request_preparation_context(
                    config,
                    options.system_directive.as_deref(),
                    &options.tools,
                )
                .map_err(|(code, message)| format!("{code}: {message}"))?;
                crate::dispatch::prepare_provider_request(
                    &context,
                    prompt,
                    Some(transcript.to_vec()),
                    &options.request_stem,
                    &options.session_id,
                )
                .map_err(|(code, message)| format!("{code}: {message}"))?
            }
        };
        let mut budget = match &options.selected_budget {
            Some(budget) => budget.clone(),
            None => crate::context_budget::SelectedBudget::legacy_input(
                config,
                options.window_tokens.unwrap_or(u64::MAX),
            )?,
        };
        if options.selected_budget.is_none() && options.window_tokens.is_none() {
            budget.identity = crate::context_budget::BudgetIdentity::for_config(
                config,
                "unmanaged",
                "unmanaged",
            )?;
        }
        let estimate = crate::context_budget::estimate_prepared_request(&request, &budget)
            .map_err(|error| error.to_string())?;
        let allowance = remaining_allowance(options, report)?;
        let mut checkpoint = if let Some(journal) = &options.journal {
            let checkpoint = journal
                .accounting_checkpoint_detailed()
                .map_err(OrdinaryDispatchError::accounting)?;
            if !qualified_detailed(&checkpoint, &options.session_id) {
                return Err(OrdinaryDispatchError::accounting(
                    "context accounting owner or child does not match this turn",
                ));
            }
            if checkpoint.pending().is_some()
                || checkpoint.totals().knownness == AccountingKnownness::Uncertain
            {
                mark_ordinary_uncertain(report);
                return Err(OrdinaryDispatchError::accounting(
                    "context accounting has a pending uncertain request; inspect before continuing",
                ));
            }
            if let Some(allowance) = allowance
                && (checkpoint.baseline() == crate::AccountingBaseline::UnknownLegacy
                    || checkpoint.totals().knownness != AccountingKnownness::Known
                    || checkpoint.totals().ordinary.cost_microcents.is_none()
                    || (checkpoint.totals().housekeeping.cost_microcents.is_none()
                        && !allowance.allow_unpriced_housekeeping))
            {
                report.accounting.knownness = checkpoint.totals().knownness;
                report.accounting.ordinary.cost_microcents = None;
                return Err("spend allowance cannot use unknown historical namespace costs".into());
            }
            Some(checkpoint)
        } else {
            None
        };
        crate::compaction::admit_spend(allowance, config, &estimate, 0, false)
            .map_err(str::to_owned)?;
        let binding = policy
            .map(|policy| request.ordinary_attempt_binding(policy))
            .transpose()
            .map_err(OrdinaryDispatchError::accounting)?;
        let intent = AttemptIntent {
            owner_session_id: checkpoint.as_ref().map_or_else(
                || options.session_id.clone(),
                |c| c.owner_session_id().to_owned(),
            ),
            child_id: checkpoint
                .as_ref()
                .and_then(|c| c.child_id().map(str::to_owned)),
            request_id: request.request_id().into(),
            purpose: AttemptPurpose::Ordinary,
            budget: budget.identity,
        };
        let digest = intent.digest().map_err(OrdinaryDispatchError::accounting)?;
        // No intent is published after cancellation, including a long preparation.
        if cancel.is_cancelled() {
            return Err(OrdinaryDispatchError::Cancelled);
        }
        let reference = if let (Some(journal), Some(checkpoint)) = (&options.journal, &checkpoint) {
            checkpoint.revision().0.checked_add(2).ok_or_else(|| {
                OrdinaryDispatchError::accounting("context accounting revision overflow")
            })?;
            if binding.is_some()
                && let Some(rollup) = checkpoint.refusals()
            {
                rollup.count().checked_add(1).ok_or_else(|| {
                    OrdinaryDispatchError::accounting("context refusal count overflow")
                })?;
            }
            let reference = journal
                .begin_attempt_detailed(checkpoint.revision(), &intent, binding.as_ref())
                .map_err(|error| {
                    if error == crate::HistoryError::Uncertain {
                        mark_ordinary_uncertain(report);
                    }
                    OrdinaryDispatchError::accounting(error)
                })?;
            if reference.request_id != intent.request_id
                || reference.intent_digest != digest
                || reference.revision.0 != checkpoint.revision().0 + 1
            {
                mark_ordinary_uncertain(report);
                return Err(OrdinaryDispatchError::accounting(
                    "context accounting begin publication is uncertain",
                ));
            }
            Some(reference)
        } else {
            None
        };
        if cancel.is_cancelled() {
            if let Some(reference) = &reference {
                // This is the only proven NotSent path after a successful begin.
                let receipt = RequestAccountingReceipt {
                    request_id: intent.request_id.clone(),
                    purpose: AttemptPurpose::Ordinary,
                    totals: AccountingTotals::known_zero(),
                    usage: None,
                    knownness: AccountingKnownness::Known,
                    completed: false,
                };
                let recorded = record_accounting_with_refusals(
                    report,
                    refusals,
                    std::slice::from_ref(&receipt),
                );
                settle_ordinary(options, &mut checkpoint, reference, &intent, &receipt)
                    .inspect_err(|_| mark_ordinary_uncertain(report))
                    .map_err(OrdinaryDispatchError::accounting)?;
                recorded.map_err(OrdinaryDispatchError::accounting)?;
            }
            return Err(OrdinaryDispatchError::Cancelled);
        }
        let mut observed = false;
        let mut metadata = crate::compaction::MetadataAccounting::default();
        let mut lifecycle = ToolLifecycle::default();
        let detailed = crate::dispatch::run_prepared_dispatch_detailed(
            home,
            config,
            request,
            Some(&mut |event| {
                observe_ordinary_event(event, &mut observed, &mut metadata, &mut lifecycle, events);
            }),
            cancel.clone(),
            &options.session_id,
        );
        // Every provider event disqualifies a final-refusal proof. The private
        // text flag conservatively summarizes the all-event latch, including
        // admission, thinking, signature, usage, tools and terminal events.
        let eligibility = crate::retry::RefusalEligibility {
            text_observed: observed,
            cancelled: cancel.is_cancelled(),
            spend_capped: options.spend_allowance.is_some(),
            ..Default::default()
        };
        let refusal = match (&detailed, &reference, &binding, policy) {
            (Err(failure), Some(reference), Some(binding), Some(policy)) => failure
                .qualify_final_refusal(&intent, reference, binding, policy, &eligibility)
                .ok(),
            _ => None,
        };
        if let Some(refusal) = refusal {
            // Once live proof exists, finish exactly this settlement and ACK
            // despite a racing cancel. No normal receipt may also settle it.
            let journal = options
                .journal
                .as_ref()
                .ok_or_else(|| OrdinaryDispatchError::accounting("context journal is missing"))?;
            let before = checkpoint.as_ref().ok_or_else(|| {
                OrdinaryDispatchError::accounting("context accounting checkpoint is missing")
            })?;
            let ack = journal
                .settle_refused_ordinary(refusal.attempt(), &refusal)
                .inspect_err(|_| mark_ordinary_uncertain(report))
                .map_err(OrdinaryDispatchError::accounting)?;
            ack.validate_for(&refusal, before)
                .inspect_err(|_| mark_ordinary_uncertain(report))
                .map_err(OrdinaryDispatchError::accounting)?;
            require_accounting_slot(report, refusals)?;
            let record = refusal.to_record();
            let _ = checkpoint.replace(ack.checkpoint().clone());
            report.accounting = record.totals_after(&report.accounting);
            refusals.push(record);
            events(FrontendEvent::Status {
                text: "Provider returned a final rejection; usage and billing remain unknown under the selected retry policy.".into(),
            });
            if cancel.is_cancelled() {
                return Err(OrdinaryDispatchError::Cancelled);
            }
            // Qualification above requires an actual failure; this projection
            // is read-only and never feeds a second settlement.
            let failure = detailed.as_ref().err().ok_or_else(|| {
                OrdinaryDispatchError::accounting("final rejection lost its failure")
            })?;
            let (code, message) = failure.legacy();
            if is_retryable(code) && attempt < max_attempts {
                require_accounting_slot(report, refusals)?;
                retry_wait(attempt, code, message, cancel, events)?;
                attempt += 1;
                // The accepted ACK was consumed before this loop can read a
                // new checkpoint or publish another genuine request identity.
                continue;
            }
            return Err(OrdinaryDispatchError::Failure(format!("{code}: {message}")));
        }
        // Unknown transport evidence and admitted streams use the original
        // measured/provisional receipt exactly once, without managed replay.
        let result = detailed.map_err(crate::dispatch::DetailedDispatchFailure::into_legacy);
        let lifecycle_valid = result
            .as_ref()
            .is_ok_and(|o| lifecycle.matches(&o.tool_calls) && valid_tool_set(&o.tool_calls));
        let receipt =
            metadata.ordinary_receipt(intent.request_id.clone(), config, &result, lifecycle_valid);
        let uncertain = receipt.knownness == AccountingKnownness::Uncertain;
        let recorded =
            record_accounting_with_refusals(report, refusals, std::slice::from_ref(&receipt));
        if recorded.as_ref().is_ok_and(|incomplete| *incomplete) {
            events(FrontendEvent::Status { text: "Provider usage or pricing is incomplete; totals include validated subtotals only.".into() });
        }
        if let Some(reference) = &reference {
            settle_ordinary(options, &mut checkpoint, reference, &intent, &receipt)
                .inspect_err(|_| mark_ordinary_uncertain(report))
                .map_err(OrdinaryDispatchError::accounting)?;
        }
        recorded.map_err(OrdinaryDispatchError::accounting)?;
        match result {
            Ok(o) => {
                if matches!(
                    StopReason::classify(&o),
                    StopReason::CompleteText | StopReason::CompleteTools
                ) {
                    if !lifecycle_valid {
                        return Err("E0411: incomplete provider tool-call lifecycle".into());
                    }
                    if uncertain {
                        return Err(
                            "provider accounting is uncertain; inspect before continuing".into(),
                        );
                    }
                }
                if let Some(digest) = &o.egress_digest {
                    events(FrontendEvent::LedgerAppended {
                        record_count: orbit_ledger::count_records(&home.join("ledger")),
                        head_digest: digest.clone(),
                        kind: "egress".into(),
                        summary: if o.input_tokens == 0 && o.output_tokens == 0 {
                            config.model.clone()
                        } else {
                            format!(
                                "{} · {} in / {} out",
                                config.model, o.input_tokens, o.output_tokens
                            )
                        },
                    });
                }
                let observed_context_tokens = (receipt.knownness == AccountingKnownness::Known)
                    .then_some(receipt.usage)
                    .flatten()
                    .and_then(|usage| {
                        usage
                            .input_tokens
                            .checked_add(usage.cache_read_tokens)?
                            .checked_add(usage.cache_write_tokens)
                    });
                return Ok(OrdinaryDispatch {
                    outcome: o,
                    occupancy: OccupancyAnchor {
                        before: estimate,
                        identity: intent.budget,
                        prefix_len: transcript.len(),
                        observed_context_tokens,
                    },
                });
            }
            Err(_) if cancel.is_cancelled() => return Err(OrdinaryDispatchError::Cancelled),
            Err((code, message))
                if options.journal.is_none()
                    && options.spend_allowance.is_none()
                    && !observed
                    && is_retryable(code)
                    && attempt < max_attempts =>
            {
                require_accounting_slot(report, refusals)?;
                retry_wait(attempt, code, &message, cancel, events)?;
                attempt += 1;
            }
            Err((code, message)) => return Err(format!("{code}: {message}").into()),
        }
    }
}

fn observe_ordinary_event(
    event: &orbit_adapter::types::ProviderStreamEvent,
    observed: &mut bool,
    metadata: &mut crate::compaction::MetadataAccounting,
    lifecycle: &mut ToolLifecycle,
    events: EventSink<'_>,
) {
    // Every actual provider event denies final-refusal retry, even events
    // carrying no visible text. Keep accounting and tool observations intact.
    *observed = true;
    metadata.observe(event);
    lifecycle.observe(&event.event);
    if let orbit_adapter::types::ProviderEventKind::TextDelta { bytes } = &event.event {
        events(FrontendEvent::TextDelta {
            text: String::from_utf8_lossy(bytes).into_owned(),
        });
    }
}

fn mark_ordinary_uncertain(report: &mut TurnReport) {
    report.accounting.knownness = AccountingKnownness::Uncertain;
    report.accounting.ordinary.cost_microcents = None;
}

fn require_accounting_slot(
    report: &TurnReport,
    refusals: &[crate::retry::RefusalRecord],
) -> Result<(), OrdinaryDispatchError> {
    if remaining_accounting_metadata(report, refusals).map_err(OrdinaryDispatchError::accounting)?
        == 0
    {
        return Err(OrdinaryDispatchError::accounting(
            "turn accounting metadata limit reached; start a new turn (ORBIT-E0411)",
        ));
    }
    Ok(())
}

fn qualified_detailed(
    checkpoint: &crate::retry::DetailedAccountingCheckpoint,
    session: &str,
) -> bool {
    checkpoint.validate().is_ok()
        && checkpoint
            .child_id()
            .unwrap_or(checkpoint.owner_session_id())
            == session
}

fn retry_wait(
    attempt: u32,
    code: &str,
    message: &str,
    cancel: &orbit_provider_http::CancelToken,
    events: EventSink<'_>,
) -> Result<(), OrdinaryDispatchError> {
    if cancel.is_cancelled() {
        return Err(OrdinaryDispatchError::Cancelled);
    }
    let base = 1000u64.saturating_mul(1 << (attempt - 1).min(5));
    let delay = base + ulid::Ulid::new().timestamp_ms() % 250;
    events(FrontendEvent::Retrying {
        attempt,
        retry_in_ms: delay,
        reason: safe_failure(&format!("{code}: {message}")),
    });
    let deadline = std::time::Instant::now() + Duration::from_millis(delay);
    while std::time::Instant::now() < deadline {
        if cancel.is_cancelled() {
            return Err(OrdinaryDispatchError::Cancelled);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn settle_ordinary(
    options: &TurnOptions,
    checkpoint: &mut Option<crate::retry::DetailedAccountingCheckpoint>,
    reference: &crate::AttemptRef,
    intent: &AttemptIntent,
    receipt: &RequestAccountingReceipt,
) -> Result<(), String> {
    let journal = options
        .journal
        .as_ref()
        .ok_or_else(|| "context journal is missing".to_string())?;
    let previous = checkpoint
        .as_ref()
        .ok_or_else(|| "context accounting checkpoint is missing".to_string())?;
    let expected = previous
        .totals()
        .checked_with(receipt)
        .map_err(|error| error.to_string())?;
    let expected_priced_subtotals = previous
        .known_priced_subtotals()
        .map(|subtotals| subtotals.checked_with(receipt))
        .transpose()
        .map_err(|error| error.to_string())?;
    let revision = reference
        .revision
        .0
        .checked_add(1)
        .ok_or_else(|| "context accounting revision overflow".to_string())?;
    let digest = receipt.digest().map_err(|error| error.to_string())?;
    let next = journal
        .settle_attempt_detailed(reference, receipt)
        .map_err(|error| error.to_string())?;
    let linked = if receipt.knownness == AccountingKnownness::Uncertain {
        next.pending().is_some_and(|pending| {
            pending.reference == *reference && pending.intent == *intent && pending.uncertain
        }) && next.last_settlement() == previous.last_settlement()
    } else {
        next.pending().is_none()
            && next.last_settlement().is_some_and(|last| {
                matches!(last,
                    crate::retry::DetailedLastSettlement::Legacy(last)
                        if last.reference == *reference && last.receipt_digest == digest
                )
            })
    };
    if next.owner_session_id() != previous.owner_session_id()
        || next.child_id() != previous.child_id()
        || next.baseline() != previous.baseline()
        || !qualified_detailed(&next, &options.session_id)
        || next.revision().0 != revision
        || next.totals() != &expected
        || next.known_priced_subtotals() != expected_priced_subtotals
        || next.refusals() != previous.refusals()
        || !linked
    {
        return Err("context accounting settlement publication is uncertain".into());
    }
    *checkpoint = Some(next);
    Ok(())
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
        // E5: a stalled stream (idle timeout, E0409) is transient —
        // the retry re-requests and the provider usually answers.
        || code.starts_with("E0409")
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
        origin_model: None,
        origin_provider: None,
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
#[cfg(test)]
struct NoopExecutor;

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(
        index: u32,
        id: &str,
        name: &str,
        arguments: &[u8],
    ) -> crate::dispatch::PendingToolCall {
        crate::dispatch::PendingToolCall {
            index,
            id: id.into(),
            name: name.into(),
            arguments: arguments.into(),
        }
    }

    #[test]
    fn terminal_gate_independently_validates_the_whole_outcome() {
        let valid = pending(0, "one", "Effect", b"{}");
        for invalid in [
            pending(1, "", "Effect", b"{}"),
            pending(1, "two", "", b"{}"),
            pending(1, "two", "Effect", b"{"),
            pending(1, "two", "Effect", b"[]"),
            pending(1, "one", "Effect", b"{}"),
            pending(0, "two", "Effect", b"{}"),
            pending(1, "two", "Effect", &[0xff]),
        ] {
            let outcome = crate::dispatch::TurnOutcome {
                finish_reason: Some("tool_calls".into()),
                tool_calls: vec![valid.clone(), invalid],
                ..Default::default()
            };
            assert_eq!(StopReason::classify(&outcome), StopReason::Incomplete);
        }
        let mut outcome = crate::dispatch::TurnOutcome {
            finish_reason: Some("tool_calls".into()),
            tool_calls: vec![valid],
            ..Default::default()
        };
        assert_eq!(StopReason::classify(&outcome), StopReason::CompleteTools);
        for (reason, expected) in [
            ("length", StopReason::Truncated),
            ("max_tokens", StopReason::Truncated),
            ("content_filter", StopReason::Filtered),
            ("cancelled", StopReason::Cancelled),
            ("stop", StopReason::Incomplete),
            ("end_turn", StopReason::Incomplete),
            ("unknown", StopReason::Incomplete),
        ] {
            outcome.finish_reason = Some(reason.into());
            assert_eq!(StopReason::classify(&outcome), expected);
        }
        outcome.finish_reason = None;
        assert_eq!(StopReason::classify(&outcome), StopReason::Incomplete);
        outcome.tool_calls.clear();
        outcome.finish_reason = Some("tool_calls".into());
        assert_eq!(StopReason::classify(&outcome), StopReason::Incomplete);
    }

    #[test]
    fn terminal_gate_requires_coherent_tool_lifecycles() {
        use orbit_adapter::types::ProviderEventKind;
        let started = ProviderEventKind::ToolCallStarted {
            call_index: 0,
            provider_call_id: Some("one".into()),
            name: "Effect".into(),
        };
        let arguments = ProviderEventKind::ToolCallArgumentsDelta {
            call_index: 0,
            bytes: b"{}".to_vec(),
        };
        let finished = ProviderEventKind::ToolCallFinished { call_index: 0 };
        let calls = [pending(0, "one", "Effect", b"{}")];
        let mut lifecycle = ToolLifecycle::default();
        lifecycle.observe(&started);
        lifecycle.observe(&arguments);
        assert!(!lifecycle.matches(&calls));
        lifecycle.observe(&finished);
        assert!(lifecycle.matches(&calls));
        lifecycle.observe(&arguments);
        assert!(!lifecycle.matches(&calls));
        for events in [
            vec![&arguments, &started, &finished],
            vec![&started, &started, &finished],
            vec![&started, &finished, &finished],
        ] {
            let mut lifecycle = ToolLifecycle::default();
            for event in events {
                lifecycle.observe(event);
            }
            assert!(!lifecycle.matches(&calls));
        }
        let mut lifecycle = ToolLifecycle::default();
        lifecycle.observe(&ProviderEventKind::ToolCallStarted {
            call_index: 0,
            provider_call_id: None,
            name: "Effect".into(),
        });
        lifecycle.observe(&finished);
        assert!(!lifecycle.matches(&calls));
    }

    #[test]
    fn retryable_codes() {
        assert!(is_retryable("ORBIT-E0407"));
        assert!(!is_retryable("ORBIT-E0402")); // auth: never retry
        assert!(!is_retryable("ORBIT-E0401")); // bad url: never retry
    }

    fn target(name: &str, args: serde_json::Value) -> String {
        call_target(name, args.to_string().as_bytes())
    }

    fn tool(name: &str, desc: &str) -> orbit_adapter::types::ToolDefinition {
        orbit_adapter::types::ToolDefinition {
            name: name.into(),
            description: desc.into(),
            parameters: serde_json::json!({"type": "object"}),
            schema_digest: orbit_adapter::types::Sha256Digest("0".repeat(64)),
        }
    }

    /// The parts of the context, in estimated tokens (~4 bytes each), and
    /// the line where compaction starts. The system text is split from the
    /// memory the front-end measured; the conversation is the transcript's.
    #[test]
    fn the_context_breakdown_names_its_parts() {
        let options = TurnOptions {
            system_directive: Some("s".repeat(4_000)),
            memory_bytes: 1_200,
            tools: vec![tool("Read", &"d".repeat(360))],
            window_tokens: Some(100_000),
            output_reserve_tokens: 10_000,
            ..Default::default()
        };
        let transcript = vec![user_message("m".repeat(800))];
        let b = context_breakdown(&options, &transcript).expect("a window is set");
        assert_eq!(b.system, 700, "(4000 - 1200 memory) / 4");
        assert_eq!(b.memory, 300, "1200 / 4");
        let wire = ("Read".len() + 360 + r#"{"type":"object"}"#.len()) / 4;
        assert_eq!(b.tools, wire as u64);
        assert_eq!(b.messages, 225, "800 bytes + an eighth, over four");
        assert_eq!(b.compact_at, 81_000, "90% of (100k - 10k)");
        assert_eq!(b.reserve, 10_000);
    }

    #[test]
    fn without_a_window_there_is_nothing_to_compare() {
        assert!(context_breakdown(&TurnOptions::default(), &[]).is_none());
    }

    /// A memory size larger than the directive (a stale value) cannot
    /// make the system share underflow.
    #[test]
    fn a_stale_memory_size_cannot_underflow() {
        let options = TurnOptions {
            system_directive: Some("x".repeat(100)),
            memory_bytes: 5_000,
            window_tokens: Some(1_000),
            ..Default::default()
        };
        let b = context_breakdown(&options, &[]).unwrap();
        assert_eq!((b.system, b.memory), (0, 25));
    }

    #[test]
    fn a_call_names_its_command_path_or_pattern() {
        assert_eq!(
            target("Bash", serde_json::json!({"command": "ls -la"})),
            "ls -la"
        );
        assert_eq!(
            target("Read", serde_json::json!({"file_path": "/a/b.rs"})),
            "/a/b.rs"
        );
        assert_eq!(
            target("Glob", serde_json::json!({"pattern": "**/*.py"})),
            "**/*.py"
        );
        assert_eq!(
            target("calculator", serde_json::json!({"expression": "1+1"})),
            ""
        );
        assert_eq!(call_target("Bash", b"not json"), "");
    }

    /// A target reaches the screen and the `stream-json` events (CI logs):
    /// a token in a command must not travel with it.
    #[test]
    fn a_target_never_carries_a_secret() {
        let secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let t = target(
            "Bash",
            serde_json::json!({"command": format!("curl -H 'x-api-key: {secret}' https://api")}),
        );
        assert!(!t.contains(secret), "{t}");
        assert!(
            t.starts_with("curl"),
            "the rest of the command still shows: {t}"
        );
    }

    /// A subagent call says which agent and what it was asked.
    #[test]
    fn a_subagent_call_names_the_agent_and_the_task() {
        assert_eq!(
            target(
                "Task",
                serde_json::json!({"agent": "Explore", "prompt": "find add()\nthen report"})
            ),
            "Explore · find add()"
        );
        assert_eq!(
            target(
                "Agent",
                serde_json::json!({"agent_type": "plan", "prompt": "outline"})
            ),
            "plan · outline"
        );
        assert_eq!(
            target("Task", serde_json::json!({"prompt": "just do it"})),
            "just do it"
        );
    }
}

#[cfg(test)]
mod accounting_tests {
    use super::*;
    use crate::dispatch::TurnOutcome;

    #[test]
    fn accounting_overflow_keeps_every_existing_total_unchanged() {
        for field in ["input", "output", "cost"] {
            let mut report = TurnReport {
                input_tokens: 7,
                output_tokens: 11,
                cost_microcents: 13,
                ..Default::default()
            };
            let mut outcome = TurnOutcome {
                input_tokens: 1,
                output_tokens: 1,
                cost_microcents: 1,
                ..Default::default()
            };
            match field {
                "input" => outcome.input_tokens = u64::MAX,
                "output" => outcome.output_tokens = u64::MAX,
                "cost" => outcome.cost_microcents = u64::MAX,
                _ => unreachable!(),
            }
            assert!(accumulate_accounting(&mut report, &outcome).is_err());
            assert_eq!(
                (
                    report.input_tokens,
                    report.output_tokens,
                    report.cost_microcents
                ),
                (7, 11, 13),
                "failed {field} addition must not partially update other totals"
            );
        }
    }

    #[test]
    fn accounting_exact_integer_boundary_remains_representable() {
        let mut report = TurnReport {
            input_tokens: u64::MAX - 1,
            output_tokens: u64::MAX - 2,
            cost_microcents: u64::MAX - 3,
            ..Default::default()
        };
        let outcome = TurnOutcome {
            input_tokens: 1,
            output_tokens: 2,
            cost_microcents: 3,
            ..Default::default()
        };
        accumulate_accounting(&mut report, &outcome).unwrap();
        assert_eq!(
            (
                report.input_tokens,
                report.output_tokens,
                report.cost_microcents
            ),
            (u64::MAX, u64::MAX, u64::MAX)
        );
    }

    #[test]
    fn current_turn_receipt_bound_refuses_before_growing_or_applying_an_extra_bill() {
        let mut report = TurnReport::default();
        let receipts: Vec<_> = (0..MAX_TURN_ACCOUNTING_ATTEMPTS)
            .map(|index| RequestAccountingReceipt {
                request_id: format!("bounded-{index}"),
                purpose: if index.is_multiple_of(2) {
                    AttemptPurpose::Ordinary
                } else {
                    AttemptPurpose::Chunk
                },
                totals: AccountingTotals {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: Some(1),
                },
                usage: Some(orbit_adapter::types::ProviderUsage::default()),
                knownness: AccountingKnownness::Known,
                completed: true,
            })
            .collect();
        assert!(!record_accounting(&mut report, &receipts).unwrap());
        assert_eq!(report.attempts.len(), MAX_TURN_ACCOUNTING_ATTEMPTS);
        assert_eq!(report.cost_microcents, MAX_TURN_ACCOUNTING_ATTEMPTS as u64);
        assert_eq!(report.accounting.ordinary.cost_microcents, Some(512));
        assert_eq!(report.accounting.housekeeping.cost_microcents, Some(512));
        let before = report.accounting.clone();
        assert!(record_accounting(&mut report, &receipts[..1]).is_err());
        assert_eq!(report.attempts.len(), MAX_TURN_ACCOUNTING_ATTEMPTS);
        assert_eq!(report.accounting, before);
        assert_eq!(report.cost_microcents, MAX_TURN_ACCOUNTING_ATTEMPTS as u64);
    }

    #[test]
    fn unpriced_housekeeping_policy_never_authorizes_unknown_ordinary_cost() {
        let mut report = TurnReport::default();
        let mut receipt = RequestAccountingReceipt {
            request_id: "unpriced".into(),
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(orbit_adapter::types::ProviderUsage::default()),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        record_accounting(&mut report, std::slice::from_ref(&receipt)).unwrap();
        let mut options = TurnOptions {
            spend_allowance: Some(SpendAllowance {
                remaining_microcents: 5,
                allow_unpriced_housekeeping: true,
            }),
            ..Default::default()
        };
        assert_eq!(
            remaining_allowance(&options, &report)
                .unwrap()
                .unwrap()
                .remaining_microcents,
            5
        );
        options
            .spend_allowance
            .as_mut()
            .unwrap()
            .allow_unpriced_housekeeping = false;
        assert!(remaining_allowance(&options, &report).is_err());
        receipt.purpose = AttemptPurpose::Ordinary;
        let mut ordinary = TurnReport::default();
        record_accounting(&mut ordinary, &[receipt]).unwrap();
        options
            .spend_allowance
            .as_mut()
            .unwrap()
            .allow_unpriced_housekeeping = true;
        assert!(remaining_allowance(&options, &ordinary).is_err());
    }

    #[test]
    fn review_regression_accounting_overflow_preserves_all_paid_batch_receipts() {
        let receipt = |id: &str, purpose, cost| RequestAccountingReceipt {
            request_id: id.into(),
            purpose,
            totals: AccountingTotals {
                input_tokens: 1,
                output_tokens: 1,
                cost_microcents: Some(cost),
            },
            usage: Some(orbit_adapter::types::ProviderUsage {
                input_tokens: 1,
                output_tokens: 1,
                ..Default::default()
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        let ordinary = receipt("prior-ordinary", AttemptPurpose::Ordinary, u64::MAX - 5);
        let batch = [
            receipt("paid-chunk-a", AttemptPurpose::Chunk, 4),
            receipt("paid-chunk-b", AttemptPurpose::Chunk, 4),
            receipt("paid-merge", AttemptPurpose::Merge, 4),
        ];
        let mut report = TurnReport::default();
        record_accounting(&mut report, std::slice::from_ref(&ordinary)).unwrap();
        let mut independently_attributed = report.accounting.clone();
        for paid in &batch {
            independently_attributed = independently_attributed.checked_with(paid).unwrap();
        }
        assert_eq!(
            independently_attributed.ordinary.cost_microcents,
            Some(u64::MAX - 5)
        );
        assert_eq!(
            independently_attributed.housekeeping.cost_microcents,
            Some(12)
        );
        assert!(record_accounting(&mut report, &batch).is_err());
        let mut all_paid = vec![ordinary];
        all_paid.extend(batch);
        assert_eq!(
            report.attempts, all_paid,
            "numeric overflow must not discard already-paid later receipts"
        );
        assert_eq!(
            report.cost_microcents,
            u64::MAX - 1,
            "keep the last representable numeric subtotal without wrapping"
        );
        assert_eq!(report.accounting.knownness, AccountingKnownness::Uncertain);
        let capped = TurnOptions {
            spend_allowance: Some(SpendAllowance {
                remaining_microcents: u64::MAX,
                allow_unpriced_housekeeping: true,
            }),
            ..Default::default()
        };
        assert!(remaining_allowance(&capped, &report).is_err());
    }
}

#[cfg(test)]
mod combined_accounting_tests {
    use super::*;

    // Checked inert metadata supplies lengths only; it cannot become live proof.
    fn refusal_snapshot() -> crate::retry::RefusalRecord {
        let intent = AttemptIntent {
            owner_session_id: "session".into(),
            child_id: None,
            request_id: "metadata-slot".into(),
            purpose: AttemptPurpose::Ordinary,
            budget: crate::context_budget::BudgetIdentity {
                binding_digest: "a".repeat(64),
                metadata_revision: "fixture".into(),
                policy_revision: "fixture".into(),
            },
        };
        let reference = crate::compaction::AttemptRef {
            revision: crate::compaction::AccountingRevision(1),
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest().unwrap(),
        };
        let binding = crate::retry::OrdinaryAttemptBindingRecord::new(
            intent.request_id.clone(),
            intent.request_id.clone(),
            intent.request_id.clone(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap();
        crate::retry::RefusalRecord::new(intent, reference, binding, "1".repeat(64), 503, 0)
            .unwrap()
    }

    fn measured_receipt() -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: "measured-slot".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 1,
                output_tokens: 0,
                cost_microcents: Some(7),
            },
            usage: Some(orbit_adapter::types::ProviderUsage {
                input_tokens: 1,
                ..Default::default()
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        }
    }

    #[test]
    fn ordinary_observer_latches_all_provider_kinds_and_preserves_private_observations() {
        use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent, ProviderUsage};
        let usage = ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 3,
            cache_write_tokens: 2,
            reasoning_tokens: 5,
        };
        let config = TurnConfig {
            provider_id: "fixture".into(),
            gate: "http://127.0.0.1:12345/v1".into(),
            model: "fixture-model".into(),
            kind: crate::ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: None,
            max_output_tokens: 64,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        let kinds = [
            ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
            ProviderEventKind::TextDelta {
                bytes: b"visible-text".to_vec(),
            },
            ProviderEventKind::ThinkingDelta {
                bytes: b"private-thinking".to_vec(),
            },
            ProviderEventKind::ThinkingSignatureDelta {
                bytes: b"private-signature".to_vec(),
            },
            ProviderEventKind::ToolCallStarted {
                call_index: 0,
                provider_call_id: Some("call".into()),
                name: "Read".into(),
            },
            ProviderEventKind::ToolCallArgumentsDelta {
                call_index: 0,
                bytes: b"{}".to_vec(),
            },
            ProviderEventKind::ToolCallFinished { call_index: 0 },
            ProviderEventKind::UsageUpdate(usage),
            ProviderEventKind::Finished {
                finish_reason: Some("stop".into()),
                final_usage: Some(usage),
            },
        ];
        for kind in kinds {
            let carries_usage = matches!(
                &kind,
                ProviderEventKind::UsageUpdate(_) | ProviderEventKind::Finished { .. }
            );
            let is_text = matches!(&kind, ProviderEventKind::TextDelta { .. });
            let is_tool_start = matches!(&kind, ProviderEventKind::ToolCallStarted { .. });
            let invalid_tool_order = matches!(
                &kind,
                ProviderEventKind::ToolCallArgumentsDelta { .. }
                    | ProviderEventKind::ToolCallFinished { .. }
            );
            let mut observed = false;
            let mut metadata = crate::compaction::MetadataAccounting::default();
            let mut lifecycle = ToolLifecycle::default();
            let mut frontend = Vec::new();
            observe_ordinary_event(
                &ProviderStreamEvent {
                    sequence: 0,
                    event: kind,
                },
                &mut observed,
                &mut metadata,
                &mut lifecycle,
                &mut |event| frontend.push(event),
            );
            // This is the actual latch passed to the private eligibility flag;
            // live transport qualification is tested separately with real HTTP.
            assert!(observed);
            assert_eq!(frontend.len(), usize::from(is_text));
            if is_text {
                assert!(
                    matches!(&frontend[0], FrontendEvent::TextDelta { text } if text == "visible-text")
                );
            }
            assert_eq!(lifecycle.calls.len(), usize::from(is_tool_start));
            assert_eq!(lifecycle.invalid, invalid_tool_order);
            let receipt = metadata.ordinary_receipt(
                "observed-request".into(),
                &config,
                &Err(("E0410", "fixture failure".into())),
                false,
            );
            assert_eq!(receipt.usage, carries_usage.then_some(usage));
            assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
        }
    }

    #[test]
    fn combined_refusal_receipt_boundary_retains_last_measured_slot_and_refuses_extra() {
        let refusals = vec![refusal_snapshot(); MAX_TURN_ACCOUNTING_ATTEMPTS - 1];
        let mut report = TurnReport::default();
        assert_eq!(remaining_accounting_metadata(&report, &refusals), Ok(1));
        assert!(require_accounting_slot(&report, &refusals).is_ok());
        record_accounting_with_refusals(&mut report, &refusals, &[measured_receipt()]).unwrap();
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.input_tokens, 1);
        assert_eq!(report.cost_microcents, 7);
        assert_eq!(remaining_accounting_metadata(&report, &refusals), Ok(0));
        assert!(require_accounting_slot(&report, &refusals).is_err());
        let before = report.accounting.clone();
        assert!(
            record_accounting_with_refusals(&mut report, &refusals, &[measured_receipt()]).is_err()
        );
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.accounting, before);
        assert_eq!(report.cost_microcents, 7);
    }

    #[test]
    fn refusal_only_limit_and_mixed_over_limit_cannot_dispatch_or_append() {
        let mut refusals = vec![refusal_snapshot(); MAX_TURN_ACCOUNTING_ATTEMPTS];
        let mut report = TurnReport::default();
        assert_eq!(remaining_accounting_metadata(&report, &refusals), Ok(0));
        assert!(require_accounting_slot(&report, &refusals).is_err());
        assert!(
            record_accounting_with_refusals(&mut report, &refusals, &[measured_receipt()]).is_err()
        );
        assert!(report.attempts.is_empty());
        refusals.push(refusal_snapshot());
        assert!(remaining_accounting_metadata(&report, &refusals).is_err());
        assert!(require_accounting_slot(&report, &refusals).is_err());
        record_accounting(&mut report, &[measured_receipt()]).unwrap();
        refusals.pop();
        assert!(remaining_accounting_metadata(&report, &refusals).is_err());
        assert_eq!(report.attempts.len(), 1);
    }
}

#[cfg(test)]
mod image_block_tests {
    use super::*;

    fn cancelled_transcript(
        prompt: &str,
        user_blocks: Option<Vec<orbit_adapter::types::ContentBlock>>,
    ) -> Vec<ChatMessage> {
        let home = std::env::temp_dir().join(format!("orbit-user-blocks-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        let config = TurnConfig {
            provider_id: "test".into(),
            gate: "http://127.0.0.1:1".into(),
            model: "test".into(),
            kind: crate::dispatch::ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: None,
            max_output_tokens: 32,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        let options = TurnOptions {
            user_blocks,
            ..Default::default()
        };
        let cancel = orbit_provider_http::CancelToken::new();
        cancel.cancel();
        let mut transcript = vec![user_message("earlier turn")];
        let mut executor = NoopExecutor;
        let report = run_turn(
            &home,
            &config,
            &options,
            prompt,
            &mut transcript,
            &mut executor,
            &cancel,
            &mut |_| {},
        )
        .unwrap();
        assert!(report.interrupted);
        std::fs::remove_dir_all(home).unwrap();
        transcript
    }

    #[test]
    fn initial_user_images_survive_the_engine_and_transcript_round_trip() {
        use orbit_adapter::types::ContentBlock;
        let blocks = vec![
            ContentBlock::Text {
                text: "inspect this image".into(),
            },
            ContentBlock::Image {
                data: "aGVsbG8=".into(),
                media_type: "image/png".into(),
            },
        ];
        let transcript = cancelled_transcript("inspect this image", Some(blocks.clone()));
        assert_eq!(transcript.len(), 2);
        assert_eq!(transcript[0].content, "earlier turn");
        assert!(transcript[0].blocks.is_none());
        assert_eq!(transcript[1].role, ChatRole::User);
        assert_eq!(transcript[1].content, "inspect this image");
        assert_eq!(transcript[1].blocks, Some(blocks));
        let saved = serde_json::to_string(&transcript).unwrap();
        let restored: Vec<ChatMessage> = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored[1].blocks, transcript[1].blocks);
    }

    #[test]
    fn ordinary_user_turns_keep_the_text_only_contract() {
        let transcript = cancelled_transcript("plain prompt", None);
        assert_eq!(transcript[1].content, "plain prompt");
        assert!(transcript[1].blocks.is_none());
    }

    /// A Read result carrying image data yields one Image block; the
    /// text-only result yields none.
    #[test]
    fn image_data_becomes_one_image_block() {
        let content = serde_json::json!({
            "ok": true,
            "content": "[image: shot.png, 40 bytes, image/png]",
            "image_base64": "aGVsbG8=",
            "image_media_type": "image/png",
        })
        .to_string();
        let blocks = image_block_of(&content).expect("an image block");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            orbit_adapter::types::ContentBlock::Image { data, media_type } => {
                assert_eq!(data, "aGVsbG8=");
                assert_eq!(media_type, "image/png");
            }
            other => panic!("not an image block: {other:?}"),
        }
    }

    #[test]
    fn a_text_result_has_no_image_block() {
        let content =
            serde_json::json!({ "ok": true, "content": "def add():\n  return 1" }).to_string();
        assert!(image_block_of(&content).is_none());
        // Not JSON at all: no panic, no block.
        assert!(image_block_of("not json").is_none());
    }

    /// A media type the payload omitted falls back to png — the block
    /// is still valid, never a blank media type.
    #[test]
    fn a_missing_media_type_defaults_to_png() {
        let content = serde_json::json!({ "ok": true, "image_base64": "aGVsbG8=" }).to_string();
        let blocks = image_block_of(&content).expect("an image block");
        match &blocks[0] {
            orbit_adapter::types::ContentBlock::Image { media_type, .. } => {
                assert_eq!(media_type, "image/png");
            }
            other => panic!("not an image block: {other:?}"),
        }
    }
}
