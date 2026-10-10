#![allow(dead_code)] // data-bearing variants wired into the live loop in PR-C/PR-D

//! TUI message types (DR-20 §2.3).
//!
//! `Msg` is the single event type that flows through the `Bus` into
//! `App::reduce`. Control messages come from crossterm input; data-bearing
//! messages come from the worker thread (stream events, usage, tool calls).

use crate::model::ApprovalDecision;

/// The rule an approval card offers to remember (`s` for the session, `a`
/// for good), as the backend derived it from the call: shown as written,
/// so what the key grants is what the card says.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalGrant {
    /// `Bash(cargo test *)`.
    pub rule: String,
    /// Whether `a` can write it down: the folder is trusted.
    pub can_save: bool,
}

/// A message processed by the reducer (`App::reduce`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    // ── Control (from crossterm input) ──────────────────────────────────────
    /// Operator requested quit (`q`, `Ctrl+C`, or signal).
    Quit,
    /// Terminal resized (debounced 50 ms, H-12).
    Resize(u16, u16),
    /// 16 ms UI tick — advances animation, checks coalescer.
    Tick,

    // ── Data (from the worker thread / backend bridge) ──────────────────────
    /// A chunk of streamed text from the model. Already passed through
    /// `display_safe` by the bridge before it reaches the reducer.
    TextDelta(String),
    /// A one-line status message (model changed, session loaded, etc.).
    /// Rendered in the status bar / toast, NOT in the transcript.
    Status(String),
    /// The session's permission mode changed at runtime (S5:
    /// Shift+Tab or /mode). Payload: the mode name (default,
    /// acceptEdits, plan, dontAsk, bypass).
    ModeChanged(String),
    /// The model finished a response (final text + usage).
    ResponseFinished {
        output: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    },
    /// A tool call started: the call's id (lines are keyed by it, so two
    /// calls of one tool never share a card), the tool name and a
    /// display-safe argument summary. An empty `call_id` (a front-end
    /// that has none) falls back to matching by name.
    ToolCallStarted {
        call_id: String,
        name: String,
        summary: String,
    },
    /// The context is being compacted (`true`) or has been (`false`): the
    /// status line shows the amber "compacting context" while it runs.
    /// `tokens` is the conversation's estimated size: before the compaction
    /// when it starts, after it when it ends.
    Compaction { running: bool, tokens: u64 },
    /// Something for the Activity panel: a ledger record the session just
    /// appended (`digest` set) or a notable runtime event (a request, a
    /// compaction, a retry). Display-safe.
    Activity {
        kind: String,
        target: String,
        fact: String,
        digest: Option<String>,
    },
    /// Readiness rows the front-end cannot measure itself (the sandbox):
    /// `(ok, label)`, added to the welcome screen's READY list.
    Readiness(Vec<(bool, String)>),
    /// Facts and a preview for the approval that follows (same call id),
    /// from real data only: the sandbox state of a command, the lines an
    /// edit changes. Sent just before `ApprovalRequested`.
    ApprovalDetail {
        call_id: String,
        /// `(label, value)` rows for the card.
        facts: Vec<(String, String)>,
        /// Lines shown under the action: `- ` removed, `+ ` added,
        /// anything else context.
        preview: Vec<String>,
        /// The rule `s` and `a` would remember, when there is one.
        grant: Option<ApprovalGrant>,
    },
    /// The session's task list changed (TaskCreate/TaskUpdate): the Plan
    /// panel lists these, `(title, status)` in creation order, status
    /// pending | in_progress | done.
    TasksUpdate(Vec<(String, String)>),
    /// One line of a running command's live output, for the Terminal
    /// panel. Already display-safe.
    ToolOutput { call_id: String, line: String },
    /// The operator answered an approval card (§12): `once`, `session` or
    /// `denied`. Records the Activity `grant` row (§9.16) and the tool-line
    /// marker (◆ once / ◈ session).
    ApprovalDecision {
        tool: String,
        decision: ApprovalDecision,
    },
    /// A tool call finished. `outcome` distinguishes success, failure, an
    /// operator denial (a decision, not an error — §11.5 rule 4) and an
    /// unknown-tool block (deny-by-default), so the transcript never shows
    /// a red `✕ failed` for a refusal.
    ToolCallFinished {
        call_id: String,
        name: String,
        outcome: crate::model::ToolOutcome,
        /// A short true fact about the result ("212 lines", "exit 1"),
        /// or empty when the result carries none.
        fact: String,
    },
    /// An error from the backend (provider failure, etc.).
    BackendError(String),

    // ── Worker thread / harness ─────────────────────────────────────────────
    /// Operator submitted a prompt — the worker thread should begin a turn.
    /// The composer is the full text (multi-line supported in PR-D+).
    TextSubmitted(String),
    /// A tool call is awaiting approval (DR-20 §2.6). The input handler
    /// resolves it by looking up `call_id` in the `ApprovalRegistry`.
    ApprovalRequested {
        call_id: String,
        tool_name: String,
        summary: String,
        /// Structured risk (0..=3) from the backend classification —
        /// backend-authoritative, the UI renders it (§6.15).
        risk: u8,
        /// The working directory the call runs in — a real fact for the
        /// approval card (never invented).
        working_dir: String,
    },
    /// Connection state changed (set by the harness on provider errors).
    ConnectionChanged(crate::model::ConnectionState),
    /// The current turn's running cost (microcents) — after each provider
    /// round (§13.3 D5). The displayed total is committed + this; the
    /// commit happens on ResponseFinished, which carries the final turn
    /// cost exactly once.
    TurnCostUpdated(u64),
    /// Legacy alias kept while the Go bridge catches up (emits the
    /// session-cumulative number). Maps to committed-only display.
    CostUpdated(u64),
    /// The bridge rejected a text chunk (D7) — never renders the text.
    /// `kind` names the gate that rejected it for the chip label.
    Redacted { kind: crate::model::RedactionKind },
    /// Initialize status-bar identity before the first render.
    Identity {
        model: String,
        provider: String,
        session_prefix: String,
        /// The full session id (the §8.4 shutdown line needs it for the
        /// resume hint).
        session_id: String,
        /// D18: false when the model has no pricing entry — the status bar
        /// shows `cost n/a` instead of `$0.0000`.
        priced: bool,
    },
    /// Composer's text changed — force a re-render so the composer box updates
    /// every keystroke (the text lives in the event loop, not the App).
    ComposerChanged,
    /// Composer text snapshot — the reducer derives the live
    /// slash-hint dropdown from it (open/matches/selection).
    ComposerTextChanged(String),
    /// Move the slash-hint dropdown selection.
    SlashHintSelect(usize),
    /// Toggle plan mode (Shift+Tab cycle).
    PlanModeToggle,
    /// A plan-mode turn finished; the text is held for approval.
    PlanReady(String),
    /// Operator approved the pending plan (payload = plan text).
    PlanApproved(String),
    /// Operator discarded the pending plan.
    PlanDiscarded,
    /// Ctrl+C pressed — first press shows "press again to quit", second quits.
    /// While a turn is streaming, the first press cancels the turn instead.
    CtrlC,
    /// Cancel the in-flight turn (fired by Ctrl+C while streaming). The
    /// event loop triggers the worker's CancelToken; the reducer sets
    /// `cancel_requested` so the next `ResponseFinished` stamps the transcript.
    CancelTurn,
    /// Enter plain-text transcript copy mode.
    EnterCopyMode,
    /// Exit copy mode without yanking.
    ExitCopyMode,
    /// Move the copy cursor by delta lines (per-pane copy mode).
    CopyMove(i32),
    /// Start/extend selection at the copy cursor.
    CopySelect,
    /// Yank the current selection to the system clipboard.
    CopyYank,
    /// Command palette (§6.13): toggle open/closed.
    PaletteToggle,
    /// A character typed into the palette query.
    PaletteChar(char),
    /// Backspace in the palette query.
    PaletteBackspace,
    /// Move the palette selection (true = down, false = up).
    PaletteMove(bool),
    /// Execute the selected palette command.
    PaletteExecute,
    /// Input mode changed (insert ↔ normal).
    InputModeChanged(crate::model::InputMode),
    /// Scroll the focused pane by delta lines (positive = down).
    PaneScroll {
        pane: crate::model::Focus,
        delta: i32,
    },
    /// Toggle zoom on a pane (herdr-style fullscreen).
    ZoomToggle(crate::model::Focus),
    /// Anchor a per-pane selection at (row, col).
    SelectionAnchor {
        pane: crate::model::Focus,
        row: u16,
        col: u16,
    },
    /// Extend the active selection (clamped to its pane).
    SelectionExtend {
        pane: crate::model::Focus,
        row: u16,
        col: u16,
    },
    /// Finalize the selection on mouse-up (copies via OSC 52).
    SelectionFinish,
    /// Clear the selection.
    SelectionClear,
    /// The workspace pane's live state (plan/findings/verification) —
    /// emitted by the worker as the turn progresses.
    WorkspaceUpdate(crate::model::Workspace),
    /// §8.3: skip the startup reveal to the final frame.
    SplashSkip,
    /// §6.12: show a toast (3 s or until the next keypress).
    ToastShow {
        text: String,
        kind: crate::model::ToastKind,
    },
    /// §6.12: dismiss the toast (any keypress).
    ToastDismiss,
    /// §6.16: toggle the help overlay.
    HelpToggle,
    /// Request to quit — opens confirmation prompt (q, Ctrl+D).
    RequestQuit,
    /// Confirm quit from the modal.
    ConfirmQuit,
    /// Cancel quit and return to the TUI.
    CancelQuit,
    /// Noninteractive shutdown (SIGHUP/SIGTERM/SIGINT via `kill`): terminal
    /// is gone or an external manager demands exit — skip the modal, quit now.
    SignalShutdown,
    /// D8: Ctrl+C while approvals are pending — deny them all (releases
    /// the parked worker) and clear the cards. NOT a quit gesture.
    ApprovalsDenied,
    /// A `/command` was typed in the composer (handled by the event loop).
    SlashCommand(String),
    /// `/clear` — wipe the visible transcript (and any in-flight buffer).
    ClearTranscript,
    /// The active model changed (status bar + future turns).
    ModelChanged(String),
    /// A file the agent changed (path, lines added/removed) — the
    /// Changes panel's rows.
    FileChanged {
        path: String,
        added: u32,
        removed: u32,
        /// Bounded unified hunks (M11) — None when there was no
        /// "before" to diff against.
        hunks: Option<Vec<orbit_frontend_protocol::DiffHunk>>,
    },
    /// A subagent started (id, name, task).
    SubagentStarted {
        id: String,
        name: String,
        task: String,
    },
    /// A subagent's current action.
    SubagentProgress { id: String, action: String },
    /// A subagent finished with its report.
    /// `ok` is whether the subagent completed (false: it failed or was
    /// stopped); `report` is its final words, or why it stopped.
    SubagentFinished {
        id: String,
        report: String,
        ok: bool,
    },
    /// Context usage: tokens in use and the model's window, and (when the
    /// engine measured it) what the use is made of.
    Usage {
        used_tokens: u64,
        window_tokens: u64,
        breakdown: Option<orbit_frontend_protocol::ContextBreakdown>,
    },
    /// The ledger grew: the record count after the append.
    LedgerAppended { record_count: u64 },
    /// A display-safe system line appended to the transcript (e.g. command
    /// results such as `/help`, `/usage`, `/models`, `/sessions`).
    SystemMessage(String),
    /// The worker restored a session on boot or via `/resume <id>` — replaces
    /// the transcript and counters in one reduce.
    TranscriptLoaded {
        lines: Vec<crate::model::TranscriptLine>,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
        turns: u64,
    },
}
