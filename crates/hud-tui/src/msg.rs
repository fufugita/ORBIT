#![allow(dead_code)] // data-bearing variants wired into the live loop in PR-C/PR-D

//! TUI message types (DR-20 §2.3).
//!
//! `Msg` is the single event type that flows through the `Bus` into
//! `App::reduce`. Control messages come from crossterm input; data-bearing
//! messages come from the worker thread (stream events, usage, tool calls).

use crate::input::KeyAction;

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
    /// A parsed key action from crossterm.
    KeyAction(KeyAction),

    // ── Data (from the worker thread / backend bridge) ──────────────────────
    /// A chunk of streamed text from the model. Already passed through
    /// `display_safe` by the bridge before it reaches the reducer.
    TextDelta(String),
    /// A one-line status message (model changed, session loaded, etc.).
    /// Rendered in the status bar / toast, NOT in the transcript.
    Status(String),
    /// The model finished a response (final text + usage).
    ResponseFinished {
        output: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    },
    /// A tool call started (name + display-safe argument summary).
    ToolCallStarted { name: String, summary: String },
    /// A tool call finished (display-safe result summary).
    ToolCallFinished { name: String, ok: bool },
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
    },
    /// Connection state changed (set by the harness on provider errors).
    ConnectionChanged(crate::state::ConnectionState),
    /// Cumulative cost updated (status bar).
    CostUpdated(u64),
    /// Initialize status-bar identity before the first render.
    Identity {
        model: String,
        provider: String,
        session_prefix: String,
    },
    /// Composer's text changed — force a re-render so the composer box updates
    /// every keystroke (the text lives in the event loop, not the App).
    ComposerChanged,
    /// Ctrl+C pressed — first press shows "press again to quit", second quits.
    /// While a turn is streaming, the first press cancels the turn instead.
    CtrlC,
    /// Cancel the in-flight turn (fired by Ctrl+C while streaming). The
    /// event loop triggers the worker's CancelToken; the reducer sets
    /// `cancel_requested` so the next `ResponseFinished` stamps the transcript.
    CancelTurn,
    /// Enter plain-text transcript copy mode.
    EnterCopyMode,
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
    /// Request to quit — opens confirmation prompt (q, Ctrl+D).
    RequestQuit,
    /// Confirm quit from the modal.
    ConfirmQuit,
    /// Cancel quit and return to the TUI.
    CancelQuit,
    /// Noninteractive shutdown (SIGHUP/SIGTERM/SIGINT via `kill`): terminal
    /// is gone or an external manager demands exit — skip the modal, quit now.
    SignalShutdown,
    /// A `/command` was typed in the composer (handled by the event loop).
    SlashCommand(String),
    /// `/clear` — wipe the visible transcript (and any in-flight buffer).
    ClearTranscript,
    /// The active model changed (status bar + future turns).
    ModelChanged(String),
    /// A display-safe system line appended to the transcript (e.g. command
    /// results such as `/help`, `/usage`, `/models`, `/sessions`).
    SystemMessage(String),
    /// The worker restored a session on boot or via `/resume <id>` — replaces
    /// the transcript and counters in one reduce.
    TranscriptLoaded {
        lines: Vec<crate::state::TranscriptLine>,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
        turns: u64,
    },
}
