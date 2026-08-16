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
    CtrlC,
    /// Enter plain-text transcript copy mode.
    EnterCopyMode,
    /// Request to quit — opens confirmation prompt (q, Ctrl+D).
    RequestQuit,
    /// Confirm quit from the modal.
    ConfirmQuit,
    /// Cancel quit and return to the TUI.
    CancelQuit,
    /// Noninteractive shutdown (SIGHUP/SIGTERM/SIGINT via `kill`): terminal
    /// is gone or an external manager demands exit — skip the modal, quit now.
    SignalShutdown,
}
