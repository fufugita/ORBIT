//! Worker-thread spawner abstraction (DR-20 §2.3).
//!
//! The worker thread runs the backend (`run_turn`, tool execution, session
//! save) and communicates with the reducer exclusively through `Bus<Msg>`.
//!
//! Prompt delivery: the worker owns the receiver end of a prompt channel;
//! the TUI's input handler owns the sender. After creating the prompt channel,
//! `run` passes the sender to its input handler and the receiver to the
//! worker-spawner closure.

use crate::approval::ApprovalRegistry;
use crate::bus::BusSender;
use std::sync::mpsc;

/// A typed command sent from the TUI to the worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerCommand {
    /// Run a normal user prompt as a turn.
    Prompt(String),
    /// Run a prompt in PLAN MODE (Claude Code parity): read-only posture
    /// — the turn carries a plan directive, every tool call is denied
    /// with a plan-mode notice, and the final text is delivered as a
    /// PlanReady card awaiting operator approval instead of running.
    PlanPrompt(String),
    /// `/model <M>` — switch the active model for subsequent turns.
    SetModel(String),
    /// `/models` — list provider/model entries (formatted by the worker).
    ListModels,
    /// `/sessions` — list saved sessions (formatted by the worker).
    ListSessions,
    /// `/resume <id>` — load a saved session (transcript + counters).
    ResumeSession(String),
    /// `/compact` — Claude Code parity: summarize the transcript into one
    /// message via the provider, then REPLACE the working transcript with
    /// that summary. Fresh context window, same session.
    Compact,
    /// `/rewind` — restore code and/or conversation to a checkpoint
    /// (phase 4). No argument: list checkpoints. With an id: restore.
    Rewind(String),
    /// `/mods` — list installed mods with enabled state (formatted here).
    ListInstalledMods,
    /// `/mod <name>` — toggle a mod; subsequent turns see (or drop) its
    /// instructions.
    ToggleMod(String),
    /// `/mods refresh` — rescan `$ORBIT_HOME/mods/` (after the operator
    /// edits or installs one mid-session).
    RefreshMods,
    /// A mod-contributed command `/name:cmd` — run the command's prompt
    /// body as a normal turn.
    ModCommand(String, String),
    /// `/undo` — drop the last exchange (user prompt + its assistant
    /// reply + any tool plumbing) from the working transcript, and emit
    /// the removed text so the operator can re-paste it.
    Undo,
    /// `/permissions [allow|deny|reset <tool>]` — view/mutate the
    /// persistent permission rules (CLI-side: the rules module lives in
    /// orbit-cli, which the TUI crate can't depend on).
    Permissions(String),
}

/// The sender end of the worker-command channel — held by the TUI's event
/// loop. The worker spawner does NOT see this; the `WorkerCtx` carries the
/// receiver.
pub type CommandSink = mpsc::Sender<WorkerCommand>;

/// The context a worker-spawner closure needs to talk to the TUI.
pub struct WorkerCtx {
    pub sender: BusSender,
    pub approvals: ApprovalRegistry,
    /// Receiver end of the worker-command channel. The worker blocks here for
    /// the next user prompt or `/command`.
    pub command_rx: mpsc::Receiver<WorkerCommand>,
}

/// Fires cancellation of the worker's CURRENT turn, if one is running.
/// The CLI implements this around the provider `CancelToken`; the TUI only
/// sees an opaque closure (no provider-http dependency here).
pub type CancelHandle = std::sync::Arc<dyn Fn() + Send + Sync>;

/// Spawns the backend worker thread. The CLI provides the implementation
/// (it owns `run_turn`); the TUI calls it after entering the terminal.
/// `command_sink` is the sender end the CLI may keep if it wants to feed
/// synthetic commands; normally the TUI's event loop holds it.
/// Returns a `CancelHandle` the event loop fires on Ctrl+C-mid-turn.
pub type WorkerSpawner =
    Box<dyn FnOnce(WorkerCtx, CommandSink) -> Result<CancelHandle, String> + Send>;
