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
    /// `/model <M>` — switch the active model for subsequent turns.
    SetModel(String),
    /// `/models` — list provider/model entries (formatted by the worker).
    ListModels,
    /// `/sessions` — list saved sessions (formatted by the worker).
    ListSessions,
    /// `/resume <id>` — load a saved session (transcript + counters).
    ResumeSession(String),
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
