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

/// The sender end of the prompt channel — held by the TUI's input handler.
/// The worker spawner does NOT see this; the `WorkerCtx` carries the receiver.
pub type PromptSink = mpsc::Sender<String>;

/// The context a worker-spawner closure needs to talk to the TUI.
pub struct WorkerCtx {
    pub sender: BusSender,
    pub approvals: ApprovalRegistry,
    /// Receiver end of the prompt channel. The worker blocks here for the
    /// next user prompt.
    pub prompt_rx: mpsc::Receiver<String>,
}

/// Spawns the backend worker thread. The CLI provides the implementation
/// (it owns `run_turn`); the TUI calls it after entering the terminal.
/// `prompt_sink` is the sender end the CLI may keep if it wants to feed
/// synthetic prompts; normally the TUI's input handler holds it.
pub type WorkerSpawner = Box<dyn FnOnce(WorkerCtx, PromptSink) -> Result<(), String> + Send>;
