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

/// A worker's committed session identity. Generations change only on a real swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualAction {
    Compact,
    Clear,
}

#[derive(Clone)]
pub struct ManualOperation {
    inner: std::sync::Arc<ManualOperationInner>,
}

struct ManualOperationInner {
    source: SessionBinding,
    action: ManualAction,
    id: u64,
    state: std::sync::Mutex<ManualCancelState>,
}

#[derive(Default)]
struct ManualCancelState {
    installed: bool,
    closed: bool,
    requested: bool,
    callback: Option<CancelHandle>,
}

impl std::fmt::Debug for ManualOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualOperation")
            .field("source", self.source())
            .field("action", &self.action())
            .field("id", &self.id())
            .finish()
    }
}

impl PartialEq for ManualOperation {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for ManualOperation {}

/// Closes only its captured operation; dropping it performs no I/O.
pub struct ManualCancelRegistration {
    operation: ManualOperation,
}

impl Drop for ManualCancelRegistration {
    fn drop(&mut self) {
        if let Ok(mut state) = self.operation.inner.state.lock() {
            state.closed = true;
            state.callback = None;
        }
    }
}

impl ManualOperation {
    pub fn new(
        source: SessionBinding,
        action: ManualAction,
        id: u64,
    ) -> Result<Self, &'static str> {
        if id == 0
            || source.generation == 0
            || source.session_id.is_empty()
            || source.session_id.len() > 128
            || !source
                .session_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid manual operation identity");
        }
        Ok(Self {
            inner: std::sync::Arc::new(ManualOperationInner {
                source,
                action,
                id,
                state: std::sync::Mutex::new(ManualCancelState::default()),
            }),
        })
    }

    pub fn source(&self) -> &SessionBinding {
        &self.inner.source
    }
    pub fn action(&self) -> ManualAction {
        self.inner.action
    }
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    pub fn cancel(&self) -> Result<bool, &'static str> {
        let callback = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| "manual cancellation unavailable")?;
            if state.closed {
                return Ok(false);
            }
            state.requested = true;
            state.callback.clone()
        };
        if let Some(callback) = callback {
            callback();
        }
        Ok(true)
    }

    pub fn install_cancel(
        &self,
        callback: CancelHandle,
    ) -> Result<ManualCancelRegistration, &'static str> {
        let requested = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| "manual cancellation unavailable")?;
            if state.closed || state.installed {
                return Err("manual operation already consumed");
            }
            state.installed = true;
            state.callback = Some(callback.clone());
            state.requested
        };
        if requested {
            callback();
        }
        Ok(ManualCancelRegistration {
            operation: self.clone(),
        })
    }

    pub fn finish_unstarted(&self) -> Result<(), &'static str> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "manual cancellation unavailable")?;
        if state.installed {
            return Err("manual operation already installed");
        }
        state.closed = true;
        state.callback = None;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForegroundKind {
    Prompt,
    PlanPrompt,
    Control,
    Resume,
}

impl ForegroundKind {
    pub fn is_ordinary(self) -> bool {
        matches!(self, Self::Prompt | Self::PlanPrompt)
    }
}

/// One source-bound foreground admission, retained until its checked projection.
#[derive(Clone)]
pub struct ForegroundOperation {
    inner: std::sync::Arc<ForegroundOperationInner>,
}

struct ForegroundOperationInner {
    source: SessionBinding,
    kind: ForegroundKind,
    id: u64,
    state: std::sync::atomic::AtomicU8,
}

impl std::fmt::Debug for ForegroundOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForegroundOperation")
            .field("source", self.source())
            .field("kind", &self.kind())
            .field("id", &self.id())
            .finish()
    }
}
impl PartialEq for ForegroundOperation {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for ForegroundOperation {}

pub struct ForegroundRegistration {
    operation: ForegroundOperation,
}
impl Drop for ForegroundRegistration {
    fn drop(&mut self) {
        self.operation
            .inner
            .state
            .store(2, std::sync::atomic::Ordering::Release);
    }
}

impl ForegroundOperation {
    pub fn new(
        source: SessionBinding,
        kind: ForegroundKind,
        id: u64,
    ) -> Result<Self, &'static str> {
        if id == 0
            || source.generation == 0
            || source.session_id.is_empty()
            || source.session_id.len() > 128
            || !source
                .session_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid foreground operation identity");
        }
        Ok(Self {
            inner: std::sync::Arc::new(ForegroundOperationInner {
                source,
                kind,
                id,
                state: std::sync::atomic::AtomicU8::new(0),
            }),
        })
    }
    pub fn source(&self) -> &SessionBinding {
        &self.inner.source
    }
    pub fn kind(&self) -> ForegroundKind {
        self.inner.kind
    }
    pub fn id(&self) -> u64 {
        self.inner.id
    }
    pub fn start(&self, command: &WorkerCommand) -> Result<ForegroundRegistration, &'static str> {
        if command.foreground_kind() != Some(self.kind()) {
            return Err("foreground operation kind differs from its command");
        }
        self.inner
            .state
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| "foreground operation already consumed")?;
        Ok(ForegroundRegistration {
            operation: self.clone(),
        })
    }
    pub fn finish_unstarted(&self) -> Result<(), &'static str> {
        self.inner
            .state
            .compare_exchange(
                0,
                2,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| "foreground operation already consumed")?;
        Ok(())
    }
}

/// A typed command sent from the TUI to the worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerCommand {
    /// Official managed UI admission; legacy constructors remain available.
    Bound {
        operation: ForegroundOperation,
        command: Box<WorkerCommand>,
    },
    /// Run a normal user prompt as a turn.
    Prompt(String),
    /// Run a prompt in PLAN MODE (Claude Code parity): read-only posture
    /// — the turn carries a plan directive, every tool call is denied
    /// with a plan-mode notice, and the final text is delivered as a
    /// PlanReady card awaiting operator approval instead of running.
    PlanPrompt(String),
    /// `/model <M>` — switch the active model for subsequent turns.
    SetModel(String),
    /// `/effort [VALUE]` — query or select a subsequent-request effort control.
    Effort(String),
    /// `/route` — inspect routing or explicitly restore automatic selection.
    Route(String),
    /// `/models` — list provider/model entries (formatted by the worker).
    ListModels,
    /// `/sessions` — list saved sessions (formatted by the worker).
    ListSessions,
    /// `/resume <id>` — load a saved session (transcript + counters).
    ResumeSession(String),
    /// `/compact` — Claude Code parity: summarize the transcript into one
    /// message via the provider, then REPLACE the working transcript with
    /// that summary. Fresh context window, same session.
    Compact(ManualOperation),
    /// Preserve this source and start a positively fresh session.
    ClearSession(ManualOperation),
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
    /// Change the session's permission mode at runtime (S5): the
    /// worker mutates the session's PermissionScope in place; the next
    /// turn (and every approval card) obeys it. Payload: the mode name
    /// (default, acceptEdits, plan, dontAsk, bypass).
    SetMode(String),
    /// `!command` — the shell bang (gate 1): run one command through
    /// the Bash tool's full path — sandbox, permissions, approvals,
    /// scanner — and show the result as a tool line. The composer
    /// stays responsive: the command runs on the worker thread, and
    /// Esc kills it like any tool.
    ShellBang(String),
}

impl WorkerCommand {
    pub fn foreground_kind(&self) -> Option<ForegroundKind> {
        match self {
            Self::Prompt(_) | Self::ModCommand(_, _) => Some(ForegroundKind::Prompt),
            Self::PlanPrompt(_) => Some(ForegroundKind::PlanPrompt),
            Self::ResumeSession(_) => Some(ForegroundKind::Resume),
            Self::SetModel(_)
            | Self::Effort(_)
            | Self::Route(_)
            | Self::Rewind(_)
            | Self::ToggleMod(_)
            | Self::RefreshMods
            | Self::Undo
            | Self::Permissions(_)
            | Self::SetMode(_)
            | Self::ShellBang(_) => Some(ForegroundKind::Control),
            Self::Bound { .. }
            | Self::Compact(_)
            | Self::ClearSession(_)
            | Self::ListModels
            | Self::ListSessions
            | Self::ListInstalledMods => None,
        }
    }
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
