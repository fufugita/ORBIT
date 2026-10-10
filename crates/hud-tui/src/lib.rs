//! ORBIT HUD-TUI: the terminal front-end.
//!
//! The screen lives in [`proto`]; `orbit` starts it when stdin and stdout
//! are a TTY (`--no-tui` keeps the plain REPL). The rest of the crate is
//! the contract the CLI's worker drives it through: the message bus
//! ([`bus`], [`msg`]), the approval registry ([`approval`]), the bridge
//! that makes what reaches the screen display-safe ([`bridge`]), and the
//! types they share ([`model`]).

#![forbid(unsafe_code)]

pub mod approval;
pub mod bridge;
pub mod bus;
pub mod model;
pub mod msg;
pub mod proto;
pub mod selection;
mod terminal;
pub mod tokens;
pub mod worker;

pub use approval::{ApprovalRegistry, ApprovalResponse};
pub use bridge::{
    emit_activity, emit_approval_detail, emit_compaction, emit_cost, emit_error, emit_file_changed,
    emit_ledger_appended, emit_mode_changed, emit_plan_ready, emit_readiness,
    emit_response_finished, emit_status, emit_subagent_finished, emit_subagent_progress,
    emit_subagent_started, emit_tasks, emit_text, emit_tool_finished, emit_tool_output,
    emit_tool_started, emit_turn_cost, emit_usage, emit_workspace, safe_text, safe_text_probe,
    sanitize_glyphs, strip_cot, terminal_safe, CotStripper,
};
pub use model::RedactionKind;
pub use msg::ApprovalGrant;
pub use proto::shell::panes::tokens_short;
pub use worker::{CommandSink, WorkerCommand, WorkerCtx, WorkerSpawner};
