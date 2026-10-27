//! Shared per-turn settings for owned session backends.

use orbit_adapter::types::{ChatMessage, EffortSetting};
use std::path::PathBuf;

/// The per-turn state the worker needs to run one prompt.
#[derive(Clone)]
pub struct SessionTurnConfig {
    pub home: PathBuf,
    pub session_id: String,
    pub gate: String,
    pub model: String,
    /// Selection provenance, independent of the resolved provider wire value.
    pub effort: Option<EffortSetting>,
    pub provider_id: String,
    pub auto_tools: bool,
    /// The session's permission scope (S5): mode + operator lists.
    /// Mutable at runtime via WorkerCommand::SetMode.
    pub scope: crate::tool_runtime::PermissionScope,
    /// Restored session state. Empty/zero for a fresh chat.
    pub initial_transcript: Vec<ChatMessage>,
    pub initial_turns: u64,
    pub initial_input_tokens: u64,
    pub initial_output_tokens: u64,
    pub initial_cost_microcents: u64,
}
