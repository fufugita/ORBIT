//! TTE — Task and Tool Execution (DR-12 §5, DR-14 amendments).
//!
//! Executes authorized work through capability-gated tool calls. Never selects
//! models (TTE-I1: declared ModelRef only). TaskSpec carries a `uai_scope_digest`
//! and requires `AuthorizedByUai` before Ready (TTE-I11); a task not covered by
//! the effective grant is refused (TTE-I12 / E1930). Sandbox strictness is
//! tighten-only (TTE-I13 / E1910).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// TTE errors (E1301-E1305 + E1930).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TteError {
    #[error("ORBIT-E1301 tte_task_not_found: {0}")]
    TaskNotFound(String),
    #[error("ORBIT-E1302 tte_tool_not_allowed: {0}")]
    ToolNotAllowed(String),
    #[error("ORBIT-E1303 tte_concurrent_execution_exceeded: {0}")]
    ConcurrencyExceeded(String),
    #[error("ORBIT-E1304 tte_cancel_incompatible: {0}")]
    CancelIncompatible(String),
    #[error("ORBIT-E1930 grant_not_covering_capability: {0}")]
    GrantNotCovering(String),
}

impl TteError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TaskNotFound(_) => "E1301",
            Self::ToolNotAllowed(_) => "E1302",
            Self::ConcurrencyExceeded(_) => "E1303",
            Self::CancelIncompatible(_) => "E1304",
            Self::GrantNotCovering(_) => "E1930",
        }
    }
}

/// Task state (DR-12 §5.4 + DR-14 TTE-I11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Accepted,
    AuthorizedByUai, // grant covers the task before Ready
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

/// A task spec with the DR-14 UAI binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub task_id: String,
    pub session_id: String,
    pub tool: String,             // the tool to invoke
    pub declared_model: String,   // ModelRef flat string (TTE-I1)
    pub uai_scope_digest: String, // DR-14: effective grant scope
    pub state: TaskState,
}

/// The TTE service.
pub struct TteService;

impl TteService {
    /// Authorize a task against the effective grant scope (TTE-I11/I12).
    /// The grant must cover the task's tool; else E1930.
    pub fn authorize(
        &self,
        mut task: TaskSpec,
        grant_covers_tool: bool,
    ) -> Result<TaskSpec, TteError> {
        if !grant_covers_tool {
            return Err(TteError::GrantNotCovering(format!(
                "grant does not cover tool {} for task {} (E1930)",
                task.tool, task.task_id
            )));
        }
        if task.uai_scope_digest.is_empty() {
            return Err(TteError::GrantNotCovering(
                "task missing uai_scope_digest (E1930)".into(),
            ));
        }
        task.state = TaskState::AuthorizedByUai;
        Ok(task)
    }

    /// Run a task (only after AuthorizedByUai).
    pub fn run(&self, task: &TaskSpec) -> Result<TaskState, TteError> {
        if task.state != TaskState::AuthorizedByUai {
            return Err(TteError::CancelIncompatible(format!(
                "task {} must be AuthorizedByUai before Running (E1304)",
                task.task_id
            )));
        }
        Ok(TaskState::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(uai: &str) -> TaskSpec {
        TaskSpec {
            task_id: "t1".into(),
            session_id: "s1".into(),
            tool: "fs.read".into(),
            declared_model: "gpt-4".into(),
            uai_scope_digest: uai.into(),
            state: TaskState::Accepted,
        }
    }

    #[test]
    fn task_without_grant_refused() {
        let svc = TteService;
        let t = task("");
        assert_eq!(svc.authorize(t, false).unwrap_err().code(), "E1930");
    }

    #[test]
    fn run_requires_authorization() {
        let svc = TteService;
        let t = task("digest");
        assert_eq!(svc.run(&t).unwrap_err().code(), "E1304");
        let t = svc.authorize(t, true).unwrap();
        assert_eq!(svc.run(&t).unwrap(), TaskState::Running);
    }
}
