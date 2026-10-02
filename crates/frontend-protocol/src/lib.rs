//! The typed frontend protocol — the shared event/action vocabulary
//! every ORBIT frontend speaks (TUI, REPL, web, headless `-p`).
//!
//! The protocol is the DOMAIN layer: what the harness did and what the
//! operator asked. It is deliberately free of presentation concerns —
//! no crossterm keys, no terminal sizes, no DOM events. Each frontend
//! maps its own input onto `FrontendAction` and renders `FrontendEvent`
//! however it renders.
//!
//! Law (DESIGN-PRINCIPLES): the same protocol drives every frontend —
//! a capability added here appears in all of them, not per-frontend
//! forks. `orbit -p --output-format stream-json` emits these events
//! verbatim, one JSON object per line, so the SDKs generate from this
//! schema and cannot drift.
//!
//! PROTOCOL VERSION: 2. Every client states the version it speaks
//! (`FrontendAction::Hello { protocol_version }`); the engine rejects
//! mismatches rather than guessing.

use serde::{Deserialize, Serialize};

// ── Events: harness → frontend ──────────────────────────────────────────────

/// Something the harness reports to the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FrontendEvent {
    /// A chunk of assistant text arrived (streaming).
    TextDelta { text: String },
    /// The model finished a response (final text + usage).
    ResponseFinished {
        output: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    },
    /// A tool call started (name + display-safe summary).
    ToolStarted { name: String, summary: String },
    /// A tool call finished (ok/fail).
    ToolFinished { name: String, ok: bool },
    /// Cumulative cost updated.
    CostUpdated { total_microcents: u64 },
    /// The workspace's live state (plan/findings/verification).
    WorkspaceUpdate(Workspace),
    /// An approval is required before a tool runs.
    ApprovalRequested {
        call_id: String,
        tool_name: String,
        summary: String,
        risk: u8,
    },
    /// An approval was decided (granted/denied + scope).
    ApprovalResolved {
        call_id: String,
        granted: bool,
        session_wide: bool,
    },
    /// The connection state changed.
    ConnectionChanged(ConnectionState),
    /// Session identity (model/provider/session id) — sent at boot.
    Identity(Identity),
    /// An error from the backend.
    Error { message: String },
    /// A transient status note (toast-class).
    Status { text: String },
    /// A provider round started inside the running turn (engine v2).
    /// `round` counts from 0 within the turn.
    RoundStarted { round: u32 },
    /// The turn ended (engine v2). `interrupted` is true when the
    /// operator cancelled mid-round; partial text is kept.
    TurnEnded {
        ok: bool,
        interrupted: bool,
        rounds: u32,
        input_tokens: u64,
        output_tokens: u64,
        cost_microcents: u64,
    },
    /// The engine is retrying after a rate limit or server error
    /// (engine v2). `attempt` counts from 1; `retry_in_ms` is the
    /// backoff delay before the next attempt.
    Retrying {
        attempt: u32,
        retry_in_ms: u64,
        reason: String,
    },
    /// The reply was cut off by the output-token limit (engine v2).
    /// The turn ends with this note visible.
    OutputTruncated { limit: u64 },
}

// ── Actions: frontend → harness ─────────────────────────────────────────────

/// Something the operator asked the harness to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FrontendAction {
    /// Send a prompt (starts or queues a turn).
    Prompt { text: String },
    /// Cancel the in-flight turn.
    Cancel,
    /// Decide a pending approval.
    ApprovalDecision {
        call_id: String,
        decision: ApprovalDecision,
    },
    /// Start a new session.
    NewSession,
    /// Quit the frontend.
    Quit,
    /// State the protocol version the client speaks (engine v2). The
    /// engine rejects a mismatch instead of guessing.
    Hello { protocol_version: u32 },
}

/// An approval decision + its scope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Allow this one call.
    AllowOnce,
    /// Allow every call to this tool for the session.
    AllowSession,
    /// Deny the call.
    Deny,
}

// ── Shared state shapes ─────────────────────────────────────────────────────

/// Session identity — the model, provider, and session id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub model: String,
    pub provider: String,
    pub session_id: String,
}

/// The connection to the model gate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectionState {
    Online,
    Reconnecting,
    Offline,
}

/// The workspace pane's live state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Workspace {
    /// 0..=4: orient → reason → act → verify → respond.
    pub phase_index: usize,
    pub plan: Vec<Task>,
    pub findings: Vec<Finding>,
    pub verification: Vec<Verification>,
}

/// One plan row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub title: String,
    pub state: TaskState,
    /// Optional single sub-line (what it's doing / why blocked).
    pub sub: Option<String>,
    /// Verified proofs count (0 = claimed).
    pub evidence: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskState {
    Active,
    Blocked,
    Failed,
    Retest,
    AwaitingApproval,
    Done,
}

/// One finding row: title + inline source path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub source: Option<String>,
}

/// One verification row: check name + result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verification {
    pub name: String,
    pub result: VerificationResult,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationResult {
    Pass,
    Fail,
    NotRun,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_through_serde() {
        let ev = FrontendEvent::TextDelta {
            text: "hello".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"text_delta\""));
        let back: FrontendEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn actions_round_trip_through_serde() {
        let act = FrontendAction::ApprovalDecision {
            call_id: "call-0".into(),
            decision: ApprovalDecision::AllowSession,
        };
        let json = serde_json::to_string(&act).unwrap();
        let back: FrontendAction = serde_json::from_str(&json).unwrap();
        assert_eq!(act, back);
    }

    #[test]
    fn workspace_round_trips() {
        let ws = Workspace {
            phase_index: 2,
            plan: vec![Task {
                title: "patch".into(),
                state: TaskState::Active,
                sub: None,
                evidence: 0,
            }],
            findings: vec![],
            verification: vec![Verification {
                name: "cargo test".into(),
                result: VerificationResult::Pass,
            }],
        };
        let ev = FrontendEvent::WorkspaceUpdate(ws.clone());
        let back: FrontendEvent =
            serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(back, FrontendEvent::WorkspaceUpdate(ws));
    }
}
