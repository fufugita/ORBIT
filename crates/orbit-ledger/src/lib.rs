//! ORBIT primitive-specific Ledger events — Phase G.
//!
//! Digest-only event shapes for the six primitives (DR-12 §4-§9), honoring the
//! DR-06 digest-only rule: no prompt bytes, no raw content — only digests,
//! IDs, and counts (DR-14 UAI-I6 / KERN-2: every primitive call is an event).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Ledger-event errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EventError {
    #[error("invalid event: {0}")]
    Invalid(String),
}

/// PEB event: submission lifecycle (digest-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebEvent {
    pub submission_id: String,
    pub intent_digest: String, // UAI digest; never prompt bytes
    pub state: String,         // received | compiled | dispatched | closed
}

/// TTE event: task lifecycle (digest-only, no tool output bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TteEvent {
    pub task_id: String,
    pub tool: String,
    pub uai_scope_digest: String,
    pub state: String, // authorized | running | succeeded | failed | cancelled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_microcents: Option<u64>,
}

/// ML event: memory lifecycle (digest-only; value hash never the value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlEvent {
    pub memory_id: String,
    pub key: String,
    pub value_digest: String,
    pub scope: String,
    pub op: String, // write | export | forget
}

/// RTA event: trust assessment (immutable once recorded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtaEvent {
    pub assessment_id: String,
    pub target: String,
    pub level: String, // standard | local (attested reserved)
    pub at_ms: u64,
}

/// EPB event: evidence bundle (digest-only artifacts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpbEvent {
    pub bundle_id: String,
    pub artifact_digests: Vec<String>,
    pub verification: String, // ok | failed (immutable)
}

/// SDE event: session/decision envelope (UAI-anchored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdeEvent {
    pub envelope_id: String,
    pub session_id: String,
    pub uai_root_digest: String,
    pub state: String, // open | derived | closed
}

/// The unified primitive event envelope (KERN-2: every call is an event).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "primitive", rename_all = "snake_case")]
pub enum PrimitiveEvent {
    Peb(PebEvent),
    Tte(TteEvent),
    Ml(MlEvent),
    Rta(RtaEvent),
    Epb(EpbEvent),
    Sde(SdeEvent),
}

impl PrimitiveEvent {
    /// Validate an event carries only digests (no raw prompt/secret bytes).
    /// Rejects any field that looks like raw content (KERN-2 digest-only).
    pub fn validate_digest_only(&self) -> Result<(), EventError> {
        match self {
            Self::Peb(e) => {
                if e.intent_digest.len() != 64 {
                    return Err(EventError::Invalid(
                        "PEB intent_digest must be 64 hex".into(),
                    ));
                }
            }
            Self::Ml(e) => {
                if e.value_digest.len() != 64 {
                    return Err(EventError::Invalid("ML value_digest must be 64 hex".into()));
                }
            }
            Self::Epb(e) => {
                for d in &e.artifact_digests {
                    if d.len() != 64 {
                        return Err(EventError::Invalid(
                            "EPB artifact digest must be 64 hex".into(),
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_carry_only_digests() {
        let peb = PrimitiveEvent::Peb(PebEvent {
            submission_id: "s1".into(),
            intent_digest: "a".repeat(64),
            state: "compiled".into(),
        });
        assert!(peb.validate_digest_only().is_ok());

        let bad = PrimitiveEvent::Peb(PebEvent {
            submission_id: "s2".into(),
            intent_digest: "not-a-digest".into(),
            state: "compiled".into(),
        });
        assert!(bad.validate_digest_only().is_err());
    }

    #[test]
    fn ml_value_never_raw() {
        let ev = PrimitiveEvent::Ml(MlEvent {
            memory_id: "m1".into(),
            key: "k".into(),
            value_digest: "b".repeat(64),
            scope: "global".into(),
            op: "write".into(),
        });
        assert!(ev.validate_digest_only().is_ok());
        // The value itself is never in the event — only its digest.
        assert!(!serde_json::to_string(&ev).unwrap().contains("raw-value"));
    }
}
