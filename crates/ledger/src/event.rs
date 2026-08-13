//! Ledger event taxonomy (DR-06 §5-6) and the hash-chained record wrapper (§2).
//!
//! Every record carries:
//! - `ledger_hash_prev`: SHA256(previous_record.canonical_bytes)
//! - `ledger_hash_self`: SHA256(record_without_self_hash_and_without_signature.canonical_bytes)
//!
//! Wire rules (DR-06 §2.1): no `null`; absent fields omitted; sorted keys.
//! `signature` is present as `null` placeholder (v0.1 out-of-tree) except on
//! `AuthorityGrant` where DR-14 requires an in-process Ed25519 signature.

use crate::canonical;
use serde::{Deserialize, Serialize};

/// Session id (ULID).
pub type SessionId = String;
/// Decision id (ULID).
pub type DecisionId = String;
/// Subagent id (ULID).
pub type SubagentId = String;
/// Grant id (v7 UUID) for DR-14 AuthorityGrant.
pub type GrantId = String;

/// Reactor phases (DR-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Init,
    Plan,
    Execute,
    Verify,
    Checkpoint,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Plan => "plan",
            Self::Execute => "exec",
            Self::Verify => "ver",
            Self::Checkpoint => "ckpt",
        }
    }
}

/// Terminal outcome kinds (DR-01 I12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalOutcome {
    Completed,
    Failed,
    Cancelled,
}

/// Egress categories (DR-06 §6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressCategory {
    #[serde(rename = "model_inference")]
    ModelInference,
}

/// A single egress destination tuple (DR-01 I16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    pub provider_id: String,
    pub region_id: String,
}

/// EgressIntent — the egress gate (DR-06 §6.4). Written BEFORE any DNS/TLS/network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIntent {
    pub session_id: SessionId,
    pub intent_id: DecisionId,
    pub decision_id: DecisionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<SubagentId>,
    pub destinations: Vec<EgressDestination>,
    pub egress_digest: String, // SHA256(canonical_destinations_sorted)
    pub egress_categories: Vec<EgressCategory>,
    pub policy_snapshot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_card_proofs: Option<Vec<String>>,
}

/// SubagentCall — one record per spawn (DR-06 §6.5, DR-01 I7), declared+resolved atomic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentCall {
    pub call_id: SubagentId,
    pub session_id: SessionId,
    pub decision_id: DecisionId,
    pub declared_model: String,
    pub resolved_model: String,
    pub outcome: TerminalOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_microcents: Option<u64>,
}

/// Refused — a pre-dispatch denial (DR-06 §6.7); includes authority reason classes (DR-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub session_id: SessionId,
    pub decision_id: DecisionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<SubagentId>,
    pub reason_class: String,
    pub hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_intent_hash: Option<String>,
}

/// AuthorityGrant — a confirmed, operator-signed user authority grant (DR-14, DR-06 §6.21).
/// Digest-only; signature is REQUIRED (DR-14 Ed25519 exception).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityGrant {
    pub session_id: SessionId,
    pub grant_id: GrantId,
    pub intent_digest: String,
    pub diff_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_hash: Option<String>,
    pub policy_snapshot_id_before: String,
    pub policy_snapshot_id_after: String,
    pub operator_principal: String,
    pub signature: GrantSignature,
}

/// Grant signature (Ed25519, in-process for DR-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSignature {
    pub algorithm: String, // "Ed25519"
    pub fingerprint: String,
    pub value: String, // base64
}

/// AuthorityRevoke (DR-14, DR-06 §6.22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRevoke {
    pub session_id: SessionId,
    pub grant_id: GrantId,
    pub reason_class: String, // UserRevoke | EmergencyRevoked | Expired | KernelDenied
    pub revoked_by: String,
}

/// SessionStart / SessionEnd / PhaseTransition (DR-06 §6.1-6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStart {
    pub session_id: SessionId,
    pub restricted: bool,
    pub pib_id: Option<String>,
    pub policy_snapshot_id: String,
    pub operator_principal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    pub session_id: SessionId,
    pub terminal: TerminalOutcome,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTransition {
    pub session_id: SessionId,
    pub from: Phase,
    pub to: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,
}

/// SegmentHeader — first record of each segment (DR-06 §1.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentHeader {
    pub v: String, // "ledger/segment-header/v1"
    pub segment_ordinal: u64,
    pub wall_clock_open_ms: i64,
    pub writer_id: String,
    pub writer_version: String,
    pub ledger_hash_prev: String,
}

/// The full event taxonomy (DR-06 §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "variant", rename_all = "snake_case")]
pub enum LedgerEvent {
    SegmentHeader(SegmentHeader),
    SessionStart(SessionStart),
    SessionEnd(SessionEnd),
    PhaseTransition(PhaseTransition),
    EgressIntent(EgressIntent),
    SubagentCall(SubagentCall),
    Refused(Refused),
    AuthorityGrant(AuthorityGrant),
    AuthorityRevoke(AuthorityRevoke),
}

/// The hash-chained on-disk record (DR-06 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub v: String, // "ledger/record/v1"
    pub event: LedgerEvent,
    pub ledger_hash_prev: String,
    /// `signature` is `null` for ordinary records (v0.1 out-of-tree) — omitted.
    /// On AuthorityGrant it is carried inside `event`. We keep the field off
    /// the generic record: DR-06 §2.1 forbids `null`; the grant signature
    /// lives in the event payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger_hash_self: Option<String>,
}

impl LedgerRecord {
    /// Compute the self-hash over (event + prev), omitting `ledger_hash_self`.
    pub fn compute_self_hash(&self) -> Result<String, canonical::CanonicalError> {
        let digest_form = LedgerRecordDigest {
            v: self.v.clone(),
            event: self.event.clone(),
            ledger_hash_prev: self.ledger_hash_prev.clone(),
        };
        canonical::sha256_hex(&digest_form)
    }

    /// Build a record with `ledger_hash_self` filled.
    pub fn finalized(mut self) -> Result<Self, canonical::CanonicalError> {
        let h = self.compute_self_hash()?;
        self.ledger_hash_self = Some(h);
        Ok(self)
    }
}

/// The exact shape hashed for `ledger_hash_self` (no self_hash, no signature).
#[derive(Serialize)]
struct LedgerRecordDigest {
    v: String,
    event: LedgerEvent,
    ledger_hash_prev: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_self_hash_deterministic_and_chainable() {
        let ev = LedgerEvent::PhaseTransition(PhaseTransition {
            session_id: "01J-test".into(),
            from: Phase::Init,
            to: Phase::Plan,
            checkpoint_seq: None,
        });
        let r = LedgerRecord {
            v: "ledger/record/v1".into(),
            event: ev,
            ledger_hash_prev: "0".repeat(64),
            ledger_hash_self: None,
        };
        let h1 = r.compute_self_hash().unwrap();
        let h2 = r.compute_self_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);

        // chained: next record's prev == this self hash
        let next = LedgerRecord {
            v: "ledger/record/v1".into(),
            event: LedgerEvent::SessionEnd(SessionEnd {
                session_id: "01J-test".into(),
                terminal: TerminalOutcome::Completed,
                reason: "done".into(),
            }),
            ledger_hash_prev: h1.clone(),
            ledger_hash_self: None,
        };
        let next_h = next.compute_self_hash().unwrap();
        assert_ne!(h1, next_h);
        let _ = next_h;
    }

    #[test]
    fn authority_grant_requires_signature_field_present() {
        let g = AuthorityGrant {
            session_id: "s".into(),
            grant_id: "g".into(),
            intent_digest: "a".repeat(64),
            diff_hash: "b".repeat(64),
            risk_hash: None,
            policy_snapshot_id_before: "c".into(),
            policy_snapshot_id_after: "d".into(),
            operator_principal: "uid=1000".into(),
            signature: GrantSignature {
                algorithm: "Ed25519".into(),
                fingerprint: "f".into(),
                value: "v".into(),
            },
        };
        let b = canonical::canonical_bytes(&g).unwrap();
        assert!(!b.is_empty());
        // signature must be present in canonical output (not omitted)
        let s = String::from_utf8(b).unwrap();
        assert!(s.contains("Ed25519"));
    }
}
