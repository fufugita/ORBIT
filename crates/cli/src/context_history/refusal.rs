//! Strict private snapshot codec. These records confer no live retry authority.

use super::{Budget, HistoryError, Intent, Purpose, Reference, encode};
use orbit_engine::compaction::AttemptIntent;
use orbit_engine::retry::{
    MAX_ATTEMPT_BINDING_RECORD_BYTES, MAX_REFUSAL_RECORD_BYTES, MAX_REFUSAL_ROLLUP_BYTES,
    OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    request_id: String,
    decision_id: String,
    attempt_id: String,
    provider_digest: String,
    model_digest: String,
    route_digest: String,
    body_digest: String,
    adapter_identity_sha256: String,
    policy_digest: String,
    digest: String,
}
impl Binding {
    pub(super) fn from_public(value: &OrdinaryAttemptBindingRecord) -> Self {
        Self {
            request_id: value.request_id().into(),
            decision_id: value.decision_id().into(),
            attempt_id: value.attempt_id().into(),
            provider_digest: value.provider_digest().into(),
            model_digest: value.model_digest().into(),
            route_digest: value.route_digest().into(),
            body_digest: value.body_digest().into(),
            adapter_identity_sha256: value.adapter_identity_sha256().into(),
            policy_digest: value.policy_digest().into(),
            digest: value.digest().into(),
        }
    }
    pub(super) fn to_public(&self) -> Result<OrdinaryAttemptBindingRecord, HistoryError> {
        encode(
            self,
            MAX_ATTEMPT_BINDING_RECORD_BYTES,
            HistoryError::InvalidRecord,
        )?;
        OrdinaryAttemptBindingRecord::from_parts(
            self.request_id.clone(),
            self.decision_id.clone(),
            self.attempt_id.clone(),
            self.provider_digest.clone(),
            self.model_digest.clone(),
            self.route_digest.clone(),
            self.body_digest.clone(),
            self.adapter_identity_sha256.clone(),
            self.policy_digest.clone(),
            self.digest.clone(),
        )
    }
    fn maximum() -> Self {
        Self {
            request_id: "r".repeat(256),
            decision_id: "d".repeat(256),
            attempt_id: "a".repeat(256),
            provider_digest: "f".repeat(64),
            model_digest: "f".repeat(64),
            route_digest: "f".repeat(64),
            body_digest: "f".repeat(64),
            adapter_identity_sha256: "f".repeat(64),
            policy_digest: "f".repeat(64),
            digest: "f".repeat(64),
        }
    }
}

// New proof metadata uses the U2 metadata key shape, rather than changing the
// established short-key Intent codec used by all legacy pending entries.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordIntent {
    owner_session_id: String,
    child_id: Option<String>,
    request_id: String,
    purpose: Purpose,
    budget: Budget,
}
impl RecordIntent {
    fn from_public(value: &AttemptIntent) -> Self {
        Self {
            owner_session_id: value.owner_session_id.clone(),
            child_id: value.child_id.clone(),
            request_id: value.request_id.clone(),
            purpose: Purpose::from_public(value.purpose),
            budget: Budget::from_public(&value.budget),
        }
    }
    fn to_public(&self) -> AttemptIntent {
        Intent {
            owner: self.owner_session_id.clone(),
            child: self.child_id.clone(),
            request_id: self.request_id.clone(),
            purpose: self.purpose,
            budget: self.budget.clone(),
        }
        .to_public()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    intent: RecordIntent,
    attempt: Reference,
    binding: Binding,
    observation_digest: String,
    status: u16,
    response_body_bytes: u32,
    digest: String,
}
impl Record {
    pub(super) fn from_public(value: &RefusalRecord) -> Self {
        Self {
            intent: RecordIntent::from_public(value.intent()),
            attempt: Reference::from_public(value.attempt()),
            binding: Binding::from_public(value.binding()),
            observation_digest: value.observation_digest().into(),
            status: value.status(),
            response_body_bytes: value.response_body_bytes(),
            digest: value.digest().into(),
        }
    }
    pub(super) fn to_public(&self) -> Result<RefusalRecord, HistoryError> {
        encode(self, MAX_REFUSAL_RECORD_BYTES, HistoryError::InvalidRecord)?;
        RefusalRecord::from_parts(
            self.intent.to_public(),
            self.attempt.to_public(),
            self.binding.to_public()?,
            self.observation_digest.clone(),
            self.status,
            self.response_body_bytes,
            self.digest.clone(),
        )
    }
    /// Size-only synthetic maximum. Never validate, persist or expose this as evidence.
    fn maximum() -> Self {
        Self {
            intent: RecordIntent {
                owner_session_id: "o".repeat(128),
                child_id: Some("0".repeat(26)),
                request_id: "r".repeat(256),
                purpose: Purpose::Ordinary,
                budget: Budget {
                    binding_digest: "f".repeat(64),
                    metadata_revision: "\\".repeat(256),
                    policy_revision: "\\".repeat(256),
                },
            },
            attempt: Reference {
                revision: u64::MAX,
                request_id: "r".repeat(256),
                intent_digest: "f".repeat(64),
            },
            binding: Binding::maximum(),
            observation_digest: "f".repeat(64),
            status: 529,
            response_body_bytes: 65_536,
            digest: "f".repeat(64),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rollup {
    count: u64,
    chain_digest: String,
    previous_chain_digest: String,
    latest: Record,
}
impl Rollup {
    pub(super) fn from_public(value: &RefusalRollup) -> Self {
        Self {
            count: value.count(),
            chain_digest: value.chain_digest().into(),
            previous_chain_digest: value.previous_chain_digest().into(),
            latest: Record::from_public(value.latest()),
        }
    }
    pub(super) fn to_public(&self) -> Result<RefusalRollup, HistoryError> {
        encode(self, MAX_REFUSAL_ROLLUP_BYTES, HistoryError::InvalidRecord)?;
        let checked = RefusalRollup::from_parts(
            self.count,
            self.chain_digest.clone(),
            self.previous_chain_digest.clone(),
            self.latest.to_public()?,
        )?;
        // The private shape has exactly the bounded public metadata fields; it
        // cannot retain unchecked extensions through a successful conversion.
        let canonical = Self::from_public(&checked);
        if encode(self, MAX_REFUSAL_ROLLUP_BYTES, HistoryError::InvalidRecord)?
            != encode(
                &canonical,
                MAX_REFUSAL_ROLLUP_BYTES,
                HistoryError::InvalidRecord,
            )?
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(checked)
    }
    fn maximum(latest: Record) -> Self {
        Self {
            count: u64::MAX,
            chain_digest: "f".repeat(64),
            previous_chain_digest: "f".repeat(64),
            latest,
        }
    }
}

/// A length reservation, not a decoded record or an authority-bearing object.
/// All synthesized DTOs stay local and are never validated, persisted or returned.
pub(super) fn maximum_entry_size(
    entry: &super::Entry,
    maximum: usize,
) -> Result<usize, HistoryError> {
    let mut future = entry.clone();
    let record = Record::maximum();
    future.pending = None;
    future.last = Some(super::Settlement {
        reference: Reference {
            revision: u64::MAX,
            request_id: "r".repeat(256),
            intent_digest: "f".repeat(64),
        },
        receipt: None,
        refused: Some(record.clone()),
    });
    future.refusals = Some(Rollup::maximum(record));
    Ok(encode(&future, maximum, HistoryError::Full)?.len())
}
