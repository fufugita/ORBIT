//! Explicit ordinary-request refusal assumptions and checked accounting metadata.
//!
//! Transport facts, an operator policy, and a durable acknowledgement are
//! independent. Checked snapshot records confer none of the live authorities.

use crate::compaction::{
    AccountingBaseline, AccountingCheckpoint, AccountingDelta, AccountingKnownness,
    AccountingRevision, AttemptIntent, AttemptPurpose, AttemptRef, HistoryError,
    KnownPricedSubtotals, PendingAttempt, SettledAttempt,
};
use crate::dispatch::{ProviderKind, TurnConfig, request_preparation_context};
use orbit_adapter::types::{AdapterIdentity, AdapterKind, ProviderRequest};
use orbit_provider_http::adapter_trait::{HttpRejectionObservation, RequestFingerprint};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_REFUSAL_RECORD_BYTES: usize = 4096;
pub const MAX_ATTEMPT_BINDING_RECORD_BYTES: usize = 2048;
pub const MAX_REFUSAL_ROLLUP_BYTES: usize = 4608;
const POLICY_DOMAIN: &[u8] = b"orbit-final-rejection-policy-v1\0";
const BINDING_DOMAIN: &[u8] = b"orbit-ordinary-attempt-binding-v1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"orbit-refused-ordinary-settlement-v1\0";
const CHAIN_DOMAIN: &[u8] = b"orbit-refused-ordinary-chain-v1\0";
const STATUSES: &[u16] = &[429, 500, 502, 503, 504, 529];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicyError {
    InvalidDeclaration,
    UnsupportedContract,
    UnsupportedAdapter,
    SelectionMismatch,
    InvalidSelection,
}
impl fmt::Display for RetryPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDeclaration => "final-rejection policy declaration is invalid",
            Self::UnsupportedContract => "final-rejection policy contract is unsupported",
            Self::UnsupportedAdapter => {
                "final-rejection policy requires the OpenAI-compatible adapter"
            }
            Self::SelectionMismatch => {
                "final-rejection policy does not match the selected provider"
            }
            Self::InvalidSelection => {
                "selected provider cannot be bound to a final-rejection policy"
            }
        })
    }
}
impl std::error::Error for RetryPolicyError {}

/// Complete exact selector. The endpoint is private and excluded from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct FinalRejectionSelector {
    provider: String,
    model: String,
    endpoint: String,
    adapter_identity_sha256: String,
}
impl FinalRejectionSelector {
    pub fn new(
        provider: String,
        model: String,
        endpoint: String,
        adapter_identity_sha256: String,
    ) -> Result<Self, RetryPolicyError> {
        if !bounded_text(&provider, 128)
            || !bounded_text(&model, 256)
            || !bounded_text(&endpoint, 2048)
            || !valid_digest(&adapter_identity_sha256)
            || orbit_provider_http::endpoint::validate_provider_url(&endpoint).is_err()
        {
            return Err(RetryPolicyError::InvalidDeclaration);
        }
        Ok(Self {
            provider,
            model,
            endpoint,
            adapter_identity_sha256,
        })
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    /// Effective OpenAI-compatible method URL, independent of policy activation.
    /// This performs the same pure route preparation as a selected request.
    pub fn canonical_endpoint(&self) -> Result<String, RetryPolicyError> {
        let config = TurnConfig {
            provider_id: self.provider.clone(),
            gate: self.endpoint.clone(),
            model: self.model.clone(),
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            billing: None,
            pricing: None,
            max_output_tokens: 1,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        let context = request_preparation_context(&config, None, &[])
            .map_err(|_| RetryPolicyError::InvalidDeclaration)?;
        method_url(context.route()).map_err(|_| RetryPolicyError::InvalidDeclaration)
    }
    pub fn adapter_identity_sha256(&self) -> &str {
        &self.adapter_identity_sha256
    }
}
impl fmt::Debug for FinalRejectionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalRejectionSelector")
            .field("adapter_identity_sha256", &self.adapter_identity_sha256)
            .finish_non_exhaustive()
    }
}

/// The only supported declaration: final generation refusal with unknown bill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalRejectionContract(());
impl FinalRejectionContract {
    pub fn new(
        scope: &str,
        generation: &str,
        billing: &str,
        allow_uncapped_retry: bool,
    ) -> Result<Self, RetryPolicyError> {
        if scope != "ordinary"
            || generation != "final_rejection"
            || billing != "unknown"
            || !allow_uncapped_retry
        {
            return Err(RetryPolicyError::UnsupportedContract);
        }
        Ok(Self(()))
    }
    pub fn scope(&self) -> &'static str {
        "ordinary"
    }
    pub fn generation(&self) -> &'static str {
        "final_rejection"
    }
    pub fn billing(&self) -> &'static str {
        "unknown"
    }
    pub fn allow_uncapped_retry(&self) -> bool {
        true
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FinalRejectionPolicy {
    id: String,
    selector: FinalRejectionSelector,
    statuses: Vec<u16>,
    contract: FinalRejectionContract,
    max_attempts: u32,
    digest: String,
}
impl FinalRejectionPolicy {
    pub fn new(
        id: String,
        selector: FinalRejectionSelector,
        statuses: Vec<u16>,
        contract: FinalRejectionContract,
        max_attempts: u32,
    ) -> Result<Self, RetryPolicyError> {
        if !valid_id(&id, 128)
            || !(2..=8).contains(&max_attempts)
            || statuses.is_empty()
            || statuses.len() > STATUSES.len()
            || !statuses.windows(2).all(|pair| pair[0] < pair[1])
            || statuses.iter().any(|status| !STATUSES.contains(status))
        {
            return Err(RetryPolicyError::InvalidDeclaration);
        }
        let mut hash = Fields::new(POLICY_DOMAIN);
        hash.number(1)
            .text(&id)
            .text(&selector.provider)
            .text(&selector.model)
            .text(&selector.endpoint)
            .text(&selector.adapter_identity_sha256)
            .number(statuses.len() as u64);
        for status in &statuses {
            hash.number(u64::from(*status));
        }
        hash.text(contract.scope())
            .text(contract.generation())
            .text(contract.billing())
            .number(u64::from(contract.allow_uncapped_retry()))
            .number(u64::from(max_attempts));
        Ok(Self {
            id,
            selector,
            statuses,
            contract,
            max_attempts,
            digest: hash.finish(),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn selector(&self) -> &FinalRejectionSelector {
        &self.selector
    }
    pub fn statuses(&self) -> &[u16] {
        &self.statuses
    }
    pub fn contract(&self) -> FinalRejectionContract {
        self.contract
    }
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
impl fmt::Debug for FinalRejectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalRejectionPolicy")
            .field("digest", &self.digest)
            .field("statuses", &self.statuses)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

/// Hashes all opaque identity fields. Their values need not themselves be hex.
pub fn adapter_identity_digest(identity: &AdapterIdentity) -> String {
    let mut hash = Fields::new(b"orbit-retry-adapter-identity-v1\0");
    let kind = match identity.kind {
        AdapterKind::OpenAiCompatibleHttpV1 => "OpenAiCompatibleHttpV1",
        AdapterKind::DeclarativeHttpJsonV1 => "DeclarativeHttpJsonV1",
        AdapterKind::LocalProcessV1 => "LocalProcessV1",
        AdapterKind::DeterministicTestV1 => "DeterministicTestV1",
        AdapterKind::MockHttpV1 => "MockHttpV1",
    };
    hash.text(kind)
        .text(&identity.implementation_digest.0)
        .text(&identity.profile_digest.0);
    hash.finish()
}

/// Frozen selected declaration. Constructing it performs no I/O or dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct RetryPolicyBinding {
    policy: FinalRejectionPolicy,
    selection_digest: String,
    provider_digest: String,
    model_digest: String,
    identity_digest: String,
}
impl RetryPolicyBinding {
    pub fn for_config(
        config: &TurnConfig,
        declaration: FinalRejectionPolicy,
    ) -> Result<Self, RetryPolicyError> {
        if config.kind != ProviderKind::OpenAiCompatible {
            return Err(RetryPolicyError::UnsupportedAdapter);
        }
        let identity_digest =
            adapter_identity_digest(&orbit_provider_http::openai::openai_identity());
        if config.provider_id != declaration.selector.provider
            || config.model != declaration.selector.model
            || identity_digest != declaration.selector.adapter_identity_sha256
        {
            return Err(RetryPolicyError::SelectionMismatch);
        }
        let selected = request_preparation_context(config, None, &[])
            .map_err(|_| RetryPolicyError::InvalidSelection)?;
        let selected_url = method_url(selected.route())?;
        if selected_url != declaration.selector.canonical_endpoint()? {
            return Err(RetryPolicyError::SelectionMismatch);
        }
        let mut selection = Fields::new(b"orbit-retry-selection-v1\0");
        selection
            .text(&config.provider_id)
            .text(&config.model)
            .text(&selected_url)
            .text(&identity_digest);
        Ok(Self {
            provider_digest: text_digest(b"orbit-retry-provider-id-v1\0", &config.provider_id),
            model_digest: text_digest(b"orbit-retry-model-id-v1\0", &config.model),
            policy: declaration,
            selection_digest: selection.finish(),
            identity_digest,
        })
    }
    pub fn policy_digest(&self) -> &str {
        self.policy.digest()
    }
    pub fn selection_digest(&self) -> &str {
        &self.selection_digest
    }
    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }
    pub fn model_digest(&self) -> &str {
        &self.model_digest
    }
    pub fn adapter_identity_sha256(&self) -> &str {
        &self.identity_digest
    }
    pub fn statuses(&self) -> &[u16] {
        self.policy.statuses()
    }
    pub fn max_attempts(&self) -> u32 {
        self.policy.max_attempts()
    }
}
impl fmt::Debug for RetryPolicyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryPolicyBinding")
            .field("policy_digest", &self.policy_digest())
            .field("selection_digest", &self.selection_digest)
            .field("statuses", &self.statuses())
            .finish()
    }
}
fn method_url(
    route: &orbit_adapter::types::ProviderRouteBinding,
) -> Result<String, RetryPolicyError> {
    orbit_provider_http::endpoint::provider_method_url(route, "/v1", "chat/completions")
        .map_err(|_| RetryPolicyError::InvalidSelection)
}

/// Shape-checked, nonauthoritative snapshot. It cannot become a live binding.
#[derive(Clone, PartialEq, Eq)]
pub struct OrdinaryAttemptBindingRecord {
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
impl OrdinaryAttemptBindingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: String,
        decision_id: String,
        attempt_id: String,
        provider_digest: String,
        model_digest: String,
        route_digest: String,
        body_digest: String,
        adapter_identity_sha256: String,
        policy_digest: String,
    ) -> Result<Self, HistoryError> {
        let mut value = Self {
            request_id,
            decision_id,
            attempt_id,
            provider_digest,
            model_digest,
            route_digest,
            body_digest,
            adapter_identity_sha256,
            policy_digest,
            digest: String::new(),
        };
        value.validate_fields()?;
        value.digest = value.compute_digest();
        bounded_json(&value.metadata(), MAX_ATTEMPT_BINDING_RECORD_BYTES)?;
        Ok(value)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
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
    ) -> Result<Self, HistoryError> {
        let result = Self::new(
            request_id,
            decision_id,
            attempt_id,
            provider_digest,
            model_digest,
            route_digest,
            body_digest,
            adapter_identity_sha256,
            policy_digest,
        )?;
        if !valid_digest(&digest) || result.digest != digest {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.validate_fields()?;
        if !valid_digest(&self.digest) || self.compute_digest() != self.digest {
            return Err(HistoryError::InvalidRecord);
        }
        bounded_json(&self.metadata(), MAX_ATTEMPT_BINDING_RECORD_BYTES)
    }
    fn validate_fields(&self) -> Result<(), HistoryError> {
        if ![&self.request_id, &self.decision_id, &self.attempt_id]
            .iter()
            .all(|id| valid_id(id, 256))
            || ![
                &self.provider_digest,
                &self.model_digest,
                &self.route_digest,
                &self.body_digest,
                &self.adapter_identity_sha256,
                &self.policy_digest,
            ]
            .iter()
            .all(|value| valid_digest(value))
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(())
    }
    fn compute_digest(&self) -> String {
        let mut hash = Fields::new(BINDING_DOMAIN);
        hash.text(&self.request_id)
            .text(&self.decision_id)
            .text(&self.attempt_id)
            .text(&self.provider_digest)
            .text(&self.model_digest)
            .text(&self.route_digest)
            .text(&self.body_digest)
            .text(&self.adapter_identity_sha256)
            .text(&self.policy_digest);
        hash.finish()
    }
    fn metadata(&self) -> serde_json::Value {
        serde_json::json!({"request_id":self.request_id,"decision_id":self.decision_id,
            "attempt_id":self.attempt_id,"provider_digest":self.provider_digest,
            "model_digest":self.model_digest,"route_digest":self.route_digest,"body_digest":self.body_digest,
            "adapter_identity_sha256":self.adapter_identity_sha256,"policy_digest":self.policy_digest,
            "digest":self.digest})
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }
    pub fn model_digest(&self) -> &str {
        &self.model_digest
    }
    pub fn route_digest(&self) -> &str {
        &self.route_digest
    }
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
    pub fn adapter_identity_sha256(&self) -> &str {
        &self.adapter_identity_sha256
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
impl fmt::Debug for OrdinaryAttemptBindingRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrdinaryAttemptBindingRecord")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Engine-created request binding. There is deliberately no record-to-live API.
///
/// ```compile_fail
/// use orbit_engine::retry::{OrdinaryAttemptBinding, OrdinaryAttemptBindingRecord};
/// fn upgrade(record: OrdinaryAttemptBindingRecord) -> OrdinaryAttemptBinding { record.into() }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct OrdinaryAttemptBinding {
    record: OrdinaryAttemptBindingRecord,
    fingerprint: RequestFingerprint,
    selection_digest: String,
}
impl OrdinaryAttemptBinding {
    pub(crate) fn for_request(
        request: &ProviderRequest,
        identity: &AdapterIdentity,
        policy: &RetryPolicyBinding,
    ) -> Result<Self, HistoryError> {
        let fingerprint = RequestFingerprint::for_request(request, identity)
            .map_err(|_| HistoryError::InvalidRecord)?;
        let identity_digest = adapter_identity_digest(identity);
        let provider_digest = text_digest(
            b"orbit-retry-provider-id-v1\0",
            &request.route.provider_id.0,
        );
        let model_digest = text_digest(b"orbit-retry-model-id-v1\0", &request.route.expected_model);
        let mut selection = Fields::new(b"orbit-retry-selection-v1\0");
        let url = method_url(&request.route).map_err(|_| HistoryError::InvalidRecord)?;
        selection
            .text(&request.route.provider_id.0)
            .text(&request.route.expected_model)
            .text(&url)
            .text(&identity_digest);
        if identity_digest != policy.identity_digest
            || provider_digest != policy.provider_digest
            || model_digest != policy.model_digest
            || selection.finish() != policy.selection_digest
        {
            return Err(HistoryError::InvalidRecord);
        }
        let record = OrdinaryAttemptBindingRecord::new(
            fingerprint.request_id().into(),
            fingerprint.decision_id().into(),
            fingerprint.attempt_id().into(),
            provider_digest,
            model_digest,
            fingerprint.route_digest().into(),
            fingerprint.body_digest().into(),
            identity_digest,
            policy.policy_digest().into(),
        )?;
        Ok(Self {
            record,
            fingerprint,
            selection_digest: policy.selection_digest.clone(),
        })
    }
    pub fn to_record(&self) -> OrdinaryAttemptBindingRecord {
        self.record.clone()
    }
    pub fn digest(&self) -> &str {
        self.record.digest()
    }
}
impl fmt::Debug for OrdinaryAttemptBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrdinaryAttemptBinding")
            .field("digest", &self.digest())
            .finish()
    }
}

/// Engine-only facts observed during the actual attempt. No external caller can
/// set these flags to create a trusted settlement.
#[derive(Default)]
pub(crate) struct RefusalEligibility {
    pub(crate) text_observed: bool,
    pub(crate) tool_observed: bool,
    pub(crate) usage_observed: bool,
    pub(crate) terminal_observed: bool,
    pub(crate) cancelled: bool,
    pub(crate) spend_capped: bool,
}
impl RefusalEligibility {
    fn is_eligible(&self) -> bool {
        !self.text_observed
            && !self.tool_observed
            && !self.usage_observed
            && !self.terminal_observed
            && !self.cancelled
            && !self.spend_capped
    }
}

/// Live settlement issued only after engine comparison of actual transport
/// facts. No Deserialize or public constructor can reconstruct this authority.
///
/// ```compile_fail
/// use orbit_engine::retry::{RefusalRecord, RefusedOrdinarySettlement};
/// fn upgrade(record: RefusalRecord) -> RefusedOrdinarySettlement { record.into() }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RefusedOrdinarySettlement {
    record: RefusalRecord,
}
impl RefusedOrdinarySettlement {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_rejection(
        intent: &AttemptIntent,
        attempt: &AttemptRef,
        binding: &OrdinaryAttemptBinding,
        policy: &RetryPolicyBinding,
        request: &ProviderRequest,
        observation: &HttpRejectionObservation,
        eligibility: &RefusalEligibility,
    ) -> Result<Self, HistoryError> {
        if !eligibility.is_eligible()
            || intent.purpose != AttemptPurpose::Ordinary
            || binding.selection_digest != policy.selection_digest
            || binding.record.policy_digest != policy.policy_digest()
            || !policy.statuses().contains(&observation.status())
            || !observation
                .matches_request(request, &orbit_provider_http::openai::openai_identity())
            || !observation.matches_request(request, binding.fingerprint.adapter_identity())
            || RequestFingerprint::for_request(request, binding.fingerprint.adapter_identity())
                .map_err(|_| HistoryError::InvalidRecord)?
                != binding.fingerprint
            || observation.request_id() != binding.record.request_id
            || observation.decision_id() != binding.record.decision_id
            || observation.attempt_id() != binding.record.attempt_id
            || observation.route_digest() != binding.record.route_digest
            || observation.body_digest() != binding.record.body_digest
            || adapter_identity_digest(observation.adapter_identity())
                != binding.record.adapter_identity_sha256
        {
            return Err(HistoryError::InvalidRecord);
        }
        let record = RefusalRecord::new(
            intent.clone(),
            attempt.clone(),
            binding.to_record(),
            observation.observation_digest().into(),
            observation.status(),
            observation.response_body_bytes(),
        )?;
        Ok(Self { record })
    }
    pub fn to_record(&self) -> RefusalRecord {
        self.record.clone()
    }
    pub fn intent(&self) -> &AttemptIntent {
        self.record.intent()
    }
    pub fn attempt(&self) -> &AttemptRef {
        self.record.attempt()
    }
    pub fn binding(&self) -> &OrdinaryAttemptBindingRecord {
        self.record.binding()
    }
    pub fn observation_digest(&self) -> &str {
        self.record.observation_digest()
    }
    pub fn policy_digest(&self) -> &str {
        self.record.binding.policy_digest()
    }
    pub fn digest(&self) -> &str {
        self.record.digest()
    }
}
impl fmt::Debug for RefusedOrdinarySettlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefusedOrdinarySettlement")
            .field("digest", &self.digest())
            .finish()
    }
}

/// Untrusted stored metadata, even after shape/digest validation. No provider
/// usage or cost claim is accepted: this disposition always has an unknown bill.
#[derive(Clone, PartialEq, Eq)]
pub struct RefusalRecord {
    intent: Box<AttemptIntent>,
    attempt: AttemptRef,
    binding: Box<OrdinaryAttemptBindingRecord>,
    observation_digest: String,
    status: u16,
    response_body_bytes: u32,
    digest: String,
}
impl RefusalRecord {
    pub fn new(
        intent: AttemptIntent,
        attempt: AttemptRef,
        binding: OrdinaryAttemptBindingRecord,
        observation_digest: String,
        status: u16,
        response_body_bytes: u32,
    ) -> Result<Self, HistoryError> {
        let mut result = Self {
            intent: Box::new(intent),
            attempt,
            binding: Box::new(binding),
            observation_digest,
            status,
            response_body_bytes,
            digest: String::new(),
        };
        result.validate_fields()?;
        result.digest = result.compute_digest()?;
        bounded_json(&result.metadata(), MAX_REFUSAL_RECORD_BYTES)?;
        Ok(result)
    }
    pub fn from_parts(
        intent: AttemptIntent,
        attempt: AttemptRef,
        binding: OrdinaryAttemptBindingRecord,
        observation_digest: String,
        status: u16,
        response_body_bytes: u32,
        digest: String,
    ) -> Result<Self, HistoryError> {
        let result = Self::new(
            intent,
            attempt,
            binding,
            observation_digest,
            status,
            response_body_bytes,
        )?;
        if !valid_digest(&digest) || digest != result.digest {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.validate_fields()?;
        if !valid_digest(&self.digest) || self.digest != self.compute_digest()? {
            return Err(HistoryError::InvalidRecord);
        }
        bounded_json(&self.metadata(), MAX_REFUSAL_RECORD_BYTES)
    }
    fn validate_fields(&self) -> Result<(), HistoryError> {
        self.binding.validate()?;
        validate_reference(&self.attempt)?;
        if self.intent.purpose != AttemptPurpose::Ordinary
            || self.intent.digest()? != self.attempt.intent_digest
            || self.intent.request_id != self.attempt.request_id
            || self.binding.request_id != self.attempt.request_id
            || !STATUSES.contains(&self.status)
            || self.response_body_bytes > 65_536
            || !valid_digest(&self.observation_digest)
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(())
    }
    fn compute_digest(&self) -> Result<String, HistoryError> {
        let mut hash = Fields::new(SETTLEMENT_DOMAIN);
        // Intent's unchanged digest binds owner, child, purpose and full budget.
        hash.text(&self.intent.digest()?)
            .number(self.attempt.revision.0)
            .text(&self.attempt.request_id)
            .text(&self.attempt.intent_digest)
            .text(self.binding.digest())
            .text(&self.observation_digest)
            .number(u64::from(self.status))
            .number(u64::from(self.response_body_bytes))
            .text(self.binding.policy_digest())
            .text("unknown")
            .text("absent");
        Ok(hash.finish())
    }
    fn metadata(&self) -> serde_json::Value {
        serde_json::json!({"intent":{"owner_session_id":self.intent.owner_session_id,
            "child_id":self.intent.child_id,"request_id":self.intent.request_id,
            "purpose":"ordinary","budget":{"binding_digest":self.intent.budget.binding_digest,
            "metadata_revision":self.intent.budget.metadata_revision,"policy_revision":self.intent.budget.policy_revision}},
            "attempt":{"revision":self.attempt.revision.0,"request_id":self.attempt.request_id,
            "intent_digest":self.attempt.intent_digest},"binding":self.binding.metadata(),
            "observation_digest":self.observation_digest,"status":self.status,
            "response_body_bytes":self.response_body_bytes,"digest":self.digest})
    }
    pub fn intent(&self) -> &AttemptIntent {
        &self.intent
    }
    pub fn attempt(&self) -> &AttemptRef {
        &self.attempt
    }
    pub fn binding(&self) -> &OrdinaryAttemptBindingRecord {
        &self.binding
    }
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn response_body_bytes(&self) -> u32 {
        self.response_body_bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Preserve measured counters and the known priced subset elsewhere. Zero
    /// contribution here means no observed usage, never zero provider usage.
    pub fn totals_after(&self, before: &AccountingDelta) -> AccountingDelta {
        let mut after = before.clone();
        after.ordinary.cost_microcents = None;
        if after.knownness == AccountingKnownness::Known {
            after.knownness = AccountingKnownness::UnknownUsage;
        }
        after
    }
}
impl fmt::Debug for RefusalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefusalRecord")
            .field("status", &self.status)
            .field("response_body_bytes", &self.response_body_bytes)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Bounded summary. Only the latest full record is retained; this does not
/// certify or reconstruct every earlier refusal.
#[derive(Clone, PartialEq, Eq)]
pub struct RefusalRollup {
    count: u64,
    chain_digest: String,
    previous_chain_digest: String,
    latest: RefusalRecord,
}
impl RefusalRollup {
    pub fn first(latest: RefusalRecord) -> Result<Self, HistoryError> {
        latest.validate()?;
        let previous = chain_seed(&latest);
        let head = chain_head(&previous, 1, latest.digest());
        Self::from_parts(1, head, previous, latest)
    }
    pub fn from_parts(
        count: u64,
        chain_digest: String,
        previous_chain_digest: String,
        latest: RefusalRecord,
    ) -> Result<Self, HistoryError> {
        let value = Self {
            count,
            chain_digest,
            previous_chain_digest,
            latest,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.latest.validate()?;
        if self.count == 0
            || !valid_digest(&self.chain_digest)
            || !valid_digest(&self.previous_chain_digest)
            || (self.count == 1 && self.previous_chain_digest != chain_seed(&self.latest))
            || self.chain_digest
                != chain_head(
                    &self.previous_chain_digest,
                    self.count,
                    self.latest.digest(),
                )
        {
            return Err(HistoryError::InvalidRecord);
        }
        bounded_json(
            &serde_json::json!({"count":self.count,"chain_digest":self.chain_digest,
            "previous_chain_digest":self.previous_chain_digest,"latest":self.latest.metadata()}),
            MAX_REFUSAL_ROLLUP_BYTES,
        )
    }
    pub fn appended(&self, latest: RefusalRecord) -> Result<Self, HistoryError> {
        self.validate()?;
        latest.validate()?;
        if latest == self.latest {
            return Ok(self.clone());
        }
        if !same_scope(self.latest.intent(), latest.intent())
            || latest.attempt.revision.0 <= self.latest.attempt.revision.0
        {
            return Err(HistoryError::Conflict);
        }
        let count = self.count.checked_add(1).ok_or(HistoryError::TooLarge)?;
        let head = chain_head(&self.chain_digest, count, latest.digest());
        Self::from_parts(count, head, self.chain_digest.clone(), latest)
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn chain_digest(&self) -> &str {
        &self.chain_digest
    }
    pub fn previous_chain_digest(&self) -> &str {
        &self.previous_chain_digest
    }
    pub fn latest(&self) -> &RefusalRecord {
        &self.latest
    }
}
impl fmt::Debug for RefusalRollup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefusalRollup")
            .field("count", &self.count)
            .field("chain_digest", &self.chain_digest)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedLastSettlement {
    Legacy(SettledAttempt),
    FinalRefusal(RefusalRecord),
}

#[derive(Clone, PartialEq, Eq)]
pub struct DetailedAccountingCheckpoint {
    owner_session_id: String,
    child_id: Option<String>,
    revision: AccountingRevision,
    baseline: AccountingBaseline,
    totals: AccountingDelta,
    pending: Option<PendingAttempt>,
    last_settlement: Option<DetailedLastSettlement>,
    known_priced_subtotals: Option<KnownPricedSubtotals>,
    refusals: Option<RefusalRollup>,
}
impl DetailedAccountingCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_session_id: String,
        child_id: Option<String>,
        revision: AccountingRevision,
        baseline: AccountingBaseline,
        totals: AccountingDelta,
        pending: Option<PendingAttempt>,
        last_settlement: Option<DetailedLastSettlement>,
        known_priced_subtotals: Option<KnownPricedSubtotals>,
        refusals: Option<RefusalRollup>,
    ) -> Result<Self, HistoryError> {
        let value = Self {
            owner_session_id,
            child_id,
            revision,
            baseline,
            totals,
            pending,
            last_settlement,
            known_priced_subtotals,
            refusals,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn from_legacy(value: AccountingCheckpoint) -> Result<Self, HistoryError> {
        Self::new(
            value.owner_session_id,
            value.child_id,
            value.revision,
            value.baseline,
            value.totals,
            value.pending,
            value.last_settlement.map(DetailedLastSettlement::Legacy),
            value.known_priced_subtotals,
            None,
        )
    }
    /// Older consumers explicitly reject any namespace carrying refusal data.
    pub fn to_legacy(&self) -> Result<AccountingCheckpoint, HistoryError> {
        self.validate()?;
        if self.refusals.is_some() {
            return Err(HistoryError::InvalidRecord);
        }
        let last_settlement = match &self.last_settlement {
            None => None,
            Some(DetailedLastSettlement::Legacy(last)) => Some(last.clone()),
            Some(DetailedLastSettlement::FinalRefusal(_)) => {
                return Err(HistoryError::InvalidRecord);
            }
        };
        Ok(AccountingCheckpoint {
            owner_session_id: self.owner_session_id.clone(),
            child_id: self.child_id.clone(),
            revision: self.revision,
            baseline: self.baseline,
            totals: self.totals.clone(),
            pending: self.pending.clone(),
            last_settlement,
            known_priced_subtotals: self.known_priced_subtotals,
        })
    }
    pub fn legacy_equivalent(&self, value: &AccountingCheckpoint) -> bool {
        self.to_legacy().is_ok_and(|legacy| legacy == *value)
    }
    pub fn validate(&self) -> Result<(), HistoryError> {
        if !valid_id(&self.owner_session_id, 128) || !valid_child(self.child_id.as_deref()) {
            return Err(HistoryError::InvalidRecord);
        }
        let costs = [
            self.totals.ordinary.cost_microcents,
            self.totals.housekeeping.cost_microcents,
        ];
        if (self.totals.knownness != AccountingKnownness::Known
            && costs.iter().all(Option::is_some))
            || (self.baseline == AccountingBaseline::UnknownLegacy
                && !matches!(
                    self.totals.knownness,
                    AccountingKnownness::UnknownLegacy | AccountingKnownness::Uncertain
                ))
            || (self.baseline == AccountingBaseline::FreshKnownZero
                && self.totals.knownness == AccountingKnownness::UnknownLegacy)
            || (self.totals.knownness == AccountingKnownness::Uncertain
                && self
                    .pending
                    .as_ref()
                    .is_none_or(|pending| !pending.uncertain))
        {
            return Err(HistoryError::InvalidRecord);
        }
        if self.revision.0 == 0 {
            let expected = match self.baseline {
                AccountingBaseline::FreshKnownZero => AccountingDelta::known_zero(),
                AccountingBaseline::UnknownLegacy => AccountingDelta::unknown_legacy(),
            };
            if self.totals != expected
                || self.pending.is_some()
                || self.last_settlement.is_some()
                || self.refusals.is_some()
            {
                return Err(HistoryError::InvalidRecord);
            }
        } else if self.pending.is_none() && self.last_settlement.is_none() {
            return Err(HistoryError::InvalidRecord);
        }
        if let Some(priced) = self.known_priced_subtotals
            && ((self.revision.0 == 0 && priced != KnownPricedSubtotals::known_zero())
                || self
                    .totals
                    .ordinary
                    .cost_microcents
                    .is_some_and(|total| priced.ordinary_microcents != total)
                || self
                    .totals
                    .housekeeping
                    .cost_microcents
                    .is_some_and(|total| priced.housekeeping_microcents != total))
        {
            return Err(HistoryError::InvalidRecord);
        }
        if let Some(pending) = &self.pending {
            validate_reference(&pending.reference)?;
            let after = pending
                .reference
                .revision
                .0
                .checked_add(1)
                .ok_or(HistoryError::InvalidRecord)?;
            if pending.intent.digest()? != pending.reference.intent_digest
                || pending.intent.request_id != pending.reference.request_id
                || pending.intent.owner_session_id != self.owner_session_id
                || pending.intent.child_id != self.child_id
                || (if pending.uncertain {
                    after
                } else {
                    pending.reference.revision.0
                }) != self.revision.0
                || (pending.uncertain && self.totals.knownness != AccountingKnownness::Uncertain)
            {
                return Err(HistoryError::InvalidRecord);
            }
        }
        if let Some(rollup) = &self.refusals {
            rollup.validate()?;
            let record = rollup.latest();
            if record.intent.owner_session_id != self.owner_session_id
                || record.intent.child_id != self.child_id
                || record.attempt.revision.0 >= self.revision.0
                || self.totals.ordinary.cost_microcents.is_some()
                || self.totals.knownness == AccountingKnownness::Known
                || self.last_settlement.is_none()
            {
                return Err(HistoryError::InvalidRecord);
            }
        }
        if let Some(last) = &self.last_settlement {
            let reference = match last {
                DetailedLastSettlement::Legacy(last) => {
                    if !valid_digest(&last.receipt_digest) {
                        return Err(HistoryError::InvalidRecord);
                    }
                    &last.reference
                }
                DetailedLastSettlement::FinalRefusal(record) => {
                    record.validate()?;
                    if self.refusals.as_ref().map(RefusalRollup::latest) != Some(record) {
                        return Err(HistoryError::InvalidRecord);
                    }
                    &record.attempt
                }
            };
            validate_reference(reference)?;
            if reference.revision.0 >= self.revision.0
                || self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| reference.revision.0 >= pending.reference.revision.0)
                || (self.pending.is_none()
                    && reference.revision.0.checked_add(1) != Some(self.revision.0))
                || self
                    .refusals
                    .as_ref()
                    .is_some_and(|rollup| rollup.latest.attempt.revision.0 > reference.revision.0)
            {
                return Err(HistoryError::InvalidRecord);
            }
        }
        Ok(())
    }
    pub fn owner_session_id(&self) -> &str {
        &self.owner_session_id
    }
    pub fn child_id(&self) -> Option<&str> {
        self.child_id.as_deref()
    }
    pub fn revision(&self) -> AccountingRevision {
        self.revision
    }
    pub fn baseline(&self) -> AccountingBaseline {
        self.baseline
    }
    pub fn totals(&self) -> &AccountingDelta {
        &self.totals
    }
    pub fn pending(&self) -> Option<&PendingAttempt> {
        self.pending.as_ref()
    }
    pub fn last_settlement(&self) -> Option<&DetailedLastSettlement> {
        self.last_settlement.as_ref()
    }
    pub fn known_priced_subtotals(&self) -> Option<KnownPricedSubtotals> {
        self.known_priced_subtotals
    }
    pub fn refusals(&self) -> Option<&RefusalRollup> {
        self.refusals.as_ref()
    }
}
impl fmt::Debug for DetailedAccountingCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetailedAccountingCheckpoint")
            .field("revision", &self.revision)
            .field("knownness", &self.totals.knownness)
            .field("has_pending", &self.pending.is_some())
            .field("refusals", &self.refusals)
            .finish_non_exhaustive()
    }
}

/// A checked store acknowledgement contains snapshot metadata only. Its
/// existence does not establish durability; the engine must compare it with
/// its held live settlement and the expected pre-attempt accounting state.
#[derive(Clone, PartialEq, Eq)]
pub struct RefusedSettlementAck {
    checkpoint: DetailedAccountingCheckpoint,
    attempt: AttemptRef,
    binding: OrdinaryAttemptBindingRecord,
    settlement_digest: String,
    observation_digest: String,
    policy_digest: String,
}
impl RefusedSettlementAck {
    pub fn new(
        checkpoint: DetailedAccountingCheckpoint,
        attempt: AttemptRef,
        binding: OrdinaryAttemptBindingRecord,
        settlement_digest: String,
        observation_digest: String,
        policy_digest: String,
    ) -> Result<Self, HistoryError> {
        checkpoint.validate()?;
        validate_reference(&attempt)?;
        binding.validate()?;
        let Some(DetailedLastSettlement::FinalRefusal(record)) = checkpoint.last_settlement()
        else {
            return Err(HistoryError::InvalidRecord);
        };
        if checkpoint.pending().is_some()
            || record.attempt() != &attempt
            || record.binding() != &binding
            || record.digest() != settlement_digest
            || record.observation_digest() != observation_digest
            || binding.policy_digest() != policy_digest
            || attempt.revision.0.checked_add(1) != Some(checkpoint.revision().0)
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(Self {
            checkpoint,
            attempt,
            binding,
            settlement_digest,
            observation_digest,
            policy_digest,
        })
    }
    /// `before` is the exact checkpoint held before begin, or the matching
    /// nonuncertain pending checkpoint after begin. No inert record enables replay.
    pub fn validate_for(
        &self,
        settlement: &RefusedOrdinarySettlement,
        before: &DetailedAccountingCheckpoint,
    ) -> Result<(), HistoryError> {
        before.validate()?;
        self.checkpoint.validate()?;
        let record = &settlement.record;
        let expected_rollup = match before.refusals() {
            Some(previous) => previous.appended(record.clone())?,
            None => RefusalRollup::first(record.clone())?,
        };
        let valid_before_revision = match before.pending() {
            Some(pending) => {
                !pending.uncertain
                    && pending.reference == self.attempt
                    && pending.intent == *record.intent()
                    && before.revision() == self.attempt.revision
            }
            None => before.revision().0.checked_add(1) == Some(self.attempt.revision.0),
        };
        if !valid_before_revision
            || self.attempt != *settlement.attempt()
            || self.binding != *settlement.binding()
            || self.settlement_digest != settlement.digest()
            || self.observation_digest != settlement.observation_digest()
            || self.policy_digest != settlement.policy_digest()
            || self.checkpoint.owner_session_id() != before.owner_session_id()
            || self.checkpoint.child_id() != before.child_id()
            || self.checkpoint.baseline() != before.baseline()
            || record.intent.owner_session_id != before.owner_session_id
            || record.intent.child_id != before.child_id
            || self.checkpoint.totals() != &record.totals_after(before.totals())
            || self.checkpoint.known_priced_subtotals() != before.known_priced_subtotals()
            || self.checkpoint.refusals() != Some(&expected_rollup)
            || self.checkpoint.last_settlement()
                != Some(&DetailedLastSettlement::FinalRefusal(record.clone()))
            || self.checkpoint.pending().is_some()
            || self.attempt.revision.0.checked_add(1) != Some(self.checkpoint.revision().0)
        {
            return Err(HistoryError::Conflict);
        }
        Ok(())
    }
    pub fn checkpoint(&self) -> &DetailedAccountingCheckpoint {
        &self.checkpoint
    }
    pub fn attempt(&self) -> &AttemptRef {
        &self.attempt
    }
    pub fn binding(&self) -> &OrdinaryAttemptBindingRecord {
        &self.binding
    }
    pub fn settlement_digest(&self) -> &str {
        &self.settlement_digest
    }
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}
impl fmt::Debug for RefusedSettlementAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefusedSettlementAck")
            .field("settlement_digest", &self.settlement_digest)
            .field("checkpoint_revision", &self.checkpoint.revision)
            .finish()
    }
}

fn same_scope(a: &AttemptIntent, b: &AttemptIntent) -> bool {
    a.owner_session_id == b.owner_session_id && a.child_id == b.child_id
}
fn chain_seed(record: &RefusalRecord) -> String {
    let mut hash = Fields::new(CHAIN_DOMAIN);
    hash.text("seed")
        .text(&record.intent.owner_session_id)
        .optional_text(record.intent.child_id.as_deref());
    hash.finish()
}
fn chain_head(previous: &str, count: u64, settlement: &str) -> String {
    let mut hash = Fields::new(CHAIN_DOMAIN);
    hash.text("link")
        .text(previous)
        .number(count)
        .text(settlement);
    hash.finish()
}
fn validate_reference(value: &AttemptRef) -> Result<(), HistoryError> {
    if value.revision.0 == 0
        || !valid_id(&value.request_id, 256)
        || !valid_digest(&value.intent_digest)
    {
        return Err(HistoryError::InvalidRecord);
    }
    Ok(())
}
fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn valid_child(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value.len() == 26 && ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
    })
}
fn bounded_json(value: &serde_json::Value, maximum: usize) -> Result<(), HistoryError> {
    let bytes = serde_json::to_vec(value).map_err(|_| HistoryError::InvalidRecord)?;
    if bytes.len() > maximum {
        return Err(HistoryError::TooLarge);
    }
    Ok(())
}
fn text_digest(domain: &[u8], text: &str) -> String {
    let mut hash = Fields::new(domain);
    hash.text(text);
    hash.finish()
}
/// Scalars are length-prefixed in a fixed field order. Numbers are big-endian
/// u64; their fixed eight-byte scalar is length-prefixed as well.
struct Fields(Sha256);
impl Fields {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        Self(hash)
    }
    fn text(&mut self, value: &str) -> &mut Self {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
        self
    }
    fn number(&mut self, value: u64) -> &mut Self {
        self.0.update(8u64.to_be_bytes());
        self.0.update(value.to_be_bytes());
        self
    }
    fn optional_text(&mut self, value: Option<&str>) -> &mut Self {
        self.number(u64::from(value.is_some()));
        if let Some(value) = value {
            self.text(value);
        }
        self
    }
    fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_budget::BudgetIdentity;
    use orbit_adapter::credential::SecretBytes;
    use orbit_adapter::types::{AttemptId, DecisionId, RequestId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config() -> TurnConfig {
        TurnConfig {
            provider_id: "fixture".into(),
            gate: "http://127.0.0.1:8123".into(),
            model: "model".into(),
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            billing: None,
            pricing: None,
            max_output_tokens: 32,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        }
    }
    #[test]
    fn canonical_selector_endpoint_uses_default_base_and_exact_raw_query() {
        let selector = |endpoint: &str| {
            FinalRejectionSelector::new(
                "fixture".into(),
                "model".into(),
                endpoint.into(),
                "a".repeat(64),
            )
            .unwrap()
        };
        for endpoint in [
            "https://example.invalid",
            "https://example.invalid/",
            "https://example.invalid/v1",
            "https://example.invalid/v1/",
            "https://example.invalid:443",
            "https://example.invalid:443/v1/",
        ] {
            assert_eq!(
                selector(endpoint).canonical_endpoint().unwrap(),
                "https://example.invalid:443/v1/chat/completions"
            );
        }
        assert_eq!(
            selector("http://127.0.0.1").canonical_endpoint().unwrap(),
            "http://127.0.0.1:80/v1/chat/completions"
        );
        let first = selector("https://example.invalid/tenant/v1?x=%2F&y=1")
            .canonical_endpoint()
            .unwrap();
        assert_eq!(
            first,
            "https://example.invalid:443/tenant/v1/chat/completions?x=%2F&y=1"
        );
        let nondefault = selector("https://example.invalid:8443/tenant/v1?x=%2F&y=1")
            .canonical_endpoint()
            .unwrap();
        assert_eq!(
            nondefault,
            "https://example.invalid:8443/tenant/v1/chat/completions?x=%2F&y=1"
        );
        assert_ne!(first, nondefault);
        assert_ne!(
            first,
            selector("https://example.invalid/tenant/v1?y=1&x=%2F")
                .canonical_endpoint()
                .unwrap()
        );
        assert_ne!(
            first,
            selector("https://example.invalid/tenant/v1?x=%2f&y=1")
                .canonical_endpoint()
                .unwrap()
        );
        assert_ne!(
            first,
            selector("https://example.invalid/other/v1?x=%2F&y=1")
                .canonical_endpoint()
                .unwrap()
        );
    }

    #[test]
    fn canonical_selector_keeps_stale_identity_inactive_and_matches_actual_selection() {
        let config = config();
        let identity = adapter_identity_digest(&orbit_provider_http::openai::openai_identity());
        let current = FinalRejectionSelector::new(
            config.provider_id.clone(),
            config.model.clone(),
            config.gate.clone(),
            identity.clone(),
        )
        .unwrap();
        let stale_identity = "a".repeat(64);
        let stale = FinalRejectionSelector::new(
            config.provider_id.clone(),
            config.model.clone(),
            config.gate.clone(),
            stale_identity.clone(),
        )
        .unwrap();
        assert_ne!(identity, stale.adapter_identity_sha256());
        assert_eq!(
            current.canonical_endpoint().unwrap(),
            stale.canonical_endpoint().unwrap()
        );
        assert_eq!(stale.adapter_identity_sha256(), stale_identity);
        let actual = request_preparation_context(&config, None, &[]).unwrap();
        assert_eq!(
            current.canonical_endpoint().unwrap(),
            method_url(actual.route()).unwrap()
        );
        for (selector, accepted) in [(current, true), (stale, false)] {
            let declaration = FinalRejectionPolicy::new(
                "canonical-selector".into(),
                selector,
                vec![503],
                FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true)
                    .unwrap(),
                2,
            )
            .unwrap();
            let result = RetryPolicyBinding::for_config(&config, declaration);
            if accepted {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err(), RetryPolicyError::SelectionMismatch);
            }
        }
    }

    fn policy(config: &TurnConfig) -> RetryPolicyBinding {
        RetryPolicyBinding::for_config(
            config,
            FinalRejectionPolicy::new(
                "fixture-policy".into(),
                FinalRejectionSelector::new(
                    config.provider_id.clone(),
                    config.model.clone(),
                    config.gate.clone(),
                    adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
                )
                .unwrap(),
                vec![500, 503],
                FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true)
                    .unwrap(),
                3,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn request(config: &TurnConfig) -> ProviderRequest {
        let context = request_preparation_context(config, None, &[]).unwrap();
        ProviderRequest {
            schema_version: 1,
            request_id: RequestId("request".into()),
            decision_id: DecisionId("decision".into()),
            attempt_id: AttemptId("attempt".into()),
            route: context.route().clone(),
            input: SecretBytes::new(b"private-prompt".to_vec()),
            messages: None,
            effort: None,
            sampling: orbit_adapter::types::SamplingParameters {
                temperature_milliunits: 0,
                top_p_millionths: 0,
                max_output_tokens: 32,
            },
            output: orbit_adapter::types::OutputRequirements::Text,
            tools: Vec::new(),
            metadata: Default::default(),
            connect_timeout_ms: 100,
            first_byte_timeout_ms: 100,
            idle_timeout_ms: 100,
        }
    }
    fn record(revision: u64, request: &str) -> RefusalRecord {
        let intent = AttemptIntent {
            owner_session_id: "owner".into(),
            child_id: None,
            request_id: request.into(),
            purpose: AttemptPurpose::Ordinary,
            budget: BudgetIdentity {
                binding_digest: "a".repeat(64),
                metadata_revision: "meta".into(),
                policy_revision: "budget".into(),
            },
        };
        let reference = AttemptRef {
            revision: AccountingRevision(revision),
            request_id: request.into(),
            intent_digest: intent.digest().unwrap(),
        };
        RefusalRecord::new(
            intent,
            reference,
            OrdinaryAttemptBindingRecord::new(
                request.into(),
                "decision".into(),
                "attempt".into(),
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
                "f".repeat(64),
            )
            .unwrap(),
            "a".repeat(64),
            503,
            0,
        )
        .unwrap()
    }
    fn checkpoint() -> DetailedAccountingCheckpoint {
        DetailedAccountingCheckpoint::from_legacy(AccountingCheckpoint {
            owner_session_id: "owner".into(),
            child_id: None,
            revision: AccountingRevision(0),
            baseline: AccountingBaseline::FreshKnownZero,
            totals: AccountingDelta::known_zero(),
            pending: None,
            last_settlement: None,
            known_priced_subtotals: Some(KnownPricedSubtotals::known_zero()),
        })
        .unwrap()
    }
    fn ack_for(
        record: RefusalRecord,
        before: &DetailedAccountingCheckpoint,
    ) -> RefusedSettlementAck {
        let rollup = match before.refusals() {
            Some(rollup) => rollup.appended(record.clone()).unwrap(),
            None => RefusalRollup::first(record.clone()).unwrap(),
        };
        let checkpoint = DetailedAccountingCheckpoint::new(
            before.owner_session_id().into(),
            before.child_id().map(str::to_owned),
            AccountingRevision(record.attempt.revision.0 + 1),
            before.baseline(),
            record.totals_after(before.totals()),
            None,
            Some(DetailedLastSettlement::FinalRefusal(record.clone())),
            before.known_priced_subtotals(),
            Some(rollup),
        )
        .unwrap();
        RefusedSettlementAck::new(
            checkpoint,
            record.attempt.clone(),
            record.binding().clone(),
            record.digest.clone(),
            record.observation_digest.clone(),
            record.binding.policy_digest.clone(),
        )
        .unwrap()
    }

    #[test]
    fn live_binding_uses_provider_fingerprint_and_rejects_changed_selection() {
        let config = config();
        let policy = policy(&config);
        let mut request = request(&config);
        let identity = orbit_provider_http::openai::openai_identity();
        let binding = OrdinaryAttemptBinding::for_request(&request, &identity, &policy).unwrap();
        assert_eq!(
            binding.fingerprint,
            RequestFingerprint::for_request(&request, &identity).unwrap()
        );
        assert_eq!(
            binding.to_record().route_digest(),
            binding.fingerprint.route_digest()
        );
        assert_eq!(
            binding.to_record().body_digest(),
            binding.fingerprint.body_digest()
        );
        request.route.endpoint_query = Some("changed=yes".into());
        assert!(OrdinaryAttemptBinding::for_request(&request, &identity, &policy).is_err());
        request.route.endpoint_query = None;
        request.route.expected_model = "different".into();
        assert!(OrdinaryAttemptBinding::for_request(&request, &identity, &policy).is_err());
        assert!(!format!("{binding:?}").contains("private-prompt"));
    }

    #[test]
    fn eligibility_refuses_each_observed_effect_cancel_and_spend_cap() {
        assert!(RefusalEligibility::default().is_eligible());
        for index in 0..6 {
            let mut flags = RefusalEligibility::default();
            match index {
                0 => flags.text_observed = true,
                1 => flags.tool_observed = true,
                2 => flags.usage_observed = true,
                3 => flags.terminal_observed = true,
                4 => flags.cancelled = true,
                _ => flags.spend_capped = true,
            }
            assert!(!flags.is_eligible());
        }
    }

    #[test]
    fn acknowledgement_requires_exact_live_settlement_revision_totals_and_rollup() {
        let before = checkpoint();
        let record = record(1, "request");
        // Only this private unit fixture can assemble a live object directly.
        // Public consumers receive this authority only from for_rejection.
        let live = RefusedOrdinarySettlement {
            record: record.clone(),
        };
        let ack = ack_for(record.clone(), &before);
        ack.validate_for(&live, &before).unwrap();
        let mut changed = live.clone();
        changed.record.observation_digest = "b".repeat(64);
        assert!(ack.validate_for(&changed, &before).is_err());
        let mut wrong_totals = ack.clone();
        wrong_totals.checkpoint.totals.ordinary.input_tokens = 1;
        assert!(wrong_totals.validate_for(&live, &before).is_err());
        let mut wrong_subset = ack.clone();
        wrong_subset.checkpoint.known_priced_subtotals = None;
        assert!(wrong_subset.validate_for(&live, &before).is_err());
        let mut wrong_revision = before.clone();
        wrong_revision.revision = AccountingRevision(7);
        assert!(ack.validate_for(&live, &wrong_revision).is_err());
        let mut wrong_binding = ack.clone();
        wrong_binding.binding.policy_digest = "b".repeat(64);
        assert!(wrong_binding.validate_for(&live, &before).is_err());
        let mut wrong_scope = before.clone();
        wrong_scope.owner_session_id = "another-owner".into();
        assert!(ack.validate_for(&live, &wrong_scope).is_err());
    }

    #[test]
    fn acknowledgement_after_pending_checks_uncertain_and_exact_intent() {
        let before = checkpoint();
        let record = record(1, "request");
        let live = RefusedOrdinarySettlement {
            record: record.clone(),
        };
        let ack = ack_for(record.clone(), &before);
        let mut pending = before;
        pending.revision = record.attempt.revision;
        pending.pending = Some(PendingAttempt {
            reference: record.attempt.clone(),
            intent: record.intent().clone(),
            uncertain: false,
        });
        ack.validate_for(&live, &pending).unwrap();
        pending.pending.as_mut().unwrap().uncertain = true;
        assert!(ack.validate_for(&live, &pending).is_err());
    }

    #[test]
    fn refusal_stays_inspectable_after_later_legacy_receipt() {
        let before = checkpoint();
        let ack = ack_for(record(1, "request"), &before);
        let mut later = ack.checkpoint.clone();
        later.revision = AccountingRevision(4);
        later.last_settlement = Some(DetailedLastSettlement::Legacy(SettledAttempt {
            reference: AttemptRef {
                revision: AccountingRevision(3),
                request_id: "later".into(),
                intent_digest: "b".repeat(64),
            },
            receipt_digest: "c".repeat(64),
        }));
        later.validate().unwrap();
        assert_eq!(
            later.refusals().unwrap().latest().digest(),
            ack.settlement_digest()
        );
        assert!(later.to_legacy().is_err());
        assert_eq!(later.totals().ordinary.cost_microcents, None);
    }

    #[test]
    fn rollup_count_overflow_and_scope_changes_are_rejected() {
        let first = record(1, "first");
        let second = record(3, "second");
        let previous = "a".repeat(64);
        let max = RefusalRollup::from_parts(
            u64::MAX,
            chain_head(&previous, u64::MAX, first.digest()),
            previous,
            first,
        )
        .unwrap();
        assert_eq!(max.appended(second.clone()), Err(HistoryError::TooLarge));
        let first = RefusalRollup::first(record(1, "first")).unwrap();
        let mut changed = second.intent().clone();
        changed.owner_session_id = "another-owner".into();
        let reference = AttemptRef {
            intent_digest: changed.digest().unwrap(),
            ..second.attempt.clone()
        };
        let changed = RefusalRecord::new(
            changed,
            reference,
            second.binding().clone(),
            second.observation_digest.clone(),
            503,
            0,
        )
        .unwrap();
        assert!(first.appended(changed).is_err());
    }

    #[tokio::test]
    async fn live_settlement_requires_real_matching_complete_rejection_and_no_effects() {
        use orbit_provider_http::adapter_trait::FailureObservation;
        use orbit_provider_http::{AsyncProviderAdapter, CancelToken, OpenAiCompatibleHttpV1};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const DEADLINE: Duration = Duration::from_secs(4);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let mut config = config();
        config.gate = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let policy = policy(&config);
        let mut request = request(&config);
        request.connect_timeout_ms = 2000;
        request.idle_timeout_ms = 2000;
        struct Server(tokio::task::JoinHandle<()>);
        impl Drop for Server {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let mut server = Server(tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(DEADLINE, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut part = [0; 1024];
                let n = tokio::time::timeout(DEADLINE, stream.read(&mut part))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && bytes.len() + n <= 16_384);
                bytes.extend_from_slice(&part[..n]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 8192);
            while bytes.len() < header_end + length {
                let mut part = [0; 1024];
                let n = tokio::time::timeout(DEADLINE, stream.read(&mut part))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && bytes.len() + n <= 16_384);
                bytes.extend_from_slice(&part[..n]);
            }
            assert!(
                std::str::from_utf8(&bytes[header_end..])
                    .unwrap()
                    .contains("private-prompt")
            );
            // These JSON counters and the zero charge are deliberately ignored.
            let body = b"{\"usage\":{\"total_tokens\":999},\"cost\":0}";
            let head = format!(
                "HTTP/1.1 503 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tokio::time::timeout(DEADLINE, async {
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .unwrap();
        }));
        let identity = orbit_provider_http::openai::openai_identity();
        let binding = OrdinaryAttemptBinding::for_request(&request, &identity, &policy).unwrap();
        let adapter = OpenAiCompatibleHttpV1::new(
            identity,
            orbit_provider_http::openai::openai_capabilities(),
            orbit_adapter::types::TlsPinPolicy {
                webpki: false,
                spki_sha256: None,
            },
        )
        .unwrap();
        let failure = match tokio::time::timeout(
            DEADLINE,
            adapter.invoke_detailed(&request, None, &CancelToken::new()),
        )
        .await
        .unwrap()
        {
            Ok(_) => panic!("expected complete HTTP rejection"),
            Err(failure) => failure,
        };
        tokio::time::timeout(DEADLINE, &mut server.0)
            .await
            .unwrap()
            .unwrap();
        let FailureObservation::CompleteHttpRejection(observation) = failure.observation() else {
            panic!("real complete rejection observation missing");
        };
        let record = record(1, "request");
        let live = RefusedOrdinarySettlement::for_rejection(
            record.intent(),
            record.attempt(),
            &binding,
            &policy,
            &request,
            observation,
            &RefusalEligibility::default(),
        )
        .unwrap();
        assert_eq!(live.to_record().status(), 503);
        assert_eq!(
            live.to_record().observation_digest(),
            observation.observation_digest()
        );
        assert_eq!(live.binding(), &binding.to_record());
        assert_eq!(
            live.to_record()
                .totals_after(&AccountingDelta::known_zero())
                .ordinary
                .cost_microcents,
            None
        );
        for index in 0..6 {
            let mut flags = RefusalEligibility::default();
            match index {
                0 => flags.text_observed = true,
                1 => flags.tool_observed = true,
                2 => flags.usage_observed = true,
                3 => flags.terminal_observed = true,
                4 => flags.cancelled = true,
                _ => flags.spend_capped = true,
            }
            assert!(
                RefusedOrdinarySettlement::for_rejection(
                    record.intent(),
                    record.attempt(),
                    &binding,
                    &policy,
                    &request,
                    observation,
                    &flags
                )
                .is_err()
            );
        }
        let mut wrong = record.intent().clone();
        wrong.purpose = AttemptPurpose::Chunk;
        let wrong_ref = AttemptRef {
            intent_digest: wrong.digest().unwrap(),
            ..record.attempt().clone()
        };
        assert!(
            RefusedOrdinarySettlement::for_rejection(
                &wrong,
                &wrong_ref,
                &binding,
                &policy,
                &request,
                observation,
                &RefusalEligibility::default()
            )
            .is_err()
        );
        request.input = SecretBytes::new(b"changed-private-prompt".to_vec());
        assert!(
            RefusedOrdinarySettlement::for_rejection(
                record.intent(),
                record.attempt(),
                &binding,
                &policy,
                &request,
                observation,
                &RefusalEligibility::default()
            )
            .is_err()
        );
    }

    #[derive(Debug, Default)]
    struct OldStore {
        calls: AtomicUsize,
    }
    impl crate::compaction::CompactionJournal for OldStore {
        fn check_archive_capacity(&self, _: u64) -> Result<(), HistoryError> {
            Ok(())
        }
        fn publish(
            &self,
            _: &[orbit_adapter::types::ChatMessage],
            _: &crate::compaction::CompactionCandidate,
            _: &crate::compaction::CompactionReceipt,
        ) -> Result<crate::compaction::CompactionRecordRef, HistoryError> {
            Err(HistoryError::Missing)
        }
        fn initialize_accounting(
            &self,
            _: AccountingBaseline,
        ) -> Result<AccountingCheckpoint, HistoryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            checkpoint().to_legacy()
        }
        fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            checkpoint().to_legacy()
        }
        fn begin_attempt(
            &self,
            _: AccountingRevision,
            intent: &AttemptIntent,
        ) -> Result<AttemptRef, HistoryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AttemptRef {
                revision: AccountingRevision(1),
                request_id: intent.request_id.clone(),
                intent_digest: intent.digest()?,
            })
        }
        fn settle_attempt(
            &self,
            _: &AttemptRef,
            _: &crate::compaction::RequestAccountingReceipt,
        ) -> Result<AccountingCheckpoint, HistoryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            checkpoint().to_legacy()
        }
    }
    #[test]
    fn old_store_defaults_reject_qualified_begin_and_refusal_without_calls() {
        use crate::compaction::CompactionJournal;
        let store = OldStore::default();
        let config = config();
        let binding = OrdinaryAttemptBinding::for_request(
            &request(&config),
            &orbit_provider_http::openai::openai_identity(),
            &policy(&config),
        )
        .unwrap();
        let record = record(1, "request");
        assert_eq!(
            store.begin_attempt_detailed(AccountingRevision(0), record.intent(), Some(&binding)),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            store.settle_refused_ordinary(
                record.attempt(),
                &RefusedOrdinarySettlement {
                    record: record.clone()
                }
            ),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    }
}
