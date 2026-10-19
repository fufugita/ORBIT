#![deny(unsafe_code)]

use orbit_adapter::types::{AdapterIdentity, AdapterKind, Sha256Digest};
use orbit_engine::compaction::*;
use orbit_engine::context_budget::BudgetIdentity;
use orbit_engine::retry::*;
use orbit_engine::{ProviderKind, TurnConfig};
use std::sync::atomic::{AtomicUsize, Ordering};

fn config(endpoint: &str) -> TurnConfig {
    TurnConfig {
        provider_id: "fixture".into(),
        gate: endpoint.into(),
        model: "fixture-model".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32,
        sampling: None,
        effort: None,
        supported_efforts: None,
    }
}
fn selector(endpoint: &str) -> FinalRejectionSelector {
    FinalRejectionSelector::new(
        "fixture".into(),
        "fixture-model".into(),
        endpoint.into(),
        adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
    )
    .unwrap()
}
fn contract() -> FinalRejectionContract {
    FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true).unwrap()
}
fn policy(endpoint: &str) -> FinalRejectionPolicy {
    FinalRejectionPolicy::new(
        "fixture-policy".into(),
        selector(endpoint),
        vec![429, 500, 503],
        contract(),
        3,
    )
    .unwrap()
}
fn binding() -> OrdinaryAttemptBindingRecord {
    OrdinaryAttemptBindingRecord::new(
        "request".into(),
        "decision".into(),
        "attempt".into(),
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
    )
    .unwrap()
}
fn intent() -> AttemptIntent {
    AttemptIntent {
        owner_session_id: "owner".into(),
        child_id: None,
        request_id: "request".into(),
        purpose: AttemptPurpose::Ordinary,
        budget: BudgetIdentity {
            binding_digest: "a".repeat(64),
            metadata_revision: "metadata".into(),
            policy_revision: "budget-policy".into(),
        },
    }
}
fn record() -> RefusalRecord {
    let intent = intent();
    let reference = AttemptRef {
        revision: AccountingRevision(1),
        request_id: intent.request_id.clone(),
        intent_digest: intent.digest().unwrap(),
    };
    RefusalRecord::new(intent, reference, binding(), "a".repeat(64), 503, 65_536).unwrap()
}
fn legacy() -> AccountingCheckpoint {
    AccountingCheckpoint {
        owner_session_id: "owner".into(),
        child_id: None,
        revision: AccountingRevision(0),
        baseline: AccountingBaseline::FreshKnownZero,
        totals: AccountingDelta::known_zero(),
        pending: None,
        last_settlement: None,
        known_priced_subtotals: Some(KnownPricedSubtotals::known_zero()),
    }
}

#[test]
fn policy_requires_supported_explicit_contract_and_sorted_bounded_statuses() {
    for (scope, generation, billing, allow) in [
        ("summary", "final_rejection", "unknown", true),
        ("ordinary", "unknown", "unknown", true),
        ("ordinary", "final_rejection", "zero", true),
        ("ordinary", "final_rejection", "unknown", false),
    ] {
        assert!(FinalRejectionContract::new(scope, generation, billing, allow).is_err());
    }
    for statuses in [
        vec![],
        vec![500, 429],
        vec![500, 500],
        vec![400],
        vec![501],
        vec![200],
    ] {
        assert!(
            FinalRejectionPolicy::new(
                "policy".into(),
                selector("http://127.0.0.1"),
                statuses,
                contract(),
                2
            )
            .is_err()
        );
    }
    for attempts in [0, 1, 9, u32::MAX] {
        assert!(
            FinalRejectionPolicy::new(
                "policy".into(),
                selector("http://127.0.0.1"),
                vec![503],
                contract(),
                attempts
            )
            .is_err()
        );
    }
    for id in [
        String::new(),
        "x".repeat(129),
        "contains space".into(),
        "bad\nvalue".into(),
    ] {
        assert!(
            FinalRejectionPolicy::new(id, selector("http://127.0.0.1"), vec![503], contract(), 2)
                .is_err()
        );
    }
    assert!(
        FinalRejectionPolicy::new(
            "x".repeat(128),
            selector("http://127.0.0.1"),
            vec![429, 500, 502, 503, 504, 529],
            contract(),
            8
        )
        .is_ok()
    );
}

#[test]
fn policy_selector_enforces_lengths_hashes_and_endpoint_validation() {
    let hash = "a".repeat(64);
    for (provider, model, endpoint, identity) in [
        (
            String::new(),
            "model".into(),
            "http://127.0.0.1".into(),
            hash.clone(),
        ),
        (
            "x".repeat(129),
            "model".into(),
            "http://127.0.0.1".into(),
            hash.clone(),
        ),
        (
            "provider".into(),
            "x".repeat(257),
            "http://127.0.0.1".into(),
            hash.clone(),
        ),
        (
            "provider".into(),
            "model".into(),
            "http://example.invalid".into(),
            hash.clone(),
        ),
        (
            "provider".into(),
            "model".into(),
            "https://user:password@example.invalid".into(),
            hash.clone(),
        ),
        (
            "provider".into(),
            "model".into(),
            "https://example.invalid".into(),
            "A".repeat(64),
        ),
        (
            "provider".into(),
            "model".into(),
            "https://example.invalid".into(),
            "a".repeat(63),
        ),
    ] {
        assert!(FinalRejectionSelector::new(provider, model, endpoint, identity).is_err());
    }
}

#[test]
fn policy_binding_matches_actual_effective_endpoint_and_exact_query_bytes() {
    let root = config("http://127.0.0.1:8123");
    let p = policy("http://127.0.0.1:8123/v1");
    let bound = RetryPolicyBinding::for_config(&root, p).unwrap();
    assert_eq!(bound.statuses(), &[429, 500, 503]);
    assert_eq!(bound.max_attempts(), 3);
    for changed in [
        "http://127.0.0.1:8123/tenant/v1",
        "http://127.0.0.1:8124/v1",
        "http://127.0.0.1:8123/v1?region=west",
    ] {
        assert!(RetryPolicyBinding::for_config(&root, policy(changed)).is_err());
    }
    let query = "http://127.0.0.1:8123/exact?region=a&scope=b&escaped=%2F";
    RetryPolicyBinding::for_config(&config(query), policy(query)).unwrap();
    for changed in [
        "http://127.0.0.1:8123/exact?scope=b&region=a&escaped=%2F",
        "http://127.0.0.1:8123/exact?region=a&scope=b&escaped=%2f",
    ] {
        assert!(RetryPolicyBinding::for_config(&config(query), policy(changed)).is_err());
    }
    let mut changed = root.clone();
    changed.provider_id = "Fixture".into();
    assert!(RetryPolicyBinding::for_config(&changed, policy(&root.gate)).is_err());
    changed = root.clone();
    changed.model = "other".into();
    assert!(RetryPolicyBinding::for_config(&changed, policy(&root.gate)).is_err());
    changed = root.clone();
    changed.kind = ProviderKind::Anthropic;
    assert_eq!(
        RetryPolicyBinding::for_config(&changed, policy(&root.gate)),
        Err(RetryPolicyError::UnsupportedAdapter)
    );
}

#[test]
fn selected_policy_digest_includes_every_declaration_value() {
    let endpoint = "http://127.0.0.1:8123/v1";
    let base = policy(endpoint);
    let variants = [
        FinalRejectionPolicy::new(
            "other".into(),
            selector(endpoint),
            base.statuses().to_vec(),
            contract(),
            3,
        )
        .unwrap(),
        FinalRejectionPolicy::new(
            base.id().into(),
            FinalRejectionSelector::new(
                "other".into(),
                "fixture-model".into(),
                endpoint.into(),
                selector(endpoint).adapter_identity_sha256().into(),
            )
            .unwrap(),
            base.statuses().to_vec(),
            contract(),
            3,
        )
        .unwrap(),
        FinalRejectionPolicy::new(
            base.id().into(),
            FinalRejectionSelector::new(
                "fixture".into(),
                "other".into(),
                endpoint.into(),
                selector(endpoint).adapter_identity_sha256().into(),
            )
            .unwrap(),
            base.statuses().to_vec(),
            contract(),
            3,
        )
        .unwrap(),
        policy("http://127.0.0.1:8123/other"),
        FinalRejectionPolicy::new(
            base.id().into(),
            FinalRejectionSelector::new(
                "fixture".into(),
                "fixture-model".into(),
                endpoint.into(),
                "a".repeat(64),
            )
            .unwrap(),
            base.statuses().to_vec(),
            contract(),
            3,
        )
        .unwrap(),
        FinalRejectionPolicy::new(
            base.id().into(),
            selector(endpoint),
            vec![503],
            contract(),
            3,
        )
        .unwrap(),
        FinalRejectionPolicy::new(
            base.id().into(),
            selector(endpoint),
            base.statuses().to_vec(),
            contract(),
            4,
        )
        .unwrap(),
    ];
    for variant in variants {
        assert_ne!(base.digest(), variant.digest());
    }
    assert_eq!(base.digest(), policy(endpoint).digest());
}

#[test]
fn actual_opaque_adapter_identity_is_hashed_without_hex_reinterpretation() {
    let identity = orbit_provider_http::openai::openai_identity();
    assert!(identity.implementation_digest.0.contains('i'));
    let digest = adapter_identity_digest(&identity);
    assert_eq!(digest.len(), 64);
    let variants = [
        AdapterIdentity {
            kind: AdapterKind::MockHttpV1,
            ..identity.clone()
        },
        AdapterIdentity {
            implementation_digest: Sha256Digest("changed".into()),
            ..identity.clone()
        },
        AdapterIdentity {
            profile_digest: Sha256Digest("changed".into()),
            ..identity.clone()
        },
    ];
    for variant in variants {
        assert_ne!(digest, adapter_identity_digest(&variant));
    }
}

#[test]
fn every_binding_field_is_bound_and_decode_cannot_accept_old_digest() {
    let base = binding();
    let fields = [
        base.request_id(),
        base.decision_id(),
        base.attempt_id(),
        base.provider_digest(),
        base.model_digest(),
        base.route_digest(),
        base.body_digest(),
        base.adapter_identity_sha256(),
        base.policy_digest(),
    ];
    for changed in 0..fields.len() {
        let mut values: Vec<String> = fields.iter().map(|field| (*field).into()).collect();
        values[changed] = if changed < 3 {
            "changed".into()
        } else {
            "1".repeat(64)
        };
        assert!(
            OrdinaryAttemptBindingRecord::from_parts(
                values[0].clone(),
                values[1].clone(),
                values[2].clone(),
                values[3].clone(),
                values[4].clone(),
                values[5].clone(),
                values[6].clone(),
                values[7].clone(),
                values[8].clone(),
                base.digest().into()
            )
            .is_err()
        );
    }
    let mut bad = fields
        .iter()
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();
    for index in 0..3 {
        let old = bad[index].clone();
        bad[index] = "r".repeat(257);
        assert!(
            OrdinaryAttemptBindingRecord::new(
                bad[0].clone(),
                bad[1].clone(),
                bad[2].clone(),
                bad[3].clone(),
                bad[4].clone(),
                bad[5].clone(),
                bad[6].clone(),
                bad[7].clone(),
                bad[8].clone()
            )
            .is_err()
        );
        bad[index] = old;
    }
    OrdinaryAttemptBindingRecord::from_parts(
        fields[0].into(),
        fields[1].into(),
        fields[2].into(),
        fields[3].into(),
        fields[4].into(),
        fields[5].into(),
        fields[6].into(),
        fields[7].into(),
        fields[8].into(),
        base.digest().into(),
    )
    .unwrap();
}

#[test]
fn refusal_record_checks_scope_reference_status_size_and_full_digest() {
    let record = record();
    record.validate().unwrap();
    RefusalRecord::from_parts(
        record.intent().clone(),
        record.attempt().clone(),
        record.binding().clone(),
        record.observation_digest().into(),
        record.status(),
        record.response_body_bytes(),
        record.digest().into(),
    )
    .unwrap();
    for (observation, status, bytes) in [
        ("b".repeat(64), 503, 65_536),
        ("a".repeat(64), 500, 65_536),
        ("a".repeat(64), 503, 0),
    ] {
        assert!(
            RefusalRecord::from_parts(
                record.intent().clone(),
                record.attempt().clone(),
                record.binding().clone(),
                observation,
                status,
                bytes,
                record.digest().into()
            )
            .is_err()
        );
    }
    for (status, bytes) in [(200, 0), (400, 0), (503, 65_537)] {
        assert!(
            RefusalRecord::new(
                record.intent().clone(),
                record.attempt().clone(),
                record.binding().clone(),
                record.observation_digest().into(),
                status,
                bytes
            )
            .is_err()
        );
    }
    let mut changed = record.intent().clone();
    changed.purpose = AttemptPurpose::Chunk;
    let reference = AttemptRef {
        intent_digest: changed.digest().unwrap(),
        ..record.attempt().clone()
    };
    assert!(
        RefusalRecord::new(
            changed,
            reference,
            record.binding().clone(),
            record.observation_digest().into(),
            503,
            0
        )
        .is_err()
    );
    let mut changed = record.attempt().clone();
    changed.request_id = "other".into();
    assert!(
        RefusalRecord::new(
            record.intent().clone(),
            changed,
            record.binding().clone(),
            record.observation_digest().into(),
            503,
            0
        )
        .is_err()
    );
    let mut changed = record.attempt().clone();
    changed.revision = AccountingRevision(2);
    assert!(
        RefusalRecord::from_parts(
            record.intent().clone(),
            changed,
            record.binding().clone(),
            record.observation_digest().into(),
            503,
            65_536,
            record.digest().into()
        )
        .is_err()
    );
    let mut changed = record.intent().clone();
    changed.budget.policy_revision = "other".into();
    let reference = AttemptRef {
        intent_digest: changed.digest().unwrap(),
        ..record.attempt().clone()
    };
    assert!(
        RefusalRecord::from_parts(
            changed,
            reference,
            record.binding().clone(),
            record.observation_digest().into(),
            503,
            65_536,
            record.digest().into()
        )
        .is_err()
    );
    let binding = record.binding();
    let changed = OrdinaryAttemptBindingRecord::new(
        binding.request_id().into(),
        binding.decision_id().into(),
        binding.attempt_id().into(),
        binding.provider_digest().into(),
        binding.model_digest().into(),
        binding.route_digest().into(),
        "1".repeat(64),
        binding.adapter_identity_sha256().into(),
        binding.policy_digest().into(),
    )
    .unwrap();
    assert!(
        RefusalRecord::from_parts(
            record.intent().clone(),
            record.attempt().clone(),
            changed,
            record.observation_digest().into(),
            503,
            65_536,
            record.digest().into()
        )
        .is_err()
    );
}

#[test]
fn maximum_bounded_snapshot_fields_fit_and_overlong_old_revisions_are_rejected() {
    let mut intent = intent();
    intent.owner_session_id = "o".repeat(128);
    intent.child_id = Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".into());
    intent.request_id = "r".repeat(256);
    intent.budget.metadata_revision = "\\".repeat(256);
    intent.budget.policy_revision = "\\".repeat(256);
    let attempt = AttemptRef {
        revision: AccountingRevision(u64::MAX - 1),
        request_id: intent.request_id.clone(),
        intent_digest: intent.digest().unwrap(),
    };
    let binding = OrdinaryAttemptBindingRecord::new(
        intent.request_id.clone(),
        "d".repeat(256),
        "t".repeat(256),
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
    )
    .unwrap();
    let max = RefusalRecord::new(
        intent.clone(),
        attempt.clone(),
        binding.clone(),
        "a".repeat(64),
        529,
        65_536,
    )
    .unwrap();
    RefusalRollup::first(max).unwrap().validate().unwrap();
    intent.budget.metadata_revision.push('x');
    assert!(RefusalRecord::new(intent, attempt, binding, "a".repeat(64), 529, 65_536).is_err());
}

#[test]
fn refusal_keeps_real_counters_and_unknown_bill_without_synthetic_receipt() {
    let record = record();
    let mut totals = AccountingDelta::known_zero();
    totals.ordinary = AccountingTotals {
        input_tokens: 12,
        output_tokens: 7,
        cost_microcents: Some(9),
    };
    totals.housekeeping = AccountingTotals {
        input_tokens: 4,
        output_tokens: 2,
        cost_microcents: Some(3),
    };
    let after = record.totals_after(&totals);
    assert_eq!(
        (after.ordinary.input_tokens, after.ordinary.output_tokens),
        (12, 7)
    );
    assert_eq!(after.ordinary.cost_microcents, None);
    assert_eq!(after.housekeeping, totals.housekeeping);
    assert_eq!(after.knownness, AccountingKnownness::UnknownUsage);
    let invalid = RequestAccountingReceipt {
        request_id: "request".into(),
        purpose: AttemptPurpose::Ordinary,
        totals: AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None,
        },
        usage: None,
        knownness: AccountingKnownness::UnknownUsage,
        completed: false,
    };
    assert!(invalid.validate().is_err());
    let mut uncertain = totals;
    uncertain.knownness = AccountingKnownness::Uncertain;
    assert_eq!(
        record.totals_after(&uncertain).knownness,
        AccountingKnownness::Uncertain
    );
}

#[test]
fn rollup_validates_link_and_seed_and_retains_only_latest_full_record() {
    let record = record();
    let first = RefusalRollup::first(record.clone()).unwrap();
    assert_eq!(first.count(), 1);
    assert_eq!(first.latest(), &record);
    assert_eq!(first.appended(record.clone()).unwrap(), first);
    for (count, head, previous) in [
        (0, first.chain_digest(), first.previous_chain_digest()),
        (2, first.chain_digest(), first.previous_chain_digest()),
        (1, first.previous_chain_digest(), first.chain_digest()),
    ] {
        assert!(
            RefusalRollup::from_parts(count, head.into(), previous.into(), record.clone()).is_err()
        );
    }
    let mut later_intent = record.intent().clone();
    later_intent.request_id = "later".into();
    let later_reference = AttemptRef {
        revision: AccountingRevision(3),
        request_id: "later".into(),
        intent_digest: later_intent.digest().unwrap(),
    };
    let later_binding = OrdinaryAttemptBindingRecord::new(
        "later".into(),
        "later-decision".into(),
        "later-attempt".into(),
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
    )
    .unwrap();
    let later = RefusalRecord::new(
        later_intent,
        later_reference,
        later_binding,
        "b".repeat(64),
        500,
        0,
    )
    .unwrap();
    let second = first.appended(later.clone()).unwrap();
    assert_eq!(second.count(), 2);
    assert_eq!(second.previous_chain_digest(), first.chain_digest());
    assert_eq!(second.latest(), &later);
}

#[derive(Debug, Default)]
struct LegacyJournal {
    initialize: AtomicUsize,
    read: AtomicUsize,
    begin: AtomicUsize,
    settle: AtomicUsize,
    settled_checkpoint: Option<AccountingCheckpoint>,
}
impl CompactionJournal for LegacyJournal {
    fn check_archive_capacity(&self, _: u64) -> Result<(), HistoryError> {
        Ok(())
    }
    fn publish(
        &self,
        _: &[orbit_adapter::types::ChatMessage],
        _: &CompactionCandidate,
        _: &CompactionReceipt,
    ) -> Result<CompactionRecordRef, HistoryError> {
        Err(HistoryError::Missing)
    }
    fn initialize_accounting(
        &self,
        _: AccountingBaseline,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.initialize.fetch_add(1, Ordering::SeqCst);
        Ok(legacy())
    }
    fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
        self.read.fetch_add(1, Ordering::SeqCst);
        Ok(legacy())
    }
    fn begin_attempt(
        &self,
        revision: AccountingRevision,
        intent: &AttemptIntent,
    ) -> Result<AttemptRef, HistoryError> {
        self.begin.fetch_add(1, Ordering::SeqCst);
        Ok(AttemptRef {
            revision: AccountingRevision(revision.0 + 1),
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest()?,
        })
    }
    fn settle_attempt(
        &self,
        _: &AttemptRef,
        _: &RequestAccountingReceipt,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.settle.fetch_add(1, Ordering::SeqCst);
        Ok(self.settled_checkpoint.clone().unwrap_or_else(legacy))
    }
}

#[test]
fn legacy_journal_implementers_need_no_new_required_methods_and_defaults_call_once() {
    let store = LegacyJournal::default();
    let initialized = store
        .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
        .unwrap();
    assert!(initialized.legacy_equivalent(&legacy()));
    assert!(
        store
            .accounting_checkpoint_detailed()
            .unwrap()
            .legacy_equivalent(&legacy())
    );
    let intent = intent();
    let attempt = store
        .begin_attempt_detailed(AccountingRevision(0), &intent, None)
        .unwrap();
    let receipt = RequestAccountingReceipt {
        request_id: intent.request_id,
        purpose: AttemptPurpose::Ordinary,
        totals: AccountingTotals::known_zero(),
        usage: None,
        knownness: AccountingKnownness::Known,
        completed: false,
    };
    assert!(
        store
            .settle_attempt_detailed(&attempt, &receipt)
            .unwrap()
            .legacy_equivalent(&legacy())
    );
    assert_eq!(
        [
            store.initialize.load(Ordering::SeqCst),
            store.read.load(Ordering::SeqCst),
            store.begin.load(Ordering::SeqCst),
            store.settle.load(Ordering::SeqCst)
        ],
        [1, 1, 1, 1]
    );
}

fn unpriced_legacy_settlement() -> (AccountingCheckpoint, AttemptRef, RequestAccountingReceipt) {
    let intent = intent();
    let attempt = AttemptRef {
        revision: AccountingRevision(1),
        request_id: intent.request_id.clone(),
        intent_digest: intent.digest().unwrap(),
    };
    let receipt = RequestAccountingReceipt {
        request_id: intent.request_id,
        purpose: AttemptPurpose::Ordinary,
        totals: AccountingTotals {
            input_tokens: 13,
            output_tokens: 5,
            cost_microcents: None,
        },
        usage: Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 13,
            output_tokens: 5,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
        }),
        knownness: AccountingKnownness::Known,
        completed: true,
    };
    receipt.validate().unwrap();
    let mut checkpoint = legacy();
    checkpoint.revision = AccountingRevision(2);
    checkpoint.totals = checkpoint.totals.checked_with(&receipt).unwrap();
    checkpoint.last_settlement = Some(SettledAttempt {
        reference: attempt.clone(),
        receipt_digest: receipt.digest().unwrap(),
    });
    (checkpoint, attempt, receipt)
}

#[test]
fn detailed_checkpoint_preserves_validated_usage_with_unknown_legacy_price() {
    let (checkpoint, _, receipt) = unpriced_legacy_settlement();
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(receipt.usage.unwrap().input_tokens, 13);
    let detailed = DetailedAccountingCheckpoint::from_legacy(checkpoint.clone())
        .expect("validated final usage remains valid when selected pricing is unavailable");
    assert!(detailed.legacy_equivalent(&checkpoint));
    assert_eq!(detailed.totals().ordinary.input_tokens, 13);
    assert_eq!(detailed.totals().ordinary.output_tokens, 5);
    assert_eq!(detailed.totals().ordinary.cost_microcents, None);
}

#[test]
fn legacy_detailed_settle_accepts_unpriced_final_usage_after_exactly_one_old_call() {
    let (checkpoint, attempt, receipt) = unpriced_legacy_settlement();
    let store = LegacyJournal {
        settled_checkpoint: Some(checkpoint.clone()),
        ..Default::default()
    };
    let result = store.settle_attempt_detailed(&attempt, &receipt);
    assert_eq!(store.settle.load(Ordering::SeqCst), 1);
    assert_eq!(store.initialize.load(Ordering::SeqCst), 0);
    assert_eq!(store.read.load(Ordering::SeqCst), 0);
    assert_eq!(store.begin.load(Ordering::SeqCst), 0);
    let detailed =
        result.expect("a successful old settlement with unpriced usage must remain usable");
    assert!(detailed.legacy_equivalent(&checkpoint));
}

fn checked_checkpoint(
    value: &AccountingCheckpoint,
) -> Result<DetailedAccountingCheckpoint, HistoryError> {
    DetailedAccountingCheckpoint::new(
        value.owner_session_id.clone(),
        value.child_id.clone(),
        value.revision,
        value.baseline,
        value.totals.clone(),
        value.pending.clone(),
        value
            .last_settlement
            .clone()
            .map(DetailedLastSettlement::Legacy),
        value.known_priced_subtotals,
        None,
    )
}

fn priced_legacy_checkpoint() -> AccountingCheckpoint {
    let (mut checkpoint, _, mut ordinary) = unpriced_legacy_settlement();
    ordinary.totals.cost_microcents = Some(9);
    ordinary.validate().unwrap();
    let mut summary = ordinary.clone();
    summary.request_id = "summary".into();
    summary.purpose = AttemptPurpose::Chunk;
    summary.totals = AccountingTotals {
        input_tokens: 4,
        output_tokens: 2,
        cost_microcents: Some(3),
    };
    summary.usage.as_mut().unwrap().input_tokens = 4;
    summary.usage.as_mut().unwrap().output_tokens = 2;
    summary.validate().unwrap();
    checkpoint.totals = AccountingDelta::known_zero()
        .checked_with(&ordinary)
        .unwrap()
        .checked_with(&summary)
        .unwrap();
    checkpoint.known_priced_subtotals = Some(
        KnownPricedSubtotals::known_zero()
            .checked_with(&ordinary)
            .unwrap()
            .checked_with(&summary)
            .unwrap(),
    );
    let mut summary_intent = intent();
    summary_intent.request_id = summary.request_id.clone();
    summary_intent.purpose = AttemptPurpose::Chunk;
    checkpoint.revision = AccountingRevision(4);
    checkpoint.last_settlement = Some(SettledAttempt {
        reference: AttemptRef {
            revision: AccountingRevision(3),
            request_id: summary.request_id.clone(),
            intent_digest: summary_intent.digest().unwrap(),
        },
        receipt_digest: summary.digest().unwrap(),
    });
    checkpoint
}

#[test]
fn present_priced_subtotals_must_equal_each_known_full_bucket_cost() {
    let checkpoint = priced_legacy_checkpoint();
    assert!(
        checked_checkpoint(&checkpoint)
            .unwrap()
            .legacy_equivalent(&checkpoint)
    );
    assert!(DetailedAccountingCheckpoint::from_legacy(checkpoint.clone()).is_ok());
    for (ordinary_microcents, housekeeping_microcents) in [(8, 3), (10, 3), (9, 2), (9, 4)] {
        let mut invalid = checkpoint.clone();
        invalid.known_priced_subtotals = Some(KnownPricedSubtotals {
            ordinary_microcents,
            housekeeping_microcents,
        });
        assert_eq!(
            checked_checkpoint(&invalid),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            DetailedAccountingCheckpoint::from_legacy(invalid),
            Err(HistoryError::InvalidRecord)
        );
    }
    let mut untracked = checkpoint;
    untracked.known_priced_subtotals = None;
    assert!(
        checked_checkpoint(&untracked)
            .unwrap()
            .legacy_equivalent(&untracked)
    );
}

#[test]
fn revision_zero_present_priced_subtotals_are_zero_for_both_baselines() {
    for baseline in [
        AccountingBaseline::FreshKnownZero,
        AccountingBaseline::UnknownLegacy,
    ] {
        let mut checkpoint = legacy();
        checkpoint.baseline = baseline;
        if baseline == AccountingBaseline::UnknownLegacy {
            checkpoint.totals = AccountingDelta::unknown_legacy();
        }
        assert!(checked_checkpoint(&checkpoint).is_ok());
        assert!(DetailedAccountingCheckpoint::from_legacy(checkpoint.clone()).is_ok());
        for (ordinary_microcents, housekeeping_microcents) in [(1, 0), (0, 1)] {
            let mut invalid = checkpoint.clone();
            invalid.known_priced_subtotals = Some(KnownPricedSubtotals {
                ordinary_microcents,
                housekeeping_microcents,
            });
            assert_eq!(
                checked_checkpoint(&invalid),
                Err(HistoryError::InvalidRecord)
            );
            assert_eq!(
                DetailedAccountingCheckpoint::from_legacy(invalid),
                Err(HistoryError::InvalidRecord)
            );
        }
        checkpoint.known_priced_subtotals = None;
        assert!(
            checked_checkpoint(&checkpoint)
                .unwrap()
                .legacy_equivalent(&checkpoint)
        );
    }
}

#[test]
fn later_unpriced_usage_keeps_prior_known_priced_subset_and_optional_legacy_marker() {
    let mut checkpoint = priced_legacy_checkpoint();
    let (_, _, mut receipt) = unpriced_legacy_settlement();
    receipt.request_id = "later-unpriced".into();
    let mut later_intent = intent();
    later_intent.request_id = receipt.request_id.clone();
    checkpoint.totals = checkpoint.totals.checked_with(&receipt).unwrap();
    checkpoint.known_priced_subtotals = checkpoint
        .known_priced_subtotals
        .map(|priced| priced.checked_with(&receipt).unwrap());
    checkpoint.revision = AccountingRevision(6);
    checkpoint.last_settlement = Some(SettledAttempt {
        reference: AttemptRef {
            revision: AccountingRevision(5),
            request_id: receipt.request_id.clone(),
            intent_digest: later_intent.digest().unwrap(),
        },
        receipt_digest: receipt.digest().unwrap(),
    });
    let detailed = DetailedAccountingCheckpoint::from_legacy(checkpoint.clone()).unwrap();
    assert!(
        checked_checkpoint(&checkpoint)
            .unwrap()
            .legacy_equivalent(&checkpoint)
    );
    assert_eq!(detailed.totals().ordinary.cost_microcents, None);
    assert_eq!(detailed.totals().ordinary.input_tokens, 26);
    assert_eq!(detailed.totals().ordinary.output_tokens, 10);
    assert_eq!(
        detailed.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: 9,
            housekeeping_microcents: 3,
        })
    );
    checkpoint.known_priced_subtotals = None;
    assert!(
        DetailedAccountingCheckpoint::from_legacy(checkpoint.clone())
            .unwrap()
            .legacy_equivalent(&checkpoint)
    );
}

#[test]
fn baseline_knownness_rejects_impossible_nonzero_legacy_and_fresh_snapshots() {
    let (base, _, _) = unpriced_legacy_settlement();
    for (baseline, knownness) in [
        (
            AccountingBaseline::UnknownLegacy,
            AccountingKnownness::Known,
        ),
        (
            AccountingBaseline::UnknownLegacy,
            AccountingKnownness::UnknownUsage,
        ),
        (
            AccountingBaseline::FreshKnownZero,
            AccountingKnownness::UnknownLegacy,
        ),
    ] {
        let mut invalid = base.clone();
        invalid.baseline = baseline;
        invalid.totals.knownness = knownness;
        assert_eq!(
            checked_checkpoint(&invalid),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            DetailedAccountingCheckpoint::from_legacy(invalid),
            Err(HistoryError::InvalidRecord)
        );
    }
}

#[test]
fn ordinary_refusal_preserves_legacy_unknownness_and_marks_fresh_usage_unknown() {
    for baseline in [
        AccountingBaseline::FreshKnownZero,
        AccountingBaseline::UnknownLegacy,
    ] {
        let before = match baseline {
            AccountingBaseline::FreshKnownZero => AccountingDelta::known_zero(),
            AccountingBaseline::UnknownLegacy => AccountingDelta::unknown_legacy(),
        };
        let record = record();
        let totals = record.totals_after(&before);
        let expected = match baseline {
            AccountingBaseline::FreshKnownZero => AccountingKnownness::UnknownUsage,
            AccountingBaseline::UnknownLegacy => AccountingKnownness::UnknownLegacy,
        };
        assert_eq!(totals.knownness, expected);
        let detailed = DetailedAccountingCheckpoint::new(
            "owner".into(),
            None,
            AccountingRevision(2),
            baseline,
            totals,
            None,
            Some(DetailedLastSettlement::FinalRefusal(record.clone())),
            Some(KnownPricedSubtotals::known_zero()),
            Some(RefusalRollup::first(record).unwrap()),
        )
        .unwrap();
        assert_eq!(detailed.totals().knownness, expected);
        assert_eq!(detailed.totals().ordinary.cost_microcents, None);
        assert_eq!(detailed.refusals().unwrap().count(), 1);
    }
}

#[test]
fn debug_never_prints_operator_selector_or_record_identifiers() {
    let endpoint = "https://private-fixture.invalid/secret?tenant=private-value";
    let policy = policy(endpoint);
    let bound = RetryPolicyBinding::for_config(&config(endpoint), policy.clone()).unwrap();
    let record = record();
    let debug = format!(
        "{:?} {policy:?} {bound:?} {record:?} {:?} {:?}",
        policy.selector(),
        record.binding(),
        RefusalRollup::first(record.clone()).unwrap()
    );
    for secret in [
        "private-fixture",
        "secret",
        "private-value",
        "fixture-model",
        "fixture-policy",
        "request",
        "decision",
    ] {
        assert!(
            !debug.contains(secret),
            "Debug leaked selector or record identity"
        );
    }
}
