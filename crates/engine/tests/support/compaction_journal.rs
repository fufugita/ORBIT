use orbit_adapter::types::ChatMessage;
use orbit_engine::compaction::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    None,
    Capacity,
    Namespace,
    Begin,
    Settle,
    Publish,
    PublishUncertain,
}

#[derive(Clone)]
pub struct Archive {
    pub source: Vec<ChatMessage>,
    pub candidate: Vec<ChatMessage>,
    pub reference: CompactionRecordRef,
    pub attempts: Vec<RequestAccountingReceipt>,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Entry {
    checkpoint: AccountingCheckpoint,
    last_receipt: Option<RequestAccountingReceipt>,
    uncertain_receipt: Option<RequestAccountingReceipt>,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<Option<String>, Entry>,
    archives: BTreeMap<String, Archive>,
    intents: Vec<AttemptIntent>,
    receipts: Vec<RequestAccountingReceipt>,
    events: Vec<&'static str>,
}

pub struct MemoryJournal {
    owner: String,
    child: Option<String>,
    state: Arc<Mutex<State>>,
    failure: Mutex<Failure>,
    cancel_after_publish: Mutex<Option<orbit_provider_http::CancelToken>>,
    cancel_after_begin: Mutex<Option<orbit_provider_http::CancelToken>>,
}
impl std::fmt::Debug for MemoryJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryJournal { bounded fixture storage }")
    }
}

// Pure archive validation and encoding; callers retain all authorization.
pub(crate) fn encode_archive(
    source: &[ChatMessage],
    candidate: &CompactionCandidate,
    receipt: &CompactionReceipt,
) -> Result<Vec<u8>, HistoryError> {
    let source_bytes = serde_json::to_vec(source).map_err(|_| HistoryError::InvalidRecord)?;
    let candidate_bytes =
        serde_json::to_vec(candidate.messages()).map_err(|_| HistoryError::InvalidRecord)?;
    let hash = |domain: &[u8], bytes: &[u8]| {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(bytes);
        hex::encode(h.finalize())
    };
    if hash(b"orbit-compaction-source-v1\0", &source_bytes) != receipt.source_digest
        || hash(b"orbit-compaction-candidate-v1\0", &candidate_bytes) != receipt.candidate_digest
        || receipt.source_digest != candidate.source_digest()
        || receipt.candidate_digest != candidate.candidate_digest()
    {
        return Err(HistoryError::InvalidRecord);
    }
    let bytes = serde_json::to_vec(&json!({"source":source,"candidate":candidate.messages(),"operation":receipt.operation_id,"owner":receipt.owner_session_id,"child":receipt.child_id,"source_digest":receipt.source_digest,"candidate_digest":receipt.candidate_digest,"conversation_budget":format!("{:?}",receipt.conversation_budget),"summary_budget":format!("{:?}",receipt.summary_budget),"accounting":format!("{:?}",receipt.accounting),"attempts":receipt.attempts.iter().map(|attempt| format!("{attempt:?}")).collect::<Vec<_>>(),"attempt_digests":receipt.attempts.iter().map(RequestAccountingReceipt::digest).collect::<Result<Vec<_>,_>>()?})).map_err(|_| HistoryError::InvalidRecord)?;
    Ok(bytes)
}

fn valid_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_child(value: &str) -> bool {
    value.len() == 26 && ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}
fn metadata_bytes(entries: &BTreeMap<Option<String>, Entry>) -> Result<usize, HistoryError> {
    let mut total = 64usize;
    for entry in entries.values() {
        let actual = serde_json::to_vec(&format!("{entry:?}"))
            .map_err(|_| HistoryError::InvalidRecord)?
            .len();
        // Reserve a whole maximum pending/settled entry, including all bounded
        // strings and maximal counters, before every metadata mutation.
        let mut maximum = entry.checkpoint.clone();
        maximum.revision = AccountingRevision(u64::MAX);
        maximum.totals.ordinary = AccountingTotals {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cost_microcents: Some(u64::MAX),
        };
        maximum.totals.housekeeping = maximum.totals.ordinary;
        maximum.totals.knownness = AccountingKnownness::UnknownLegacy;
        if let Some(subtotals) = &mut maximum.known_priced_subtotals {
            subtotals.ordinary_microcents = u64::MAX;
            subtotals.housekeeping_microcents = u64::MAX;
        }
        let reference = AttemptRef {
            revision: AccountingRevision(u64::MAX),
            request_id: "r".repeat(512),
            intent_digest: "d".repeat(64),
        };
        maximum.pending = Some(PendingAttempt {
            reference: reference.clone(),
            uncertain: true,
            intent: AttemptIntent {
                owner_session_id: maximum.owner_session_id.clone(),
                child_id: maximum.child_id.clone(),
                request_id: "r".repeat(512),
                purpose: AttemptPurpose::Ordinary,
                budget: orbit_engine::context_budget::BudgetIdentity {
                    binding_digest: "b".repeat(64),
                    metadata_revision: "\\".repeat(256),
                    policy_revision: "\\".repeat(256),
                },
            },
        });
        maximum.last_settlement = Some(SettledAttempt {
            reference,
            receipt_digest: "d".repeat(64),
        });
        let maximum_receipt = RequestAccountingReceipt {
            request_id: "r".repeat(512),
            purpose: AttemptPurpose::Ordinary,
            totals: maximum.totals.ordinary,
            usage: Some(orbit_adapter::types::ProviderUsage {
                input_tokens: u64::MAX,
                output_tokens: u64::MAX,
                cache_read_tokens: u64::MAX,
                cache_write_tokens: u64::MAX,
                reasoning_tokens: u64::MAX,
            }),
            knownness: AccountingKnownness::UnknownLegacy,
            completed: false,
        };
        // This is a size witness, not a semantically valid accounting receipt.
        // Both retained receipt slots reserve their complete bounded evidence.
        let maximum_entry = Entry {
            checkpoint: maximum,
            last_receipt: Some(maximum_receipt.clone()),
            uncertain_receipt: Some(maximum_receipt),
        };
        let reserved = serde_json::to_vec(&format!("{maximum_entry:?}"))
            .map_err(|_| HistoryError::InvalidRecord)?
            .len();
        total = total
            .checked_add(actual.max(reserved))
            .and_then(|n| n.checked_add(32))
            .ok_or(HistoryError::TooLarge)?;
    }
    if total > MAX_ACCOUNTING_CHECKPOINT_BYTES {
        return Err(HistoryError::Full);
    }
    Ok(total)
}

impl MemoryJournal {
    pub fn uninitialized(owner: &str) -> Arc<Self> {
        assert!(valid_owner(owner));
        Arc::new(Self {
            owner: owner.into(),
            child: None,
            state: Arc::new(Mutex::new(State::default())),
            failure: Mutex::new(Failure::None),
            cancel_after_publish: Mutex::new(None),
            cancel_after_begin: Mutex::new(None),
        })
    }
    pub fn fresh(owner: &str) -> Arc<Self> {
        let journal = Self::uninitialized(owner);
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        journal
    }
    pub fn child(
        &self,
        child: &str,
        baseline: AccountingBaseline,
    ) -> Result<Arc<Self>, HistoryError> {
        if !valid_child(child) {
            return Err(HistoryError::InvalidRecord);
        }
        let journal = Arc::new(Self {
            owner: self.owner.clone(),
            child: Some(child.into()),
            state: self.state.clone(),
            failure: Mutex::new(Failure::None),
            cancel_after_publish: Mutex::new(None),
            cancel_after_begin: Mutex::new(None),
        });
        journal.initialize_accounting(baseline)?;
        Ok(journal)
    }
    pub fn fail(&self, failure: Failure) {
        *self.failure.lock().unwrap() = failure;
    }
    pub fn cancel_after_publication(&self, cancel: orbit_provider_http::CancelToken) {
        *self.cancel_after_publish.lock().unwrap() = Some(cancel);
    }
    pub fn cancel_after_begin(&self, cancel: orbit_provider_http::CancelToken) {
        *self.cancel_after_begin.lock().unwrap() = Some(cancel);
    }
    pub fn intents(&self) -> Vec<AttemptIntent> {
        self.state.lock().unwrap().intents.clone()
    }
    pub fn receipts(&self) -> Vec<RequestAccountingReceipt> {
        self.state.lock().unwrap().receipts.clone()
    }
    pub fn retained_receipts(
        &self,
    ) -> (
        Option<RequestAccountingReceipt>,
        Option<RequestAccountingReceipt>,
    ) {
        let state = self.state.lock().unwrap();
        let entry = state.entries.get(&self.child).unwrap();
        (entry.last_receipt.clone(), entry.uncertain_receipt.clone())
    }
    pub fn archives(&self) -> Vec<Archive> {
        self.state
            .lock()
            .unwrap()
            .archives
            .values()
            .cloned()
            .collect()
    }
    pub fn events(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().events.clone()
    }
    pub fn reserved_metadata_bytes(&self) -> usize {
        metadata_bytes(&self.state.lock().unwrap().entries).unwrap()
    }
    fn scope(&self, owner: &str, child: &Option<String>) -> Result<(), HistoryError> {
        if owner != self.owner
            || child != &self.child
            || !valid_owner(owner)
            || child.as_deref().is_some_and(|id| !valid_child(id))
        {
            return Err(HistoryError::InvalidRecord);
        }
        Ok(())
    }
    fn trace(state: &mut State, event: &'static str) -> Result<(), HistoryError> {
        if state.events.len() >= 128 {
            return Err(HistoryError::Full);
        }
        state.events.push(event);
        Ok(())
    }
}

impl CompactionJournal for MemoryJournal {
    fn check_archive_capacity(&self, minimum_record_bytes: u64) -> Result<(), HistoryError> {
        if *self.failure.lock().unwrap() == Failure::Capacity {
            return Err(HistoryError::Full);
        }
        let mut state = self.state.lock().unwrap();
        metadata_bytes(&state.entries)?;
        let used = state
            .archives
            .values()
            .try_fold(0u64, |sum, record| {
                sum.checked_add(record.bytes.len() as u64)
            })
            .ok_or(HistoryError::TooLarge)?;
        if minimum_record_bytes > MAX_COMPACTION_SOURCE_BYTES as u64
            || state.archives.len() >= 64
            || used
                .checked_add(minimum_record_bytes)
                .is_none_or(|n| n > 128 * 1024 * 1024)
        {
            return Err(HistoryError::Full);
        }
        Self::trace(&mut state, "capacity")
    }
    fn initialize_accounting(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        let mut state = self.state.lock().unwrap();
        if state.entries.contains_key(&self.child) {
            return Err(HistoryError::Conflict);
        }
        let checkpoint = AccountingCheckpoint {
            owner_session_id: self.owner.clone(),
            child_id: self.child.clone(),
            revision: AccountingRevision(0),
            baseline,
            totals: if baseline == AccountingBaseline::FreshKnownZero {
                AccountingDelta::known_zero()
            } else {
                AccountingDelta::unknown_legacy()
            },
            pending: None,
            last_settlement: None,
            known_priced_subtotals: Some(KnownPricedSubtotals::known_zero()),
        };
        let mut prospective = state.entries.clone();
        prospective.insert(
            self.child.clone(),
            Entry {
                checkpoint: checkpoint.clone(),
                last_receipt: None,
                uncertain_receipt: None,
            },
        );
        metadata_bytes(&prospective)?;
        state.entries = prospective;
        Ok(checkpoint)
    }
    fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
        let mut checkpoint = self
            .state
            .lock()
            .unwrap()
            .entries
            .get(&self.child)
            .ok_or(HistoryError::Missing)?
            .checkpoint
            .clone();
        self.scope(&checkpoint.owner_session_id, &checkpoint.child_id)?;
        if *self.failure.lock().unwrap() == Failure::Namespace {
            checkpoint.owner_session_id = "wrong-owner".into();
        }
        Ok(checkpoint)
    }
    fn begin_attempt(
        &self,
        expected_revision: AccountingRevision,
        intent: &AttemptIntent,
    ) -> Result<AttemptRef, HistoryError> {
        self.scope(&intent.owner_session_id, &intent.child_id)?;
        if intent.request_id.is_empty()
            || intent.request_id.len() > 512
            || intent.budget.binding_digest.len() != 64
            || intent.budget.metadata_revision.len() > 256
            || intent.budget.policy_revision.len() > 256
        {
            return Err(HistoryError::InvalidRecord);
        }
        if *self.failure.lock().unwrap() == Failure::Begin {
            return Err(HistoryError::Conflict);
        }
        let mut state = self.state.lock().unwrap();
        let mut entries = state.entries.clone();
        let entry = entries.get_mut(&self.child).ok_or(HistoryError::Missing)?;
        let revision = AccountingRevision(
            expected_revision
                .0
                .checked_add(1)
                .ok_or(HistoryError::TooLarge)?,
        );
        if let Some(pending) = &entry.checkpoint.pending {
            return if pending.reference.revision == revision
                && pending.intent == *intent
                && pending.reference.intent_digest == intent.digest()?
            {
                Ok(pending.reference.clone())
            } else {
                Err(HistoryError::Conflict)
            };
        }
        if entry.checkpoint.revision != expected_revision {
            return Err(HistoryError::Conflict);
        }
        let reference = AttemptRef {
            revision,
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest()?,
        };
        entry.checkpoint.revision = revision;
        entry.checkpoint.pending = Some(PendingAttempt {
            reference: reference.clone(),
            intent: intent.clone(),
            uncertain: false,
        });
        metadata_bytes(&entries)?;
        if state.intents.len() >= 64 {
            return Err(HistoryError::Full);
        }
        Self::trace(&mut state, "begin")?;
        state.entries = entries;
        state.intents.push(intent.clone());
        drop(state);
        if let Some(cancel) = self.cancel_after_begin.lock().unwrap().as_ref() {
            cancel.cancel();
        }
        Ok(reference)
    }
    fn settle_attempt(
        &self,
        reference: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        if reference.request_id != receipt.request_id {
            return Err(HistoryError::InvalidRecord);
        }
        if *self.failure.lock().unwrap() == Failure::Settle {
            return Err(HistoryError::Uncertain);
        }
        let digest = receipt.digest()?;
        let mut state = self.state.lock().unwrap();
        let mut entries = state.entries.clone();
        let entry = entries.get_mut(&self.child).ok_or(HistoryError::Missing)?;
        self.scope(
            &entry.checkpoint.owner_session_id,
            &entry.checkpoint.child_id,
        )?;
        if let Some(last) = &entry.checkpoint.last_settlement {
            if reference == &last.reference {
                return if digest == last.receipt_digest {
                    Ok(entry.checkpoint.clone())
                } else {
                    Err(HistoryError::Conflict)
                };
            }
            if reference.revision.0 < last.reference.revision.0 {
                return Err(HistoryError::StaleNonApplying);
            }
        }
        let pending = entry
            .checkpoint
            .pending
            .as_ref()
            .ok_or(HistoryError::Conflict)?;
        if &pending.reference != reference
            || pending.intent.request_id != receipt.request_id
            || pending.intent.purpose != receipt.purpose
            || pending.intent.digest()? != reference.intent_digest
        {
            return Err(HistoryError::Conflict);
        }
        if let Some(previous) = &entry.uncertain_receipt {
            return if previous.digest()? == digest {
                Ok(entry.checkpoint.clone())
            } else {
                Err(HistoryError::Conflict)
            };
        }
        let totals = entry.checkpoint.totals.checked_with(receipt)?;
        let known_priced_subtotals = entry
            .checkpoint
            .known_priced_subtotals
            .map(|subtotals| subtotals.checked_with(receipt))
            .transpose()?;
        entry.checkpoint.totals = totals;
        entry.checkpoint.known_priced_subtotals = known_priced_subtotals;
        if receipt.knownness == AccountingKnownness::Uncertain {
            entry.checkpoint.pending.as_mut().unwrap().uncertain = true;
            entry.uncertain_receipt = Some(receipt.clone());
        } else {
            entry.last_receipt = Some(receipt.clone());
            entry.uncertain_receipt = None;
            entry.checkpoint.pending = None;
            entry.checkpoint.last_settlement = Some(SettledAttempt {
                reference: reference.clone(),
                receipt_digest: digest,
            });
        }
        entry.checkpoint.revision = AccountingRevision(
            reference
                .revision
                .0
                .checked_add(1)
                .ok_or(HistoryError::TooLarge)?,
        );
        metadata_bytes(&entries)?;
        let checkpoint = entries.get(&self.child).unwrap().checkpoint.clone();
        if state.receipts.len() >= 64 {
            return Err(HistoryError::Full);
        }
        Self::trace(&mut state, "settle")?;
        state.entries = entries;
        state.receipts.push(receipt.clone());
        Ok(checkpoint)
    }
    fn publish(
        &self,
        source: &[ChatMessage],
        candidate: &CompactionCandidate,
        receipt: &CompactionReceipt,
    ) -> Result<CompactionRecordRef, HistoryError> {
        self.scope(&receipt.owner_session_id, &receipt.child_id)?;
        if !valid_owner(&receipt.operation_id) || receipt.attempts.len() > MAX_SUMMARY_CHUNKS + 1 {
            return Err(HistoryError::InvalidRecord);
        }
        let bytes = encode_archive(source, candidate, receipt)?;
        let failure = *self.failure.lock().unwrap();
        if failure == Failure::Publish {
            return Err(HistoryError::Unsafe);
        }
        if failure == Failure::PublishUncertain {
            return Err(HistoryError::Uncertain);
        }
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.archives.get(&receipt.operation_id) {
            return if existing.bytes == bytes {
                Ok(existing.reference.clone())
            } else {
                Err(HistoryError::Conflict)
            };
        }
        let used = state
            .archives
            .values()
            .try_fold(0usize, |sum, archive| sum.checked_add(archive.bytes.len()))
            .ok_or(HistoryError::TooLarge)?;
        if bytes.len() > MAX_COMPACTION_SOURCE_BYTES
            || state.archives.len() >= 64
            || used
                .checked_add(bytes.len())
                .is_none_or(|n| n > 128 * 1024 * 1024)
        {
            return Err(HistoryError::Full);
        }
        metadata_bytes(&state.entries)?;
        let checkpoint = &state
            .entries
            .get(&self.child)
            .ok_or(HistoryError::Missing)?
            .checkpoint;
        if checkpoint.pending.is_some()
            || checkpoint.totals.knownness == AccountingKnownness::Uncertain
        {
            return Err(HistoryError::Conflict);
        }
        let mut accounted = AccountingDelta::known_zero();
        let mut request_ids = std::collections::BTreeSet::new();
        for attempt in &receipt.attempts {
            if !request_ids.insert(&attempt.request_id)
                || !state.receipts.contains(attempt)
                || !state.intents.iter().any(|intent| {
                    intent.request_id == attempt.request_id
                        && intent.owner_session_id == self.owner
                        && intent.child_id == self.child
                        && intent.purpose == attempt.purpose
                })
            {
                return Err(HistoryError::InvalidRecord);
            }
            accounted = accounted.checked_with(attempt)?;
        }
        if accounted != receipt.accounting {
            return Err(HistoryError::InvalidRecord);
        }
        let reference = CompactionRecordRef {
            owner_session_id: self.owner.clone(),
            child_id: self.child.clone(),
            record_id: receipt.operation_id.clone(),
            source_digest: receipt.source_digest.clone(),
            candidate_digest: receipt.candidate_digest.clone(),
        };
        Self::trace(&mut state, "publish")?;
        state.archives.insert(
            receipt.operation_id.clone(),
            Archive {
                source: source.to_vec(),
                candidate: candidate.messages().to_vec(),
                reference: reference.clone(),
                attempts: receipt.attempts.clone(),
                bytes,
            },
        );
        drop(state);
        if let Some(cancel) = self.cancel_after_publish.lock().unwrap().as_ref() {
            cancel.cancel();
        }
        Ok(reference)
    }
}
