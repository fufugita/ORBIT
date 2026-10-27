#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::types::{
    ChatMessage, ChatRole, ContentBlock, CostRates, ProviderUsage, Sha256Digest, ToolCallMessage,
    ToolDefinition,
};
use orbit_engine::compaction::{
    AccountingBaseline, AccountingCheckpoint, AccountingDelta, AccountingKnownness,
    AccountingRevision, AccountingTotals, AttemptIntent, AttemptPurpose, AttemptRef,
    CompactionCandidate, CompactionJournal, CompactionReceipt, CompactionRecordRef,
    CompactionStatus, HistoryError, KnownPricedSubtotals, MAX_COMPACTION_SOURCE_BYTES,
    MAX_SUMMARY_CHUNKS, PendingAttempt, RequestAccountingReceipt, SettledAttempt,
};
use orbit_engine::retry::{
    DetailedAccountingCheckpoint, DetailedLastSettlement, FinalRejectionContract,
    FinalRejectionPolicy, FinalRejectionSelector, OrdinaryAttemptBinding,
    OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup, RefusedOrdinarySettlement,
    RefusedSettlementAck, RetryPolicyBinding, adapter_identity_digest,
};
use orbit_engine::turn::{RetryTurnCompletion, run_turn_detailed_with_retry_policy};
use orbit_engine::{
    PendingToolCall, ProviderKind, SpendAllowance, ToolExecutor, ToolRoundResult, TurnConfig,
    TurnEnd, TurnOptions,
};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[path = "support/compaction_journal.rs"]
pub mod compaction_journal;

const OWNER: &str = "refusal-component-owner";
const PROMPT: &str = "continue this exact controlled task λ";
const ANSWER: &str = "controlled ordinary answer";
const MAX_REQUESTS: usize = 4;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_TRACE: usize = 64;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_ISOLATED").as_deref(),
            Ok("1")
        );
        let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap());
        assert!(root.is_absolute() && std::env::current_dir().unwrap().starts_with(&root));
        let root_meta = fs::symlink_metadata(&root).unwrap();
        assert!(root_meta.is_dir() && !root_meta.file_type().is_symlink());
        assert_eq!(root_meta.mode() & 0o777, 0o700);
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ] {
            let path = PathBuf::from(std::env::var_os(name).unwrap());
            assert!(path.starts_with(&root) && path != root);
            assert_eq!(path.canonicalize().unwrap(), path);
        }
        let path =
            std::env::temp_dir().join(format!("orbit-refusal-component-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Begin,
    BadBeginReference,
    RefusalBefore,
    RefusalAfter,
    PriorAck,
    NormalBefore,
    NormalAfter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CancelAt {
    None,
    BeginEntry,
    Begin(usize),
    RefusalEntry,
    RefusalAck,
    NormalEntry,
    NormalAck,
}

#[derive(Clone)]
struct ComponentArchive {
    source: Vec<ChatMessage>,
    candidate: CompactionCandidate,
    reference: CompactionRecordRef,
    conversation_budget: orbit_engine::context_budget::BudgetIdentity,
    summary_budget: orbit_engine::context_budget::BudgetIdentity,
    accounting: AccountingDelta,
    attempts: Vec<RequestAccountingReceipt>,
    checkpoint: DetailedAccountingCheckpoint,
    bytes: Vec<u8>,
}
impl ComponentArchive {
    fn receipt(&self) -> CompactionReceipt {
        CompactionReceipt {
            operation_id: self.reference.record_id.clone(),
            owner_session_id: self.reference.owner_session_id.clone(),
            child_id: self.reference.child_id.clone(),
            source_digest: self.reference.source_digest.clone(),
            candidate_digest: self.reference.candidate_digest.clone(),
            conversation_budget: self.conversation_budget.clone(),
            summary_budget: self.summary_budget.clone(),
            accounting: self.accounting.clone(),
            attempts: self.attempts.clone(),
        }
    }
}
struct JournalState {
    checkpoint: DetailedAccountingCheckpoint,
    binding: Option<OrdinaryAttemptBindingRecord>,
    begins: Vec<(AttemptIntent, Option<OrdinaryAttemptBindingRecord>)>,
    receipts: Vec<RequestAccountingReceipt>,
    refused: Vec<RefusalRecord>,
    provisional: Option<RequestAccountingReceipt>,
    prior_ack: Option<RefusedSettlementAck>,
    trace: Vec<&'static str>,
    archives: BTreeMap<String, ComponentArchive>,
}

// This bounded store models component transitions only. It makes no filesystem
// durability claim; U5v separately crosses the genuine CLI storage boundary.
struct ComponentJournal {
    state: Mutex<JournalState>,
    fault: Fault,
    cancel_at: CancelAt,
    cancel: CancelToken,
    cancel_after_publish: Mutex<Option<CancelToken>>,
}
impl std::fmt::Debug for ComponentJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ComponentJournal { bounded memory only }")
    }
}
impl ComponentJournal {
    fn new(owner: &str, fault: Fault, cancel_at: CancelAt, cancel: &CancelToken) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(JournalState {
                checkpoint: DetailedAccountingCheckpoint::new(
                    owner.into(),
                    None,
                    AccountingRevision(0),
                    AccountingBaseline::FreshKnownZero,
                    AccountingDelta::known_zero(),
                    None,
                    None,
                    Some(KnownPricedSubtotals::known_zero()),
                    None,
                )
                .unwrap(),
                binding: None,
                begins: Vec::new(),
                receipts: Vec::new(),
                refused: Vec::new(),
                provisional: None,
                prior_ack: None,
                trace: Vec::new(),
                archives: BTreeMap::new(),
            }),
            fault,
            cancel_at,
            cancel: cancel.clone(),
            cancel_after_publish: Mutex::new(None),
        })
    }
    fn trace(state: &mut JournalState, event: &'static str) -> Result<(), HistoryError> {
        if state.trace.len() >= MAX_TRACE {
            return Err(HistoryError::Full);
        }
        state.trace.push(event);
        Ok(())
    }
    fn snapshot(&self) -> DetailedAccountingCheckpoint {
        self.state.lock().unwrap().checkpoint.clone()
    }
    fn counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (
            state.begins.len(),
            state.receipts.len(),
            state.refused.len(),
        )
    }
    fn calls(&self, name: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|event| **event == name)
            .count()
    }
    fn archives(&self) -> Vec<ComponentArchive> {
        self.state
            .lock()
            .unwrap()
            .archives
            .values()
            .cloned()
            .collect()
    }
    fn cancel_after_publish(&self, cancel: &CancelToken) {
        *self.cancel_after_publish.lock().unwrap() = Some(cancel.clone());
    }
    fn ack(
        checkpoint: DetailedAccountingCheckpoint,
        settlement: &RefusedOrdinarySettlement,
    ) -> Result<RefusedSettlementAck, HistoryError> {
        RefusedSettlementAck::new(
            checkpoint,
            settlement.attempt().clone(),
            settlement.binding().clone(),
            settlement.digest().into(),
            settlement.observation_digest().into(),
            settlement.policy_digest().into(),
        )
    }
}
impl CompactionJournal for ComponentJournal {
    fn check_archive_capacity(&self, minimum: u64) -> Result<(), HistoryError> {
        let state = self.state.lock().unwrap();
        let used = state
            .archives
            .values()
            .try_fold(0u64, |total, archive| {
                total.checked_add(archive.bytes.len() as u64)
            })
            .ok_or(HistoryError::TooLarge)?;
        if minimum > MAX_COMPACTION_SOURCE_BYTES as u64
            || state.archives.len() >= 64
            || used
                .checked_add(minimum)
                .is_none_or(|total| total > 128 * 1024 * 1024)
        {
            return Err(HistoryError::Full);
        }
        Ok(())
    }
    fn publish(
        &self,
        source: &[ChatMessage],
        candidate: &CompactionCandidate,
        receipt: &CompactionReceipt,
    ) -> Result<CompactionRecordRef, HistoryError> {
        let valid_id = !receipt.operation_id.is_empty()
            && receipt.operation_id.len() <= 128
            && receipt
                .operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        let bytes = compaction_journal::encode_archive(source, candidate, receipt)?;
        let mut state = self.state.lock().unwrap();
        if !valid_id
            || receipt.owner_session_id != state.checkpoint.owner_session_id()
            || receipt.child_id.as_deref() != state.checkpoint.child_id()
            || receipt.attempts.is_empty()
            || receipt.attempts.len() > MAX_SUMMARY_CHUNKS + 1
        {
            return Err(HistoryError::InvalidRecord);
        }
        // Immutable exact re-ACK precedes current accounting authorization.
        // Later activity cannot invalidate an already saved identical archive.
        if let Some(existing) = state.archives.get(&receipt.operation_id) {
            return if existing.bytes == bytes {
                Ok(existing.reference.clone())
            } else {
                Err(HistoryError::Conflict)
            };
        }
        let checkpoint = &state.checkpoint;
        checkpoint.validate()?;
        if checkpoint.pending().is_some()
            || checkpoint.totals().knownness == AccountingKnownness::Uncertain
        {
            return Err(HistoryError::Conflict);
        }
        let Some(DetailedLastSettlement::Legacy(last)) = checkpoint.last_settlement() else {
            return Err(HistoryError::Conflict);
        };
        let last_receipt = receipt.attempts.last().ok_or(HistoryError::InvalidRecord)?;
        if last.reference.request_id != last_receipt.request_id
            || last.receipt_digest != last_receipt.digest()?
            || last.reference.revision.0.checked_add(1) != Some(checkpoint.revision().0)
        {
            return Err(HistoryError::Conflict);
        }
        let mut ids = BTreeSet::new();
        let mut delta = AccountingDelta::known_zero();
        for attempt in &receipt.attempts {
            attempt.validate()?;
            if !attempt.completed
                || !matches!(
                    attempt.purpose,
                    AttemptPurpose::Chunk | AttemptPurpose::Merge
                )
                || !ids.insert(&attempt.request_id)
                || !state.receipts.contains(attempt)
            {
                return Err(HistoryError::InvalidRecord);
            }
            let (intent, binding) = state
                .begins
                .iter()
                .find(|(intent, _)| intent.request_id == attempt.request_id)
                .ok_or(HistoryError::InvalidRecord)?;
            if binding.is_some()
                || intent.owner_session_id != receipt.owner_session_id
                || intent.child_id != receipt.child_id
                || intent.purpose != attempt.purpose
                || intent.budget != receipt.summary_budget
            {
                return Err(HistoryError::InvalidRecord);
            }
            let digest = intent.digest()?;
            if attempt.request_id == last_receipt.request_id
                && digest != last.reference.intent_digest
            {
                return Err(HistoryError::InvalidRecord);
            }
            delta = delta.checked_with(attempt)?;
        }
        if delta != receipt.accounting {
            return Err(HistoryError::InvalidRecord);
        }
        let used = state
            .archives
            .values()
            .try_fold(0usize, |total, archive| {
                total.checked_add(archive.bytes.len())
            })
            .ok_or(HistoryError::TooLarge)?;
        if bytes.len() > MAX_COMPACTION_SOURCE_BYTES
            || state.archives.len() >= 64
            || used
                .checked_add(bytes.len())
                .is_none_or(|total| total > 128 * 1024 * 1024)
        {
            return Err(HistoryError::Full);
        }
        let reference = CompactionRecordRef {
            owner_session_id: receipt.owner_session_id.clone(),
            child_id: receipt.child_id.clone(),
            record_id: receipt.operation_id.clone(),
            source_digest: receipt.source_digest.clone(),
            candidate_digest: receipt.candidate_digest.clone(),
        };
        let archive = ComponentArchive {
            source: source.to_vec(),
            candidate: candidate.clone(),
            reference: reference.clone(),
            conversation_budget: receipt.conversation_budget.clone(),
            summary_budget: receipt.summary_budget.clone(),
            accounting: receipt.accounting.clone(),
            attempts: receipt.attempts.clone(),
            checkpoint: checkpoint.clone(),
            bytes,
        };
        Self::trace(&mut state, "publish")?;
        state.archives.insert(receipt.operation_id.clone(), archive);
        drop(state);
        if let Some(cancel) = self.cancel_after_publish.lock().unwrap().as_ref() {
            cancel.cancel();
        }
        Ok(reference)
    }
    fn initialize_accounting(
        &self,
        _: AccountingBaseline,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        Err(HistoryError::Conflict)
    }
    fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
        panic!("managed ordinary loop selected the legacy checkpoint API")
    }
    fn begin_attempt(
        &self,
        _: AccountingRevision,
        _: &AttemptIntent,
    ) -> Result<AttemptRef, HistoryError> {
        panic!("managed ordinary loop selected the legacy begin API")
    }
    fn settle_attempt(
        &self,
        _: &AttemptRef,
        _: &RequestAccountingReceipt,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        panic!("managed ordinary loop selected the legacy settlement API")
    }
    fn initialize_accounting_detailed(
        &self,
        _: AccountingBaseline,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        Err(HistoryError::Conflict)
    }
    fn accounting_checkpoint_detailed(&self) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        let mut state = self.state.lock().unwrap();
        Self::trace(&mut state, "read")?;
        state.checkpoint.validate()?;
        Ok(state.checkpoint.clone())
    }
    fn begin_attempt_detailed(
        &self,
        expected: AccountingRevision,
        intent: &AttemptIntent,
        binding: Option<&OrdinaryAttemptBinding>,
    ) -> Result<AttemptRef, HistoryError> {
        if self.cancel_at == CancelAt::BeginEntry {
            self.cancel.cancel();
        }
        let mut state = self.state.lock().unwrap();
        Self::trace(&mut state, "begin")?;
        if self.fault == Fault::Begin {
            return Err(HistoryError::Uncertain);
        }
        let before = &state.checkpoint;
        if before.revision() != expected
            || before.pending().is_some()
            || before.totals().knownness == AccountingKnownness::Uncertain
            || before.owner_session_id() != intent.owner_session_id
            || before.child_id() != intent.child_id.as_deref()
            || state.begins.len() >= MAX_TRACE
        {
            return Err(HistoryError::Conflict);
        }
        let binding = binding.map(OrdinaryAttemptBinding::to_record);
        if binding.as_ref().is_some_and(|value| {
            value.request_id() != intent.request_id || intent.purpose != AttemptPurpose::Ordinary
        }) {
            return Err(HistoryError::InvalidRecord);
        }
        expected.0.checked_add(2).ok_or(HistoryError::TooLarge)?;
        let reference = AttemptRef {
            revision: AccountingRevision(expected.0 + 1),
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest()?,
        };
        let next = DetailedAccountingCheckpoint::new(
            before.owner_session_id().into(),
            before.child_id().map(str::to_owned),
            reference.revision,
            before.baseline(),
            before.totals().clone(),
            Some(PendingAttempt {
                reference: reference.clone(),
                intent: intent.clone(),
                uncertain: false,
            }),
            before.last_settlement().cloned(),
            before.known_priced_subtotals(),
            before.refusals().cloned(),
        )?;
        state.checkpoint = next;
        state.binding = binding.clone();
        state.begins.push((intent.clone(), binding));
        state.provisional = None;
        let count = state.begins.len();
        drop(state);
        if self.cancel_at == CancelAt::Begin(count) {
            self.cancel.cancel();
        }
        if self.fault == Fault::BadBeginReference {
            let mut bad = reference;
            bad.request_id = "incorrect-returned-reference".into();
            return Ok(bad);
        }
        Ok(reference)
    }
    fn settle_attempt_detailed(
        &self,
        reference: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        if self.cancel_at == CancelAt::NormalEntry {
            self.cancel.cancel();
        }
        let mut state = self.state.lock().unwrap();
        Self::trace(&mut state, "normal")?;
        if self.fault == Fault::NormalBefore {
            return Err(HistoryError::Uncertain);
        }
        receipt.validate()?;
        let before = &state.checkpoint;
        let pending = before.pending().ok_or(HistoryError::Conflict)?;
        if &pending.reference != reference
            || pending.intent.request_id != receipt.request_id
            || pending.intent.purpose != receipt.purpose
            || pending.intent.digest()? != reference.intent_digest
        {
            return Err(HistoryError::Conflict);
        }
        if let Some(provisional) = &state.provisional {
            return if provisional == receipt {
                Ok(before.clone())
            } else {
                Err(HistoryError::Conflict)
            };
        }
        if state.receipts.len() >= MAX_TRACE {
            return Err(HistoryError::Full);
        }
        let uncertain = receipt.knownness == AccountingKnownness::Uncertain;
        let next_pending = uncertain.then(|| PendingAttempt {
            uncertain: true,
            ..pending.clone()
        });
        let last = if uncertain {
            before.last_settlement().cloned()
        } else {
            Some(DetailedLastSettlement::Legacy(SettledAttempt {
                reference: reference.clone(),
                receipt_digest: receipt.digest()?,
            }))
        };
        let next = DetailedAccountingCheckpoint::new(
            before.owner_session_id().into(),
            before.child_id().map(str::to_owned),
            AccountingRevision(
                reference
                    .revision
                    .0
                    .checked_add(1)
                    .ok_or(HistoryError::TooLarge)?,
            ),
            before.baseline(),
            before.totals().checked_with(receipt)?,
            next_pending,
            last,
            before
                .known_priced_subtotals()
                .map(|value| value.checked_with(receipt))
                .transpose()?,
            before.refusals().cloned(),
        )?;
        state.checkpoint = next.clone();
        state.provisional = uncertain.then(|| receipt.clone());
        if !uncertain {
            state.binding = None;
        }
        state.receipts.push(receipt.clone());
        drop(state);
        if self.cancel_at == CancelAt::NormalAck {
            self.cancel.cancel();
        }
        if self.fault == Fault::NormalAfter {
            return Err(HistoryError::Uncertain);
        }
        Ok(next)
    }
    fn settle_refused_ordinary(
        &self,
        reference: &AttemptRef,
        settlement: &RefusedOrdinarySettlement,
    ) -> Result<RefusedSettlementAck, HistoryError> {
        if self.cancel_at == CancelAt::RefusalEntry {
            self.cancel.cancel();
        }
        let mut state = self.state.lock().unwrap();
        Self::trace(&mut state, "refusal")?;
        if self.fault == Fault::RefusalBefore {
            return Err(HistoryError::Uncertain);
        }
        let record = settlement.to_record();
        record.validate()?;
        let before = &state.checkpoint;
        let pending = before.pending().ok_or(HistoryError::Conflict)?;
        if &pending.reference != reference
            || record.attempt() != reference
            || pending.uncertain
            || pending.intent != *record.intent()
            || state.binding.as_ref() != Some(record.binding())
        {
            return Err(HistoryError::Conflict);
        }
        let rollup = match before.refusals() {
            Some(value) => value.appended(record.clone())?,
            None => RefusalRollup::first(record.clone())?,
        };
        let next = DetailedAccountingCheckpoint::new(
            before.owner_session_id().into(),
            before.child_id().map(str::to_owned),
            AccountingRevision(
                reference
                    .revision
                    .0
                    .checked_add(1)
                    .ok_or(HistoryError::TooLarge)?,
            ),
            before.baseline(),
            record.totals_after(before.totals()),
            None,
            Some(DetailedLastSettlement::FinalRefusal(record.clone())),
            before.known_priced_subtotals(),
            Some(rollup),
        )?;
        let ack = Self::ack(next.clone(), settlement)?;
        ack.validate_for(settlement, before)?;
        if state.refused.len() >= MAX_TRACE {
            return Err(HistoryError::Full);
        }
        state.checkpoint = next;
        state.binding = None;
        state.refused.push(record);
        let previous_ack = state.prior_ack.replace(ack.clone());
        drop(state);
        if self.cancel_at == CancelAt::RefusalAck {
            self.cancel.cancel();
        }
        if self.fault == Fault::RefusalAfter {
            return Err(HistoryError::Uncertain);
        }
        if self.fault == Fault::PriorAck
            && let Some(previous) = previous_ack
        {
            return Ok(previous);
        }
        Ok(ack)
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    extra_length: usize,
    cancel_before_eof: Option<CancelToken>,
}
impl Reply {
    fn rejection(status: u16, bytes: usize) -> Self {
        Self {
            status,
            body: vec![b'x'; bytes],
            extra_length: 0,
            cancel_before_eof: None,
        }
    }
    fn success() -> Self {
        Self { status: 200, body: format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"index":0,"delta":{"content":ANSWER},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})).into_bytes(), extra_length: 0, cancel_before_eof: None }
    }
    fn text(text: &str) -> Self {
        Self { status: 200, body: format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"index":0,"delta":{"content":text},"finish_reason":"stop"}], "usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})).into_bytes(), extra_length: 0, cancel_before_eof: None }
    }
    fn admitted_malformed(provisional: bool) -> Self {
        let prefix = if provisional {
            format!(
                "data: {}\n\n",
                json!({"choices":[{"index":0,"delta":{"content":"kept partial text"},"finish_reason":null}],
            "usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})
            )
        } else {
            String::new()
        };
        Self {
            status: 200,
            body: format!("{prefix}data: invalid-json\n\n").into_bytes(),
            extra_length: 0,
            cancel_before_eof: None,
        }
    }
}
#[derive(Clone)]
struct Capture {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
struct Wire {
    url: String,
    authority: String,
    captures: Arc<Mutex<Vec<Capture>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
    watchdog_thread: Option<std::thread::JoinHandle<()>>,
}
impl Wire {
    fn new(replies: Vec<Reply>) -> Self {
        assert!(replies.len() <= MAX_REQUESTS);
        Self::with_request_limit(replies, MAX_REQUESTS)
    }
    fn with_request_limit(replies: Vec<Reply>, limit: usize) -> Self {
        assert!((1..=12).contains(&limit) && replies.len() <= limit);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/tenant/v1?scope=refusal-component");
        let captures = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = captures.clone();
        let accepted = connections.clone();
        let stopping = stop.clone();
        let (watchdog, receive) = std::sync::mpsc::channel();
        let watchdog_thread = std::thread::spawn(move || {
            if matches!(
                receive.recv_timeout(Duration::from_secs(25)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("refusal component owned fixture watchdog");
                std::process::exit(91);
            }
        });
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut replies = replies.into_iter();
            loop {
                if Instant::now() >= deadline {
                    return Err("listener deadline");
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        if accepted.fetch_add(1, Ordering::SeqCst) >= limit {
                            return Err("request count bound");
                        }
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .map_err(|_| "read timeout")?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .map_err(|_| "write timeout")?;
                        observed
                            .lock()
                            .map_err(|_| "capture lock")?
                            .push(read_request(&mut socket)?);
                        let reply = replies.next().ok_or("unexpected replay")?;
                        let content_type = if reply.status == 200 {
                            "text/event-stream"
                        } else {
                            "application/json"
                        };
                        let length = reply.body.len() + reply.extra_length;
                        write!(socket, "HTTP/1.1 {} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n", reply.status).map_err(|_| "header write")?;
                        if let Some(cancel) = reply.cancel_before_eof {
                            let prefix = reply.body.len().saturating_sub(1);
                            socket
                                .write_all(&reply.body[..prefix])
                                .map_err(|_| "prefix write")?;
                            socket.flush().map_err(|_| "prefix flush")?;
                            cancel.cancel();
                            while !stopping.load(Ordering::SeqCst) {
                                if Instant::now() >= deadline {
                                    return Err("cancelled body hold deadline");
                                }
                                std::thread::sleep(Duration::from_millis(2));
                            }
                        } else {
                            if let Err(error) = socket.write_all(&reply.body)
                                && !matches!(
                                    error.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::ConnectionReset
                                )
                            {
                                return Err("body write");
                            }
                            let _ = socket.flush();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopping.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Err("listener accept"),
                }
            }
        });
        Self {
            url,
            authority,
            captures,
            connections,
            stop,
            thread: Some(thread),
            watchdog: Some(watchdog),
            watchdog_thread: Some(watchdog_thread),
        }
    }
    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap().expect("owned wire failure");
        }
        assert_eq!(
            self.connections.load(Ordering::SeqCst),
            self.captures.lock().unwrap().len()
        );
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.watchdog_thread.take() {
            thread.join().unwrap();
        }
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.watchdog_thread.take() {
            let _ = thread.join();
        }
    }
}
fn read_request(socket: &mut TcpStream) -> Result<Capture, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() >= 16 * 1024 || Instant::now() >= deadline {
            return Err("header bound");
        }
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(1) => raw.push(byte[0]),
            Ok(_) => return Err("incomplete header"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("header read"),
        }
    }
    let raw = std::str::from_utf8(&raw).map_err(|_| "header UTF-8")?;
    let mut lines = raw.lines();
    let target = lines.next().ok_or("missing target")?.to_owned();
    let headers: Vec<_> = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or("header separator")?;
            Ok((name.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<Result<_, &'static str>>()?;
    if headers.iter().any(|(name, _)| name == "transfer-encoding") {
        return Err("unexpected transfer encoding");
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .collect();
    if lengths.len() != 1 {
        return Err("single content length required");
    }
    let length = lengths[0]
        .1
        .parse::<usize>()
        .map_err(|_| "content length")?;
    if length == 0 || length > MAX_BODY {
        return Err("request body bound");
    }
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        if Instant::now() >= deadline {
            return Err("request body deadline");
        }
        match socket.read(&mut body[offset..]) {
            Ok(0) => return Err("incomplete body"),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("body read"),
        }
    }
    serde_json::from_slice::<Value>(&body).map_err(|_| "request JSON")?;
    Ok(Capture {
        target,
        headers,
        body,
    })
}

fn config(wire: &Wire) -> TurnConfig {
    TurnConfig {
        billing: Some(test_billing("component-provider", "component/raw", 13)),
        provider_id: "component-provider".into(),
        gate: wire.url.clone(),
        model: "component/raw".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: Some(CostRates {
            input_per_million_microcents: 0,
            output_per_million_microcents: 0,
            cache_read_per_million_microcents: Some(0),
            cache_write_per_million_microcents: Some(0),
            reasoning_per_million_microcents: Some(0),
            request_flat_microcents: 13,
        }),
        max_output_tokens: 73,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    }
}

fn test_billing(
    provider: &str,
    model: &str,
    flat_fee: u64,
) -> orbit_adapter::types::BillingQuoteContractV1 {
    use orbit_adapter::types::{
        BillingQuoteContractV1, BillingRatesV1, ModelId, PricingDeclarationState, ProviderId,
        ReasoningCounterBasis, ReasoningRatePolicy,
    };
    BillingQuoteContractV1::try_new(
        ProviderId(provider.into()),
        ModelId(model.into()),
        PricingDeclarationState::DeclaredV2,
        BillingRatesV1 {
            input_per_million_microdollars: Some(0),
            output_per_million_microdollars: Some(0),
            cache_read_per_million_microdollars: Some(0),
            cache_write_per_million_microdollars: Some(0),
            reasoning_per_million_microdollars: None,
            request_flat_microdollars: Some(flat_fee),
        },
        ReasoningCounterBasis::IncludedInOutput,
        ReasoningRatePolicy::OutputRate,
    )
    .unwrap()
}
fn policy(config: &TurnConfig, ceiling: u32) -> RetryPolicyBinding {
    let selector = FinalRejectionSelector::new(
        config.provider_id.clone(),
        config.model.clone(),
        config.gate.clone(),
        adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
    )
    .unwrap();
    RetryPolicyBinding::for_config(
        config,
        FinalRejectionPolicy::new(
            "controlled-policy".into(),
            selector,
            vec![429, 500, 503],
            FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true).unwrap(),
            ceiling,
        )
        .unwrap(),
    )
    .unwrap()
}
fn options(config: &TurnConfig, journal: Arc<ComponentJournal>, ceiling: u32) -> TurnOptions {
    TurnOptions {
        session_id: OWNER.into(),
        request_stem: "refusal-component".into(),
        max_attempts: ceiling,
        max_rounds: 1,
        journal: Some(journal),
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(config, 8000).unwrap(),
        ),
        system_directive: Some("Use the exact controlled intent.".into()),
        ..Default::default()
    }
}
#[derive(Default)]
struct Executor(usize);
impl ToolExecutor for Executor {
    fn execute(&mut self, _: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        Vec::new()
    }
}
#[allow(clippy::too_many_arguments)]
fn invoke(
    home: &Home,
    config: &TurnConfig,
    options: &TurnOptions,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
    policy: Option<&RetryPolicyBinding>,
    cancel_on_retry: bool,
) -> (RetryTurnCompletion, Vec<FrontendEvent>) {
    let mut events = Vec::new();
    let mut executor = Executor::default();
    let completion = run_turn_detailed_with_retry_policy(
        &home.0,
        config,
        options,
        prompt,
        transcript,
        &mut executor,
        cancel,
        &mut |event| {
            assert!(events.len() < 256, "event bound");
            if cancel_on_retry && matches!(event, FrontendEvent::Retrying { .. }) {
                cancel.cancel();
            }
            events.push(event);
        },
        policy,
    );
    assert_eq!(executor.0, 0);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
    (completion, events)
}
fn retries(events: &[FrontendEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, FrontendEvent::Retrying { .. }))
        .count()
}
fn assert_wire(wire: &Wire, count: usize) {
    let captures = wire.captures.lock().unwrap();
    assert_eq!(captures.len(), count);
    for capture in captures.iter() {
        assert_eq!(
            capture.target,
            "POST /tenant/v1/chat/completions?scope=refusal-component HTTP/1.1"
        );
        assert_eq!(
            capture
                .headers
                .iter()
                .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                .collect::<Vec<_>>(),
            [wire.authority.as_str()]
        );
        assert!(
            !capture
                .headers
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
        );
        let body: Value = serde_json::from_slice(&capture.body).unwrap();
        assert_eq!(body["model"], "component/raw");
        assert_eq!(body["max_tokens"], 73);
    }
}

#[test]
fn genuine_qualified_retry_has_fresh_ids_one_retry_and_sticky_unknown_full_bill() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 17), Reply::success()]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 2);
    let policy = policy(&selected, 2);
    let mut transcript = Vec::new();
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_wire(&wire, 2);
    assert!(matches!(result.completion().end, TurnEnd::Completed));
    assert_eq!(retries(&events), 1);
    assert!(matches!(
        events
            .iter()
            .find(|event| matches!(event, FrontendEvent::Retrying { .. }))
            .unwrap(),
        FrontendEvent::Retrying {
            attempt: 1,
            retry_in_ms: 1000..=1249,
            ..
        }
    ));
    assert_eq!(journal.counts(), (2, 1, 1));
    assert_eq!(journal.calls("refusal"), 1);
    assert_eq!(journal.calls("normal"), 1);
    let state = journal.state.lock().unwrap();
    let first = state.begins[0].1.as_ref().unwrap();
    let second = state.begins[1].1.as_ref().unwrap();
    assert_ne!(first.request_id(), second.request_id());
    assert_ne!(first.decision_id(), second.decision_id());
    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_eq!(first.body_digest(), second.body_digest());
    assert_eq!(first.route_digest(), second.route_digest());
    assert_eq!(first.policy_digest(), second.policy_digest());
    let decisions = vec![
        first.decision_id().to_owned(),
        second.decision_id().to_owned(),
    ];
    assert_eq!(result.refusals(), state.refused.as_slice());
    assert_eq!(
        state.receipts[0].usage,
        Some(ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 3,
            cache_write_tokens: 0,
            reasoning_tokens: 5
        })
    );
    drop(state);
    let egress: Vec<_> = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0
        .into_iter()
        .filter_map(|entry| match entry.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, OWNER);
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(egress, decisions);
    let captured = wire.captures.lock().unwrap();
    assert_eq!(captured[0].body, captured[1].body);
    drop(captured);
    assert_eq!(
        transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
            .count(),
        1
    );
    assert_eq!(
        transcript
            .iter()
            .filter(|message| message.role == ChatRole::Assistant && message.content == ANSWER)
            .count(),
        1
    );
    let report = &result.completion().report;
    assert_eq!(report.rounds, 1);
    assert_eq!(
        (
            report.input_tokens,
            report.output_tokens,
            report.cost_microcents
        ),
        (11, 7, 13)
    );
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(
        report.accounting.ordinary,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: None
        }
    );
    assert_eq!(
        report.accounting.knownness,
        AccountingKnownness::UnknownUsage
    );
    let checkpoint = journal.snapshot();
    assert_eq!(checkpoint.revision(), AccountingRevision(4));
    assert!(checkpoint.pending().is_none());
    assert_eq!(checkpoint.totals(), &report.accounting);
    assert_eq!(
        checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: 13,
            housekeeping_microcents: 0
        })
    );
    assert_eq!(checkpoint.refusals().unwrap().count(), 1);
}

#[test]
fn zero_ceiling_blocks_even_otherwise_automatic_summary_input_before_any_post() {
    let home = Home::new();
    let mut wire = Wire::new(vec![]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let mut options = options(&selected, journal.clone(), 0);
    options.selected_budget =
        Some(orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 1000).unwrap());
    options.compaction_config = Some(selected.clone());
    options.compaction_budget =
        Some(orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 12000).unwrap());
    let policy = policy(&selected, 2);
    let mut transcript: Vec<_> = (0..12)
        .map(|index| {
            let text = format!("history-{index}: {}", "preserve ".repeat(50));
            if index % 2 == 0 {
                orbit_engine::user_message(text)
            } else {
                orbit_engine::assistant_message(text)
            }
        })
        .collect();
    let original = transcript.clone();
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_wire(&wire, 0);
    assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
    assert_eq!(journal.counts(), (0, 0, 0));
    assert_eq!(journal.snapshot().revision(), AccountingRevision(0));
    assert_eq!(retries(&events), 0);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Compacting { .. }))
    );
    assert_eq!(transcript, original);

    // Positive control uses the same source and real, unchanged summary path.
    // Its old component store is intentionally separate from qualified storage.
    let control_home = Home::new();
    let mut control_wire = Wire::new(vec![Reply::success(), Reply::success()]);
    let control_config = config(&control_wire);
    let control_options = TurnOptions {
        session_id: OWNER.into(),
        max_attempts: 1,
        max_rounds: 1,
        journal: Some(compaction_journal::MemoryJournal::fresh(OWNER)),
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&control_config, 1000)
                .unwrap(),
        ),
        compaction_config: Some(control_config.clone()),
        compaction_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&control_config, 12000)
                .unwrap(),
        ),
        system_directive: options.system_directive.clone(),
        ..Default::default()
    };
    let (control, control_events) = invoke(
        &control_home,
        &control_config,
        &control_options,
        PROMPT,
        &mut original.clone(),
        &CancelToken::new(),
        None,
        false,
    );
    control_wire.finish();
    assert_wire(&control_wire, 2);
    assert!(matches!(control.completion().end, TurnEnd::Completed));
    assert!(
        control_events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Compacting { .. }))
    );
    let control_captures = control_wire.captures.lock().unwrap();
    let summary: Value = serde_json::from_slice(&control_captures[0].body).unwrap();
    assert!(
        summary["messages"]
            .to_string()
            .contains("Summarize this conversation for continuation.")
    );
}

#[test]
fn policy_and_existing_attempt_ceilings_intersect_without_raising_one() {
    for (caller, policy_max, expected) in [(1, 8, 1), (3, 2, 2), (2, 8, 2)] {
        let home = Home::new();
        let mut wire = Wire::new((0..expected).map(|_| Reply::rejection(503, 1)).collect());
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
        let options = options(&selected, journal.clone(), caller);
        let policy = policy(&selected, policy_max);
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, expected);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert_eq!(result.refusals().len(), expected);
        assert_eq!(journal.counts(), (expected, 0, expected));
        assert_eq!(retries(&events), expected - 1);
        assert!(journal.snapshot().pending().is_none());
    }
}

#[test]
fn selected_policy_refuses_no_journal_caps_compacting_and_wrong_selection_before_send() {
    for kind in [
        "no-journal",
        "cap",
        "compacting",
        "provider",
        "model",
        "endpoint",
        "namespace",
        "budget",
    ] {
        let home = Home::new();
        let mut wire = Wire::new(vec![]);
        let mut selected = config(&wire);
        let policy = policy(&selected, 2);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(
            if kind == "namespace" {
                "other-owner"
            } else {
                OWNER
            },
            Fault::None,
            CancelAt::None,
            &cancel,
        );
        let mut options = options(&selected, journal.clone(), 2);
        match kind {
            "no-journal" => options.journal = None,
            "cap" => {
                options.spend_allowance = Some(SpendAllowance {
                    remaining_microcents: 100,
                    allow_unpriced_housekeeping: true,
                })
            }
            "compacting" => options.compacting = true,
            "provider" => selected.provider_id = "other-provider".into(),
            "model" => selected.model = "other/model".into(),
            "endpoint" => selected.gate.push_str("-changed"),
            "namespace" | "budget" => {}
            _ => unreachable!(),
        }
        options.selected_budget = Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8000).unwrap(),
        );
        if kind == "budget" {
            options
                .selected_budget
                .as_mut()
                .unwrap()
                .ceilings
                .output_tokens = Some(72);
        }
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 0);
        assert!(
            matches!(result.completion().end, TurnEnd::Failed(_)),
            "accepted {kind}"
        );
        assert_eq!(journal.counts(), (0, 0, 0));
        assert_eq!(journal.calls("begin"), 0);
        assert_eq!(retries(&events), 0);
    }
}

#[test]
fn none_policy_new_invocation_preserves_history_but_reports_only_its_own_success() {
    let home = Home::new();
    let mut wire = Wire::new(vec![
        Reply::rejection(503, 1),
        Reply::success(),
        Reply::success(),
    ]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 2);
    let policy = policy(&selected, 2);
    let mut transcript = Vec::new();
    let (first, _) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    assert!(matches!(first.completion().end, TurnEnd::Completed));
    let old_rollup = journal.snapshot().refusals().cloned().unwrap();
    let (second, events) = invoke(
        &home,
        &selected,
        &options,
        "new explicit controlled prompt",
        &mut transcript,
        &cancel,
        None,
        false,
    );
    wire.finish();
    assert_wire(&wire, 3);
    assert!(matches!(second.completion().end, TurnEnd::Completed));
    assert!(second.refusals().is_empty());
    assert_eq!(retries(&events), 0);
    let report = &second.completion().report;
    assert_eq!(
        (
            report.input_tokens,
            report.output_tokens,
            report.cost_microcents
        ),
        (11, 7, 13)
    );
    assert_eq!(report.accounting.knownness, AccountingKnownness::Known);
    assert_eq!(report.accounting.ordinary.cost_microcents, Some(13));
    assert_eq!(journal.snapshot().refusals(), Some(&old_rollup));
    assert_eq!(
        journal.snapshot().totals().ordinary,
        AccountingTotals {
            input_tokens: 22,
            output_tokens: 14,
            cost_microcents: None
        }
    );
    assert_eq!(
        journal
            .snapshot()
            .known_priced_subtotals()
            .unwrap()
            .ordinary_microcents,
        26
    );
    let state = journal.state.lock().unwrap();
    assert!(state.begins[2].1.is_none());
    assert_ne!(state.begins[2].0.request_id, state.begins[0].0.request_id);
    assert_ne!(state.begins[2].0.request_id, state.begins[1].0.request_id);
}

#[test]
fn no_policy_complete_http_rejection_never_replays_or_mints_refusal() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 8)]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 3);
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut Vec::new(),
        &cancel,
        None,
        false,
    );
    wire.finish();
    assert_wire(&wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
    assert!(result.refusals().is_empty());
    assert_eq!(journal.counts(), (1, 1, 0));
    assert_eq!(journal.calls("refusal"), 0);
    assert_eq!(retries(&events), 0);
    assert!(journal.snapshot().pending().unwrap().uncertain);
    assert_eq!(
        journal.snapshot().totals().knownness,
        AccountingKnownness::Uncertain
    );
}

#[test]
fn oversized_truncated_and_admitted_error_responses_never_authorize_replay() {
    for kind in ["body-cap", "truncated", "admitted", "partial"] {
        let home = Home::new();
        let reply = match kind {
            "body-cap" => Reply::rejection(503, 65_537),
            "truncated" => Reply {
                extra_length: 100,
                ..Reply::rejection(503, 17)
            },
            "admitted" => Reply::admitted_malformed(false),
            "partial" => Reply::admitted_malformed(true),
            _ => unreachable!(),
        };
        let mut wire = Wire::new(vec![reply]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        let mut transcript = Vec::new();
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut transcript,
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert!(result.refusals().is_empty());
        assert_eq!(retries(&events), 0);
        assert_eq!(journal.counts(), (1, 1, 0));
        assert_eq!(journal.calls("refusal"), 0);
        assert!(journal.snapshot().pending().unwrap().uncertain);
        let state = journal.state.lock().unwrap();
        assert_eq!(state.receipts[0].knownness, AccountingKnownness::Uncertain);
        assert_eq!(state.receipts[0].totals.cost_microcents, None);
        if kind == "partial" {
            assert!(state.receipts[0].usage.is_none());
            assert!(
                transcript
                    .iter()
                    .any(|message| message.role == ChatRole::Assistant
                        && message.content == "kept partial text")
            );
        }
    }
}

#[test]
fn incomplete_rejection_body_cancellation_cannot_become_a_final_refusal() {
    let home = Home::new();
    let cancel = CancelToken::new();
    let mut reply = Reply::rejection(503, 17);
    reply.cancel_before_eof = Some(cancel.clone());
    let mut wire = Wire::new(vec![reply]);
    let selected = config(&wire);
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 2);
    let policy = policy(&selected, 2);
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut Vec::new(),
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_wire(&wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert!(result.refusals().is_empty());
    assert_eq!(journal.counts(), (1, 1, 0));
    assert_eq!(journal.calls("refusal"), 0);
    assert_eq!(retries(&events), 0);
    assert!(journal.snapshot().pending().unwrap().uncertain);
}

#[test]
fn begin_failure_or_bad_returned_reference_never_enters_dispatch() {
    for (fault, cancel_at) in [
        (Fault::Begin, CancelAt::None),
        (Fault::Begin, CancelAt::BeginEntry),
        (Fault::BadBeginReference, CancelAt::None),
    ] {
        let home = Home::new();
        let mut wire = Wire::new(vec![]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, fault, cancel_at, &cancel);
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 0);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert_eq!(journal.calls("begin"), 1);
        assert_eq!(journal.calls("normal"), 0);
        assert_eq!(journal.calls("refusal"), 0);
        assert_eq!(retries(&events), 0);
    }
}

#[test]
fn refusal_settlement_and_lost_ack_errors_outrank_racing_cancellation_without_second_settlement() {
    for (fault, cancel_at) in [
        (Fault::RefusalBefore, CancelAt::None),
        (Fault::RefusalBefore, CancelAt::RefusalEntry),
        (Fault::RefusalAfter, CancelAt::None),
        (Fault::RefusalAfter, CancelAt::RefusalEntry),
        (Fault::RefusalAfter, CancelAt::RefusalAck),
    ] {
        let home = Home::new();
        let mut wire = Wire::new(vec![Reply::rejection(503, 8)]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, fault, cancel_at, &cancel);
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 1);
        assert!(
            matches!(result.completion().end, TurnEnd::Failed(_)),
            "masked accounting error {fault:?}/{cancel_at:?}"
        );
        assert_eq!(journal.calls("refusal"), 1);
        assert_eq!(journal.calls("normal"), 0);
        assert_eq!(retries(&events), 0);
        assert!(result.refusals().is_empty());
        let report = &result.completion().report;
        assert_eq!(report.accounting.knownness, AccountingKnownness::Uncertain);
        assert_eq!(report.accounting.ordinary.cost_microcents, None);
        assert!(report.attempts.is_empty());
        assert_eq!(
            journal.snapshot().pending().is_some(),
            fault == Fault::RefusalBefore
        );
        assert_eq!(
            journal.snapshot().refusals().is_some(),
            fault == Fault::RefusalAfter
        );
    }
}

#[test]
fn earlier_genuine_component_ack_cannot_acknowledge_a_new_live_refusal() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 8), Reply::rejection(503, 8)]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::PriorAck, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 1);
    let policy = policy(&selected, 2);
    let mut transcript = Vec::new();
    let (first, _) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    assert_eq!(first.refusals().len(), 1);
    let old_attempt = first.refusals()[0].attempt().clone();
    // The fault returns an unchanged ACK actually created for the prior live
    // operation. It does not manufacture a checkpoint or mutate proof hashes.
    let (second, events) = invoke(
        &home,
        &selected,
        &options,
        "new explicit refusal",
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_wire(&wire, 2);
    assert!(matches!(second.completion().end, TurnEnd::Failed(_)));
    assert!(second.refusals().is_empty());
    let report = &second.completion().report;
    assert_eq!(report.accounting.knownness, AccountingKnownness::Uncertain);
    assert_eq!(report.accounting.ordinary.cost_microcents, None);
    assert!(report.attempts.is_empty());
    assert_eq!(retries(&events), 0);
    assert_eq!(journal.counts(), (2, 0, 2));
    assert_eq!(journal.calls("normal"), 0);
    let checkpoint = journal.snapshot();
    assert!(checkpoint.pending().is_none());
    assert_eq!(checkpoint.refusals().unwrap().count(), 2);
    assert_ne!(
        checkpoint.refusals().unwrap().latest().attempt(),
        &old_attempt
    );
}

#[test]
fn normal_settlement_errors_outrank_racing_cancellation_and_preserve_partial_text() {
    for (fault, cancel_at) in [
        (Fault::NormalBefore, CancelAt::NormalEntry),
        (Fault::NormalAfter, CancelAt::NormalEntry),
        (Fault::NormalAfter, CancelAt::NormalAck),
    ] {
        let home = Home::new();
        let mut wire = Wire::new(vec![Reply::success()]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, fault, cancel_at, &cancel);
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        let mut transcript = Vec::new();
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut transcript,
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert_eq!(journal.calls("normal"), 1);
        assert_eq!(journal.calls("refusal"), 0);
        assert_eq!(retries(&events), 0);
        assert!(result.refusals().is_empty());
        let report = &result.completion().report;
        assert_eq!(report.accounting.knownness, AccountingKnownness::Uncertain);
        assert_eq!(report.accounting.ordinary.cost_microcents, None);
        assert_eq!(
            (
                report.input_tokens,
                report.output_tokens,
                report.cost_microcents
            ),
            (11, 7, 13)
        );
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].knownness, AccountingKnownness::Known);
        assert!(
            transcript
                .iter()
                .any(|message| message.role == ChatRole::Assistant && message.content == ANSWER)
        );
        assert_eq!(
            journal.snapshot().pending().is_some(),
            fault == Fault::NormalBefore
        );
    }
}

#[test]
fn cancellation_before_or_after_begin_uses_only_positive_not_sent_receipt() {
    for before_begin in [true, false] {
        let home = Home::new();
        let mut wire = Wire::new(vec![]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(
            OWNER,
            Fault::None,
            if before_begin {
                CancelAt::None
            } else {
                CancelAt::Begin(1)
            },
            &cancel,
        );
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        if before_begin {
            cancel.cancel();
        }
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 0);
        assert!(matches!(result.completion().end, TurnEnd::Cancelled));
        assert!(result.refusals().is_empty());
        assert_eq!(retries(&events), 0);
        assert_eq!(
            journal.counts(),
            if before_begin { (0, 0, 0) } else { (1, 1, 0) }
        );
        assert!(journal.snapshot().pending().is_none());
        if !before_begin {
            let state = journal.state.lock().unwrap();
            assert_eq!(state.receipts[0].knownness, AccountingKnownness::Known);
            assert!(!state.receipts[0].completed);
            assert!(state.receipts[0].usage.is_none());
            assert_eq!(state.receipts[0].totals, AccountingTotals::known_zero());
        }
    }
}

#[test]
fn cancellation_after_live_refusal_construction_finishes_one_settlement_and_retains_it() {
    for cancel_at in [CancelAt::RefusalEntry, CancelAt::RefusalAck] {
        let home = Home::new();
        let mut wire = Wire::new(vec![Reply::rejection(503, 8)]);
        let selected = config(&wire);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, Fault::None, cancel_at, &cancel);
        let options = options(&selected, journal.clone(), 2);
        let policy = policy(&selected, 2);
        let (result, events) = invoke(
            &home,
            &selected,
            &options,
            PROMPT,
            &mut Vec::new(),
            &cancel,
            Some(&policy),
            false,
        );
        wire.finish();
        assert_wire(&wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Cancelled));
        assert_eq!(result.refusals().len(), 1);
        assert_eq!(journal.counts(), (1, 0, 1));
        assert_eq!(journal.calls("refusal"), 1);
        assert_eq!(journal.calls("normal"), 0);
        assert_eq!(retries(&events), 0);
        assert!(journal.snapshot().pending().is_none());
        assert_eq!(
            result.completion().report.accounting.knownness,
            AccountingKnownness::UnknownUsage
        );
    }
}

#[test]
fn cancellation_in_retry_event_never_starts_a_second_attempt() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 8)]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let options = options(&selected, journal.clone(), 2);
    let policy = policy(&selected, 2);
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut Vec::new(),
        &cancel,
        Some(&policy),
        true,
    );
    wire.finish();
    assert_wire(&wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert_eq!(result.refusals().len(), 1);
    assert_eq!(journal.counts(), (1, 0, 1));
    assert_eq!(retries(&events), 1);
    assert!(journal.snapshot().pending().is_none());
}

#[test]
fn cancellation_after_second_begin_settles_not_sent_without_replaying_first_refusal() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 8)]);
    let selected = config(&wire);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::Begin(2), &cancel);
    let options = options(&selected, journal.clone(), 2);
    let policy = policy(&selected, 2);
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        PROMPT,
        &mut Vec::new(),
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_wire(&wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert_eq!(journal.counts(), (2, 1, 1));
    assert_eq!(result.refusals().len(), 1);
    assert_eq!(retries(&events), 1);
    assert!(journal.snapshot().pending().is_none());
    let state = journal.state.lock().unwrap();
    assert_eq!(state.receipts[0].totals, AccountingTotals::known_zero());
    assert!(state.receipts[0].usage.is_none() && !state.receipts[0].completed);
    assert_ne!(
        state.receipts[0].request_id,
        state.refused[0].attempt().request_id
    );
    assert_eq!(state.checkpoint.refusals().unwrap().count(), 1);
}

const SUMMARY_TEXT: &str = "short controlled historical summary";
const HIDDEN_ORIGINAL: &str = "PRIVATE-ORIGINAL-SUMMARY-THOUGHT";

fn summary_pair(source: &mut Vec<ChatMessage>, label: &str, bytes: usize) {
    source.push(orbit_engine::user_message(format!(
        "{label}-USER {} {label}-USER-END",
        "u".repeat(bytes)
    )));
    source.push(orbit_engine::assistant_message(format!(
        "{label}-ASSISTANT {} {label}-ASSISTANT-END",
        "a".repeat(bytes)
    )));
}
fn summary_history(groups: usize, bytes: usize, typed: bool) -> Vec<ChatMessage> {
    let mut source = vec![ChatMessage {
        role: ChatRole::System,
        ..orbit_engine::user_message("exact immutable summary system")
    }];
    if typed {
        source.push(orbit_engine::user_message(format!(
            "{}OLD-VISIBLE-LATE",
            "u".repeat(4000)
        )));
        let mut call = orbit_engine::assistant_message("visible old action");
        call.tool_calls = Some(vec![ToolCallMessage {
            id: "old-summary-call".into(),
            name: "inspect".into(),
            arguments: format!("{{\"path\":\"{}OLD-ARGS-LATE\"}}", "a".repeat(900)),
        }]);
        source.push(call);
        let mut result = orbit_engine::user_message("unused fallback");
        result.role = ChatRole::Tool;
        result.tool_call_id = Some("old-summary-call".into());
        result.tool_result = Some(format!("{}OLD-RESULT-LATE", "r".repeat(900)));
        source.push(result);
        let mut done = orbit_engine::assistant_message("visible old completion");
        done.blocks = Some(vec![ContentBlock::Opaque { json: json!({"type":"thinking","thinking":HIDDEN_ORIGINAL,"signature":"private-original-signature"}).to_string() }]);
        done.origin_provider = Some("foreign".into());
        done.origin_model = Some("foreign".into());
        source.push(done);
    }
    for index in 0..groups {
        summary_pair(&mut source, &format!("OLDER-{index}"), bytes);
    }
    summary_pair(&mut source, "LATEST", 0);
    summary_pair(&mut source, "PRIOR-INTENT", 0);
    source
}
fn summary_selection(selected: &TurnConfig) -> TurnConfig {
    let mut summary = selected.clone();
    summary.provider_id = "summary-provider".into();
    summary.model = "summary/raw".into();
    summary.pricing.as_mut().unwrap().request_flat_microcents = 17;
    summary.billing = Some(test_billing("summary-provider", "summary/raw", 17));
    summary
}
fn summary_options(
    selected: &TurnConfig,
    journal: &Arc<ComponentJournal>,
    main_window: u64,
    summary_window: u64,
) -> TurnOptions {
    let summary = summary_selection(selected);
    TurnOptions {
        session_id: OWNER.into(),
        request_stem: "qualified-summary".into(),
        max_attempts: 1,
        max_rounds: 1,
        system_directive: Some("exact immutable selected directive".into()),
        tools: vec![ToolDefinition {
            name: "inspect".into(),
            description: "inspect exact state".into(),
            parameters: json!({"type":"object"}),
            schema_digest: Sha256Digest("fixture".into()),
        }],
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(selected, main_window)
                .unwrap(),
        ),
        compaction_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&summary, summary_window)
                .unwrap(),
        ),
        compaction_config: Some(summary),
        journal: Some(journal.clone()),
        ..Default::default()
    }
}
fn summary_seed(
    home: &Home,
    wire: &Wire,
    journal: &Arc<ComponentJournal>,
    source: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
) -> TurnConfig {
    let selected = config(wire);
    let mut options = options(&selected, journal.clone(), 2);
    options.selected_budget = Some(
        orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 80_000).unwrap(),
    );
    let binding = policy(&selected, 2);
    let (result, events) = invoke(
        home,
        &selected,
        &options,
        PROMPT,
        source,
        cancel,
        Some(&binding),
        false,
    );
    assert!(matches!(result.completion().end, TurnEnd::Completed));
    assert_eq!(retries(&events), 1);
    assert_eq!(result.refusals().len(), 1);
    assert_eq!(journal.counts(), (2, 1, 1));
    assert!(journal.archives().is_empty());
    assert_eq!(
        journal.snapshot().refusals().unwrap().latest(),
        &result.refusals()[0]
    );
    assert_eq!(wire.captures.lock().unwrap().len(), 2);
    selected
}
fn manual_summary(
    home: &Home,
    selected: &TurnConfig,
    options: &TurnOptions,
    source: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
) -> (orbit_engine::ManualCompactionCompletion, Vec<FrontendEvent>) {
    let mut events = Vec::new();
    let result = orbit_engine::compact_context_detailed(
        &home.0,
        selected,
        options,
        source,
        cancel,
        &mut |event| {
            assert!(events.len() < 256);
            events.push(event);
        },
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        FrontendEvent::TextDelta { .. }
            | FrontendEvent::ResponseFinished { .. }
            | FrontendEvent::TurnEnded { .. }
            | FrontendEvent::RoundStarted { .. }
            | FrontendEvent::Retrying { .. }
    )));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
            .count(),
        usize::from(result.applied)
    );
    for event in &events {
        if let FrontendEvent::Compacted { summary, .. } = event {
            assert!(summary.is_empty());
        }
    }
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains(HIDDEN_ORIGINAL)
    );
    (result, events)
}
fn assert_summary_delta(
    delta: &AccountingDelta,
    attempts: &[RequestAccountingReceipt],
    count: usize,
) {
    assert_eq!(attempts.len(), count);
    assert_eq!(delta.ordinary, AccountingTotals::known_zero());
    assert_eq!(
        delta.housekeeping,
        AccountingTotals {
            input_tokens: 11 * count as u64,
            output_tokens: 7 * count as u64,
            cost_microcents: Some(17 * count as u64)
        }
    );
    assert_eq!(delta.knownness, AccountingKnownness::Known);
    for attempt in attempts {
        assert!(matches!(
            attempt.purpose,
            AttemptPurpose::Chunk | AttemptPurpose::Merge
        ));
        assert!(attempt.completed);
        assert_eq!(attempt.knownness, AccountingKnownness::Known);
        assert_eq!(
            attempt.usage,
            Some(ProviderUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_read_tokens: 3,
                cache_write_tokens: 0,
                reasoning_tokens: 5
            })
        );
        assert_eq!(attempt.totals.cost_microcents, Some(17));
    }
}
fn assert_summary_namespace(
    journal: &ComponentJournal,
    historical: &RefusalRollup,
    summary_count: usize,
    ordinary_successes: u64,
) {
    let checkpoint = journal.snapshot();
    assert!(checkpoint.pending().is_none());
    assert_eq!(checkpoint.refusals(), Some(historical));
    assert_eq!(
        checkpoint.totals().knownness,
        AccountingKnownness::UnknownUsage
    );
    assert_eq!(
        checkpoint.totals().ordinary,
        AccountingTotals {
            input_tokens: 11 * ordinary_successes,
            output_tokens: 7 * ordinary_successes,
            cost_microcents: None
        }
    );
    assert_eq!(
        checkpoint.totals().housekeeping,
        AccountingTotals {
            input_tokens: 11 * summary_count as u64,
            output_tokens: 7 * summary_count as u64,
            cost_microcents: Some(17 * summary_count as u64)
        }
    );
    assert_eq!(
        checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: 13 * ordinary_successes,
            housekeeping_microcents: 17 * summary_count as u64
        })
    );
}
fn assert_summary_archive(
    archive: &ComponentArchive,
    journal: &ComponentJournal,
    original: &[ChatMessage],
    options: &TurnOptions,
    count: usize,
) {
    assert_eq!(archive.source, original);
    assert_eq!(
        archive.conversation_budget,
        options.selected_budget.as_ref().unwrap().identity
    );
    assert_eq!(
        archive.summary_budget,
        options.compaction_budget.as_ref().unwrap().identity
    );
    assert_summary_delta(&archive.accounting, &archive.attempts, count);
    let checkpoint = &archive.checkpoint;
    assert!(checkpoint.pending().is_none());
    let Some(DetailedLastSettlement::Legacy(last)) = checkpoint.last_settlement() else {
        panic!("summary publication lacks its actual Legacy receipt");
    };
    let receipt = archive.attempts.last().unwrap();
    assert_eq!(last.reference.request_id, receipt.request_id);
    assert_eq!(last.receipt_digest, receipt.digest().unwrap());
    assert_eq!(last.reference.revision.0 + 1, checkpoint.revision().0);
    let state = journal.state.lock().unwrap();
    for receipt in &archive.attempts {
        let (intent, binding) = state
            .begins
            .iter()
            .find(|(intent, _)| intent.request_id == receipt.request_id)
            .unwrap();
        assert!(binding.is_none());
        assert_eq!(intent.owner_session_id, OWNER);
        assert!(intent.child_id.is_none());
        assert_eq!(intent.purpose, receipt.purpose);
        assert_eq!(intent.budget, archive.summary_budget);
        if receipt.request_id == last.reference.request_id {
            assert_eq!(intent.digest().unwrap(), last.reference.intent_digest);
        }
    }
    drop(state);
    assert_eq!(
        compaction_journal::encode_archive(&archive.source, &archive.candidate, &archive.receipt())
            .unwrap(),
        archive.bytes
    );
}
fn assert_summary_wire(
    home: &Home,
    journal: &ComponentJournal,
    wire: &Wire,
    summary_posts: usize,
    ordinary_posts: usize,
) {
    let captures = wire.captures.lock().unwrap();
    assert_eq!(captures.len(), summary_posts + ordinary_posts);
    let mut summary_count = 0;
    for capture in captures.iter() {
        assert_eq!(
            capture.target,
            "POST /tenant/v1/chat/completions?scope=refusal-component HTTP/1.1"
        );
        assert_eq!(
            capture
                .headers
                .iter()
                .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                .collect::<Vec<_>>(),
            [wire.authority.as_str()]
        );
        assert!(
            !capture
                .headers
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
        );
        let body: Value = serde_json::from_slice(&capture.body).unwrap();
        if body["model"] == "summary/raw" {
            summary_count += 1;
            assert!(body.get("tools").is_none() && body.get("tool_choice").is_none());
            assert!(!body["messages"].to_string().contains(HIDDEN_ORIGINAL));
        } else {
            assert_eq!(body["model"], "component/raw");
        }
        assert_eq!(body["max_tokens"], 73);
    }
    assert_eq!(summary_count, summary_posts);
    drop(captures);
    let state = journal.state.lock().unwrap();
    let mut fresh = BTreeSet::new();
    let expected: Vec<_> = state
        .begins
        .iter()
        .filter_map(|(intent, binding)| {
            assert!(fresh.insert(intent.request_id.clone()));
            if intent.purpose != AttemptPurpose::Ordinary {
                assert!(binding.is_none());
            }
            if state.receipts.iter().any(|receipt| {
                receipt.request_id == intent.request_id
                    && !receipt.completed
                    && receipt.knownness == AccountingKnownness::Known
                    && receipt.usage.is_none()
                    && receipt.totals == AccountingTotals::known_zero()
            }) {
                return None;
            }
            Some(binding.as_ref().map_or_else(
                || intent.request_id.clone(),
                |binding| binding.decision_id().to_owned(),
            ))
        })
        .collect();
    drop(state);
    let actual: Vec<_> = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0
        .into_iter()
        .filter_map(|entry| match entry.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, OWNER);
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(actual.len(), summary_posts + ordinary_posts);
    assert_eq!(actual, expected);
}

#[test]
fn summary_manual_after_refusal_preserves_full_original_and_qualified_bill() {
    let home = Home::new();
    let mut wire = Wire::new(vec![
        Reply::rejection(503, 17),
        Reply::success(),
        Reply::text(SUMMARY_TEXT),
    ]);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let mut source = summary_history(3, 1800, true);
    let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
    let historical = journal.snapshot().refusals().cloned().unwrap();
    let original = source.clone();
    let options = summary_options(&selected, &journal, 1000, 12_000);
    let (result, _) = manual_summary(&home, &selected, &options, &mut source, &cancel);
    wire.finish();
    assert_eq!(result.status, CompactionStatus::PublishedReady);
    assert!(result.applied);
    assert_summary_delta(&result.accounting, &result.attempts, 1);
    assert_eq!(source[0], original[0]);
    assert_eq!(
        source[1],
        orbit_engine::user_message("[Earlier conversation summary: historical data]")
    );
    assert_eq!(source[2], orbit_engine::assistant_message(SUMMARY_TEXT));
    assert!(original.ends_with(&source[3..]));
    assert_eq!(&source[source.len() - 2..], &original[original.len() - 2..]);
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].candidate.messages(), source.as_slice());
    assert_eq!(archives[0].attempts, result.attempts);
    assert_summary_archive(&archives[0], &journal, &original, &options, 1);
    assert_eq!(archives[0].checkpoint, journal.snapshot());
    assert!(
        serde_json::to_string(&archives[0].source)
            .unwrap()
            .contains(HIDDEN_ORIGINAL)
    );
    assert_summary_namespace(&journal, &historical, 1, 1);
    assert_eq!(journal.counts(), (3, 2, 1));
    assert_summary_wire(&home, &journal, &wire, 1, 2);
}

#[test]
fn summary_automatic_after_refusal_uses_publication_checkpoint_and_current_delta() {
    let home = Home::new();
    let mut wire = Wire::new(vec![
        Reply::rejection(503, 17),
        Reply::success(),
        Reply::text(SUMMARY_TEXT),
        Reply::success(),
    ]);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let mut source = summary_history(3, 1800, true);
    let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
    let historical = journal.snapshot().refusals().cloned().unwrap();
    let before = source.clone();
    let options = summary_options(&selected, &journal, 1000, 12_000);
    let next_prompt = "new current intent after historical refusal";
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        next_prompt,
        &mut source,
        &cancel,
        None,
        false,
    );
    wire.finish();
    assert!(matches!(result.completion().end, TurnEnd::Completed));
    assert!(result.refusals().is_empty());
    assert_eq!(retries(&events), 0);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacting { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
            .count(),
        1
    );
    let report = &result.completion().report;
    assert_eq!(report.attempts.len(), 2);
    assert_eq!(report.accounting.knownness, AccountingKnownness::Known);
    assert_eq!(
        report.accounting.ordinary,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: Some(13)
        }
    );
    assert_eq!(
        report.accounting.housekeeping,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: Some(17)
        }
    );
    assert_eq!(
        (
            report.input_tokens,
            report.output_tokens,
            report.cost_microcents
        ),
        (22, 14, 30)
    );
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    let mut exact_original = before;
    exact_original.push(orbit_engine::user_message(next_prompt));
    assert_summary_archive(&archives[0], &journal, &exact_original, &options, 1);
    assert_eq!(source[0], exact_original[0]);
    assert!(
        source
            .iter()
            .any(|message| message.role == ChatRole::User && message.content == next_prompt)
    );
    assert_eq!(source.last().unwrap().content, ANSWER);
    assert_eq!(
        source
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == next_prompt)
            .count(),
        1
    );
    let final_checkpoint = journal.snapshot();
    assert!(
        matches!(final_checkpoint.last_settlement(), Some(DetailedLastSettlement::Legacy(last)) if last.reference.request_id == report.attempts[1].request_id)
    );
    assert_ne!(
        archives[0].checkpoint.revision(),
        final_checkpoint.revision()
    );
    assert_summary_namespace(&journal, &historical, 1, 2);
    assert_summary_wire(&home, &journal, &wire, 1, 3);
}

#[test]
fn summary_partitioned_chunks_and_merge_keep_one_qualified_journal() {
    let home = Home::new();
    let mut wire = Wire::with_request_limit(
        vec![
            Reply::rejection(503, 17),
            Reply::success(),
            Reply::text("CHUNK-A-REPLY"),
            Reply::text("CHUNK-B-REPLY"),
            Reply::text(SUMMARY_TEXT),
        ],
        12,
    );
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let mut source = summary_history(2, 2400, false);
    let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
    let historical = journal.snapshot().refusals().cloned().unwrap();
    let original = source.clone();
    let options = summary_options(&selected, &journal, 1000, 2000);
    let (result, _) = manual_summary(&home, &selected, &options, &mut source, &cancel);
    wire.finish();
    assert!(result.applied);
    assert_eq!(result.status, CompactionStatus::PublishedReady);
    assert_eq!(
        result
            .attempts
            .iter()
            .map(|attempt| attempt.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Merge
        ]
    );
    assert_summary_delta(&result.accounting, &result.attempts, 3);
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_summary_archive(&archives[0], &journal, &original, &options, 3);
    assert_summary_namespace(&journal, &historical, 3, 1);
    assert_summary_wire(&home, &journal, &wire, 3, 2);
    let captures = wire.captures.lock().unwrap();
    for capture in &captures[2..] {
        let body: Value = serde_json::from_slice(&capture.body).unwrap();
        assert!((serde_json::to_vec(&body).unwrap().len() as u64).div_ceil(4) <= 2000);
    }
    let merge: Value = serde_json::from_slice(&captures[4].body).unwrap();
    let merge_messages = merge["messages"].to_string();
    assert_eq!(merge_messages.matches("CHUNK-A-REPLY").count(), 1);
    assert_eq!(merge_messages.matches("CHUNK-B-REPLY").count(), 1);
}

#[test]
fn summary_none_continuation_preserves_historical_qualification() {
    let home = Home::new();
    let mut wire = Wire::new(vec![
        Reply::rejection(503, 17),
        Reply::success(),
        Reply::text(SUMMARY_TEXT),
        Reply::success(),
    ]);
    let cancel = CancelToken::new();
    let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
    let mut source = summary_history(3, 1800, true);
    let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
    let historical = journal.snapshot().refusals().cloned().unwrap();
    let summary_options = summary_options(&selected, &journal, 1000, 12_000);
    let (summary, _) = manual_summary(&home, &selected, &summary_options, &mut source, &cancel);
    assert!(summary.applied);
    let archive = journal.archives().remove(0);
    let continuation_options = options(&selected, journal.clone(), 2);
    let (result, events) = invoke(
        &home,
        &selected,
        &continuation_options,
        "explicit current None policy continuation",
        &mut source,
        &cancel,
        None,
        false,
    );
    assert!(matches!(result.completion().end, TurnEnd::Completed));
    assert!(result.refusals().is_empty());
    assert_eq!(retries(&events), 0);
    let report = &result.completion().report;
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.accounting.knownness, AccountingKnownness::Known);
    assert_eq!(
        report.accounting.ordinary,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: Some(13)
        }
    );
    assert_eq!(
        report.accounting.housekeeping,
        AccountingTotals::known_zero()
    );
    assert_eq!(
        (
            report.input_tokens,
            report.output_tokens,
            report.cost_microcents
        ),
        (11, 7, 13)
    );
    assert_summary_namespace(&journal, &historical, 1, 2);
    let before = journal.snapshot();
    let counts = journal.counts();
    assert_eq!(
        journal
            .publish(&archive.source, &archive.candidate, &archive.receipt())
            .unwrap(),
        archive.reference
    );
    assert_eq!(journal.snapshot(), before);
    assert_eq!(journal.counts(), counts);
    assert_eq!(journal.archives().len(), 1);
    let mut conflict = archive.receipt();
    conflict
        .conversation_budget
        .metadata_revision
        .push_str("-changed");
    assert_eq!(
        journal.publish(&archive.source, &archive.candidate, &conflict),
        Err(HistoryError::Conflict)
    );
    let mut new_operation = archive.receipt();
    new_operation.operation_id = "new-after-ordinary".into();
    assert_eq!(
        journal.publish(&archive.source, &archive.candidate, &new_operation),
        Err(HistoryError::Conflict)
    );
    assert_eq!(journal.snapshot(), before);
    assert_eq!(journal.archives()[0].bytes, archive.bytes);
    let state = journal.state.lock().unwrap();
    assert!(
        state.begins[2..]
            .iter()
            .all(|(_, binding)| binding.is_none())
    );
    drop(state);
    wire.finish();
    assert_summary_wire(&home, &journal, &wire, 1, 3);
}

#[test]
fn summary_caps_and_pending_refuse_before_summary_traffic() {
    for kind in ["cap", "cap-housekeeping-optin", "pending"] {
        let home = Home::new();
        let mut replies = vec![Reply::rejection(503, 17), Reply::success()];
        if kind == "pending" {
            replies.push(Reply::rejection(503, 17));
        }
        let mut wire = Wire::new(replies);
        let cancel = CancelToken::new();
        let journal = ComponentJournal::new(OWNER, Fault::None, CancelAt::None, &cancel);
        let mut source = summary_history(3, 1800, true);
        let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
        let historical = journal.snapshot().refusals().cloned().unwrap();
        if kind == "pending" {
            let mut ordinary = options(&selected, journal.clone(), 2);
            ordinary.selected_budget = Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 80_000)
                    .unwrap(),
            );
            let (result, events) = invoke(
                &home,
                &selected,
                &ordinary,
                "new uncertain ordinary invocation",
                &mut source,
                &cancel,
                None,
                false,
            );
            assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
            assert!(result.refusals().is_empty());
            assert_eq!(retries(&events), 0);
            assert!(journal.snapshot().pending().unwrap().uncertain);
        }
        let mut summary_options = summary_options(&selected, &journal, 1000, 12_000);
        if kind != "pending" {
            summary_options.spend_allowance = Some(SpendAllowance {
                remaining_microcents: 1000,
                allow_unpriced_housekeeping: kind == "cap-housekeeping-optin",
            });
        }
        let original = source.clone();
        let before = journal.snapshot();
        let counts = journal.counts();
        let (result, _) = manual_summary(&home, &selected, &summary_options, &mut source, &cancel);
        assert_eq!(
            result.status,
            if kind == "pending" {
                CompactionStatus::AccountingUncertain
            } else {
                CompactionStatus::SpendRefused
            }
        );
        assert!(!result.applied);
        assert!(result.attempts.is_empty());
        assert_eq!(result.accounting, AccountingDelta::known_zero());
        assert_eq!(source, original);
        assert_eq!(journal.snapshot(), before);
        assert_eq!(journal.counts(), counts);
        assert_eq!(journal.snapshot().refusals(), Some(&historical));
        assert!(journal.archives().is_empty());
        wire.finish();
        assert_summary_wire(
            &home,
            &journal,
            &wire,
            0,
            if kind == "pending" { 3 } else { 2 },
        );
    }
}

fn summary_authority_denials_use_real_candidates() {
    for kind in ["final-refusal", "pending", "not-sent", "earlier-budget"] {
        let home = Home::new();
        let cancel = CancelToken::new();
        let mut replies = vec![
            Reply::rejection(503, 17),
            Reply::success(),
            Reply::text(SUMMARY_TEXT),
        ];
        if matches!(kind, "final-refusal" | "pending") {
            replies.push(Reply::rejection(503, 17));
        }
        if kind == "earlier-budget" {
            replies.push(Reply::text(SUMMARY_TEXT));
        }
        let mut wire = Wire::new(replies);
        let journal = ComponentJournal::new(
            OWNER,
            Fault::None,
            if kind == "not-sent" {
                CancelAt::Begin(4)
            } else {
                CancelAt::None
            },
            &cancel,
        );
        let mut source = summary_history(3, 1800, true);
        let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
        let options = summary_options(&selected, &journal, 1000, 12_000);
        // Public service returns a genuine published candidate, without applying
        // it. The next negative uses this exact original candidate and source.
        let attempt = orbit_engine::compaction::compact_context(
            &home.0, &selected, &options, &source, &cancel,
        );
        assert_eq!(attempt.status, CompactionStatus::PublishedReady);
        let genuine_candidate = attempt.candidate.unwrap();
        let original = source.clone();
        let first_archive = journal.archives().remove(0);
        let mut proposed = first_archive.receipt();
        proposed.operation_id = format!("new-authority-{kind}");
        if matches!(kind, "final-refusal" | "pending") {
            let mut ordinary_options = crate::options(&selected, journal.clone(), 1);
            ordinary_options.selected_budget = Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 80_000)
                    .unwrap(),
            );
            let binding = policy(&selected, 2);
            let (result, events) = invoke(
                &home,
                &selected,
                &ordinary_options,
                "later real ordinary activity",
                &mut source,
                &cancel,
                if kind == "final-refusal" {
                    Some(&binding)
                } else {
                    None
                },
                false,
            );
            assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
            assert_eq!(retries(&events), 0);
            if kind == "final-refusal" {
                assert_eq!(result.refusals().len(), 1);
                assert!(matches!(
                    journal.snapshot().last_settlement(),
                    Some(DetailedLastSettlement::FinalRefusal(_))
                ));
            } else {
                assert!(journal.snapshot().pending().unwrap().uncertain);
            }
            assert_eq!(
                journal
                    .publish(&original, &genuine_candidate, &first_archive.receipt())
                    .unwrap(),
                first_archive.reference
            );
        } else if kind == "not-sent" {
            let (cancelled, _) = manual_summary(&home, &selected, &options, &mut source, &cancel);
            assert_eq!(cancelled.status, CompactionStatus::Cancelled);
            assert!(!cancelled.applied);
            assert_eq!(source, original);
            assert_eq!(cancelled.attempts.len(), 1);
            assert_eq!(cancelled.attempts[0].knownness, AccountingKnownness::Known);
            assert!(!cancelled.attempts[0].completed);
            assert!(cancelled.attempts[0].usage.is_none());
            assert_eq!(cancelled.attempts[0].totals, AccountingTotals::known_zero());
            proposed.attempts = cancelled.attempts;
            proposed.accounting = cancelled.accounting;
        } else {
            let mut changed_options = options.clone();
            changed_options.compaction_budget.as_mut().unwrap().identity =
                orbit_engine::context_budget::BudgetIdentity::for_config(
                    changed_options.compaction_config.as_ref().unwrap(),
                    "new-summary-metadata",
                    "byte4-v1",
                )
                .unwrap();
            let second = orbit_engine::compaction::compact_context(
                &home.0,
                &selected,
                &changed_options,
                &source,
                &cancel,
            );
            assert_eq!(second.status, CompactionStatus::PublishedReady);
            let second_candidate = second.candidate.unwrap();
            let second_archive = journal
                .archives()
                .into_iter()
                .find(|archive| archive.reference != first_archive.reference)
                .unwrap();
            assert_ne!(first_archive.summary_budget, second_archive.summary_budget);
            proposed = second_archive.receipt();
            proposed.operation_id = "new-earlier-budget".into();
            proposed
                .attempts
                .insert(0, first_archive.attempts[0].clone());
            proposed.accounting = proposed
                .attempts
                .iter()
                .try_fold(AccountingDelta::known_zero(), |delta, receipt| {
                    delta.checked_with(receipt)
                })
                .unwrap();
            let before = journal.snapshot();
            let count = journal.archives().len();
            assert_eq!(
                journal.publish(&original, &second_candidate, &proposed),
                Err(HistoryError::InvalidRecord)
            );
            assert_eq!(journal.snapshot(), before);
            assert_eq!(journal.archives().len(), count);
            wire.finish();
            assert_summary_wire(&home, &journal, &wire, 2, 2);
            continue;
        }
        let before = journal.snapshot();
        let counts = journal.counts();
        let archive_count = journal.archives().len();
        assert_eq!(
            journal.publish(&original, &genuine_candidate, &proposed),
            Err(if kind == "not-sent" {
                HistoryError::InvalidRecord
            } else {
                HistoryError::Conflict
            })
        );
        assert_eq!(journal.snapshot(), before);
        assert_eq!(journal.counts(), counts);
        assert_eq!(journal.archives().len(), archive_count);
        assert_eq!(journal.archives()[0].bytes, first_archive.bytes);
        wire.finish();
        assert_summary_wire(
            &home,
            &journal,
            &wire,
            1,
            if kind == "not-sent" { 2 } else { 3 },
        );
    }
}

#[test]
fn summary_failures_cancellation_and_publication_authority_remain_conservative() {
    for kind in [
        "rejection",
        "partial",
        "cancel-body",
        "precancel",
        "not-sent",
        "after-publish",
    ] {
        let home = Home::new();
        let cancel = CancelToken::new();
        let mut replies = vec![Reply::rejection(503, 17), Reply::success()];
        if !matches!(kind, "precancel" | "not-sent") {
            replies.push(match kind {
                "rejection" => Reply::rejection(503, 17),
                "partial" => Reply::admitted_malformed(true),
                "cancel-body" => Reply {
                    cancel_before_eof: Some(cancel.clone()),
                    ..Reply::rejection(503, 17)
                },
                "after-publish" => Reply::text(SUMMARY_TEXT),
                _ => unreachable!(),
            });
        }
        let mut wire = Wire::new(replies);
        let journal = ComponentJournal::new(
            OWNER,
            Fault::None,
            if kind == "not-sent" {
                CancelAt::Begin(3)
            } else {
                CancelAt::None
            },
            &cancel,
        );
        let mut source = summary_history(3, 1800, true);
        let selected = summary_seed(&home, &wire, &journal, &mut source, &cancel);
        let historical = journal.snapshot().refusals().cloned().unwrap();
        let original = source.clone();
        let before = journal.snapshot();
        let options = summary_options(&selected, &journal, 1000, 12_000);
        if kind == "precancel" {
            cancel.cancel();
        }
        if kind == "after-publish" {
            journal.cancel_after_publish(&cancel);
        }
        let (result, _) = manual_summary(&home, &selected, &options, &mut source, &cancel);
        assert!(!result.applied);
        assert_eq!(source, original);
        assert_eq!(journal.snapshot().refusals(), Some(&historical));
        if matches!(
            kind,
            "precancel" | "not-sent" | "cancel-body" | "after-publish"
        ) {
            assert_eq!(result.status, CompactionStatus::Cancelled);
        } else {
            assert_eq!(result.status, CompactionStatus::AccountingUncertain);
        }
        if kind == "precancel" {
            assert!(result.attempts.is_empty());
            assert_eq!(journal.snapshot(), before);
            assert_eq!(journal.counts(), (2, 1, 1));
        } else {
            assert_eq!(result.attempts.len(), 1);
            assert_eq!(result.attempts[0].purpose, AttemptPurpose::Chunk);
            assert_eq!(journal.counts(), (3, 2, 1));
            assert_eq!(journal.calls("refusal"), 1);
            assert!(journal.state.lock().unwrap().begins[2].1.is_none());
            if kind == "not-sent" {
                assert!(!result.attempts[0].completed);
                assert_eq!(result.attempts[0].totals, AccountingTotals::known_zero());
                assert_eq!(result.attempts[0].knownness, AccountingKnownness::Known);
                assert!(result.attempts[0].usage.is_none());
                assert!(journal.snapshot().pending().is_none());
            } else if kind == "after-publish" {
                assert_summary_delta(&result.accounting, &result.attempts, 1);
                let archives = journal.archives();
                assert_eq!(archives.len(), 1);
                assert_summary_archive(&archives[0], &journal, &original, &options, 1);
                assert_ne!(archives[0].candidate.messages(), original.as_slice());
                assert_summary_namespace(&journal, &historical, 1, 1);
            } else {
                let receipt = &result.attempts[0];
                assert!(!receipt.completed);
                assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
                assert_eq!(receipt.totals.cost_microcents, None);
                assert!(journal.snapshot().pending().unwrap().uncertain);
                assert_eq!(
                    journal.snapshot().last_settlement(),
                    before.last_settlement()
                );
                assert_eq!(
                    journal.snapshot().known_priced_subtotals(),
                    before.known_priced_subtotals()
                );
                assert_eq!(
                    journal.state.lock().unwrap().provisional.as_ref(),
                    Some(receipt)
                );
                if kind == "partial" {
                    assert!(receipt.usage.is_none());
                }
                let counts = journal.counts();
                let checkpoint = journal.snapshot();
                let (again, _) =
                    manual_summary(&home, &selected, &options, &mut source, &CancelToken::new());
                assert_eq!(again.status, CompactionStatus::AccountingUncertain);
                assert!(again.attempts.is_empty());
                assert_eq!(journal.counts(), counts);
                assert_eq!(journal.snapshot(), checkpoint);
            }
        }
        if kind != "after-publish" {
            assert!(journal.archives().is_empty());
        }
        wire.finish();
        assert_summary_wire(
            &home,
            &journal,
            &wire,
            usize::from(!matches!(kind, "precancel" | "not-sent")),
            2,
        );
    }
    summary_authority_denials_use_real_candidates();
}
