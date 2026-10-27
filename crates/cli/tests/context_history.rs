#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock, ProviderUsage, ToolCallMessage};
use orbit_cli::context_history::{context_journal, load_compaction_source};
use orbit_cli::sessions::{SessionFile, SessionLease};
use orbit_engine::compaction::{
    self, AccountingBaseline, AccountingDelta, AccountingKnownness, AccountingRevision,
    AccountingTotals, AttemptIntent, AttemptPurpose, CompactionAttempt, CompactionJournal,
    CompactionReceipt, CompactionStatus, HistoryError, RequestAccountingReceipt,
};
use orbit_engine::{
    PendingToolCall, ProviderKind, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions,
};
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const OWNER: &str = "history-owner";
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 4;
const INTENT: &str = "continue the exact typed task λ";
const SUMMARY: &str = "durable synthetic summary";
const PRIVATE: &str = "PRIVATE-ORIGINAL-OPAQUE-SIGNATURE";

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("orbit-context-history-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn lease(&self, id: &str) -> SessionLease {
        SessionLease::acquire(&self.0, id, "fixture").unwrap()
    }
    fn owner_dir(&self) -> PathBuf {
        self.0.join("context-history").join(OWNER)
    }
    fn accounting(&self) -> PathBuf {
        self.owner_dir().join("accounting.json")
    }
    fn archive(&self, record: &str) -> PathBuf {
        self.owner_dir()
            .join("archives")
            .join(format!("{record}.json"))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn configured(gate: &str, summary: bool) -> TurnConfig {
    TurnConfig {
        provider_id: if summary {
            "summary-provider"
        } else {
            "main-provider"
        }
        .into(),
        gate: gate.into(),
        model: if summary { "summary/raw" } else { "main/raw" }.into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        billing: None,
        max_output_tokens: if summary { 37 } else { 73 },
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    }
}
fn intent(id: &str, child: Option<&str>) -> AttemptIntent {
    AttemptIntent {
        owner_session_id: OWNER.into(),
        child_id: child.map(str::to_owned),
        request_id: id.into(),
        purpose: AttemptPurpose::Chunk,
        budget: orbit_engine::context_budget::BudgetIdentity::for_config(
            &configured("http://127.0.0.1:9", false),
            "metadata",
            "policy",
        )
        .unwrap(),
    }
}
fn billed(id: &str, input: u64, output: u64, cost: Option<u64>) -> RequestAccountingReceipt {
    RequestAccountingReceipt {
        request_id: id.into(),
        purpose: AttemptPurpose::Chunk,
        totals: AccountingTotals {
            input_tokens: input,
            output_tokens: output,
            cost_microcents: cost,
        },
        usage: Some(ProviderUsage {
            input_tokens: input,
            output_tokens: output,
            ..Default::default()
        }),
        knownness: AccountingKnownness::Known,
        completed: true,
    }
}
fn retry_busy<T>(mut work: impl FnMut() -> Result<T, HistoryError>) -> Result<T, HistoryError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match work() {
            Err(HistoryError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            other => return other,
        }
    }
}

struct Captured {
    target: String,
    headers: Vec<(String, String)>,
    body: Value,
}

struct Response {
    body: String,
    pause: bool,
}
impl Response {
    fn text(text: &str, reason: &str, usage: Option<Value>) -> Self {
        let mut event =
            json!({"choices":[{"index":0,"delta":{"content":text},"finish_reason":reason}]});
        if let Some(usage) = usage {
            event["usage"] = usage;
        }
        Self {
            body: format!("data: {event}\n\ndata: [DONE]\n\n"),
            pause: false,
        }
    }
    fn complete(text: &str) -> Self {
        Self::text(
            text,
            "stop",
            Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
        )
    }
}

struct Fixture {
    url: String,
    authority: String,
    requests: Arc<Mutex<Vec<Captured>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
    watchdog_thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(responses: Vec<Response>) -> Self {
        Self::with_held_headers(responses, false)
    }
    fn with_held_headers(responses: Vec<Response>, hold_headers: bool) -> Self {
        let (watchdog, receive) = std::sync::mpsc::channel();
        let watchdog_thread = std::thread::spawn(move || {
            if matches!(
                receive.recv_timeout(Duration::from_secs(25)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("compaction fixture watchdog expired");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/tenant/v1?scope=compaction");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut responses = responses.into_iter();
            loop {
                if Instant::now() >= deadline {
                    return Err("listener deadline");
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        if accepted.fetch_add(1, Ordering::SeqCst) >= MAX_REQUESTS {
                            return Err("request bound");
                        }
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .map_err(|_| "read timeout")?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .map_err(|_| "write timeout")?;
                        let request = read_request(&mut socket)?;
                        captured.lock().map_err(|_| "capture lock")?.push(request);
                        if hold_headers {
                            while !stopping.load(Ordering::SeqCst) {
                                if Instant::now() >= deadline {
                                    return Err("held headers deadline");
                                }
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            continue;
                        }
                        let response = responses.next().ok_or("unexpected extra request")?;
                        let length = if response.pause {
                            response.body.len() + 1_000_000
                        } else {
                            response.body.len()
                        };
                        if let Err(error) = write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{}",
                            response.body
                        ) {
                            if response.pause
                                && matches!(
                                    error.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::ConnectionReset
                                )
                            {
                                continue;
                            }
                            return Err("response write");
                        }
                        socket.flush().map_err(|_| "response flush")?;
                        while response.pause && !stopping.load(Ordering::SeqCst) {
                            if Instant::now() >= deadline {
                                return Err("paused response deadline");
                            }
                            let mut byte = [0];
                            match socket.read(&mut byte) {
                                Ok(0) => break,
                                Ok(_) => {}
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
            requests,
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
            thread
                .join()
                .expect("fixture thread panic")
                .expect("bounded fixture failure");
        }
        assert_eq!(
            self.connections.load(Ordering::SeqCst),
            self.requests.lock().unwrap().len()
        );
    }
}
impl Drop for Fixture {
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

fn read_request(socket: &mut TcpStream) -> Result<Captured, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16 * 1024 || Instant::now() >= deadline {
            return Err("header bound");
        }
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(1) => header.push(byte[0]),
            Ok(_) => return Err("incomplete header"),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("header read"),
        }
    }
    let header = std::str::from_utf8(&header).map_err(|_| "header encoding")?;
    let mut lines = header.lines();
    let target = lines.next().ok_or("request line")?.to_owned();
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("header form")?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .collect();
    if lengths.len() != 1 {
        return Err("single content length required");
    }
    let size = lengths[0]
        .1
        .parse::<usize>()
        .map_err(|_| "content length")?;
    if size == 0 || size > MAX_BODY {
        return Err("body bound");
    }
    let mut bytes = vec![0; size];
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("body deadline");
        }
        match socket.read(&mut bytes[offset..]) {
            Ok(0) => return Err("incomplete body"),
            Ok(count) => offset += count,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("body read"),
        }
    }
    let body = serde_json::from_slice(&bytes).map_err(|_| "body JSON")?;
    Ok(Captured {
        target,
        headers,
        body,
    })
}

fn options(fixture: &Fixture, journal: Arc<dyn CompactionJournal>) -> TurnOptions {
    let selected = configured(&fixture.url, false);
    let summary = configured(&fixture.url, true);
    TurnOptions {
        session_id: OWNER.into(),
        request_stem: "host-history".into(),
        max_attempts: 1,
        max_rounds: 1,
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 1000).unwrap(),
        ),
        compaction_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&summary, 12_000).unwrap(),
        ),
        compaction_config: Some(summary),
        journal: Some(journal),
        system_directive: Some("Keep exact typed task state.".into()),
        ..Default::default()
    }
}
fn plain_source(bytes: usize) -> Vec<ChatMessage> {
    vec![
        orbit_engine::user_message(format!("{}OLD-LATE-USER-END", "u".repeat(bytes))),
        orbit_engine::assistant_message(format!("{}OLD-LATE-ASSISTANT-END", "a".repeat(bytes))),
        orbit_engine::user_message("latest completed exchange"),
        orbit_engine::assistant_message("exact recent answer"),
        orbit_engine::user_message(INTENT),
    ]
}
fn typed_source() -> Vec<ChatMessage> {
    let mut source = vec![orbit_engine::user_message(format!(
        "{}OLD-LATE-TASK-END",
        "u".repeat(6000)
    ))];
    let mut call = orbit_engine::assistant_message("exact visible call");
    call.tool_calls = Some(vec![ToolCallMessage {
        id: "historical-call".into(),
        name: "inspect".into(),
        arguments: format!("{{\"query\":\"{}ARGUMENT-END\"}}", "q".repeat(900)),
    }]);
    source.push(call);
    let mut result = orbit_engine::user_message("fallback display differs from full raw result");
    result.role = ChatRole::Tool;
    result.tool_call_id = Some("historical-call".into());
    result.tool_result = Some(format!("{}RESULT-END", "r".repeat(900)));
    source.push(result);
    let mut done = orbit_engine::assistant_message("complete old visible task state");
    done.blocks = Some(vec![ContentBlock::Opaque {
        json: json!({"type":"thinking","thinking":PRIVATE,"signature":PRIVATE}).to_string(),
    }]);
    done.origin_provider = Some("foreign-original-provider".into());
    done.origin_model = Some("foreign-original-model".into());
    source.push(done);
    let mut image = orbit_engine::user_message("latest retained image");
    image.blocks=Some(vec![ContentBlock::Text {text:"latest retained image".into()},ContentBlock::Image {data:"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=".into(),media_type:"image/png".into()}]);
    source.push(image);
    source.push(orbit_engine::assistant_message("image exchange complete"));
    let mut current = orbit_engine::user_message(INTENT);
    current.blocks = Some(vec![ContentBlock::Text {
        text: INTENT.into(),
    }]);
    source.push(current);
    source
}
fn receipt_for(attempt: &CompactionAttempt, options: &TurnOptions) -> CompactionReceipt {
    let candidate = attempt.candidate.as_ref().unwrap();
    let record = candidate.published_record().unwrap();
    CompactionReceipt {
        operation_id: record.record_id.clone(),
        owner_session_id: record.owner_session_id.clone(),
        child_id: record.child_id.clone(),
        source_digest: candidate.source_digest().into(),
        candidate_digest: candidate.candidate_digest().into(),
        conversation_budget: options.selected_budget.as_ref().unwrap().identity.clone(),
        summary_budget: options.compaction_budget.as_ref().unwrap().identity.clone(),
        accounting: attempt.accounting.clone(),
        attempts: attempt.attempts.clone(),
    }
}
fn assert_wire(fixture: &Fixture, count: usize, summary_window: u64) {
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), count);
    for request in requests.iter() {
        assert_eq!(
            request.target,
            "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
        );
        assert_eq!(
            request
                .headers
                .iter()
                .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                .collect::<Vec<_>>(),
            [fixture.authority.as_str()]
        );
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
        );
        assert_eq!(request.body["model"], "summary/raw");
        assert_eq!(request.body["max_tokens"], 37);
        assert!(request.body.get("tools").is_none());
        assert!(
            (serde_json::to_vec(&request.body).unwrap().len() as u64).div_ceil(4) <= summary_window
        );
        assert!(!request.body.to_string().contains(PRIVATE));
        assert!(!request.body.to_string().contains(INTENT));
    }
}

#[test]
fn missing_checkpoint_requires_explicit_expected_absent_initialization() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    assert_eq!(journal.accounting_checkpoint(), Err(HistoryError::Missing));
    let first = journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    assert_eq!(first.revision, AccountingRevision(0));
    assert_eq!(first.owner_session_id, OWNER);
    assert!(first.child_id.is_none());
    assert_eq!(first.baseline, AccountingBaseline::FreshKnownZero);
    assert_eq!(first.totals, AccountingDelta::known_zero());
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(
        journal.initialize_accounting(AccountingBaseline::UnknownLegacy),
        Err(HistoryError::Conflict)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    drop(journal);
    assert_eq!(
        context_journal(&home.0, OWNER, None)
            .unwrap()
            .accounting_checkpoint()
            .unwrap(),
        first
    );
}

#[test]
fn legacy_baseline_stays_unknown_after_reopen_and_cannot_be_reset_to_zero() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    let old = journal
        .initialize_accounting(AccountingBaseline::UnknownLegacy)
        .unwrap();
    assert_eq!(old.totals, AccountingDelta::unknown_legacy());
    let bytes = fs::read(home.accounting()).unwrap();
    drop(journal);
    let reopened = context_journal(&home.0, OWNER, None).unwrap();
    assert_eq!(reopened.accounting_checkpoint().unwrap(), old);
    assert_eq!(
        reopened.initialize_accounting(AccountingBaseline::FreshKnownZero),
        Err(HistoryError::Conflict)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
}

#[test]
fn durable_begin_checks_revision_and_refuses_pending_replay_after_reopen() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let request = intent("pending-request", None);
    assert_eq!(
        journal.begin_attempt(AccountingRevision(9), &request),
        Err(HistoryError::Conflict)
    );
    let reference = journal
        .begin_attempt(AccountingRevision(0), &request)
        .unwrap();
    assert_eq!(reference.intent_digest, request.digest().unwrap());
    assert_eq!(reference.revision, AccountingRevision(1));
    drop(journal);
    let reopened = context_journal(&home.0, OWNER, None).unwrap();
    let before = reopened.accounting_checkpoint().unwrap();
    assert_eq!(before.pending.as_ref().unwrap().intent, request);
    assert_eq!(
        reopened.begin_attempt(AccountingRevision(0), &request),
        Err(HistoryError::Conflict)
    );
    assert_eq!(
        reopened.begin_attempt(before.revision, &intent("different-request", None)),
        Err(HistoryError::Conflict)
    );
    assert_eq!(reopened.accounting_checkpoint().unwrap(), before);
}

#[test]
fn settlement_exact_last_is_idempotent_conflict_refuses_and_older_is_nonapplying() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let first = journal
        .begin_attempt(AccountingRevision(0), &intent("first", None))
        .unwrap();
    let receipt = billed("first", 3, 2, Some(7));
    let settled = journal.settle_attempt(&first, &receipt).unwrap();
    assert_eq!(settled.revision, AccountingRevision(2));
    drop(journal);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(journal.settle_attempt(&first, &receipt).unwrap(), settled);
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let mut conflict = receipt.clone();
    conflict.totals.cost_microcents = Some(8);
    assert_eq!(
        journal.settle_attempt(&first, &conflict),
        Err(HistoryError::Conflict)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let second = journal
        .begin_attempt(settled.revision, &intent("second", None))
        .unwrap();
    let final_state = journal
        .settle_attempt(&second, &billed("second", 5, 4, None))
        .unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(
        journal.settle_attempt(&first, &receipt),
        Err(HistoryError::StaleNonApplying)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    assert_eq!(journal.accounting_checkpoint().unwrap(), final_state);
    assert_eq!(final_state.totals.housekeeping.input_tokens, 8);
    assert_eq!(final_state.totals.housekeeping.output_tokens, 6);
    assert_eq!(final_state.totals.housekeeping.cost_microcents, None);
}

#[test]
fn uncertain_full_usage_survives_restart_and_pending_blocks_actual_service_replay() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let reference = journal
        .begin_attempt(AccountingRevision(0), &intent("uncertain", None))
        .unwrap();
    let usage = ProviderUsage {
        input_tokens: 11,
        output_tokens: 7,
        cache_read_tokens: 5,
        cache_write_tokens: 3,
        reasoning_tokens: 2,
    };
    let receipt = RequestAccountingReceipt {
        request_id: "uncertain".into(),
        purpose: AttemptPurpose::Chunk,
        totals: AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None,
        },
        usage: Some(usage),
        knownness: AccountingKnownness::Uncertain,
        completed: false,
    };
    let pending = journal.settle_attempt(&reference, &receipt).unwrap();
    assert!(pending.pending.as_ref().unwrap().uncertain);
    drop(journal);
    let reopened = context_journal(&home.0, OWNER, None).unwrap();
    assert_eq!(reopened.accounting_checkpoint().unwrap(), pending);
    let document: Value = serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
    let entry = document["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["namespace"]["kind"] == "owner")
        .unwrap();
    assert_eq!(entry["pending"]["uncertain_receipt"]["usage"], json!(usage));
    assert_eq!(
        entry["pending"]["uncertain_receipt"]["totals"]["cost_microcents"],
        Value::Null
    );
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(
        reopened.settle_attempt(&reference, &receipt).unwrap(),
        pending
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let mut fixture = Fixture::new(vec![]);
    let options = options(&fixture, reopened);
    let source = plain_source(3000);
    let original = source.clone();
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(attempt.candidate.is_none());
    assert!(attempt.attempts.is_empty());
    assert_eq!(source, original);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
}

#[test]
fn missing_usage_and_proven_not_sent_keep_distinct_full_receipts_after_restart() {
    for missing in [true, false] {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let request = intent("presence", None);
        let reference = journal
            .begin_attempt(AccountingRevision(0), &request)
            .unwrap();
        let receipt = RequestAccountingReceipt {
            request_id: request.request_id,
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: if missing { None } else { Some(0) },
            },
            usage: None,
            knownness: if missing {
                AccountingKnownness::UnknownUsage
            } else {
                AccountingKnownness::Known
            },
            completed: missing,
        };
        let expected = journal.settle_attempt(&reference, &receipt).unwrap();
        drop(journal);
        let reopened = context_journal(&home.0, OWNER, None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), expected);
        let document: Value =
            serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
        let retained = &document["entries"][0]["last"]["receipt"];
        assert_eq!(retained["usage"], Value::Null);
        assert_eq!(retained["completed"], missing);
        assert_eq!(
            retained["totals"]["cost_microcents"],
            if missing { Value::Null } else { json!(0) }
        );
        assert!(expected.pending.is_none());
        assert_eq!(
            reopened.settle_attempt(&reference, &receipt).unwrap(),
            expected
        );
    }
}

#[test]
fn numeric_overflow_preserves_the_durable_pending_state_without_partial_settlement() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let first = journal
        .begin_attempt(AccountingRevision(0), &intent("maximum", None))
        .unwrap();
    let state = journal
        .settle_attempt(
            &first,
            &billed("maximum", u64::MAX, u64::MAX, Some(u64::MAX)),
        )
        .unwrap();
    let second = journal
        .begin_attempt(state.revision, &intent("overflow", None))
        .unwrap();
    let before = journal.accounting_checkpoint().unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(
        journal.settle_attempt(&second, &billed("overflow", 1, 1, Some(1))),
        Err(HistoryError::TooLarge)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    drop(journal);
    assert_eq!(
        context_journal(&home.0, OWNER, None)
            .unwrap()
            .accounting_checkpoint()
            .unwrap(),
        before
    );
}

#[test]
fn concurrent_children_merge_latest_container_without_overwriting_owner_pending() {
    let home = Home::new();
    let _owner_lease = home.lease(OWNER);
    let root = context_journal(&home.0, OWNER, None).unwrap();
    root.initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    root.begin_attempt(AccountingRevision(0), &intent("owner-pending", None))
        .unwrap();
    let owner_before = root.accounting_checkpoint().unwrap();
    let children = [ulid::Ulid::new().to_string(), ulid::Ulid::new().to_string()];
    let _leases: Vec<_> = children.iter().map(|id| home.lease(id)).collect();
    let mut gates = Vec::new();
    let mut threads = Vec::new();
    for (index, child) in children.iter().enumerate() {
        let journal = context_journal(&home.0, OWNER, Some(child)).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let (start, gate) = std::sync::mpsc::channel();
        gates.push(start);
        let child = child.clone();
        threads.push(std::thread::spawn(move || {
            gate.recv_timeout(Duration::from_secs(2)).unwrap();
            let request = intent(&format!("child-{index}"), Some(&child));
            let reference =
                retry_busy(|| journal.begin_attempt(AccountingRevision(0), &request)).unwrap();
            retry_busy(|| {
                journal.settle_attempt(
                    &reference,
                    &billed(&request.request_id, index as u64 + 3, 2, Some(7)),
                )
            })
            .unwrap()
        }));
    }
    for gate in gates {
        gate.send(()).unwrap();
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(root.accounting_checkpoint().unwrap(), owner_before);
    let foreign = results[0]
        .last_settlement
        .as_ref()
        .unwrap()
        .reference
        .clone();
    assert_eq!(
        root.settle_attempt(&foreign, &billed("child-0", 3, 2, Some(7))),
        Err(HistoryError::Conflict)
    );
    assert_eq!(root.accounting_checkpoint().unwrap(), owner_before);
    for (index, child) in children.iter().enumerate() {
        let reopened = context_journal(&home.0, OWNER, Some(child)).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), results[index]);
        assert_eq!(results[index].owner_session_id, OWNER);
        assert_eq!(results[index].child_id.as_deref(), Some(child.as_str()));
        assert_eq!(
            results[index].totals.housekeeping.input_tokens,
            index as u64 + 3
        );
        assert!(results[index].pending.is_none());
    }
    assert!(fs::metadata(home.accounting()).unwrap().len() <= 128 * 1024);
}

#[test]
fn same_namespace_expected_revision_allows_only_one_competing_begin() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut gates = Vec::new();
    let mut threads = Vec::new();
    for index in 0..2 {
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        let (start, gate) = std::sync::mpsc::channel();
        gates.push(start);
        threads.push(std::thread::spawn(move || {
            gate.recv_timeout(Duration::from_secs(2)).unwrap();
            retry_busy(|| {
                journal.begin_attempt(
                    AccountingRevision(0),
                    &intent(&format!("competing-{index}"), None),
                )
            })
        }));
    }
    for gate in gates {
        gate.send(()).unwrap();
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(HistoryError::Conflict)))
            .count(),
        1
    );
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.revision, AccountingRevision(1));
    assert_eq!(checkpoint.pending.as_ref().unwrap().reference, winner);
}

#[test]
fn whole_entry_reservation_preserves_prior_receipt_and_maximum_pending_settlement() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let root = context_journal(&home.0, OWNER, None).unwrap();
    root.initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut previous = intent(&"p".repeat(256), None);
    previous.budget.metadata_revision = "\\".repeat(256);
    previous.budget.policy_revision = "\\".repeat(256);
    let reference = root
        .begin_attempt(AccountingRevision(0), &previous)
        .unwrap();
    let mut receipt = billed(&previous.request_id, 1, 1, Some(1));
    receipt.usage = Some(ProviderUsage {
        input_tokens: 1,
        output_tokens: 1,
        cache_read_tokens: u64::MAX,
        cache_write_tokens: u64::MAX,
        reasoning_tokens: u64::MAX,
    });
    let first = root.settle_attempt(&reference, &receipt).unwrap();
    let mut pending = intent(&"r".repeat(256), None);
    pending.budget = previous.budget;
    let reference = root.begin_attempt(first.revision, &pending).unwrap();
    let pending_before = root.accounting_checkpoint().unwrap();
    let mut children = Vec::new();
    let mut leases = Vec::new();
    loop {
        let child = ulid::Ulid::new().to_string();
        let lease = home.lease(&child);
        let journal = context_journal(&home.0, OWNER, Some(&child)).unwrap();
        match journal.initialize_accounting(AccountingBaseline::FreshKnownZero) {
            Ok(checkpoint) => {
                children.push((child, checkpoint));
                leases.push(lease);
            }
            Err(HistoryError::Full) => break,
            Err(error) => panic!("unexpected reservation refusal: {error}"),
        }
        assert!(
            children.len() <= orbit_engine::compaction::MAX_ACCOUNTING_CHECKPOINT_BYTES,
            "reservation must reach the actual bounded container, not silently grow forever"
        );
    }
    assert!(!children.is_empty());
    assert_eq!(root.accounting_checkpoint().unwrap(), pending_before);
    let mut maximum = billed(
        &pending.request_id,
        u64::MAX - 1,
        u64::MAX - 1,
        Some(u64::MAX - 1),
    );
    maximum.usage = Some(ProviderUsage {
        input_tokens: u64::MAX - 1,
        output_tokens: u64::MAX - 1,
        cache_read_tokens: u64::MAX,
        cache_write_tokens: u64::MAX,
        reasoning_tokens: u64::MAX,
    });
    let settled = root
        .settle_attempt(&reference, &maximum)
        .expect("new sibling entries must not steal already reserved complete settlement space");
    assert_eq!(
        settled.totals.housekeeping,
        AccountingTotals {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cost_microcents: Some(u64::MAX)
        }
    );
    assert!(settled.pending.is_none());
    for (child, checkpoint) in &children {
        assert_eq!(
            context_journal(&home.0, OWNER, Some(child))
                .unwrap()
                .accounting_checkpoint()
                .unwrap(),
            *checkpoint
        );
    }
    let document: Value = serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
    assert_eq!(
        document["entries"].as_array().unwrap().len(),
        children.len() + 1
    );
    assert!(fs::metadata(home.accounting()).unwrap().len() <= 128 * 1024);
    drop(leases);
}

#[test]
fn invalid_owner_child_and_record_identifiers_never_escape_the_private_root() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    for owner in ["", "../escape", "owner/child", "white space"] {
        assert_eq!(
            context_journal(&home.0, owner, None).unwrap_err(),
            HistoryError::InvalidRecord
        );
    }
    for child in ["", "../escape", "not-a-canonical-child"] {
        assert_eq!(
            context_journal(&home.0, OWNER, Some(child)).unwrap_err(),
            HistoryError::InvalidRecord
        );
    }
    for record in ["", "../escape", "compact-invalid.json", "noncanonical"] {
        assert_eq!(
            load_compaction_source(&home.0, OWNER, None, record),
            Err(HistoryError::InvalidRecord)
        );
    }
    assert!(!home.0.join("context-history").exists());
}

#[test]
fn symlink_home_or_owner_directory_is_refused_without_target_mutation() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let target = home.0.join("outside-owned-target");
    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
    let alias = home.0.join("home-alias");
    symlink(&home.0, &alias).unwrap();
    assert_eq!(
        context_journal(&alias, OWNER, None).unwrap_err(),
        HistoryError::Unsafe
    );
    let parent = home.0.join("context-history");
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
    symlink(&target, parent.join(OWNER)).unwrap();
    assert_eq!(
        context_journal(&home.0, OWNER, None).unwrap_err(),
        HistoryError::Unsafe
    );
    assert_eq!(fs::read_dir(target).unwrap().count(), 0);
}

#[test]
fn accounting_special_links_and_permissions_are_refused_without_repair() {
    for kind in ["symlink", "hardlink", "fifo", "permissions"] {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let path = home.accounting();
        let original = fs::read(&path).unwrap();
        let target = home.0.join("untouched-target");
        match kind {
            "symlink" => {
                private_file(&target, &original);
                fs::remove_file(&path).unwrap();
                symlink(&target, &path).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&path, &target).unwrap();
            }
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            }
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::Unsafe),
            "kind={kind}"
        );
        assert_eq!(
            journal.initialize_accounting(AccountingBaseline::UnknownLegacy),
            Err(HistoryError::Unsafe),
            "kind={kind}"
        );
        if kind == "symlink" || kind == "hardlink" {
            assert_eq!(fs::read(target).unwrap(), original);
        }
        if kind == "permissions" {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
}

#[test]
fn malformed_or_wrong_owner_container_is_not_reinitialized_or_reinterpreted() {
    for wrong_owner in [false, true] {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let mut document: Value =
            serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
        let bytes = if wrong_owner {
            document["owner"] = json!("different-owner");
            serde_json::to_vec(&document).unwrap()
        } else {
            b"{\"version\":1,\"entries\":[".to_vec()
        };
        fs::write(home.accounting(), &bytes).unwrap();
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            journal.initialize_accounting(AccountingBaseline::FreshKnownZero),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    }
}

#[test]
fn actual_compaction_archives_full_typed_source_before_candidate_save_and_reopen() {
    let home = Home::new();
    let lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let options = options(&fixture, journal.clone());
    let source = typed_source();
    let original = source.clone();
    lease
        .save(&SessionFile::from_chat(
            OWNER,
            "main/raw",
            &fixture.url,
            "main-provider",
            &source,
            9,
            0,
            0,
            0,
        ))
        .unwrap();
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_wire(&fixture, 1, 12_000);
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    assert_eq!(source, original);
    let candidate = attempt.candidate.as_ref().unwrap();
    let reference = candidate.published_record().unwrap().clone();
    assert_eq!(reference.owner_session_id, OWNER);
    assert!(reference.child_id.is_none());
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id).unwrap(),
        original
    );
    assert_eq!(
        &candidate.messages()[candidate.messages().len() - 3..],
        &original[original.len() - 3..]
    );
    assert_eq!(attempt.accounting.housekeeping.cost_microcents, None);
    assert_eq!(attempt.attempts[0].knownness, AccountingKnownness::Known);
    let path = home.archive(&reference.record_id);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(home.owner_dir()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    lease
        .save(&SessionFile::from_chat(
            OWNER,
            "main/raw",
            &fixture.url,
            "main-provider",
            candidate.messages(),
            9,
            11,
            7,
            0,
        ))
        .unwrap();
    drop(options);
    drop(journal);
    drop(lease);
    let _lease = home.lease(OWNER);
    let reopened = context_journal(&home.0, OWNER, None).unwrap();
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id).unwrap(),
        original
    );
    assert_eq!(
        orbit_cli::sessions::load_session(&home.0, OWNER)
            .unwrap()
            .transcript,
        candidate.messages()
    );
    assert_eq!(
        reopened
            .accounting_checkpoint()
            .unwrap()
            .totals
            .housekeeping,
        attempt.accounting.housekeeping
    );
    let requests = fixture.requests.lock().unwrap();
    let visible = requests[0].body["messages"].to_string();
    for sentinel in ["OLD-LATE-TASK-END", "ARGUMENT-END", "RESULT-END"] {
        assert!(visible.contains(sentinel));
    }
    assert!(!visible.contains(PRIVATE));
    assert!(
        (serde_json::to_vec(&requests[0].body).unwrap().len() as u64).div_ceil(4) > 1000,
        "the actual summary request must demonstrate its independent larger input policy"
    );
}

#[test]
fn exact_child_archive_scope_and_legacy_baseline_survive_reopen_without_parent_billing() {
    let home = Home::new();
    let _owner_lease = home.lease(OWNER);
    let child = ulid::Ulid::new().to_string();
    let _child_lease = home.lease(&child);
    let root = context_journal(&home.0, OWNER, None).unwrap();
    root.initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let journal = context_journal(&home.0, OWNER, Some(&child)).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::UnknownLegacy)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let mut options = options(&fixture, journal.clone());
    options.session_id = child.clone();
    let source = typed_source();
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_wire(&fixture, 1, 12_000);
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    let reference = attempt
        .candidate
        .unwrap()
        .published_record()
        .unwrap()
        .clone();
    assert_eq!(reference.owner_session_id, OWNER);
    assert_eq!(reference.child_id.as_deref(), Some(child.as_str()));
    drop(options);
    drop(journal);
    let reopened = context_journal(&home.0, OWNER, Some(&child)).unwrap();
    assert_eq!(
        load_compaction_source(&home.0, OWNER, Some(&child), &reference.record_id).unwrap(),
        source
    );
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id),
        Err(HistoryError::InvalidRecord)
    );
    assert_eq!(
        reopened.accounting_checkpoint().unwrap().totals.knownness,
        AccountingKnownness::UnknownLegacy
    );
    assert_eq!(
        root.accounting_checkpoint().unwrap().revision,
        AccountingRevision(0)
    );
    assert_eq!(
        root.accounting_checkpoint().unwrap().totals,
        AccountingDelta::known_zero()
    );
}

#[test]
fn immutable_archive_above_profile_bound_reopens_and_exact_publish_is_idempotent() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let mut options = options(&fixture, journal.clone());
    options.compaction_budget = Some(
        orbit_engine::context_budget::SelectedBudget::legacy_input(
            options.compaction_config.as_ref().unwrap(),
            262_144,
        )
        .unwrap(),
    );
    let source = plain_source(150_000);
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    assert_wire(&fixture, 1, 262_144);
    let candidate = attempt.candidate.as_ref().unwrap();
    let reference = candidate.published_record().unwrap().clone();
    let receipt = receipt_for(&attempt, &options);
    let path = home.archive(&reference.record_id);
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 128 * 1024);
    assert!(bytes.len() <= 32 * 1024 * 1024);
    drop(options);
    drop(journal);
    let reopened = context_journal(&home.0, OWNER, None).unwrap();
    assert_eq!(
        reopened.publish(&source, candidate, &receipt).unwrap(),
        reference
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id).unwrap(),
        source
    );
    assert_eq!(
        fs::read_dir(home.owner_dir().join("archives"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn final_archive_count_quota_rechecks_under_lock_and_blocks_service_before_new_post() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let options = options(&fixture, journal.clone());
    let source = plain_source(3000);
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    let candidate = attempt.candidate.as_ref().unwrap();
    let mut receipt = receipt_for(&attempt, &options);
    let first = candidate.published_record().unwrap().clone();
    for _ in 1..64 {
        receipt.operation_id = format!("compact-{}", ulid::Ulid::new());
        journal.publish(&source, candidate, &receipt).unwrap();
    }
    assert_eq!(
        fs::read_dir(home.owner_dir().join("archives"))
            .unwrap()
            .count(),
        64
    );
    assert_eq!(
        journal.check_archive_capacity(serde_json::to_vec(&source).unwrap().len() as u64),
        Err(HistoryError::Full)
    );
    receipt.operation_id = format!("compact-{}", ulid::Ulid::new());
    let bytes = fs::read(home.accounting()).unwrap();
    assert_eq!(
        journal.publish(&source, candidate, &receipt),
        Err(HistoryError::Full)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let refused = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(refused.candidate.is_none());
    assert!(refused.attempts.is_empty());
    assert_wire(&fixture, 1, 12_000);
    assert_eq!(
        fs::read_dir(home.owner_dir().join("archives"))
            .unwrap()
            .count(),
        64
    );
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &first.record_id).unwrap(),
        source
    );
}

#[test]
fn impossible_archive_lower_bound_refuses_without_mutating_accounting() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let before = fs::read(home.accounting()).unwrap();
    assert_eq!(
        journal.check_archive_capacity(32 * 1024 * 1024),
        Ok(()),
        "the source lower bound is advisory, not a reservation for encoded record overhead"
    );
    assert_eq!(
        journal.check_archive_capacity(32 * 1024 * 1024 + 1),
        Err(HistoryError::TooLarge)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), before);
    assert_eq!(
        fs::read_dir(home.owner_dir().join("archives"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn unsafe_archive_links_specials_and_modes_refuse_checked_load_and_capacity() {
    for kind in ["symlink", "hardlink", "fifo", "permissions"] {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
        let options = options(&fixture, journal.clone());
        let source = plain_source(3000);
        let attempt = compaction::compact_context(
            &home.0,
            &configured(&fixture.url, false),
            &options,
            &source,
            &CancelToken::new(),
        );
        fixture.finish();
        assert_eq!(attempt.status, CompactionStatus::PublishedReady);
        let reference = attempt
            .candidate
            .unwrap()
            .published_record()
            .unwrap()
            .clone();
        let path = home.archive(&reference.record_id);
        let bytes = fs::read(&path).unwrap();
        let target = home.0.join("unchanged-archive-target");
        match kind {
            "symlink" => {
                private_file(&target, &bytes);
                fs::remove_file(&path).unwrap();
                symlink(&target, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, &target).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            }
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert_eq!(
            load_compaction_source(&home.0, OWNER, None, &reference.record_id),
            Err(HistoryError::Unsafe),
            "kind={kind}"
        );
        assert_eq!(
            journal.check_archive_capacity(1),
            Err(HistoryError::Unsafe),
            "kind={kind}"
        );
        if kind == "symlink" || kind == "hardlink" {
            assert_eq!(fs::read(target).unwrap(), bytes);
        }
    }
}

#[test]
fn corrupted_archive_is_rejected_instead_of_returning_partial_originals() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let options = options(&fixture, journal.clone());
    let source = typed_source();
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    let reference = attempt
        .candidate
        .unwrap()
        .published_record()
        .unwrap()
        .clone();
    let path = home.archive(&reference.record_id);
    let mut document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["source"][0]["content"] = json!("tampered original content");
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id),
        Err(HistoryError::InvalidRecord)
    );
}

#[test]
fn failed_session_save_keeps_previous_snapshot_and_checked_full_original_archive() {
    let home = Home::new();
    let lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let options = options(&fixture, journal.clone());
    let source = typed_source();
    let old = SessionFile::from_chat(
        OWNER,
        "main/raw",
        &fixture.url,
        "main-provider",
        &source,
        9,
        0,
        0,
        0,
    );
    lease.save(&old).unwrap();
    let attempt = compaction::compact_context(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    let candidate = attempt.candidate.as_ref().unwrap();
    let reference = candidate.published_record().unwrap().clone();
    let snapshot = home.0.join("sessions").join(format!("{OWNER}.json"));
    let before = fs::read(&snapshot).unwrap();
    let linked = home.0.join("snapshot-witness");
    fs::hard_link(&snapshot, &linked).unwrap();
    let replacement = SessionFile::from_chat(
        OWNER,
        "main/raw",
        &fixture.url,
        "main-provider",
        candidate.messages(),
        9,
        11,
        7,
        0,
    );
    assert!(lease.save(&replacement).is_err());
    assert_eq!(fs::read(&snapshot).unwrap(), before);
    fs::remove_file(linked).unwrap();
    drop(options);
    drop(journal);
    drop(lease);
    let _lease = home.lease(OWNER);
    assert_eq!(
        orbit_cli::sessions::load_session(&home.0, OWNER)
            .unwrap()
            .transcript,
        source
    );
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &reference.record_id).unwrap(),
        source
    );
}

#[derive(Default)]
struct NoEffects(usize);
impl ToolExecutor for NoEffects {
    fn execute(&mut self, _: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        panic!("historical tools must never execute")
    }
}
#[test]
fn unsafe_archive_storage_refuses_actual_turn_without_overwriting_saved_source() {
    let home = Home::new();
    let lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let mut fixture = Fixture::new(vec![]);
    let options = options(&fixture, journal.clone());
    let mut source = plain_source(3000);
    source.pop();
    lease
        .save(&SessionFile::from_chat(
            OWNER,
            "main/raw",
            &fixture.url,
            "main-provider",
            &source,
            9,
            0,
            0,
            0,
        ))
        .unwrap();
    let snapshot = home.0.join("sessions").join(format!("{OWNER}.json"));
    let before = fs::read(&snapshot).unwrap();
    let mut expected = source.clone();
    expected.push(orbit_engine::user_message(INTENT));
    fs::set_permissions(
        home.owner_dir().join("archives"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let error = orbit_engine::run_turn(
        &home.0,
        &configured(&fixture.url, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    )
    .expect_err("unsafe archive storage must not publish a candidate");
    fixture.finish();
    assert!(error.len() <= 512);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0, 0);
    assert_eq!(source, expected);
    assert_eq!(fs::read(snapshot).unwrap(), before);
    assert!(!events.iter().any(|event| matches!(
        event,
        orbit_frontend_protocol::FrontendEvent::Compacted { .. }
    )));
}

#[test]
fn missing_archive_lookup_is_read_only_and_does_not_initialize_storage() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let record = format!("compact-{}", ulid::Ulid::new());
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &record),
        Err(HistoryError::Missing)
    );
    assert!(!home.0.join("context-history").exists());

    let archives = home.owner_dir().join("archives");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&archives)
        .unwrap();
    assert_eq!(
        load_compaction_source(&home.0, OWNER, None, &record),
        Err(HistoryError::Missing)
    );
    assert_eq!(fs::read_dir(home.owner_dir()).unwrap().count(), 1);
    assert!(!home.owner_dir().join(".history.lock").exists());
    assert!(!home.accounting().exists());
    assert_eq!(fs::read_dir(archives).unwrap().count(), 0);
}

#[test]
fn live_journal_rejects_replaced_owner_directory_without_losing_bills_or_pending() {
    let mut observations = Vec::new();
    for settle in [true, false] {
        let home = Home::new();
        let lease = home.lease(OWNER);
        lease
            .save(&SessionFile::from_chat(
                OWNER,
                "main/raw",
                "http://127.0.0.1:9",
                "main-provider",
                &[],
                0,
                0,
                0,
                0,
            ))
            .unwrap();
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let initial = fs::read(home.accounting()).unwrap();
        let reference = journal
            .begin_attempt(AccountingRevision(0), &intent("original-admission", None))
            .unwrap();
        if settle {
            journal
                .settle_attempt(&reference, &billed("original-admission", 3, 2, Some(8)))
                .unwrap();
        }
        let retained = home.0.join("retained-original-owner");
        fs::rename(home.owner_dir(), &retained).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(home.owner_dir())
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(home.owner_dir().join("archives"))
            .unwrap();
        private_file(&home.accounting(), &initial);
        assert_eq!(lease.load().unwrap().turns, 0);
        let checkpoint = journal.accounting_checkpoint();
        let readmitted = journal.begin_attempt(
            AccountingRevision(0),
            &intent("replacement-admission", None),
        );
        observations.push((
            settle,
            matches!(checkpoint, Err(HistoryError::Unsafe)),
            matches!(readmitted, Err(HistoryError::Unsafe)),
        ));
        assert!(retained.join("accounting.json").is_file());
    }
    assert_eq!(observations, [(true, true, true), (false, true, true)]);
}

mod task2a_known_price_tests {
    use super::*;
    use orbit_engine::KnownPricedSubtotals;

    fn settle(
        journal: &dyn CompactionJournal,
        id: &str,
        child: Option<&str>,
        purpose: AttemptPurpose,
        price: Option<u64>,
    ) -> (
        orbit_engine::AttemptRef,
        RequestAccountingReceipt,
        orbit_engine::AccountingCheckpoint,
    ) {
        let mut request = intent(id, child);
        request.purpose = purpose;
        let reference = journal
            .begin_attempt(journal.accounting_checkpoint().unwrap().revision, &request)
            .unwrap();
        let mut receipt = billed(id, 1, 1, price);
        receipt.purpose = purpose;
        let checkpoint = journal.settle_attempt(&reference, &receipt).unwrap();
        (reference, receipt, checkpoint)
    }

    fn omit_new_zero_field(bytes: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        let member =
            ",\"known_priced_subtotals\":{\"ordinary_microcents\":0,\"housekeeping_microcents\":0}";
        assert_eq!(text.matches(member).count(), 1);
        text.replacen(member, "", 1).into_bytes()
    }

    #[test]
    fn task2a_explicit_new_baselines_track_known_zero_without_claiming_legacy_full_cost() {
        for baseline in [
            AccountingBaseline::FreshKnownZero,
            AccountingBaseline::UnknownLegacy,
        ] {
            let home = Home::new();
            let _lease = home.lease(OWNER);
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            let first = journal.initialize_accounting(baseline).unwrap();
            assert_eq!(
                first.known_priced_subtotals,
                Some(KnownPricedSubtotals::known_zero())
            );
            assert_eq!(first.baseline, baseline);
            assert_eq!(
                first.totals,
                if baseline == AccountingBaseline::FreshKnownZero {
                    AccountingDelta::known_zero()
                } else {
                    AccountingDelta::unknown_legacy()
                }
            );
            let bytes = fs::read(home.accounting()).unwrap();
            drop(journal);
            let reopened = context_journal(&home.0, OWNER, None).unwrap();
            assert_eq!(reopened.accounting_checkpoint().unwrap(), first);
            assert_eq!(
                reopened.initialize_accounting(AccountingBaseline::FreshKnownZero),
                Err(HistoryError::Conflict)
            );
            assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
        }
    }

    #[test]
    fn task2a_priced_subset_survives_sticky_unknown_reopen_and_independent_child_settlement() {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let (first_ref, first_receipt, _) = settle(
            journal.as_ref(),
            "priced-ordinary",
            None,
            AttemptPurpose::Ordinary,
            Some(7),
        );
        settle(
            journal.as_ref(),
            "unpriced-chunk",
            None,
            AttemptPurpose::Chunk,
            None,
        );
        let (last_ref, last_receipt, state) = settle(
            journal.as_ref(),
            "priced-merge",
            None,
            AttemptPurpose::Merge,
            Some(5),
        );
        assert_eq!(
            state.known_priced_subtotals,
            Some(KnownPricedSubtotals {
                ordinary_microcents: 7,
                housekeeping_microcents: 5
            })
        );
        assert_eq!(state.totals.ordinary.cost_microcents, Some(7));
        assert_eq!(state.totals.housekeeping.cost_microcents, None);
        let bytes = fs::read(home.accounting()).unwrap();
        drop(journal);
        let reopened = context_journal(&home.0, OWNER, None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), state);
        assert_eq!(
            reopened.settle_attempt(&last_ref, &last_receipt).unwrap(),
            state
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
        let mut conflict = last_receipt.clone();
        conflict.totals.cost_microcents = Some(6);
        assert_eq!(
            reopened.settle_attempt(&last_ref, &conflict),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            reopened.settle_attempt(&first_ref, &first_receipt),
            Err(HistoryError::StaleNonApplying)
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
        let child_id = ulid::Ulid::new().to_string();
        let _child_lease = home.lease(&child_id);
        let child = context_journal(&home.0, OWNER, Some(&child_id)).unwrap();
        child
            .initialize_accounting(AccountingBaseline::UnknownLegacy)
            .unwrap();
        let (_, _, child_state) = settle(
            child.as_ref(),
            "child-priced-ordinary",
            Some(&child_id),
            AttemptPurpose::Ordinary,
            Some(11),
        );
        assert_eq!(
            child_state.known_priced_subtotals,
            Some(KnownPricedSubtotals {
                ordinary_microcents: 11,
                housekeeping_microcents: 0
            })
        );
        assert_eq!(
            child_state.totals.knownness,
            AccountingKnownness::UnknownLegacy
        );
        assert_eq!(child_state.totals.ordinary.cost_microcents, None);
        assert_eq!(reopened.accounting_checkpoint().unwrap(), state);
        drop(child);
        assert_eq!(
            context_journal(&home.0, OWNER, Some(&child_id))
                .unwrap()
                .accounting_checkpoint()
                .unwrap(),
            child_state
        );
    }

    #[test]
    fn task2a_omitted_v1_tracking_is_unavailable_and_never_upgraded_by_read_or_sibling_write() {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        drop(journal);
        let old = omit_new_zero_field(&fs::read(home.accounting()).unwrap());
        fs::write(home.accounting(), &old).unwrap();
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        let legacy = journal.accounting_checkpoint().unwrap();
        assert_eq!(legacy.revision, AccountingRevision(0));
        assert!(legacy.known_priced_subtotals.is_none());
        assert_eq!(fs::read(home.accounting()).unwrap(), old);
        assert_eq!(
            journal.initialize_accounting(AccountingBaseline::FreshKnownZero),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            journal.initialize_accounting(AccountingBaseline::UnknownLegacy),
            Err(HistoryError::Conflict)
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), old);
        let old_text = std::str::from_utf8(&old).unwrap();
        let old_entry = old_text
            .split_once("\"entries\":[")
            .unwrap()
            .1
            .strip_suffix("]}")
            .unwrap();
        let child_id = ulid::Ulid::new().to_string();
        let _child_lease = home.lease(&child_id);
        let child = context_journal(&home.0, OWNER, Some(&child_id)).unwrap();
        assert_eq!(
            child
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap()
                .known_priced_subtotals,
            Some(KnownPricedSubtotals::known_zero())
        );
        let merged = fs::read_to_string(home.accounting()).unwrap();
        assert!(
            merged.contains(old_entry),
            "the complete old canonical owner entry must survive sibling mutation byte-for-byte"
        );
        assert!(
            journal
                .accounting_checkpoint()
                .unwrap()
                .known_priced_subtotals
                .is_none()
        );
        let (_, _, settled) = settle(
            journal.as_ref(),
            "old-unavailable-priced",
            None,
            AttemptPurpose::Ordinary,
            Some(9),
        );
        assert!(settled.known_priced_subtotals.is_none());
        assert_eq!(settled.totals.ordinary.cost_microcents, Some(9));
        drop(journal);
        let reopened = context_journal(&home.0, OWNER, None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), settled);
        let doc: Value = serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
        let owner = doc["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["namespace"]["kind"] == "owner")
            .unwrap();
        assert!(owner.get("known_priced_subtotals").is_none());
    }

    #[test]
    fn task2a_malformed_present_tracking_is_refused_without_rewrite_or_reset() {
        for replacement in [
            "null",
            "{}",
            "{\"ordinary_microcents\":0}",
            "{\"ordinary_microcents\":-1,\"housekeeping_microcents\":0}",
            "{\"ordinary_microcents\":\"0\",\"housekeeping_microcents\":0}",
            "{\"ordinary_microcents\":0.5,\"housekeeping_microcents\":0}",
            "{\"ordinary_microcents\":18446744073709551616,\"housekeeping_microcents\":0}",
            "{\"ordinary_microcents\":0,\"housekeeping_microcents\":0,\"extra\":1}",
            "{\"ordinary_microcents\":0,\"ordinary_microcents\":0,\"housekeeping_microcents\":0}",
            "{\"ordinary_microcents\":0,\"housekeeping_microcents\":0},\"known_priced_subtotals\":{\"ordinary_microcents\":0,\"housekeeping_microcents\":0}",
            "{\"housekeeping_microcents\":0,\"ordinary_microcents\":0}",
        ] {
            let home = Home::new();
            let _lease = home.lease(OWNER);
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            journal
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            drop(journal);
            let text = fs::read_to_string(home.accounting()).unwrap();
            let valid = "\"known_priced_subtotals\":{\"ordinary_microcents\":0,\"housekeeping_microcents\":0}";
            assert_eq!(text.matches(valid).count(), 1);
            let malformed = text.replacen(
                valid,
                &format!("\"known_priced_subtotals\":{replacement}"),
                1,
            );
            fs::write(home.accounting(), malformed.as_bytes()).unwrap();
            assert!(
                matches!(
                    context_journal(&home.0, OWNER, None),
                    Err(HistoryError::InvalidRecord)
                ),
                "present invalid tracking must not be treated as absent: {replacement}"
            );
            assert_eq!(fs::read(home.accounting()).unwrap(), malformed.as_bytes());
        }
    }

    #[test]
    fn task2a_known_priced_overflow_preserves_pending_and_prior_full_receipt() {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        settle(
            journal.as_ref(),
            "unknown-price-first",
            None,
            AttemptPurpose::Ordinary,
            None,
        );
        let (_, maximum_receipt, maximum) = settle(
            journal.as_ref(),
            "known-priced-maximum",
            None,
            AttemptPurpose::Ordinary,
            Some(u64::MAX),
        );
        assert_eq!(maximum.totals.ordinary.cost_microcents, None);
        assert_eq!(
            maximum.known_priced_subtotals,
            Some(KnownPricedSubtotals {
                ordinary_microcents: u64::MAX,
                housekeeping_microcents: 0
            })
        );
        let mut request = intent("known-priced-overflow", None);
        request.purpose = AttemptPurpose::Ordinary;
        let reference = journal.begin_attempt(maximum.revision, &request).unwrap();
        let before = journal.accounting_checkpoint().unwrap();
        let bytes = fs::read(home.accounting()).unwrap();
        let mut receipt = billed("known-priced-overflow", 1, 1, Some(1));
        receipt.purpose = AttemptPurpose::Ordinary;
        assert_eq!(
            journal.settle_attempt(&reference, &receipt),
            Err(HistoryError::TooLarge)
        );
        assert_eq!(journal.accounting_checkpoint().unwrap(), before);
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
        drop(journal);
        let reopened = context_journal(&home.0, OWNER, None).unwrap();
        assert_eq!(reopened.accounting_checkpoint().unwrap(), before);
        let doc: Value = serde_json::from_slice(&fs::read(home.accounting()).unwrap()).unwrap();
        assert_eq!(
            doc["entries"][0]["last"]["receipt"]["request_id"],
            maximum_receipt.request_id
        );
        assert_eq!(
            doc["entries"][0]["last"]["receipt"]["totals"]["cost_microcents"],
            json!(u64::MAX)
        );
        assert_eq!(before.pending.unwrap().intent, request);
    }

    #[test]
    fn task2a_unknown_usage_and_uncertain_prefix_keep_prior_known_price_without_fabricating_cost() {
        for uncertain in [false, true] {
            let home = Home::new();
            let _lease = home.lease(OWNER);
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            journal
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
            let (_, _, priced) = settle(
                journal.as_ref(),
                "known-before-unknown",
                None,
                AttemptPurpose::Ordinary,
                Some(6),
            );
            let mut request = intent("unknown-after-priced", None);
            request.purpose = AttemptPurpose::Ordinary;
            let reference = journal.begin_attempt(priced.revision, &request).unwrap();
            let prefix = ProviderUsage {
                input_tokens: 3,
                output_tokens: 2,
                cache_read_tokens: 4,
                cache_write_tokens: 5,
                reasoning_tokens: 6,
            };
            let receipt = RequestAccountingReceipt {
                request_id: request.request_id.clone(),
                purpose: AttemptPurpose::Ordinary,
                totals: AccountingTotals {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: None,
                },
                usage: Some(prefix),
                knownness: if uncertain {
                    AccountingKnownness::Uncertain
                } else {
                    AccountingKnownness::UnknownUsage
                },
                completed: !uncertain,
            };
            let state = journal.settle_attempt(&reference, &receipt).unwrap();
            assert_eq!(
                state.known_priced_subtotals,
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 6,
                    housekeeping_microcents: 0
                })
            );
            assert_eq!(state.totals.ordinary.cost_microcents, None);
            assert_eq!(state.totals.ordinary.input_tokens, 1);
            assert_eq!(state.totals.ordinary.output_tokens, 1);
            assert_eq!(state.totals.knownness, receipt.knownness);
            assert_eq!(
                state
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.uncertain),
                uncertain
            );
            let bytes = fs::read(home.accounting()).unwrap();
            drop(journal);
            let reopened = context_journal(&home.0, OWNER, None).unwrap();
            assert_eq!(reopened.accounting_checkpoint().unwrap(), state);
            assert_eq!(
                reopened.settle_attempt(&reference, &receipt).unwrap(),
                state
            );
            assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
            let doc: Value = serde_json::from_slice(&bytes).unwrap();
            let saved = if uncertain {
                &doc["entries"][0]["pending"]["uncertain_receipt"]
            } else {
                &doc["entries"][0]["last"]["receipt"]
            };
            assert_eq!(
                saved["usage"],
                json!({"input_tokens":3,"output_tokens":2,"cache_read_tokens":4,"cache_write_tokens":5,"reasoning_tokens":6})
            );
            if uncertain {
                assert_eq!(
                    reopened.begin_attempt(state.revision, &intent("must-not-replay", None)),
                    Err(HistoryError::Conflict)
                );
            }
        }
    }
}

#[test]
fn detailed_checkpoint_companion_keeps_legacy_pending_and_settled_bytes_unchanged() {
    let home = Home::new();
    let _lease = home.lease(OWNER);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    let first = journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    assert!(
        journal
            .accounting_checkpoint_detailed()
            .unwrap()
            .legacy_equivalent(&first)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let reference = journal
        .begin_attempt(AccountingRevision(0), &intent("companion", None))
        .unwrap();
    let pending = journal.accounting_checkpoint().unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    assert!(
        journal
            .accounting_checkpoint_detailed()
            .unwrap()
            .legacy_equivalent(&pending)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    let receipt = billed("companion", 7, 3, Some(11));
    let settled = journal.settle_attempt(&reference, &receipt).unwrap();
    let bytes = fs::read(home.accounting()).unwrap();
    let detailed = journal.accounting_checkpoint_detailed().unwrap();
    assert!(detailed.legacy_equivalent(&settled));
    assert!(detailed.refusals().is_none());
    assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    assert!(
        orbit_cli::context_history::inspect_accounting_detailed(&home.0, OWNER, None)
            .unwrap()
            .checkpoint
            .legacy_equivalent(&settled)
    );
}

mod detailed_storage {
    use super::*;
    use orbit_engine::KnownPricedSubtotals;
    use orbit_engine::compaction::AttemptRef;
    use orbit_engine::retry::{
        DetailedLastSettlement, OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup,
    };

    fn object(fields: &[(&str, String)]) -> String {
        format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}:{value}", scalar(key)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
    fn scalar(value: impl serde::Serialize) -> String {
        serde_json::to_string(&value).unwrap()
    }
    fn reference(value: &AttemptRef) -> String {
        object(&[
            ("revision", scalar(value.revision.0)),
            ("request_id", scalar(&value.request_id)),
            ("intent_digest", scalar(&value.intent_digest)),
        ])
    }
    fn record(value: &RefusalRecord) -> String {
        let intent = value.intent();
        let binding = value.binding();
        let budget = object(&[
            ("binding_digest", scalar(&intent.budget.binding_digest)),
            (
                "metadata_revision",
                scalar(&intent.budget.metadata_revision),
            ),
            ("policy_revision", scalar(&intent.budget.policy_revision)),
        ]);
        let intent = object(&[
            ("owner_session_id", scalar(&intent.owner_session_id)),
            ("child_id", scalar(&intent.child_id)),
            ("request_id", scalar(&intent.request_id)),
            ("purpose", scalar("ordinary")),
            ("budget", budget),
        ]);
        let binding = object(&[
            ("request_id", scalar(binding.request_id())),
            ("decision_id", scalar(binding.decision_id())),
            ("attempt_id", scalar(binding.attempt_id())),
            ("provider_digest", scalar(binding.provider_digest())),
            ("model_digest", scalar(binding.model_digest())),
            ("route_digest", scalar(binding.route_digest())),
            ("body_digest", scalar(binding.body_digest())),
            (
                "adapter_identity_sha256",
                scalar(binding.adapter_identity_sha256()),
            ),
            ("policy_digest", scalar(binding.policy_digest())),
            ("digest", scalar(binding.digest())),
        ]);
        object(&[
            ("intent", intent),
            ("attempt", reference(value.attempt())),
            ("binding", binding),
            ("observation_digest", scalar(value.observation_digest())),
            ("status", scalar(value.status())),
            ("response_body_bytes", scalar(value.response_body_bytes())),
            ("digest", scalar(value.digest())),
        ])
    }

    // This installs checked snapshot metadata into one fresh namespace. It is
    // deliberately not a live refusal writer, binding factory or durable ACK.
    fn seed_refusal(home: &Home, child: Option<&str>) -> RefusalRollup {
        let journal = context_journal(&home.0, OWNER, child).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let mut refused_intent = intent("snapshot-refusal", child);
        refused_intent.purpose = AttemptPurpose::Ordinary;
        let attempt = AttemptRef {
            revision: AccountingRevision(1),
            request_id: refused_intent.request_id.clone(),
            intent_digest: refused_intent.digest().unwrap(),
        };
        let binding = OrdinaryAttemptBindingRecord::new(
            refused_intent.request_id.clone(),
            "decision".into(),
            "attempt".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap();
        let refused =
            RefusalRecord::new(refused_intent, attempt, binding, "9".repeat(64), 503, 0).unwrap();
        let rollup = RefusalRollup::first(refused.clone()).unwrap();
        let last = object(&[
            ("reference", reference(refused.attempt())),
            ("refused", record(&refused)),
        ]);
        let encoded_rollup = object(&[
            ("count", scalar(rollup.count())),
            ("chain_digest", scalar(rollup.chain_digest())),
            (
                "previous_chain_digest",
                scalar(rollup.previous_chain_digest()),
            ),
            ("latest", record(rollup.latest())),
        ]);
        let mut raw = String::from_utf8(fs::read(home.accounting()).unwrap()).unwrap();
        assert_eq!(raw.matches("\"revision\":0").count(), 1);
        raw = raw
            .replacen("\"revision\":0", "\"revision\":2", 1)
            .replacen("\"cost_microcents\":0", "\"cost_microcents\":null", 1)
            .replacen(
                "\"knownness\":\"known\"",
                "\"knownness\":\"unknown_usage\"",
                1,
            )
            .replacen("\"last\":null", &format!("\"last\":{last}"), 1);
        let end = raw.rfind("}]}").unwrap();
        raw.insert_str(end, &format!(",\"refusals\":{encoded_rollup}"));
        assert!(raw.len() < 128 * 1024);
        fs::write(home.accounting(), raw.as_bytes()).unwrap();
        assert_eq!(
            journal.accounting_checkpoint_detailed().unwrap().refusals(),
            Some(&rollup)
        );
        rollup
    }

    #[test]
    fn detailed_none_writers_publish_exact_legacy_bytes_receipts_and_digests() {
        let legacy_home = Home::new();
        let detailed_home = Home::new();
        let _legacy_lease = legacy_home.lease(OWNER);
        let _detailed_lease = detailed_home.lease(OWNER);
        let legacy = context_journal(&legacy_home.0, OWNER, None).unwrap();
        let detailed = context_journal(&detailed_home.0, OWNER, None).unwrap();
        let first = legacy
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        assert!(
            detailed
                .initialize_accounting_detailed(AccountingBaseline::FreshKnownZero)
                .unwrap()
                .legacy_equivalent(&first)
        );
        assert_eq!(
            fs::read(legacy_home.accounting()).unwrap(),
            fs::read(detailed_home.accounting()).unwrap()
        );
        let mut revision = first.revision;
        for uncertain in [false, true] {
            let id = if uncertain { "uncertain" } else { "final" };
            let attempted = intent(id, None);
            let old_ref = legacy.begin_attempt(revision, &attempted).unwrap();
            let new_ref = detailed
                .begin_attempt_detailed(revision, &attempted, None)
                .unwrap();
            assert_eq!(old_ref, new_ref);
            assert_eq!(
                fs::read(legacy_home.accounting()).unwrap(),
                fs::read(detailed_home.accounting()).unwrap()
            );
            let mut receipt = billed(id, 11, 7, Some(13));
            receipt.usage = Some(ProviderUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_read_tokens: 3,
                cache_write_tokens: 2,
                reasoning_tokens: 5,
            });
            if uncertain {
                receipt.totals = AccountingTotals {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: None,
                };
                receipt.knownness = AccountingKnownness::Uncertain;
                receipt.completed = false;
            }
            let old = legacy.settle_attempt(&old_ref, &receipt).unwrap();
            let new = detailed
                .settle_attempt_detailed(&new_ref, &receipt)
                .unwrap();
            assert!(new.legacy_equivalent(&old));
            let old_view =
                orbit_cli::context_history::inspect_accounting(&legacy_home.0, OWNER, None)
                    .unwrap();
            let new_view = orbit_cli::context_history::inspect_accounting_detailed(
                &detailed_home.0,
                OWNER,
                None,
            )
            .unwrap();
            assert_eq!(old_view.inspection_digest, new_view.inspection_digest);
            assert_eq!(old_view.pending_receipt, new_view.pending_receipt);
            assert_eq!(old_view.last_receipt, new_view.last_legacy_receipt);
            assert_eq!(
                fs::read(legacy_home.accounting()).unwrap(),
                fs::read(detailed_home.accounting()).unwrap()
            );
            revision = old.revision;
        }
    }

    #[test]
    fn detailed_success_after_snapshot_refusal_retains_unknown_bill_rollup_and_full_receipt() {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let rollup = seed_refusal(&home, None);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        let before = fs::read(home.accounting()).unwrap();
        let checkpoint = journal.accounting_checkpoint_detailed().unwrap();
        let mut next_intent = intent("later-explicit-work", None);
        next_intent.purpose = AttemptPurpose::Ordinary;
        assert_eq!(
            journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            journal.begin_attempt(checkpoint.revision(), &next_intent),
            Err(HistoryError::InvalidRecord)
        );
        let mut legacy_receipt = billed("snapshot-refusal", 1, 1, Some(1));
        legacy_receipt.purpose = AttemptPurpose::Ordinary;
        assert_eq!(
            journal.settle_attempt(rollup.latest().attempt(), &legacy_receipt),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), before);
        let next = journal
            .begin_attempt_detailed(checkpoint.revision(), &next_intent, None)
            .unwrap();
        let mut receipt = billed("later-explicit-work", 11, 7, Some(13));
        receipt.purpose = AttemptPurpose::Ordinary;
        receipt.usage = Some(ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 3,
            cache_write_tokens: 2,
            reasoning_tokens: 5,
        });
        let settled = journal.settle_attempt_detailed(&next, &receipt).unwrap();
        assert_eq!(settled.revision(), AccountingRevision(4));
        assert_eq!(settled.refusals(), Some(&rollup));
        assert_eq!(
            settled.totals().ordinary,
            AccountingTotals {
                input_tokens: 11,
                output_tokens: 7,
                cost_microcents: None
            }
        );
        assert_eq!(
            settled.totals().knownness,
            AccountingKnownness::UnknownUsage
        );
        assert_eq!(
            settled.known_priced_subtotals(),
            Some(KnownPricedSubtotals {
                ordinary_microcents: 13,
                housekeeping_microcents: 0
            })
        );
        match settled.last_settlement().unwrap() {
            DetailedLastSettlement::Legacy(last) => {
                assert_eq!(last.receipt_digest, receipt.digest().unwrap())
            }
            DetailedLastSettlement::FinalRefusal(_) => {
                panic!("later receipt was replaced by a refusal")
            }
        }
        let bytes = fs::read(home.accounting()).unwrap();
        assert_eq!(
            journal.settle_attempt_detailed(&next, &receipt).unwrap(),
            settled
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
        let inspection =
            orbit_cli::context_history::inspect_accounting_detailed(&home.0, OWNER, None).unwrap();
        assert_eq!(inspection.last_legacy_receipt, Some(receipt));
        assert_eq!(inspection.checkpoint, settled);
        drop(journal);
        assert_eq!(
            context_journal(&home.0, OWNER, None)
                .unwrap()
                .accounting_checkpoint_detailed()
                .unwrap(),
            settled
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    }

    #[test]
    fn detailed_pending_after_snapshot_refusal_preserves_qualification_and_blocks_reopen_admission()
    {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let rollup = seed_refusal(&home, None);
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        let mut attempted = intent("later-pending", None);
        attempted.purpose = AttemptPurpose::Ordinary;
        let reference = journal
            .begin_attempt_detailed(AccountingRevision(2), &attempted, None)
            .unwrap();
        let mut receipt = billed("later-pending", 0, 0, None);
        receipt.purpose = AttemptPurpose::Ordinary;
        receipt.usage = Some(ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 3,
            cache_write_tokens: 2,
            reasoning_tokens: 5,
        });
        receipt.knownness = AccountingKnownness::Uncertain;
        receipt.completed = false;
        let uncertain = journal
            .settle_attempt_detailed(&reference, &receipt)
            .unwrap();
        assert_eq!(uncertain.refusals(), Some(&rollup));
        assert_eq!(uncertain.revision(), AccountingRevision(4));
        assert_eq!(uncertain.totals().knownness, AccountingKnownness::Uncertain);
        assert!(uncertain.pending().unwrap().uncertain);
        let bytes = fs::read(home.accounting()).unwrap();
        drop(journal);
        let reopened = context_journal(&home.0, OWNER, None).unwrap();
        assert_eq!(
            reopened.accounting_checkpoint_detailed().unwrap(),
            uncertain
        );
        assert_eq!(
            orbit_cli::context_history::inspect_accounting_detailed(&home.0, OWNER, None)
                .unwrap()
                .pending_receipt,
            Some(receipt.clone())
        );
        assert_eq!(
            reopened
                .settle_attempt_detailed(&reference, &receipt)
                .unwrap(),
            uncertain
        );
        let next = intent("must-not-replay", None);
        assert!(
            reopened
                .begin_attempt_detailed(uncertain.revision(), &next, None)
                .is_err()
        );
        assert_eq!(fs::read(home.accounting()).unwrap(), bytes);
    }

    #[test]
    fn qualified_child_and_legacy_owner_writes_keep_selected_namespace_boundaries() {
        let home = Home::new();
        let _lease = home.lease(OWNER);
        let child = "00000000000000000000000001";
        let rollup = seed_refusal(&home, Some(child));
        let child_journal = context_journal(&home.0, OWNER, Some(child)).unwrap();
        let child_before = child_journal.accounting_checkpoint_detailed().unwrap();
        assert_eq!(child_before.child_id(), Some(child));
        let owner = context_journal(&home.0, OWNER, None).unwrap();
        let root = owner
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let reference = owner
            .begin_attempt(root.revision, &intent("owner-only", None))
            .unwrap();
        let receipt = billed("owner-only", 2, 3, Some(5));
        let root = owner.settle_attempt(&reference, &receipt).unwrap();
        assert_eq!(root.totals.housekeeping.cost_microcents, Some(5));
        assert_eq!(
            child_journal.accounting_checkpoint_detailed().unwrap(),
            child_before
        );
        assert_eq!(child_before.refusals(), Some(&rollup));
        assert_eq!(
            child_journal.accounting_checkpoint(),
            Err(HistoryError::InvalidRecord)
        );
        assert_eq!(
            orbit_cli::context_history::inspect_accounting(&home.0, OWNER, None)
                .unwrap()
                .checkpoint,
            root
        );
        assert_eq!(
            orbit_cli::context_history::inspect_accounting_detailed(&home.0, OWNER, Some(child))
                .unwrap()
                .checkpoint,
            child_before
        );
        assert_eq!(owner.accounting_checkpoint().unwrap(), root);
    }
}
