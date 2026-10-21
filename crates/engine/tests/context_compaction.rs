#![deny(unsafe_code)]

use orbit_adapter::types::{
    ChatMessage, ChatRole, ContentBlock, CostRates, Sha256Digest, ToolCallMessage, ToolDefinition,
};
use orbit_engine::{
    PendingToolCall, ProviderKind, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions,
};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[path = "support/compaction_journal.rs"]
pub mod compaction_journal;
use compaction_journal::{Failure, MemoryJournal};
use orbit_engine::compaction::{
    self, AccountingBaseline, AccountingKnownness, AccountingRevision, AttemptIntent,
    AttemptPurpose, CompactionJournal, CompactionStatus, HistoryError, RequestAccountingReceipt,
};

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 10;
const INTENT: &str = "continue exact current task λ";
const ANSWER: &str = "ordinary completed answer";
const SUMMARY: &str = "short synthetic summary";
const HIDDEN: &str = "PRIVATE-ORIGINAL-THOUGHT";

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("orbit-context-compaction-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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

fn config(fixture: &Fixture, summary: bool) -> TurnConfig {
    TurnConfig {
        provider_id: if summary {
            "summary-provider"
        } else {
            "main-provider"
        }
        .into(),
        gate: fixture.url.clone(),
        model: if summary {
            "raw-summary/model"
        } else {
            "raw-main/model"
        }
        .into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: if summary { 37 } else { 73 },
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    }
}

fn pair(source: &mut Vec<ChatMessage>, label: &str, bytes: usize) {
    source.push(orbit_engine::user_message(format!(
        "{label}-USER {} {label}-USER-END",
        "u".repeat(bytes)
    )));
    source.push(orbit_engine::assistant_message(format!(
        "{label}-ASSISTANT {} {label}-ASSISTANT-END",
        "a".repeat(bytes)
    )));
}

fn history(groups: usize, bytes: usize) -> Vec<ChatMessage> {
    let mut source = Vec::new();
    for index in 0..groups {
        pair(&mut source, &format!("OLDER-{index}"), bytes);
    }
    pair(&mut source, "LATEST", 0);
    source.push(orbit_engine::user_message(INTENT));
    source
}

fn body_estimate(body: &Value) -> u64 {
    (serde_json::to_vec(body).unwrap().len() as u64).div_ceil(4)
}

#[derive(Default)]
struct NoEffects(usize);
impl ToolExecutor for NoEffects {
    fn execute(&mut self, _: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        panic!("compaction must not execute historical/provider tools")
    }
}

fn assert_transport(fixture: &Fixture) {
    for request in fixture.requests.lock().unwrap().iter() {
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
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "content-type" && value == "application/json")
        );
    }
}

fn options(
    fixture: &Fixture,
    journal: &Arc<MemoryJournal>,
    main_window: u64,
    summary_window: u64,
) -> TurnOptions {
    let c = config(fixture, false);
    let s = config(fixture, true);
    TurnOptions {
        max_attempts: 1,
        max_rounds: 1,
        session_id: "service-owner".into(),
        request_stem: "compaction-service".into(),
        system_directive: Some("immutable selected system directive".into()),
        tools: vec![ToolDefinition {
            name: "inspect".into(),
            description: "inspect exact state".into(),
            parameters: json!({"type":"object"}),
            schema_digest: Sha256Digest("fixture".into()),
        }],
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&c, main_window).unwrap(),
        ),
        compaction_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&s, summary_window).unwrap(),
        ),
        compaction_config: Some(s),
        journal: Some(journal.clone()),
        ..Default::default()
    }
}

fn assert_ids(home: &Home, journal: &MemoryJournal, post_count: usize) {
    let records = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0;
    let egress: Vec<_> = records
        .into_iter()
        .filter_map(|record| match record.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                Some((event.session_id, event.decision_id))
            }
            _ => None,
        })
        .collect();
    assert_eq!(egress.len(), post_count);
    let intents = journal.intents();
    let receipts = journal.receipts();
    assert_eq!(intents.len(), receipts.len());
    assert_eq!(
        intents.len(),
        post_count,
        "every actual dispatch must have exactly one durable intent and receipt"
    );
    for ((intent, receipt), (session, decision)) in intents.iter().zip(&receipts).zip(&egress) {
        assert_eq!(&intent.request_id, decision);
        assert_eq!(intent.request_id, receipt.request_id);
        assert_eq!(intent.purpose, receipt.purpose);
        assert_eq!(
            session,
            intent.child_id.as_ref().unwrap_or(&intent.owner_session_id)
        );
    }
    let unique: std::collections::BTreeSet<_> = egress.iter().map(|(_, id)| id).collect();
    assert_eq!(unique.len(), egress.len());
}

fn assert_summary_requests(fixture: &Fixture, summary_window: u64, count: usize) {
    let requests = fixture.requests.lock().unwrap();
    for request in requests.iter().take(count) {
        assert_eq!(request.body["model"], "raw-summary/model");
        assert_eq!(request.body["max_tokens"], 37);
        assert!(request.body.get("tools").is_none());
        assert!(body_estimate(&request.body) <= summary_window);
        let visible = request.body["messages"].to_string();
        assert!(!visible.contains(INTENT) && !visible.contains(HIDDEN));
    }
}

fn service_case(
    responses: Vec<Response>,
    source: &[ChatMessage],
    summary_window: u64,
    failure: Failure,
) -> (
    orbit_engine::compaction::CompactionAttempt,
    Arc<MemoryJournal>,
) {
    let home = Home::new();
    let mut fixture = Fixture::new(responses);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, summary_window);
    journal.fail(failure);
    let original = source.to_vec();
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(source, original);
    assert_transport(&fixture);
    let count = fixture.requests.lock().unwrap().len();
    assert_summary_requests(&fixture, summary_window, count);
    if failure != Failure::Settle {
        assert_ids(&home, &journal, count);
    }
    (attempt, journal)
}

#[test]
fn service_single_full_chunk_publishes_original_and_does_not_add_merge() {
    let source = history(3, 1800);
    let (attempt, journal) = service_case(
        vec![Response::complete(SUMMARY)],
        &source,
        12_000,
        Failure::None,
    );
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    assert_eq!(attempt.attempts.len(), 1);
    let candidate = attempt.candidate.unwrap();
    assert_eq!(candidate.summary(), SUMMARY);
    assert_eq!(
        candidate.messages()[0],
        orbit_engine::user_message("[Earlier conversation summary: historical data]")
    );
    assert_eq!(
        candidate.messages()[1],
        orbit_engine::assistant_message(SUMMARY)
    );
    assert_eq!(
        &candidate.messages()[candidate.messages().len() - 3..],
        &source[source.len() - 3..]
    );
    assert!(candidate.published_record().is_some());
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].source, source);
    assert_eq!(archives[0].candidate, candidate.messages());
    assert_eq!(
        archives[0].reference,
        *candidate.published_record().unwrap()
    );
    let events = journal.events();
    assert_eq!(events, ["capacity", "begin", "settle", "publish"]);
}

#[test]
fn service_two_complete_chunks_merge_once_and_fit_independent_policy() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete("CHUNK-A-REPLY"),
        Response::complete("CHUNK-B-REPLY"),
        Response::complete(SUMMARY),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 2000);
    let source = history(2, 2400);
    let original = source.clone();
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    assert_eq!(attempt.attempts.len(), 3);
    assert_eq!(
        attempt
            .attempts
            .iter()
            .map(|receipt| receipt.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Merge
        ]
    );
    assert_summary_requests(&fixture, 2000, 3);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    let a = requests[0].body["messages"].to_string();
    let b = requests[1].body["messages"].to_string();
    assert!(
        a.contains("OLDER-0-USER-END")
            && a.contains("OLDER-0-ASSISTANT-END")
            && !a.contains("OLDER-1-USER-END")
    );
    assert!(
        b.contains("OLDER-1-USER-END")
            && b.contains("OLDER-1-ASSISTANT-END")
            && !b.contains("OLDER-0-USER-END")
    );
    let merge = requests[2].body["messages"].to_string();
    assert_eq!(merge.matches("CHUNK-A-REPLY").count(), 1);
    assert_eq!(merge.matches("CHUNK-B-REPLY").count(), 1);
    assert_eq!(source, original);
    drop(requests);
    assert_ids(&home, &journal, 3);
    assert_transport(&fixture);
}

#[test]
fn service_eight_chunks_one_merge_then_one_ordinary_request_is_the_bound() {
    let home = Home::new();
    let mut replies: Vec<_> = (0..8)
        .map(|i| Response::complete(&format!("CHUNK-{i}-REPLY")))
        .collect();
    replies.extend([Response::complete(SUMMARY), Response::complete(ANSWER)]);
    let mut fixture = Fixture::new(replies);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 2000);
    let mut source = history(8, 2400);
    let intent = source.pop().unwrap();
    let mut expected = source.clone();
    expected.push(intent.clone());
    let tail = expected[expected.len() - 3..].to_vec();
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |e| events.push(e),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 10);
    assert_summary_requests(&fixture, 2000, 9);
    let requests = fixture.requests.lock().unwrap();
    for (i, request) in requests.iter().take(8).enumerate() {
        assert!(
            request.body["messages"]
                .to_string()
                .contains(&format!("OLDER-{i}-USER-END"))
        );
    }
    let merge = requests[8].body["messages"].to_string();
    for i in 0..8 {
        assert_eq!(merge.matches(&format!("CHUNK-{i}-REPLY")).count(), 1);
    }
    assert_eq!(requests[9].body["model"], "raw-main/model");
    assert_eq!(requests[9].body["max_tokens"], 73);
    assert!(body_estimate(&requests[9].body) <= 1000);
    let end = source.len() - 1;
    assert_eq!(source[end].content, ANSWER);
    assert_eq!(&source[end - tail.len()..end], tail.as_slice());
    assert_eq!(journal.archives()[0].source, expected);
    assert_eq!(journal.intents().len(), 10);
    assert_eq!(
        journal
            .intents()
            .iter()
            .map(|intent| intent.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Merge,
            AttemptPurpose::Ordinary
        ]
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|e| if let FrontendEvent::TextDelta { text } = e {
                Some(text.as_str())
            } else {
                None
            })
            .collect::<Vec<_>>(),
        [ANSWER]
    );
    drop(requests);
    assert_ids(&home, &journal, 10);
    assert_transport(&fixture);
}

#[test]
fn service_more_than_eight_required_chunks_refuses_before_an_extra_summary() {
    let source = history(9, 2400);
    let (attempt, journal) = service_case(Vec::new(), &source, 2000, Failure::None);
    assert_eq!(attempt.status, CompactionStatus::SummaryTooLarge);
    assert!(attempt.candidate.is_none() && attempt.attempts.is_empty());
    assert!(journal.intents().is_empty() && journal.archives().is_empty());
}

#[test]
fn service_oversized_indivisible_group_refuses_without_truncating_state() {
    let source = history(1, 9000);
    let (attempt, journal) = service_case(Vec::new(), &source, 2000, Failure::None);
    assert_eq!(attempt.status, CompactionStatus::SummaryTooLarge);
    assert!(attempt.candidate.is_none() && journal.intents().is_empty());
}

#[test]
fn service_invalid_terminal_empty_and_ineffective_summaries_preserve_source() {
    for (text, reason) in [
        ("summary", "length"),
        ("summary", "content_filter"),
        ("", "stop"),
        (" \n\t", "stop"),
    ] {
        let source = history(3, 1800);
        let (attempt, journal) = service_case(
            vec![Response::text(
                text,
                reason,
                Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
            )],
            &source,
            12_000,
            Failure::None,
        );
        assert!(attempt.candidate.is_none());
        assert_ne!(attempt.status, CompactionStatus::PublishedReady);
        assert_eq!(attempt.attempts.len(), 1);
        assert!(journal.archives().is_empty());
    }
    let source = history(3, 1800);
    let (attempt, journal) = service_case(
        vec![Response::complete(&"oversized summary ".repeat(1000))],
        &source,
        12_000,
        Failure::None,
    );
    assert!(attempt.candidate.is_none());
    assert_eq!(attempt.attempts.len(), 1);
    assert!(journal.archives().is_empty());
}

#[test]
fn service_capacity_namespace_begin_settle_and_publish_failures_stop_progress() {
    for failure in [
        Failure::Capacity,
        Failure::Namespace,
        Failure::Begin,
        Failure::Settle,
        Failure::Publish,
        Failure::PublishUncertain,
    ] {
        let responses = if matches!(
            failure,
            Failure::Settle | Failure::Publish | Failure::PublishUncertain
        ) {
            vec![Response::complete(SUMMARY)]
        } else {
            Vec::new()
        };
        let (attempt, journal) = service_case(responses, &history(3, 1800), 12_000, failure);
        assert!(attempt.candidate.is_none());
        assert_ne!(attempt.status, CompactionStatus::PublishedReady);
        assert!(journal.archives().is_empty());
        if matches!(
            failure,
            Failure::Capacity | Failure::Namespace | Failure::Begin
        ) {
            assert!(journal.intents().is_empty());
        }
        if failure == Failure::Settle {
            assert!(journal.accounting_checkpoint().unwrap().pending.is_some());
        }
    }
}

#[test]
fn service_cancel_after_publication_keeps_orphan_and_does_not_apply() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let journal = MemoryJournal::fresh("service-owner");
    let cancel = CancelToken::new();
    journal.cancel_after_publication(cancel.clone());
    let direct_options = options(&fixture, &journal, 1000, 12_000);
    let source = history(3, 1800);
    let original = source.clone();
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &direct_options,
        &source,
        &cancel,
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::Cancelled);
    assert!(attempt.candidate.is_none());
    assert_eq!(source, original);
    assert_eq!(journal.archives().len(), 1);
    assert_eq!(journal.archives()[0].source, original);
    assert_eq!(attempt.attempts.len(), 1);
    // Exercise the real owner's replacement boundary too: the archive is an
    // orphan after cancellation, while the working transcript stays original.
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let journal = MemoryJournal::fresh("service-owner");
    let cancel = CancelToken::new();
    journal.cancel_after_publication(cancel.clone());
    let options = options(&fixture, &journal, 1000, 12_000);
    let mut transcript = history(3, 1800);
    let expected = transcript.clone();
    transcript.pop();
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut transcript,
        &mut executor,
        &cancel,
        &mut |e| events.push(e),
    )
    .unwrap();
    fixture.finish();
    assert!(report.interrupted && !report.ok);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(transcript, expected);
    assert_eq!(journal.archives().len(), 1);
    assert_eq!(journal.archives()[0].source, expected);
    assert!(!events.iter().any(|e| matches!(
        e,
        FrontendEvent::Compacted { .. } | FrontendEvent::TextDelta { .. }
    )));
}

#[test]
fn service_pre_cancelled_request_has_no_archive_or_provider_effect() {
    let home = Home::new();
    let mut fixture = Fixture::new(Vec::new());
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let cancel = CancelToken::new();
    cancel.cancel();
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &history(3, 1800),
        &cancel,
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::Cancelled);
    assert!(journal.intents().is_empty() && journal.archives().is_empty());
}

#[test]
fn service_priced_summary_cost_is_settled_once_and_unpriced_is_unknown() {
    for priced in [true, false] {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
        let journal = MemoryJournal::fresh("service-owner");
        let mut options = options(&fixture, &journal, 1000, 12_000);
        if priced {
            options.compaction_config.as_mut().unwrap().pricing = Some(CostRates {
                input_per_million_microcents: 1_000_000,
                output_per_million_microcents: 2_000_000,
                cache_read_per_million_microcents: None,
                cache_write_per_million_microcents: None,
                reasoning_per_million_microcents: None,
                request_flat_microcents: 3,
            });
        }
        let attempt = compaction::compact_context(
            &home.0,
            &config(&fixture, false),
            &options,
            &history(3, 1800),
            &CancelToken::new(),
        );
        fixture.finish();
        assert_eq!(attempt.status, CompactionStatus::PublishedReady);
        assert_eq!(attempt.accounting.housekeeping.input_tokens, 11);
        assert_eq!(attempt.accounting.housekeeping.output_tokens, 7);
        assert_eq!(
            attempt.accounting.housekeeping.cost_microcents,
            priced.then_some(28)
        );
        assert_eq!(attempt.accounting.ordinary.input_tokens, 0);
        assert_eq!(attempt.attempts[0].knownness, AccountingKnownness::Known);
        let checkpoint = journal.accounting_checkpoint().unwrap();
        assert_eq!(
            checkpoint.totals.housekeeping,
            attempt.accounting.housekeeping
        );
        assert!(checkpoint.pending.is_none());
        let reference = checkpoint
            .last_settlement
            .as_ref()
            .unwrap()
            .reference
            .clone();
        assert_eq!(
            journal
                .settle_attempt(&reference, &attempt.attempts[0])
                .unwrap(),
            checkpoint
        );
        assert_eq!(journal.receipts().len(), 1);
    }
}

#[test]
fn service_positive_missing_usage_and_explicit_zero_keep_presence_distinct() {
    for usage in [
        None,
        Some(json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0})),
    ] {
        let present = usage.is_some();
        let (attempt, journal) = service_case(
            vec![Response::text(SUMMARY, "stop", usage)],
            &history(3, 1800),
            12_000,
            Failure::None,
        );
        assert_eq!(attempt.status, CompactionStatus::PublishedReady);
        assert_eq!(attempt.attempts[0].usage.is_some(), present);
        assert_eq!(
            attempt.attempts[0].knownness,
            if present {
                AccountingKnownness::Known
            } else {
                AccountingKnownness::UnknownUsage
            }
        );
        assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
        assert_eq!(attempt.accounting.housekeeping.cost_microcents, None);
        assert_eq!(
            journal.retained_receipts(),
            (Some(attempt.attempts[0].clone()), None)
        );
    }
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::text(
        SUMMARY,
        "stop",
        Some(json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0})),
    )]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1000, 12_000);
    options.compaction_config.as_mut().unwrap().pricing = Some(CostRates {
        input_per_million_microcents: 1,
        output_per_million_microcents: 1,
        cache_read_per_million_microcents: None,
        cache_write_per_million_microcents: None,
        reasoning_per_million_microcents: None,
        request_flat_microcents: 5,
    });
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &history(3, 1800),
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    assert!(attempt.attempts[0].usage.is_some());
    assert_eq!(attempt.attempts[0].totals.cost_microcents, Some(5));
    assert_eq!(attempt.accounting.housekeeping.cost_microcents, Some(5));
}

#[test]
fn service_known_billed_truncation_is_returned_without_a_candidate() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::text(
        "truncated private summary",
        "length",
        Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
    )]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1000, 12_000);
    options.compaction_config.as_mut().unwrap().pricing = Some(CostRates {
        input_per_million_microcents: 1_000_000,
        output_per_million_microcents: 2_000_000,
        cache_read_per_million_microcents: None,
        cache_write_per_million_microcents: None,
        reasoning_per_million_microcents: None,
        request_flat_microcents: 3,
    });
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &history(3, 1800),
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(attempt.candidate.is_none());
    assert_eq!(attempt.attempts.len(), 1);
    assert_eq!(attempt.attempts[0].knownness, AccountingKnownness::Known);
    assert!(!attempt.attempts[0].completed);
    assert_eq!(attempt.accounting.housekeeping.cost_microcents, Some(28));
    assert_eq!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .totals
            .housekeeping
            .cost_microcents,
        Some(28)
    );
    assert!(journal.archives().is_empty());
}

#[test]
fn service_cancellation_during_stream_retains_pending_uncertainty() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response { body:"data: {\"choices\":[{\"delta\":{\"content\":\"private partial\"},\"finish_reason\":null}]}\n\n".into(), pause:true }]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let cancel = CancelToken::new();
    let cancelling = cancel.clone();
    let calls = fixture.requests.clone();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while calls.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        cancelling.cancel();
    });
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &history(3, 1800),
        &cancel,
    );
    thread.join().unwrap();
    fixture.finish();
    assert!(attempt.candidate.is_none());
    assert!(matches!(
        attempt.status,
        CompactionStatus::Cancelled | CompactionStatus::AccountingUncertain
    ));
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert!(
        checkpoint
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain),
        "status={:?}, attempts={:?}, checkpoint={checkpoint:?}",
        attempt.status,
        attempt.attempts,
    );
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
    assert!(journal.archives().is_empty());
    let retained = journal.retained_receipts();
    assert!(retained.0.is_none());
    assert_eq!(retained.1.as_ref(), attempt.attempts.last());
    assert_eq!(checkpoint.totals.housekeeping.cost_microcents, None);
}

#[test]
fn journal_fixture_revisions_scope_idempotence_and_stale_references_are_real() {
    let journal = MemoryJournal::fresh("service-owner");
    assert_eq!(
        journal.initialize_accounting(AccountingBaseline::FreshKnownZero),
        Err(HistoryError::Conflict)
    );
    let c = TurnConfig {
        provider_id: "p".into(),
        gate: "http://127.0.0.1:9".into(),
        model: "m".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 37,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    };
    let budget =
        orbit_engine::context_budget::BudgetIdentity::for_config(&c, "metadata", "policy").unwrap();
    let intent = AttemptIntent {
        owner_session_id: "service-owner".into(),
        child_id: None,
        request_id: "first-request".into(),
        purpose: AttemptPurpose::Chunk,
        budget: budget.clone(),
    };
    assert_eq!(
        journal.begin_attempt(AccountingRevision(99), &intent),
        Err(HistoryError::Conflict)
    );
    let first = journal
        .begin_attempt(AccountingRevision(0), &intent)
        .unwrap();
    assert_eq!(
        journal
            .begin_attempt(AccountingRevision(0), &intent)
            .unwrap(),
        first
    );
    assert_eq!(journal.intents().len(), 1);
    let receipt = RequestAccountingReceipt {
        request_id: intent.request_id.clone(),
        purpose: AttemptPurpose::Chunk,
        totals: orbit_engine::AccountingTotals {
            input_tokens: 1,
            output_tokens: 2,
            cost_microcents: Some(3),
        },
        usage: Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 1,
            output_tokens: 2,
            ..Default::default()
        }),
        knownness: AccountingKnownness::Known,
        completed: true,
    };
    let settled = journal.settle_attempt(&first, &receipt).unwrap();
    assert_eq!(journal.settle_attempt(&first, &receipt).unwrap(), settled);
    assert_eq!(journal.retained_receipts(), (Some(receipt.clone()), None));
    let mut conflict = receipt.clone();
    conflict.totals.cost_microcents = Some(4);
    assert_eq!(
        journal.settle_attempt(&first, &conflict),
        Err(HistoryError::Conflict)
    );
    let mut second = intent.clone();
    second.request_id = "second-request".into();
    let reference = journal.begin_attempt(settled.revision, &second).unwrap();
    let mut second_receipt = receipt.clone();
    second_receipt.request_id = second.request_id;
    journal.settle_attempt(&reference, &second_receipt).unwrap();
    assert_eq!(
        journal.settle_attempt(&first, &receipt),
        Err(HistoryError::StaleNonApplying)
    );
    let mut foreign = intent;
    foreign.owner_session_id = "foreign-owner".into();
    assert_eq!(
        journal.begin_attempt(AccountingRevision(4), &foreign),
        Err(HistoryError::InvalidRecord)
    );
    let before = journal.accounting_checkpoint().unwrap();
    let third = AttemptIntent {
        owner_session_id: "service-owner".into(),
        child_id: None,
        request_id: "third-request".into(),
        purpose: AttemptPurpose::Chunk,
        budget,
    };
    let third_ref = journal.begin_attempt(before.revision, &third).unwrap();
    let uncertain = RequestAccountingReceipt {
        request_id: third.request_id,
        purpose: AttemptPurpose::Chunk,
        totals: orbit_engine::AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None,
        },
        usage: Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 9,
            output_tokens: 4,
            ..Default::default()
        }),
        knownness: AccountingKnownness::Uncertain,
        completed: false,
    };
    let pending = journal.settle_attempt(&third_ref, &uncertain).unwrap();
    assert_eq!(
        pending.totals,
        before.totals.checked_with(&uncertain).unwrap()
    );
    assert_eq!(pending.last_settlement, before.last_settlement);
    assert_eq!(
        journal.retained_receipts(),
        (Some(second_receipt), Some(uncertain.clone()))
    );
    assert_eq!(
        journal.settle_attempt(&third_ref, &uncertain).unwrap(),
        pending
    );
    assert_eq!(journal.receipts().len(), 3);
}

#[test]
fn journal_fixture_one_bounded_owner_container_keeps_children_independent() {
    let journal = MemoryJournal::fresh("service-owner");
    let child = journal
        .child(
            &ulid::Ulid::new().to_string(),
            AccountingBaseline::UnknownLegacy,
        )
        .unwrap();
    assert_eq!(
        child.accounting_checkpoint().unwrap().totals.knownness,
        AccountingKnownness::UnknownLegacy
    );
    assert_eq!(
        journal.accounting_checkpoint().unwrap().totals.knownness,
        AccountingKnownness::Known
    );
    let mut accepted = 0;
    loop {
        match journal.child(
            &ulid::Ulid::new().to_string(),
            AccountingBaseline::FreshKnownZero,
        ) {
            Ok(_) => accepted += 1,
            Err(HistoryError::Full) => break,
            Err(error) => panic!("unexpected bounded fixture error: {error}"),
        }
        assert!(
            accepted < 128,
            "encoded reservation must bound the shared owner container"
        );
    }
    assert!(accepted > 1);
    assert!(
        journal.reserved_metadata_bytes()
            <= orbit_engine::compaction::MAX_ACCOUNTING_CHECKPOINT_BYTES
    );
    assert_eq!(
        journal.accounting_checkpoint().unwrap().revision,
        AccountingRevision(0)
    );
    assert_eq!(
        child.accounting_checkpoint().unwrap().totals.knownness,
        AccountingKnownness::UnknownLegacy
    );
}

#[test]
fn service_parallel_group_keeps_exact_typed_tail_and_full_visible_old_payloads() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete(SUMMARY),
        Response::complete(ANSWER),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1500, 12_000);
    let call = |id: &str, args: String| ToolCallMessage {
        id: id.into(),
        name: "inspect".into(),
        arguments: args,
    };
    let result = |id: &str, text: String| {
        let mut m = orbit_engine::user_message("fallback must not duplicate selected result");
        m.role = ChatRole::Tool;
        m.tool_call_id = Some(id.into());
        m.tool_result = Some(text);
        m
    };
    let mut source = vec![orbit_engine::user_message(format!(
        "{}OLD-TEXT-END",
        "u".repeat(4000)
    ))];
    let mut called = orbit_engine::assistant_message("");
    called.tool_calls = Some(vec![call(
        "old-call",
        format!("{{\"path\":\"{}ARGUMENT-END\"}}", "x".repeat(900)),
    )]);
    source.push(called);
    source.push(result("old-call", format!("{}RESULT-END", "r".repeat(900))));
    let mut done = orbit_engine::assistant_message("old complete visible state");
    done.blocks = Some(vec![ContentBlock::Opaque {
        json: json!({"type":"thinking","thinking":HIDDEN,"signature":"original-private-signature"})
            .to_string(),
    }]);
    done.origin_provider = Some("foreign-provider".into());
    done.origin_model = Some("foreign-model".into());
    source.push(done);
    let retained = source.len();
    source.push(orbit_engine::user_message(
        "newest complete parallel exchange",
    ));
    let mut parallel = orbit_engine::assistant_message("four exact lookups");
    parallel.tool_calls = Some(
        (0..4)
            .map(|i| call(&format!("latest-{i}"), "{\"path\":\"exact\"}".into()))
            .collect(),
    );
    source.push(parallel);
    for i in [2, 0, 3, 1] {
        source.push(result(
            &format!("latest-{i}"),
            format!("exact result {i} λ"),
        ));
    }
    source.push(orbit_engine::assistant_message("latest exchange completed"));
    let mut intent = orbit_engine::user_message(INTENT);
    intent.blocks = Some(vec![ContentBlock::Text {
        text: INTENT.into(),
    }]);
    options.user_blocks = intent.blocks.clone();
    let mut original = source.clone();
    original.push(intent.clone());
    let tail = original[retained..].to_vec();
    assert!(tail.len() > 6);
    let mut events = Vec::new();
    let mut executor = NoEffects::default();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |e| events.push(e),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    assert_summary_requests(&fixture, 12_000, 1);
    let requests = fixture.requests.lock().unwrap();
    let summary = requests[0].body["messages"].to_string();
    for marker in ["OLD-TEXT-END", "ARGUMENT-END", "RESULT-END"] {
        assert_eq!(summary.matches(marker).count(), 1);
    }
    assert!(!requests[1].body.to_string().contains(HIDDEN));
    assert!(body_estimate(&requests[1].body) <= 1500);
    let end = source.len() - 1;
    assert_eq!(&source[end - tail.len()..end], tail.as_slice());
    assert_eq!(journal.archives()[0].source, original);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, FrontendEvent::Compacted { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|e| if let FrontendEvent::TextDelta { text } = e {
                Some(text.as_str())
            } else {
                None
            })
            .collect::<Vec<_>>(),
        [ANSWER]
    );
    assert!(!format!("{events:?}").contains(HIDDEN));
    assert_ids(&home, &journal, 2);
}

#[test]
fn service_unfit_merge_preserves_two_accounted_chunk_attempts() {
    let source = history(2, 2400);
    let (attempt, journal) = service_case(
        vec![
            Response::complete(&"chunk a ".repeat(700)),
            Response::complete(&"chunk b ".repeat(700)),
        ],
        &source,
        2000,
        Failure::None,
    );
    assert_eq!(attempt.status, CompactionStatus::SummaryTooLarge);
    assert!(attempt.candidate.is_none());
    assert_eq!(attempt.attempts.len(), 2);
    assert_eq!(journal.receipts().len(), 2);
    assert!(journal.archives().is_empty());
}

#[test]
fn service_summary_tool_call_is_rejected_without_executing_or_replaying_it() {
    let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"unadvertised-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let response = Response {
        body: format!("data: {event}\n\ndata: [DONE]\n\n"),
        pause: false,
    };
    let (attempt, journal) = service_case(vec![response], &history(3, 1800), 12_000, Failure::None);
    assert!(attempt.candidate.is_none());
    assert_ne!(attempt.status, CompactionStatus::PublishedReady);
    assert_eq!(attempt.status, CompactionStatus::SummaryUnusable);
    assert_eq!(attempt.attempts.len(), 1);
    assert!(journal.archives().is_empty());
    let receipt = &attempt.attempts[0];
    assert_eq!(receipt.knownness, AccountingKnownness::Known);
    assert!(!receipt.completed);
    assert_eq!(receipt.usage.unwrap().input_tokens, 11);
    assert_eq!(receipt.usage.unwrap().output_tokens, 7);
    assert_eq!(receipt.totals.cost_microcents, None);
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert!(checkpoint.pending.is_none());
    assert_eq!(checkpoint.totals.housekeeping.input_tokens, 11);
    assert_eq!(checkpoint.totals.housekeeping.output_tokens, 7);
    assert_eq!(journal.retained_receipts(), (Some(receipt.clone()), None));
    let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"unadvertised-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response {
        body: format!("data: {event}\n\ndata: [DONE]\n\n"),
        pause: false,
    }]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let mut transcript = history(3, 1800);
    let expected = transcript.clone();
    transcript.pop();
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let error = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |e| events.push(e),
    )
    .expect_err("summary tools are unusable and must not reach ordinary dispatch");
    fixture.finish();
    assert!(error.len() <= 512);
    assert_eq!(executor.0, 0);
    assert_eq!(transcript, expected);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert!(journal.archives().is_empty());
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert_eq!(journal.receipts()[0].knownness, AccountingKnownness::Known);
    assert!(!events.iter().any(|e| matches!(
        e,
        FrontendEvent::Compacted { .. } | FrontendEvent::TextDelta { .. }
    )));
}

#[test]
fn service_exact_child_namespace_and_unknown_legacy_baseline_are_preserved() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let root = MemoryJournal::fresh("service-owner");
    let id = ulid::Ulid::new().to_string();
    let child = root.child(&id, AccountingBaseline::UnknownLegacy).unwrap();
    let mut options = options(&fixture, &child, 1000, 12_000);
    options.session_id = id.clone();
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &history(3, 1800),
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::PublishedReady);
    let record = attempt
        .candidate
        .unwrap()
        .published_record()
        .unwrap()
        .clone();
    assert_eq!(record.owner_session_id, "service-owner");
    assert_eq!(record.child_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        child.accounting_checkpoint().unwrap().totals.knownness,
        AccountingKnownness::UnknownLegacy
    );
    assert_eq!(
        root.accounting_checkpoint().unwrap().revision,
        AccountingRevision(0)
    );
    assert_ids(&home, &child, 1);
}

#[test]
fn service_cancel_inside_durable_begin_is_proven_not_sent_and_closes_pending() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let source = history(3, 1800);
    let original = source.clone();
    let cancel = CancelToken::new();
    journal.cancel_after_begin(cancel.clone());
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &source,
        &cancel,
    );
    fixture.finish();
    assert_eq!(attempt.status, CompactionStatus::Cancelled);
    assert_eq!(source, original);
    assert!(attempt.candidate.is_none());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert!(journal.archives().is_empty());
    assert_eq!(journal.intents().len(), 1);
    assert_eq!(attempt.attempts.len(), 1);
    let receipt = &attempt.attempts[0];
    assert_eq!(receipt.knownness, AccountingKnownness::Known);
    assert!(!receipt.completed);
    assert!(receipt.usage.is_none());
    assert_eq!(receipt.totals, orbit_engine::AccountingTotals::known_zero());
    assert_eq!(journal.receipts(), attempt.attempts);
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert!(checkpoint.pending.is_none());
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
    assert_eq!(
        checkpoint.totals.housekeeping,
        orbit_engine::AccountingTotals::known_zero()
    );
    assert_eq!(journal.retained_receipts(), (Some(receipt.clone()), None));
}

#[test]
fn service_after_current_user_tool_round_remaps_anchor_and_preserves_typed_intent_once() {
    struct CurrentTool(usize);
    impl ToolExecutor for CurrentTool {
        fn execute(&mut self, calls: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
            self.0 += 1;
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].name, "inspect");
            vec![ToolRoundResult {
                call_id: calls[0].id.clone(),
                content: format!("{}CURRENT-TOOL-RESULT-END", "r".repeat(4500)),
            }]
        }
    }
    let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"current-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response {
            body: format!("data: {event}\n\ndata: [DONE]\n\n"),
            pause: false,
        },
        Response::complete(SUMMARY),
        Response::complete(ANSWER),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 2000, 12_000);
    options.max_rounds = 3;
    options.user_blocks = Some(vec![ContentBlock::Text {
        text: INTENT.into(),
    }]);
    let mut source = Vec::new();
    for i in 0..4 {
        pair(&mut source, &format!("old-{i}"), 600);
    }
    let original = source.clone();
    let mut events = Vec::new();
    let mut executor = CurrentTool(0);
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |e| events.push(e),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!(executor.0, 1);
    assert_eq!(report.final_text, ANSWER);
    assert_transport(&fixture);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].body["model"], "raw-main/model");
    assert!(body_estimate(&requests[0].body) < 1800);
    assert_eq!(requests[1].body["model"], "raw-summary/model");
    assert!(body_estimate(&requests[1].body) <= 12_000);
    assert!(requests[1].body.get("tools").is_none());
    assert!(!requests[1].body.to_string().contains(INTENT));
    assert!(
        !requests[1]
            .body
            .to_string()
            .contains("CURRENT-TOOL-RESULT-END")
    );
    assert_eq!(requests[2].body["model"], "raw-main/model");
    assert!(body_estimate(&requests[2].body) <= 2000);
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    let archived = &archives[0].source;
    assert_eq!(&archived[..original.len()], original.as_slice());
    assert_eq!(archived.last().unwrap().role, ChatRole::Tool);
    let current = archived
        .iter()
        .position(|m| m.role == ChatRole::User && m.content == INTENT)
        .unwrap();
    assert_eq!(archived[current].blocks, options.user_blocks);
    assert_eq!(
        &source[source.len() - 1 - (archived.len() - current)..source.len() - 1],
        &archived[current..]
    );
    assert_eq!(
        source
            .iter()
            .filter(|m| m.role == ChatRole::User && m.content == INTENT)
            .count(),
        1
    );
    assert!(
        requests[2]
            .body
            .to_string()
            .contains("CURRENT-TOOL-RESULT-END")
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, FrontendEvent::Compacted { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e,FrontendEvent::TextDelta{text} if text.contains(SUMMARY)))
    );
    let ledger = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0;
    let ids: Vec<_> = ledger
        .into_iter()
        .filter_map(|r| {
            if let orbit_ledger::LedgerEvent::EgressIntent(e) = r.record.event {
                Some(e.decision_id)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(journal.intents().len(), 3);
    assert_eq!(
        journal
            .intents()
            .iter()
            .map(|intent| intent.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Ordinary,
            AttemptPurpose::Chunk,
            AttemptPurpose::Ordinary
        ]
    );
    assert_eq!(journal.intents()[1].request_id, ids[1]);
    assert_eq!(journal.receipts()[1].request_id, ids[1]);
    assert_ids(&home, &journal, 3);
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
}

#[test]
fn service_published_history_can_compact_again_after_more_completed_exchanges() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete(SUMMARY),
        Response::complete("second compacted state"),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let first_source = history(3, 1800);
    let first_original = first_source.clone();
    let first = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &first_source,
        &CancelToken::new(),
    );
    assert_eq!(
        first.status,
        CompactionStatus::PublishedReady,
        "the first compaction must actually succeed before exercising reuse"
    );
    assert_eq!(first_source, first_original);
    assert_eq!(first.attempts.len(), 1);
    let first_candidate = first.candidate.unwrap();
    let first_record = first_candidate.published_record().unwrap().clone();
    assert_eq!(
        &first_candidate.messages()[first_candidate.messages().len() - 3..],
        &first_source[first_source.len() - 3..]
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);

    // Resume the actual published candidate, finish its current exchange, then
    // accumulate complete new exchanges rather than a protected huge intent.
    let mut second_source = first_candidate.messages().to_vec();
    second_source.push(orbit_engine::assistant_message(
        "the first current exchange is complete",
    ));
    for i in 0..3 {
        pair(&mut second_source, &format!("SECOND-OLDER-{i}"), 1800);
    }
    pair(&mut second_source, "SECOND-LATEST", 0);
    let second_intent = "second exact current intent λ";
    let mut typed_intent = orbit_engine::user_message(second_intent);
    typed_intent.blocks = Some(vec![ContentBlock::Text {
        text: second_intent.into(),
    }]);
    second_source.push(typed_intent.clone());
    let second_original = second_source.clone();
    let second_tail = second_source[second_source.len() - 3..].to_vec();
    assert!(
        second_source
            .iter()
            .map(|message| message.content.len())
            .sum::<usize>()
            > 4000
    );
    let second = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &second_source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert_eq!(
        second.status,
        CompactionStatus::PublishedReady,
        "a published summary must not become an incomplete group that pins all later history"
    );
    assert_eq!(second_source, second_original);
    assert_eq!(second.attempts.len(), 1);
    let second_candidate = second.candidate.unwrap();
    let second_record = second_candidate.published_record().unwrap().clone();
    assert_ne!(first_record.record_id, second_record.record_id);
    assert_ne!(first_record.source_digest, second_record.source_digest);
    assert_eq!(
        &second_candidate.messages()[second_candidate.messages().len() - second_tail.len()..],
        second_tail.as_slice()
    );
    assert_eq!(
        second_candidate
            .messages()
            .iter()
            .filter(|message| **message == typed_intent)
            .count(),
        1
    );
    let archives = journal.archives();
    assert_eq!(archives.len(), 2);
    assert_eq!(
        archives
            .iter()
            .find(|archive| archive.reference == first_record)
            .unwrap()
            .source,
        first_original
    );
    assert_eq!(
        archives
            .iter()
            .find(|archive| archive.reference == second_record)
            .unwrap()
            .source,
        second_original
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(request.body["model"], "raw-summary/model");
        assert_eq!(request.body["max_tokens"], 37);
        assert!(request.body.get("tools").is_none());
        assert!(body_estimate(&request.body) <= 12_000);
        assert!(!request.body.to_string().contains(second_intent));
        assert!(!request.body.to_string().contains(HIDDEN));
    }
    drop(requests);
    assert_transport(&fixture);
    assert_ids(&home, &journal, 2);
}

#[test]
fn service_compacted_event_redacts_secret_before_display_truncation() {
    let token = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
    let private_summary = format!("{}{token}", "x".repeat(8182));
    let scanned = orbit_tools::scan::scan_result(&private_summary);
    assert!(scanned.redactions.iter().any(|kind| kind == "api token"));
    assert!(!scanned.text.contains(token) && !scanned.text.contains("sk-"));
    assert!(scanned.text.contains("[redacted:api token]"));
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete(&private_summary),
        Response::complete(ANSWER),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 10_000, 32_000);
    options.user_blocks = Some(vec![ContentBlock::Text {
        text: INTENT.into(),
    }]);
    let mut original = history(3, 12_000);
    original.last_mut().unwrap().blocks = options.user_blocks.clone();
    let tail = original[original.len() - 3..].to_vec();
    let mut transcript = original[..original.len() - 1].to_vec();
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!(report.final_text, ANSWER);
    assert_eq!(executor.0, 0);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["model"], "raw-summary/model");
    assert_eq!(requests[0].body["max_tokens"], 37);
    assert!(requests[0].body.get("tools").is_none());
    assert!(body_estimate(&requests[0].body) <= 32_000);
    assert_eq!(requests[1].body["model"], "raw-main/model");
    assert_eq!(requests[1].body["max_tokens"], 73);
    assert!(body_estimate(&requests[1].body) <= 10_000);
    assert!(
        requests[1].body.to_string().contains(&private_summary),
        "the private continuation retains the exact original summary bytes"
    );
    drop(requests);
    assert_transport(&fixture);
    assert_ids(&home, &journal, 2);
    assert_eq!(
        &transcript[transcript.len() - 1 - tail.len()..transcript.len() - 1],
        tail.as_slice()
    );
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].source, original);
    assert_eq!(archives[0].candidate, &transcript[..transcript.len() - 1]);
    assert_eq!(
        archives[0]
            .candidate
            .iter()
            .filter(|message| message.content.contains(&private_summary))
            .count(),
        1
    );
    let visible: Vec<_> = events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::Compacted { summary, .. } = event {
                Some(summary.as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(visible.len(), 1);
    assert!(visible[0].len() <= 8192);
    assert!(
        !visible[0].contains("sk-"),
        "safe compaction projection must not expose a token prefix cut before its minimum scanner length"
    );
    assert!(!visible[0].contains(token));
    assert_eq!(
        events
            .iter()
            .filter_map(|event| if let FrontendEvent::TextDelta { text } = event {
                Some(text.as_str())
            } else {
                None
            })
            .collect::<Vec<_>>(),
        [ANSWER]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
}

#[test]
fn service_cancel_after_captured_post_before_headers_retains_uncertain_accounting() {
    let home = Home::new();
    let mut fixture = Fixture::with_held_headers(vec![], true);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 1000, 12_000);
    let source = history(3, 1800);
    let original = source.clone();
    let cancel = CancelToken::new();
    let cancelling = cancel.clone();
    let calls = fixture.requests.clone();
    let canceller = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while calls.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        cancelling.cancel();
    });
    let attempt = compaction::compact_context(
        &home.0,
        &config(&fixture, false),
        &options,
        &source,
        &cancel,
    );
    canceller.join().unwrap();
    fixture.finish();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(journal.intents().len(), 1);
    assert_eq!(source, original);
    assert!(attempt.candidate.is_none());
    assert!(journal.archives().is_empty());
    assert!(matches!(
        attempt.status,
        CompactionStatus::Cancelled | CompactionStatus::AccountingUncertain
    ));
    assert_eq!(attempt.attempts.len(), 1);
    let receipt = &attempt.attempts[0];
    assert_eq!(
        receipt.knownness,
        AccountingKnownness::Uncertain,
        "an accepted POST without any response headers has no proven final bill"
    );
    assert!(!receipt.completed);
    assert_eq!(receipt.totals.cost_microcents, None);
    assert!(
        receipt
            .usage
            .is_none_or(|usage| usage == orbit_adapter::types::ProviderUsage::default())
    );
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
    assert_eq!(checkpoint.totals.housekeeping.cost_microcents, None);
    assert!(
        checkpoint
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_eq!(journal.retained_receipts(), (None, Some(receipt.clone())));
    assert_transport(&fixture);
    assert_summary_requests(&fixture, 12_000, 1);
    assert_ids(&home, &journal, 1);
}

#[test]
fn task05_ordinary_fitting_request_settles_supplied_journal_once() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(ANSWER)]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 8000, 8000);
    let mut source = Vec::new();
    let mut executor = NoEffects::default();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok);
    assert_eq!((report.input_tokens, report.output_tokens), (11, 7));
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(source.last().unwrap().content, ANSWER);
    assert!(journal.archives().is_empty());
    assert_transport(&fixture);
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.revision, AccountingRevision(2));
    assert_eq!(checkpoint.totals.ordinary.input_tokens, 11);
    assert_eq!(checkpoint.totals.ordinary.output_tokens, 7);
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
    assert_eq!(
        checkpoint.totals.housekeeping,
        compaction::AccountingTotals::known_zero()
    );
    assert!(checkpoint.pending.is_none());
    assert_eq!(journal.intents().len(), 1);
    assert_eq!(journal.receipts().len(), 1);
    assert_eq!(journal.intents()[0].purpose, AttemptPurpose::Ordinary);
    assert_ids(&home, &journal, 1);
}

#[test]
fn task05_ordinary_fitting_request_without_journal_keeps_legacy_wrapper() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(ANSWER)]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.journal = None;
    let mut source = Vec::new();
    let mut executor = NoEffects::default();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!((report.input_tokens, report.output_tokens), (11, 7));
    assert_eq!(source.len(), 2);
    assert_eq!(source[0], orbit_engine::user_message(INTENT));
    assert_eq!(source[1].content, ANSWER);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_transport(&fixture);
    assert!(journal.intents().is_empty());
}

fn task05_flat_price(flat: u64) -> CostRates {
    CostRates {
        input_per_million_microcents: 0,
        output_per_million_microcents: 0,
        cache_read_per_million_microcents: Some(0),
        cache_write_per_million_microcents: Some(0),
        reasoning_per_million_microcents: Some(0),
        request_flat_microcents: flat,
    }
}
fn task05_assert_terminal(events: &[FrontendEvent], report: &orbit_engine::TurnReport, ok: bool) {
    let ended: Vec<_> = events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::TurnEnded {
                ok,
                interrupted,
                rounds,
                input_tokens,
                output_tokens,
                cost_microcents,
            } = event
            {
                Some((
                    *ok,
                    *interrupted,
                    *rounds,
                    *input_tokens,
                    *output_tokens,
                    *cost_microcents,
                ))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        ended,
        [(
            ok,
            report.interrupted,
            report.rounds,
            report.input_tokens,
            report.output_tokens,
            report.cost_microcents
        )]
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event,FrontendEvent::TextDelta{text} if text.contains(SUMMARY)))
    );
}
fn task05_detailed(
    fixture: &Fixture,
    home: &Home,
    config: &TurnConfig,
    options: &TurnOptions,
    source: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
) -> (orbit_engine::TurnCompletion, Vec<FrontendEvent>) {
    let mut events = Vec::new();
    let mut executor = NoEffects::default();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        config,
        options,
        INTENT,
        source,
        &mut executor,
        cancel,
        &mut |event| events.push(event),
    );
    assert_eq!(executor.0, 0);
    assert!(!fixture.stop.load(Ordering::SeqCst));
    if let orbit_engine::TurnEnd::Failed(failure) = &completion.end {
        assert!(!failure.message.is_empty() && failure.message.len() <= 8192);
        for private in [INTENT, HIDDEN, SUMMARY] {
            assert!(!failure.message.contains(private));
        }
    }
    (completion, events)
}

#[test]
fn task05_detailed_ordinary_usage_presence_zero_and_full_counter_pricing_are_exact() {
    for mode in ["missing", "zero", "priced-zero", "priced-counters"] {
        let usage = match mode {
            "missing" => None,
            "priced-counters" => Some(
                json!({"prompt_tokens":19,"completion_tokens":7,"total_tokens":26,"prompt_tokens_details":{"cached_tokens":5},"completion_tokens_details":{"reasoning_tokens":2}}),
            ),
            _ => Some(json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0})),
        };
        let home = Home::new();
        let mut fixture = Fixture::new(vec![Response::text(ANSWER, "stop", usage)]);
        let journal = MemoryJournal::fresh("service-owner");
        let options = options(&fixture, &journal, 8000, 8000);
        let mut selected = config(&fixture, false);
        if mode == "priced-zero" {
            selected.pricing = Some(task05_flat_price(5));
        }
        if mode == "priced-counters" {
            selected.pricing = Some(CostRates {
                input_per_million_microcents: 2_000_000,
                output_per_million_microcents: 3_000_000,
                cache_read_per_million_microcents: Some(4_000_000),
                cache_write_per_million_microcents: Some(5_000_000),
                reasoning_per_million_microcents: Some(6_000_000),
                request_flat_microcents: 7,
            });
        }
        let mut source = Vec::new();
        let (completion, events) = task05_detailed(
            &fixture,
            &home,
            &selected,
            &options,
            &mut source,
            &CancelToken::new(),
        );
        fixture.finish();
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
        assert!(completion.report.ok && !completion.report.interrupted);
        assert_eq!(completion.report.final_text, ANSWER);
        assert_eq!(completion.report.attempts.len(), 1);
        let receipt = &completion.report.attempts[0];
        assert_eq!(receipt.purpose, AttemptPurpose::Ordinary);
        assert!(receipt.completed);
        let expected_cost = match mode {
            "priced-zero" => Some(5),
            "priced-counters" => Some(88),
            _ => None,
        };
        assert_eq!(receipt.totals.cost_microcents, expected_cost);
        assert_eq!(completion.report.accounting.ordinary, receipt.totals);
        assert_eq!(
            completion.report.accounting.housekeeping,
            compaction::AccountingTotals::known_zero()
        );
        if mode == "missing" {
            assert!(receipt.usage.is_none());
            assert_eq!(receipt.knownness, AccountingKnownness::UnknownUsage);
        } else {
            assert_eq!(receipt.knownness, AccountingKnownness::Known);
            let expected = if mode == "priced-counters" {
                orbit_adapter::types::ProviderUsage {
                    input_tokens: 14,
                    output_tokens: 7,
                    cache_read_tokens: 5,
                    cache_write_tokens: 0,
                    reasoning_tokens: 2,
                }
            } else {
                orbit_adapter::types::ProviderUsage::default()
            };
            assert_eq!(receipt.usage, Some(expected));
            assert_eq!(
                (receipt.totals.input_tokens, receipt.totals.output_tokens),
                (expected.input_tokens, expected.output_tokens)
            );
        }
        assert_eq!(
            completion.report.cost_microcents,
            expected_cost.unwrap_or(0)
        );
        assert_eq!(journal.receipts(), completion.report.attempts);
        assert_eq!(
            journal.accounting_checkpoint().unwrap().totals.ordinary,
            receipt.totals
        );
        assert_ids(&home, &journal, 1);
        assert_transport(&fixture);
        task05_assert_terminal(&events, &completion.report, true);
    }
}

#[test]
fn task05_distinct_summary_and_ordinary_prices_are_attributed_once() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete(SUMMARY),
        Response::text(
            ANSWER,
            "stop",
            Some(
                json!({"prompt_tokens":19,"completion_tokens":7,"total_tokens":26,"prompt_tokens_details":{"cached_tokens":5},"completion_tokens_details":{"reasoning_tokens":2}}),
            ),
        ),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1000, 12_000);
    options.compaction_config.as_mut().unwrap().pricing = Some(CostRates {
        input_per_million_microcents: 1_000_000,
        output_per_million_microcents: 2_000_000,
        cache_read_per_million_microcents: None,
        cache_write_per_million_microcents: None,
        reasoning_per_million_microcents: None,
        request_flat_microcents: 3,
    });
    let mut selected = config(&fixture, false);
    selected.pricing = Some(CostRates {
        input_per_million_microcents: 2_000_000,
        output_per_million_microcents: 3_000_000,
        cache_read_per_million_microcents: Some(4_000_000),
        cache_write_per_million_microcents: Some(5_000_000),
        reasoning_per_million_microcents: Some(6_000_000),
        request_flat_microcents: 7,
    });
    let mut source = history(3, 1800);
    source.pop();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (25, 14, 116)
    );
    assert_eq!(
        completion.report.accounting.housekeeping.cost_microcents,
        Some(28)
    );
    assert_eq!(
        completion.report.accounting.ordinary.cost_microcents,
        Some(88)
    );
    assert_eq!(
        completion
            .report
            .attempts
            .iter()
            .map(|receipt| receipt.purpose)
            .collect::<Vec<_>>(),
        [AttemptPurpose::Chunk, AttemptPurpose::Ordinary]
    );
    assert_eq!(journal.receipts(), completion.report.attempts);
    assert_eq!(
        journal.accounting_checkpoint().unwrap().totals,
        completion.report.accounting
    );
    assert_eq!(
        journal.archives()[0].attempts.len(),
        1,
        "the archived compaction receipt must not acquire a later ordinary bill"
    );
    assert_ids(&home, &journal, 2);
    assert_transport(&fixture);
    assert_summary_requests(&fixture, 12_000, 1);
    task05_assert_terminal(&events, &completion.report, true);
    assert_eq!(
        events
            .iter()
            .filter_map(|event| if let FrontendEvent::TextDelta { text } = event {
                Some(text.as_str())
            } else {
                None
            })
            .collect::<Vec<_>>(),
        [ANSWER]
    );
}

#[test]
fn task05_billed_truncated_ordinary_completion_retains_failure_accounting() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::text(
        "visible truncated ordinary",
        "length",
        Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
    )]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 8000, 8000);
    let mut selected = config(&fixture, false);
    selected.pricing = Some(task05_flat_price(9));
    let mut source = Vec::new();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert!(!completion.report.ok && !completion.report.interrupted);
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (11, 7, 9)
    );
    let receipt = &completion.report.attempts[0];
    assert_eq!(receipt.knownness, AccountingKnownness::Known);
    assert!(!receipt.completed);
    assert_eq!(receipt.totals.cost_microcents, Some(9));
    assert_eq!(completion.report.accounting.ordinary, receipt.totals);
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert_eq!(source.last().unwrap().content, "visible truncated ordinary");
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_ordinary_cancel_after_post_before_headers_is_uncertain_and_never_retried() {
    let home = Home::new();
    let mut fixture = Fixture::with_held_headers(vec![], true);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.max_attempts = 3;
    let cancel = CancelToken::new();
    let cancelling = cancel.clone();
    let requests = fixture.requests.clone();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while requests.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        cancelling.cancel();
    });
    let mut source = Vec::new();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &options,
        &mut source,
        &cancel,
    );
    thread.join().unwrap();
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Cancelled));
    assert!(completion.report.interrupted && !completion.report.ok);
    assert_eq!(completion.report.attempts.len(), 1);
    let receipt = &completion.report.attempts[0];
    assert_eq!(receipt.purpose, AttemptPurpose::Ordinary);
    assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
    assert_eq!(receipt.totals.cost_microcents, None);
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_eq!(source, [orbit_engine::user_message(INTENT)]);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Retrying { .. }))
    );
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_ordinary_cancel_during_partial_stream_preserves_provisional_usage_and_intent() {
    let prefix =
        json!({"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":1,"total_tokens":12}});
    let event = json!({"choices":[{"index":0,"delta":{"content":"visible partial ordinary"},"finish_reason":null}]});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response {
        body: format!("data: {prefix}\n\ndata: {event}\n\n"),
        pause: true,
    }]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.max_attempts = 3;
    let cancel = CancelToken::new();
    let mut events = Vec::new();
    let mut source = Vec::new();
    let mut executor = NoEffects::default();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &cancel,
        &mut |event| {
            if matches!(&event,FrontendEvent::TextDelta{text} if text.contains("visible partial")) {
                cancel.cancel();
            }
            events.push(event);
        },
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Cancelled));
    assert_eq!(executor.0, 0);
    assert_eq!(source[0], orbit_engine::user_message(INTENT));
    assert_eq!(source.last().unwrap().content, "visible partial ordinary");
    let receipt = &completion.report.attempts[0];
    assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
    assert_eq!(receipt.totals.cost_microcents, None);
    assert_eq!(
        receipt.usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 11,
            output_tokens: 1,
            ..Default::default()
        })
    );
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (0, 0, 0)
    );
    assert_eq!(
        completion.report.accounting.knownness,
        AccountingKnownness::Uncertain
    );
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_invalid_final_usage_keeps_last_usable_prefix_without_booking_a_bill() {
    let prefix =
        json!({"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":1,"total_tokens":12}});
    let invalid = json!({"choices":[{"index":0,"delta":{"content":"visible invalid-final prefix"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17}});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response {
            body: format!("data: {prefix}\n\ndata: {invalid}\n\ndata: [DONE]\n\n"),
            pause: false,
        },
        Response::complete(ANSWER),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.max_attempts = 3;
    let mut source = Vec::new();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert_eq!(completion.report.attempts.len(), 1);
    let receipt = &completion.report.attempts[0];
    assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
    assert_eq!(receipt.totals.cost_microcents, None);
    assert_eq!(
        receipt.usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 11,
            output_tokens: 1,
            ..Default::default()
        })
    );
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (0, 0, 0)
    );
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(source[0], orbit_engine::user_message(INTENT));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Retrying { .. }))
    );
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_invalid_ordinary_tool_arguments_have_no_effect_and_leave_uncertain_receipt() {
    let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"invalid-call","type":"function","function":{"name":"inspect","arguments":"{"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response {
        body: format!("data: {event}\n\ndata: [DONE]\n\n"),
        pause: false,
    }]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.max_rounds = 3;
    options.max_attempts = 3;
    let mut source = Vec::new();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert_eq!(completion.report.attempts.len(), 1);
    assert_eq!(
        completion.report.attempts[0].knownness,
        AccountingKnownness::Uncertain
    );
    assert!(
        source
            .iter()
            .all(|message| message.role != ChatRole::Tool && message.tool_calls.is_none())
    );
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_failed_followup_retains_billed_summary_and_valid_tool_round_exactly_once() {
    struct OneTool(usize);
    impl ToolExecutor for OneTool {
        fn execute(&mut self, calls: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
            self.0 += 1;
            assert_eq!(calls.len(), 1);
            vec![ToolRoundResult {
                call_id: calls[0].id.clone(),
                content: "safe current result".into(),
            }]
        }
    }
    let tool = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"valid-current-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete(SUMMARY),
        Response {
            body: format!("data: {tool}\n\ndata: [DONE]\n\n"),
            pause: false,
        },
        Response {
            body: "data: {malformed\n\n".into(),
            pause: false,
        },
        Response::complete(ANSWER),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1000, 12_000);
    options.max_rounds = 3;
    options.max_attempts = 3;
    options.compaction_config.as_mut().unwrap().pricing = Some(task05_flat_price(28));
    let mut selected = config(&fixture, false);
    selected.pricing = Some(task05_flat_price(5));
    let mut source = history(3, 1800);
    source.pop();
    let mut executor = OneTool(0);
    let mut events = Vec::new();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &selected,
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert!(!completion.report.ok);
    assert_eq!(executor.0, 1);
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (22, 14, 33)
    );
    assert_eq!(
        completion.report.accounting.housekeeping.cost_microcents,
        Some(28)
    );
    assert_eq!(completion.report.accounting.ordinary.cost_microcents, None);
    assert_eq!(
        completion.report.accounting.knownness,
        AccountingKnownness::Uncertain
    );
    let receipts = &completion.report.attempts;
    assert_eq!(receipts.len(), 3);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Chunk,
            AttemptPurpose::Ordinary,
            AttemptPurpose::Ordinary
        ]
    );
    assert_eq!(receipts[0].totals.cost_microcents, Some(28));
    assert_eq!(receipts[1].totals.cost_microcents, Some(5));
    assert!(receipts[1].completed);
    assert_eq!(receipts[1].knownness, AccountingKnownness::Known);
    assert_eq!(receipts[2].knownness, AccountingKnownness::Uncertain);
    assert_eq!(receipts[2].totals.cost_microcents, None);
    assert_eq!(journal.receipts(), *receipts);
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.uncertain)
    );
    assert_eq!(journal.archives().len(), 1);
    assert!(source.iter().any(|message| message.role == ChatRole::Tool
        && message.tool_result.as_deref() == Some("safe current result")));
    assert_ids(&home, &journal, 3);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_summary_exhausts_allowance_before_ordinary_admission() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(SUMMARY)]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 1000, 12_000);
    options.compaction_config.as_mut().unwrap().pricing = Some(task05_flat_price(28));
    options.spend_allowance = Some(orbit_engine::SpendAllowance {
        remaining_microcents: 28,
        allow_unpriced_housekeeping: false,
    });
    let mut selected = config(&fixture, false);
    selected.pricing = Some(task05_flat_price(1));
    let mut source = history(3, 1800);
    source.pop();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert_eq!(completion.report.attempts.len(), 1);
    assert_eq!(completion.report.attempts[0].purpose, AttemptPurpose::Chunk);
    assert_eq!(
        completion.report.accounting.housekeeping.cost_microcents,
        Some(28)
    );
    assert_eq!(
        completion.report.accounting.ordinary,
        compaction::AccountingTotals::known_zero()
    );
    assert_eq!(completion.report.cost_microcents, 28);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(journal.intents().len(), 1);
    assert_eq!(journal.archives().len(), 1);
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert!(
        events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Compacted { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::TextDelta { .. }))
    );
    assert_ids(&home, &journal, 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_insufficient_allowance_refuses_before_housekeeping_or_ordinary_post() {
    for compact in [false, true] {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![]);
        let journal = MemoryJournal::fresh("service-owner");
        let mut options = options(
            &fixture,
            &journal,
            if compact { 1000 } else { 8000 },
            12_000,
        );
        options.compaction_config.as_mut().unwrap().pricing = Some(task05_flat_price(3));
        options.spend_allowance = Some(orbit_engine::SpendAllowance {
            remaining_microcents: 2,
            allow_unpriced_housekeeping: false,
        });
        let mut selected = config(&fixture, false);
        selected.pricing = Some(task05_flat_price(3));
        let mut source = if compact {
            history(3, 1800)
        } else {
            vec![orbit_engine::user_message(INTENT)]
        };
        let expected = source.clone();
        source.pop();
        let (completion, events) = task05_detailed(
            &fixture,
            &home,
            &selected,
            &options,
            &mut source,
            &CancelToken::new(),
        );
        fixture.finish();
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
        assert!(completion.report.attempts.is_empty());
        assert_eq!(source, expected);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        assert!(journal.intents().is_empty());
        assert!(journal.archives().is_empty());
        assert_eq!(
            journal.accounting_checkpoint().unwrap().revision,
            AccountingRevision(0)
        );
        task05_assert_terminal(&events, &completion.report, false);
    }
}

#[test]
fn task05_unpriced_housekeeping_requires_explicit_policy_without_granting_unpriced_ordinary() {
    for allow in [false, true] {
        let home = Home::new();
        let mut fixture = Fixture::new(if allow {
            vec![Response::complete(SUMMARY), Response::complete(ANSWER)]
        } else {
            vec![]
        });
        let journal = MemoryJournal::fresh("service-owner");
        let mut options = options(&fixture, &journal, 1000, 12_000);
        options.spend_allowance = Some(orbit_engine::SpendAllowance {
            remaining_microcents: 10,
            allow_unpriced_housekeeping: allow,
        });
        let mut selected = config(&fixture, false);
        selected.pricing = Some(task05_flat_price(1));
        let mut source = history(3, 1800);
        source.pop();
        let (completion, events) = task05_detailed(
            &fixture,
            &home,
            &selected,
            &options,
            &mut source,
            &CancelToken::new(),
        );
        fixture.finish();
        if allow {
            assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
            assert_eq!(
                completion.report.accounting.housekeeping.cost_microcents,
                None
            );
            assert_eq!(
                completion.report.accounting.ordinary.cost_microcents,
                Some(1)
            );
            assert_eq!(completion.report.cost_microcents, 1);
            assert_ids(&home, &journal, 2);
        } else {
            assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
            assert!(completion.report.attempts.is_empty());
            assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        }
        task05_assert_terminal(&events, &completion.report, allow);
    }
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.spend_allowance = Some(orbit_engine::SpendAllowance {
        remaining_microcents: 10,
        allow_unpriced_housekeeping: true,
    });
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &options,
        &mut Vec::new(),
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert!(completion.report.attempts.is_empty());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_legacy_unknown_namespace_refuses_spend_cap_without_inventing_zero() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let journal = MemoryJournal::uninitialized("service-owner");
    journal
        .initialize_accounting(AccountingBaseline::UnknownLegacy)
        .unwrap();
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.spend_allowance = Some(orbit_engine::SpendAllowance {
        remaining_microcents: 100,
        allow_unpriced_housekeeping: true,
    });
    let mut selected = config(&fixture, false);
    selected.pricing = Some(task05_flat_price(1));
    let before = journal.accounting_checkpoint().unwrap();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &options,
        &mut Vec::new(),
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert!(completion.report.attempts.is_empty());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert_eq!(journal.accounting_checkpoint().unwrap(), before);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn task05_settlement_overflow_retains_actual_known_attempt_and_halts() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::complete(ANSWER)]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 8000, 8000);
    let selected = config(&fixture, false);
    let seed = AttemptIntent {
        owner_session_id: "service-owner".into(),
        child_id: None,
        request_id: "historical-ordinary".into(),
        purpose: AttemptPurpose::Ordinary,
        budget: options.selected_budget.as_ref().unwrap().identity.clone(),
    };
    let reference = journal.begin_attempt(AccountingRevision(0), &seed).unwrap();
    let prior = RequestAccountingReceipt {
        request_id: seed.request_id,
        purpose: AttemptPurpose::Ordinary,
        totals: compaction::AccountingTotals {
            input_tokens: u64::MAX,
            output_tokens: 0,
            cost_microcents: Some(0),
        },
        usage: Some(orbit_adapter::types::ProviderUsage {
            input_tokens: u64::MAX,
            ..Default::default()
        }),
        knownness: AccountingKnownness::Known,
        completed: true,
    };
    journal.settle_attempt(&reference, &prior).unwrap();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &options,
        &mut Vec::new(),
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
    assert_eq!(completion.report.attempts.len(), 1);
    let actual = &completion.report.attempts[0];
    assert_eq!(actual.knownness, AccountingKnownness::Known);
    assert_eq!(
        (actual.totals.input_tokens, actual.totals.output_tokens),
        (11, 7)
    );
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens
        ),
        (11, 7)
    );
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(checkpoint.totals.ordinary.input_tokens, u64::MAX);
    assert!(checkpoint.pending.is_some());
    let records = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0;
    let ids: Vec<_> = records
        .into_iter()
        .filter_map(|record| {
            if let orbit_ledger::LedgerEvent::EgressIntent(event) = record.record.event {
                Some(event.decision_id)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(ids, std::slice::from_ref(&actual.request_id));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    task05_assert_terminal(&events, &completion.report, false);
}

#[test]
fn review_regression_usage_immediately_includes_the_appended_assistant_message() {
    let reply = format!("completed visible reply {}", "r".repeat(192));
    let home = Home::new();
    let mut fixture = Fixture::new(vec![Response::text(
        &reply,
        "stop",
        Some(json!({"prompt_tokens":11,"completion_tokens":64,"total_tokens":75})),
    )]);
    let journal = MemoryJournal::fresh("service-owner");
    let options = options(&fixture, &journal, 8000, 8000);
    let mut source = Vec::new();
    let (completion, events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert_eq!(
        source,
        [
            orbit_engine::user_message(INTENT),
            orbit_engine::assistant_message(reply.clone())
        ]
    );
    let mut current_body = fixture.requests.lock().unwrap()[0].body.clone();
    let before = body_estimate(&current_body);
    current_body["messages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"role":"assistant","content":reply}));
    let after = body_estimate(&current_body);
    assert!(
        after > before + 40,
        "the actual assistant text and message framing must grow the prepared context"
    );
    let (used, window) = events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::Usage {
                used_tokens,
                window_tokens,
                ..
            } = event
            {
                Some((*used_tokens, *window_tokens))
            } else {
                None
            }
        })
        .next_back()
        .expect("a fitting ordinary completion emits context usage");
    assert_eq!(window, 8000);
    assert!(
        used >= after,
        "immediate usage {used} must include the exact appended assistant message, whose full rendered floor is {after}, rather than the pre-reply floor {before}"
    );
    assert_ids(&home, &journal, 1);
    assert_transport(&fixture);
    task05_assert_terminal(&events, &completion.report, true);
}

#[test]
fn review_control_usage_recomputes_the_prepared_floor_after_history_and_selection_change() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response::complete("first small reply"),
        Response::complete("second small reply"),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let first_options = options(&fixture, &journal, 8000, 8000);
    let mut source = Vec::new();
    let (first, first_events) = task05_detailed(
        &fixture,
        &home,
        &config(&fixture, false),
        &first_options,
        &mut source,
        &CancelToken::new(),
    );
    assert!(matches!(first.end, orbit_engine::TurnEnd::Completed));
    let first_meter = first_events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::Usage { used_tokens, .. } = event {
                Some(*used_tokens)
            } else {
                None
            }
        })
        .next_back()
        .unwrap();
    pair(&mut source, "ADDED-HISTORY", 1200);
    let mut selected = config(&fixture, false);
    selected.model = "raw-main/changed-selection".into();
    selected.max_output_tokens = 97;
    let mut next_options = options(&fixture, &journal, 8000, 8000);
    next_options.system_directive =
        Some(format!("changed immutable directive {}", "d".repeat(512)));
    next_options.selected_budget =
        Some(orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8000).unwrap());
    let (second, second_events) = task05_detailed(
        &fixture,
        &home,
        &selected,
        &next_options,
        &mut source,
        &CancelToken::new(),
    );
    fixture.finish();
    assert!(matches!(second.end, orbit_engine::TurnEnd::Completed));
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].body["model"], "raw-main/changed-selection");
    assert_eq!(requests[1].body["max_tokens"], 97);
    assert!(
        requests[1].body["messages"]
            .to_string()
            .contains("ADDED-HISTORY-ASSISTANT-END")
    );
    let first_floor = body_estimate(&requests[0].body);
    let changed_floor = body_estimate(&requests[1].body);
    assert!(changed_floor > first_floor + 500);
    let (changed_meter, window) = second_events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::Usage {
                used_tokens,
                window_tokens,
                ..
            } = event
            {
                Some((*used_tokens, *window_tokens))
            } else {
                None
            }
        })
        .next_back()
        .unwrap();
    assert_eq!(window, 8000);
    assert!(first_meter >= first_floor);
    assert!(
        changed_meter >= changed_floor && changed_meter > first_meter + 500,
        "a prior observation must not hide newly rendered history or a changed selection/directive"
    );
    drop(requests);
    assert_ids(&home, &journal, 2);
    assert_transport(&fixture);
    task05_assert_terminal(&first_events, &first.report, true);
    task05_assert_terminal(&second_events, &second.report, true);
}

#[test]
fn review_regression_missing_summary_usage_under_cap_stops_before_the_next_request() {
    for multiple_chunks in [false, true] {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![
            Response::text(SUMMARY, "stop", None),
            Response::complete("SECOND-CHUNK-MUST-NOT-RUN"),
            Response::complete(SUMMARY),
            Response::complete(ANSWER),
        ]);
        let journal = MemoryJournal::fresh("service-owner");
        let summary_window = if multiple_chunks { 2000 } else { 12_000 };
        let mut options = options(&fixture, &journal, 1000, summary_window);
        options.spend_allowance = Some(orbit_engine::SpendAllowance {
            remaining_microcents: 10,
            allow_unpriced_housekeeping: true,
        });
        let mut selected = config(&fixture, false);
        selected.pricing = Some(task05_flat_price(1));
        let mut source = if multiple_chunks {
            history(2, 2400)
        } else {
            history(3, 1800)
        };
        let expected = source.clone();
        source.pop();
        let (completion, events) = task05_detailed(
            &fixture,
            &home,
            &selected,
            &options,
            &mut source,
            &CancelToken::new(),
        );
        fixture.finish();
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            1,
            "allowing unknown price must not authorize unknown usage before another chunk, merge, or ordinary request"
        );
        assert_eq!(journal.intents().len(), 1);
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
        assert_eq!(completion.report.attempts.len(), 1);
        let receipt = &completion.report.attempts[0];
        assert_eq!(receipt.purpose, AttemptPurpose::Chunk);
        assert_eq!(receipt.knownness, AccountingKnownness::UnknownUsage);
        assert!(receipt.completed && receipt.usage.is_none());
        assert_eq!(
            (
                receipt.totals.input_tokens,
                receipt.totals.output_tokens,
                receipt.totals.cost_microcents
            ),
            (0, 0, None)
        );
        assert_eq!(journal.receipts(), completion.report.attempts);
        assert_eq!(
            completion.report.accounting.knownness,
            AccountingKnownness::UnknownUsage
        );
        assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
        assert!(!events.iter().any(|event| matches!(
            event,
            FrontendEvent::TextDelta { .. } | FrontendEvent::Retrying { .. }
        )));
        if multiple_chunks {
            assert_eq!(source, expected);
            assert!(journal.archives().is_empty());
        } else if source != expected {
            assert_eq!(journal.archives().len(), 1);
            assert_eq!(journal.archives()[0].source, expected);
            assert_eq!(
                source
                    .iter()
                    .filter(|message| message.role == ChatRole::User && message.content == INTENT)
                    .count(),
                1
            );
        }
        assert_ids(&home, &journal, 1);
        assert_summary_requests(&fixture, summary_window, 1);
        assert_transport(&fixture);
        task05_assert_terminal(&events, &completion.report, false);
    }
}

#[test]
fn review_regression_historical_missing_housekeeping_usage_under_cap_refuses_all_work() {
    for needs_compaction in [false, true] {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![
            Response::complete(SUMMARY),
            Response::complete(ANSWER),
        ]);
        let journal = MemoryJournal::fresh("service-owner");
        let mut options = options(
            &fixture,
            &journal,
            if needs_compaction { 1000 } else { 8000 },
            12_000,
        );
        options.compaction_config.as_mut().unwrap().pricing = Some(task05_flat_price(1));
        options.spend_allowance = Some(orbit_engine::SpendAllowance {
            remaining_microcents: 10,
            allow_unpriced_housekeeping: true,
        });
        let historical = AttemptIntent {
            owner_session_id: "service-owner".into(),
            child_id: None,
            request_id: "historical-missing-summary-usage".into(),
            purpose: AttemptPurpose::Chunk,
            budget: options.compaction_budget.as_ref().unwrap().identity.clone(),
        };
        let reference = journal
            .begin_attempt(AccountingRevision(0), &historical)
            .unwrap();
        let historical_receipt = RequestAccountingReceipt {
            request_id: historical.request_id.clone(),
            purpose: AttemptPurpose::Chunk,
            totals: compaction::AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: None,
            knownness: AccountingKnownness::UnknownUsage,
            completed: true,
        };
        journal
            .settle_attempt(&reference, &historical_receipt)
            .unwrap();
        let before = journal.accounting_checkpoint().unwrap();
        assert_eq!(before.totals.knownness, AccountingKnownness::UnknownUsage);
        let mut selected = config(&fixture, false);
        selected.pricing = Some(task05_flat_price(1));
        let mut source = if needs_compaction {
            history(3, 1800)
        } else {
            vec![orbit_engine::user_message(INTENT)]
        };
        let expected = source.clone();
        source.pop();
        let (completion, events) = task05_detailed(
            &fixture,
            &home,
            &selected,
            &options,
            &mut source,
            &CancelToken::new(),
        );
        fixture.finish();
        assert_eq!(
            fixture.connections.load(Ordering::SeqCst),
            0,
            "a historical unknown-usage bill must refuse both ordinary and housekeeping admission"
        );
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
        assert!(completion.report.attempts.is_empty());
        assert_eq!(source, expected);
        assert_eq!(journal.accounting_checkpoint().unwrap(), before);
        assert_eq!(journal.intents(), [historical]);
        assert_eq!(journal.receipts(), [historical_receipt]);
        assert!(journal.archives().is_empty());
        task05_assert_terminal(&events, &completion.report, false);
    }
}

#[test]
fn task05_tool_result_and_final_reply_usage_follow_only_the_matching_observation() {
    struct ObservedTool(usize);
    impl ToolExecutor for ObservedTool {
        fn execute(&mut self, calls: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
            self.0 += 1;
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].id, "meter-tool-call");
            assert_eq!(calls[0].name, "inspect");
            assert_eq!(calls[0].arguments.as_slice(), b"{}");
            vec![ToolRoundResult {
                call_id: calls[0].id.clone(),
                content: format!("exact bounded tool data {}", "result ".repeat(48)),
            }]
        }
    }
    let tool = json!({"choices":[{"index":0,"delta":{"content":"tool step","tool_calls":[{"index":0,"id":"meter-tool-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1600,"completion_tokens":7,"total_tokens":1607,"prompt_tokens_details":{"cached_tokens":600}}});
    let final_reply = format!("final visible response {}", "r".repeat(96));
    let home = Home::new();
    let mut fixture = Fixture::new(vec![
        Response {
            body: format!("data: {tool}\n\ndata: [DONE]\n\n"),
            pause: false,
        },
        Response::text(
            &final_reply,
            "stop",
            Some(
                json!({"prompt_tokens":1800,"completion_tokens":31,"total_tokens":1831,"prompt_tokens_details":{"cached_tokens":600}}),
            ),
        ),
    ]);
    let journal = MemoryJournal::fresh("service-owner");
    let mut options = options(&fixture, &journal, 8000, 8000);
    options.max_rounds = 2;
    let mut source = Vec::new();
    let mut executor = ObservedTool(0);
    let mut events = Vec::new();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &config(&fixture, false),
        &options,
        INTENT,
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert_eq!(executor.0, 1);
    assert_eq!(completion.report.final_text, final_reply);
    assert_eq!(
        source.last(),
        Some(&orbit_engine::assistant_message(final_reply.clone()))
    );
    let expected_tool_result = format!("exact bounded tool data {}", "result ".repeat(48));
    assert!(source.iter().any(|message| message.role == ChatRole::Tool
        && message.tool_call_id.as_deref() == Some("meter-tool-call")
        && message.tool_result.as_deref() == Some(expected_tool_result.as_str())));
    let (first_body, second_body) = {
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        (requests[0].body.clone(), requests[1].body.clone())
    };
    let first_floor = body_estimate(&first_body);
    let second_floor = body_estimate(&second_body);
    assert!(
        second_body["messages"]
            .to_string()
            .contains(&expected_tool_result)
    );
    assert!(
        second_floor > first_floor + 80,
        "the second actual request must carry the exact completed tool exchange"
    );
    let mut final_body = second_body.clone();
    final_body["messages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"role":"assistant","content":final_reply}));
    let final_floor = body_estimate(&final_body);
    assert!(final_floor > second_floor);
    assert!(
        first_floor < 1600 && second_floor < 1800,
        "observed input must dominate the fresh floor so this tests a real usage anchor"
    );
    let samples: Vec<_> = events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::Usage {
                used_tokens,
                window_tokens,
                ..
            } = event
            {
                Some((*used_tokens, *window_tokens))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        samples,
        [
            (1600 + (second_floor - first_floor), 8000),
            (1800 + (final_floor - second_floor), 8000)
        ],
        "cache is included once in each matching provider observation; add only newly rendered content, never output tokens or cumulative request traffic"
    );
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens
        ),
        (2200, 38)
    );
    assert_eq!(completion.report.attempts.len(), 2);
    assert_eq!(
        completion.report.attempts[0].usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 1000,
            output_tokens: 7,
            cache_read_tokens: 600,
            cache_write_tokens: 0,
            reasoning_tokens: 0
        })
    );
    assert_eq!(
        completion.report.attempts[1].usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 1200,
            output_tokens: 31,
            cache_read_tokens: 600,
            cache_write_tokens: 0,
            reasoning_tokens: 0
        })
    );
    assert_ids(&home, &journal, 2);
    assert_transport(&fixture);
    task05_assert_terminal(&events, &completion.report, true);
}

mod task2a_journal_transition_tests {
    use super::*;
    use orbit_engine::{AccountingCheckpoint, AttemptRef, KnownPricedSubtotals};

    #[derive(Clone, Copy, Debug)]
    enum Lie {
        UnavailableToZero,
        AvailableToNone,
        WrongPurpose,
        WrongSum,
    }

    #[derive(Debug)]
    struct LyingJournal {
        inner: Arc<MemoryJournal>,
        lie: Lie,
        settlements: AtomicUsize,
    }
    impl CompactionJournal for LyingJournal {
        fn initialize_accounting(
            &self,
            baseline: AccountingBaseline,
        ) -> Result<AccountingCheckpoint, HistoryError> {
            self.inner.initialize_accounting(baseline)
        }
        fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
            let mut value = self.inner.accounting_checkpoint()?;
            if matches!(self.lie, Lie::UnavailableToZero) {
                value.known_priced_subtotals = None;
            }
            Ok(value)
        }
        fn begin_attempt(
            &self,
            expected_revision: AccountingRevision,
            intent: &AttemptIntent,
        ) -> Result<AttemptRef, HistoryError> {
            self.inner.begin_attempt(expected_revision, intent)
        }
        fn settle_attempt(
            &self,
            reference: &AttemptRef,
            receipt: &RequestAccountingReceipt,
        ) -> Result<AccountingCheckpoint, HistoryError> {
            let mut value = self.inner.settle_attempt(reference, receipt)?;
            self.settlements.fetch_add(1, Ordering::SeqCst);
            match self.lie {
                Lie::UnavailableToZero => {
                    value.known_priced_subtotals = Some(KnownPricedSubtotals::known_zero())
                }
                Lie::AvailableToNone => value.known_priced_subtotals = None,
                Lie::WrongPurpose => {
                    let actual = value.known_priced_subtotals.unwrap();
                    value.known_priced_subtotals = Some(KnownPricedSubtotals {
                        ordinary_microcents: actual.housekeeping_microcents,
                        housekeeping_microcents: actual.ordinary_microcents,
                    });
                }
                Lie::WrongSum => {
                    let mut actual = value.known_priced_subtotals.unwrap();
                    if receipt.purpose == AttemptPurpose::Ordinary {
                        actual.ordinary_microcents =
                            actual.ordinary_microcents.checked_add(1).unwrap();
                    } else {
                        actual.housekeeping_microcents =
                            actual.housekeeping_microcents.checked_add(1).unwrap();
                    }
                    value.known_priced_subtotals = Some(actual);
                }
            }
            Ok(value)
        }
        fn check_archive_capacity(&self, minimum_record_bytes: u64) -> Result<(), HistoryError> {
            self.inner.check_archive_capacity(minimum_record_bytes)
        }
        fn publish(
            &self,
            source: &[ChatMessage],
            candidate: &compaction::CompactionCandidate,
            receipt: &compaction::CompactionReceipt,
        ) -> Result<compaction::CompactionRecordRef, HistoryError> {
            self.inner.publish(source, candidate, receipt)
        }
    }

    #[test]
    fn task2a_ordinary_rejects_every_lying_subtotal_transition_before_tools_or_next_post() {
        for lie in [
            Lie::UnavailableToZero,
            Lie::AvailableToNone,
            Lie::WrongPurpose,
            Lie::WrongSum,
        ] {
            let tool = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"priced-subtotal-tool","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
            let home = Home::new();
            let mut fixture = Fixture::new(vec![
                Response {
                    body: format!("data: {tool}\n\ndata: [DONE]\n\n"),
                    pause: false,
                },
                Response::complete(ANSWER),
            ]);
            let inner = MemoryJournal::fresh("service-owner");
            let journal = Arc::new(LyingJournal {
                inner: inner.clone(),
                lie,
                settlements: AtomicUsize::new(0),
            });
            let mut options = options(&fixture, &inner, 8000, 8000);
            options.journal = Some(journal.clone());
            options.max_rounds = 2;
            let mut selected = config(&fixture, false);
            selected.pricing = Some(task05_flat_price(3));
            let mut source = Vec::new();
            let mut executor = NoEffects::default();
            let mut events = Vec::new();
            let completion = orbit_engine::run_turn_detailed(
                &home.0,
                &selected,
                &options,
                INTENT,
                &mut source,
                &mut executor,
                &CancelToken::new(),
                &mut |event| events.push(event),
            );
            fixture.finish();
            assert!(
                matches!(completion.end, orbit_engine::TurnEnd::Failed(_)),
                "must reject {lie:?}"
            );
            assert_eq!(
                fixture.requests.lock().unwrap().len(),
                1,
                "bad settlement cannot authorize continuation: {lie:?}"
            );
            assert_eq!(executor.0, 0);
            assert_eq!(journal.settlements.load(Ordering::SeqCst), 1);
            assert_eq!(source, [orbit_engine::user_message(INTENT)]);
            assert_eq!(completion.report.attempts.len(), 1);
            assert_eq!(
                completion.report.attempts[0].purpose,
                AttemptPurpose::Ordinary
            );
            assert_eq!(
                completion.report.attempts[0].knownness,
                AccountingKnownness::Known
            );
            assert_eq!(
                completion.report.attempts[0].totals.cost_microcents,
                Some(3)
            );
            assert_eq!(
                (
                    completion.report.input_tokens,
                    completion.report.output_tokens,
                    completion.report.cost_microcents
                ),
                (11, 7, 3)
            );
            assert_eq!(
                inner
                    .accounting_checkpoint()
                    .unwrap()
                    .known_priced_subtotals,
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 3,
                    housekeeping_microcents: 0
                })
            );
            assert_eq!(inner.receipts(), completion.report.attempts);
            assert!(inner.archives().is_empty());
            assert!(!events.iter().any(|event| matches!(
                event,
                FrontendEvent::Retrying { .. } | FrontendEvent::ToolStartedFull { .. }
            )));
            assert_ids(&home, &inner, 1);
            assert_transport(&fixture);
            task05_assert_terminal(&events, &completion.report, false);
        }
    }

    #[test]
    fn task2a_summary_rejects_every_lying_subtotal_transition_before_publication_or_main_post() {
        for lie in [
            Lie::UnavailableToZero,
            Lie::AvailableToNone,
            Lie::WrongPurpose,
            Lie::WrongSum,
        ] {
            let home = Home::new();
            let mut fixture = Fixture::new(vec![
                Response::complete(SUMMARY),
                Response::complete(ANSWER),
            ]);
            let inner = MemoryJournal::fresh("service-owner");
            let journal = Arc::new(LyingJournal {
                inner: inner.clone(),
                lie,
                settlements: AtomicUsize::new(0),
            });
            let mut options = options(&fixture, &inner, 1000, 12_000);
            options.journal = Some(journal.clone());
            options.compaction_config.as_mut().unwrap().pricing = Some(task05_flat_price(3));
            let mut source = history(3, 1800);
            let expected = source.clone();
            source.pop();
            let mut executor = NoEffects::default();
            let mut events = Vec::new();
            let completion = orbit_engine::run_turn_detailed(
                &home.0,
                &config(&fixture, false),
                &options,
                INTENT,
                &mut source,
                &mut executor,
                &CancelToken::new(),
                &mut |event| events.push(event),
            );
            fixture.finish();
            assert!(
                matches!(completion.end, orbit_engine::TurnEnd::Failed(_)),
                "must reject {lie:?}"
            );
            assert_eq!(
                fixture.requests.lock().unwrap().len(),
                1,
                "bad summary settlement cannot authorize another request: {lie:?}"
            );
            assert_eq!(executor.0, 0);
            assert_eq!(journal.settlements.load(Ordering::SeqCst), 1);
            assert_eq!(source, expected);
            assert!(inner.archives().is_empty());
            assert_eq!(completion.report.attempts.len(), 1);
            assert_eq!(completion.report.attempts[0].purpose, AttemptPurpose::Chunk);
            assert_eq!(
                completion.report.attempts[0].knownness,
                AccountingKnownness::Known
            );
            assert_eq!(
                completion.report.attempts[0].totals.cost_microcents,
                Some(3)
            );
            assert_eq!(
                (
                    completion.report.input_tokens,
                    completion.report.output_tokens,
                    completion.report.cost_microcents
                ),
                (11, 7, 3)
            );
            assert_eq!(
                inner
                    .accounting_checkpoint()
                    .unwrap()
                    .known_priced_subtotals,
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 0,
                    housekeeping_microcents: 3
                })
            );
            assert_eq!(inner.receipts(), completion.report.attempts);
            assert!(!events.iter().any(|event| matches!(
                event,
                FrontendEvent::Compacted { .. }
                    | FrontendEvent::TextDelta { .. }
                    | FrontendEvent::Retrying { .. }
            )));
            assert_ids(&home, &inner, 1);
            assert_transport(&fixture);
            assert_summary_requests(&fixture, 12_000, 1);
            task05_assert_terminal(&events, &completion.report, false);
        }
    }

    #[test]
    fn task2a_actual_subtotal_overflow_preserves_the_current_known_receipt_and_pending_intent() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![Response::complete(ANSWER)]);
        let journal = MemoryJournal::fresh("service-owner");
        let options = options(&fixture, &journal, 8000, 8000);
        for (id, price) in [
            ("unpriced-seed", None),
            ("maximum-priced-seed", Some(u64::MAX)),
        ] {
            let request = AttemptIntent {
                owner_session_id: "service-owner".into(),
                child_id: None,
                request_id: id.into(),
                purpose: AttemptPurpose::Ordinary,
                budget: options.selected_budget.as_ref().unwrap().identity.clone(),
            };
            let reference = journal
                .begin_attempt(journal.accounting_checkpoint().unwrap().revision, &request)
                .unwrap();
            let receipt = RequestAccountingReceipt {
                request_id: id.into(),
                purpose: AttemptPurpose::Ordinary,
                totals: compaction::AccountingTotals {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: price,
                },
                usage: Some(orbit_adapter::types::ProviderUsage::default()),
                knownness: AccountingKnownness::Known,
                completed: true,
            };
            journal.settle_attempt(&reference, &receipt).unwrap();
        }
        let before = journal.accounting_checkpoint().unwrap();
        assert_eq!(before.totals.ordinary.cost_microcents, None);
        assert_eq!(
            before.known_priced_subtotals,
            Some(KnownPricedSubtotals {
                ordinary_microcents: u64::MAX,
                housekeeping_microcents: 0
            })
        );
        let mut selected = config(&fixture, false);
        selected.pricing = Some(task05_flat_price(1));
        let mut source = Vec::new();
        let mut executor = NoEffects::default();
        let mut events = Vec::new();
        let completion = orbit_engine::run_turn_detailed(
            &home.0,
            &selected,
            &options,
            INTENT,
            &mut source,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        fixture.finish();
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
        assert_eq!(executor.0, 0);
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        assert_eq!(completion.report.attempts.len(), 1);
        let actual = &completion.report.attempts[0];
        assert_eq!(actual.purpose, AttemptPurpose::Ordinary);
        assert_eq!(actual.knownness, AccountingKnownness::Known);
        assert!(actual.completed);
        assert_eq!(
            actual.totals,
            compaction::AccountingTotals {
                input_tokens: 11,
                output_tokens: 7,
                cost_microcents: Some(1)
            }
        );
        assert_eq!(
            actual.usage,
            Some(orbit_adapter::types::ProviderUsage {
                input_tokens: 11,
                output_tokens: 7,
                ..Default::default()
            })
        );
        assert_eq!(
            (
                completion.report.input_tokens,
                completion.report.output_tokens,
                completion.report.cost_microcents
            ),
            (11, 7, 1)
        );
        let checkpoint = journal.accounting_checkpoint().unwrap();
        assert_eq!(
            checkpoint.known_priced_subtotals,
            before.known_priced_subtotals
        );
        assert_eq!(checkpoint.totals, before.totals);
        assert_eq!(checkpoint.last_settlement, before.last_settlement);
        assert_eq!(checkpoint.revision.0, before.revision.0 + 1);
        let pending = checkpoint.pending.unwrap();
        assert_eq!(pending.intent.request_id, actual.request_id);
        assert_eq!(pending.reference.request_id, actual.request_id);
        assert_eq!(source[0], orbit_engine::user_message(INTENT));
        assert_eq!(source.last().unwrap().content, ANSWER);
        let records = orbit_ledger::verify_ledger(&home.0.join("ledger"))
            .unwrap()
            .0;
        let actual_ids: Vec<_> = records
            .into_iter()
            .filter_map(|record| {
                if let orbit_ledger::LedgerEvent::EgressIntent(event) = record.record.event {
                    Some(event.decision_id)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(actual_ids, std::slice::from_ref(&actual.request_id));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, FrontendEvent::Retrying { .. }))
        );
        assert_transport(&fixture);
        task05_assert_terminal(&events, &completion.report, false);
    }
}
