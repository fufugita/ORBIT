#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::types::{CostRates, ProviderUsage};
use orbit_cli::context_history::context_journal;
use orbit_cli::session_accounting::{
    AccountingError, ChildOrigin, FullCostStatus, NamespaceSpendPolicy, RootOrigin,
    SessionAccountingWatermark, prepare_child, prepare_root,
};
use orbit_cli::sessions::{SessionFile, SessionLease};
use orbit_engine::agent_store::{AgentStatus, AgentStore};
use orbit_engine::{
    AccountingBaseline, AccountingCheckpoint, AccountingKnownness, AccountingTotals, AttemptIntent,
    AttemptPurpose, CompactionJournal, KnownPricedSubtotals, PendingToolCall, ProviderKind,
    RequestAccountingReceipt, ToolExecutor, ToolRoundResult, TurnConfig, TurnEnd, TurnOptions,
};
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const OWNER: &str = "accounting-owner";
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 4;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("orbit-session-accounting-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn lease(&self) -> SessionLease {
        SessionLease::acquire(&self.0, OWNER, "fixture").unwrap()
    }
    fn snapshot(&self) -> PathBuf {
        self.0.join("sessions").join(format!("{OWNER}.json"))
    }
    fn accounting(&self) -> PathBuf {
        self.0
            .join("context-history")
            .join(OWNER)
            .join("accounting.json")
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn snapshot(input: u64, output: u64, cost: u64) -> SessionFile {
    SessionFile::from_chat(
        OWNER,
        "main/raw",
        "http://127.0.0.1:9",
        "main-provider",
        &[],
        0,
        input,
        output,
        cost,
    )
}
fn config(gate: &str, price: Option<u64>) -> TurnConfig {
    TurnConfig {
        provider_id: "main-provider".into(),
        gate: gate.into(),
        model: "main/raw".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: price.map(|flat| CostRates {
            input_per_million_microcents: 0,
            output_per_million_microcents: 0,
            cache_read_per_million_microcents: Some(0),
            cache_write_per_million_microcents: Some(0),
            reasoning_per_million_microcents: Some(0),
            request_flat_microcents: flat,
        }),
        max_output_tokens: 73,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    }
}
fn request(id: &str, child: Option<&str>, purpose: AttemptPurpose) -> AttemptIntent {
    AttemptIntent {
        owner_session_id: OWNER.into(),
        child_id: child.map(str::to_owned),
        request_id: id.into(),
        purpose,
        budget: orbit_engine::context_budget::BudgetIdentity::for_config(
            &config("http://127.0.0.1:9", None),
            "metadata",
            "policy",
        )
        .unwrap(),
    }
}
fn bill(
    id: &str,
    purpose: AttemptPurpose,
    input: u64,
    output: u64,
    price: Option<u64>,
) -> RequestAccountingReceipt {
    RequestAccountingReceipt {
        request_id: id.into(),
        purpose,
        totals: AccountingTotals {
            input_tokens: input,
            output_tokens: output,
            cost_microcents: price,
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
fn settle(
    journal: &dyn CompactionJournal,
    child: Option<&str>,
    receipt: &RequestAccountingReceipt,
) -> AccountingCheckpoint {
    let before = journal.accounting_checkpoint().unwrap();
    let reference = journal
        .begin_attempt(
            before.revision,
            &request(&receipt.request_id, child, receipt.purpose),
        )
        .unwrap();
    journal.settle_attempt(&reference, receipt).unwrap()
}
fn unknown_usage(id: &str, purpose: AttemptPurpose) -> RequestAccountingReceipt {
    RequestAccountingReceipt {
        request_id: id.into(),
        purpose,
        totals: AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None,
        },
        usage: None,
        knownness: AccountingKnownness::UnknownUsage,
        completed: true,
    }
}
fn options() -> TurnOptions {
    TurnOptions {
        session_id: OWNER.into(),
        max_attempts: 1,
        max_rounds: 1,
        ..Default::default()
    }
}
fn saved_equal(left: &SessionFile, right: &SessionFile) {
    assert_eq!(
        serde_json::to_value(left).unwrap(),
        serde_json::to_value(right).unwrap()
    );
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

#[test]
fn fresh_preparation_persists_a_qualified_zero_anchor_before_any_work() {
    let home = Home::new();
    let lease = home.lease();
    let mut current = snapshot(0, 0, 0);
    assert!(lease.load_optional().unwrap().is_none());
    let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let checkpoint = accounting.namespace().checkpoint().unwrap();
    assert_eq!(checkpoint.owner_session_id, OWNER);
    assert_eq!(checkpoint.child_id, None);
    assert_eq!(checkpoint.revision.0, 0);
    assert_eq!(checkpoint.baseline, AccountingBaseline::FreshKnownZero);
    assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
    assert_eq!(
        checkpoint.known_priced_subtotals,
        Some(KnownPricedSubtotals::known_zero())
    );
    assert!(checkpoint.pending.is_none() && checkpoint.last_settlement.is_none());
    saved_equal(&lease.load().unwrap(), &current);
    let anchor = current.accounting_watermark.as_ref().unwrap();
    assert_eq!(anchor.owner_session_id, OWNER);
    assert_eq!(anchor.child_id, None);
    assert_eq!(anchor.revision, 0);
    assert_eq!(anchor.full_cost_status, FullCostStatus::Known);
    let before = fs::read(home.accounting()).unwrap();
    let view = accounting.persist(&lease, &mut current).unwrap();
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (0, 0, 0)
    );
    assert_eq!(fs::read(home.accounting()).unwrap(), before);
}

#[test]
fn fresh_candidates_cannot_replace_saved_snapshots_or_orphan_accounting() {
    for with_snapshot in [false, true] {
        let home = Home::new();
        let lease = home.lease();
        if with_snapshot {
            lease.save(&snapshot(3, 2, 5)).unwrap();
        } else {
            context_journal(&home.0, OWNER, None)
                .unwrap()
                .initialize_accounting(AccountingBaseline::FreshKnownZero)
                .unwrap();
        }
        let before_snapshot = fs::read(home.snapshot()).ok();
        let before_journal = fs::read(home.accounting()).ok();
        assert!(prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::FreshCandidate).is_err());
        assert_eq!(fs::read(home.snapshot()).ok(), before_snapshot);
        assert_eq!(fs::read(home.accounting()).ok(), before_journal);
    }
    for inherited in ["turns", "input", "output", "cost", "watermark"] {
        let home = Home::new();
        let lease = home.lease();
        let mut candidate = snapshot(0, 0, 0);
        match inherited {
            "turns" => candidate.turns = 1,
            "input" => candidate.input_tokens = 1,
            "output" => candidate.output_tokens = 1,
            "cost" => candidate.cost_microcents = 1,
            "watermark" => {
                candidate.accounting_watermark = Some(SessionAccountingWatermark {
                    owner_session_id: OWNER.into(),
                    child_id: None,
                    revision: 0,
                    known_input_tokens: 0,
                    known_output_tokens: 0,
                    known_ordinary_microcents: 0,
                    known_housekeeping_microcents: 0,
                    full_cost_status: FullCostStatus::Known,
                })
            }
            _ => unreachable!(),
        }
        assert!(prepare_root(&lease, &mut candidate, RootOrigin::FreshCandidate).is_err());
        assert!(!home.snapshot().exists() && !home.accounting().exists());
    }
}

#[test]
fn restored_prefix_comes_from_the_saved_snapshot_and_is_anchored_before_admission() {
    let home = Home::new();
    let lease = home.lease();
    let original = snapshot(10, 20, 30);
    lease.save(&original).unwrap();
    let mut candidate = snapshot(999, 888, 777);
    let accounting = prepare_root(&lease, &mut candidate, RootOrigin::RestoredOrLegacy).unwrap();
    assert_eq!(
        (
            candidate.input_tokens,
            candidate.output_tokens,
            candidate.cost_microcents
        ),
        (10, 20, 30)
    );
    let checkpoint = accounting.namespace().checkpoint().unwrap();
    assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
    assert_eq!(
        checkpoint.totals.knownness,
        AccountingKnownness::UnknownLegacy
    );
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(
        checkpoint.known_priced_subtotals,
        Some(KnownPricedSubtotals::known_zero())
    );
    let anchor = lease.load().unwrap().accounting_watermark.unwrap();
    assert_eq!(anchor.revision, 0);
    assert_eq!(anchor.known_input_tokens, 0);
    assert_eq!(anchor.full_cost_status, FullCostStatus::UnknownLegacy);
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    settle(
        journal.as_ref(),
        None,
        &bill("new-work", AttemptPurpose::Ordinary, 2, 3, Some(5)),
    );
    candidate.input_tokens = 700;
    candidate.output_tokens = 800;
    candidate.cost_microcents = 900;
    let view = accounting.persist(&lease, &mut candidate).unwrap();
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (12, 23, 35)
    );
    assert_eq!(view.full_cost_status, FullCostStatus::UnknownLegacy);
    let durable = fs::read(home.accounting()).unwrap();
    assert_eq!(accounting.persist(&lease, &mut candidate).unwrap(), view);
    assert_eq!(fs::read(home.accounting()).unwrap(), durable);
    drop(accounting);
    drop(journal);
    drop(lease);
    let lease = home.lease();
    let mut reloaded = lease.load().unwrap();
    let restored = prepare_root(&lease, &mut reloaded, RootOrigin::RestoredOrLegacy).unwrap();
    assert_eq!(restored.reconcile(&mut reloaded).unwrap(), view);
}

#[test]
fn empty_runtime_and_fork_bootstraps_are_legacy_without_inferred_freshness() {
    for origin in [
        RootOrigin::RestoredOrLegacy,
        RootOrigin::ForkedThisInvocation,
    ] {
        let home = Home::new();
        let lease = home.lease();
        let mut candidate = snapshot(4, 5, 6);
        candidate.accounting_watermark = Some(SessionAccountingWatermark {
            owner_session_id: "source-session".into(),
            child_id: None,
            revision: 100,
            known_input_tokens: 80,
            known_output_tokens: 90,
            known_ordinary_microcents: 70,
            known_housekeeping_microcents: 0,
            full_cost_status: FullCostStatus::Known,
        });
        let accounting = prepare_root(&lease, &mut candidate, origin).unwrap();
        let checkpoint = accounting.namespace().checkpoint().unwrap();
        assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
        assert_eq!(
            (
                candidate.input_tokens,
                candidate.output_tokens,
                candidate.cost_microcents
            ),
            (4, 5, 6)
        );
        assert_eq!(
            candidate
                .accounting_watermark
                .as_ref()
                .unwrap()
                .owner_session_id,
            OWNER
        );
        assert_eq!(candidate.accounting_watermark.as_ref().unwrap().revision, 0);
        assert_eq!(
            accounting
                .reconcile(&mut candidate)
                .unwrap()
                .full_cost_status,
            FullCostStatus::UnknownLegacy
        );
    }
    let home = Home::new();
    let lease = home.lease();
    let accounting =
        prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::RestoredOrLegacy).unwrap();
    assert_eq!(
        accounting.namespace().checkpoint().unwrap().baseline,
        AccountingBaseline::UnknownLegacy
    );
}

#[test]
fn missing_or_corrupt_journal_never_reinitializes_a_saved_anchor() {
    for corrupt in [false, true] {
        let home = Home::new();
        let lease = home.lease();
        let mut current = snapshot(0, 0, 0);
        let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
        drop(accounting);
        let before = fs::read(home.snapshot()).unwrap();
        if corrupt {
            fs::write(home.accounting(), b"{invalid").unwrap();
        } else {
            fs::remove_file(home.accounting()).unwrap();
        }
        assert!(prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).is_err());
        assert_eq!(fs::read(home.snapshot()).unwrap(), before);
        if corrupt {
            assert_eq!(fs::read(home.accounting()).unwrap(), b"{invalid");
        } else {
            assert!(!home.accounting().exists());
        }
    }
}

#[test]
fn legacy_work_without_an_anchor_and_old_unavailable_tracking_require_recovery() {
    for unavailable in [false, true] {
        let home = Home::new();
        let lease = home.lease();
        lease.save(&snapshot(10, 20, 30)).unwrap();
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::UnknownLegacy)
            .unwrap();
        if unavailable {
            let bytes = fs::read_to_string(home.accounting()).unwrap();
            let field = ",\"known_priced_subtotals\":{\"ordinary_microcents\":0,\"housekeeping_microcents\":0}";
            assert_eq!(bytes.matches(field).count(), 1);
            fs::write(home.accounting(), bytes.replacen(field, "", 1)).unwrap();
            assert_eq!(
                journal
                    .accounting_checkpoint()
                    .unwrap()
                    .known_priced_subtotals,
                None
            );
        } else {
            settle(
                journal.as_ref(),
                None,
                &bill("unanchored", AttemptPurpose::Ordinary, 2, 3, Some(5)),
            );
        }
        let before_snapshot = fs::read(home.snapshot()).unwrap();
        let before_journal = fs::read(home.accounting()).unwrap();
        assert!(
            prepare_root(
                &lease,
                &mut snapshot(900, 800, 700),
                RootOrigin::RestoredOrLegacy
            )
            .is_err()
        );
        assert_eq!(fs::read(home.snapshot()).unwrap(), before_snapshot);
        assert_eq!(fs::read(home.accounting()).unwrap(), before_journal);
    }
}

#[test]
fn fresh_authoritative_totals_recover_a_present_snapshot_without_a_watermark() {
    let home = Home::new();
    let lease = home.lease();
    lease.save(&snapshot(900, 800, 700)).unwrap();
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    journal
        .initialize_accounting(AccountingBaseline::FreshKnownZero)
        .unwrap();
    settle(
        journal.as_ref(),
        None,
        &bill("tracked", AttemptPurpose::Ordinary, 2, 3, Some(5)),
    );
    let mut candidate = lease.load().unwrap();
    let accounting = prepare_root(&lease, &mut candidate, RootOrigin::RestoredOrLegacy).unwrap();
    let view = accounting.reconcile(&mut candidate).unwrap();
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (2, 3, 5)
    );
    assert_eq!(view.full_cost_status, FullCostStatus::Known);
    assert_eq!(candidate.accounting_watermark.as_ref().unwrap().revision, 2);
}

#[test]
fn foreign_ahead_and_inconsistent_saved_watermarks_refuse_without_replacing_bytes() {
    for fault in [
        "owner",
        "child",
        "ahead",
        "input",
        "price",
        "status",
        "underflow",
    ] {
        let home = Home::new();
        let lease = home.lease();
        let mut current = snapshot(0, 0, 0);
        let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
        drop(accounting);
        let mut value = serde_json::to_value(&current).unwrap();
        match fault {
            "owner" => value["accounting_watermark"]["owner_session_id"] = json!("foreign-owner"),
            "child" => {
                value["accounting_watermark"]["child_id"] = json!(ulid::Ulid::new().to_string())
            }
            "ahead" => value["accounting_watermark"]["revision"] = json!(2),
            "input" => value["accounting_watermark"]["known_input_tokens"] = json!(1),
            "price" => value["accounting_watermark"]["known_housekeeping_microcents"] = json!(1),
            "status" => value["accounting_watermark"]["full_cost_status"] = json!("unknown_usage"),
            "underflow" => {
                let journal = context_journal(&home.0, OWNER, None).unwrap();
                settle(
                    journal.as_ref(),
                    None,
                    &bill("billed", AttemptPurpose::Ordinary, 2, 3, Some(5)),
                );
                value["accounting_watermark"]["revision"] = json!(2);
                value["accounting_watermark"]["known_input_tokens"] = json!(2);
                value["accounting_watermark"]["known_output_tokens"] = json!(3);
                value["accounting_watermark"]["known_ordinary_microcents"] = json!(5);
            }
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(home.snapshot(), &bytes).unwrap();
        let journal_before = fs::read(home.accounting()).unwrap();
        assert!(
            prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).is_err(),
            "accepted {fault}"
        );
        assert_eq!(fs::read(home.snapshot()).unwrap(), bytes);
        assert_eq!(fs::read(home.accounting()).unwrap(), journal_before);
    }
}

#[test]
fn projection_overflow_never_partially_updates_the_snapshot_or_saved_prefix() {
    for component in ["input", "output", "cost"] {
        let home = Home::new();
        let lease = home.lease();
        let mut current = match component {
            "input" => snapshot(u64::MAX, 0, 0),
            "output" => snapshot(0, u64::MAX, 0),
            "cost" => snapshot(0, 0, u64::MAX),
            _ => unreachable!(),
        };
        lease.save(&current).unwrap();
        let accounting = prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).unwrap();
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        settle(
            journal.as_ref(),
            None,
            &bill("one-more", AttemptPurpose::Ordinary, 1, 1, Some(1)),
        );
        let before = serde_json::to_value(&current).unwrap();
        let saved = fs::read(home.snapshot()).unwrap();
        assert!(accounting.persist(&lease, &mut current).is_err());
        assert_eq!(serde_json::to_value(&current).unwrap(), before);
        assert_eq!(fs::read(home.snapshot()).unwrap(), saved);
        assert_eq!(journal.accounting_checkpoint().unwrap().revision.0, 2);
    }
}

#[test]
fn namespace_policies_subtract_known_prices_without_promoting_unknown_cost_or_usage() {
    for row in [
        "priced",
        "exhausted",
        "unpriced-main",
        "unpriced-housekeeping",
        "missing-usage",
        "legacy",
    ] {
        let home = Home::new();
        let lease = home.lease();
        let mut current = snapshot(0, 0, 0);
        let origin = if row == "legacy" {
            RootOrigin::RestoredOrLegacy
        } else {
            RootOrigin::FreshCandidate
        };
        let accounting = prepare_root(&lease, &mut current, origin).unwrap();
        let journal = context_journal(&home.0, OWNER, None).unwrap();
        if row != "legacy" {
            let receipt = match row {
                "unpriced-main" => bill("policy-work", AttemptPurpose::Ordinary, 2, 3, None),
                "unpriced-housekeeping" => bill("policy-work", AttemptPurpose::Chunk, 2, 3, None),
                "missing-usage" => unknown_usage("policy-work", AttemptPurpose::Chunk),
                _ => bill("policy-work", AttemptPurpose::Ordinary, 2, 3, Some(7)),
            };
            settle(journal.as_ref(), None, &receipt);
        }
        let before = fs::read(home.accounting()).unwrap();
        for allow_unpriced_housekeeping in [false, true] {
            let mut proposed = options();
            proposed.spend_allowance = Some(orbit_engine::SpendAllowance {
                remaining_microcents: 99,
                allow_unpriced_housekeeping: true,
            });
            let policy = NamespaceSpendPolicy {
                maximum_microcents: if row == "exhausted" { 6 } else { 10 },
                allow_unpriced_housekeeping,
            };
            let accepted =
                row == "priced" || (row == "unpriced-housekeeping" && allow_unpriced_housekeeping);
            let result = accounting
                .namespace()
                .apply_options(&mut proposed, Some(policy));
            assert_eq!(
                result.is_ok(),
                accepted,
                "row {row}, permit {allow_unpriced_housekeeping}"
            );
            if accepted {
                assert!(proposed.journal.is_some());
                assert_eq!(
                    proposed.spend_allowance.unwrap().remaining_microcents,
                    if row == "priced" { 3 } else { 10 }
                );
            } else {
                assert!(matches!(result, Err(AccountingError::SpendRefused(_))));
                assert!(proposed.journal.is_none());
                assert_eq!(proposed.spend_allowance.unwrap().remaining_microcents, 99);
            }
        }
        let mut uncapped = options();
        accounting
            .namespace()
            .apply_options(&mut uncapped, None)
            .unwrap();
        assert!(uncapped.journal.is_some() && uncapped.spend_allowance.is_none());
        assert_eq!(fs::read(home.accounting()).unwrap(), before);
    }
}

#[test]
fn uncertain_pending_receipts_can_be_projected_but_never_admit_more_work_or_replay() {
    let home = Home::new();
    let lease = home.lease();
    let mut current = snapshot(0, 0, 0);
    let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    let receipt = RequestAccountingReceipt {
        request_id: "uncertain-provider-attempt".into(),
        purpose: AttemptPurpose::Ordinary,
        totals: AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None,
        },
        usage: Some(ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 3,
            cache_write_tokens: 2,
            reasoning_tokens: 5,
        }),
        knownness: AccountingKnownness::Uncertain,
        completed: false,
    };
    let checkpoint = settle(journal.as_ref(), None, &receipt);
    assert!(checkpoint.pending.as_ref().unwrap().uncertain);
    let before_journal = fs::read(home.accounting()).unwrap();
    let view = accounting.persist(&lease, &mut current).unwrap();
    assert_eq!(view.full_cost_status, FullCostStatus::Uncertain);
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (0, 0, 0)
    );
    let raw: Value = serde_json::from_slice(&before_journal).unwrap();
    let saved_receipt = &raw["entries"][0]["pending"]["uncertain_receipt"];
    assert_eq!(
        saved_receipt["usage"],
        json!({"input_tokens":11,"output_tokens":7,"cache_read_tokens":3,"cache_write_tokens":2,"reasoning_tokens":5})
    );
    assert_eq!(saved_receipt["totals"]["cost_microcents"], Value::Null);
    for policy in [
        None,
        Some(NamespaceSpendPolicy {
            maximum_microcents: 100,
            allow_unpriced_housekeeping: true,
        }),
    ] {
        let mut proposed = options();
        assert!(
            accounting
                .namespace()
                .apply_options(&mut proposed, policy)
                .is_err()
        );
        assert!(proposed.journal.is_none() && proposed.spend_allowance.is_none());
    }
    assert!(prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).is_err());
    assert_eq!(fs::read(home.accounting()).unwrap(), before_journal);
    assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
}

#[test]
fn namespace_and_persistence_require_the_exact_held_root_identity() {
    let home = Home::new();
    let lease = home.lease();
    let mut current = snapshot(0, 0, 0);
    let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let before = fs::read(home.snapshot()).unwrap();
    let mut wrong_options = options();
    wrong_options.session_id = "different-owner".into();
    assert!(
        accounting
            .namespace()
            .apply_options(&mut wrong_options, None)
            .is_err()
    );
    assert!(wrong_options.journal.is_none());
    let wrong_lease = SessionLease::acquire(&home.0, "different-owner", "fixture").unwrap();
    assert!(accounting.persist(&wrong_lease, &mut current).is_err());
    let other_home = Home::new();
    let other_lease = other_home.lease();
    assert!(accounting.persist(&other_lease, &mut current).is_err());
    let mut foreign = current.clone();
    foreign.session_id = "different-owner".into();
    assert!(accounting.reconcile(&mut foreign).is_err());
    assert_eq!(fs::read(home.snapshot()).unwrap(), before);
    assert!(other_lease.load_optional().unwrap().is_none());
}

#[test]
fn actual_agent_runs_keep_fresh_and_resumed_child_accounting_separate_from_the_owner() {
    let home = Home::new();
    let lease = home.lease();
    let root = prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::FreshCandidate).unwrap();
    let root_before = root.namespace().checkpoint().unwrap();
    let store = AgentStore::new(&home.0, OWNER).unwrap();
    let created = store
        .create(
            "explorer",
            Some("first child"),
            "main-provider/main/raw",
            None,
        )
        .unwrap();
    let run = store.begin(&created.agent_id, None).unwrap();
    let child = prepare_child(&home.0, &run, ChildOrigin::CreatedThisInvocation).unwrap();
    assert_eq!(
        child.checkpoint().unwrap().baseline,
        AccountingBaseline::FreshKnownZero
    );
    let mut child_options = options();
    child_options.session_id = created.agent_id.clone();
    child.apply_options(&mut child_options, None).unwrap();
    let journal = child_options.journal.as_ref().unwrap();
    let checkpoint = settle(
        journal.as_ref(),
        Some(&created.agent_id),
        &bill("child-work", AttemptPurpose::Ordinary, 2, 3, Some(5)),
    );
    assert_eq!(checkpoint.owner_session_id, OWNER);
    assert_eq!(
        checkpoint.child_id.as_deref(),
        Some(created.agent_id.as_str())
    );
    assert_eq!(root.namespace().checkpoint().unwrap(), root_before);
    assert!(prepare_child(&home.0, &run, ChildOrigin::CreatedThisInvocation).is_err());
    let child_snapshot = run
        .finish(
            vec![
                orbit_engine::user_message("child question"),
                orbit_engine::assistant_message("child answer"),
            ],
            "child answer".into(),
            AgentStatus::Completed,
            1,
        )
        .unwrap();
    let value = serde_json::to_value(&child_snapshot).unwrap();
    for field in [
        "accounting_watermark",
        "input_tokens",
        "output_tokens",
        "cost_microcents",
    ] {
        assert!(value.get(field).is_none());
    }
    drop(child_options);
    drop(child);
    let run = store.begin(&created.agent_id, None).unwrap();
    let resumed = prepare_child(&home.0, &run, ChildOrigin::Resumed).unwrap();
    assert_eq!(resumed.checkpoint().unwrap(), checkpoint);
    let mut wrong_options = options();
    assert!(resumed.apply_options(&mut wrong_options, None).is_err());
    run.finish(
        child_snapshot.transcript,
        "unchanged".into(),
        AgentStatus::Completed,
        1,
    )
    .unwrap();
    let empty = store
        .create("explorer", None, "main-provider/main/raw", None)
        .unwrap();
    let empty_run = store.begin(&empty.agent_id, None).unwrap();
    let legacy = prepare_child(&home.0, &empty_run, ChildOrigin::Resumed).unwrap();
    assert_eq!(
        legacy.checkpoint().unwrap().baseline,
        AccountingBaseline::UnknownLegacy
    );
    assert_eq!(
        legacy.checkpoint().unwrap().known_priced_subtotals,
        Some(KnownPricedSubtotals::known_zero())
    );
    assert_eq!(root.namespace().checkpoint().unwrap(), root_before);
}

#[test]
fn watermark_schema_is_optional_for_legacy_sessions_and_strict_when_present() {
    let legacy = snapshot(1, 2, 3);
    let raw = serde_json::to_value(&legacy).unwrap();
    assert!(raw.get("accounting_watermark").is_none());
    assert!(
        serde_json::from_value::<SessionFile>(raw.clone())
            .unwrap()
            .accounting_watermark
            .is_none()
    );
    let valid = SessionAccountingWatermark {
        owner_session_id: OWNER.into(),
        child_id: None,
        revision: 0,
        known_input_tokens: 0,
        known_output_tokens: 0,
        known_ordinary_microcents: 0,
        known_housekeeping_microcents: 0,
        full_cost_status: FullCostStatus::Known,
    };
    for fault in ["unknown", "negative", "status", "missing"] {
        let mut watermark = serde_json::to_value(&valid).unwrap();
        match fault {
            "unknown" => watermark["unexpected"] = json!(1),
            "negative" => watermark["known_input_tokens"] = json!(-1),
            "status" => watermark["full_cost_status"] = json!("guessed_zero"),
            "missing" => {
                watermark.as_object_mut().unwrap().remove("revision");
            }
            _ => unreachable!(),
        }
        let mut candidate = raw.clone();
        candidate["accounting_watermark"] = watermark;
        assert!(
            serde_json::from_value::<SessionFile>(candidate).is_err(),
            "accepted {fault}"
        );
    }
}

#[derive(Default)]
struct NoEffects(usize);
impl ToolExecutor for NoEffects {
    fn execute(&mut self, _: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        panic!("ordinary text fixture cannot execute tools")
    }
}

#[test]
fn actual_priced_unpriced_work_survives_failed_snapshot_save_and_reconciles_once_on_reopen() {
    let home = Home::new();
    let lease = home.lease();
    let mut current = snapshot(0, 0, 0);
    let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let mut fixture = Fixture::new(vec![
        Response::complete("answer one"),
        Response::complete("answer two"),
        Response::complete("answer three"),
    ]);
    let mut transcript = Vec::new();
    let mut executor = NoEffects::default();
    let mut request_ids = Vec::new();
    let mut first_saved = Vec::new();
    for (index, price) in [Some(7), None, Some(5)].into_iter().enumerate() {
        let selected = config(&fixture.url, price);
        let mut turn_options = options();
        turn_options.request_stem = format!("accounting-recovery-{index}");
        turn_options.selected_budget = Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8000).unwrap(),
        );
        accounting
            .namespace()
            .apply_options(&mut turn_options, None)
            .unwrap();
        let mut events = Vec::new();
        let completion = orbit_engine::run_turn_detailed(
            &home.0,
            &selected,
            &turn_options,
            &format!("question {index}"),
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        assert!(matches!(completion.end, TurnEnd::Completed));
        assert!(completion.report.ok);
        assert_eq!(completion.report.attempts.len(), 1);
        let receipt = &completion.report.attempts[0];
        assert_eq!(receipt.purpose, AttemptPurpose::Ordinary);
        assert_eq!(receipt.knownness, AccountingKnownness::Known);
        assert_eq!(receipt.totals.cost_microcents, price);
        assert_eq!(
            (receipt.totals.input_tokens, receipt.totals.output_tokens),
            (11, 7)
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    orbit_frontend_protocol::FrontendEvent::TurnEnded { .. }
                ))
                .count(),
            1
        );
        request_ids.push(receipt.request_id.clone());
        current.transcript = transcript.clone();
        current.turns += 1;
        if index == 0 {
            let view = accounting.persist(&lease, &mut current).unwrap();
            assert_eq!((view.revision, view.known_cost_microcents), (2, 7));
            first_saved = fs::read(home.snapshot()).unwrap();
        }
    }
    fixture.finish();
    assert_eq!(executor.0, 0);
    assert_eq!(
        request_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    let ledger = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0;
    let actual_ids: Vec<_> = ledger
        .into_iter()
        .filter_map(|record| match record.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, OWNER);
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(actual_ids, request_ids);
    let captured = fixture.requests.lock().unwrap();
    assert_eq!(captured.len(), 3);
    for (index, request) in captured.iter().enumerate() {
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
        assert_eq!(request.body["model"], "main/raw");
        assert_eq!(request.body["max_tokens"], 73);
        assert!(request.body.get("tools").is_none());
        assert!(
            request.body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["content"] == format!("question {index}"))
        );
    }
    drop(captured);
    let checkpoint = accounting.namespace().checkpoint().unwrap();
    assert_eq!(checkpoint.revision.0, 6);
    assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    assert_eq!(
        checkpoint
            .known_priced_subtotals
            .unwrap()
            .ordinary_microcents,
        12
    );
    assert_eq!(
        checkpoint
            .last_settlement
            .as_ref()
            .unwrap()
            .reference
            .request_id,
        request_ids[2]
    );
    let journal_bytes = fs::read(home.accounting()).unwrap();
    fs::set_permissions(home.0.join("sessions"), fs::Permissions::from_mode(0o755)).unwrap();
    let failed = accounting.persist(&lease, &mut current);
    fs::set_permissions(home.0.join("sessions"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err());
    assert_eq!(fs::read(home.snapshot()).unwrap(), first_saved);
    assert_eq!(fs::read(home.accounting()).unwrap(), journal_bytes);
    drop(accounting);
    drop(lease);
    let lease = home.lease();
    let mut restored = lease.load().unwrap();
    assert_eq!(restored.turns, 1);
    assert_eq!(restored.transcript.len(), 2);
    let adapter = prepare_root(&lease, &mut restored, RootOrigin::RestoredOrLegacy).unwrap();
    let view = adapter.persist(&lease, &mut restored).unwrap();
    assert_eq!(
        (
            view.revision,
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (6, 33, 21, 12)
    );
    assert_eq!(view.full_cost_status, FullCostStatus::Unpriced);
    assert_eq!(adapter.persist(&lease, &mut restored).unwrap(), view);
    saved_equal(&lease.load().unwrap(), &restored);
    assert_eq!(fs::read(home.accounting()).unwrap(), journal_bytes);
}

#[test]
fn a_durable_unsettled_begin_projects_uncertainty_without_inventing_a_known_bill() {
    let home = Home::new();
    let lease = home.lease();
    let mut fixture = Fixture::new(vec![Response::complete("unexpected provider work")]);
    let mut current = snapshot(0, 0, 0);
    current.gate = fixture.url.clone();
    let accounting = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let journal = context_journal(&home.0, OWNER, None).unwrap();
    settle(
        journal.as_ref(),
        None,
        &bill(
            "previous-known-work",
            AttemptPurpose::Ordinary,
            2,
            3,
            Some(5),
        ),
    );
    accounting.persist(&lease, &mut current).unwrap();
    let before = journal.accounting_checkpoint().unwrap();
    let reference = journal
        .begin_attempt(
            before.revision,
            &request("unsettled-attempt", None, AttemptPurpose::Ordinary),
        )
        .unwrap();
    let pending = journal.accounting_checkpoint().unwrap();
    assert_eq!(pending.pending.as_ref().unwrap().reference, reference);
    assert_eq!(pending.totals.knownness, AccountingKnownness::Known);
    assert_eq!(pending.totals, before.totals);
    assert_eq!(
        pending.known_priced_subtotals,
        before.known_priced_subtotals
    );
    let before_journal = fs::read(home.accounting()).unwrap();
    let view = accounting.persist(&lease, &mut current).unwrap();
    assert_eq!(view.full_cost_status, FullCostStatus::Uncertain);
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (2, 3, 5)
    );
    assert_eq!(
        lease
            .load()
            .unwrap()
            .accounting_watermark
            .unwrap()
            .full_cost_status,
        FullCostStatus::Uncertain
    );
    let mut proposed = options();
    assert!(
        accounting
            .namespace()
            .apply_options(&mut proposed, None)
            .is_err()
    );
    assert!(proposed.journal.is_none() && proposed.spend_allowance.is_none());
    assert_eq!(fs::read(home.accounting()).unwrap(), before_journal);
    assert_eq!(journal.accounting_checkpoint().unwrap(), pending);
    fixture.finish();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
}

mod detailed_projection {
    use super::*;
    use orbit_engine::SpendAllowance;
    use orbit_engine::compaction::{AccountingRevision, AttemptRef, HistoryError};
    use orbit_engine::retry::{
        FinalRejectionContract, FinalRejectionPolicy, FinalRejectionSelector,
        OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup, RetryPolicyBinding,
        adapter_identity_digest,
    };

    fn retry_policy(name: &str, provider: &str, model: &str) -> RetryPolicyBinding {
        let mut selected = config("http://127.0.0.1:9", None);
        selected.provider_id = provider.into();
        selected.model = model.into();
        let selector = FinalRejectionSelector::new(
            selected.provider_id.clone(),
            selected.model.clone(),
            selected.gate.clone(),
            adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
        )
        .unwrap();
        RetryPolicyBinding::for_config(
            &selected,
            FinalRejectionPolicy::new(
                name.into(),
                selector,
                vec![503],
                FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true)
                    .unwrap(),
                2,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn allowance(remaining: u64, housekeeping: bool) -> SpendAllowance {
        SpendAllowance {
            remaining_microcents: remaining,
            allow_unpriced_housekeeping: housekeeping,
        }
    }
    fn unchanged_options(
        proposed: &TurnOptions,
        journal: &Arc<dyn CompactionJournal>,
        original: Option<SpendAllowance>,
    ) {
        assert!(Arc::ptr_eq(proposed.journal.as_ref().unwrap(), journal));
        assert_eq!(proposed.spend_allowance, original);
        assert_eq!(proposed.session_id, OWNER);
        assert_eq!(proposed.max_attempts, 1);
        assert_eq!(proposed.max_rounds, 1);
    }

    fn apply_options_variant(
        namespace: &orbit_cli::session_accounting::NamespaceAccounting,
        detailed: bool,
        proposed: &mut TurnOptions,
        policy: Option<NamespaceSpendPolicy>,
    ) -> Result<(), AccountingError> {
        if detailed {
            namespace.apply_options_detailed(proposed, policy, None)
        } else {
            namespace.apply_options(proposed, policy)
        }
    }

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

    // Checked snapshot fixtures confer neither a live binding nor a settlement
    // acknowledgement. Actual live refusal acceptance belongs to engine tests.
    fn seed_refusal(home: &Home, baseline: AccountingBaseline) -> RefusalRollup {
        let intent = request("snapshot-refusal", None, AttemptPurpose::Ordinary);
        let attempt = AttemptRef {
            revision: AccountingRevision(1),
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest().unwrap(),
        };
        let binding = OrdinaryAttemptBindingRecord::new(
            intent.request_id.clone(),
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
        let refused = RefusalRecord::new(intent, attempt, binding, "9".repeat(64), 503, 0).unwrap();
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
            .replacen("\"last\":null", &format!("\"last\":{last}"), 1);
        if baseline == AccountingBaseline::FreshKnownZero {
            raw = raw
                .replacen("\"cost_microcents\":0", "\"cost_microcents\":null", 1)
                .replacen(
                    "\"knownness\":\"known\"",
                    "\"knownness\":\"unknown_usage\"",
                    1,
                );
        }
        let end = raw.rfind("}]}").unwrap();
        raw.insert_str(end, &format!(",\"refusals\":{encoded_rollup}"));
        assert!(raw.len() < 128 * 1024);
        fs::write(home.accounting(), raw.as_bytes()).unwrap();
        assert_eq!(
            context_journal(&home.0, OWNER, None)
                .unwrap()
                .accounting_checkpoint_detailed()
                .unwrap()
                .refusals(),
            Some(&rollup)
        );
        rollup
    }

    #[test]
    fn detailed_none_intersects_remaining_caps_once_and_combines_permissions_strictly() {
        for detailed in [false, true] {
            let home = Home::new();
            let lease = home.lease();
            let root =
                prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::FreshCandidate).unwrap();
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            settle(
                journal.as_ref(),
                None,
                &bill("priced", AttemptPurpose::Ordinary, 2, 3, Some(7)),
            );
            let before = fs::read(home.accounting()).unwrap();
            for existing in [
                None,
                Some(allowance(2, false)),
                Some(allowance(2, true)),
                Some(allowance(8, false)),
                Some(allowance(8, true)),
            ] {
                for namespace_permission in [false, true] {
                    let mut proposed = options();
                    proposed.spend_allowance = existing;
                    apply_options_variant(root.namespace(), detailed, &mut proposed, None).unwrap();
                    assert_eq!(proposed.spend_allowance, existing);
                    proposed.spend_allowance = existing;
                    apply_options_variant(
                        root.namespace(),
                        detailed,
                        &mut proposed,
                        Some(NamespaceSpendPolicy {
                            maximum_microcents: 10,
                            allow_unpriced_housekeeping: namespace_permission,
                        }),
                    )
                    .unwrap();
                    assert_eq!(
                        proposed.spend_allowance,
                        Some(allowance(
                            existing.map_or(3, |value| value.remaining_microcents.min(3)),
                            namespace_permission
                                && existing.is_none_or(|value| value.allow_unpriced_housekeeping),
                        ))
                    );
                    assert!(proposed.journal.is_some());
                    assert_eq!(fs::read(home.accounting()).unwrap(), before);
                }
            }
            assert_eq!(fs::read(home.accounting()).unwrap(), before);
        }
    }

    #[test]
    fn selected_retry_with_either_cap_refuses_before_changing_options_or_storage() {
        let home = Home::new();
        let lease = home.lease();
        let root =
            prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::FreshCandidate).unwrap();
        let sentinel = context_journal(&home.0, OWNER, None).unwrap();
        let retry = retry_policy("current", "main-provider", "main/raw");
        let before = fs::read(home.accounting()).unwrap();
        for (namespace, existing) in [
            (
                Some(NamespaceSpendPolicy {
                    maximum_microcents: 20,
                    allow_unpriced_housekeeping: true,
                }),
                None,
            ),
            (None, Some(allowance(17, true))),
            (
                Some(NamespaceSpendPolicy {
                    maximum_microcents: 20,
                    allow_unpriced_housekeeping: false,
                }),
                Some(allowance(17, true)),
            ),
        ] {
            let mut proposed = options();
            proposed.journal = Some(Arc::clone(&sentinel));
            proposed.spend_allowance = existing;
            assert!(matches!(
                root.namespace()
                    .apply_options_detailed(&mut proposed, namespace, Some(&retry)),
                Err(AccountingError::SpendRefused(_))
            ));
            unchanged_options(&proposed, &sentinel, existing);
            assert_eq!(fs::read(home.accounting()).unwrap(), before);
        }
        let mut uncapped = options();
        root.namespace()
            .apply_options_detailed(&mut uncapped, None, Some(&retry))
            .unwrap();
        assert!(uncapped.journal.is_some() && uncapped.spend_allowance.is_none());
        assert_eq!(fs::read(home.accounting()).unwrap(), before);
    }

    #[test]
    fn detailed_caps_refuse_every_unknown_ordinary_bill_even_with_housekeeping_permission() {
        for kind in ["unpriced", "missing-usage", "legacy", "refusal"] {
            let home = Home::new();
            let lease = home.lease();
            let mut current = snapshot(0, 0, 0);
            let root = prepare_root(
                &lease,
                &mut current,
                if kind == "legacy" {
                    RootOrigin::RestoredOrLegacy
                } else {
                    RootOrigin::FreshCandidate
                },
            )
            .unwrap();
            let sentinel = context_journal(&home.0, OWNER, None).unwrap();
            match kind {
                "unpriced" => {
                    settle(
                        sentinel.as_ref(),
                        None,
                        &bill("unpriced", AttemptPurpose::Ordinary, 2, 3, None),
                    );
                }
                "missing-usage" => {
                    settle(
                        sentinel.as_ref(),
                        None,
                        &unknown_usage("missing", AttemptPurpose::Ordinary),
                    );
                }
                "refusal" => {
                    seed_refusal(&home, AccountingBaseline::FreshKnownZero);
                }
                "legacy" => {}
                _ => unreachable!(),
            }
            let before = fs::read(home.accounting()).unwrap();
            for namespace_cap in [false, true] {
                let original = if namespace_cap {
                    None
                } else {
                    Some(allowance(100, true))
                };
                let mut proposed = options();
                proposed.journal = Some(Arc::clone(&sentinel));
                proposed.spend_allowance = original;
                let policy = namespace_cap.then_some(NamespaceSpendPolicy {
                    maximum_microcents: 100,
                    allow_unpriced_housekeeping: true,
                });
                assert!(
                    matches!(
                        root.namespace()
                            .apply_options_detailed(&mut proposed, policy, None),
                        Err(AccountingError::SpendRefused(_))
                    ),
                    "accepted {kind} cap {namespace_cap}"
                );
                unchanged_options(&proposed, &sentinel, original);
                assert_eq!(fs::read(home.accounting()).unwrap(), before);
            }
        }
    }

    #[test]
    fn unpriced_housekeeping_requires_the_effective_intersection_permission() {
        for detailed in [false, true] {
            let home = Home::new();
            let lease = home.lease();
            let root =
                prepare_root(&lease, &mut snapshot(0, 0, 0), RootOrigin::FreshCandidate).unwrap();
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            settle(
                journal.as_ref(),
                None,
                &bill("unpriced-summary", AttemptPurpose::Chunk, 2, 3, None),
            );
            let before = fs::read(home.accounting()).unwrap();
            for existing_permission in [false, true] {
                for namespace_permission in [false, true] {
                    let mut proposed = options();
                    proposed.journal = Some(Arc::clone(&journal));
                    proposed.spend_allowance = Some(allowance(17, existing_permission));
                    let result = apply_options_variant(
                        root.namespace(),
                        detailed,
                        &mut proposed,
                        Some(NamespaceSpendPolicy {
                            maximum_microcents: 20,
                            allow_unpriced_housekeeping: namespace_permission,
                        }),
                    );
                    if existing_permission && namespace_permission {
                        result.unwrap();
                        assert_eq!(proposed.spend_allowance, Some(allowance(17, true)));
                    } else {
                        assert!(matches!(result, Err(AccountingError::SpendRefused(_))));
                        unchanged_options(
                            &proposed,
                            &journal,
                            Some(allowance(17, existing_permission)),
                        );
                    }
                    assert_eq!(fs::read(home.accounting()).unwrap(), before);
                }
            }
            for namespace_only in [false, true] {
                let mut proposed = options();
                let policy = if namespace_only {
                    Some(NamespaceSpendPolicy {
                        maximum_microcents: 20,
                        allow_unpriced_housekeeping: true,
                    })
                } else {
                    proposed.spend_allowance = Some(allowance(17, true));
                    None
                };
                apply_options_variant(root.namespace(), detailed, &mut proposed, policy).unwrap();
                assert_eq!(
                    proposed.spend_allowance,
                    Some(allowance(if namespace_only { 20 } else { 17 }, true))
                );
            }
            for namespace_only in [false, true] {
                let mut proposed = options();
                proposed.journal = Some(Arc::clone(&journal));
                let original = if namespace_only {
                    None
                } else {
                    Some(allowance(17, false))
                };
                proposed.spend_allowance = original;
                let policy = namespace_only.then_some(NamespaceSpendPolicy {
                    maximum_microcents: 20,
                    allow_unpriced_housekeeping: false,
                });
                assert!(matches!(
                    apply_options_variant(root.namespace(), detailed, &mut proposed, policy),
                    Err(AccountingError::SpendRefused(_))
                ));
                unchanged_options(&proposed, &journal, original);
                assert_eq!(fs::read(home.accounting()).unwrap(), before);
            }
            assert_eq!(fs::read(home.accounting()).unwrap(), before);
        }
    }

    #[test]
    fn refusal_projection_restart_preserves_numeric_prefix_and_detailed_floor() {
        for legacy in [false, true] {
            let home = Home::new();
            let lease = home.lease();
            let mut current = if legacy {
                snapshot(10, 20, 30)
            } else {
                snapshot(0, 0, 0)
            };
            let root = prepare_root(
                &lease,
                &mut current,
                if legacy {
                    RootOrigin::RestoredOrLegacy
                } else {
                    RootOrigin::FreshCandidate
                },
            )
            .unwrap();
            let rollup = seed_refusal(
                &home,
                if legacy {
                    AccountingBaseline::UnknownLegacy
                } else {
                    AccountingBaseline::FreshKnownZero
                },
            );
            let refused_bytes = fs::read(home.accounting()).unwrap();
            assert!(matches!(
                root.namespace().checkpoint(),
                Err(AccountingError::History(HistoryError::InvalidRecord))
            ));
            let sentinel = context_journal(&home.0, OWNER, None).unwrap();
            let mut legacy_options = options();
            legacy_options.journal = Some(Arc::clone(&sentinel));
            legacy_options.spend_allowance = Some(allowance(99, false));
            assert!(
                root.namespace()
                    .apply_options(&mut legacy_options, None)
                    .is_err()
            );
            unchanged_options(&legacy_options, &sentinel, Some(allowance(99, false)));
            let view = root.persist(&lease, &mut current).unwrap();
            assert_eq!(
                (
                    view.input_tokens,
                    view.output_tokens,
                    view.known_cost_microcents
                ),
                if legacy { (10, 20, 30) } else { (0, 0, 0) }
            );
            assert_eq!(
                view.full_cost_status,
                if legacy {
                    FullCostStatus::UnknownLegacy
                } else {
                    FullCostStatus::UnknownUsage
                }
            );
            if !legacy {
                let changed = retry_policy("changed", "other-provider", "other/model");
                for retry in [None, Some(&changed)] {
                    let mut proposed = options();
                    root.namespace()
                        .apply_options_detailed(&mut proposed, None, retry)
                        .unwrap();
                    assert!(proposed.journal.is_some() && proposed.spend_allowance.is_none());
                }
            }
            let mut successful = bill("later-success", AttemptPurpose::Ordinary, 2, 3, Some(5));
            successful.usage = Some(ProviderUsage {
                input_tokens: 2,
                output_tokens: 3,
                cache_read_tokens: 7,
                cache_write_tokens: 11,
                reasoning_tokens: 13,
            });
            let reference = sentinel
                .begin_attempt_detailed(
                    AccountingRevision(2),
                    &request("later-success", None, AttemptPurpose::Ordinary),
                    None,
                )
                .unwrap();
            let final_checkpoint = sentinel
                .settle_attempt_detailed(&reference, &successful)
                .unwrap();
            assert_eq!(final_checkpoint.refusals(), Some(&rollup));
            let final_view = root.persist(&lease, &mut current).unwrap();
            assert_eq!(
                (
                    final_view.input_tokens,
                    final_view.output_tokens,
                    final_view.known_cost_microcents
                ),
                if legacy { (12, 23, 35) } else { (2, 3, 5) }
            );
            assert_eq!(final_view.full_cost_status, view.full_cost_status);
            let final_bytes = fs::read(home.accounting()).unwrap();
            assert_eq!(root.persist(&lease, &mut current).unwrap(), final_view);
            assert_eq!(fs::read(home.accounting()).unwrap(), final_bytes);
            drop(root);
            drop(sentinel);
            drop(lease);
            let lease = home.lease();
            let mut loaded = lease.load().unwrap();
            let reopened = prepare_root(&lease, &mut loaded, RootOrigin::RestoredOrLegacy).unwrap();
            assert_eq!(reopened.reconcile(&mut loaded).unwrap(), final_view);
            assert_eq!(
                reopened.namespace().checkpoint_detailed().unwrap(),
                final_checkpoint
            );
            fs::write(home.accounting(), &refused_bytes).unwrap();
            let saved_before = fs::read(home.snapshot()).unwrap();
            assert!(reopened.namespace().checkpoint_detailed().is_err());
            assert!(reopened.persist(&lease, &mut loaded).is_err());
            assert!(prepare_root(&lease, &mut loaded, RootOrigin::RestoredOrLegacy).is_err());
            assert_eq!(fs::read(home.accounting()).unwrap(), refused_bytes);
            assert_eq!(fs::read(home.snapshot()).unwrap(), saved_before);
        }
    }

    #[test]
    fn pending_detailed_work_after_refusal_projects_uncertainty_without_readmission() {
        for settle_uncertain in [false, true] {
            let home = Home::new();
            let lease = home.lease();
            let mut current = snapshot(0, 0, 0);
            let root = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
            let rollup = seed_refusal(&home, AccountingBaseline::FreshKnownZero);
            let journal = context_journal(&home.0, OWNER, None).unwrap();
            let paid = bill("known-later-work", AttemptPurpose::Ordinary, 2, 3, Some(5));
            let paid_reference = journal
                .begin_attempt_detailed(
                    AccountingRevision(2),
                    &request("known-later-work", None, AttemptPurpose::Ordinary),
                    None,
                )
                .unwrap();
            journal
                .settle_attempt_detailed(&paid_reference, &paid)
                .unwrap();
            root.persist(&lease, &mut current).unwrap();
            let reference = journal
                .begin_attempt_detailed(
                    AccountingRevision(4),
                    &request("pending-later-work", None, AttemptPurpose::Ordinary),
                    None,
                )
                .unwrap();
            if settle_uncertain {
                let receipt = RequestAccountingReceipt {
                    request_id: "pending-later-work".into(),
                    purpose: AttemptPurpose::Ordinary,
                    totals: AccountingTotals {
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microcents: None,
                    },
                    usage: Some(ProviderUsage {
                        input_tokens: 11,
                        output_tokens: 7,
                        cache_read_tokens: 3,
                        cache_write_tokens: 2,
                        reasoning_tokens: 5,
                    }),
                    knownness: AccountingKnownness::Uncertain,
                    completed: false,
                };
                journal
                    .settle_attempt_detailed(&reference, &receipt)
                    .unwrap();
            }
            let checkpoint = root.namespace().checkpoint_detailed().unwrap();
            assert_eq!(checkpoint.refusals(), Some(&rollup));
            assert_eq!(checkpoint.pending().unwrap().uncertain, settle_uncertain);
            let before = fs::read(home.accounting()).unwrap();
            let view = root.persist(&lease, &mut current).unwrap();
            assert_eq!(
                (
                    view.input_tokens,
                    view.output_tokens,
                    view.known_cost_microcents
                ),
                (2, 3, 5)
            );
            assert_eq!(view.full_cost_status, FullCostStatus::Uncertain);
            let mut proposed = options();
            proposed.journal = Some(Arc::clone(&journal));
            proposed.spend_allowance = Some(allowance(99, true));
            assert!(
                root.namespace()
                    .apply_options_detailed(&mut proposed, None, None)
                    .is_err()
            );
            unchanged_options(&proposed, &journal, Some(allowance(99, true)));
            assert!(prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).is_err());
            assert_eq!(fs::read(home.accounting()).unwrap(), before);
            assert_eq!(
                journal.accounting_checkpoint_detailed().unwrap(),
                checkpoint
            );
        }
    }
}
