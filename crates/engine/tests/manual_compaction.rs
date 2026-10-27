#![deny(unsafe_code)]

use orbit_adapter::types::{
    ChatMessage, ChatRole, ContentBlock, CostRates, Sha256Digest, ToolCallMessage, ToolDefinition,
};
use orbit_engine::{ProviderKind, TurnConfig, TurnOptions};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[path = "support/compaction_journal.rs"]
pub mod compaction_journal;
use compaction_journal::{Failure, MemoryJournal};
use orbit_engine::compaction::{
    self, AccountingKnownness, AttemptPurpose, CompactionJournal, CompactionStatus,
};

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 10;
const INTENT: &str = "continue exact current task λ";
const SUMMARY: &str = "short synthetic summary";
const HIDDEN: &str = "PRIVATE-ORIGINAL-THOUGHT";

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("orbit-manual-compaction-{}", ulid::Ulid::new()));
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
        billing: summary.then(|| {
            use orbit_adapter::types::{
                BillingQuoteContractV1, BillingRatesV1, ModelId, PricingDeclarationState,
                ProviderId, ReasoningCounterBasis, ReasoningRatePolicy,
            };
            BillingQuoteContractV1::try_new(
                ProviderId("summary-provider".into()),
                ModelId("raw-summary/model".into()),
                PricingDeclarationState::DeclaredV2,
                BillingRatesV1 {
                    input_per_million_microdollars: Some(0),
                    output_per_million_microdollars: Some(0),
                    cache_read_per_million_microdollars: Some(0),
                    cache_write_per_million_microdollars: Some(0),
                    reasoning_per_million_microdollars: None,
                    request_flat_microdollars: Some(17),
                },
                ReasoningCounterBasis::IncludedInOutput,
                ReasoningRatePolicy::OutputRate,
            )
            .unwrap()
        }),
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
        credential_env: Some(
            if summary {
                "ORBIT_MANUAL_SUMMARY_FIXTURE"
            } else {
                "ORBIT_MANUAL_MAIN_FIXTURE"
            }
            .into(),
        ),
        pricing: Some(CostRates {
            input_per_million_microcents: 0,
            output_per_million_microcents: 0,
            cache_read_per_million_microcents: Some(0),
            cache_write_per_million_microcents: Some(0),
            reasoning_per_million_microcents: Some(0),
            request_flat_microcents: if summary { 17 } else { 91 },
        }),
        max_output_tokens: if summary { 37 } else { 73 },
        sampling: None,
        effort: Some(serde_json::from_value(json!(if summary { "high" } else { "low" })).unwrap()),
        supported_efforts: Some(vec![
            serde_json::from_value(json!("low")).unwrap(),
            serde_json::from_value(json!("high")).unwrap(),
        ]),
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
    pair(&mut source, INTENT, 0);
    source
}

fn body_estimate(body: &Value) -> u64 {
    (serde_json::to_vec(body).unwrap().len() as u64).div_ceil(4)
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
        assert_eq!(
            request
                .headers
                .iter()
                .filter_map(|(name, value)| (name == "authorization").then_some(value.as_str()))
                .collect::<Vec<_>>(),
            ["Bearer synthetic-manual-summary-key"]
        );
        assert!(!request.headers.iter().any(|(name, _)| name == "x-api-key"));
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
        session_id: "manual-owner".into(),
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

fn dispatch_isolated(exact: &str) -> bool {
    let isolated = std::env::var_os("ORBIT_ACTIVATION_ISOLATED");
    let depth = std::env::var_os("ORBIT_ACTIVATION_RUNNER_DEPTH");
    if isolated.as_deref() == Some(std::ffi::OsStr::new("1")) {
        assert_eq!(
            depth.as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "invalid isolated runner depth"
        );
        return true;
    }
    assert!(
        isolated.is_none() && depth.is_none(),
        "malformed isolation dispatch controls"
    );
    let required = std::env::var("ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION").as_deref() == Ok("1");
    let output = std::process::Command::new("/usr/bin/python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/fixtures/context_session_isolation.py"
        ))
        .arg("--binary")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", exact, "--timeout", "45"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("tracked isolation runner did not start");
    assert!(
        output.stdout.len() <= 512 * 1024 && output.stderr.len() <= 64 * 1024,
        "runner receipt output bound"
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid isolation runner receipt, exit {:?}",
            output.status.code()
        )
    });
    assert_eq!(report["schema"], "orbit.context-session-isolation/v1");
    assert_eq!(report["test_filter"], exact);
    let visible = json!({"schema":report["schema"],"test_filter":exact,"status":report["status"],
            "test_started":report["test_started"],"reason":report["reason"],"harness":report["harness"],
            "binary_sha256":report["binary_sha256"],"binary_metadata_and_hash_unchanged":report["binary_metadata_and_hash_unchanged"],
            "host_managed_path_metadata_unchanged":report["host_managed_path_metadata_unchanged"],"owned_fixture_removed":report["owned_fixture_removed"]});
    // Direct Write bypasses libtest's println capture. A returning NOTRUN
    // wrapper must stay visible and must not count as an inner pass.
    let line = format!("ORBIT_CONTEXT_SESSION_ISOLATION {visible}\n");
    std::io::Write::write_all(&mut std::io::stdout().lock(), line.as_bytes()).unwrap();
    match report["status"].as_str() {
        Some("TEST_PASSED") => {
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(report["test_started"], true);
            assert_eq!(report["harness"]["passed"], 1);
            assert_eq!(report["harness"]["failed"], 0);
            assert_eq!(report["harness"]["ignored"], 0);
            for field in [
                "binary_metadata_and_hash_unchanged",
                "host_managed_path_metadata_unchanged",
                "owned_fixture_removed",
                "binary_postcheck_inside",
            ] {
                assert_eq!(report[field], true);
            }
        }
        Some("NOTRUN") => {
            assert_eq!(output.status.code(), Some(77));
            assert_eq!(report["test_started"], false);
            assert!(
                !required,
                "NOTRUN: this infrastructure-required job needs namespace capability"
            );
        }
        Some("TEST_FAILED") | Some("INFRA_FAILURE") => {
            panic!(
                "isolated test did not pass: {} / {} / {}",
                report["status"], report["stdout_excerpt"], report["stderr_excerpt"]
            );
        }
        _ => panic!("unknown isolation runner status"),
    }
    false
}

fn require_private_system_fixture() {
    // Check descriptors/namespace identity BEFORE opening managed content,
    // creating a fixture, spawning a provider or starting any caller.
    let descriptor = |name: &str| {
        let value: u32 = std::env::var(name)
            .expect("isolated runner descriptor missing")
            .parse()
            .unwrap();
        assert!(value < 4096);
        fs::metadata(format!("/proc/self/fd/{value}")).unwrap()
    };
    let parent_mount = descriptor("ORBIT_ACTIVATION_PARENT_MOUNT_FD");
    let parent_user = descriptor("ORBIT_ACTIVATION_PARENT_USER_FD");
    let own_mount = fs::metadata("/proc/self/ns/mnt").unwrap();
    let own_user = fs::metadata("/proc/self/ns/user").unwrap();
    assert_ne!(
        (parent_mount.dev(), parent_mount.ino()),
        (own_mount.dev(), own_mount.ino())
    );
    assert_ne!(
        (parent_user.dev(), parent_user.ino()),
        (own_user.dev(), own_user.ino())
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        )
    );
    let expected = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
    assert!(expected.starts_with("ORBIT_ACTIVATION_MANAGED_") && expected.len() <= 128);
    assert!(
        expected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let path = Path::new("/etc/orbit/ORBIT.md");
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(metadata.len() <= 128);
    assert_eq!(fs::read(path).unwrap(), expected.as_bytes());
    assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
    let root =
        PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").expect("private root missing"));
    assert!(root.is_absolute());
    assert_eq!(root.canonicalize().unwrap(), root);
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("oc-")
    );
    assert_eq!(fs::symlink_metadata(&root).unwrap().mode() & 0o777, 0o700);
    for name in [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
    ] {
        let path = PathBuf::from(std::env::var_os(name).expect("private user path missing"));
        assert!(path.is_absolute() && path.starts_with(&root) && path != root);
        assert_eq!(path.canonicalize().unwrap(), path);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }
    assert!(std::env::current_dir().unwrap().starts_with(&root));
    for name in [
        "ORBIT_HOME",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        assert!(
            std::env::var_os(name).is_none(),
            "runner did not clear an inherited provider setting"
        );
    }
}

macro_rules! isolated {
    ($name:literal) => {
        if !dispatch_isolated($name) {
            return;
        }
        require_private_system_fixture();
    };
}

fn setup(
    responses: Vec<Response>,
    main_window: u64,
    summary_window: u64,
) -> (Home, Fixture, Arc<MemoryJournal>, TurnConfig, TurnOptions) {
    let home = Home::new();
    let fixture = Fixture::new(responses);
    let selected = config(&fixture, false);
    let summary = config(&fixture, true);
    let store = orbit_adapter::provider_credentials::ProviderCredentialStore::new(&home.0).unwrap();
    for (config, key) in [
        (&selected, "synthetic-manual-main-key"),
        (&summary, "synthetic-manual-summary-key"),
    ] {
        assert!(std::env::var_os(config.credential_env.as_ref().unwrap()).is_none());
        let identity = orbit_adapter::provider_credentials::ProviderAuthIdentity::new(
            &config.provider_id,
            "openai-compatible",
            &config.gate,
            config.credential_env.as_deref(),
        )
        .unwrap();
        store
            .save(
                &identity,
                orbit_adapter::SecretBytes::new(key.as_bytes().to_vec()),
                orbit_adapter::provider_credentials::ExpectedRevision::Absent,
            )
            .unwrap();
    }
    let journal = MemoryJournal::fresh("manual-owner");
    let options = options(&fixture, &journal, main_window, summary_window);
    (home, fixture, journal, selected, options)
}

fn invoke(
    home: &Home,
    config: &TurnConfig,
    options: &TurnOptions,
    source: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
) -> (orbit_engine::ManualCompactionCompletion, Vec<FrontendEvent>) {
    let mut events = Vec::new();
    let result = orbit_engine::compact_context_detailed(
        &home.0,
        config,
        options,
        source,
        cancel,
        &mut |event| events.push(event),
    );
    (result, events)
}

fn assert_private_manual_events(events: &[FrontendEvent], applied: bool) {
    assert!(!events.iter().any(|event| matches!(
        event,
        FrontendEvent::TextDelta { .. }
            | FrontendEvent::ResponseFinished { .. }
            | FrontendEvent::TurnEnded { .. }
            | FrontendEvent::RoundStarted { .. }
    )));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
            .count(),
        usize::from(applied)
    );
    for event in events {
        if let FrontendEvent::Compacted { summary, .. } = event {
            assert!(summary.is_empty());
        }
    }
    let encoded = serde_json::to_string(events).unwrap();
    assert!(!encoded.contains(HIDDEN) && !encoded.contains("synthetic-manual-summary-key"));
}

fn assert_paid(
    result: &orbit_engine::ManualCompactionCompletion,
    journal: &MemoryJournal,
    count: usize,
) {
    assert_eq!(result.attempts.len(), count);
    assert_eq!(journal.receipts(), result.attempts);
    assert_eq!(
        result.accounting.ordinary,
        compaction::AccountingTotals::known_zero()
    );
    assert_eq!(
        result.accounting.housekeeping.input_tokens,
        11 * count as u64
    );
    assert_eq!(
        result.accounting.housekeeping.output_tokens,
        7 * count as u64
    );
    assert_eq!(
        result.accounting.housekeeping.cost_microcents,
        Some(17 * count as u64)
    );
    assert_eq!(result.accounting.knownness, AccountingKnownness::Known);
    for receipt in &result.attempts {
        assert_ne!(receipt.purpose, AttemptPurpose::Ordinary);
        assert_eq!(receipt.knownness, AccountingKnownness::Known);
        assert_eq!(receipt.totals.cost_microcents, Some(17));
        assert_eq!(receipt.usage.unwrap().input_tokens, 11);
    }
}

#[test]
fn manual_completed_tool_history_applies_exact_closed_pair_and_private_full_archive() {
    isolated!("manual_completed_tool_history_applies_exact_closed_pair_and_private_full_archive");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
    let mut source = vec![
        ChatMessage {
            role: ChatRole::System,
            ..orbit_engine::user_message("exact immutable system")
        },
        orbit_engine::user_message(format!("{}OLD-VISIBLE-LATE", "u".repeat(4000))),
    ];
    let mut call = orbit_engine::assistant_message("visible old action");
    call.tool_calls = Some(vec![ToolCallMessage {
        id: "old-call".into(),
        name: "inspect".into(),
        arguments: format!("{{\"path\":\"{}OLD-ARGS-LATE\"}}", "a".repeat(900)),
    }]);
    source.push(call);
    let mut result = orbit_engine::user_message("unused tool fallback");
    result.role = ChatRole::Tool;
    result.tool_call_id = Some("old-call".into());
    result.tool_result = Some(format!("{}OLD-RESULT-LATE", "r".repeat(900)));
    source.push(result);
    let mut done = orbit_engine::assistant_message("visible old completion");
    done.blocks = Some(vec![ContentBlock::Opaque {
        json: json!({"type":"thinking","thinking":HIDDEN,"signature":"private-original-signature"})
            .to_string(),
    }]);
    done.origin_provider = Some("foreign".into());
    done.origin_model = Some("foreign".into());
    source.push(done);
    source.extend(history(3, 1800));
    let original = source.clone();
    let (completion, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert_eq!(completion.status, CompactionStatus::PublishedReady);
    assert!(completion.applied);
    assert_eq!(source[0], original[0]);
    assert_eq!(
        source[1],
        orbit_engine::user_message("[Earlier conversation summary: historical data]")
    );
    assert_eq!(source[2], orbit_engine::assistant_message(SUMMARY));
    assert!(original.ends_with(&source[3..]));
    assert_eq!(&source[source.len() - 4..], &original[original.len() - 4..]);
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].source, original);
    assert_eq!(archives[0].candidate, source);
    assert_eq!(archives[0].attempts, completion.attempts);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let projected = requests[0].body["messages"].to_string();
    for marker in ["OLD-VISIBLE-LATE", "OLD-ARGS-LATE", "OLD-RESULT-LATE"] {
        assert_eq!(projected.matches(marker).count(), 1);
    }
    assert!(!projected.contains(HIDDEN));
    assert_eq!(requests[0].body["reasoning_effort"], "high");
    drop(requests);
    assert_paid(&completion, &journal, 1);
    assert_ids(&home, &journal, 1);
    assert_summary_requests(&fixture, 12_000, 1);
    assert_transport(&fixture);
    assert_private_manual_events(&events, true);
}

#[test]
fn manual_empty_and_system_only_are_local_noops_without_journal_or_provider() {
    isolated!("manual_empty_and_system_only_are_local_noops_without_journal_or_provider");
    let (home, mut fixture, journal, selected, mut options) = setup(
        vec![Response::complete(SUMMARY), Response::complete(SUMMARY)],
        1000,
        12_000,
    );
    options.journal = None;
    for mut source in [
        vec![],
        vec![ChatMessage {
            role: ChatRole::System,
            ..orbit_engine::user_message("system only")
        }],
    ] {
        let original = source.clone();
        let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
        assert_eq!(result.status, CompactionStatus::NothingToCompact);
        assert!(!result.applied);
        assert!(result.attempts.is_empty());
        assert_eq!(result.accounting, compaction::AccountingDelta::known_zero());
        assert_eq!(source, original);
        assert_private_manual_events(&events, false);
    }
    fixture.finish();
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(journal.intents().is_empty() && journal.archives().is_empty());
}

#[test]
fn manual_malformed_nonempty_is_refused_without_turn_or_network() {
    isolated!("manual_malformed_nonempty_is_refused_without_turn_or_network");
    let (home, mut fixture, journal, selected, options) = setup(
        vec![Response::complete(SUMMARY), Response::complete(SUMMARY)],
        1000,
        12_000,
    );
    let mut orphan = orbit_engine::user_message("orphan result");
    orphan.role = ChatRole::Tool;
    orphan.tool_call_id = Some("missing".into());
    orphan.tool_result = Some("exact result".into());
    for mut source in [
        vec![orbit_engine::assistant_message("assistant only")],
        vec![orbit_engine::user_message("task"), orphan],
    ] {
        let original = source.clone();
        let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
        assert_eq!(result.status, CompactionStatus::InvalidHistory);
        assert!(!result.applied);
        assert_eq!(source, original);
        assert!(result.attempts.is_empty());
        assert_private_manual_events(&events, false);
    }
    fixture.finish();
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(journal.intents().is_empty());
}

#[test]
fn manual_fitting_complete_history_keeps_exact_source_and_counters() {
    isolated!("manual_fitting_complete_history_keeps_exact_source_and_counters");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::complete(SUMMARY)], 10_000, 12_000);
    let mut source = history(0, 0);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::NothingToCompact);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert!(result.attempts.is_empty());
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert_eq!(journal.accounting_checkpoint().unwrap().revision.0, 0);
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_summary_own_budget_refuses_before_any_summary_or_application() {
    isolated!("manual_summary_own_budget_refuses_before_any_summary_or_application");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 1);
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::SummaryTooLarge);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert!(result.attempts.is_empty());
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(journal.intents().is_empty());
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_nonempty_without_journal_is_a_zero_post_refusal() {
    isolated!("manual_nonempty_without_journal_is_a_zero_post_refusal");
    let (home, mut fixture, journal, selected, mut options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
    options.journal = None;
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::MissingJournal);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert!(result.attempts.is_empty());
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(journal.intents().is_empty());
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_length_empty_filtered_and_ineffective_summaries_keep_original_and_paid_bill() {
    isolated!("manual_length_empty_filtered_and_ineffective_summaries_keep_original_and_paid_bill");
    for (summary, reason) in [
        ("incomplete length", "length"),
        ("", "stop"),
        (" \n\t", "stop"),
        ("filtered", "content_filter"),
        (&"oversized ".repeat(2000), "stop"),
    ] {
        let (home, mut fixture, journal, selected, options) = setup(
            vec![Response::text(
                summary,
                reason,
                Some(json!({"prompt_tokens":11,"completion_tokens":7})),
            )],
            1000,
            12_000,
        );
        let mut source = history(3, 1800);
        let original = source.clone();
        let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
        fixture.finish();
        assert!(!result.applied);
        assert_ne!(result.status, CompactionStatus::PublishedReady);
        assert_eq!(source, original);
        assert!(journal.archives().is_empty());
        assert_paid(&result, &journal, 1);
        assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        assert_ids(&home, &journal, 1);
        assert_private_manual_events(&events, false);
    }
}

#[test]
fn manual_truncated_summary_retains_uncertain_receipt_and_blocks_another_dispatch() {
    isolated!("manual_truncated_summary_retains_uncertain_receipt_and_blocks_another_dispatch");
    let event = json!({"choices":[{"index":0,"delta":{"content":"private unfinished summary"},"finish_reason":null}]});
    let (home, mut fixture, journal, selected, options) = setup(
        vec![
            Response {
                body: format!("data: {event}\n\n"),
                pause: false,
            },
            Response::complete(SUMMARY),
        ],
        1000,
        12_000,
    );
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    assert!(!result.applied);
    assert_eq!(source, original);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.attempts[0].knownness, AccountingKnownness::Uncertain);
    assert_eq!(result.attempts[0].totals.cost_microcents, None);
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert!(checkpoint.pending.as_ref().unwrap().uncertain);
    let (second, _) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(!second.applied && second.attempts.is_empty());
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(journal.accounting_checkpoint().unwrap(), checkpoint);
    assert!(journal.archives().is_empty());
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("private unfinished summary")
    );
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_summary_tool_lifecycle_is_billed_but_never_applied_or_executed() {
    isolated!("manual_summary_tool_lifecycle_is_billed_but_never_applied_or_executed");
    let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"forbidden","type":"function","function":{"name":"Write","arguments":"{\"file_path\":\"must-not-exist\",\"content\":\"no\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7}});
    let (home, mut fixture, journal, selected, options) = setup(
        vec![Response {
            body: format!("data: {event}\n\ndata: [DONE]\n\n"),
            pause: false,
        }],
        1000,
        12_000,
    );
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::SummaryUnusable);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert_paid(&result, &journal, 1);
    assert!(!result.attempts[0].completed);
    assert!(!home.0.join("must-not-exist").exists());
    assert!(journal.archives().is_empty());
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert_summary_requests(&fixture, 12_000, 1);
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_known_unpriced_summary_applies_with_unknown_price_not_free_bill() {
    isolated!("manual_known_unpriced_summary_applies_with_unknown_price_not_free_bill");
    let (home, mut fixture, journal, selected, mut options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
    let compaction = options.compaction_config.as_mut().unwrap();
    compaction.pricing = None;
    compaction.billing = None;
    let mut source = history(3, 1800);
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(result.applied);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.attempts[0].knownness, AccountingKnownness::Known);
    assert_eq!(result.attempts[0].totals.cost_microcents, None);
    assert_eq!(result.accounting.housekeeping.input_tokens, 11);
    assert_eq!(result.accounting.housekeeping.cost_microcents, None);
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert_private_manual_events(&events, true);
}

#[test]
fn manual_precancel_and_cancel_inside_begin_have_distinct_zero_post_accounting() {
    isolated!("manual_precancel_and_cancel_inside_begin_have_distinct_zero_post_accounting");
    for inside_begin in [false, true] {
        let (home, mut fixture, journal, selected, options) =
            setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
        let cancel = CancelToken::new();
        if inside_begin {
            journal.cancel_after_begin(cancel.clone());
        } else {
            cancel.cancel();
        }
        let mut source = history(3, 1800);
        let original = source.clone();
        let (result, events) = invoke(&home, &selected, &options, &mut source, &cancel);
        fixture.finish();
        assert_eq!(result.status, CompactionStatus::Cancelled);
        assert!(!result.applied);
        assert_eq!(source, original);
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert!(journal.archives().is_empty());
        assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
        if inside_begin {
            assert_eq!(result.attempts.len(), 1);
            let receipt = &result.attempts[0];
            assert_eq!(receipt.knownness, AccountingKnownness::Known);
            assert!(!receipt.completed);
            assert!(receipt.usage.is_none());
            assert_eq!(receipt.totals, compaction::AccountingTotals::known_zero());
        } else {
            assert!(result.attempts.is_empty());
            assert!(journal.intents().is_empty());
        }
        assert_private_manual_events(&events, false);
    }
}

#[test]
fn manual_cancel_after_captured_post_before_headers_is_uncertain_and_preserves_source() {
    isolated!("manual_cancel_after_captured_post_before_headers_is_uncertain_and_preserves_source");
    let (home, old_fixture, journal, mut selected, mut options) = setup(vec![], 1000, 12_000);
    drop(old_fixture);
    let mut fixture = Fixture::with_held_headers(vec![], true);
    selected.gate = fixture.url.clone();
    options = options_for_new_endpoint(&home, &fixture, &journal, &selected, options);
    let cancel = CancelToken::new();
    let signal = cancel.clone();
    let captured = fixture.requests.clone();
    let cancelling = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(3);
        while captured.lock().unwrap().is_empty() {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
        signal.cancel();
    });
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &cancel);
    cancelling.join().unwrap();
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::Cancelled);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.attempts[0].knownness, AccountingKnownness::Uncertain);
    assert_eq!(result.attempts[0].totals.cost_microcents, None);
    assert!(
        journal
            .accounting_checkpoint()
            .unwrap()
            .pending
            .unwrap()
            .uncertain
    );
    assert!(journal.archives().is_empty());
    assert_ids(&home, &journal, 1);
    assert_private_manual_events(&events, false);
}

fn options_for_new_endpoint(
    home: &Home,
    fixture: &Fixture,
    journal: &Arc<MemoryJournal>,
    selected: &TurnConfig,
    mut options: TurnOptions,
) -> TurnOptions {
    let summary = config(fixture, true);
    let store = orbit_adapter::provider_credentials::ProviderCredentialStore::new(&home.0).unwrap();
    for (config, key) in [
        (selected, "synthetic-manual-main-key"),
        (&summary, "synthetic-manual-summary-key"),
    ] {
        let identity = orbit_adapter::provider_credentials::ProviderAuthIdentity::new(
            &config.provider_id,
            "openai-compatible",
            &config.gate,
            config.credential_env.as_deref(),
        )
        .unwrap();
        store
            .save(
                &identity,
                orbit_adapter::SecretBytes::new(key.as_bytes().to_vec()),
                orbit_adapter::provider_credentials::ExpectedRevision::Absent,
            )
            .unwrap();
    }
    options.selected_budget =
        Some(orbit_engine::context_budget::SelectedBudget::legacy_input(selected, 1000).unwrap());
    options.compaction_budget =
        Some(orbit_engine::context_budget::SelectedBudget::legacy_input(&summary, 12_000).unwrap());
    options.compaction_config = Some(summary);
    options.journal = Some(journal.clone());
    options
}

#[test]
fn manual_cancel_after_publication_retains_only_inert_orphan_and_paid_charge() {
    isolated!("manual_cancel_after_publication_retains_only_inert_orphan_and_paid_charge");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
    let cancel = CancelToken::new();
    journal.cancel_after_publication(cancel.clone());
    let mut source = history(3, 1800);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &cancel);
    fixture.finish();
    assert_eq!(result.status, CompactionStatus::Cancelled);
    assert!(!result.applied);
    assert_eq!(source, original);
    assert_paid(&result, &journal, 1);
    let archives = journal.archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].source, original);
    assert_ne!(archives[0].candidate, source);
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_checked_storage_failures_never_replace_original_or_erase_paid_attempt() {
    isolated!("manual_checked_storage_failures_never_replace_original_or_erase_paid_attempt");
    for failure in [
        Failure::Capacity,
        Failure::Namespace,
        Failure::Begin,
        Failure::Settle,
        Failure::Publish,
        Failure::PublishUncertain,
    ] {
        let (home, mut fixture, journal, selected, options) =
            setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
        journal.fail(failure);
        let mut source = history(3, 1800);
        let original = source.clone();
        let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
        fixture.finish();
        assert!(!result.applied);
        assert_eq!(source, original);
        assert_ne!(result.status, CompactionStatus::PublishedReady);
        assert!(journal.archives().is_empty());
        let dispatched = matches!(
            failure,
            Failure::Settle | Failure::Publish | Failure::PublishUncertain
        );
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            usize::from(dispatched)
        );
        assert_eq!(result.attempts.len(), usize::from(dispatched));
        if dispatched {
            assert_eq!(result.attempts[0].totals.cost_microcents, Some(17));
        }
        assert_private_manual_events(&events, false);
    }
}

#[test]
fn manual_two_bounded_chunks_merge_once_without_ordinary_request() {
    isolated!("manual_two_bounded_chunks_merge_once_without_ordinary_request");
    let (home, mut fixture, journal, selected, options) = setup(
        vec![
            Response::complete("CHUNK-A-REPLY"),
            Response::complete("CHUNK-B-REPLY"),
            Response::complete(SUMMARY),
        ],
        1000,
        2000,
    );
    let mut source = history(2, 2400);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(result.applied);
    assert_eq!(result.status, CompactionStatus::PublishedReady);
    assert_eq!(
        result
            .attempts
            .iter()
            .map(|r| r.purpose)
            .collect::<Vec<_>>(),
        [
            AttemptPurpose::Chunk,
            AttemptPurpose::Chunk,
            AttemptPurpose::Merge
        ]
    );
    assert_paid(&result, &journal, 3);
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    assert_summary_requests(&fixture, 2000, 3);
    assert_eq!(journal.archives()[0].source, original);
    assert_eq!(journal.archives()[0].candidate, source);
    assert_ids(&home, &journal, 3);
    assert_private_manual_events(&events, true);
}

#[test]
fn manual_positive_missing_usage_keeps_unknown_usage_and_never_invents_a_free_bill() {
    isolated!("manual_positive_missing_usage_keeps_unknown_usage_and_never_invents_a_free_bill");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::text(SUMMARY, "stop", None)], 1000, 12_000);
    let mut source = history(3, 1800);
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(result.applied);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(
        result.attempts[0].knownness,
        AccountingKnownness::UnknownUsage
    );
    assert_eq!(result.attempts[0].totals.cost_microcents, None);
    assert_eq!(result.accounting.housekeeping.input_tokens, 0);
    assert_eq!(result.accounting.housekeeping.output_tokens, 0);
    assert_eq!(result.accounting.housekeeping.cost_microcents, None);
    assert_eq!(
        result.accounting.knownness,
        AccountingKnownness::UnknownUsage
    );
    assert!(journal.accounting_checkpoint().unwrap().pending.is_none());
    assert_private_manual_events(&events, true);
}

#[test]
fn manual_paid_chunks_then_truncated_merge_preserve_each_known_charge_and_original() {
    isolated!("manual_paid_chunks_then_truncated_merge_preserve_each_known_charge_and_original");
    let event = json!({"choices":[{"index":0,"delta":{"content":"private partial merge"},"finish_reason":null}]});
    let (home, mut fixture, journal, selected, options) = setup(
        vec![
            Response::complete("CHUNK-A-REPLY"),
            Response::complete("CHUNK-B-REPLY"),
            Response {
                body: format!("data: {event}\n\n"),
                pause: false,
            },
        ],
        1000,
        2000,
    );
    let mut source = history(2, 2400);
    let original = source.clone();
    let (result, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(!result.applied);
    assert_eq!(source, original);
    assert_eq!(result.attempts.len(), 3);
    assert_eq!(
        result
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
    assert_eq!(result.attempts[0].totals.cost_microcents, Some(17));
    assert_eq!(result.attempts[1].totals.cost_microcents, Some(17));
    assert_eq!(result.attempts[2].knownness, AccountingKnownness::Uncertain);
    assert_eq!(result.accounting.housekeeping.input_tokens, 22);
    assert_eq!(result.accounting.housekeeping.output_tokens, 14);
    assert_eq!(result.accounting.housekeeping.cost_microcents, None);
    let checkpoint = journal.accounting_checkpoint().unwrap();
    assert_eq!(
        checkpoint
            .known_priced_subtotals
            .unwrap()
            .housekeeping_microcents,
        34
    );
    assert_eq!(
        checkpoint.pending.unwrap().intent.purpose,
        AttemptPurpose::Merge
    );
    assert!(journal.archives().is_empty());
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    assert_ids(&home, &journal, 3);
    assert_private_manual_events(&events, false);
}

#[test]
fn manual_tool_ending_current_group_retains_exact_anchor_calls_and_results() {
    isolated!("manual_tool_ending_current_group_retains_exact_anchor_calls_and_results");
    let (home, mut fixture, journal, selected, options) =
        setup(vec![Response::complete(SUMMARY)], 1000, 12_000);
    let mut source = history(3, 1800);
    source.pop();
    let mut call = orbit_engine::assistant_message("exact current call");
    call.tool_calls = Some(vec![ToolCallMessage {
        id: "current-call".into(),
        name: "inspect".into(),
        arguments: "{\"path\":\"exact\"}".into(),
    }]);
    source.push(call);
    let mut result = orbit_engine::user_message("fallback");
    result.role = ChatRole::Tool;
    result.tool_call_id = Some("current-call".into());
    result.tool_result = Some("exact current tool result λ".into());
    source.push(result);
    let original = source.clone();
    let tail = original[original.len() - 3..].to_vec();
    let (completion, events) = invoke(&home, &selected, &options, &mut source, &CancelToken::new());
    fixture.finish();
    assert!(completion.applied);
    assert!(source.ends_with(&tail));
    assert_eq!(
        source
            .iter()
            .filter(|message| message.content == tail[0].content)
            .count(),
        1
    );
    assert_eq!(journal.archives()[0].source, original);
    assert_paid(&completion, &journal, 1);
    assert_private_manual_events(&events, true);
}
