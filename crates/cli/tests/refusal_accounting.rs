#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole, CostRates, ProviderUsage};
use orbit_cli::context_history::{
    InspectionQualification, context_journal, inspect_accounting_detailed,
};
use orbit_cli::session_accounting::{
    AccountingError, ChildOrigin, FullCostStatus, NamespaceAccounting, NamespaceSpendPolicy,
    RootOrigin, prepare_child, prepare_root,
};
use orbit_cli::sessions::{SessionFile, SessionLease};
use orbit_engine::agent_store::{AgentStatus, AgentStore};
use orbit_engine::compaction::{
    AccountingBaseline, AccountingCheckpoint, AccountingKnownness, AccountingRevision,
    AccountingTotals, AttemptIntent, AttemptPurpose, AttemptRef, CompactionCandidate,
    CompactionJournal, CompactionReceipt, CompactionRecordRef, HistoryError, KnownPricedSubtotals,
    RequestAccountingReceipt,
};
use orbit_engine::retry::{
    DetailedAccountingCheckpoint, DetailedLastSettlement, FinalRejectionContract,
    FinalRejectionPolicy, FinalRejectionSelector, OrdinaryAttemptBinding,
    OrdinaryAttemptBindingRecord, RefusalRecord, RefusedOrdinarySettlement, RefusedSettlementAck,
    RetryPolicyBinding, adapter_identity_digest,
};
use orbit_engine::turn::{RetryTurnCompletion, run_turn_detailed_with_retry_policy};
use orbit_engine::{
    PendingToolCall, ProviderKind, SpendAllowance, ToolExecutor, ToolRoundResult, TurnConfig,
    TurnEnd, TurnOptions,
};
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
    mpsc,
};
use std::time::{Duration, Instant};

const OWNER: &str = "refusal-storage-owner";
const PROMPT: &str = "continue this exact controlled task λ";
const ANSWER: &str = "controlled ordinary answer";
const MAX_REQUESTS: usize = 4;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_TRACE: usize = 64;
const SNAPSHOT_LIMIT: u64 = 131072;
const CHANNEL_WAIT: Duration = Duration::from_secs(3);

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

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_ISOLATED").as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_RUNNER_DEPTH").as_deref(),
            Ok("1")
        );
        require_private_system_fixture();
        let path =
            std::env::temp_dir().join(format!("orbit-refusal-storage-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn lease(&self) -> SessionLease {
        SessionLease::acquire(&self.0, OWNER, "refusal-fixture").unwrap()
    }
    fn owner(&self) -> PathBuf {
        self.0.join("context-history").join(OWNER)
    }
    fn bytes(&self) -> Vec<u8> {
        let path = self.owner().join("accounting.json");
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= SNAPSHOT_LIMIT);
        fs::read(path).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn snapshot(config: &TurnConfig) -> SessionFile {
    SessionFile::from_chat(
        OWNER,
        &config.model,
        &config.gate,
        &config.provider_id,
        &[],
        0,
        0,
        0,
        0,
    )
}
fn usage() -> ProviderUsage {
    ProviderUsage {
        input_tokens: 11,
        output_tokens: 7,
        cache_read_tokens: 3,
        cache_write_tokens: 0,
        reasoning_tokens: 5,
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    extra_length: usize,
    body_gate: Option<AckWait>,
}
impl Reply {
    fn rejection(status: u16, bytes: usize) -> Self {
        Self {
            status,
            body: vec![b'x'; bytes],
            extra_length: 0,
            body_gate: None,
        }
    }
    fn success() -> Self {
        Self { status: 200, body: format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"index":0,"delta":{"content":ANSWER},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})).into_bytes(), extra_length: 0, body_gate: None }
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
            body_gate: None,
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
    barrier: mpsc::Sender<mpsc::SyncSender<usize>>,
    probe: Arc<Mutex<Option<Arc<ObservedJournal>>>>,
    thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
    watchdog_thread: Option<std::thread::JoinHandle<()>>,
}
impl Wire {
    fn new(replies: Vec<Reply>) -> Self {
        assert!(replies.len() <= MAX_REQUESTS);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/tenant/v1?scope=refusal-storage");
        let captures = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = captures.clone();
        let accepted = connections.clone();
        let stopping = stop.clone();
        let (barrier, barriers) = mpsc::channel::<mpsc::SyncSender<usize>>();
        let probe: Arc<Mutex<Option<Arc<ObservedJournal>>>> = Arc::new(Mutex::new(None));
        let wire_probe = probe.clone();
        let (watchdog, receive) = std::sync::mpsc::channel();
        let watchdog_thread = std::thread::spawn(move || {
            if matches!(
                receive.recv_timeout(Duration::from_secs(25)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("refusal storage owned fixture watchdog");
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
                        if accepted.fetch_add(1, Ordering::SeqCst) >= MAX_REQUESTS {
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
                        if let Some(journal) = wire_probe.lock().map_err(|_| "probe lock")?.clone()
                        {
                            journal.observe_post()?;
                        }
                        let reply = replies.next().ok_or("unexpected replay")?;
                        let content_type = if reply.status == 200 {
                            "text/event-stream"
                        } else {
                            "application/json"
                        };
                        let length = reply.body.len() + reply.extra_length;
                        write!(socket, "HTTP/1.1 {} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n", reply.status).map_err(|_| "header write")?;
                        if let Some(gate) = reply.body_gate {
                            let prefix = reply.body.len().saturating_sub(1);
                            socket
                                .write_all(&reply.body[..prefix])
                                .map_err(|_| "held prefix write")?;
                            socket.flush().map_err(|_| "held prefix flush")?;
                            gate.held.send(()).map_err(|_| "held body notice")?;
                            gate.release
                                .recv_timeout(CHANNEL_WAIT)
                                .map_err(|_| "held body release")?;
                            // Deliberately never transmit the missing final byte.
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
                        while let Ok(reply) = barriers.try_recv() {
                            reply
                                .send(accepted.load(Ordering::SeqCst))
                                .map_err(|_| "barrier receiver")?;
                        }
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
            barrier,
            probe,
            thread: Some(thread),
            watchdog: Some(watchdog),
            watchdog_thread: Some(watchdog_thread),
        }
    }
    fn arm(&self, journal: &Arc<ObservedJournal>) {
        *self.probe.lock().unwrap() = Some(journal.clone());
    }
    fn barrier(&self) -> usize {
        let (send, receive) = mpsc::sync_channel(1);
        self.barrier.send(send).unwrap();
        receive
            .recv_timeout(CHANNEL_WAIT)
            .expect("listener did not acknowledge its poll")
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
        provider_id: "fixture-provider".into(),
        gate: wire.url.clone(),
        model: "fixture/raw".into(),
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
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Plain,
    HoldAck,
    LostAck(bool),
    DisplaceOwner(bool),
    CancelBegin(usize),
    CancelRefusalEntry,
}
#[derive(Clone)]
struct BeginObservation {
    before: DetailedAccountingCheckpoint,
    intent: AttemptIntent,
    binding: Option<OrdinaryAttemptBindingRecord>,
    reference: AttemptRef,
}
#[derive(Default)]
struct Observations {
    calls: Vec<&'static str>,
    begins: Vec<BeginObservation>,
    receipts: Vec<RequestAccountingReceipt>,
    refusals: Vec<RefusalRecord>,
    acknowledgements: Vec<DetailedAccountingCheckpoint>,
    layout_error: Option<HistoryError>,
    pending_before_layout: Option<Vec<u8>>,
}
struct AckWait {
    held: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
struct AckControl {
    held: mpsc::Receiver<()>,
    release: mpsc::SyncSender<()>,
    cancel: CancelToken,
}
impl AckControl {
    fn wait(&self) {
        self.held
            .recv_timeout(CHANNEL_WAIT)
            .expect("actual inner ACK not observed");
    }
    fn release(&self) {
        self.release.try_send(()).unwrap();
    }
}
impl Drop for AckControl {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.release.try_send(());
    }
}
struct ObservedJournal {
    inner: Arc<dyn CompactionJournal>,
    home: PathBuf,
    child: Option<String>,
    budget: orbit_engine::context_budget::BudgetIdentity,
    mode: Mode,
    cancel: CancelToken,
    observations: Mutex<Observations>,
    gate: Mutex<Option<AckWait>>,
    inner_ack: AtomicBool,
    released: AtomicBool,
    retries: AtomicUsize,
}
impl std::fmt::Debug for ObservedJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservedJournal { real checked storage }")
    }
}
impl ObservedJournal {
    fn new(
        home: &Home,
        child: Option<&str>,
        inner: Arc<dyn CompactionJournal>,
        budget: orbit_engine::context_budget::BudgetIdentity,
        mode: Mode,
        cancel: &CancelToken,
    ) -> (Arc<Self>, Option<AckControl>) {
        let (gate, control) = if mode == Mode::HoldAck {
            let (held, held_rx) = mpsc::sync_channel(1);
            let (release_tx, release) = mpsc::sync_channel(1);
            (
                Some(AckWait { held, release }),
                Some(AckControl {
                    held: held_rx,
                    release: release_tx,
                    cancel: cancel.clone(),
                }),
            )
        } else {
            (None, None)
        };
        (
            Arc::new(Self {
                inner,
                home: home.0.clone(),
                child: child.map(str::to_owned),
                budget,
                mode,
                cancel: cancel.clone(),
                observations: Mutex::new(Observations::default()),
                gate: Mutex::new(gate),
                inner_ack: AtomicBool::new(false),
                released: AtomicBool::new(false),
                retries: AtomicUsize::new(0),
            }),
            control,
        )
    }
    fn record(&self, call: &'static str) {
        let mut trace = self.observations.lock().unwrap();
        assert!(trace.calls.len() < MAX_TRACE);
        trace.calls.push(call);
    }
    fn counts(&self) -> (usize, usize, usize) {
        let trace = self.observations.lock().unwrap();
        (
            trace.begins.len(),
            trace.receipts.len(),
            trace
                .calls
                .iter()
                .filter(|call| **call == "refusal")
                .count(),
        )
    }
    fn snapshot(&self) -> DetailedAccountingCheckpoint {
        self.inner.accounting_checkpoint_detailed().unwrap()
    }
    fn observe_post(&self) -> Result<(), &'static str> {
        let checkpoint = self
            .inner
            .accounting_checkpoint_detailed()
            .map_err(|_| "wire checkpoint")?;
        let trace = self.observations.lock().map_err(|_| "wire trace")?;
        let begin = trace.begins.last().ok_or("POST before real begin")?;
        let pending = checkpoint
            .pending()
            .ok_or("POST without real pending attempt")?;
        if pending.reference != begin.reference
            || pending.intent != begin.intent
            || pending.uncertain
        {
            return Err("POST/pending identity differs");
        }
        if self.mode == Mode::HoldAck
            && trace.begins.len() > 1
            && (!self.inner_ack.load(Ordering::SeqCst) || !self.released.load(Ordering::SeqCst))
        {
            return Err("second POST before actual ACK release");
        }
        Ok(())
    }
    fn assert_only_detailed(&self) {
        let trace = self.observations.lock().unwrap();
        assert!(!trace.calls.iter().any(|name| name.starts_with("legacy")));
    }
}
// Each operation delegates once to the same actual production journal. The
// observer stores arguments and returned values; it implements no transitions.
impl CompactionJournal for ObservedJournal {
    fn check_archive_capacity(&self, bytes: u64) -> Result<(), HistoryError> {
        self.record("capacity");
        self.inner.check_archive_capacity(bytes)
    }
    fn publish(
        &self,
        source: &[ChatMessage],
        candidate: &CompactionCandidate,
        receipt: &CompactionReceipt,
    ) -> Result<CompactionRecordRef, HistoryError> {
        self.record("publish");
        self.inner.publish(source, candidate, receipt)
    }
    fn initialize_accounting(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.record("legacy initialize");
        self.inner.initialize_accounting(baseline)
    }
    fn accounting_checkpoint(&self) -> Result<AccountingCheckpoint, HistoryError> {
        self.record("legacy checkpoint");
        self.inner.accounting_checkpoint()
    }
    fn begin_attempt(
        &self,
        revision: AccountingRevision,
        intent: &AttemptIntent,
    ) -> Result<AttemptRef, HistoryError> {
        self.record("legacy begin");
        self.inner.begin_attempt(revision, intent)
    }
    fn settle_attempt(
        &self,
        reference: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<AccountingCheckpoint, HistoryError> {
        self.record("legacy settle");
        self.inner.settle_attempt(reference, receipt)
    }
    fn initialize_accounting_detailed(
        &self,
        baseline: AccountingBaseline,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        self.record("initialize");
        self.inner.initialize_accounting_detailed(baseline)
    }
    fn accounting_checkpoint_detailed(&self) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        self.record("checkpoint");
        self.inner.accounting_checkpoint_detailed()
    }
    fn begin_attempt_detailed(
        &self,
        revision: AccountingRevision,
        intent: &AttemptIntent,
        binding: Option<&OrdinaryAttemptBinding>,
    ) -> Result<AttemptRef, HistoryError> {
        self.record("begin");
        let before = self.inner.accounting_checkpoint_detailed()?;
        assert_eq!(intent.owner_session_id, OWNER);
        assert_eq!(intent.child_id.as_deref(), self.child.as_deref());
        assert_eq!(intent.purpose, AttemptPurpose::Ordinary);
        assert_eq!(intent.budget, self.budget);
        assert_eq!(before.revision(), revision);
        let reference = self
            .inner
            .begin_attempt_detailed(revision, intent, binding)?;
        let ordinal = {
            let mut trace = self.observations.lock().unwrap();
            assert!(trace.begins.len() < MAX_REQUESTS);
            trace.begins.push(BeginObservation {
                before,
                intent: intent.clone(),
                binding: binding.map(OrdinaryAttemptBinding::to_record),
                reference: reference.clone(),
            });
            trace.begins.len()
        };
        if self.mode == Mode::CancelBegin(ordinal) {
            self.cancel.cancel();
        }
        Ok(reference)
    }
    fn settle_attempt_detailed(
        &self,
        reference: &AttemptRef,
        receipt: &RequestAccountingReceipt,
    ) -> Result<DetailedAccountingCheckpoint, HistoryError> {
        self.record("normal");
        {
            let mut trace = self.observations.lock().unwrap();
            assert!(trace.receipts.len() < MAX_REQUESTS);
            trace.receipts.push(receipt.clone());
        }
        self.inner.settle_attempt_detailed(reference, receipt)
    }
    fn settle_refused_ordinary(
        &self,
        reference: &AttemptRef,
        settlement: &RefusedOrdinarySettlement,
    ) -> Result<RefusedSettlementAck, HistoryError> {
        self.record("refusal");
        if self.mode == Mode::CancelRefusalEntry || self.mode == Mode::DisplaceOwner(true) {
            self.cancel.cancel();
        }
        if matches!(self.mode, Mode::DisplaceOwner(_)) {
            let original = bounded_bytes(
                &self
                    .home
                    .join("context-history")
                    .join(OWNER)
                    .join("accounting.json"),
            );
            let mut displacement = DisplacedOwner::new(&self.home);
            let result = self.inner.settle_refused_ordinary(reference, settlement);
            assert!(matches!(result, Err(HistoryError::Unsafe)));
            displacement.restore();
            assert_eq!(
                bounded_bytes(
                    &self
                        .home
                        .join("context-history")
                        .join(OWNER)
                        .join("accounting.json")
                ),
                original
            );
            let mut trace = self.observations.lock().unwrap();
            trace.layout_error = Some(HistoryError::Unsafe);
            trace.pending_before_layout = Some(original);
            return result;
        }
        let before = {
            let trace = self.observations.lock().unwrap();
            trace
                .begins
                .iter()
                .find(|begin| &begin.reference == reference)
                .unwrap()
                .before
                .clone()
        };
        let ack = self.inner.settle_refused_ordinary(reference, settlement)?;
        ack.validate_for(settlement, &before)?;
        let inspected = inspect_accounting_detailed(&self.home, OWNER, self.child.as_deref())?;
        assert_eq!(
            inspected.qualification,
            InspectionQualification::VisibleValidated
        );
        assert_eq!(ack.checkpoint(), &inspected.checkpoint);
        assert!(inspected.pending_receipt.is_none());
        assert_eq!(ack.attempt(), reference);
        assert_eq!(ack.binding(), settlement.binding());
        assert_eq!(ack.settlement_digest(), settlement.digest());
        assert_eq!(ack.observation_digest(), settlement.observation_digest());
        assert_eq!(ack.policy_digest(), settlement.policy_digest());
        {
            let mut trace = self.observations.lock().unwrap();
            assert!(trace.refusals.len() < MAX_REQUESTS);
            trace.refusals.push(settlement.to_record());
            trace.acknowledgements.push(ack.checkpoint().clone());
        }
        self.inner_ack.store(true, Ordering::SeqCst);
        if let Mode::LostAck(cancel) = self.mode {
            if cancel {
                self.cancel.cancel();
            }
            return Err(HistoryError::Uncertain);
        }
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.held.send(()).unwrap();
            gate.release
                .recv_timeout(CHANNEL_WAIT)
                .expect("actual ACK not released");
            self.released.store(true, Ordering::SeqCst);
        }
        Ok(ack)
    }
}
fn bounded_bytes(path: &Path) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.nlink(), 1);
    assert!(metadata.len() <= SNAPSHOT_LIMIT);
    fs::read(path).unwrap()
}
fn checked_identity(path: &Path) -> Result<(u64, u64), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "owned directory metadata missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o777 != 0o700 {
        return Err("owned directory metadata changed");
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn identity(path: &Path) -> (u64, u64) {
    checked_identity(path).unwrap()
}
// This owns exactly the original directory and two create-only replacements.
// It exercises the real path anchor guard, not a simulated fsync failure.
struct DisplacedOwner {
    original: PathBuf,
    retained: PathBuf,
    original_identity: (u64, u64),
    replacement_identity: Option<(u64, u64)>,
    archive_identity: Option<(u64, u64)>,
    displaced: bool,
    restored: bool,
}
impl DisplacedOwner {
    fn new(home: &Path) -> Self {
        let original = home.join("context-history").join(OWNER);
        let original_identity = identity(&original);
        let retained = home.join(format!("retained-owner-{}", ulid::Ulid::new()));
        assert!(!retained.exists());
        // Install the guard before the first mutation so subsequent assertion
        // failures restore the original rather than abandoning its identity.
        let mut guard = Self {
            original,
            retained,
            original_identity,
            replacement_identity: None,
            archive_identity: None,
            displaced: false,
            restored: false,
        };
        fs::rename(&guard.original, &guard.retained).unwrap();
        guard.displaced = true;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&guard.original)
            .unwrap();
        guard.replacement_identity = Some(identity(&guard.original));
        let archives = guard.original.join("archives");
        fs::DirBuilder::new().mode(0o700).create(&archives).unwrap();
        guard.archive_identity = Some(identity(&archives));
        guard
    }
    fn restore_inner(&mut self) -> Result<(), &'static str> {
        if self.restored || !self.displaced {
            return Ok(());
        }
        if checked_identity(&self.retained)? != self.original_identity {
            return Err("retained owner identity changed");
        }
        if let Some(expected) = self.replacement_identity {
            if checked_identity(&self.original)? != expected {
                return Err("replacement owner identity changed");
            }
            if let Some(expected) = self.archive_identity {
                if checked_identity(&self.original.join("archives"))? != expected {
                    return Err("replacement archive identity changed");
                }
                fs::remove_dir(self.original.join("archives"))
                    .map_err(|_| "replacement archive not empty")?;
                self.archive_identity = None;
            }
            fs::remove_dir(&self.original).map_err(|_| "replacement owner not empty")?;
            self.replacement_identity = None;
        } else if self
            .original
            .try_exists()
            .map_err(|_| "replacement owner lookup")?
        {
            return Err("unowned replacement owner exists");
        }
        fs::rename(&self.retained, &self.original).map_err(|_| "original restore")?;
        if checked_identity(&self.original)? != self.original_identity {
            return Err("restored identity differs");
        }
        self.restored = true;
        Ok(())
    }
    fn restore(&mut self) {
        self.restore_inner().expect("owned layout restore failed");
    }
}
impl Drop for DisplacedOwner {
    fn drop(&mut self) {
        let restored = self.restore_inner();
        if !std::thread::panicking() {
            restored.expect("owned layout cleanup failed");
        }
    }
}
fn base_options(config: &TurnConfig, session: &str, ceiling: u32) -> TurnOptions {
    TurnOptions {
        session_id: session.into(),
        request_stem: "refusal-storage".into(),
        max_attempts: ceiling,
        max_rounds: 1,
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(config, 8000).unwrap(),
        ),
        system_directive: Some("Use the exact controlled intent.".into()),
        ..Default::default()
    }
}
#[allow(clippy::too_many_arguments)]
fn managed_options(
    home: &Home,
    namespace: &NamespaceAccounting,
    config: &TurnConfig,
    session: &str,
    child: Option<&str>,
    ceiling: u32,
    policy: Option<&RetryPolicyBinding>,
    mode: Mode,
    cancel: &CancelToken,
) -> (TurnOptions, Arc<ObservedJournal>, Option<AckControl>) {
    let mut options = base_options(config, session, ceiling);
    namespace
        .apply_options_detailed(&mut options, None, policy)
        .unwrap();
    let inner = options.journal.take().unwrap();
    let (journal, gate) = ObservedJournal::new(
        home,
        child,
        inner,
        options.selected_budget.as_ref().unwrap().identity.clone(),
        mode,
        cancel,
    );
    options.journal = Some(journal.clone());
    (options, journal, gate)
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
    journal: &ObservedJournal,
    prompt: &str,
    transcript: &mut Vec<ChatMessage>,
    cancel: &CancelToken,
    policy: Option<&RetryPolicyBinding>,
    cancel_on_retry: bool,
) -> (RetryTurnCompletion, Vec<FrontendEvent>) {
    let mut events = Vec::new();
    let mut executor = Executor::default();
    let result = run_turn_detailed_with_retry_policy(
        &home.0,
        config,
        options,
        prompt,
        transcript,
        &mut executor,
        cancel,
        &mut |event| {
            assert!(events.len() < 256, "event bound");
            if matches!(event, FrontendEvent::Retrying { .. }) {
                if journal.mode == Mode::HoldAck {
                    assert!(journal.released.load(Ordering::SeqCst));
                }
                journal.retries.fetch_add(1, Ordering::SeqCst);
                if cancel_on_retry {
                    cancel.cancel();
                }
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
    journal.assert_only_detailed();
    (result, events)
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
            "POST /tenant/v1/chat/completions?scope=refusal-storage HTTP/1.1"
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
        assert_eq!(body["max_tokens"], 73);
        assert!(body["model"].as_str().unwrap().starts_with("fixture/"));
    }
}
fn inspect(
    home: &Home,
    child: Option<&str>,
) -> orbit_cli::context_history::DetailedAccountingInspection {
    let before = home.bytes();
    let value = inspect_accounting_detailed(&home.0, OWNER, child).unwrap();
    assert_eq!(
        value.qualification,
        InspectionQualification::VisibleValidated
    );
    assert_eq!(home.bytes(), before);
    value
}
fn assert_unknown_bill(
    checkpoint: &DetailedAccountingCheckpoint,
    measured: u64,
    refusals: u64,
    revision: u64,
) {
    assert_eq!(checkpoint.owner_session_id(), OWNER);
    assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
    assert_eq!(checkpoint.revision(), AccountingRevision(revision));
    assert!(checkpoint.pending().is_none());
    assert_eq!(
        checkpoint.totals().knownness,
        AccountingKnownness::UnknownUsage
    );
    assert_eq!(
        checkpoint.totals().ordinary,
        AccountingTotals {
            input_tokens: measured * 11,
            output_tokens: measured * 7,
            cost_microcents: None
        }
    );
    assert_eq!(
        checkpoint.totals().housekeeping,
        AccountingTotals::known_zero()
    );
    assert_eq!(
        checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: measured * 13,
            housekeeping_microcents: 0
        })
    );
    assert_eq!(checkpoint.refusals().unwrap().count(), refusals);
}
fn assert_ledger(home: &Home, session: &str, journals: &[&ObservedJournal], posts: usize) {
    let actual: Vec<_> = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0
        .into_iter()
        .filter_map(|entry| match entry.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, session);
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect();
    let expected: Vec<_> = journals
        .iter()
        .flat_map(|journal| {
            journal
                .observations
                .lock()
                .unwrap()
                .begins
                .iter()
                .map(|begin| {
                    if let Some(binding) = &begin.binding {
                        assert_eq!(binding.request_id(), begin.intent.request_id);
                        assert_eq!(begin.intent.owner_session_id, OWNER);
                        assert_eq!(begin.intent.child_id.as_deref(), journal.child.as_deref());
                        binding.decision_id().to_owned()
                    } else {
                        begin.intent.request_id.clone()
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();
    // For this route the prepared request uses one fresh ID for its request,
    // decision and attempt fields. No ID is claimed to be a wire header.
    assert_eq!(actual.len(), posts);
    assert_eq!(actual, expected);
}
#[allow(clippy::too_many_arguments)]
fn assert_positive(
    home: &Home,
    wire: &Wire,
    journal: &ObservedJournal,
    result: &RetryTurnCompletion,
    events: &[FrontendEvent],
    transcript: &[ChatMessage],
    child: Option<&str>,
) {
    assert_wire(wire, 2);
    assert!(matches!(result.completion().end, TurnEnd::Completed));
    assert_eq!(retries(events), 1);
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
    let trace = journal.observations.lock().unwrap();
    let first = trace.begins[0].binding.as_ref().unwrap();
    let second = trace.begins[1].binding.as_ref().unwrap();
    first.validate().unwrap();
    second.validate().unwrap();
    assert_ne!(first.request_id(), second.request_id());
    assert_ne!(first.decision_id(), second.decision_id());
    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_eq!(first.body_digest(), second.body_digest());
    assert_eq!(first.route_digest(), second.route_digest());
    assert_eq!(first.policy_digest(), second.policy_digest());
    assert_eq!(result.refusals(), trace.refusals.as_slice());
    assert_eq!(trace.acknowledgements.len(), 1);
    assert_eq!(trace.acknowledgements[0].revision(), AccountingRevision(2));
    assert_eq!(trace.receipts[0].usage, Some(usage()));
    assert_eq!(trace.receipts[0].request_id, second.request_id());
    assert!(trace.receipts[0].completed);
    let expected_receipt = trace.receipts[0].clone();
    let expected_refusal = trace.refusals[0].clone();
    let second_reference = trace.begins[1].reference.clone();
    drop(trace);
    assert_ledger(home, child.unwrap_or(OWNER), &[journal], 2);
    let captures = wire.captures.lock().unwrap();
    assert_eq!(captures[0].target, captures[1].target);
    assert_eq!(captures[0].body, captures[1].body);
    let body: Value = serde_json::from_slice(&captures[0].body).unwrap();
    assert_eq!(body["model"], "fixture/raw");
    assert_eq!(
        body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "user" && message["content"] == PROMPT)
            .count(),
        1
    );
    drop(captures);
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
    assert_eq!(
        report.attempts.as_slice(),
        std::slice::from_ref(&expected_receipt)
    );
    assert_eq!(
        report.accounting.knownness,
        AccountingKnownness::UnknownUsage
    );
    assert_eq!(
        report.accounting.ordinary,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: None
        }
    );
    let checkpoint = journal.snapshot();
    assert_unknown_bill(&checkpoint, 1, 1, 4);
    assert_eq!(checkpoint.child_id(), child);
    assert_eq!(checkpoint.totals(), &report.accounting);
    assert_eq!(checkpoint.refusals().unwrap().latest(), &expected_refusal);
    assert!(
        matches!(checkpoint.last_settlement(), Some(DetailedLastSettlement::Legacy(last)) if last.reference == second_reference)
    );
    let visible = inspect(home, child);
    assert_eq!(visible.checkpoint, checkpoint);
    assert!(visible.pending_receipt.is_none());
    assert_eq!(visible.last_legacy_receipt, Some(expected_receipt));
    let bytes = home.bytes();
    let reopened = context_journal(&home.0, OWNER, child).unwrap();
    assert_eq!(
        reopened.accounting_checkpoint_detailed().unwrap(),
        checkpoint
    );
    assert_eq!(home.bytes(), bytes);
}

#[test]
fn qualified_retry_waits_for_real_durable_ack_before_second_post() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 17), Reply::success()]);
    let selected = config(&wire);
    let lease = home.lease();
    let mut current = snapshot(&selected);
    let root = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let cancel = CancelToken::new();
    let policy = policy(&selected, 2);
    let (options, journal, control) = managed_options(
        &home,
        root.namespace(),
        &selected,
        OWNER,
        None,
        2,
        Some(&policy),
        Mode::HoldAck,
        &cancel,
    );
    wire.arm(&journal);
    let mut transcript = Vec::new();
    let (result, events) = std::thread::scope(|scope| {
        // This drop guard releases/cancels before the scoped worker is joined,
        // including assertion failures in the controller.
        let control = control.unwrap();
        let worker = scope.spawn(|| {
            invoke(
                &home,
                &selected,
                &options,
                &journal,
                PROMPT,
                &mut transcript,
                &cancel,
                Some(&policy),
                false,
            )
        });
        control.wait();
        assert!(journal.inner_ack.load(Ordering::SeqCst));
        assert!(!journal.released.load(Ordering::SeqCst));
        assert_eq!(journal.counts(), (1, 0, 1));
        assert_eq!(journal.retries.load(Ordering::SeqCst), 0);
        let saved = inspect(&home, None);
        assert_unknown_bill(&saved.checkpoint, 0, 1, 2);
        assert!(matches!(
            saved.checkpoint.last_settlement(),
            Some(DetailedLastSettlement::FinalRefusal(_))
        ));
        assert_eq!(wire.barrier(), 1);
        assert_eq!(journal.counts(), (1, 0, 1));
        assert_eq!(journal.retries.load(Ordering::SeqCst), 0);
        assert!(!worker.is_finished());
        control.release();
        let joined = worker.join().unwrap();
        drop(control);
        joined
    });
    wire.finish();
    assert_positive(&home, &wire, &journal, &result, &events, &transcript, None);
    current.transcript = transcript;
    current.turns += 1;
    let view = root.persist(&lease, &mut current).unwrap();
    assert_eq!(view.full_cost_status, FullCostStatus::UnknownUsage);
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (11, 7, 13)
    );
    let saved = lease.load().unwrap();
    assert_eq!(saved.turns, 1);
    assert_eq!(
        saved.accounting_watermark.unwrap().full_cost_status,
        FullCostStatus::UnknownUsage
    );
}
struct Managed {
    options: TurnOptions,
    journal: Arc<ObservedJournal>,
    control: Option<AckControl>,
    root: orbit_cli::session_accounting::RootSessionAccounting,
    current: SessionFile,
    lease: SessionLease,
    selected: TurnConfig,
    policy: Option<RetryPolicyBinding>,
    cancel: CancelToken,
    wire: Wire,
    home: Home,
}
impl Managed {
    fn new(replies: Vec<Reply>, mode: Mode, ceiling: u32, qualified: bool) -> Self {
        let home = Home::new();
        let wire = Wire::new(replies);
        let selected = config(&wire);
        let lease = home.lease();
        let mut current = snapshot(&selected);
        let root = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
        let cancel = CancelToken::new();
        let policy = qualified.then(|| policy(&selected, 2));
        let (options, journal, control) = managed_options(
            &home,
            root.namespace(),
            &selected,
            OWNER,
            None,
            ceiling,
            policy.as_ref(),
            mode,
            &cancel,
        );
        wire.arm(&journal);
        Self {
            options,
            journal,
            control,
            root,
            current,
            lease,
            selected,
            policy,
            cancel,
            wire,
            home,
        }
    }
    fn run(
        &mut self,
        cancel_on_retry: bool,
    ) -> (RetryTurnCompletion, Vec<FrontendEvent>, Vec<ChatMessage>) {
        let mut transcript = Vec::new();
        let (result, events) = invoke(
            &self.home,
            &self.selected,
            &self.options,
            &self.journal,
            PROMPT,
            &mut transcript,
            &self.cancel,
            self.policy.as_ref(),
            cancel_on_retry,
        );
        (result, events, transcript)
    }
    fn persist(&mut self, transcript: Vec<ChatMessage>) {
        self.current.transcript = transcript;
        self.current.turns += 1;
        self.root.persist(&self.lease, &mut self.current).unwrap();
    }
}
fn assert_uncertain(
    home: &Home,
    journal: &ObservedJournal,
    result: &RetryTurnCompletion,
    events: &[FrontendEvent],
) {
    assert!(result.refusals().is_empty());
    assert_eq!(retries(events), 0);
    assert_eq!(journal.counts(), (1, 1, 0));
    let trace = journal.observations.lock().unwrap();
    assert_eq!(trace.receipts[0].knownness, AccountingKnownness::Uncertain);
    assert_eq!(trace.receipts[0].totals.cost_microcents, None);
    let receipt = trace.receipts[0].clone();
    drop(trace);
    let checkpoint = journal.snapshot();
    assert!(checkpoint.pending().unwrap().uncertain);
    assert!(checkpoint.refusals().is_none());
    assert_eq!(
        checkpoint.totals().knownness,
        AccountingKnownness::Uncertain
    );
    assert_eq!(checkpoint.totals().ordinary.cost_microcents, None);
    let visible = inspect(home, None);
    assert_eq!(visible.checkpoint, checkpoint);
    assert_eq!(visible.pending_receipt, Some(receipt));
    assert!(visible.last_legacy_receipt.is_none());
    let before = home.bytes();
    assert_eq!(
        context_journal(&home.0, OWNER, None)
            .unwrap()
            .accounting_checkpoint_detailed()
            .unwrap(),
        checkpoint
    );
    assert_eq!(home.bytes(), before);
}

#[test]
fn qualified_child_retry_preserves_owner_and_stable_child_scope() {
    let home = Home::new();
    let mut wire = Wire::new(vec![Reply::rejection(503, 17), Reply::success()]);
    let selected = config(&wire);
    let lease = home.lease();
    let mut current = snapshot(&selected);
    let root = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
    let owner_before = root.namespace().checkpoint_detailed().unwrap();
    let store = AgentStore::new(&home.0, OWNER).unwrap();
    let created = store
        .create(
            "explorer",
            Some("controlled child"),
            "fixture-provider/fixture/raw",
            None,
        )
        .unwrap();
    let run = store.begin(&created.agent_id, None).unwrap();
    assert!(store.begin(&created.agent_id, None).is_err());
    let namespace = prepare_child(&home.0, &run, ChildOrigin::CreatedThisInvocation).unwrap();
    let policy = policy(&selected, 2);
    let cancel = CancelToken::new();
    let (options, journal, gate) = managed_options(
        &home,
        &namespace,
        &selected,
        &created.agent_id,
        Some(&created.agent_id),
        2,
        Some(&policy),
        Mode::Plain,
        &cancel,
    );
    assert!(gate.is_none());
    wire.arm(&journal);
    let mut transcript = Vec::new();
    let (result, events) = invoke(
        &home,
        &selected,
        &options,
        &journal,
        PROMPT,
        &mut transcript,
        &cancel,
        Some(&policy),
        false,
    );
    wire.finish();
    assert_positive(
        &home,
        &wire,
        &journal,
        &result,
        &events,
        &transcript,
        Some(&created.agent_id),
    );
    let accepted = namespace.checkpoint_detailed().unwrap();
    assert_eq!(
        root.namespace().checkpoint_detailed().unwrap(),
        owner_before
    );
    assert!(prepare_child(&home.0, &run, ChildOrigin::CreatedThisInvocation).is_err());
    let finished = run
        .finish(transcript, ANSWER.into(), AgentStatus::Completed, 1)
        .unwrap();
    assert_eq!(finished.owner_session_id, OWNER);
    assert_eq!(finished.agent_id, created.agent_id);
    assert_eq!(finished.turns, 1);
    drop(options);
    drop(journal);
    drop(namespace);
    let bytes = home.bytes();
    let resumed_run = store.begin(&created.agent_id, None).unwrap();
    let resumed = prepare_child(&home.0, &resumed_run, ChildOrigin::Resumed).unwrap();
    assert_eq!(resumed.checkpoint_detailed().unwrap(), accepted);
    assert_eq!(home.bytes(), bytes);
    assert_eq!(
        root.namespace().checkpoint_detailed().unwrap(),
        owner_before
    );
    let mut wrong_scope = base_options(&selected, OWNER, 2);
    assert!(
        resumed
            .apply_options_detailed(&mut wrong_scope, None, Some(&policy))
            .is_err()
    );
    assert!(wrong_scope.journal.is_none());
    resumed_run
        .finish(
            finished.transcript,
            ANSWER.into(),
            AgentStatus::Completed,
            1,
        )
        .unwrap();
    let view = root.reconcile(&mut current).unwrap();
    assert_eq!(
        (
            view.input_tokens,
            view.output_tokens,
            view.known_cost_microcents
        ),
        (0, 0, 0)
    );
    assert_eq!(view.full_cost_status, FullCostStatus::Known);
}

#[test]
fn lost_real_ack_stops_without_replay_or_second_settlement() {
    for racing_cancel in [false, true] {
        let mut fixture = Managed::new(
            vec![Reply::rejection(503, 17)],
            Mode::LostAck(racing_cancel),
            2,
            true,
        );
        let (result, events, _) = fixture.run(false);
        assert_eq!(fixture.wire.barrier(), 1);
        fixture.wire.finish();
        assert_wire(&fixture.wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert!(result.refusals().is_empty());
        assert!(result.completion().report.attempts.is_empty());
        assert_eq!(
            result.completion().report.accounting.knownness,
            AccountingKnownness::Uncertain
        );
        assert_eq!(
            result
                .completion()
                .report
                .accounting
                .ordinary
                .cost_microcents,
            None
        );
        assert_eq!(retries(&events), 0);
        assert_eq!(fixture.journal.counts(), (1, 0, 1));
        assert!(fixture.journal.inner_ack.load(Ordering::SeqCst));
        let checkpoint = fixture.journal.snapshot();
        assert_unknown_bill(&checkpoint, 0, 1, 2);
        let trace = fixture.journal.observations.lock().unwrap();
        assert_eq!(
            trace.acknowledgements.as_slice(),
            std::slice::from_ref(&checkpoint)
        );
        assert_eq!(checkpoint.refusals().unwrap().latest(), &trace.refusals[0]);
        drop(trace);
        let visible = inspect(&fixture.home, None);
        assert_eq!(visible.checkpoint, checkpoint);
        assert!(visible.pending_receipt.is_none());
        assert!(visible.last_legacy_receipt.is_none());
        let before = fixture.home.bytes();
        assert_eq!(
            context_journal(&fixture.home.0, OWNER, None)
                .unwrap()
                .accounting_checkpoint_detailed()
                .unwrap(),
            checkpoint
        );
        assert_eq!(fixture.home.bytes(), before);
        assert_ledger(&fixture.home, OWNER, &[&fixture.journal], 1);
    }
}

#[test]
fn real_owned_layout_failure_stops_without_replay_or_second_settlement() {
    for racing_cancel in [false, true] {
        let mut fixture = Managed::new(
            vec![Reply::rejection(503, 17)],
            Mode::DisplaceOwner(racing_cancel),
            2,
            true,
        );
        let owner_identity = identity(&fixture.home.owner());
        let (result, events, _) = fixture.run(false);
        assert_eq!(fixture.wire.barrier(), 1);
        fixture.wire.finish();
        assert_wire(&fixture.wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert!(result.refusals().is_empty());
        assert!(result.completion().report.attempts.is_empty());
        assert_eq!(
            result.completion().report.accounting.knownness,
            AccountingKnownness::Uncertain
        );
        assert_eq!(
            result
                .completion()
                .report
                .accounting
                .ordinary
                .cost_microcents,
            None
        );
        assert_eq!(retries(&events), 0);
        assert_eq!(fixture.journal.counts(), (1, 0, 1));
        assert!(!fixture.journal.inner_ack.load(Ordering::SeqCst));
        assert_eq!(identity(&fixture.home.owner()), owner_identity);
        assert!(!fs::read_dir(&fixture.home.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("retained-owner-")
        }));
        let trace = fixture.journal.observations.lock().unwrap();
        assert_eq!(trace.layout_error, Some(HistoryError::Unsafe));
        assert!(trace.acknowledgements.is_empty());
        assert!(trace.refusals.is_empty());
        assert_eq!(
            fixture.home.bytes(),
            *trace.pending_before_layout.as_ref().unwrap()
        );
        drop(trace);
        let visible = inspect(&fixture.home, None);
        assert_eq!(visible.checkpoint.revision(), AccountingRevision(1));
        let pending = visible.checkpoint.pending().unwrap();
        assert!(!pending.uncertain);
        assert_eq!(
            pending.reference,
            fixture.journal.observations.lock().unwrap().begins[0].reference
        );
        assert!(visible.checkpoint.refusals().is_none());
        assert!(visible.pending_receipt.is_none());
        let mut blocked = base_options(&fixture.selected, OWNER, 2);
        assert!(
            fixture
                .root
                .namespace()
                .apply_options_detailed(&mut blocked, None, fixture.policy.as_ref())
                .is_err()
        );
        assert!(blocked.journal.is_none());
        assert_ledger(&fixture.home, OWNER, &[&fixture.journal], 1);
    }
}
#[test]
fn explicit_new_invocations_use_current_policy_without_replaying_refused_intent() {
    for qualified_again in [false, true] {
        let home = Home::new();
        let mut replies = vec![Reply::rejection(503, 17), Reply::success()];
        if qualified_again {
            replies.push(Reply::rejection(503, 17));
        }
        replies.push(Reply::success());
        let mut wire = Wire::new(replies);
        let selected = config(&wire);
        let lease = home.lease();
        let mut current = snapshot(&selected);
        let root = prepare_root(&lease, &mut current, RootOrigin::FreshCandidate).unwrap();
        let first_cancel = CancelToken::new();
        let first_policy = policy(&selected, 2);
        let (first_options, first_journal, _) = managed_options(
            &home,
            root.namespace(),
            &selected,
            OWNER,
            None,
            2,
            Some(&first_policy),
            Mode::Plain,
            &first_cancel,
        );
        wire.arm(&first_journal);
        let mut transcript = Vec::new();
        let (first, _) = invoke(
            &home,
            &selected,
            &first_options,
            &first_journal,
            PROMPT,
            &mut transcript,
            &first_cancel,
            Some(&first_policy),
            false,
        );
        assert!(matches!(first.completion().end, TurnEnd::Completed));
        let historical = first_journal.snapshot().refusals().cloned().unwrap();
        let historical_decisions: Vec<_> = first_journal
            .observations
            .lock()
            .unwrap()
            .begins
            .iter()
            .map(|begin| begin.binding.as_ref().unwrap().decision_id().to_owned())
            .collect();
        current.transcript = transcript;
        current.turns += 1;
        let first_view = root.persist(&lease, &mut current).unwrap();
        assert_eq!(first_view.full_cost_status, FullCostStatus::UnknownUsage);
        let saved_bytes = home.bytes();
        drop(first_options);
        drop(first_journal);
        drop(root);
        drop(lease);

        let lease = home.lease();
        let mut current = lease.load().unwrap();
        assert_eq!(current.turns, 1);
        let root = prepare_root(&lease, &mut current, RootOrigin::RestoredOrLegacy).unwrap();
        assert_eq!(home.bytes(), saved_bytes);
        assert_eq!(
            root.namespace().checkpoint_detailed().unwrap().refusals(),
            Some(&historical)
        );
        let mut next_config = selected.clone();
        next_config.provider_id = "fixture-provider-changed".into();
        next_config.model = "fixture/changed".into();
        let next_policy = qualified_again.then(|| policy(&next_config, 2));
        if let Some(value) = &next_policy {
            assert_ne!(value.policy_digest(), first_policy.policy_digest());
            assert_ne!(value.provider_digest(), first_policy.provider_digest());
            assert_ne!(value.model_digest(), first_policy.model_digest());
        }
        let next_cancel = CancelToken::new();
        let (next_options, next_journal, _) = managed_options(
            &home,
            root.namespace(),
            &next_config,
            OWNER,
            None,
            2,
            next_policy.as_ref(),
            Mode::Plain,
            &next_cancel,
        );
        wire.arm(&next_journal);
        let mut next_transcript = current.to_transcript();
        let new_prompt = "new explicit controlled prompt after restart";
        let (second, events) = invoke(
            &home,
            &next_config,
            &next_options,
            &next_journal,
            new_prompt,
            &mut next_transcript,
            &next_cancel,
            next_policy.as_ref(),
            false,
        );
        assert!(matches!(second.completion().end, TurnEnd::Completed));
        assert_eq!(second.refusals().len(), usize::from(qualified_again));
        assert_eq!(retries(&events), usize::from(qualified_again));
        let report = &second.completion().report;
        assert_eq!(
            (
                report.input_tokens,
                report.output_tokens,
                report.cost_microcents
            ),
            (11, 7, 13)
        );
        assert_eq!(report.rounds, 1);
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].usage, Some(usage()));
        assert_eq!(
            report.accounting.knownness,
            if qualified_again {
                AccountingKnownness::UnknownUsage
            } else {
                AccountingKnownness::Known
            }
        );
        assert_eq!(
            report.accounting.ordinary.cost_microcents,
            if qualified_again { None } else { Some(13) }
        );
        assert_eq!(
            next_transcript
                .iter()
                .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
                .count(),
            1
        );
        assert_eq!(
            next_transcript
                .iter()
                .filter(|message| message.role == ChatRole::User && message.content == new_prompt)
                .count(),
            1
        );
        let trace = next_journal.observations.lock().unwrap();
        assert!(
            trace
                .begins
                .iter()
                .all(|begin| begin.binding.is_some() == qualified_again)
        );
        assert!(
            trace
                .begins
                .iter()
                .all(|begin| !historical_decisions.contains(&begin.intent.request_id))
        );
        let next_decisions: Vec<_> = trace
            .begins
            .iter()
            .map(|begin| begin.intent.request_id.clone())
            .collect();
        drop(trace);
        let checkpoint = next_journal.snapshot();
        assert_unknown_bill(
            &checkpoint,
            2,
            if qualified_again { 2 } else { 1 },
            if qualified_again { 8 } else { 6 },
        );
        if qualified_again {
            assert_ne!(
                checkpoint.refusals().unwrap().latest().attempt(),
                historical.latest().attempt()
            );
            assert_eq!(
                second.refusals(),
                &[checkpoint.refusals().unwrap().latest().clone()]
            );
        } else {
            assert_eq!(checkpoint.refusals(), Some(&historical));
        }
        current.transcript = next_transcript;
        current.turns += 1;
        current.provider = next_config.provider_id.clone();
        current.model = next_config.model.clone();
        let view = root.persist(&lease, &mut current).unwrap();
        assert_eq!(view.full_cost_status, FullCostStatus::UnknownUsage);
        assert_eq!(
            (
                view.input_tokens,
                view.output_tokens,
                view.known_cost_microcents
            ),
            (22, 14, 26)
        );
        assert_eq!(lease.load().unwrap().turns, 2);
        let count = if qualified_again { 4 } else { 3 };
        assert_eq!(wire.barrier(), count);
        wire.finish();
        assert_wire(&wire, count);
        let captures = wire.captures.lock().unwrap();
        for capture in &captures[2..] {
            let body: Value = serde_json::from_slice(&capture.body).unwrap();
            assert_eq!(body["model"], "fixture/changed");
            let messages = body["messages"].as_array().unwrap();
            let users: Vec<_> = messages
                .iter()
                .filter(|message| message["role"] == "user")
                .collect();
            assert_eq!(users.last().unwrap()["content"], new_prompt);
            assert_eq!(
                users
                    .iter()
                    .filter(|message| message["content"] == PROMPT)
                    .count(),
                1
            );
        }
        if qualified_again {
            assert_eq!(captures[2].body, captures[3].body);
        }
        drop(captures);
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
        assert_eq!(
            actual,
            historical_decisions
                .into_iter()
                .chain(next_decisions)
                .collect::<Vec<_>>()
        );
        let bytes = home.bytes();
        assert_eq!(inspect(&home, None).checkpoint, checkpoint);
        assert_eq!(home.bytes(), bytes);
    }
}

#[test]
fn historical_refusal_caps_refuse_before_any_new_traffic() {
    let mut fixture = Managed::new(
        vec![Reply::rejection(503, 17), Reply::success()],
        Mode::Plain,
        2,
        true,
    );
    let (first, _, transcript) = fixture.run(false);
    assert!(matches!(first.completion().end, TurnEnd::Completed));
    fixture.persist(transcript);
    let before = fixture.home.bytes();
    let counts = fixture.journal.counts();
    for namespace_cap in [false, true] {
        for allow_housekeeping in [false, true] {
            for qualified in [false, true] {
                let mut capped = base_options(&fixture.selected, OWNER, 2);
                capped.journal = Some(fixture.journal.clone());
                let namespace_policy = namespace_cap.then_some(NamespaceSpendPolicy {
                    maximum_microcents: 1000,
                    allow_unpriced_housekeeping: allow_housekeeping,
                });
                if !namespace_cap {
                    capped.spend_allowance = Some(SpendAllowance {
                        remaining_microcents: 1000,
                        allow_unpriced_housekeeping: allow_housekeeping,
                    });
                }
                let original_journal = capped.journal.clone().unwrap();
                let original_allowance = capped.spend_allowance;
                assert!(matches!(
                    fixture.root.namespace().apply_options_detailed(
                        &mut capped,
                        namespace_policy,
                        if qualified {
                            fixture.policy.as_ref()
                        } else {
                            None
                        }
                    ),
                    Err(AccountingError::SpendRefused(_))
                ));
                assert!(Arc::ptr_eq(
                    capped.journal.as_ref().unwrap(),
                    &original_journal
                ));
                assert_eq!(capped.spend_allowance, original_allowance);
                assert_eq!(capped.max_attempts, 2);
                assert_eq!(fixture.home.bytes(), before);
            }
        }
    }
    // The public engine also rejects a capped qualified invocation when a
    // caller bypasses namespace option resolution entirely.
    let mut direct = fixture.options.clone();
    direct.spend_allowance = Some(SpendAllowance {
        remaining_microcents: 1000,
        allow_unpriced_housekeeping: true,
    });
    let mut transcript = Vec::new();
    let (result, events) = invoke(
        &fixture.home,
        &fixture.selected,
        &direct,
        &fixture.journal,
        "new capped prompt",
        &mut transcript,
        &fixture.cancel,
        fixture.policy.as_ref(),
        false,
    );
    assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
    assert!(result.refusals().is_empty());
    assert_eq!(retries(&events), 0);
    assert!(transcript.is_empty());
    assert_eq!(fixture.journal.counts(), counts);
    assert_eq!(fixture.home.bytes(), before);
    assert_eq!(fixture.wire.barrier(), 2);
    fixture.wire.finish();
    assert_wire(&fixture.wire, 2);
}

#[test]
fn no_policy_complete_rejection_uses_one_detailed_uncertain_settlement() {
    let mut fixture = Managed::new(vec![Reply::rejection(503, 17)], Mode::Plain, 2, false);
    let (result, events, transcript) = fixture.run(false);
    assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
    assert_uncertain(&fixture.home, &fixture.journal, &result, &events);
    assert!(
        fixture.journal.observations.lock().unwrap().begins[0]
            .binding
            .is_none()
    );
    assert_eq!(fixture.wire.barrier(), 1);
    assert_wire(&fixture.wire, 1);
    fixture.persist(transcript);
    let before = fixture.home.bytes();
    let inspection_before = inspect(&fixture.home, None);
    let saved_path = fixture
        .home
        .0
        .join("sessions")
        .join(format!("{OWNER}.json"));
    let saved_before = bounded_bytes(&saved_path);
    let Managed {
        options,
        journal,
        root,
        current: _,
        lease,
        home,
        mut wire,
        selected: _,
        policy: _,
        cancel: _,
        control: _,
    } = fixture;
    drop(options);
    drop(journal);
    drop(root);
    drop(lease);
    let lease = home.lease();
    let mut restored = lease.load().unwrap();
    assert_eq!(
        restored
            .accounting_watermark
            .as_ref()
            .unwrap()
            .full_cost_status,
        FullCostStatus::Uncertain
    );
    let candidate_before = serde_json::to_value(&restored).unwrap();
    assert!(matches!(
        prepare_root(&lease, &mut restored, RootOrigin::RestoredOrLegacy),
        Err(AccountingError::InvalidState(
            "a pending uncertain request requires explicit inspection before admission"
        ))
    ));
    assert_eq!(serde_json::to_value(&restored).unwrap(), candidate_before);
    assert_eq!(home.bytes(), before);
    assert_eq!(bounded_bytes(&saved_path), saved_before);
    let inspection_after = inspect(&home, None);
    assert_eq!(inspection_after, inspection_before);
    assert!(inspection_after.checkpoint.pending().unwrap().uncertain);
    assert!(inspection_after.checkpoint.refusals().is_none());
    let pending_receipt = inspection_after.pending_receipt.unwrap();
    assert_eq!(pending_receipt.knownness, AccountingKnownness::Uncertain);
    assert_eq!(pending_receipt.totals.cost_microcents, None);
    assert_eq!(wire.barrier(), 1);
    wire.finish();
    assert_wire(&wire, 1);
}

#[test]
fn zero_and_one_attempt_ceilings_are_never_raised_by_policy() {
    for ceiling in [0, 1] {
        let replies = if ceiling == 0 {
            vec![]
        } else {
            vec![Reply::rejection(503, 17)]
        };
        let mut fixture = Managed::new(replies, Mode::Plain, ceiling, true);
        let before = fixture.home.bytes();
        let (result, events, _) = fixture.run(false);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert_eq!(retries(&events), 0);
        assert_eq!(fixture.wire.barrier(), ceiling as usize);
        fixture.wire.finish();
        assert_wire(&fixture.wire, ceiling as usize);
        if ceiling == 0 {
            assert_eq!(fixture.journal.counts(), (0, 0, 0));
            assert!(result.refusals().is_empty());
            assert_eq!(fixture.home.bytes(), before);
        } else {
            assert_eq!(fixture.journal.counts(), (1, 0, 1));
            assert_eq!(result.refusals().len(), 1);
            let checkpoint = fixture.journal.snapshot();
            assert_unknown_bill(&checkpoint, 0, 1, 2);
            assert_eq!(
                checkpoint.refusals().unwrap().latest(),
                &result.refusals()[0]
            );
            assert!(matches!(
                checkpoint.last_settlement(),
                Some(DetailedLastSettlement::FinalRefusal(_))
            ));
        }
    }
}
#[test]
fn pre_begin_and_post_begin_cancellation_never_send_or_invent_refusal() {
    for before_begin in [false, true] {
        let mut fixture = Managed::new(
            vec![],
            if before_begin {
                Mode::Plain
            } else {
                Mode::CancelBegin(1)
            },
            2,
            true,
        );
        let before = fixture.home.bytes();
        if before_begin {
            fixture.cancel.cancel();
        }
        let (result, events, _) = fixture.run(false);
        assert!(matches!(result.completion().end, TurnEnd::Cancelled));
        assert!(result.refusals().is_empty());
        assert_eq!(retries(&events), 0);
        assert_eq!(fixture.wire.barrier(), 0);
        fixture.wire.finish();
        assert_wire(&fixture.wire, 0);
        let checkpoint = fixture.journal.snapshot();
        assert!(checkpoint.pending().is_none());
        assert!(checkpoint.refusals().is_none());
        assert_eq!(checkpoint.totals().knownness, AccountingKnownness::Known);
        assert_eq!(checkpoint.totals().ordinary, AccountingTotals::known_zero());
        assert_eq!(
            checkpoint.known_priced_subtotals(),
            Some(KnownPricedSubtotals::known_zero())
        );
        if before_begin {
            assert_eq!(fixture.journal.counts(), (0, 0, 0));
            assert_eq!(fixture.home.bytes(), before);
        } else {
            assert_eq!(fixture.journal.counts(), (1, 1, 0));
            assert_eq!(checkpoint.revision(), AccountingRevision(2));
            let trace = fixture.journal.observations.lock().unwrap();
            let receipt = &trace.receipts[0];
            assert_eq!(receipt.knownness, AccountingKnownness::Known);
            assert!(!receipt.completed);
            assert!(receipt.usage.is_none());
            assert_eq!(receipt.totals, AccountingTotals::known_zero());
            let inspected = inspect(&fixture.home, None);
            assert_eq!(inspected.last_legacy_receipt.as_ref(), Some(receipt));
            assert_eq!(
                result.completion().report.attempts.as_slice(),
                std::slice::from_ref(receipt)
            );
        }
    }
}

#[test]
fn cancellation_before_complete_rejection_observation_remains_uncertain() {
    let (held, notice) = mpsc::sync_channel(1);
    let (release, resumed) = mpsc::sync_channel(1);
    let mut reply = Reply::rejection(503, 17);
    reply.body_gate = Some(AckWait {
        held,
        release: resumed,
    });
    let mut fixture = Managed::new(vec![reply], Mode::Plain, 2, true);
    let control = AckControl {
        held: notice,
        release,
        cancel: fixture.cancel.clone(),
    };
    let (result, events, _) = std::thread::scope(|scope| {
        let control = control;
        let worker = scope.spawn(|| {
            let mut transcript = Vec::new();
            let (result, events) = invoke(
                &fixture.home,
                &fixture.selected,
                &fixture.options,
                &fixture.journal,
                PROMPT,
                &mut transcript,
                &fixture.cancel,
                fixture.policy.as_ref(),
                false,
            );
            (result, events, transcript)
        });
        control.wait();
        fixture.cancel.cancel();
        let joined = worker.join().unwrap();
        control.release();
        drop(control);
        joined
    });
    fixture.wire.finish();
    assert_wire(&fixture.wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert_uncertain(&fixture.home, &fixture.journal, &result, &events);
}

#[test]
fn cancellation_after_live_proof_finishes_exactly_one_real_settlement() {
    for hold_actual_ack in [false, true] {
        let mut fixture = Managed::new(
            vec![Reply::rejection(503, 17)],
            if hold_actual_ack {
                Mode::HoldAck
            } else {
                Mode::CancelRefusalEntry
            },
            2,
            true,
        );
        let (result, events, _) = if hold_actual_ack {
            let control = fixture.control.take().unwrap();
            std::thread::scope(|scope| {
                let control = control;
                let worker = scope.spawn(|| {
                    let mut transcript = Vec::new();
                    let (result, events) = invoke(
                        &fixture.home,
                        &fixture.selected,
                        &fixture.options,
                        &fixture.journal,
                        PROMPT,
                        &mut transcript,
                        &fixture.cancel,
                        fixture.policy.as_ref(),
                        false,
                    );
                    (result, events, transcript)
                });
                control.wait();
                assert!(fixture.journal.inner_ack.load(Ordering::SeqCst));
                assert!(!fixture.journal.released.load(Ordering::SeqCst));
                assert_unknown_bill(&inspect(&fixture.home, None).checkpoint, 0, 1, 2);
                assert_eq!(fixture.wire.barrier(), 1);
                assert_eq!(fixture.journal.counts(), (1, 0, 1));
                assert_eq!(fixture.journal.retries.load(Ordering::SeqCst), 0);
                fixture.cancel.cancel();
                control.release();
                let joined = worker.join().unwrap();
                drop(control);
                joined
            })
        } else {
            fixture.run(false)
        };
        assert_eq!(fixture.wire.barrier(), 1);
        fixture.wire.finish();
        assert_wire(&fixture.wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Cancelled));
        assert_eq!(retries(&events), 0);
        assert_eq!(fixture.journal.counts(), (1, 0, 1));
        assert_eq!(result.refusals().len(), 1);
        assert!(result.completion().report.attempts.is_empty());
        assert_eq!(
            result.completion().report.accounting.knownness,
            AccountingKnownness::UnknownUsage
        );
        assert_eq!(
            result
                .completion()
                .report
                .accounting
                .ordinary
                .cost_microcents,
            None
        );
        let checkpoint = fixture.journal.snapshot();
        assert_unknown_bill(&checkpoint, 0, 1, 2);
        assert_eq!(
            checkpoint.refusals().unwrap().latest(),
            &result.refusals()[0]
        );
        assert_eq!(
            fixture
                .journal
                .observations
                .lock()
                .unwrap()
                .acknowledgements,
            [checkpoint]
        );
    }
}

#[test]
fn cancellation_during_retry_backoff_never_begins_another_attempt() {
    let mut fixture = Managed::new(vec![Reply::rejection(503, 17)], Mode::Plain, 2, true);
    let (result, events, _) = fixture.run(true);
    assert_eq!(fixture.wire.barrier(), 1);
    fixture.wire.finish();
    assert_wire(&fixture.wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert_eq!(fixture.journal.counts(), (1, 0, 1));
    assert_eq!(retries(&events), 1);
    assert_eq!(result.refusals().len(), 1);
    assert!(result.completion().report.attempts.is_empty());
    assert_unknown_bill(&fixture.journal.snapshot(), 0, 1, 2);
}

#[test]
fn cancellation_after_second_begin_does_not_send_second_post() {
    let mut fixture = Managed::new(
        vec![Reply::rejection(503, 17)],
        Mode::CancelBegin(2),
        2,
        true,
    );
    let (result, events, _) = fixture.run(false);
    assert_eq!(fixture.wire.barrier(), 1);
    fixture.wire.finish();
    assert_wire(&fixture.wire, 1);
    assert!(matches!(result.completion().end, TurnEnd::Cancelled));
    assert_eq!(fixture.journal.counts(), (2, 1, 1));
    assert_eq!(retries(&events), 1);
    assert_eq!(result.refusals().len(), 1);
    let trace = fixture.journal.observations.lock().unwrap();
    let first = trace.begins[0].binding.as_ref().unwrap();
    let second = trace.begins[1].binding.as_ref().unwrap();
    assert_ne!(first.request_id(), second.request_id());
    assert_ne!(first.decision_id(), second.decision_id());
    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_eq!(trace.receipts.len(), 1);
    let receipt = &trace.receipts[0];
    assert_eq!(receipt.request_id, second.request_id());
    assert!(!receipt.completed);
    assert_eq!(receipt.knownness, AccountingKnownness::Known);
    assert!(receipt.usage.is_none());
    assert_eq!(receipt.totals, AccountingTotals::known_zero());
    assert_eq!(
        result.completion().report.attempts.as_slice(),
        std::slice::from_ref(receipt)
    );
    let visible = inspect(&fixture.home, None);
    assert_eq!(visible.last_legacy_receipt.as_ref(), Some(receipt));
    assert_unknown_bill(&visible.checkpoint, 0, 1, 4);
    assert_eq!(
        visible.checkpoint.refusals().unwrap().latest(),
        &result.refusals()[0]
    );
}

#[test]
fn unqualified_wire_failures_retain_actual_uncertainty_and_never_retry() {
    for kind in ["body-cap", "truncated", "admitted-with-usage"] {
        let reply = match kind {
            "body-cap" => Reply::rejection(503, 65_537),
            "truncated" => Reply {
                extra_length: 100,
                ..Reply::rejection(503, 17)
            },
            "admitted-with-usage" => Reply::admitted_malformed(true),
            _ => unreachable!(),
        };
        let mut fixture = Managed::new(vec![reply], Mode::Plain, 2, true);
        let (result, events, transcript) = fixture.run(false);
        assert_eq!(fixture.wire.barrier(), 1);
        fixture.wire.finish();
        assert_wire(&fixture.wire, 1);
        assert!(matches!(result.completion().end, TurnEnd::Failed(_)));
        assert_uncertain(&fixture.home, &fixture.journal, &result, &events);
        let visible = inspect(&fixture.home, None);
        assert_eq!(
            visible.checkpoint.known_priced_subtotals(),
            Some(KnownPricedSubtotals::known_zero())
        );
        assert!(visible.checkpoint.last_settlement().is_none());
        let trace = fixture.journal.observations.lock().unwrap();
        if kind == "admitted-with-usage" {
            assert_eq!(trace.receipts[0].usage, Some(usage()));
            assert_eq!(
                visible.pending_receipt.as_ref().unwrap().usage,
                Some(usage())
            );
            assert!(
                transcript
                    .iter()
                    .any(|message| message.role == ChatRole::Assistant
                        && message.content == "kept partial text")
            );
            // These counters are provisional evidence, not validated numeric
            // subtotals. They survive in the actual receipt/pending metadata.
            let report = &result.completion().report;
            assert_eq!(
                (
                    report.input_tokens,
                    report.output_tokens,
                    report.cost_microcents
                ),
                (0, 0, 0)
            );
        } else {
            assert!(trace.receipts[0].usage.is_none());
            assert!(visible.pending_receipt.as_ref().unwrap().usage.is_none());
        }
        assert!(!trace.receipts[0].completed);
        assert_eq!(trace.receipts[0].totals.cost_microcents, None);
    }
}
