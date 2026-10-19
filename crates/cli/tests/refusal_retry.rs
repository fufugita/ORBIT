#![cfg(target_os = "linux")]
#![deny(unsafe_code)]
use orbit_adapter::types::{ChatMessage, ChatRole, ProviderUsage};
use orbit_cli::context_history::{
    DetailedAccountingInspection, context_journal, inspect_accounting_detailed,
    load_compaction_source,
};
use orbit_cli::session_accounting::FullCostStatus;
use orbit_cli::sessions::{self, SessionFile};
use orbit_engine::compaction::{
    AccountingBaseline, AccountingKnownness, AccountingTotals, AttemptPurpose, KnownPricedSubtotals,
};
use orbit_engine::retry::{DetailedLastSettlement, adapter_identity_digest};
use orbit_engine::{ProviderKind, TurnConfig};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
const MAX_REQUESTS: usize = 8;
const MAX_BODY: usize = 4 * 1024 * 1024;
const CAP: u64 = 2 * 1024 * 1024;
const PROMPT: &str = "continue this exact controlled intent";
const ANSWER: &str = "controlled ordinary answer";
const SUMMARY: &str = "short controlled historical summary";
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

#[derive(PartialEq, Eq, Debug)]
struct BinaryFingerprint {
    metadata: (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64),
    digest: Vec<u8>,
}
fn binary_fingerprint(path: &Path) -> BinaryFingerprint {
    let stamp = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let first = fs::symlink_metadata(path).unwrap();
    assert!(path.is_absolute() && path.canonicalize().unwrap() == path);
    assert!(first.is_file() && !first.file_type().is_symlink() && first.mode() & 0o111 != 0);
    assert_eq!(
        first.uid(),
        fs::metadata(std::env::var_os("HOME").unwrap())
            .unwrap()
            .uid()
    );
    assert!(first.len() > 0 && first.len() <= 1024 * 1024 * 1024);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    assert_eq!(stamp(&file.metadata().unwrap()), stamp(&first));
    let mut hashed = Sha256::new();
    let mut count = 0u64;
    let mut block = vec![0; 1024 * 1024];
    loop {
        let size = file.read(&mut block).unwrap();
        if size == 0 {
            break;
        }
        count = count.checked_add(size as u64).unwrap();
        assert!(count <= first.len());
        hashed.update(&block[..size]);
    }
    assert_eq!(count, first.len());
    assert_eq!(stamp(&file.metadata().unwrap()), stamp(&first));
    assert_eq!(stamp(&fs::symlink_metadata(path).unwrap()), stamp(&first));
    BinaryFingerprint {
        metadata: stamp(&first),
        digest: hashed.finalize().to_vec(),
    }
}

// Only binary verification may exclude time, and only while no child or
// response work is live. Every other interval shares one cumulative budget.
#[derive(Debug, Default, PartialEq, Eq)]
struct ClockState {
    last_tick: Duration,
    accounted: Duration,
    verifying: bool,
    child_live: bool,
    response_live: bool,
    wire_started: bool,
    watchdog_done: bool,
}
impl ClockState {
    fn begin_wire(&mut self, now: Duration) -> Result<Duration, &'static str> {
        if self.wire_started || self.watchdog_done {
            return Err("fixture wire budget already started");
        }
        self.advance(now);
        self.wire_started = true;
        Ok(self.accounted)
    }
    fn advance(&mut self, now: Duration) {
        let elapsed = now
            .checked_sub(self.last_tick)
            .expect("monotonic fixture clock");
        if !self.verifying || self.child_live || self.response_live {
            self.accounted = self.accounted.checked_add(elapsed).unwrap();
        }
        self.last_tick = now;
    }
    fn begin_verification(&mut self, now: Duration) -> Result<(), &'static str> {
        if self.child_live {
            return Err("binary verification with live child");
        }
        if self.response_live {
            return Err("binary verification with live response");
        }
        if self.verifying {
            return Err("nested binary verification");
        }
        self.advance(now);
        self.verifying = true;
        Ok(())
    }
    fn end_verification(&mut self, now: Duration) {
        assert!(self.verifying && !self.child_live);
        self.advance(now);
        self.verifying = false;
    }
    fn begin_child(&mut self, now: Duration) -> Result<(), &'static str> {
        if self.verifying {
            return Err("child spawn during binary verification");
        }
        if self.child_live {
            return Err("overlapping owned children");
        }
        self.advance(now);
        self.child_live = true;
        Ok(())
    }
    fn child_reaped(&mut self, now: Duration) {
        assert!(self.child_live && !self.verifying);
        self.advance(now);
        self.child_live = false;
    }
    fn begin_response(&mut self, now: Duration) {
        assert!(!self.response_live);
        self.advance(now);
        self.response_live = true;
    }
    fn end_response(&mut self, now: Duration) {
        assert!(self.response_live);
        self.advance(now);
        self.response_live = false;
    }
}
struct SharedClock {
    origin: Instant,
    state: Mutex<ClockState>,
    changed: Condvar,
}
#[derive(Clone)]
struct FixtureClock(Arc<SharedClock>);
impl FixtureClock {
    fn new() -> Self {
        Self(Arc::new(SharedClock {
            origin: Instant::now(),
            state: Mutex::new(ClockState::default()),
            changed: Condvar::new(),
        }))
    }
    fn update<T>(&self, action: impl FnOnce(&mut ClockState, Duration) -> T) -> T {
        let result = {
            let mut state = self.0.state.lock().unwrap();
            action(&mut state, self.0.origin.elapsed())
        };
        self.0.changed.notify_all();
        result
    }
    fn accounted(&self) -> Duration {
        let mut state = self.0.state.lock().unwrap();
        state.advance(self.0.origin.elapsed());
        state.accounted
    }
    fn elapsed_since(&self, baseline: Duration) -> Duration {
        self.accounted().checked_sub(baseline).unwrap()
    }
    fn verification(&self) -> Result<VerificationGuard, &'static str> {
        let result = {
            let mut state = self.0.state.lock().unwrap();
            loop {
                if state.child_live || state.verifying || !state.response_live {
                    break state.begin_verification(self.0.origin.elapsed());
                }
                // A child may exit just before the listener finishes its write.
                // Waiting for that work counts against the unchanged budgets.
                state.advance(self.0.origin.elapsed());
                state = self.0.changed.wait(state).unwrap();
            }
        };
        self.0.changed.notify_all();
        result.map(|()| VerificationGuard(self.clone()))
    }
    fn fingerprint(&self, path: &Path) -> BinaryFingerprint {
        let _verification = self.verification().expect("child-free binary verification");
        binary_fingerprint(path)
    }
    fn response(&self) -> ResponseGuard {
        self.update(ClockState::begin_response);
        ResponseGuard(self.clone())
    }
    fn watchdog_expired(&self, baseline: Duration) -> bool {
        let mut state = self.0.state.lock().unwrap();
        loop {
            state.advance(self.0.origin.elapsed());
            if state.watchdog_done {
                return false;
            }
            let elapsed = state.accounted.checked_sub(baseline).unwrap();
            let Some(remaining) = Duration::from_secs(25).checked_sub(elapsed) else {
                return true;
            };
            if remaining.is_zero() {
                return true;
            }
            state = if state.verifying && !state.response_live && !state.child_live {
                self.0.changed.wait(state).unwrap()
            } else {
                self.0.changed.wait_timeout(state, remaining).unwrap().0
            };
        }
    }
    fn finish_watchdog(&self) {
        self.update(|state, _| state.watchdog_done = true);
    }
}
struct FixtureWatchdog {
    clock: FixtureClock,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl FixtureWatchdog {
    fn start(clock: &FixtureClock, baseline: Duration) -> Self {
        let watchdog_clock = clock.clone();
        let thread = std::thread::spawn(move || {
            if watchdog_clock.watchdog_expired(baseline) {
                eprintln!("owned retry CLI fixture watchdog");
                std::process::exit(91);
            }
        });
        Self {
            clock: clock.clone(),
            thread: Some(thread),
        }
    }
    fn finish(&mut self) {
        self.clock.finish_watchdog();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
impl Drop for FixtureWatchdog {
    fn drop(&mut self) {
        self.clock.finish_watchdog();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct VerificationGuard(FixtureClock);
impl Drop for VerificationGuard {
    fn drop(&mut self) {
        self.0.update(ClockState::end_verification);
    }
}
struct ResponseGuard(FixtureClock);
impl Drop for ResponseGuard {
    fn drop(&mut self) {
        self.0.update(ClockState::end_response);
    }
}

#[test]
fn fixture_clock_counts_runtime_cumulatively_without_resetting_for_fingerprints() {
    let seconds = Duration::from_secs;
    let mut state = ClockState::default();
    let baseline = state.begin_wire(seconds(0)).unwrap();
    assert_eq!(baseline, Duration::ZERO);
    state.begin_verification(seconds(2)).unwrap();
    state.advance(seconds(102));
    assert_eq!(state.accounted, seconds(2));
    state.end_verification(seconds(102));
    state.begin_child(seconds(105)).unwrap();
    state.child_reaped(seconds(112));
    assert_eq!(state.accounted, seconds(12));
    state.begin_verification(seconds(112)).unwrap();
    state.end_verification(seconds(212));
    assert_eq!(state.accounted, seconds(12));
    assert_eq!(
        state.begin_wire(seconds(212)),
        Err("fixture wire budget already started")
    );
    state.advance(seconds(220));
    assert_eq!(state.accounted, seconds(20));
    state.advance(seconds(225));
    assert_eq!(state.accounted, seconds(25));
}

#[test]
fn fixture_clock_guards_child_lifecycles_and_counts_response_work_during_verification() {
    let seconds = Duration::from_secs;
    let mut state = ClockState::default();
    state.begin_child(seconds(0)).unwrap();
    assert_eq!(
        state.begin_verification(seconds(1)),
        Err("binary verification with live child")
    );
    assert!(state.child_live && !state.verifying);
    state.child_reaped(seconds(2));
    state.begin_verification(seconds(2)).unwrap();
    assert_eq!(
        state.begin_child(seconds(3)),
        Err("child spawn during binary verification")
    );
    assert!(!state.child_live && state.verifying);
    assert_eq!(
        state.begin_verification(seconds(3)),
        Err("nested binary verification")
    );
    state.begin_response(seconds(4));
    state.advance(seconds(7));
    assert_eq!(state.accounted, seconds(5));
    state.end_response(seconds(8));
    state.advance(seconds(10));
    assert_eq!(state.accounted, seconds(6));
    state.end_verification(seconds(10));
    state.begin_response(seconds(11));
    assert_eq!(
        state.begin_verification(seconds(12)),
        Err("binary verification with live response")
    );
    state.end_response(seconds(13));
    state.begin_child(seconds(13)).unwrap();
    assert_eq!(
        state.begin_child(seconds(14)),
        Err("overlapping owned children")
    );
    state.child_reaped(seconds(15));
    assert_eq!(state.accounted, seconds(11));

    let clock = FixtureClock::new();
    let unwind = std::panic::catch_unwind(|| {
        let _verification = clock.verification().unwrap();
        panic!("controlled fingerprint failure");
    });
    assert!(unwind.is_err());
    assert!(!clock.0.state.lock().unwrap().verifying);
    clock.update(ClockState::begin_child).unwrap();
    assert!(clock.verification().is_err());
    clock.update(ClockState::child_reaped);
    let verification = clock.verification().unwrap();
    assert!(clock.update(ClockState::begin_child).is_err());
    drop(verification);
    assert!(!clock.0.state.lock().unwrap().verifying);
    clock.finish_watchdog();
    assert!(!clock.watchdog_expired(Duration::ZERO));
}

fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write_new(path: &Path, bytes: impl AsRef<[u8]>) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes.as_ref()).unwrap();
}
fn replace_owned(path: &Path, bytes: impl AsRef<[u8]>) {
    if path.exists() {
        let m = fs::symlink_metadata(path).unwrap();
        assert!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1);
    }
    let staged = path.with_extension(format!("{}.tmp", ulid::Ulid::new()));
    write_new(&staged, bytes);
    fs::rename(staged, path).unwrap();
}
fn read_owned(path: &Path, cap: u64) -> Vec<u8> {
    let m = fs::symlink_metadata(path).unwrap();
    assert!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1 && m.len() <= cap);
    let bytes = fs::read(path).unwrap();
    assert!(bytes.len() as u64 <= cap);
    bytes
}
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    binary: PathBuf,
    pin: BinaryFingerprint,
    clock: FixtureClock,
}
impl Fixture {
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
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_orbit"));
        let clock = FixtureClock::new();
        let pin = clock.fingerprint(&binary);
        let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap())
            .join(format!("retry-cli-{}", ulid::Ulid::new()));
        private_directory(&root);
        let home = root.join("home");
        let workspace = root.join("work");
        private_directory(&home);
        private_directory(&workspace);
        let plan = orbit_cli::setup::plan_setup(&home, &orbit_cli::setup::SetupRequest::default())
            .unwrap();
        orbit_cli::setup::apply_setup(&plan).unwrap();
        Self {
            root,
            home,
            workspace,
            binary,
            pin,
            clock,
        }
    }
    fn configure(&self, wire: &Wire, window: u64, routing: bool) {
        let model = |id: &str, input: u64, price: u64| json!({"id":id,"max_output_tokens":73,"context_limits":{"input_tokens":input},"pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,"reasoning_per_million_microdollars":0,"request_flat_microdollars":price}});
        let selected = format!("http://{}/selected/v1?route=final&raw=%2F", wire.authority);
        let mut value = json!({"provider":[{"name":"fixture","kind":"openai-compatible","url":wire.url,"models":[model("model-a",window,13),model("summary-model",64000,17)]},{"name":"selected","kind":"openai-compatible","url":selected,"models":[model("model-b",window,13)]}],"roles":{"main":"fixture/model-a","compaction":"fixture/summary-model"}});
        if routing {
            value["routing"] = json!({"phases":{"coding":{"hard":"selected/model-b"}}});
        }
        let parsed: orbit_cli::config::ProvidersConfig = serde_json::from_value(value).unwrap();
        replace_owned(
            &self.home.join("providers.toml"),
            toml::to_string(&parsed).unwrap(),
        );
    }
    fn config(&self, wire: &Wire, selected: bool) -> TurnConfig {
        TurnConfig {
            provider_id: if selected { "selected" } else { "fixture" }.into(),
            model: if selected { "model-b" } else { "model-a" }.into(),
            gate: if selected {
                format!("http://{}/selected/v1?route=final&raw=%2F", wire.authority)
            } else {
                wire.url.clone()
            },
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: None,
            max_output_tokens: 73,
            sampling: None,
            effort: None,
            supported_efforts: None,
        }
    }
    fn policy(&self, config: &TurnConfig, id: &str) {
        replace_owned(
            &self.home.join("provider-policies.toml"),
            policy_document(config, id),
        );
    }
    fn saved(&self) -> SessionFile {
        let all = sessions::list_sessions(&self.home).unwrap();
        assert_eq!(all.len(), 1);
        all.into_iter().next().unwrap()
    }
    fn inspect(&self, id: &str) -> DetailedAccountingInspection {
        inspect_accounting_detailed(&self.home, id, None).unwrap()
    }
    fn accounting_bytes(&self, id: &str) -> Vec<u8> {
        read_owned(
            &self
                .home
                .join("context-history")
                .join(id)
                .join("accounting.json"),
            131072,
        )
    }
    fn pin(&self) {
        assert_eq!(self.clock.fingerprint(&self.binary), self.pin);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn policy_document(c: &TurnConfig, id: &str) -> String {
    toml::to_string(&json!({"version":1,"final_rejection":[{"id":id,"provider":c.provider_id,"model":c.model,"endpoint":c.gate,"adapter_identity_sha256":adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),"statuses":[500,503],"scope":"ordinary","generation":"final_rejection","billing":"unknown","allow_uncapped_retry":true,"max_attempts":2}]})).unwrap()
}
struct Hold {
    notice: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
struct Control {
    notice: mpsc::Receiver<()>,
    release: mpsc::SyncSender<()>,
}
impl Control {
    fn wait(&self) {
        self.notice
            .recv_timeout(Duration::from_secs(3))
            .expect("owned response hold not observed");
    }
    fn release(&self) {
        self.release.try_send(()).unwrap();
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        let _ = self.release.try_send(());
    }
}
struct Reply {
    status: u16,
    body: Vec<u8>,
    hold: Option<Hold>,
    declared_extra: usize,
    close_after_hold: bool,
}
impl Reply {
    fn rejection(status: u16) -> Self {
        Self {
            status,
            body: b"controlled rejection".to_vec(),
            hold: None,
            declared_extra: 0,
            close_after_hold: false,
        }
    }
    fn text(text: &str) -> Self {
        Self{status:200,body:format!("data: {}\n\ndata: [DONE]\n\n",json!({"choices":[{"index":0,"delta":{"content":text},"finish_reason":"stop"}],"usage":{"prompt_tokens":14,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}})).into_bytes(),hold:None,declared_extra:0,close_after_hold:false}
    }
    fn incomplete(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            hold: None,
            declared_extra: 1,
            close_after_hold: true,
        }
    }
    fn partial(text: &str, provisional: bool) -> Self {
        let mut value = json!({"choices":[{"index":0,"delta":{"content":text}}]});
        if provisional {
            value["usage"] = json!({"prompt_tokens":14,"completion_tokens":7,
                "prompt_tokens_details":{"cached_tokens":3},
                "completion_tokens_details":{"reasoning_tokens":5}});
        }
        Self::incomplete(200, format!("data: {value}\n\n").into_bytes())
    }
    fn held(mut self) -> (Self, Control) {
        let (notice, rx) = mpsc::sync_channel(1);
        let (tx, release) = mpsc::sync_channel(1);
        self.hold = Some(Hold { notice, release });
        (
            self,
            Control {
                notice: rx,
                release: tx,
            },
        )
    }
}
#[derive(Clone)]
struct Capture {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
type Probe = Arc<dyn Fn(usize, &Capture) + Send + Sync>;
struct Wire {
    url: String,
    authority: String,
    captures: Arc<Mutex<Vec<Capture>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    barrier: mpsc::Sender<mpsc::SyncSender<usize>>,
    probe: Arc<Mutex<Option<Probe>>>,
    thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: FixtureWatchdog,
}
impl Wire {
    fn new(clock: &FixtureClock, replies: Vec<Reply>) -> Self {
        assert!(replies.len() <= MAX_REQUESTS);
        let baseline = clock
            .update(ClockState::begin_wire)
            .expect("one cumulative wire budget");
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/tenant/v1?scope=refusal-cli");
        let captures = Arc::new(Mutex::new(Vec::new()));
        let observed = captures.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (barrier, barriers) = mpsc::channel::<mpsc::SyncSender<usize>>();
        let probe: Arc<Mutex<Option<Probe>>> = Arc::new(Mutex::new(None));
        let wire_probe = probe.clone();
        let watchdog = FixtureWatchdog::start(clock, baseline);
        let listener_clock = clock.clone();
        let thread = std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            loop {
                if listener_clock.elapsed_since(baseline) >= Duration::from_secs(20) {
                    return Err("listener deadline");
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let ordinal = accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        if ordinal > MAX_REQUESTS {
                            return Err("request bound");
                        }
                        let _response = listener_clock.response();
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .map_err(|_| "read timeout")?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .map_err(|_| "write timeout")?;
                        let capture = read_request(&mut socket)?;
                        observed
                            .lock()
                            .map_err(|_| "capture lock")?
                            .push(capture.clone());
                        let probe = wire_probe.lock().map_err(|_| "probe lock")?.clone();
                        if let Some(probe) = probe {
                            probe(ordinal, &capture);
                        }
                        let reply = replies.next().ok_or("unexpected replay")?;
                        let content_type = if reply.status == 200 {
                            "text/event-stream"
                        } else {
                            "application/json"
                        };
                        write!(socket,"HTTP/1.1 {} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.status,reply.body.len().checked_add(reply.declared_extra).unwrap()).map_err(|_|"headers write")?;
                        if let Some(hold) = reply.hold {
                            let end = if reply.close_after_hold {
                                reply.body.len()
                            } else {
                                reply.body.len().saturating_sub(1)
                            };
                            socket
                                .write_all(&reply.body[..end])
                                .map_err(|_| "held body write")?;
                            socket.flush().map_err(|_| "held flush")?;
                            hold.notice.send(()).map_err(|_| "hold notice")?;
                            hold.release
                                .recv_timeout(Duration::from_secs(3))
                                .map_err(|_| "hold deadline")?;
                            if !reply.close_after_hold {
                                socket
                                    .write_all(&reply.body[end..])
                                    .map_err(|_| "final body write")?;
                            }
                        } else {
                            socket.write_all(&reply.body).map_err(|_| "body write")?;
                        }
                        let _ = socket.flush();
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
            watchdog,
        }
    }
    fn barrier(&self) -> usize {
        let (tx, rx) = mpsc::sync_channel(1);
        self.barrier.send(tx).unwrap();
        rx.recv_timeout(Duration::from_secs(3))
            .expect("listener poll barrier")
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
        self.watchdog.finish();
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // The watchdog's own Drop signals done and joins after listener cleanup.
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

struct OwnedChild {
    child: Option<Child>,
    clock: FixtureClock,
    reserved: bool,
}
impl OwnedChild {
    fn spawn(clock: &FixtureClock, command: &mut Command) -> Self {
        let mut owned = Self {
            child: None,
            clock: clock.clone(),
            reserved: false,
        };
        owned
            .clock
            .update(ClockState::begin_child)
            .expect("unpaused child reservation");
        owned.reserved = true;
        // The reservation already excludes verification, including the interval
        // between successful spawn and assigning the actual owned handle.
        owned.child = Some(command.spawn().expect("owned CLI spawn"));
        owned
    }
    fn child(&mut self) -> &mut Child {
        self.child.as_mut().unwrap()
    }
    fn reaped(&mut self) {
        assert!(self.reserved);
        self.clock.update(ClockState::child_reaped);
        self.reserved = false;
    }
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let result = self.child().try_wait();
        if matches!(result, Ok(Some(_))) && self.reserved {
            self.reaped();
        }
        result
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        if let Some(child) = self.child.as_mut() {
            child.stdin.take();
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let group = format!("-{}", child.id());
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", "--", &group])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                // Failed reap never authorizes a child-free verification.
                child.wait().expect("owned CLI cleanup reap");
            }
        }
        // None is possible only when spawn failed before creating a child.
        self.reaped();
    }
}
struct Process {
    child: OwnedChild,
    paths: [PathBuf; 2],
    deadline: Instant,
    providers: Vec<u8>,
    policy: Option<Vec<u8>>,
    policy_edited: bool,
}
struct CliResult {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}
impl CliResult {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).expect("actual CLI JSON output")
    }
}
impl Process {
    fn start(f: &Fixture, args: &[&str]) -> Self {
        Self::start_with_timeouts(f, args, None)
    }
    fn start_with_timeouts(f: &Fixture, args: &[&str], timeouts: Option<(u64, u64)>) -> Self {
        require_private_system_fixture();
        f.pin();
        let id = ulid::Ulid::new().to_string();
        let paths = [
            f.root.join(format!("{id}.out")),
            f.root.join(format!("{id}.err")),
        ];
        for path in &paths {
            write_new(path, b"");
        }
        let providers = read_owned(&f.home.join("providers.toml"), 131072);
        let policy = policy_bytes(f);
        let mut command = Command::new(&f.binary);
        command
            .args(args)
            .arg("--home")
            .arg(&f.home)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&f.workspace)
            .stdin(Stdio::piped())
            .stdout(fs::OpenOptions::new().write(true).open(&paths[0]).unwrap())
            .stderr(fs::OpenOptions::new().write(true).open(&paths[1]).unwrap())
            .process_group(0);
        for name in [
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
        ] {
            command.env(name, std::env::var_os(name).unwrap());
        }
        if let Some((first, idle)) = timeouts {
            assert!((1000..=2000).contains(&first) && (1000..=2000).contains(&idle));
            command
                .env("ORBIT_TEST_FIRST_BYTE_TIMEOUT_MS", first.to_string())
                .env("ORBIT_TEST_IDLE_TIMEOUT_MS", idle.to_string());
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let child = OwnedChild::spawn(&f.clock, &mut command);
        Self {
            child,
            paths,
            deadline,
            providers,
            policy,
            policy_edited: false,
        }
    }
    fn feed(&mut self, phase: &'static str, text: &str) {
        let result = {
            let input = self.child.child().stdin.as_mut().unwrap();
            input
                .write_all(text.as_bytes())
                .map_err(|error| ("write", error))
                .and_then(|()| input.flush().map_err(|error| ("flush", error)))
        };
        if let Err((stage, error)) = result {
            let status = self.child.try_wait();
            eprintln!(
                "plain input phase={phase} stage={stage} failed: kind={:?}, actual_error={error:?}, actual_child_status={status:?}",
                error.kind(),
            );
            let capture = |path: &Path| {
                let bytes = read_owned(path, CAP);
                let first_end = bytes.len().min(1024);
                let last_start = bytes.len().saturating_sub(1024).max(first_end);
                format!(
                    "{} bytes; first {:?}; last {:?}; omitted {} bytes",
                    bytes.len(),
                    String::from_utf8_lossy(&bytes[..first_end]),
                    String::from_utf8_lossy(&bytes[last_start..]),
                    last_start - first_end,
                )
            };
            let stdout = capture(&self.paths[0]);
            let stderr = capture(&self.paths[1]);
            panic!(
                "plain input phase={phase} stage={stage} failed: kind={:?}, actual_error={error:?}, actual_child_status={status:?}; owned stdout: {stdout}; owned stderr: {stderr}",
                error.kind(),
            );
        }
    }
    fn close_input(&mut self) {
        self.child.child().stdin.take();
    }
    fn check(&mut self) {
        for path in &self.paths {
            assert!(fs::metadata(path).unwrap().len() <= CAP);
        }
        assert!(Instant::now() < self.deadline, "real CLI child deadline");
    }
    fn wait_after_policy_edit(mut self, f: &Fixture) -> CliResult {
        self.policy_edited = true;
        self.wait(f)
    }
    fn live(&mut self) {
        self.check();
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "owned CLI exited before signal"
        );
    }
    fn terminate(&mut self) {
        self.live();
        let id = self.child.child().id().to_string();
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", "--", &id])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "owned unreaped CLI signal delivery failed"
        );
    }
    fn wait(self, f: &Fixture) -> CliResult {
        self.wait_after_reap(f, || {})
    }
    fn wait_after_reap(mut self, f: &Fixture, after_reap: impl FnOnce()) -> CliResult {
        self.close_input();
        let status = loop {
            self.check();
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        after_reap();
        let stdout = String::from_utf8(read_owned(&self.paths[0], CAP)).unwrap();
        let stderr = String::from_utf8(read_owned(&self.paths[1], CAP)).unwrap();
        assert_eq!(
            read_owned(&f.home.join("providers.toml"), 131072),
            self.providers
        );
        if !self.policy_edited {
            assert_eq!(policy_bytes(f), self.policy);
        }
        f.pin();
        CliResult {
            status,
            stdout,
            stderr,
        }
    }
}
fn policy_bytes(f: &Fixture) -> Option<Vec<u8>> {
    let path = f.home.join("provider-policies.toml");
    match fs::symlink_metadata(&path) {
        Ok(_) => Some(read_owned(&path, 131073)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => panic!("owned policy metadata"),
    }
}
fn cli(f: &Fixture, args: &[&str]) -> CliResult {
    let mut process = Process::start(f, args);
    process.close_input();
    process.wait(f)
}
fn prompt(f: &Fixture, text: &str, resume: Option<&str>) -> CliResult {
    let mut args = vec!["-p", text, "--output-format", "json"];
    if let Some(id) = resume {
        args.extend(["--resume", id]);
    }
    cli(f, &args)
}
fn success(result: &CliResult) {
    assert!(
        result.status.success(),
        "actual CLI failed: {}",
        result.stderr
    );
    assert_eq!(result.json()["status"], "ok");
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
fn notices(result: &CliResult) -> usize {
    result.json()["context_notices"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|notice| {
            notice
                .as_str()
                .is_some_and(|value| value.contains("final rejection"))
        })
        .count()
}
fn assert_wire(wire: &Wire, count: usize) {
    let captures = wire.captures.lock().unwrap();
    assert_eq!(captures.len(), count);
    for capture in captures.iter() {
        assert!(capture.target.starts_with("POST ") && capture.target.ends_with(" HTTP/1.1"));
        assert_eq!(
            capture
                .headers
                .iter()
                .filter_map(|(key, value)| (key == "host").then_some(value.as_str()))
                .collect::<Vec<_>>(),
            [wire.authority.as_str()]
        );
        assert!(
            !capture
                .headers
                .iter()
                .any(|(key, _)| matches!(key.as_str(), "authorization" | "x-api-key"))
        );
        let body: Value = serde_json::from_slice(&capture.body).unwrap();
        assert_eq!(body["max_tokens"], 73);
    }
}
fn decisions(f: &Fixture, id: &str) -> Vec<String> {
    orbit_ledger::verify_ledger(&f.home.join("ledger"))
        .unwrap()
        .0
        .into_iter()
        .filter_map(|entry| match entry.record.event {
            orbit_ledger::LedgerEvent::EgressIntent(event) => {
                assert_eq!(event.session_id, id);
                Some(event.decision_id)
            }
            _ => None,
        })
        .collect()
}
fn assert_qualified(
    f: &Fixture,
    id: &str,
    ordinary_successes: u64,
    summary_successes: u64,
    refusals: u64,
) {
    let saved = sessions::load_session(&f.home, id).unwrap();
    let observed = f.inspect(id);
    let checkpoint = &observed.checkpoint;
    assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
    assert!(checkpoint.pending().is_none());
    assert_eq!(checkpoint.refusals().unwrap().count(), refusals);
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
            input_tokens: 11 * summary_successes,
            output_tokens: 7 * summary_successes,
            cost_microcents: Some(17 * summary_successes)
        }
    );
    assert_eq!(
        checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: 13 * ordinary_successes,
            housekeeping_microcents: 17 * summary_successes
        })
    );
    let anchor = saved.accounting_watermark.unwrap();
    assert_eq!(anchor.full_cost_status, FullCostStatus::UnknownUsage);
    assert_eq!(anchor.revision, checkpoint.revision().0);
    assert_eq!(
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        ),
        (
            11 * (ordinary_successes + summary_successes),
            7 * (ordinary_successes + summary_successes),
            13 * ordinary_successes + 17 * summary_successes
        )
    );
    let before = f.accounting_bytes(id);
    assert_eq!(
        context_journal(&f.home, id, None)
            .unwrap()
            .accounting_checkpoint_detailed()
            .unwrap(),
        *checkpoint
    );
    assert_eq!(f.accounting_bytes(id), before);
}
fn seed_retry(f: &Fixture, wire: &Wire) -> SessionFile {
    f.policy(&f.config(wire, false), "first-policy");
    let result = prompt(f, PROMPT, None);
    success(&result);
    assert_eq!(notices(&result), 1);
    let saved = f.saved();
    assert_qualified(f, &saved.session_id, 1, 0, 1);
    saved
}

#[test]
fn declared_500_and_503_retry_once_with_persistent_unknown_bill() {
    for status in [500, 503] {
        let f = Fixture::new();
        let mut wire = Wire::new(
            &f.clock,
            vec![Reply::rejection(status), Reply::text(ANSWER)],
        );
        f.configure(&wire, 128000, false);
        let c = f.config(&wire, false);
        f.policy(&c, "selected-policy");
        assert!(
            orbit_cli::provider_policies::load_for_config(&f.home, &c)
                .unwrap()
                .is_some()
        );
        let before = read_owned(&f.home.join("provider-policies.toml"), 131072);
        let result = cli(&f, &["-p", PROMPT, "--output-format", "stream-json"]);
        assert!(
            result.status.success(),
            "stream CLI failed: {}",
            result.stderr
        );
        let events: Vec<Value> = result
            .stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(events.len() <= 256);
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "retrying")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "turn_ended")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["type"] == "status"
                    && event["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("final rejection")))
                .count(),
            1
        );
        let saved = f.saved();
        assert_eq!(saved.turns, 1);
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
                .count(),
            1
        );
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.role == ChatRole::Assistant && message.content == ANSWER)
                .count(),
            1
        );
        assert_qualified(&f, &saved.session_id, 1, 0, 1);
        let view = f.inspect(&saved.session_id);
        assert_eq!(view.last_legacy_receipt.unwrap().usage, Some(usage()));
        let record = view.checkpoint.refusals().unwrap().latest();
        let ids = decisions(&f, &saved.session_id);
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_eq!(ids[0], record.binding().decision_id());
        assert_eq!(
            ids[1],
            view.checkpoint
                .last_settlement()
                .and_then(|last| match last {
                    DetailedLastSettlement::Legacy(last) => Some(last.reference.request_id.clone()),
                    _ => None,
                })
                .unwrap()
        );
        assert_eq!(wire.barrier(), 2);
        wire.finish();
        assert_wire(&wire, 2);
        let captured = wire.captures.lock().unwrap();
        assert_eq!(captured[0].body, captured[1].body);
        assert_eq!(
            captured[0].target,
            "POST /tenant/v1/chat/completions?scope=refusal-cli HTTP/1.1"
        );
        assert_eq!(
            read_owned(&f.home.join("provider-policies.toml"), 131072),
            before
        );
    }
}

fn policy_runtime_effect(kind: &str) {
    let f = Fixture::new();
    let local = matches!(
        kind,
        "malformed" | "unsafe" | "oversized" | "inactive-invalid"
    );
    let mut wire = Wire::new(
        &f.clock,
        if local {
            vec![Reply::text(ANSWER)]
        } else {
            vec![Reply::text(ANSWER), Reply::rejection(503)]
        },
    );
    f.configure(&wire, 128000, false);
    success(&prompt(&f, "initial checked session", None));
    let saved = f.saved();
    let before = f.accounting_bytes(&saved.session_id);
    let c = f.config(&wire, false);
    match kind {
        "missing" => {}
        "unmatched" => {
            let mut other = c.clone();
            other.model = "inactive-model".into();
            f.policy(&other, "inactive");
        }
        "stale" => {
            let text = policy_document(&c, "stale").replace(
                &adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
                &"0".repeat(64),
            );
            replace_owned(&f.home.join("provider-policies.toml"), text);
        }
        "malformed" => replace_owned(
            &f.home.join("provider-policies.toml"),
            "version=1\nSECRET_MARKER = [",
        ),
        "unsafe" => {
            f.policy(&c, "unsafe");
            fs::set_permissions(
                f.home.join("provider-policies.toml"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        "oversized" => replace_owned(&f.home.join("provider-policies.toml"), vec![b'x'; 131073]),
        "inactive-invalid" => {
            let mut other = c.clone();
            other.model = "inactive-model".into();
            replace_owned(
                &f.home.join("provider-policies.toml"),
                policy_document(&other, "inactive").replace("ordinary", "summary"),
            );
        }
        _ => unreachable!(),
    }
    let result = prompt(&f, "new current request", Some(&saved.session_id));
    assert!(!result.status.success());
    let after = f.inspect(&saved.session_id);
    if local {
        assert_eq!(f.accounting_bytes(&saved.session_id), before);
        assert!(after.checkpoint.pending().is_none());
        assert_eq!(wire.barrier(), 1);
    } else {
        assert!(after.checkpoint.pending().unwrap().uncertain);
        assert!(after.checkpoint.refusals().is_none());
        assert_eq!(
            after.pending_receipt.unwrap().knownness,
            AccountingKnownness::Uncertain
        );
        let bytes = f.accounting_bytes(&saved.session_id);
        let again = prompt(&f, "do not replay pending", Some(&saved.session_id));
        assert!(!again.status.success());
        assert_eq!(f.accounting_bytes(&saved.session_id), bytes);
        assert_eq!(wire.barrier(), 2);
    }
    wire.finish();
    assert_wire(&wire, if local { 1 } else { 2 });
}

#[test]
fn missing_policy_uses_conservative_runtime_path() {
    policy_runtime_effect("missing");
}

#[test]
fn unmatched_policy_uses_conservative_runtime_path() {
    policy_runtime_effect("unmatched");
}

#[test]
fn stale_policy_uses_conservative_runtime_path() {
    policy_runtime_effect("stale");
}

#[test]
fn malformed_policy_stops_new_runtime_traffic() {
    policy_runtime_effect("malformed");
}

#[test]
fn unsafe_policy_stops_new_runtime_traffic() {
    policy_runtime_effect("unsafe");
}

#[test]
fn oversized_policy_stops_new_runtime_traffic() {
    policy_runtime_effect("oversized");
}

#[test]
fn inactive_invalid_policy_stops_new_runtime_traffic() {
    policy_runtime_effect("inactive-invalid");
}

#[test]
fn explicit_and_phase_selection_load_the_final_policy() {
    for phase in [false, true] {
        for final_policy in [false, true] {
            let f = Fixture::new();
            let mut wire = Wire::new(
                &f.clock,
                if final_policy {
                    vec![Reply::rejection(503), Reply::text(ANSWER)]
                } else {
                    vec![Reply::rejection(503)]
                },
            );
            f.configure(&wire, 128000, phase);
            f.policy(&f.config(&wire, final_policy), "route-policy");
            let text = "implement comprehensive parser";
            let result = if phase {
                prompt(&f, text, None)
            } else {
                let c = f.config(&wire, true);
                cli(
                    &f,
                    &[
                        "-p",
                        text,
                        "--provider",
                        "selected",
                        "--model",
                        "model-b",
                        "--gate",
                        &c.gate,
                        "--output-format",
                        "json",
                    ],
                )
            };
            assert_eq!(result.status.success(), final_policy);
            let saved = f.saved();
            let observed = f.inspect(&saved.session_id);
            assert_eq!(observed.checkpoint.refusals().is_some(), final_policy);
            if final_policy {
                assert_qualified(&f, &saved.session_id, 1, 0, 1);
                assert_eq!(notices(&result), 1);
            } else {
                assert!(observed.checkpoint.pending().unwrap().uncertain);
            }
            assert_eq!(wire.barrier(), if final_policy { 2 } else { 1 });
            wire.finish();
            assert_wire(&wire, if final_policy { 2 } else { 1 });
            for capture in wire.captures.lock().unwrap().iter() {
                assert_eq!(
                    capture.target,
                    "POST /selected/v1/chat/completions?route=final&raw=%2F HTTP/1.1"
                );
                assert_eq!(
                    serde_json::from_slice::<Value>(&capture.body).unwrap()["model"],
                    "model-b"
                );
            }
            if phase {
                let providers = orbit_cli::config::ProvidersConfig::load(&f.home).unwrap();
                let base =
                    orbit_cli::phase_routing::resolve_model(&providers, "fixture/model-a", None)
                        .unwrap();
                let decision = orbit_cli::phase_routing::preview(
                    &providers,
                    &providers.phase_settings(),
                    &base,
                    orbit_cli::phase_routing::SelectionOrigin::Role,
                    text,
                    None,
                )
                .unwrap();
                assert_eq!(decision.phase, orbit_engine::routing::TaskPhase::Coding);
                assert_eq!(decision.difficulty, orbit_engine::routing::Difficulty::Hard);
                assert_eq!(
                    decision.source,
                    orbit_cli::phase_routing::RouteSource::PhaseDifficulty
                );
                assert_eq!(decision.provider_id, "selected");
                assert_eq!(decision.raw_model, "model-b");
            }
        }
    }
}

#[test]
fn file_edits_are_frozen_for_one_operation_and_reloaded_next() {
    for remove in [false, true] {
        let f = Fixture::new();
        let (held, control) = Reply::rejection(503).held();
        let mut wire = Wire::new(
            &f.clock,
            vec![held, Reply::text(ANSWER), Reply::rejection(503)],
        );
        f.configure(&wire, 128000, false);
        let c = f.config(&wire, false);
        f.policy(&c, "first-policy");
        let process = Process::start(&f, &["-p", PROMPT, "--output-format", "json"]);
        let control = control;
        control.wait();
        if remove {
            fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
        } else {
            let mut other = c.clone();
            other.model = "inactive-model".into();
            f.policy(&other, "changed-policy");
        }
        control.release();
        let result = process.wait_after_policy_edit(&f);
        success(&result);
        let saved = f.saved();
        assert_qualified(&f, &saved.session_id, 1, 0, 1);
        let historical = f
            .inspect(&saved.session_id)
            .checkpoint
            .refusals()
            .cloned()
            .unwrap();
        assert_eq!(wire.barrier(), 2);
        let next = prompt(
            &f,
            "new invocation after file change",
            Some(&saved.session_id),
        );
        assert!(!next.status.success());
        let view = f.inspect(&saved.session_id);
        assert_eq!(view.checkpoint.refusals(), Some(&historical));
        assert!(view.checkpoint.pending().unwrap().uncertain);
        assert_eq!(
            view.pending_receipt.unwrap().knownness,
            AccountingKnownness::Uncertain
        );
        assert_eq!(wire.barrier(), 3);
        wire.finish();
        assert_wire(&wire, 3);
    }
}

#[test]
fn literal_policy_removal_preserves_history_without_enabling_retry() {
    for rejected in [false, true] {
        let f = Fixture::new();
        let mut wire = Wire::new(
            &f.clock,
            vec![
                Reply::rejection(503),
                Reply::text(ANSWER),
                if rejected {
                    Reply::rejection(503)
                } else {
                    Reply::text(ANSWER)
                },
            ],
        );
        f.configure(&wire, 128000, false);
        let saved = seed_retry(&f, &wire);
        let historical = f
            .inspect(&saved.session_id)
            .checkpoint
            .refusals()
            .cloned()
            .unwrap();
        fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
        let result = prompt(
            &f,
            "fresh explicit request after literal policy removal",
            Some(&saved.session_id),
        );
        assert_eq!(result.status.success(), !rejected);
        let view = f.inspect(&saved.session_id);
        assert_eq!(view.checkpoint.refusals(), Some(&historical));
        if rejected {
            assert!(view.checkpoint.pending().unwrap().uncertain);
        } else {
            assert_qualified(&f, &saved.session_id, 2, 0, 1);
            assert_eq!(notices(&result), 0);
            assert_eq!(result.json()["cost_microcents"], 13);
            assert_eq!(result.json()["full_cost_status"], "unknown_usage");
        }
        let ids = decisions(&f, &saved.session_id);
        assert_eq!(ids.len(), 3);
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3
        );
        assert_eq!(wire.barrier(), 3);
        wire.finish();
        assert_wire(&wire, 3);
        assert!(!f.home.join("provider-policies.toml").exists());
    }
}

fn schema(f: &Fixture) -> PathBuf {
    let path = f.root.join("schema.json");
    write_new(&path,serde_json::to_vec(&json!({"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}},"additionalProperties":false})).unwrap());
    path
}
#[test]
fn schema_repair_loads_a_fresh_policy_and_fresh_ids() {
    let f = Fixture::new();
    let (held, control) = Reply::text("{\"wrong\":true}").held();
    let mut wire = Wire::new(
        &f.clock,
        vec![
            Reply::rejection(503),
            held,
            Reply::rejection(503),
            Reply::text("{\"ok\":true}"),
        ],
    );
    f.configure(&wire, 128000, false);
    let c = f.config(&wire, false);
    f.policy(&c, "first-policy");
    let schema = schema(&f);
    let process = Process::start(
        &f,
        &[
            "-p",
            PROMPT,
            "--json-schema",
            schema.to_str().unwrap(),
            "--output-format",
            "json",
        ],
    );
    let control = control;
    control.wait();
    let current = f.saved();
    let first = f
        .inspect(&current.session_id)
        .checkpoint
        .refusals()
        .unwrap()
        .latest()
        .clone();
    f.policy(&c, "repair-policy");
    control.release();
    let result = process.wait_after_policy_edit(&f);
    success(&result);
    let saved = f.saved();
    assert_qualified(&f, &saved.session_id, 2, 0, 2);
    let view = f.inspect(&saved.session_id);
    let last = view.checkpoint.refusals().unwrap().latest();
    assert_ne!(
        first.binding().policy_digest(),
        last.binding().policy_digest()
    );
    assert_ne!(first.binding().request_id(), last.binding().request_id());
    assert_ne!(first.binding().decision_id(), last.binding().decision_id());
    assert_ne!(first.binding().attempt_id(), last.binding().attempt_id());
    assert_eq!(result.json()["cost_microcents"], 26);
    let ids = decisions(&f, &saved.session_id);
    assert_eq!(ids.len(), 4);
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4
    );
    assert_eq!(ids[0], first.binding().decision_id());
    assert_eq!(ids[2], last.binding().decision_id());
    assert_eq!(wire.barrier(), 4);
    wire.finish();
    assert_wire(&wire, 4);
    let captured = wire.captures.lock().unwrap();
    assert_eq!(captured[0].body, captured[1].body);
    assert_eq!(captured[2].body, captured[3].body);
    assert_ne!(captured[0].body, captured[2].body);
    let repair: Value = serde_json::from_slice(&captured[2].body).unwrap();
    assert!(repair.get("tools").is_none());
}

#[test]
fn invalid_repair_policy_stops_only_the_repair_send() {
    let f = Fixture::new();
    let (held, control) = Reply::text("{\"wrong\":true}").held();
    let mut wire = Wire::new(
        &f.clock,
        vec![Reply::rejection(503), held, Reply::text(ANSWER)],
    );
    f.configure(&wire, 128000, false);
    f.policy(&f.config(&wire, false), "first-policy");
    let schema = schema(&f);
    let process = Process::start(
        &f,
        &[
            "-p",
            PROMPT,
            "--json-schema",
            schema.to_str().unwrap(),
            "--output-format",
            "json",
        ],
    );
    let control = control;
    control.wait();
    replace_owned(
        &f.home.join("provider-policies.toml"),
        "version=1\nfinal_rejection=[",
    );
    control.release();
    let result = process.wait_after_policy_edit(&f);
    assert!(!result.status.success());
    let saved = f.saved();
    assert_qualified(&f, &saved.session_id, 1, 0, 1);
    let view = f.inspect(&saved.session_id);
    assert_eq!(view.last_legacy_receipt.unwrap().usage, Some(usage()));
    assert!(view.checkpoint.pending().is_none());
    assert_eq!(wire.barrier(), 2);
    assert_wire(&wire, 2);
    assert_eq!(decisions(&f, &saved.session_id).len(), 2);
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
            .count(),
        1
    );
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::Assistant
                && message.content == "{\"wrong\":true}")
            .count(),
        1
    );
    let repairs: Vec<_> = saved
        .transcript
        .iter()
        .filter(|message| {
            message.role == ChatRole::User
                && message
                    .content
                    .starts_with("Your previous reply did not match the required JSON schema:")
                && message
                    .content
                    .contains("Reply with ONLY valid JSON matching this schema:")
        })
        .collect();
    assert_eq!(repairs.len(), 1);
    let retained_repair = repairs[0].content.clone();
    let original_ids = decisions(&f, &saved.session_id);
    let retained_refusals = view.checkpoint.refusals().cloned().unwrap();

    // The failed repair did not enter dispatch. A separately requested turn
    // can resume the same checked session once the owned policy is removed.
    fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
    let new_prompt = "explicit new request after repairing policy";
    let next = prompt(&f, new_prompt, Some(&saved.session_id));
    success(&next);
    assert_eq!(notices(&next), 0);
    assert_eq!(next.json()["usage"]["input_tokens"], 11);
    assert_eq!(next.json()["usage"]["output_tokens"], 7);
    assert_eq!(next.json()["cost_microcents"], 13);
    assert_eq!(next.json()["full_cost_status"], "unknown_usage");
    assert_qualified(&f, &saved.session_id, 2, 0, 1);
    let after = f.saved();
    assert_eq!(after.session_id, saved.session_id);
    assert_eq!(after.turns, saved.turns + 1);
    assert_eq!(
        after
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
            .count(),
        1
    );
    assert_eq!(
        after
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::Assistant
                && message.content == "{\"wrong\":true}")
            .count(),
        1
    );
    assert_eq!(
        after
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == retained_repair)
            .count(),
        1
    );
    assert_eq!(
        after
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == new_prompt)
            .count(),
        1
    );
    let after_view = f.inspect(&saved.session_id);
    assert!(after_view.checkpoint.pending().is_none());
    assert_eq!(after_view.checkpoint.refusals(), Some(&retained_refusals));
    let last_receipt = after_view.last_legacy_receipt.unwrap();
    assert_eq!(last_receipt.purpose, AttemptPurpose::Ordinary);
    assert_eq!(last_receipt.usage, Some(usage()));
    let new_ids = decisions(&f, &saved.session_id);
    assert_eq!(new_ids.len(), 3);
    assert_eq!(&new_ids[..2], original_ids.as_slice());
    assert!(!original_ids.contains(&new_ids[2]));
    assert_eq!(new_ids[2], last_receipt.request_id);
    assert_eq!(wire.barrier(), 3);
    wire.finish();
    assert_wire(&wire, 3);
    let captures = wire.captures.lock().unwrap();
    assert_eq!(captures[0].body, captures[1].body);
    let current: Value = serde_json::from_slice(&captures[2].body).unwrap();
    let users: Vec<_> = current["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "user")
        .collect();
    assert_eq!(users.last().unwrap()["content"], new_prompt);
    assert_eq!(
        users
            .iter()
            .filter(|message| message["content"] == retained_repair)
            .count(),
        1
    );
    assert!(!f.home.join("provider-policies.toml").exists());
}

#[test]
fn plain_repl_reloads_between_actual_prompt_boundaries() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        vec![
            Reply::rejection(503),
            Reply::text(ANSWER),
            Reply::text(ANSWER),
        ],
    );
    f.configure(&wire, 128000, false);
    f.policy(&f.config(&wire, false), "plain-first");
    let readiness = "full session cost is unknown (UnknownUsage); displayed cost is the known priced subtotal\n";
    let mut process = Process::start(&f, &["chat", "--no-tui", "--bare"]);
    process.feed("first", &format!("{PROMPT}\n/usage\n"));
    let end = Instant::now() + Duration::from_secs(5);
    let first = loop {
        process.check();
        if let Ok(saved) = sessions::list_sessions(&f.home)
            && saved.len() == 1
            && saved[0].turns == 1
            && read_owned(&process.paths[1], CAP)
                .split_inclusive(|byte| *byte == b'\n')
                .any(|line| line == readiness.as_bytes())
        {
            break saved.into_iter().next().unwrap();
        }
        assert!(Instant::now() < end, "plain first prompt boundary");
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_qualified(&f, &first.session_id, 1, 0, 1);
    assert_eq!(wire.barrier(), 2);
    fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
    process.feed("second", "second current plain prompt\nexit\n");
    let result = process.wait_after_policy_edit(&f);
    assert!(
        result.status.success(),
        "plain CLI failed: {}",
        result.stderr
    );
    assert_eq!(result.stderr.matches(readiness).count(), 1);
    assert_eq!(
        result
            .stdout
            .lines()
            .filter(|line| *line == "turns 1 · in 11 · out 7 · $0.000013")
            .count(),
        1
    );
    let saved = f.saved();
    assert_eq!(saved.turns, 2);
    assert_qualified(&f, &saved.session_id, 2, 0, 1);
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User
                && message.content == "second current plain prompt")
            .count(),
        1
    );
    assert_eq!(wire.barrier(), 3);
    wire.finish();
    assert_wire(&wire, 3);
}

#[test]
fn direct_ask_remains_one_selected_request() {
    let f = Fixture::new();
    let mut wire = Wire::new(&f.clock, vec![Reply::rejection(503)]);
    f.configure(&wire, 128000, false);
    let c = f.config(&wire, false);
    f.policy(&c, "ask-policy");
    let result = cli(
        &f,
        &[
            "ask",
            PROMPT,
            "--provider",
            "fixture",
            "--model",
            "model-a",
            "--gate",
            &c.gate,
        ],
    );
    assert!(!result.status.success());
    assert_eq!(wire.barrier(), 1);
    wire.finish();
    assert_wire(&wire, 1);
    assert!(!f.home.join("context-history").exists());
    assert!(sessions::list_sessions(&f.home).unwrap().is_empty());
}

#[test]
fn historical_unknown_bill_caps_stop_before_new_traffic() {
    let f = Fixture::new();
    let mut wire = Wire::new(&f.clock, vec![Reply::rejection(503), Reply::text(ANSWER)]);
    f.configure(&wire, 128000, false);
    let saved = seed_retry(&f, &wire);
    let before = f.accounting_bytes(&saved.session_id);
    let result = cli(
        &f,
        &[
            "-p",
            "new capped request",
            "--resume",
            &saved.session_id,
            "--max-cost",
            "1",
            "--output-format",
            "json",
        ],
    );
    assert!(!result.status.success());
    assert_eq!(f.accounting_bytes(&saved.session_id), before);
    assert_qualified(&f, &saved.session_id, 1, 0, 1);
    assert_eq!(wire.barrier(), 2);
    wire.finish();
    assert_wire(&wire, 2);
}

type PublicationObservation = Arc<Mutex<Option<(DetailedAccountingInspection, Vec<ChatMessage>)>>>;
fn archive_ids(home: &Path, id: &str) -> Vec<String> {
    let path = home.join("context-history").join(id).join("archives");
    let mut ids: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            entry
                .file_name()
                .to_str()
                .unwrap()
                .strip_suffix(".json")
                .unwrap()
                .to_owned()
        })
        .collect();
    ids.sort();
    ids
}
fn seed_history(f: &Fixture, wire: &Wire) -> SessionFile {
    let mut session = None;
    for index in 0..3 {
        let long = format!("historical question {index}: {}", "u".repeat(24000));
        let result = prompt(f, &long, session.as_deref());
        success(&result);
        session = Some(f.saved().session_id);
    }
    let id = session.unwrap();
    f.policy(&f.config(wire, false), "summary-seed");
    let result = prompt(f, PROMPT, Some(&id));
    success(&result);
    assert_eq!(notices(&result), 1);
    assert_qualified(f, &id, 4, 0, 1);
    let saved = f.saved();
    assert_eq!(saved.turns, 4);
    assert!(archive_ids(&f.home, &id).is_empty());
    saved
}
fn verify_summary_receipt(view: &DetailedAccountingInspection) {
    let receipt = view.last_legacy_receipt.as_ref().unwrap();
    assert!(receipt.completed);
    assert_ne!(receipt.purpose, AttemptPurpose::Ordinary);
    assert_eq!(receipt.usage, Some(usage()));
    assert_eq!(receipt.totals.cost_microcents, Some(17));
    let Some(DetailedLastSettlement::Legacy(last)) = view.checkpoint.last_settlement() else {
        panic!("actual summary last arm absent")
    };
    assert_eq!(last.reference.request_id, receipt.request_id);
    assert_eq!(last.receipt_digest, receipt.digest().unwrap());
}

#[test]
fn real_cli_refusal_then_manual_summary_preserves_exact_archive() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        vec![
            Reply::text(ANSWER),
            Reply::text(ANSWER),
            Reply::text(ANSWER),
            Reply::rejection(503),
            Reply::text(ANSWER),
            Reply::text(SUMMARY),
        ],
    );
    f.configure(&wire, 128000, false);
    let saved = seed_history(&f, &wire);
    let before = f.inspect(&saved.session_id);
    let original = saved.transcript.clone();
    f.configure(&wire, 10000, false);
    let result = cli(&f, &["compact", "--session", &saved.session_id, "--json"]);
    assert!(
        result.status.success(),
        "manual summary failed: {}",
        result.stderr
    );
    let value = result.json();
    assert_eq!(value["reason"], "published_ready");
    assert_eq!(value["status"], "completed");
    assert_eq!(value["applied"], true);
    assert_eq!(value["snapshot_saved"], true);
    assert_eq!(value["turns"], 4);
    assert_eq!(value["full_cost_status"], "unknown_usage");
    let after = f.saved();
    assert_eq!(after.turns, 4);
    assert_ne!(after.transcript, original);
    let prefix: Vec<_> = original
        .iter()
        .take_while(|message| message.role == ChatRole::System)
        .cloned()
        .collect();
    assert_eq!(&after.transcript[..prefix.len()], prefix.as_slice());
    assert!(original.ends_with(&after.transcript[prefix.len() + 2..]));
    assert!(
        after
            .transcript
            .iter()
            .any(|message| message.role == ChatRole::User && message.content == PROMPT)
    );
    let ids = archive_ids(&f.home, &saved.session_id);
    assert_eq!(ids.len(), 1);
    assert_eq!(
        load_compaction_source(&f.home, &saved.session_id, None, &ids[0]).unwrap(),
        original
    );
    let view = f.inspect(&saved.session_id);
    verify_summary_receipt(&view);
    assert_eq!(view.checkpoint.refusals(), before.checkpoint.refusals());
    assert_qualified(&f, &saved.session_id, 4, 1, 1);
    assert_eq!(wire.barrier(), 6);
    wire.finish();
    assert_wire(&wire, 6);
    let captures = wire.captures.lock().unwrap();
    let body: Value = serde_json::from_slice(&captures[5].body).unwrap();
    assert_eq!(body["model"], "summary-model");
    assert!(body.get("tools").is_none());
    assert_eq!(decisions(&f, &saved.session_id).len(), 6);
}

#[test]
fn real_cli_refusal_then_automatic_summary_after_policy_removal() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        vec![
            Reply::text(ANSWER),
            Reply::text(ANSWER),
            Reply::text(ANSWER),
            Reply::rejection(503),
            Reply::text(ANSWER),
            Reply::text(SUMMARY),
            Reply::text(ANSWER),
        ],
    );
    f.configure(&wire, 128000, false);
    let saved = seed_history(&f, &wire);
    let before = f.inspect(&saved.session_id);
    fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
    f.configure(&wire, 10000, false);
    let text = "new current ordinary prompt after removing policy";
    let mut original = saved.transcript.clone();
    original.push(orbit_engine::user_message(text));
    let publication: PublicationObservation = Arc::new(Mutex::new(None));
    let observed = publication.clone();
    let home = f.home.clone();
    let id = saved.session_id.clone();
    *wire.probe.lock().unwrap() = Some(Arc::new(move |ordinal, capture| {
        if ordinal == 7 {
            let body: Value = serde_json::from_slice(&capture.body).unwrap();
            assert_eq!(body["model"], "model-a");
            let view = inspect_accounting_detailed(&home, &id, None).unwrap();
            assert!(view.checkpoint.pending().is_some());
            verify_summary_receipt(&view);
            let records = archive_ids(&home, &id);
            assert_eq!(records.len(), 1);
            let source = load_compaction_source(&home, &id, None, &records[0]).unwrap();
            *observed.lock().unwrap() = Some((view, source));
        }
    }));
    let result = prompt(&f, text, Some(&saved.session_id));
    success(&result);
    assert_eq!(notices(&result), 0);
    let retained = publication
        .lock()
        .unwrap()
        .take()
        .expect("actual post-publication ordinary boundary not observed");
    assert_eq!(retained.1, original);
    assert_eq!(
        retained.0.checkpoint.refusals(),
        before.checkpoint.refusals()
    );
    let final_view = f.inspect(&saved.session_id);
    assert_eq!(
        final_view.last_legacy_receipt.as_ref().unwrap().purpose,
        AttemptPurpose::Ordinary
    );
    assert_ne!(
        retained.0.last_legacy_receipt,
        final_view.last_legacy_receipt
    );
    assert_eq!(result.json()["cost_microcents"], 30);
    assert_eq!(result.json()["full_cost_status"], "unknown_usage");
    assert_qualified(&f, &saved.session_id, 5, 1, 1);
    assert_eq!(f.saved().turns, 5);
    assert_eq!(wire.barrier(), 7);
    wire.finish();
    assert_wire(&wire, 7);
    let captures = wire.captures.lock().unwrap();
    let summary: Value = serde_json::from_slice(&captures[5].body).unwrap();
    assert_eq!(summary["model"], "summary-model");
    assert!(summary.get("tools").is_none());
    let ordinary: Value = serde_json::from_slice(&captures[6].body).unwrap();
    assert_eq!(ordinary["model"], "model-a");
    assert_eq!(
        ordinary["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "user" && message["content"] == text)
            .count(),
        1
    );
    assert_eq!(decisions(&f, &saved.session_id).len(), 7);
}

fn matching_ordinary_policy(f: &Fixture, wire: &Wire) {
    let config = f.config(wire, false);
    f.policy(&config, "admitted-policy");
    let selected = orbit_cli::provider_policies::load_for_config(&f.home, &config)
        .unwrap()
        .expect("exact ordinary policy absent");
    assert_eq!(selected.max_attempts(), 2);
}

fn matching_ordinary_and_summary_policies(f: &Fixture, wire: &Wire) {
    let ordinary = f.config(wire, false);
    let mut summary = ordinary.clone();
    summary.model = "summary-model".into();
    let mut document: toml::Value =
        toml::from_str(&policy_document(&ordinary, "summary-seed")).unwrap();
    let summary_document: toml::Value =
        toml::from_str(&policy_document(&summary, "summary-control")).unwrap();
    document["final_rejection"].as_array_mut().unwrap().extend(
        summary_document["final_rejection"]
            .as_array()
            .unwrap()
            .iter()
            .cloned(),
    );
    replace_owned(
        &f.home.join("provider-policies.toml"),
        toml::to_string(&document).unwrap(),
    );
    let first = orbit_cli::provider_policies::load_for_config(&f.home, &ordinary)
        .unwrap()
        .expect("exact ordinary declaration absent");
    let second = orbit_cli::provider_policies::load_for_config(&f.home, &summary)
        .unwrap()
        .expect("exact summary-model ordinary declaration absent");
    assert_eq!((first.max_attempts(), second.max_attempts()), (2, 2));
    assert_ne!(first.selection_digest(), second.selection_digest());
}

fn failed_stream_events(result: &CliResult) -> Vec<Value> {
    assert_eq!(result.status.code(), Some(1), "{}", result.stderr);
    let events: Vec<Value> = result
        .stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("actual event JSON"))
        .collect();
    assert!(events.len() <= 256);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "retrying")
            .count(),
        0
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "compacted")
            .count(),
        0
    );
    let terminal: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "turn_ended")
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0]["ok"], false);
    assert_eq!(terminal[0]["interrupted"], false);
    assert!(!result.stdout.contains("final rejection"));
    assert!(!result.stderr.contains("session not saved:"));
    assert!(!result.stderr.contains("process signal cleanup failed:"));
    events
}

fn uncertain_receipt(
    f: &Fixture,
    id: &str,
    purpose: AttemptPurpose,
    provisional: Option<ProviderUsage>,
) -> DetailedAccountingInspection {
    let observed = f.inspect(id);
    let checkpoint = &observed.checkpoint;
    assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
    assert_eq!(checkpoint.owner_session_id(), id);
    assert!(checkpoint.child_id().is_none());
    assert_eq!(
        checkpoint.totals().knownness,
        AccountingKnownness::Uncertain
    );
    let pending = checkpoint
        .pending()
        .expect("actual uncertain pending absent");
    assert!(pending.uncertain);
    assert_eq!(pending.intent.owner_session_id, id);
    assert!(pending.intent.child_id.is_none());
    assert_eq!(pending.intent.purpose, purpose);
    assert_eq!(pending.intent.request_id, pending.reference.request_id);
    assert!(pending.reference.revision.0 < checkpoint.revision().0);
    let receipt = observed
        .pending_receipt
        .as_ref()
        .expect("actual uncertainty receipt absent");
    receipt.validate().unwrap();
    assert_eq!(receipt.request_id, pending.reference.request_id);
    assert_eq!(receipt.purpose, purpose);
    assert_eq!(receipt.knownness, AccountingKnownness::Uncertain);
    assert!(!receipt.completed);
    assert_eq!(receipt.usage, provisional);
    assert_eq!(
        receipt.totals,
        AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None
        }
    );
    let saved = sessions::load_session(&f.home, id).unwrap();
    let anchor = saved.accounting_watermark.as_ref().unwrap();
    assert_eq!(anchor.owner_session_id, id);
    assert!(anchor.child_id.is_none());
    assert_eq!(anchor.revision, checkpoint.revision().0);
    assert_eq!(anchor.full_cost_status, FullCostStatus::Uncertain);
    assert_eq!(
        anchor.known_input_tokens,
        checkpoint.totals().ordinary.input_tokens + checkpoint.totals().housekeeping.input_tokens
    );
    assert_eq!(
        anchor.known_output_tokens,
        checkpoint.totals().ordinary.output_tokens + checkpoint.totals().housekeeping.output_tokens
    );
    let priced = checkpoint.known_priced_subtotals().unwrap();
    assert_eq!(anchor.known_ordinary_microcents, priced.ordinary_microcents);
    assert_eq!(
        anchor.known_housekeeping_microcents,
        priced.housekeeping_microcents
    );
    assert_eq!(
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        ),
        (
            anchor.known_input_tokens,
            anchor.known_output_tokens,
            priced.ordinary_microcents + priced.housekeeping_microcents
        )
    );
    let ids = decisions(f, id);
    assert_eq!(ids.last(), Some(&pending.reference.request_id));
    let bytes = f.accounting_bytes(id);
    assert_eq!(
        context_journal(&f.home, id, None)
            .unwrap()
            .accounting_checkpoint_detailed()
            .unwrap(),
        *checkpoint
    );
    assert_eq!(f.accounting_bytes(id), bytes);
    observed
}

fn refuse_pending_resume(f: &Fixture, wire: &Wire, id: &str, posts: usize) {
    let checkpoint = f.inspect(id);
    let accounting = f.accounting_bytes(id);
    let snapshot = read_owned(
        &sessions::sessions_dir(&f.home).join(format!("{id}.json")),
        131072,
    );
    let ids = decisions(f, id);
    assert_eq!(wire.barrier(), posts);
    let result = prompt(f, "do not replay this uncertain request", Some(id));
    assert!(!result.status.success());
    assert!(
        result
            .stderr
            .contains("pending uncertain request requires explicit inspection before admission")
    );
    assert!(!result.stderr.contains("process signal cleanup failed:"));
    assert_eq!(wire.barrier(), posts);
    assert_eq!(f.accounting_bytes(id), accounting);
    assert_eq!(f.inspect(id), checkpoint);
    assert_eq!(
        read_owned(
            &sessions::sessions_dir(&f.home).join(format!("{id}.json")),
            131072
        ),
        snapshot
    );
    assert_eq!(decisions(f, id), ids);
    drop(sessions::SessionLease::acquire(&f.home, id, "pending-replay-check").unwrap());
}

fn assert_uncertain_ordinary(
    f: &Fixture,
    wire: &Wire,
    partial: Option<&str>,
    provisional: Option<ProviderUsage>,
) {
    let saved = f.saved();
    assert_eq!(saved.turns, 1);
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User && message.content == PROMPT)
            .count(),
        1
    );
    if let Some(partial) = partial {
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.role == ChatRole::Assistant && message.content == partial)
                .count(),
            1
        );
    }
    let observed = uncertain_receipt(f, &saved.session_id, AttemptPurpose::Ordinary, provisional);
    assert!(observed.checkpoint.refusals().is_none());
    assert!(observed.checkpoint.last_settlement().is_none());
    assert!(observed.last_legacy_receipt.is_none());
    assert_eq!(
        observed.checkpoint.totals().ordinary,
        AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None
        }
    );
    assert_eq!(
        observed.checkpoint.totals().housekeeping,
        AccountingTotals::known_zero()
    );
    assert_eq!(
        observed.checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals::known_zero())
    );
    assert!(archive_ids(&f.home, &saved.session_id).is_empty());
    assert_eq!(decisions(f, &saved.session_id).len(), 1);
    assert_wire(wire, 1);
    refuse_pending_resume(f, wire, &saved.session_id, 1);
}

#[test]
fn declared_policy_admitted_idle_stays_uncertain_without_replay() {
    let f = Fixture::new();
    let (held, control) = Reply::partial("", false).held();
    let mut wire = Wire::new(&f.clock, vec![held, Reply::text(ANSWER)]);
    f.configure(&wire, 128000, false);
    matching_ordinary_policy(&f, &wire);
    let process = Process::start_with_timeouts(
        &f,
        &["-p", PROMPT, "--output-format", "stream-json"],
        Some((1000, 1000)),
    );
    control.wait();
    let result = process.wait_after_reap(&f, || {
        control.release();
        assert_eq!(wire.barrier(), 1);
    });
    let events = failed_stream_events(&result);
    let deltas: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event["type"] == "text_delta")
        .collect();
    assert_eq!(
        deltas.len(),
        1,
        "the admitted prefix must produce exactly one delta"
    );
    assert_eq!(deltas[0].1["text"], "");
    let error_position = events
        .iter()
        .position(|event| event["type"] == "error")
        .expect("actual idle error event absent");
    let terminal_position = events
        .iter()
        .position(|event| event["type"] == "turn_ended")
        .unwrap();
    assert!(deltas[0].0 < error_position && deltas[0].0 < terminal_position);
    assert!(
        events
            .iter()
            .enumerate()
            .filter(|(_, event)| event["type"] == "error" || event["type"] == "turn_ended")
            .all(|(position, _)| deltas[0].0 < position)
    );
    assert!(result.stdout.contains("E0409") || result.stderr.contains("E0409"));
    assert_uncertain_ordinary(&f, &wire, None, None);
    wire.finish();
    assert_wire(&wire, 1);
}

#[test]
fn declared_policy_partial_ordinary_retains_provisional_usage_without_replay() {
    let f = Fixture::new();
    let partial = "visible controlled incomplete ordinary text";
    let mut wire = Wire::new(
        &f.clock,
        vec![Reply::partial(partial, true), Reply::text(ANSWER)],
    );
    f.configure(&wire, 128000, false);
    matching_ordinary_policy(&f, &wire);
    let result = cli(&f, &["-p", PROMPT, "--output-format", "stream-json"]);
    let events = failed_stream_events(&result);
    let emitted: String = events
        .iter()
        .filter(|event| event["type"] == "text_delta")
        .map(|event| event["text"].as_str().unwrap())
        .collect();
    assert_eq!(emitted, partial);
    assert_uncertain_ordinary(&f, &wire, Some(partial), Some(usage()));
    wire.finish();
    assert_wire(&wire, 1);
}

#[test]
fn declared_policy_truncated_503_stays_uncertain_without_replay() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        vec![
            Reply::incomplete(503, b"controlled truncated rejection".to_vec()),
            Reply::text(ANSWER),
        ],
    );
    f.configure(&wire, 128000, false);
    matching_ordinary_policy(&f, &wire);
    let result = cli(&f, &["-p", PROMPT, "--output-format", "stream-json"]);
    failed_stream_events(&result);
    assert_uncertain_ordinary(&f, &wire, None, None);
    wire.finish();
    assert_wire(&wire, 1);
}

struct SummaryBaseline {
    saved: SessionFile,
    view: DetailedAccountingInspection,
    accounting: Vec<u8>,
    ledger: Vec<String>,
    archives: Vec<String>,
}

fn summary_failure_seed(f: &Fixture, wire: &Wire) -> SummaryBaseline {
    f.configure(wire, 128000, false);
    let saved = seed_history(f, wire);
    let view = f.inspect(&saved.session_id);
    let accounting = f.accounting_bytes(&saved.session_id);
    let ledger = decisions(f, &saved.session_id);
    let archives = archive_ids(&f.home, &saved.session_id);
    assert_eq!(wire.barrier(), 5);
    assert_eq!(ledger.len(), 5);
    assert!(archives.is_empty());
    let last = view.last_legacy_receipt.as_ref().unwrap();
    assert_eq!(last.purpose, AttemptPurpose::Ordinary);
    assert!(last.completed);
    assert_eq!(last.usage, Some(usage()));
    let Some(DetailedLastSettlement::Legacy(settlement)) = view.checkpoint.last_settlement() else {
        panic!("genuine historical ordinary Legacy settlement absent")
    };
    assert_eq!(settlement.reference.request_id, last.request_id);
    assert_eq!(settlement.receipt_digest, last.digest().unwrap());
    assert_eq!(ledger.last(), Some(&last.request_id));
    assert_eq!(view.checkpoint.refusals().unwrap().count(), 1);
    assert_eq!(
        ledger[3],
        view.checkpoint
            .refusals()
            .unwrap()
            .latest()
            .binding()
            .decision_id()
    );
    f.configure(wire, 10000, false);
    matching_ordinary_and_summary_policies(f, wire);
    SummaryBaseline {
        saved,
        view,
        accounting,
        ledger,
        archives,
    }
}

fn summary_failure_replies(failure: Reply) -> Vec<Reply> {
    vec![
        Reply::text(ANSWER),
        Reply::text(ANSWER),
        Reply::text(ANSWER),
        Reply::rejection(503),
        Reply::text(ANSWER),
        failure,
        Reply::text(SUMMARY),
    ]
}

fn assert_uncertain_summary(
    f: &Fixture,
    wire: &Wire,
    before: &SummaryBaseline,
    current: Option<&str>,
    provisional: Option<ProviderUsage>,
) {
    let id = &before.saved.session_id;
    let saved = f.saved();
    assert_eq!(saved.session_id, *id);
    let mut source = before.saved.transcript.clone();
    if let Some(current) = current {
        source.push(orbit_engine::user_message(current));
        assert_eq!(
            source
                .iter()
                .filter(|message| message.role == ChatRole::User && message.content == current)
                .count(),
            1
        );
    }
    assert_eq!(saved.transcript, source);
    assert_eq!(
        saved.turns,
        before.saved.turns + u64::from(current.is_some())
    );
    assert_eq!(
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        ),
        (44, 28, 52)
    );
    assert_eq!(saved.model, before.saved.model);
    assert_eq!(saved.provider, before.saved.provider);
    assert_eq!(saved.gate, before.saved.gate);
    assert_eq!(saved.effort, before.saved.effort);
    assert_eq!(archive_ids(&f.home, id), before.archives);
    let view = uncertain_receipt(f, id, AttemptPurpose::Chunk, provisional);
    assert_eq!(
        view.checkpoint.refusals(),
        before.view.checkpoint.refusals()
    );
    assert_eq!(
        view.checkpoint.last_settlement(),
        before.view.checkpoint.last_settlement()
    );
    assert_eq!(view.last_legacy_receipt, before.view.last_legacy_receipt);
    assert_eq!(
        view.checkpoint.totals().ordinary,
        before.view.checkpoint.totals().ordinary
    );
    assert_eq!(
        view.checkpoint.totals().housekeeping,
        AccountingTotals {
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: None
        }
    );
    assert_eq!(
        view.checkpoint.known_priced_subtotals(),
        before.view.checkpoint.known_priced_subtotals()
    );
    assert_eq!(
        view.checkpoint.known_priced_subtotals(),
        Some(KnownPricedSubtotals {
            ordinary_microcents: 52,
            housekeeping_microcents: 0
        })
    );
    assert!(view.checkpoint.revision().0 > before.view.checkpoint.revision().0);
    let pending = view.checkpoint.pending().unwrap();
    let Some(DetailedLastSettlement::Legacy(last)) = before.view.checkpoint.last_settlement()
    else {
        panic!("historical ordinary last settlement missing")
    };
    assert!(pending.reference.revision.0 > last.reference.revision.0);
    assert_ne!(pending.reference.request_id, last.reference.request_id);
    let ledger = decisions(f, id);
    assert_eq!(&ledger[..5], before.ledger.as_slice());
    assert_eq!(ledger.len(), 6);
    assert_ne!(f.accounting_bytes(id), before.accounting);
    assert_wire(wire, 6);
    {
        let captures = wire.captures.lock().unwrap();
        let summary: Value = serde_json::from_slice(&captures[5].body).unwrap();
        assert_eq!(summary["model"], "summary-model");
        assert!(summary.get("tools").is_none());
    }
    drop(sessions::SessionLease::acquire(&f.home, id, "summary-uncertainty-check").unwrap());
    refuse_pending_resume(f, wire, id, 6);
}

fn failed_manual_summary(result: &CliResult, cancelled: bool) {
    assert_eq!(
        result.status.code(),
        Some(if cancelled { 143 } else { 1 }),
        "{}",
        result.stderr
    );
    let value = result.json();
    assert_eq!(value["command"], "compact");
    assert_eq!(value["status"], "unknown");
    assert_eq!(value["applied"], false);
    assert_eq!(value["snapshot_saved"], true);
    assert_eq!(value["turns"], 4);
    assert_eq!(value["full_cost_status"], "uncertain");
    if cancelled {
        assert_eq!(value["reason"], "cancelled");
    }
    assert!(!result.stdout.contains("final rejection"));
    assert!(!result.stdout.contains(SUMMARY));
    assert!(!result.stderr.contains("session not saved:"));
    assert!(!result.stderr.contains("process signal cleanup failed:"));
}

#[test]
fn real_cli_post_refusal_manual_503_summary_does_not_retry() {
    let f = Fixture::new();
    let mut wire = Wire::new(&f.clock, summary_failure_replies(Reply::rejection(503)));
    let before = summary_failure_seed(&f, &wire);
    let result = cli(
        &f,
        &["compact", "--session", &before.saved.session_id, "--json"],
    );
    failed_manual_summary(&result, false);
    assert_uncertain_summary(&f, &wire, &before, None, None);
    wire.finish();
    assert_wire(&wire, 6);
}

#[test]
fn real_cli_post_refusal_manual_partial_summary_keeps_provisional_usage() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        summary_failure_replies(Reply::partial(SUMMARY, true)),
    );
    let before = summary_failure_seed(&f, &wire);
    let result = cli(
        &f,
        &["compact", "--session", &before.saved.session_id, "--json"],
    );
    failed_manual_summary(&result, false);
    assert_uncertain_summary(&f, &wire, &before, None, Some(usage()));
    wire.finish();
    assert_wire(&wire, 6);
}

#[test]
fn real_cli_post_refusal_manual_sigterm_summary_preserves_source() {
    let f = Fixture::new();
    let (held, control) = Reply::partial("", false).held();
    let mut wire = Wire::new(&f.clock, summary_failure_replies(held));
    let before = summary_failure_seed(&f, &wire);
    let mut process = Process::start(
        &f,
        &["compact", "--session", &before.saved.session_id, "--json"],
    );
    control.wait();
    process.live();
    assert!(matches!(
        sessions::SessionLease::acquire(&f.home, &before.saved.session_id, "held-summary-check"),
        Err(sessions::SessionLeaseError::Busy { .. })
    ));
    process.terminate();
    let result = process.wait_after_reap(&f, || {
        control.release();
        assert_eq!(wire.barrier(), 6);
    });
    failed_manual_summary(&result, true);
    assert_uncertain_summary(&f, &wire, &before, None, None);
    wire.finish();
    assert_wire(&wire, 6);
}

#[test]
fn real_cli_post_refusal_automatic_partial_summary_blocks_ordinary_replay() {
    let f = Fixture::new();
    let mut wire = Wire::new(
        &f.clock,
        summary_failure_replies(Reply::partial(SUMMARY, true)),
    );
    let before = summary_failure_seed(&f, &wire);
    let current = "new current intent before ambiguous automatic summary";
    let result = cli(
        &f,
        &[
            "-p",
            current,
            "--resume",
            &before.saved.session_id,
            "--output-format",
            "stream-json",
        ],
    );
    failed_stream_events(&result);
    assert!(!result.stdout.contains(SUMMARY));
    assert!(!result.stderr.contains(SUMMARY));
    assert_uncertain_summary(&f, &wire, &before, Some(current), Some(usage()));
    wire.finish();
    assert_wire(&wire, 6);
}
