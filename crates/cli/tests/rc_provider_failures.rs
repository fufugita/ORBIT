#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::types::{ChatRole, ProviderUsage};
use orbit_cli::context_history::inspect_accounting_detailed;
use orbit_cli::sessions;
use orbit_engine::compaction::{
    AccountingBaseline, AccountingKnownness, AccountingTotals, AttemptPurpose,
};
use orbit_engine::retry::DetailedLastSettlement;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROMPT: &str = "say the exact controlled greeting";
const ANSWER: &str = "controlled response deadline greeting";
const MODEL: &str = "fixture-model";
const UNSELECTED_MODEL: &str = "unselected-model";
const KEY_ENV: &str = "PR01_FIXTURE_KEY";
const KEY: &str = "synthetic-pr01-key";
const HEADER_DELAY: Duration = Duration::from_millis(11250);
const CHILD_BUDGET: Duration = Duration::from_secs(35);
const SERVER_BUDGET: Duration = Duration::from_secs(40);
const WATCHDOG_BUDGET: Duration = Duration::from_secs(45);
const CLEANUP_BUDGET: Duration = Duration::from_secs(4);
const OUTPUT_CAP: u64 = 2 * 1024 * 1024;
const BODY_CAP: usize = 1024 * 1024;
const HEADER_CAP: usize = 16384;
const COMPILED_SOURCE: &[u8] = include_bytes!("rc_provider_failures.rs");

fn private_system_root() -> PathBuf {
    assert_eq!(
        std::env::var("ORBIT_ACTIVATION_ISOLATED").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("ORBIT_ACTIVATION_RUNNER_DEPTH").as_deref(),
        Ok("1")
    );
    let descriptor = |name: &str| {
        let fd: u32 = std::env::var(name)
            .expect("private descriptor")
            .parse()
            .unwrap();
        assert!(fd < 4096);
        fs::metadata(format!("/proc/self/fd/{fd}")).unwrap()
    };
    for (name, current) in [
        ("ORBIT_ACTIVATION_PARENT_MOUNT_FD", "/proc/self/ns/mnt"),
        ("ORBIT_ACTIVATION_PARENT_USER_FD", "/proc/self/ns/user"),
    ] {
        let original = descriptor(name);
        let own = fs::metadata(current).unwrap();
        assert_ne!((original.dev(), original.ino()), (own.dev(), own.ino()));
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    for (point, kind) in [("/etc", "tmpfs"), ("/proc", "proc")] {
        assert!(
            mounts
                .lines()
                .any(|line| line.split_whitespace().nth(4) == Some(point)
                    && line.contains(&format!(" - {kind} ")))
        );
    }
    let marker = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
    assert!(
        marker.starts_with("ORBIT_ACTIVATION_MANAGED_")
            && marker.len() <= 128
            && marker
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    );
    let managed = Path::new("/etc/orbit/ORBIT.md");
    let stat = fs::symlink_metadata(managed).unwrap();
    assert!(stat.is_file() && !stat.file_type().is_symlink());
    assert_eq!((stat.mode() & 0o777, stat.nlink()), (0o600, 1));
    assert!(stat.len() <= 128);
    assert_eq!(fs::read(managed).unwrap(), marker.as_bytes());
    assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
    let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap());
    assert!(
        root.is_absolute()
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("oc-")
    );
    assert_eq!(root.canonicalize().unwrap(), root);
    let stat = fs::symlink_metadata(&root).unwrap();
    assert!(stat.is_dir() && !stat.file_type().is_symlink());
    assert_eq!(stat.mode() & 0o777, 0o700);
    for name in [
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        let path = PathBuf::from(std::env::var_os(name).unwrap());
        assert!(path.is_absolute() && path.starts_with(&root) && path != root);
        assert_eq!(path.canonicalize().unwrap(), path);
        let stat = fs::symlink_metadata(path).unwrap();
        assert!(stat.is_dir() && !stat.file_type().is_symlink());
        assert_eq!(stat.mode() & 0o777, 0o700);
    }
    assert!(std::env::current_dir().unwrap().starts_with(&root));
    for name in [
        "ORBIT_HOME",
        "ORBIT_GATE_TOKEN",
        "ORBIT_TEST_FIRST_BYTE_TIMEOUT_MS",
        "ORBIT_TEST_IDLE_TIMEOUT_MS",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        KEY_ENV,
    ] {
        assert!(
            std::env::var_os(name).is_none(),
            "uncleared caller environment: {name}"
        );
    }
    root
}

#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    stat: FileStamp,
    digest: Vec<u8>,
}

type FileStamp = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn stamp(m: &fs::Metadata) -> FileStamp {
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
}

fn fingerprint(path: &Path, executable: bool, source: Option<&[u8]>) -> Fingerprint {
    assert!(path.is_absolute());
    assert_eq!(path.canonicalize().unwrap(), path);
    let before = fs::symlink_metadata(path).unwrap();
    assert!(before.is_file() && !before.file_type().is_symlink());
    assert_eq!(
        before.uid(),
        fs::metadata(std::env::var_os("HOME").unwrap())
            .unwrap()
            .uid()
    );
    assert!(before.len() > 0 && before.len() <= 1024 * 1024 * 1024);
    if executable {
        assert_ne!(before.mode() & 0o111, 0);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    assert_eq!(stamp(&file.metadata().unwrap()), stamp(&before));
    let mut digest = Sha256::new();
    let mut block = vec![0u8; 1024 * 1024];
    let mut count = 0usize;
    loop {
        let n = file.read(&mut block).unwrap();
        if n == 0 {
            break;
        }
        if let Some(expected) = source {
            assert!(count.checked_add(n).unwrap() <= expected.len());
            assert_eq!(&block[..n], &expected[count..count + n]);
        }
        count = count.checked_add(n).unwrap();
        assert!(count as u64 <= before.len());
        digest.update(&block[..n]);
    }
    assert_eq!(count as u64, before.len());
    if let Some(expected) = source {
        assert_eq!(count, expected.len());
    }
    assert_eq!(stamp(&file.metadata().unwrap()), stamp(&before));
    assert_eq!(stamp(&fs::symlink_metadata(path).unwrap()), stamp(&before));
    Fingerprint {
        stat: stamp(&before),
        digest: digest.finalize().to_vec(),
    }
}

fn private_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) -> File {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file
}

struct Home {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
}
impl Home {
    fn new(private: &Path) -> Self {
        let root = private.join(format!("pr01-cli-{}", ulid::Ulid::new()));
        private_dir(&root);
        let home = root.join("home");
        let work = root.join("work");
        private_dir(&home);
        private_dir(&work);
        let owned = Self { root, home, work };
        let plan =
            orbit_cli::setup::plan_setup(&owned.home, &orbit_cli::setup::SetupRequest::default())
                .unwrap();
        orbit_cli::setup::apply_setup(&plan).unwrap();
        owned
    }
    fn configure(&self, authority: &str) -> Vec<u8> {
        let model = |id: &str, cap: u32| {
            let mut value = json!({"id":id,"max_output_tokens":cap,
            "context_limits":{"input_tokens":128000},
            "pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,
                "cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,
                "reasoning_per_million_microdollars":0,"request_flat_microdollars":0}});
            if id == MODEL {
                value["billing"] = json!({"version":2,"input_per_million_microdollars":0,
                    "output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,
                    "cache_write_per_million_microdollars":0,"request_flat_microdollars":0,
                    "reasoning_counter_basis":"included_in_output","reasoning_rate_policy":"output_rate"});
            }
            value
        };
        let config: orbit_cli::config::ProvidersConfig = serde_json::from_value(json!({
            "provider":[
                {"name":"unselected","kind":"openai-compatible",
                    "url":format!("http://{authority}/unused/v1"),"env":KEY_ENV,
                    "models":[model(UNSELECTED_MODEL, 19)]},
                {"name":"fixture","kind":"openai-compatible",
                    "url":format!("http://{authority}/pr01/v1"),"env":KEY_ENV,
                    "models":[model(MODEL, 73)]}],
            "roles":{"main":format!("fixture/{MODEL}")}
        }))
        .unwrap();
        let data = toml::to_string(&config).unwrap().into_bytes();
        let path = self.home.join("providers.toml");
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        drop(private_file(&path, &data));
        data
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Watchdog {
    fn new() -> Self {
        let (done, wait) = mpsc::channel();
        let thread = thread::spawn(move || {
            if matches!(
                wait.recv_timeout(WATCHDOG_BUDGET),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("PR01 independent live-work watchdog exceeded45s");
                std::process::exit(90);
            }
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[derive(Debug)]
struct Capture {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
#[derive(Debug, Default)]
struct WireResult {
    connections: usize,
    posts: usize,
    capture: Option<Capture>,
    accepted: Option<Duration>,
    captured: Option<Duration>,
    capture_ready: bool,
    header_attempt: Option<Duration>,
    header_published: Option<Duration>,
    body_published: Option<Duration>,
    response_attempt_complete: bool,
    peer_closed: Option<Duration>,
    peer_close_acknowledged: bool,
    listener_poll_barrier: bool,
    write_error: Option<io::ErrorKind>,
    error: Option<&'static str>,
}
struct WireControl {
    stop: Mutex<bool>,
    wake: Condvar,
}
struct Wire {
    authority: String,
    started: Instant,
    control: Arc<WireControl>,
    state: Arc<Mutex<WireResult>>,
    thread: Option<JoinHandle<()>>,
}

fn interrupted(control: &WireControl) -> bool {
    *control.stop.lock().unwrap()
}
fn pause(control: &WireControl) {
    let stop = control.stop.lock().unwrap();
    let _guard = control
        .wake
        .wait_timeout(stop, Duration::from_millis(5))
        .unwrap();
}
fn extras(listener: &TcpListener, state: &Mutex<WireResult>) -> Result<(), &'static str> {
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                let mut result = state.lock().unwrap();
                result.connections += 1;
                result.error = Some("unexpected additional connection");
                drop(socket);
                if result.connections > 8 {
                    return Err("unexpected connection bound");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err("extra accept failure"),
        }
    }
}

fn read_request(socket: &mut TcpStream, control: &WireControl) -> Result<Capture, &'static str> {
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| "read timeout setup")?;
    let end = Instant::now() + Duration::from_secs(3);
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        if interrupted(control) || Instant::now() >= end {
            return Err("request header deadline");
        }
        if headers.len() >= HEADER_CAP {
            return Err("request header bound");
        }
        match socket.read(&mut byte) {
            Ok(0) => return Err("request header EOF"),
            Ok(_) => headers.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("request header read"),
        }
    }
    let text = std::str::from_utf8(&headers).map_err(|_| "header encoding")?;
    let mut lines = text.split("\r\n");
    let target = lines.next().ok_or("missing request line")?.to_owned();
    if !target.starts_with("POST ") || !target.ends_with(" HTTP/1.1") {
        return Err("request line shape");
    }
    let mut parsed = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or("header separator")?;
        parsed.push((key.to_ascii_lowercase(), value.trim().to_owned()));
    }
    if parsed.iter().any(|(key, _)| key == "transfer-encoding") {
        return Err("unexpected request chunking");
    }
    let lengths = parsed
        .iter()
        .filter(|(key, _)| key == "content-length")
        .map(|(_, value)| value.parse::<usize>().map_err(|_| "request length"))
        .collect::<Result<Vec<_>, _>>()?;
    if lengths.len() != 1 || lengths[0] == 0 || lengths[0] > BODY_CAP {
        return Err("request body bound");
    }
    let mut body = vec![0; lengths[0]];
    let mut offset = 0;
    while offset < body.len() {
        if interrupted(control) || Instant::now() >= end {
            return Err("request body deadline");
        }
        match socket.read(&mut body[offset..]) {
            Ok(0) => return Err("request body EOF"),
            Ok(n) => offset += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err("request body read"),
        }
    }
    serde_json::from_slice::<Value>(&body).map_err(|_| "request body JSON")?;
    Ok(Capture {
        target,
        headers: parsed,
        body,
    })
}

fn validate_capture(capture: &Capture, authority: &str) -> Result<(), &'static str> {
    if capture.target != "POST /pr01/v1/chat/completions HTTP/1.1" {
        return Err("exact selected request path/query");
    }
    let authorization = format!("Bearer {KEY}");
    for (name, expected) in [
        ("host", authority),
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
    ] {
        let values = capture
            .headers
            .iter()
            .filter_map(|(key, value)| (key == name).then_some(value.as_str()))
            .collect::<Vec<_>>();
        if values != [expected] {
            return Err("selected host/credential/content-type");
        }
    }
    let body: Value = serde_json::from_slice(&capture.body).map_err(|_| "selected request JSON")?;
    let object = body.as_object().ok_or("selected request object")?;
    if body["model"] != MODEL
        || body["max_tokens"] != 73
        || body["stream"] != true
        || body["stream_options"] != json!({"include_usage":true})
    {
        return Err("selected model/output/stream controls");
    }
    // Current dispatch maps omitted model sampling to zero, and the encoder
    // omits those controls; no default effort was configured for this model.
    if ["temperature", "top_p", "reasoning_effort"]
        .iter()
        .any(|key| object.contains_key(*key))
    {
        return Err("unselected sampling/effort controls reached wire");
    }
    let messages = body["messages"]
        .as_array()
        .ok_or("selected messages array")?;
    let users = messages
        .iter()
        .filter(|message| message["role"] == "user")
        .collect::<Vec<_>>();
    if users.len() != 1 || users[0]["content"] != PROMPT {
        return Err("exact single current user prompt");
    }
    Ok(())
}

fn peek_peer(
    socket: &TcpStream,
    state: &Mutex<WireResult>,
    started: Instant,
) -> Result<(), &'static str> {
    if state.lock().unwrap().peer_closed.is_some() {
        return Ok(());
    }
    match socket.peek(&mut [0u8; 1]) {
        Ok(0) => {
            state
                .lock()
                .unwrap()
                .peer_closed
                .get_or_insert(started.elapsed());
            Ok(())
        }
        Ok(_) => Err("unexpected bytes after complete request"),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            state
                .lock()
                .unwrap()
                .peer_closed
                .get_or_insert(started.elapsed());
            Ok(())
        }
        Err(_) => Err("peer close observation"),
    }
}

fn write_bounded(socket: &mut TcpStream, bytes: &[u8], control: &WireControl) -> io::Result<()> {
    let end = Instant::now() + Duration::from_secs(2);
    let mut offset = 0;
    while offset < bytes.len() {
        if interrupted(control) || Instant::now() >= end {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        match socket.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(control),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn serve(
    listener: TcpListener,
    control: &WireControl,
    state: &Mutex<WireResult>,
    started: Instant,
    delay: Duration,
) -> Result<(), &'static str> {
    let mut socket = loop {
        if interrupted(control) {
            return Ok(());
        }
        if started.elapsed() >= SERVER_BUDGET {
            return Err("server lifetime");
        }
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(control),
            Err(_) => return Err("initial accept"),
        }
    };
    {
        let mut result = state.lock().unwrap();
        result.connections = 1;
        result.accepted = Some(started.elapsed());
    }
    let capture = read_request(&mut socket, control)?;
    let authority = listener
        .local_addr()
        .map_err(|_| "selected fixture authority")?
        .to_string();
    validate_capture(&capture, &authority)?;
    let captured = started.elapsed();
    {
        let mut result = state.lock().unwrap();
        result.posts = 1;
        result.capture = Some(capture);
        result.captured = Some(captured);
        result.capture_ready = true;
    }
    control.wake.notify_all();
    socket
        .set_nonblocking(true)
        .map_err(|_| "response nonblocking setup")?;
    while started.elapsed() < captured + delay {
        if interrupted(control) {
            return Err("stopped before scheduled headers");
        }
        if started.elapsed() >= SERVER_BUDGET {
            return Err("header lifetime");
        }
        extras(&listener, state)?;
        peek_peer(&socket, state, started)?;
        pause(control);
    }
    extras(&listener, state)?;
    state.lock().unwrap().header_attempt = Some(started.elapsed());
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({
            "choices":[{"index":0,"delta":{"content":ANSWER},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}
        })
    );
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    match write_bounded(&mut socket, headers.as_bytes(), control) {
        Ok(()) => {
            state.lock().unwrap().header_published = Some(started.elapsed());
            match write_bounded(&mut socket, body.as_bytes(), control) {
                Ok(()) => state.lock().unwrap().body_published = Some(started.elapsed()),
                Err(error) => state.lock().unwrap().write_error = Some(error.kind()),
            }
        }
        Err(error) => state.lock().unwrap().write_error = Some(error.kind()),
    }
    state.lock().unwrap().response_attempt_complete = true;
    loop {
        extras(&listener, state)?;
        peek_peer(&socket, state, started)?;
        if state.lock().unwrap().peer_closed.is_some() {
            // A real EOF/reset and an additional listener drain acknowledge
            // completion; the owner must observe this before normal stop.
            extras(&listener, state)?;
            let mut result = state.lock().unwrap();
            result.peer_close_acknowledged = true;
            result.listener_poll_barrier = true;
            drop(result);
            control.wake.notify_all();
        }
        if interrupted(control) {
            extras(&listener, state)?;
            return Ok(());
        }
        if started.elapsed() >= SERVER_BUDGET {
            return Err("post-response lifetime");
        }
        pause(control);
    }
}

impl Wire {
    fn start(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let started = Instant::now();
        let control = Arc::new(WireControl {
            stop: Mutex::new(false),
            wake: Condvar::new(),
        });
        let state = Arc::new(Mutex::new(WireResult::default()));
        let (thread_control, thread_state) = (control.clone(), state.clone());
        let thread = thread::spawn(move || {
            if let Err(error) = serve(listener, &thread_control, &thread_state, started, delay) {
                thread_state.lock().unwrap().error = Some(error);
            }
        });
        Self {
            authority,
            started,
            control,
            state,
            thread: Some(thread),
        }
    }
    fn finish(&mut self) {
        self.close(true);
    }
    fn abort(&mut self) {
        self.close(false);
    }
    fn close(&mut self, require_complete: bool) {
        let Some(thread) = self.thread.as_ref() else {
            return;
        };
        if require_complete {
            // A10s old-client close must not cancel the11.25s measured header
            // attempt. Reap precedes this wait; normal stop additionally needs
            // actual peer-close plus the worker's final listener-poll barrier.
            loop {
                let complete = {
                    let state = self.state.lock().unwrap();
                    state.response_attempt_complete
                        && state.peer_close_acknowledged
                        && state.listener_poll_barrier
                };
                if complete {
                    break;
                }
                if self.started.elapsed() >= SERVER_BUDGET || thread.is_finished() {
                    self.state
                        .lock()
                        .unwrap()
                        .error
                        .get_or_insert("publication/peer-close barrier incomplete");
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        *self.control.stop.lock().unwrap() = true;
        self.control.wake.notify_all();
        let until = Instant::now() + CLEANUP_BUDGET;
        while !self.thread.as_ref().unwrap().is_finished() {
            if Instant::now() >= until {
                eprintln!("PR01 owned socket/thread cleanup did not finish");
                std::process::exit(91);
            }
            thread::sleep(Duration::from_millis(5));
        }
        if self.thread.take().unwrap().join().is_err() {
            eprintln!("PR01 owned server panicked");
            std::process::exit(91);
        }
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.abort();
        }
    }
}

// The saved group is minted by this owned child's process_group(0), never read
// from a file, fixture message, old receipt or port lookup.
#[allow(unsafe_code)]
fn group_signal(group: u32, signal: i32) -> io::Result<()> {
    let group = i32::try_from(group).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if group <= 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: a positive, bounded owned child PID is negated to address its
    // newly created process group. Signal0 only observes; SIGKILL is used only
    // while its owned leader has not been positively reaped.
    if unsafe { libc::kill(-group, signal) } == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

struct OwnedChild {
    child: Child,
    group: u32,
    status: Option<ExitStatus>,
    cleaned: bool,
}
impl OwnedChild {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        let child = command.spawn()?;
        let group = child.id();
        Ok(Self {
            child,
            group,
            status: None,
            cleaned: false,
        })
    }
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }
    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        if self.status.is_none() {
            match self.child.try_wait() {
                Ok(Some(status)) => self.status = Some(status),
                Ok(None) => {
                    if let Err(error) = group_signal(self.group, libc::SIGKILL)
                        && error.raw_os_error() != Some(libc::ESRCH)
                    {
                        eprintln!("PR01 owned group signal failed: {error}");
                        std::process::exit(92);
                    }
                    let _ = self.child.kill();
                }
                Err(error) => {
                    eprintln!("PR01 owned child state failed: {error}");
                    std::process::exit(92);
                }
            }
        }
        let until = Instant::now() + CLEANUP_BUDGET;
        while self.status.is_none() {
            match self.child.try_wait() {
                Ok(Some(status)) => self.status = Some(status),
                Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(5)),
                result => {
                    eprintln!("PR01 owned child could not be positively reaped: {result:?}");
                    std::process::exit(92);
                }
            }
        }
        // After positive reap no signal that mutates a process is authorized.
        // A surviving group is an infrastructure failure, not a guessed cleanup.
        match group_signal(self.group, 0) {
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            result => {
                eprintln!("PR01 owned group still observable after reap: {result:?}");
                std::process::exit(92);
            }
        }
        self.cleaned = true;
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[derive(Debug)]
struct CliResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    runtime: Duration,
    spawn_started: Duration,
    spawned: Duration,
    returned: Duration,
}

fn read_output(path: &Path) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.mode() & 0o777 != 0o600
        || before.len() > OUTPUT_CAP
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if stamp(&file.metadata()?) != stamp(&before) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(OUTPUT_CAP + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 != before.len()
        || stamp(&file.metadata()?) != stamp(&before)
        || stamp(&fs::symlink_metadata(path)?) != stamp(&before)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(data)
}

fn run_cli(binary: &Path, home: &Home, origin: Instant) -> Result<CliResult, String> {
    let out = home.root.join("stdout");
    let err = home.root.join("stderr");
    let mut command = Command::new(binary);
    command
        .args(["-p", PROMPT, "--output-format", "json", "--home"])
        .arg(&home.home)
        .current_dir(&home.work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env(KEY_ENV, KEY)
        .stdin(Stdio::null())
        .stdout(private_file(&out, b""))
        .stderr(private_file(&err, b""))
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
        command.env(
            name,
            std::env::var_os(name).ok_or("private child environment")?,
        );
    }
    let spawn_started = origin.elapsed();
    let mut child =
        OwnedChild::spawn(&mut command).map_err(|error| format!("CLI spawn: {error}"))?;
    let spawned = origin.elapsed();
    let started = Instant::now();
    let mut failure = None;
    loop {
        match child.poll() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                failure = Some(format!("child poll: {error}"));
                break;
            }
        }
        if started.elapsed() >= CHILD_BUDGET {
            failure = Some("35s CLI lifetime".into());
            break;
        }
        let combined = fs::metadata(&out).and_then(|stdout| {
            fs::metadata(&err).map(|stderr| stdout.len().saturating_add(stderr.len()))
        });
        if !matches!(combined, Ok(length) if length <= OUTPUT_CAP) {
            failure = Some("CLI aggregate output bound".into());
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let runtime = started.elapsed();
    let returned = origin.elapsed();
    child.cleanup();
    let status = child.status.unwrap();
    drop(child);
    if let Some(failure) = failure {
        return Err(failure);
    }
    let stdout = read_output(&out).map_err(|e| e.to_string())?;
    let stderr = read_output(&err).map_err(|e| e.to_string())?;
    if (stdout.len() as u64).saturating_add(stderr.len() as u64) > OUTPUT_CAP {
        return Err("CLI final aggregate output bound".into());
    }
    Ok(CliResult {
        status,
        stdout,
        stderr,
        runtime,
        spawn_started,
        spawned,
        returned,
    })
}

fn actual_default_case(delay: Duration) {
    let private = private_system_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_orbit"));
    let test_binary = std::env::current_exe().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/rc_provider_failures.rs");
    // Every full fingerprint is outside all listener/child/watchdog live work.
    let binary_before = fingerprint(&binary, true, None);
    let test_before = fingerprint(&test_binary, true, None);
    let source_before = fingerprint(&source, false, Some(COMPILED_SOURCE));
    let home = Home::new(&private);
    let watchdog = Watchdog::new();
    let mut wire = Wire::start(delay);
    let providers = home.configure(&wire.authority);
    let result = run_cli(&binary, &home, wire.started);
    if result.is_ok() {
        wire.finish();
    } else {
        wire.abort();
    }
    drop(watchdog);
    assert_eq!(fingerprint(&binary, true, None), binary_before);
    assert_eq!(fingerprint(&test_binary, true, None), test_before);
    assert_eq!(
        fingerprint(&source, false, Some(COMPILED_SOURCE)),
        source_before
    );
    let state = wire.state.lock().unwrap();
    let result = result.expect("fixture/CLI infrastructure failure after complete owned cleanup");
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let saved = sessions::list_sessions(&home.home).unwrap();
    let inspection = if saved.len() == 1 {
        Some(inspect_accounting_detailed(&home.home, &saved[0].session_id, None).unwrap())
    } else {
        None
    };
    eprintln!(
        "PR01_BASELINE_EVIDENCE {}",
        json!({
            "delay_ms":delay.as_millis(),"exit_code":result.status.code(),
            "runtime_ms":result.runtime.as_millis(),"e0409":stderr.contains("ORBIT-E0409"),
            "connections":state.connections,"posts":state.posts,
            "client_spawn_started_ms":result.spawn_started.as_millis(),
            "client_spawn_returned_ms":result.spawned.as_millis(),
            "client_return_ms":result.returned.as_millis(),
            "accepted_ms":state.accepted.map(|d|d.as_millis()),
            "capture_ready":state.capture_ready,
            "peer_close_acknowledged":state.peer_close_acknowledged,
            "listener_poll_barrier":state.listener_poll_barrier,
            "request_captured_ms":state.captured.map(|d|d.as_millis()),
            "header_attempt_ms":state.header_attempt.map(|d|d.as_millis()),
            "header_published_ms":state.header_published.map(|d|d.as_millis()),
            "body_published_ms":state.body_published.map(|d|d.as_millis()),
            "response_attempt_complete":state.response_attempt_complete,
            "peer_closed_ms":state.peer_closed.map(|d|d.as_millis()),
            "write_error":state.write_error.map(|k|format!("{k:?}")),"server_error":state.error,
            "accounting":inspection.as_ref().map(|i|format!("{:?}",i.checkpoint)),
            "normal_cli_sha256":hex::encode(&binary_before.digest),
            "test_sha256":hex::encode(&test_before.digest),"source_sha256":hex::encode(&source_before.digest),
            "owned_child_reaped_and_group_absent":true,"owned_listener_thread_joined":true
        })
    );
    assert_eq!(
        state.connections, 1,
        "fixture expected one exact connection"
    );
    assert_eq!(state.posts, 1, "default managed caller must send once");
    assert_eq!(state.error, None, "fixture server failure");
    let capture = state
        .capture
        .as_ref()
        .expect("full request capture missing");
    assert!(
        state.capture_ready,
        "wire controls were checked before response scheduling"
    );
    validate_capture(capture, &wire.authority).expect("post-cleanup exact wire controls");
    assert_eq!(capture.target, "POST /pr01/v1/chat/completions HTTP/1.1");
    for (name, expected) in [
        ("host", wire.authority.as_str()),
        ("authorization", "Bearer synthetic-pr01-key"),
        ("content-type", "application/json"),
    ] {
        assert_eq!(
            capture
                .headers
                .iter()
                .filter_map(|(key, value)| (key == name).then_some(value.as_str()))
                .collect::<Vec<_>>(),
            [expected]
        );
    }
    let body: Value = serde_json::from_slice(&capture.body).unwrap();
    assert_eq!(body["model"], MODEL);
    assert_eq!(body["max_tokens"], 73);
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"], json!({"include_usage":true}));
    assert!(
        ["temperature", "top_p", "reasoning_effort"]
            .iter()
            .all(|key| body.get(*key).is_none())
    );
    let users = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["role"] == "user")
        .collect::<Vec<_>>();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["content"], PROMPT);
    assert_eq!(
        fs::read(home.home.join("providers.toml")).unwrap(),
        providers
    );
    assert!(!home.home.join("provider-policies.toml").exists());
    assert!(!stdout.contains(KEY) && !stderr.contains(KEY));
    assert_eq!(saved.len(), 1, "one real saved session");
    let saved = &saved[0];
    assert_eq!(saved.model, MODEL);
    assert_eq!(saved.provider, "fixture");
    assert_eq!(
        saved.selection_origin,
        Some(orbit_cli::phase_routing::SelectionOrigin::Role)
    );
    assert_eq!(saved.gate, format!("http://{}/pr01/v1", wire.authority));
    let observed = inspection.unwrap();
    let checkpoint = &observed.checkpoint;
    assert_eq!(checkpoint.owner_session_id(), saved.session_id);
    assert_eq!(checkpoint.child_id(), None);
    assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
    assert_eq!(
        checkpoint.refusals(),
        None,
        "timeout never fabricates final-refusal authority"
    );
    let ledger = orbit_ledger::verify_ledger(&home.home.join("ledger"))
        .unwrap()
        .0;
    assert_eq!(
        ledger
            .iter()
            .filter(|entry| matches!(
                &entry.record.event,
                orbit_ledger::LedgerEvent::EgressIntent(_)
            ))
            .count(),
        1
    );
    assert!(!ledger.iter().any(|entry| matches!(
        &entry.record.event,
        orbit_ledger::LedgerEvent::ToolIntent(_)
            | orbit_ledger::LedgerEvent::ToolVerdict(_)
            | orbit_ledger::LedgerEvent::ToolResult(_)
    )));
    let captured = state.captured.unwrap();
    let attempted = state.header_attempt.unwrap();
    assert!(
        state.response_attempt_complete,
        "cleanup must not cancel the measured response attempt"
    );
    assert!(
        state.peer_close_acknowledged && state.listener_poll_barrier,
        "normal stop follows actual peer closure and listener drain"
    );
    assert!(result.spawn_started <= result.spawned && result.spawned <= result.returned);
    assert!(
        state
            .accepted
            .is_some_and(|accepted| accepted >= result.spawn_started && accepted <= captured)
    );
    assert!(
        attempted >= captured + delay,
        "actual measured controlled hold"
    );
    assert!(
        attempted < Duration::from_secs(25),
        "header scheduling margin"
    );
    if !delay.is_zero() {
        assert!(attempted - captured > Duration::from_secs(10));
    }
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        checkpoint.revision().0,
        2,
        "one begin and one normal settlement"
    );
    if !result.status.success() {
        // This branch records the old source's actual failed desired positive.
        // It never changes the success requirement below into an expected error.
        assert!(
            stderr.contains("ORBIT-E0409"),
            "failure differs from the header baseline: {stderr}"
        );
        assert_eq!(value["status"], "error");
        assert!(
            value["error"]
                .as_str()
                .is_some_and(|error| error.contains("ORBIT-E0409"))
        );
        assert_eq!(
            checkpoint.totals().knownness,
            AccountingKnownness::Uncertain
        );
        assert!(
            checkpoint
                .pending()
                .is_some_and(|pending| pending.uncertain && pending.reference.revision.0 == 1)
        );
        assert!(checkpoint.last_settlement().is_none());
        assert!(
            observed
                .pending_receipt
                .as_ref()
                .is_some_and(|receipt| !receipt.completed
                    && receipt.knownness == AccountingKnownness::Uncertain
                    && receipt.purpose == AttemptPurpose::Ordinary
                    && receipt.usage.is_none())
        );
        assert!(
            state.peer_closed.is_some_and(|closed| closed <= attempted),
            "old client closes before delayed headers"
        );
    }
    assert!(
        result.status.success(),
        "desired actual-default response must succeed once; observed old-source failure: {stderr}"
    );
    assert_eq!(state.write_error, None);
    assert!(
        state.header_published.is_some()
            && state.body_published.is_some()
            && state.peer_closed.is_some()
    );
    assert!(
        result.runtime < Duration::from_secs(30),
        "normal production response budget"
    );
    assert_eq!(value["status"], "ok");
    assert_eq!(value["final_text"], ANSWER);
    assert_eq!(value["rounds"], 1);
    assert_eq!(value["usage"]["input_tokens"], 11);
    assert_eq!(value["usage"]["output_tokens"], 7);
    assert_eq!(saved.turns, 1);
    assert_eq!(
        (
            saved.input_tokens,
            saved.output_tokens,
            saved.cost_microcents
        ),
        (11, 7, 0)
    );
    assert_eq!(checkpoint.totals().knownness, AccountingKnownness::Known);
    assert_eq!(
        checkpoint.totals().ordinary,
        AccountingTotals {
            input_tokens: 11,
            output_tokens: 7,
            cost_microcents: Some(0)
        }
    );
    assert_eq!(
        checkpoint.totals().housekeeping,
        AccountingTotals::known_zero()
    );
    assert!(checkpoint.pending().is_none() && observed.pending_receipt.is_none());
    assert!(matches!(
        checkpoint.last_settlement(),
        Some(DetailedLastSettlement::Legacy(_))
    ));
    let receipt = observed.last_legacy_receipt.as_ref().unwrap();
    assert!(receipt.completed && receipt.knownness == AccountingKnownness::Known);
    assert_eq!(receipt.purpose, AttemptPurpose::Ordinary);
    assert_eq!(
        receipt.usage,
        Some(ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0
        })
    );
    if let Some(DetailedLastSettlement::Legacy(settled)) = checkpoint.last_settlement() {
        assert_eq!(settled.reference.revision.0, 1);
        assert_eq!(settled.reference.request_id, receipt.request_id);
    }
    let watermark = saved.accounting_watermark.as_ref().unwrap();
    assert_eq!(watermark.revision, checkpoint.revision().0);
    assert_eq!(
        watermark.full_cost_status,
        orbit_cli::session_accounting::FullCostStatus::Known
    );
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::User)
            .count(),
        1
    );
    assert_eq!(
        saved
            .transcript
            .iter()
            .filter(|message| message.role == ChatRole::Assistant)
            .count(),
        1
    );
    assert!(
        saved
            .transcript
            .iter()
            .all(|message| message.tool_calls.as_ref().is_none_or(Vec::is_empty))
    );
}

#[test]
fn default_provider_fast_response_succeeds_once() {
    actual_default_case(Duration::ZERO);
}

#[test]
fn default_provider_delayed_headers_succeed_once() {
    actual_default_case(HEADER_DELAY);
}
