#![cfg(target_os = "linux")]

mod headless_signal_baselines {
    use orbit_cli::context_history::context_journal;
    use orbit_cli::session_accounting::FullCostStatus;
    use orbit_cli::sessions::{SessionFile, SessionLease};
    use orbit_engine::{AccountingBaseline, AccountingCheckpoint, AccountingKnownness};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    const MAX_BODY: usize = 4 * 1024 * 1024;
    const MAX_REQUESTS: usize = 4;
    const PROMPT: &str = "retain this exact signal-boundary task";
    const RAW: &str = "signal-fixture-model";
    const INVALID: &str = r#"{"answer":"invalid"}"#;
    const PARTIAL: &str = "observed partial signal reply";
    const CAPTURE: u64 = 2 * 1024 * 1024;

    // Each case owns its isolated home, provider and child process.
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
        let required =
            std::env::var("ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION").as_deref() == Ok("1");
        let output = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/context_session_isolation.py"
            ))
            .arg("--binary")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--timeout", "180"])
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
        assert!(mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        ));
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

    struct Wire {
        url: String,
        authority: String,
        requests: Arc<Mutex<Vec<Captured>>>,
        connections: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
        watchdog: Option<std::sync::mpsc::Sender<()>>,
        watchdog_thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Wire {
        fn new(responses: Vec<Response>) -> Self {
            Self::with_held_headers(responses, false)
        }
        fn with_held_headers(responses: Vec<Response>, hold_headers: bool) -> Self {
            let (watchdog, receive) = std::sync::mpsc::channel();
            let watchdog_thread = std::thread::spawn(move || {
                if matches!(
                    receive.recv_timeout(Duration::from_secs(120)),
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
                let deadline = Instant::now() + Duration::from_secs(115);
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
            if let Some(done) = self.watchdog.take() {
                let _ = done.send(());
            }
            if let Some(thread) = self.watchdog_thread.take() {
                thread.join().expect("fixture watchdog panic");
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

    fn private_directory(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // The isolation runner pins its libtest binary. Pin the distinct real CLI
    // executable too, strictly inside the positively proved private namespace.
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

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        work: PathBuf,
        binary: PathBuf,
        binary_before: BinaryFingerprint,
    }
    impl Fixture {
        fn new() -> Self {
            require_private_system_fixture();
            let binary = PathBuf::from(env!("CARGO_BIN_EXE_orbit"));
            let binary_before = binary_fingerprint(&binary);
            let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap())
                .join(format!("sig-{}", ulid::Ulid::new()));
            private_directory(&root);
            let home = root.join("home");
            let work = root.join("work");
            private_directory(&home);
            private_directory(&work);
            let plan =
                orbit_cli::setup::plan_setup(&home, &orbit_cli::setup::SetupRequest::default())
                    .unwrap();
            orbit_cli::setup::apply_setup(&plan).unwrap();
            Self {
                root,
                home,
                work,
                binary,
                binary_before,
            }
        }
        fn configure(&self, wire: &Wire) -> PathBuf {
            let config:orbit_cli::config::ProvidersConfig=serde_json::from_value(json!({"provider":[{"name":"signal_fixture","kind":"openai-compatible","url":wire.url,"models":[{"id":RAW,"max_output_tokens":73,"context_limits":{"input_tokens":64000},"pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,"reasoning_per_million_microdollars":0,"request_flat_microdollars":5},"billing":{"version":2,"input_per_million_microdollars":0,"output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,"request_flat_microdollars":5,"reasoning_counter_basis":"included_in_output","reasoning_rate_policy":"output_rate"}}]}],"roles":{"main":format!("signal_fixture/{RAW}")}})).unwrap();
            write_private(
                &self.home.join("providers.toml"),
                toml::to_string(&config).unwrap(),
            );
            let schema = self.root.join("answer.schema.json");
            write_private(&schema,json!({"type":"object","required":["answer"],"properties":{"answer":{"type":"integer"}}}).to_string());
            schema
        }
        fn verify_binary(&self) {
            assert_eq!(binary_fingerprint(&self.binary), self.binary_before);
        }
        fn evidence(&self) -> Evidence {
            let mut paths = Vec::new();
            for (index, entry) in fs::read_dir(self.home.join("sessions"))
                .unwrap()
                .enumerate()
            {
                assert!(index < 16, "owned session enumeration bound");
                let entry = entry.unwrap();
                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
                {
                    paths.push(entry.path());
                }
            }
            assert_eq!(paths.len(), 1, "exactly one fresh invocation session");
            let id = paths[0].file_stem().unwrap().to_str().unwrap().to_owned();
            let lease =
                SessionLease::acquire(&self.home, &id, "signal-boundary-inspection").unwrap();
            let saved_bytes = read_owned(&paths[0], 128 * 1024);
            let saved = lease.load().unwrap();
            assert_eq!(saved.session_id, id);
            let checkpoint = context_journal(&self.home, &id, None)
                .unwrap()
                .accounting_checkpoint()
                .unwrap();
            let accounting_bytes = read_owned(
                &self
                    .home
                    .join("context-history")
                    .join(&id)
                    .join("accounting.json"),
                128 * 1024,
            );
            let raw: Value = serde_json::from_slice(&accounting_bytes).unwrap();
            assert_eq!(raw["version"], 1);
            assert_eq!(raw["owner"], id);
            assert_eq!(raw["entries"].as_array().unwrap().len(), 1);
            assert_eq!(raw["entries"][0]["namespace"], json!({"kind":"owner"}));
            Evidence {
                saved,
                checkpoint,
                saved_bytes,
                accounting_bytes,
                entry: raw["entries"][0].clone(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn read_owned(path: &Path, limit: u64) -> Vec<u8> {
        let before = fs::symlink_metadata(path).unwrap();
        assert!(before.is_file() && !before.file_type().is_symlink());
        assert_eq!(before.nlink(), 1);
        assert_eq!(before.mode() & 0o777, 0o600);
        assert!(before.len() <= limit);
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        let descriptor = file.metadata().unwrap();
        assert_eq!(
            (descriptor.dev(), descriptor.ino()),
            (before.dev(), before.ino())
        );
        let mut bytes = Vec::new();
        file.take(limit.checked_add(1).unwrap())
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() as u64 <= limit);
        bytes
    }
    struct Evidence {
        saved: SessionFile,
        checkpoint: AccountingCheckpoint,
        saved_bytes: Vec<u8>,
        accounting_bytes: Vec<u8>,
        entry: Value,
    }
    #[derive(Clone, Copy)]
    enum Signal {
        Int,
        Term,
        Kill,
    }
    impl Signal {
        fn argument(self) -> &'static str {
            match self {
                Self::Int => "-INT",
                Self::Term => "-TERM",
                Self::Kill => "-KILL",
            }
        }
        fn number(self) -> i32 {
            match self {
                Self::Int => 2,
                Self::Term => 15,
                Self::Kill => 9,
            }
        }
        fn exit(self) -> i32 {
            128 + self.number()
        }
    }
    #[derive(Clone, Copy)]
    enum Boundary {
        HeldHeaders,
        ObservedPartial { repair: bool },
    }
    impl Boundary {
        fn repair(self) -> bool {
            matches!(self, Self::ObservedPartial { repair: true })
        }
        fn partial(self) -> bool {
            matches!(self, Self::ObservedPartial { .. })
        }
        fn posts(self) -> usize {
            if self.repair() { 2 } else { 1 }
        }
        fn output(self) -> &'static str {
            if self.partial() {
                "stream-json"
            } else {
                "json"
            }
        }
    }
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let group = format!("-{}", self.0.id());
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", "--", &group])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    struct Capture {
        status: ExitStatus,
        stdout: String,
        stderr: String,
        observed: Vec<Value>,
    }
    fn spawn(f: &Fixture, args: &[&str]) -> (Process, [PathBuf; 2]) {
        require_private_system_fixture();
        f.verify_binary();
        let id = ulid::Ulid::new().to_string();
        let paths = [
            f.root.join(format!("{id}.out")),
            f.root.join(format!("{id}.err")),
        ];
        for path in &paths {
            write_private(path, b"");
        }
        let mut command = Command::new(&f.binary);
        command
            .args(args)
            .arg("--home")
            .arg(&f.home)
            .arg("--bare")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&f.work)
            .stdin(Stdio::null())
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
        (Process(command.spawn().unwrap()), paths)
    }
    fn stream_prefix(bytes: &[u8]) -> Vec<Value> {
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) if error.error_len().is_none() => {
                std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap()
            }
            Err(error) => panic!("invalid live CLI UTF8: {error}"),
        };
        let complete = text.rfind('\n').map_or("", |index| &text[..=index]);
        let mut events = Vec::new();
        for line in complete.lines().filter(|line| !line.is_empty()) {
            assert!(events.len() < 128, "live event bound");
            events.push(serde_json::from_str(line).expect("complete CLI event JSON"));
        }
        events
    }
    fn wait_exit(mut process: Process, paths: &[PathBuf; 2], observed: Vec<Value>) -> Capture {
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            for path in paths {
                assert!(fs::metadata(path).unwrap().len() <= CAPTURE);
            }
            if let Some(status) = process.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "CLI signal completion deadline (fixture failure)"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        let stdout = String::from_utf8(read_owned(&paths[0], CAPTURE)).unwrap();
        let stderr = String::from_utf8(read_owned(&paths[1], CAPTURE)).unwrap();
        assert!(stdout.len().checked_add(stderr.len()).unwrap() as u64 <= 2 * CAPTURE);
        Capture {
            status,
            stdout,
            stderr,
            observed,
        }
    }
    fn signalled(
        f: &Fixture,
        wire: &Wire,
        schema: &Path,
        boundary: Boundary,
        signal: Signal,
    ) -> Capture {
        let (mut process, paths) = spawn(
            f,
            &[
                "-p",
                PROMPT,
                "--json-schema",
                schema.to_str().unwrap(),
                "--output-format",
                boundary.output(),
            ],
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "CLI exited before the selected observable signal boundary"
            );
            for path in &paths {
                assert!(fs::metadata(path).unwrap().len() <= CAPTURE);
            }
            let count = wire.requests.lock().unwrap().len();
            assert!(
                count <= boundary.posts(),
                "unexpected request before signal"
            );
            let events = if boundary.partial() {
                stream_prefix(&read_owned(&paths[0], CAPTURE))
            } else {
                Vec::new()
            };
            let ready = count == boundary.posts()
                && (!boundary.partial()
                    || events
                        .iter()
                        .any(|event| event["type"] == "text_delta" && event["text"] == PARTIAL));
            if ready {
                break events;
            }
            assert!(
                Instant::now() < deadline,
                "selected POST/TextDelta boundary missing (fixture failure)"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(
            Command::new("/bin/kill")
                .args([signal.argument(), "--", &process.0.id().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "signal delivery to the still-owned unreaped CLI failed"
        );
        wait_exit(process, &paths, observed)
    }
    fn refuse_replay(f: &Fixture, evidence: &Evidence) {
        let (process, paths) = spawn(
            f,
            &[
                "-p",
                "do not replay the interrupted task",
                "--resume",
                &evidence.saved.session_id,
                "--output-format",
                "json",
            ],
        );
        let refused = wait_exit(process, &paths, Vec::new());
        assert_eq!(refused.status.signal(), None);
        assert_eq!(refused.status.code(), Some(1));
        assert!(
            refused.stderr.contains(
                "pending uncertain request requires explicit inspection before admission"
            )
        );
        let after = f.evidence();
        assert_eq!(after.saved_bytes, evidence.saved_bytes);
        assert_eq!(after.accounting_bytes, evidence.accounting_bytes);
        assert_eq!(after.checkpoint, evidence.checkpoint);
    }
    fn assert_wire_and_ids(f: &Fixture, wire: &Wire, evidence: &Evidence, boundary: Boundary) {
        let calls = wire.requests.lock().unwrap();
        assert_eq!(calls.len(), boundary.posts());
        assert_eq!(wire.connections.load(Ordering::SeqCst), boundary.posts());
        for call in calls.iter() {
            assert_eq!(
                call.target,
                "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
            );
            assert_eq!(call.body["model"], RAW);
            assert_eq!(call.body["max_tokens"], 73);
            assert_eq!(
                call.headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [wire.authority.as_str()]
            );
            assert!(
                !call
                    .headers
                    .iter()
                    .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
            );
        }
        assert_eq!(
            calls[0].body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|message| message["role"] == "user" && message["content"] == PROMPT)
                .count(),
            1
        );
        if boundary.repair() {
            assert!(calls[1].body.get("tools").is_none());
            assert_eq!(
                calls[1].body["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|message| message["role"] == "user" && message["content"] == PROMPT)
                    .count(),
                1
            );
        }
        drop(calls);
        let ledger = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0;
        let ids = ledger
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(intent) => {
                    assert_eq!(intent.session_id, evidence.saved.session_id);
                    Some(intent.decision_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), boundary.posts());
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            ids.len()
        );
        let pending = evidence.checkpoint.pending.as_ref().unwrap();
        assert_eq!(pending.reference.request_id, *ids.last().unwrap());
        assert_eq!(pending.intent.request_id, pending.reference.request_id);
        assert_eq!(
            pending.intent.purpose,
            orbit_engine::AttemptPurpose::Ordinary
        );
        if boundary.repair() {
            assert_eq!(
                evidence
                    .checkpoint
                    .last_settlement
                    .as_ref()
                    .unwrap()
                    .reference
                    .request_id,
                ids[0]
            );
            assert_eq!(
                evidence.entry["last"]["receipt"]["totals"]["cost_microcents"],
                5
            );
        }
    }
    fn assert_common(evidence: &Evidence, boundary: Boundary) {
        let checkpoint = &evidence.checkpoint;
        assert_eq!(checkpoint.owner_session_id, evidence.saved.session_id);
        assert!(checkpoint.child_id.is_none());
        assert_eq!(checkpoint.baseline, AccountingBaseline::FreshKnownZero);
        assert_eq!(
            checkpoint.totals.housekeeping,
            orbit_engine::AccountingTotals::known_zero()
        );
        assert_eq!(
            (
                checkpoint.totals.ordinary.input_tokens,
                checkpoint.totals.ordinary.output_tokens
            ),
            (
                if boundary.repair() { 11 } else { 0 },
                if boundary.repair() { 7 } else { 0 }
            )
        );
        let priced = checkpoint.known_priced_subtotals.unwrap();
        assert_eq!(
            priced.ordinary_microcents,
            if boundary.repair() { 5 } else { 0 }
        );
        assert_eq!(priced.housekeeping_microcents, 0);
        assert_eq!(evidence.saved.provider, "signal_fixture");
        assert_eq!(evidence.saved.model, RAW);
        assert!(evidence.saved.effort.is_none());
    }
    fn assert_abrupt(evidence: &Evidence, boundary: Boundary) {
        assert_common(evidence, boundary);
        let checkpoint = &evidence.checkpoint;
        assert_eq!(checkpoint.revision.0, if boundary.repair() { 3 } else { 1 });
        let pending = checkpoint.pending.as_ref().unwrap();
        assert!(!pending.uncertain);
        assert!(evidence.entry["pending"]["uncertain_receipt"].is_null());
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
        assert_eq!(
            checkpoint.totals.ordinary.cost_microcents,
            Some(if boundary.repair() { 5 } else { 0 })
        );
        assert!(
            evidence
                .saved
                .transcript
                .iter()
                .filter(|message| message.content == PROMPT)
                .count()
                <= 1
        );
        assert!(
            evidence
                .saved
                .accounting_watermark
                .as_ref()
                .unwrap()
                .revision
                <= checkpoint.revision.0
        );
    }
    fn assert_graceful(
        capture: &Capture,
        evidence: &Evidence,
        wire: &Wire,
        boundary: Boundary,
        signal: Signal,
    ) {
        assert_eq!(capture.status.signal(), None);
        assert_eq!(capture.status.code(), Some(signal.exit()));
        assert_common(evidence, boundary);
        let checkpoint = &evidence.checkpoint;
        assert_eq!(checkpoint.revision.0, if boundary.repair() { 4 } else { 2 });
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
        assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
        let receipt = &evidence.entry["pending"]["uncertain_receipt"];
        assert_eq!(
            receipt["request_id"],
            checkpoint.pending.as_ref().unwrap().reference.request_id
        );
        assert_eq!(receipt["purpose"], "ordinary");
        assert_eq!(receipt["knownness"], "uncertain");
        assert_eq!(receipt["completed"], false);
        assert_eq!(receipt["totals"]["input_tokens"], 0);
        assert_eq!(receipt["totals"]["output_tokens"], 0);
        assert!(receipt["totals"]["cost_microcents"].is_null());
        if boundary.partial() {
            assert_eq!(
                receipt["usage"],
                json!({"input_tokens":10,"output_tokens":2,"cache_read_tokens":3,"cache_write_tokens":0,"reasoning_tokens":1})
            );
        } else {
            assert!(
                receipt["usage"].is_null()
                    || receipt["usage"]
                        == json!({"input_tokens":0,"output_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0})
            );
        }
        let mut expected = vec![orbit_engine::user_message(PROMPT)];
        if boundary.repair() {
            expected.push(orbit_engine::assistant_message(INVALID));
            let calls = wire.requests.lock().unwrap();
            let prompt = calls[1].body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .find(|message| message["role"] == "user")
                .unwrap()["content"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                prompt.starts_with("Your previous reply did not match the required JSON schema:")
            );
            expected.push(orbit_engine::user_message(prompt));
        }
        if boundary.partial() {
            expected.push(orbit_engine::assistant_message(PARTIAL));
        }
        assert_eq!(evidence.saved.transcript, expected);
        assert_eq!(evidence.saved.turns, 1);
        assert_eq!(
            (
                evidence.saved.input_tokens,
                evidence.saved.output_tokens,
                evidence.saved.cost_microcents
            ),
            (
                if boundary.repair() { 11 } else { 0 },
                if boundary.repair() { 7 } else { 0 },
                if boundary.repair() { 5 } else { 0 }
            )
        );
        let watermark = evidence.saved.accounting_watermark.as_ref().unwrap();
        assert_eq!(watermark.owner_session_id, evidence.saved.session_id);
        assert!(watermark.child_id.is_none());
        assert_eq!(watermark.revision, checkpoint.revision.0);
        assert_eq!(watermark.full_cost_status, FullCostStatus::Uncertain);
        if boundary.partial() {
            let events = stream_prefix(capture.stdout.as_bytes());
            assert!(capture.stdout.ends_with('\n'));
            let terminals = events
                .iter()
                .filter(|event| event["type"] == "turn_ended")
                .collect::<Vec<_>>();
            assert_eq!(terminals.len(), boundary.posts());
            assert_eq!(terminals.last().unwrap()["interrupted"], true);
            assert_eq!(terminals.last().unwrap()["ok"], false);
            if boundary.repair() {
                assert_eq!(terminals[0]["ok"], true);
                assert_eq!(terminals[0]["interrupted"], false);
            }
            assert!(
                capture
                    .observed
                    .iter()
                    .any(|event| event["type"] == "text_delta" && event["text"] == PARTIAL)
            );
            assert!(!events.iter().any(|event| matches!(
                event["type"].as_str(),
                Some(
                    "tool_started"
                        | "tool_finished"
                        | "tool_started_full"
                        | "tool_finished_full"
                        | "tool_output"
                        | "tool_denied"
                        | "retrying"
                )
            )));
        } else {
            let value: Value =
                serde_json::from_str(&capture.stdout).expect("one final graceful JSON summary");
            assert_eq!(value["schema"], "orbit.cli/v1");
            assert_eq!(value["command"], "p");
            assert_eq!(value["status"], "stopped");
            assert_eq!(value["full_cost_status"], "uncertain");
            assert_eq!(value["usage"], json!({"input_tokens":0,"output_tokens":0}));
            assert_eq!(value["cost_microcents"], 0);
        }
    }
    fn run_case(boundary: Boundary, signal: Signal, require_graceful: bool) {
        let f = Fixture::new();
        let prefix = json!({"choices":[],"usage":{"prompt_tokens":13,"completion_tokens":2,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":1}}});
        let partial =
            json!({"choices":[{"index":0,"delta":{"content":PARTIAL},"finish_reason":null}]});
        let mut responses = Vec::new();
        if boundary.repair() {
            responses.push(Response::complete(INVALID));
        }
        responses.push(Response {
            body: format!("data: {prefix}\n\ndata: {partial}\n\n"),
            pause: true,
        });
        responses.push(Response::complete(r#"{"answer":42}"#));
        let mut wire = if matches!(boundary, Boundary::HeldHeaders) {
            Wire::with_held_headers(responses, true)
        } else {
            Wire::new(responses)
        };
        let schema = f.configure(&wire);
        let capture = signalled(&f, &wire, &schema, boundary, signal);
        let evidence = f.evidence();
        refuse_replay(&f, &evidence);
        wire.finish();
        f.verify_binary();
        assert_wire_and_ids(&f, &wire, &evidence, boundary);
        assert!(fs::read_dir(&f.work).unwrap().next().is_none());
        let graceful =
            capture.status.signal().is_none() && capture.status.code() == Some(signal.exit());
        if require_graceful {
            if graceful {
                assert_graceful(&capture, &evidence, &wire, boundary, signal);
            } else {
                assert_eq!(
                    capture.status.signal(),
                    Some(signal.number()),
                    "unexpected child termination: fixture/other behavior failure"
                );
                assert_abrupt(&evidence, boundary);
            }
            assert!(
                graceful,
                "missing graceful headless signal capability: observable owned boundary and abrupt begun-only accounting verified after cleanup; default process death is not graceful cancellation"
            );
        } else {
            assert_eq!(capture.status.signal(), Some(9));
            assert!(!graceful);
            assert_abrupt(&evidence, boundary);
        }
    }

    #[test]
    fn sigint_before_headers_persists_uncertain_intent_and_exits_normally130() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigint_before_headers_persists_uncertain_intent_and_exits_normally130",
        ) {
            return;
        }
        run_case(Boundary::HeldHeaders, Signal::Int, true);
    }
    #[test]
    fn sigterm_before_headers_persists_uncertain_intent_and_exits_normally143() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigterm_before_headers_persists_uncertain_intent_and_exits_normally143",
        ) {
            return;
        }
        run_case(Boundary::HeldHeaders, Signal::Term, true);
    }
    #[test]
    fn sigint_after_observed_partial_first_reply_preserves_text_and_one_terminal() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigint_after_observed_partial_first_reply_preserves_text_and_one_terminal",
        ) {
            return;
        }
        run_case(
            Boundary::ObservedPartial { repair: false },
            Signal::Int,
            true,
        );
    }
    #[test]
    fn sigterm_after_observed_partial_first_reply_preserves_text_and_one_terminal() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigterm_after_observed_partial_first_reply_preserves_text_and_one_terminal",
        ) {
            return;
        }
        run_case(
            Boundary::ObservedPartial { repair: false },
            Signal::Term,
            true,
        );
    }
    #[test]
    fn sigint_during_observed_schema_repair_preserves_paid_prefix_and_shared_cancellation() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigint_during_observed_schema_repair_preserves_paid_prefix_and_shared_cancellation",
        ) {
            return;
        }
        run_case(
            Boundary::ObservedPartial { repair: true },
            Signal::Int,
            true,
        );
    }
    #[test]
    fn sigterm_during_observed_schema_repair_preserves_paid_prefix_and_shared_cancellation() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigterm_during_observed_schema_repair_preserves_paid_prefix_and_shared_cancellation",
        ) {
            return;
        }
        run_case(
            Boundary::ObservedPartial { repair: true },
            Signal::Term,
            true,
        );
    }
    #[test]
    fn sigkill_remains_abrupt_begun_only_without_a_fabricated_settlement_or_replay() {
        if !dispatch_isolated(
            "headless_signal_baselines::sigkill_remains_abrupt_begun_only_without_a_fabricated_settlement_or_replay",
        ) {
            return;
        }
        for boundary in [
            Boundary::HeldHeaders,
            Boundary::ObservedPartial { repair: true },
        ] {
            run_case(boundary, Signal::Kill, false);
        }
    }

    fn assert_idle_serve_snapshot(snapshot: &orbit_cli::daemon::OwnerSnapshot, session: &str) {
        assert_eq!(snapshot.session_id, session);
        assert_eq!(snapshot.provider, "signal_fixture");
        assert_eq!(snapshot.model, RAW);
        assert_eq!(
            snapshot.selection_origin,
            orbit_cli::phase_routing::SelectionOrigin::Role
        );
        assert!(snapshot.effort.is_none());
        assert_eq!(snapshot.state, orbit_cli::daemon::TurnState::Idle);
        assert!(snapshot.messages.is_empty());
        assert!(snapshot.partial_response.is_empty());
        assert!(snapshot.pending_approvals.is_empty());
        assert!(snapshot.current_request.is_none());
        assert!(snapshot.requests.is_empty());
        assert_eq!(
            (
                snapshot.turns,
                snapshot.input_tokens,
                snapshot.output_tokens,
                snapshot.cost_microcents
            ),
            (0, 0, 0, 0)
        );
        let accounting = snapshot
            .accounting
            .expect("fresh owner must expose checked accounting");
        assert_eq!(accounting.revision, 0);
        assert_eq!(accounting.full_cost_status, FullCostStatus::Known);
        assert!(!snapshot.cursor.instance.is_empty());
    }

    fn assert_fresh_serve_saved(saved: &SessionFile, session: &str, gate: &str) {
        assert_eq!(saved.schema, "orbit.session/v1");
        assert_eq!(saved.session_id, session);
        assert_eq!(saved.provider, "signal_fixture");
        assert_eq!(saved.model, RAW);
        assert_eq!(saved.gate, gate);
        assert_eq!(
            saved.selection_origin,
            Some(orbit_cli::phase_routing::SelectionOrigin::Role)
        );
        assert!(saved.effort.is_none());
        assert!(saved.transcript.is_empty());
        assert_eq!(
            (
                saved.turns,
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (0, 0, 0, 0)
        );
        assert!(!saved.updated_at.is_empty() && saved.updated_at.len() <= 128);
        let watermark = saved
            .accounting_watermark
            .as_ref()
            .expect("fresh saved accounting watermark");
        assert_eq!(watermark.owner_session_id, session);
        assert!(watermark.child_id.is_none());
        assert_eq!(watermark.revision, 0);
        assert_eq!(
            (
                watermark.known_input_tokens,
                watermark.known_output_tokens,
                watermark.known_ordinary_microcents,
                watermark.known_housekeeping_microcents
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(watermark.full_cost_status, FullCostStatus::Known);
    }

    fn run_foreground_serve_signal(argument: &str, expected_exit: i32) {
        use std::os::unix::fs::FileTypeExt;

        assert!(matches!(
            (argument, expected_exit),
            ("-INT", 130) | ("-TERM", 143) | ("-HUP", 129)
        ));
        let f = Fixture::new();
        let mut wire = Wire::new(Vec::new());
        let _schema = f.configure(&wire);
        let session = "serve-signal-owner";
        let socket = f.root.join("owner.sock");
        let saved_path = f.home.join("sessions").join(format!("{session}.json"));
        let accounting_path = f
            .home
            .join("context-history")
            .join(session)
            .join("accounting.json");
        assert!(
            matches!(fs::symlink_metadata(&socket), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!saved_path.exists() && !accounting_path.exists());
        // spawn retains the existing private guard, full executable hash,
        // cleared environment, bare entry and owned unreaped process group.
        let (mut process, paths) = spawn(
            &f,
            &[
                "serve",
                "--session",
                session,
                "--socket",
                socket.to_str().unwrap(),
            ],
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "foreground owner exited before its socket was observed"
            );
            for path in &paths {
                assert!(fs::metadata(path).unwrap().len() <= CAPTURE);
            }
            match fs::symlink_metadata(&socket) {
                Ok(metadata) => {
                    assert!(metadata.file_type().is_socket());
                    assert_eq!(metadata.uid(), fs::metadata(&f.root).unwrap().uid());
                    if metadata.mode() & 0o777 == 0o600 {
                        break;
                    }
                    // bind precedes the server's private-mode publication.
                    // Do not attempt the peer-checked hello before that step.
                    assert!(
                        Instant::now() < deadline,
                        "foreground owner private socket mode deadline"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    assert!(
                        Instant::now() < deadline,
                        "foreground owner socket deadline"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("foreground owner socket metadata: {error}"),
            }
        }
        // This is the real private peer-checked hello and status transport.
        // An observer obtains no controller and never submits provider work.
        let mut observer = orbit_cli::attach::AttachClient::connect(&socket, false, None).unwrap();
        let initial = observer
            .recovery
            .snapshot
            .as_ref()
            .expect("observer hello recovery snapshot");
        assert_idle_serve_snapshot(initial, session);
        let instance = initial.cursor.instance.clone();
        let observed = observer.snapshot().unwrap();
        assert_idle_serve_snapshot(&observed, session);
        assert_eq!(observed.cursor.instance, instance);
        assert!(
            matches!(SessionLease::acquire(&f.home, session, "must-be-held-by-serve"),
            Err(orbit_cli::sessions::SessionLeaseError::Busy { session_id }) if session_id == session)
        );
        let active_saved_bytes = read_owned(&saved_path, 128 * 1024);
        let active_saved: SessionFile = serde_json::from_slice(&active_saved_bytes).unwrap();
        assert_fresh_serve_saved(&active_saved, session, &wire.url);
        let active_accounting_bytes = read_owned(&accounting_path, 128 * 1024);
        assert!(wire.requests.lock().unwrap().is_empty());
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(
            Command::new("/bin/kill")
                .args([argument, "--", &process.0.id().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "signal delivery to the still-owned unreaped foreground CLI failed"
        );
        drop(observer);
        let capture = wait_exit(process, &paths, Vec::new());
        assert_eq!(
            capture.status.signal(),
            None,
            "foreground stop must finish normally"
        );
        assert_eq!(capture.status.code(), Some(expected_exit));
        assert!(capture.stdout.is_empty() && capture.observed.is_empty());
        assert_eq!(
            capture.stderr,
            format!("Starting session {session} at {}\n", socket.display()),
            "foreground stop must not hide guard, runtime, join or cleanup errors behind its signal exit code"
        );
        assert!(
            matches!(fs::symlink_metadata(&socket), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "foreground stop must remove its actual owned socket"
        );
        // evidence reacquires the actual released source lease and loads the
        // one existing session and checked canonical accounting container.
        let evidence = f.evidence();
        assert_fresh_serve_saved(&evidence.saved, session, &wire.url);
        assert_eq!(
            evidence.saved.accounting_watermark,
            active_saved.accounting_watermark
        );
        assert_eq!(evidence.accounting_bytes, active_accounting_bytes);
        let checkpoint = &evidence.checkpoint;
        assert_eq!(checkpoint.owner_session_id, session);
        assert!(checkpoint.child_id.is_none());
        assert_eq!(checkpoint.baseline, AccountingBaseline::FreshKnownZero);
        assert_eq!(checkpoint.revision.0, 0);
        assert_eq!(
            checkpoint.totals,
            orbit_engine::AccountingDelta::known_zero()
        );
        assert!(checkpoint.pending.is_none() && checkpoint.last_settlement.is_none());
        let priced = checkpoint.known_priced_subtotals.unwrap();
        assert_eq!(
            (priced.ordinary_microcents, priced.housekeeping_microcents),
            (0, 0)
        );
        assert!(evidence.entry["pending"].is_null() && evidence.entry["last"].is_null());
        assert_eq!(
            fs::read_dir(
                f.home
                    .join("context-history")
                    .join(session)
                    .join("archives")
            )
            .unwrap()
            .count(),
            0
        );
        let records = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0;
        assert!(!records.iter().any(|record| matches!(
            &record.record.event,
            orbit_ledger::LedgerEvent::EgressIntent(_)
                | orbit_ledger::LedgerEvent::ToolIntent(_)
                | orbit_ledger::LedgerEvent::ToolVerdict(_)
                | orbit_ledger::LedgerEvent::ToolResult(_)
        )));
        assert!(fs::read_dir(&f.work).unwrap().next().is_none());
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        assert!(wire.requests.lock().unwrap().is_empty());
        f.verify_binary();
    }

    #[test]
    fn foreground_serve_sigint_after_authenticated_status_exits130_and_releases_fresh_owner() {
        if !dispatch_isolated(
            "headless_signal_baselines::foreground_serve_sigint_after_authenticated_status_exits130_and_releases_fresh_owner",
        ) {
            return;
        }
        run_foreground_serve_signal("-INT", 130);
    }

    #[test]
    fn foreground_serve_sigterm_after_authenticated_status_exits143_and_releases_fresh_owner() {
        if !dispatch_isolated(
            "headless_signal_baselines::foreground_serve_sigterm_after_authenticated_status_exits143_and_releases_fresh_owner",
        ) {
            return;
        }
        run_foreground_serve_signal("-TERM", 143);
    }

    #[test]
    fn foreground_serve_sighup_after_authenticated_status_exits129_and_releases_fresh_owner() {
        if !dispatch_isolated(
            "headless_signal_baselines::foreground_serve_sighup_after_authenticated_status_exits129_and_releases_fresh_owner",
        ) {
            return;
        }
        run_foreground_serve_signal("-HUP", 129);
    }
}
