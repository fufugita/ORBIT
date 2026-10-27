#![cfg(target_os = "linux")]

mod recovery_baselines {
    use orbit_adapter::types::{
        ChatMessage, ChatRole, ContentBlock, CostRates, ProviderUsage, ToolCallMessage,
    };
    use orbit_cli::context_history::{context_journal, load_compaction_source};
    use orbit_cli::phase_routing::SelectionOrigin;
    use orbit_cli::session_accounting::{FullCostStatus, RootOrigin, prepare_root};
    use orbit_cli::sessions::{SessionFile, SessionLease, SessionLeaseError};
    use orbit_engine::{
        AccountingBaseline, AccountingCheckpoint, AccountingKnownness, AccountingTotals,
        AttemptIntent, AttemptPurpose, ProviderKind, RequestAccountingReceipt, TurnConfig,
        TurnOptions,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    const MAX_BODY: usize = 4 * 1024 * 1024;
    const MAX_REQUESTS: usize = 4;
    const SESSION: &str = "recovery-source";
    const RAW_A: &str = "model-a";
    const SUMMARY: &str = "short checked synthetic recovery seed summary";
    const PRIVATE: &str = "RECOVERY_PRIVATE_OPAQUE_ORIGINAL";
    const PENDING: &str = "recovery-pending-request";

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
            Self::with_post_marker(responses, hold_headers, None)
        }
        fn with_post_marker(
            responses: Vec<Response>,
            hold_headers: bool,
            marker: Option<PathBuf>,
        ) -> Self {
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
                            if let Some(path) = &marker {
                                if path.exists() {
                                    return Err("duplicate POST marker");
                                }
                                let staged = path.with_extension("pending");
                                let mut file = fs::OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .mode(0o600)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                    .open(&staged)
                                    .map_err(|_| "POST marker open")?;
                                file.write_all(b"observed-provider-post\n")
                                    .map_err(|_| "POST marker write")?;
                                file.sync_all().map_err(|_| "POST marker sync")?;
                                fs::rename(staged, path).map_err(|_| "POST marker publish")?;
                            }
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
            // Stop this provider-workflow watchdog only after the actual
            // provider has joined and its complete capture count is checked.
            // Full CLI hashes remain mandatory, outside this live interval.
            if let Some(done) = self.watchdog.take() {
                done.send(())
                    .expect("fixture watchdog closed before provider verification");
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

    struct CliProcess(Child);
    impl Drop for CliProcess {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                // The still-live unreaped leader owns this new process group.
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
    struct CliResult {
        status: ExitStatus,
        stdout: String,
        stderr: String,
    }
    fn cli(f: &Fixture, args: &[&str], input: &str) -> CliResult {
        require_private_system_fixture();
        f.binary_unchanged();
        const CAP: u64 = 2 * 1024 * 1024;
        let id = ulid::Ulid::new().to_string();
        let paths = [
            f.root.join(format!("{id}.in")),
            f.root.join(format!("{id}.out")),
            f.root.join(format!("{id}.err")),
        ];
        for (path, bytes) in [
            (&paths[0], input.as_bytes()),
            (&paths[1], b"".as_slice()),
            (&paths[2], b"".as_slice()),
        ] {
            write_private(path, bytes);
        }
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
            .stdin(fs::File::open(&paths[0]).unwrap())
            .stdout(fs::OpenOptions::new().write(true).open(&paths[1]).unwrap())
            .stderr(fs::OpenOptions::new().write(true).open(&paths[2]).unwrap())
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
        let mut child = CliProcess(command.spawn().unwrap());
        let end = Instant::now() + Duration::from_secs(15);
        let status = loop {
            for path in &paths[1..] {
                assert!(
                    fs::metadata(path).unwrap().len() <= CAP,
                    "CLI capture bound"
                );
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < end, "real CLI deadline");
            std::thread::sleep(Duration::from_millis(2));
        };
        let capture = |path: &Path| {
            assert!(fs::metadata(path).unwrap().len() <= CAP);
            let mut bytes = Vec::new();
            fs::File::open(path)
                .unwrap()
                .take(CAP + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() as u64 <= CAP);
            String::from_utf8(bytes).unwrap()
        };
        let result = CliResult {
            status,
            stdout: capture(&paths[1]),
            stderr: capture(&paths[2]),
        };
        assert!(
            result
                .stdout
                .len()
                .checked_add(result.stderr.len())
                .unwrap() as u64
                <= 2 * CAP
        );
        result
    }

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        workspace: PathBuf,
        binary: PathBuf,
        binary_before: BinaryFingerprint,
    }
    impl Fixture {
        fn new() -> Self {
            require_private_system_fixture();
            let binary = PathBuf::from(env!("CARGO_BIN_EXE_orbit"));
            let binary_before = binary_fingerprint(&binary);
            let root = PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap())
                .join(format!("r-{}", ulid::Ulid::new()));
            private_directory(&root);
            let home = root.join("home");
            let workspace = root.join("work");
            private_directory(&home);
            private_directory(&workspace);
            let plan =
                orbit_cli::setup::plan_setup(&home, &orbit_cli::setup::SetupRequest::default())
                    .unwrap();
            orbit_cli::setup::apply_setup(&plan).unwrap();
            Self {
                root,
                home,
                workspace,
                binary,
                binary_before,
            }
        }
        fn binary_unchanged(&self) {
            assert_eq!(binary_fingerprint(&self.binary), self.binary_before);
        }
        fn configure(&self, wire: &Wire) {
            let value = json!({"provider":[{"name":"provider_a","kind":"openai-compatible","url":wire.url,
                "models":[{"id":RAW_A,"max_output_tokens":73,"context_limits":{"input_tokens":10000}}]}],
                "roles":{"main":format!("provider_a/{RAW_A}")}});
            let parsed: orbit_cli::config::ProvidersConfig = serde_json::from_value(value).unwrap();
            write_private(
                &self.home.join("providers.toml"),
                toml::to_string(&parsed).unwrap(),
            );
        }
        fn saved_path(&self) -> PathBuf {
            self.home.join("sessions").join(format!("{SESSION}.json"))
        }
        fn accounting_path(&self) -> PathBuf {
            self.home
                .join("context-history")
                .join(SESSION)
                .join("accounting.json")
        }
        fn checkpoint(&self) -> AccountingCheckpoint {
            context_journal(&self.home, SESSION, None)
                .unwrap()
                .accounting_checkpoint()
                .unwrap()
        }
        fn lease_released(&self) {
            let lease = SessionLease::acquire(&self.home, SESSION, "recovery-postcheck").unwrap();
            drop(lease);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // This is a genuine shared-service seed phase, explicitly separate from
    // the zero-additional-POST recovery interval. No private codec is recreated.
    struct Seed {
        original: Vec<ChatMessage>,
        archive: PathBuf,
        archive_id: String,
        checkpoint: AccountingCheckpoint,
    }
    fn seed(f: &Fixture, wire: &Wire) -> Seed {
        f.configure(wire);
        let mut original = Vec::new();
        for index in 0..3 {
            original.push(orbit_engine::user_message(format!(
                "old {index} {}",
                "u".repeat(12000)
            )));
            original.push(orbit_engine::assistant_message(format!(
                "old answer {index} {}",
                "a".repeat(12000)
            )));
        }
        let mut call = orbit_engine::assistant_message("typed historical call");
        call.tool_calls = Some(vec![ToolCallMessage {
            id: "historical-call".into(),
            name: "inspect".into(),
            arguments: "{\"private\":\"synthetic argument\"}".into(),
        }]);
        original.push(call);
        let mut tool = orbit_engine::user_message("display-only historical result");
        tool.role = ChatRole::Tool;
        tool.tool_call_id = Some("historical-call".into());
        tool.tool_result = Some("complete synthetic historical result".into());
        original.push(tool);
        let mut closed = orbit_engine::assistant_message("historical tool work complete");
        closed.blocks = Some(vec![ContentBlock::Opaque {
            json: json!({"type":"thinking","thinking":PRIVATE,"signature":PRIVATE}).to_string(),
        }]);
        closed.origin_provider = Some("foreign-synthetic-provider".into());
        closed.origin_model = Some("foreign-synthetic-model".into());
        original.push(closed);
        let mut image = orbit_engine::user_message("retained image");
        image.blocks = Some(vec![ContentBlock::Text { text:"retained image".into() }, ContentBlock::Image {
            data:"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=".into(), media_type:"image/png".into() }]);
        original.push(image);
        original.push(orbit_engine::assistant_message("retained image answer"));
        original.push(orbit_engine::user_message("latest completed question"));
        original.push(orbit_engine::assistant_message("latest completed answer"));
        let mut saved = SessionFile::from_chat(
            SESSION,
            RAW_A,
            &wire.url,
            "provider_a",
            &original,
            7,
            100,
            40,
            60,
        )
        .with_selection_origin(SelectionOrigin::SavedExplicit);
        saved.bind_workspace(&f.workspace).unwrap();
        let lease = SessionLease::acquire(&f.home, SESSION, "recovery-seed").unwrap();
        lease.save(&saved).unwrap();
        let accounting = prepare_root(&lease, &mut saved, RootOrigin::RestoredOrLegacy).unwrap();
        let journal = context_journal(&f.home, SESSION, None).unwrap();
        let config = |summary: bool| TurnConfig {
            provider_id: "provider_a".into(),
            gate: wire.url.clone(),
            model: if summary { "summary-model" } else { RAW_A }.into(),
            kind: ProviderKind::OpenAiCompatible,
            credential_env: None,
            pricing: Some(CostRates {
                input_per_million_microcents: 0,
                output_per_million_microcents: 0,
                cache_read_per_million_microcents: Some(0),
                cache_write_per_million_microcents: Some(0),
                reasoning_per_million_microcents: Some(0),
                request_flat_microcents: 7,
            }),
            billing: None,
            max_output_tokens: 73,
            sampling: None,
            effort: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        let main = config(false);
        let summary = config(true);
        let selected =
            orbit_engine::context_budget::SelectedBudget::legacy_input(&main, 10000).unwrap();
        let summary_budget =
            orbit_engine::context_budget::SelectedBudget::legacy_input(&summary, 64000).unwrap();
        let mut options = TurnOptions {
            max_attempts: 1,
            max_rounds: 1,
            session_id: SESSION.into(),
            request_stem: "recovery-seed".into(),
            selected_budget: Some(selected.clone()),
            compaction_budget: Some(summary_budget),
            compaction_config: Some(summary),
            journal: Some(journal.clone()),
            ..Default::default()
        };
        accounting
            .namespace()
            .apply_options(&mut options, None)
            .unwrap();
        let mut working = original.clone();
        let completion = orbit_engine::compact_context_detailed(
            &f.home,
            &main,
            &options,
            &mut working,
            &orbit_provider_http::CancelToken::new(),
            &mut |_| {},
        );
        assert_eq!(
            completion.status,
            orbit_engine::compaction::CompactionStatus::PublishedReady
        );
        assert!(completion.applied);
        assert_eq!(completion.attempts.len(), 1);
        assert_eq!(wire.requests.lock().unwrap().len(), 1);
        {
            let calls = wire.requests.lock().unwrap();
            assert_eq!(
                calls[0].target,
                "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
            );
            assert_eq!(calls[0].body["model"], "summary-model");
            assert_eq!(calls[0].body["max_tokens"], 73);
            assert!(calls[0].body.get("tools").is_none());
            assert!(!calls[0].body.to_string().contains(PRIVATE));
            assert!(
                !calls[0]
                    .headers
                    .iter()
                    .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
            );
            assert_eq!(
                calls[0]
                    .headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [wire.authority.as_str()]
            );
        }
        saved.transcript = working;
        accounting.persist(&lease, &mut saved).unwrap();
        assert_eq!(
            (
                saved.turns,
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (7, 111, 47, 67)
        );
        let archives = fs::read_dir(
            f.home
                .join("context-history")
                .join(SESSION)
                .join("archives"),
        )
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        let archive = archives[0].clone();
        let archive_id = archive.file_stem().unwrap().to_str().unwrap().to_owned();
        assert_eq!(
            load_compaction_source(&f.home, SESSION, None, &archive_id).unwrap(),
            original
        );
        let intent = AttemptIntent {
            owner_session_id: SESSION.into(),
            child_id: None,
            request_id: PENDING.into(),
            purpose: AttemptPurpose::Ordinary,
            budget: selected.identity.clone(),
        };
        let reference = journal
            .begin_attempt(journal.accounting_checkpoint().unwrap().revision, &intent)
            .unwrap();
        let receipt = RequestAccountingReceipt {
            request_id: PENDING.into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(ProviderUsage {
                input_tokens: 19,
                output_tokens: 5,
                cache_read_tokens: 3,
                cache_write_tokens: 2,
                reasoning_tokens: 4,
            }),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        };
        let checkpoint = journal.settle_attempt(&reference, &receipt).unwrap();
        assert_eq!(reference.revision.0, 3);
        assert_eq!(checkpoint.revision.0, 4);
        assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            checkpoint.pending.as_ref().unwrap().reference.request_id,
            PENDING
        );
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            7
        );
        let document: Value =
            serde_json::from_slice(&read_bounded(&f.accounting_path(), 128 * 1024)).unwrap();
        let entry = document["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["namespace"]["kind"] == "owner")
            .unwrap();
        assert_eq!(
            entry["pending"]["uncertain_receipt"]["usage"],
            json!(receipt.usage.unwrap())
        );
        assert_eq!(
            entry["pending"]["uncertain_receipt"]["totals"]["cost_microcents"],
            Value::Null
        );
        // Saved watermark is deliberately older than the journal; status must
        // inspect current durable metadata without making that snapshot current.
        assert_eq!(saved.accounting_watermark.as_ref().unwrap().revision, 2);
        assert_eq!(
            saved
                .accounting_watermark
                .as_ref()
                .unwrap()
                .full_cost_status,
            FullCostStatus::UnknownLegacy
        );
        assert!(prepare_root(&lease, &mut saved, RootOrigin::RestoredOrLegacy).is_err());
        drop(lease);
        drop(journal);
        f.lease_released();
        assert_eq!(f.checkpoint(), checkpoint);
        Seed {
            original,
            archive,
            archive_id,
            checkpoint,
        }
    }

    fn read_bounded(path: &Path, maximum: u64) -> Vec<u8> {
        let before = fs::symlink_metadata(path).unwrap();
        assert!(before.is_file() && !before.file_type().is_symlink());
        assert_eq!(before.nlink(), 1);
        assert!(before.len() <= maximum);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        assert_eq!(
            (
                file.metadata().unwrap().dev(),
                file.metadata().unwrap().ino()
            ),
            (before.dev(), before.ino())
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len() as u64, before.len());
        assert!(bytes.len() as u64 <= maximum);
        let after = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            )
        );
        bytes
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
        digest: Vec<u8>,
    }
    fn snapshot(home: &Path) -> BTreeMap<PathBuf, Stamp> {
        let mut found = BTreeMap::new();
        let mut pending = vec![home.to_owned()];
        let mut total = 0u64;
        while let Some(path) = pending.pop() {
            assert!(found.len() < 128, "bounded fixture tree");
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file() || metadata.is_dir() || metadata.file_type().is_symlink());
            let data = if metadata.is_file() {
                let bytes = read_bounded(&path, 256 * 1024);
                total = total.checked_add(bytes.len() as u64).unwrap();
                assert!(total <= 2 * 1024 * 1024);
                bytes
            } else if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                for entry in fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
                Vec::new()
            };
            let stamp = Stamp {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                size: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                digest: Sha256::digest(&data).to_vec(),
            };
            found.insert(path.strip_prefix(home).unwrap().to_path_buf(), stamp);
        }
        found
    }
    fn startup_tree_without_expected_descriptor_changes(
        tree: &BTreeMap<PathBuf, Stamp>,
    ) -> BTreeMap<PathBuf, Stamp> {
        let mut normalized = tree.clone();
        let sessions = Path::new("sessions");
        let leases = Path::new("sessions/.leases");
        let holder = leases.join(format!("{SESSION}.lock"));
        for (path, stamp) in &mut normalized {
            if path == sessions || path == leases {
                // Existing acquire calls fchmod on these two exact private
                // directories. Keep every other field, especially identity.
                stamp.changed = (0, 0);
            } else if path == &holder {
                // Only this existing lock's PID/kind description is mutable.
                // Its path, inode/device, owner, type/mode and links stay exact.
                stamp.size = 0;
                stamp.modified = (0, 0);
                stamp.changed = (0, 0);
                stamp.digest.clear();
            }
        }
        normalized
    }
    fn assert_recovery_preserved(
        f: &Fixture,
        seed: &Seed,
        before: &BTreeMap<PathBuf, Stamp>,
        wire: &Wire,
        allow_startup_lease_mutation: bool,
    ) {
        // Existing chat/serve necessarily acquire the real source lease and
        // update its descriptive holder record, and fchmod private directories.
        // Retain the complete path set and stable identity for every entry.
        // Export and new read-only status permit no such startup mutation.
        let after = snapshot(&f.home);
        if allow_startup_lease_mutation {
            assert_eq!(
                startup_tree_without_expected_descriptor_changes(&after),
                startup_tree_without_expected_descriptor_changes(before)
            );
        } else {
            assert_eq!(after, *before);
        }
        assert_eq!(f.checkpoint(), seed.checkpoint);
        assert_eq!(
            load_compaction_source(&f.home, SESSION, None, &seed.archive_id).unwrap(),
            seed.original
        );
        assert_eq!(
            wire.connections.load(Ordering::SeqCst),
            1,
            "only the separately labelled seed summary may connect"
        );
        assert_eq!(
            wire.requests.lock().unwrap().len(),
            1,
            "zero additional recovery provider POSTs"
        );
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }
    fn missing_recovery_command(result: &CliResult) -> bool {
        result.status.code() == Some(2)
            && result.stdout.is_empty()
            && result.stderr.contains("ORBIT-E1101")
            && result.stderr.contains("unsupported command recovery")
    }

    #[test]
    fn pending_startup_stays_refused_while_direct_status_exposes_cold_metadata() {
        if !dispatch_isolated(
            "recovery_baselines::pending_startup_stays_refused_while_direct_status_exposes_cold_metadata",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let before = snapshot(&f.home);
        let chat = cli(
            &f,
            &["chat", "--no-tui", "--resume", SESSION, "--bare"],
            "/usage\nexit\n",
        );
        let socket = f.root.join("owner.sock");
        let serve = cli(
            &f,
            &[
                "serve",
                "--resume",
                SESSION,
                "--bare",
                "--socket",
                socket.to_str().unwrap(),
            ],
            "",
        );
        assert_eq!(chat.status.code(), Some(2));
        assert!(chat.stderr.contains("ORBIT-E0400") && chat.stderr.contains("inspection"));
        assert_eq!(serve.status.code(), Some(2));
        assert!(serve.stderr.contains("inspection"));
        assert!(!socket.exists());
        assert_recovery_preserved(&f, &seeded, &before, &wire, true);
        f.lease_released();

        // Ordinary pending startup remains refused above. The explicit cold
        // metadata consumer is the early status route and does not admit a turn.
        let expected =
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
        assert_eq!(expected.checkpoint, seeded.checkpoint);
        let pending = expected.checkpoint.pending.as_ref().unwrap();
        let prior = expected.last_receipt.as_ref().unwrap();
        let prior_reference = expected.checkpoint.last_settlement.as_ref().unwrap();
        let status_before = snapshot(&f.home);
        let result = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        status_private(&result, &wire);
        let value = status_available(&result);
        assert_eq!(value["owner_session_id"], SESSION);
        assert!(value["child_id"].is_null());
        assert_eq!(value["checkpoint_revision"], seeded.checkpoint.revision.0);
        assert_eq!(value["baseline"], "unknown_legacy");
        assert_eq!(value["accounting_scope"], "since_namespace_initialization");
        assert_eq!(value["totals"]["knownness"], "uncertain");
        for (name, totals) in [
            ("ordinary", seeded.checkpoint.totals.ordinary),
            ("housekeeping", seeded.checkpoint.totals.housekeeping),
        ] {
            assert_eq!(
                value["totals"][name],
                json!({"input_tokens":totals.input_tokens,
                "output_tokens":totals.output_tokens,"cost_microcents":totals.cost_microcents})
            );
        }
        assert!(value["totals"]["ordinary"]["cost_microcents"].is_null());
        let priced = seeded.checkpoint.known_priced_subtotals.unwrap();
        assert_eq!(
            value["known_priced_subtotals"],
            json!({"ordinary_microcents":priced.ordinary_microcents,
            "housekeeping_microcents":priced.housekeeping_microcents})
        );
        assert_eq!(value["lifecycle"], "uncertain_receipt");
        assert_eq!(
            value["pending"]["reference"],
            json!({"revision":pending.reference.revision.0,
            "request_id":pending.reference.request_id,"intent_digest":pending.reference.intent_digest})
        );
        assert_eq!(value["pending"]["reference"]["request_id"], PENDING);
        assert_eq!(value["pending"]["expected_previous_revision"], 2);
        assert_eq!(value["pending"]["purpose"], "ordinary");
        assert_eq!(value["pending"]["uncertain"], true);
        assert_eq!(
            value["pending"]["budget"],
            json!({"binding_digest":pending.intent.budget.binding_digest,
            "metadata_revision":pending.intent.budget.metadata_revision,"policy_revision":pending.intent.budget.policy_revision})
        );
        let pending_receipt = &value["pending"]["receipt"];
        assert_eq!(pending_receipt["request_id"], PENDING);
        assert_eq!(pending_receipt["purpose"], "ordinary");
        assert_eq!(pending_receipt["knownness"], "uncertain");
        assert_eq!(pending_receipt["completed"], false);
        assert_eq!(
            pending_receipt["known_totals"],
            json!({"input_tokens":0,"output_tokens":0,"cost_microcents":null})
        );
        assert_eq!(
            pending_receipt["usage_qualification"],
            "provisional_observed"
        );
        assert_eq!(
            pending_receipt["observed_usage"],
            json!({"input_tokens":19,"output_tokens":5,
            "cache_read_tokens":3,"cache_write_tokens":2,"reasoning_tokens":4})
        );
        let last = &value["last_settlement"];
        assert_eq!(
            last["reference"],
            json!({"revision":prior_reference.reference.revision.0,
            "request_id":prior_reference.reference.request_id,"intent_digest":prior_reference.reference.intent_digest})
        );
        assert_eq!(last["receipt_digest"], prior_reference.receipt_digest);
        assert_eq!(last["receipt"]["request_id"], prior.request_id);
        assert_ne!(prior.request_id, PENDING);
        assert_eq!(
            last["receipt"]["purpose"],
            match prior.purpose {
                AttemptPurpose::Ordinary => "ordinary",
                AttemptPurpose::Chunk => "chunk",
                AttemptPurpose::Merge => "merge",
            }
        );
        assert_eq!(last["receipt"]["knownness"], "known");
        assert_eq!(last["receipt"]["completed"], true);
        assert_eq!(
            last["receipt"]["known_totals"],
            json!({"input_tokens":prior.totals.input_tokens,
            "output_tokens":prior.totals.output_tokens,"cost_microcents":prior.totals.cost_microcents})
        );
        assert_eq!(last["receipt"]["usage_qualification"], "validated_final");
        assert_eq!(
            last["receipt"]["observed_usage"],
            json!(prior.usage.unwrap())
        );
        assert!(last.get("budget").is_none());
        assert_eq!(value["inspection_digest"], expected.inspection_digest);
        let digest = value["inspection_digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            value["inspection"],
            json!({"qualification":"visible_validated",
            "prior_publication_durability":"not_established","provider_outcome":"not_established_by_inspection"})
        );
        assert_recovery_preserved(&f, &seeded, &status_before, &wire, false);
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn legacy_export_stays_ledger_only_while_selected_recovery_export_preserves_exact_evidence() {
        if !dispatch_isolated(
            "recovery_baselines::legacy_export_stays_ledger_only_while_selected_recovery_export_preserves_exact_evidence",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let before = snapshot(&f.home);
        let target = f.root.join("legacy.age");
        assert!(!target.exists());
        assert!(!target.with_extension("age.key").exists());
        let expected = [f.saved_path(), f.accounting_path(), seeded.archive.clone()]
            .into_iter()
            .map(|path| {
                let relative = path
                    .strip_prefix(&f.home)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let digest = hex::encode(Sha256::digest(read_bounded(&path, 256 * 1024)));
                (relative, digest)
            })
            .collect::<Vec<_>>();
        let exact_snapshot = read_bounded(&f.saved_path(), 256 * 1024);
        let exact_accounting = read_bounded(&f.accounting_path(), 128 * 1024);
        let exact_archive = read_bounded(&seeded.archive, 256 * 1024);
        // Existing export concatenates actual ledger segments in filename order.
        // Compare its authenticated decrypted manifest with these independent bytes.
        let mut segments = fs::read_dir(f.home.join("ledger/segments"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert!(segments.len() <= 64);
        segments.sort_by_key(|path| path.file_name().unwrap().to_owned());
        let mut ledger_bytes = Vec::new();
        for segment in segments {
            let bytes = read_bounded(&segment, 256 * 1024);
            assert!(ledger_bytes.len().checked_add(bytes.len()).unwrap() <= 2 * 1024 * 1024);
            ledger_bytes.extend_from_slice(&bytes);
        }
        let ledger_digest = hex::encode(Sha256::digest(&ledger_bytes));
        let ledger_head = read_bounded(&f.home.join("ledger/HEAD"), 4096);
        let result = cli(&f, &["export", "--to", target.to_str().unwrap()], "");
        assert!(result.status.success());
        let answer: Value = serde_json::from_str(&result.stdout).unwrap();
        assert_eq!(answer["command"], "export");
        assert_eq!(answer["encrypted"], true);
        let sealed = read_bounded(&target, 2 * 1024 * 1024);
        let key = read_bounded(&target.with_extension("age.key"), 4096);
        let identity: age::x25519::Identity =
            std::str::from_utf8(&key).unwrap().trim().parse().unwrap();
        let manifest = orbit_export::restore(
            &sealed,
            &identity,
            "new-inert-inspection",
            "session-example",
        )
        .unwrap();
        assert_eq!(manifest.schema, "orbit.export/v1");
        assert!(
            manifest
                .files
                .get("ledger/segments")
                .is_some_and(|file| file.excluded_reason.is_none())
        );
        let ledger = manifest.files.get("ledger/segments").unwrap();
        assert_eq!(ledger.path, "ledger/segments");
        assert_eq!(ledger.content_sha256, ledger_digest);
        assert_eq!(
            manifest.ledger_head_hash,
            std::str::from_utf8(&ledger_head).unwrap().trim()
        );
        // restore authenticates and checks manifest digests against decrypted
        // payloads; compare those public digests with our exact source bytes.
        // An included path with empty or unrelated bytes cannot satisfy this.
        let missing = expected
            .iter()
            .filter(|(path, digest)| {
                !manifest.files.get(path).is_some_and(|file| {
                    file.excluded_reason.is_none()
                        && file.path.as_str() == path.as_str()
                        && file.content_sha256.as_str() == digest.as_str()
                })
            })
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        assert_recovery_preserved(&f, &seeded, &before, &wire, false);
        f.lease_released();
        assert_eq!(
            missing.len(),
            expected.len(),
            "encrypted legacy ledger export still omits all three selected recovery payloads"
        );
        assert_ne!(manifest.source_session_id, SESSION);

        // The selected recovery route is a private inert directory, not an age
        // envelope or a claim that legacy restore reconstructs these originals.
        let selected_before = snapshot(&f.home);
        let status = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        status_private(&status, &wire);
        let status = status_available(&status);
        assert_eq!(status["checkpoint_revision"], seeded.checkpoint.revision.0);
        let digest = status["inspection_digest"].as_str().unwrap();
        assert_recovery_preserved(&f, &seeded, &selected_before, &wire, false);
        let stale = f.root.join("selected-stale-recovery");
        let rejected = recovery_export_cli(
            &f,
            &stale,
            seeded.checkpoint.revision.0.checked_add(1).unwrap(),
            digest,
        );
        status_private(&rejected, &wire);
        let rejected = recovery_export_json(&rejected, "conflict", 2);
        assert_eq!(rejected["reason"], "recovery_inspection_conflict");
        assert!(rejected["artifact"].is_null() && rejected["included_files"].is_null());
        assert!(!stale.exists());
        recovery_export_no_stage(&f);
        recovery_export_source_preserved(&f, &seeded, &selected_before, &wire);
        let destination = f.root.join("selected-recovery");
        assert!(!destination.exists());
        let result = recovery_export_cli(&f, &destination, seeded.checkpoint.revision.0, digest);
        status_private(&result, &wire);
        let receipt = recovery_export_json(&result, "published", 0);
        assert!(receipt["reason"].is_null());
        assert_eq!(receipt["expected_revision"], seeded.checkpoint.revision.0);
        assert_eq!(receipt["expected_inspection"], digest);
        assert_eq!(receipt["publication_qualification"], "published_synced");
        let artifact = &receipt["artifact"];
        assert_eq!(artifact["target"], destination.to_str().unwrap());
        assert_eq!(artifact["owner_session_id"], SESSION);
        assert!(artifact["child_id"].is_null());
        assert_eq!(
            artifact["checkpoint_revision"],
            seeded.checkpoint.revision.0
        );
        assert_eq!(artifact["inspection_digest"], digest);
        assert!(artifact["retained_stage"].is_null());
        let stage = artifact["intended_stage_basename"].as_str().unwrap();
        assert_eq!(stage.len(), 80);
        assert!(stage.starts_with(".recovery-stage-"));
        assert!(!f.root.join(stage).exists());
        let new_manifest_bytes = read_bounded(&destination.join("manifest.json"), 128 * 1024);
        assert_eq!(
            artifact["manifest_sha256"],
            hex::encode(Sha256::digest(&new_manifest_bytes))
        );
        let new_manifest: Value = serde_json::from_slice(&new_manifest_bytes).unwrap();
        assert_eq!(new_manifest["schema"], "orbit.recovery-export/v1");
        assert_eq!(
            new_manifest["source"],
            json!({"owner_session_id":SESSION,"child_id":null})
        );
        assert_eq!(
            new_manifest["capture"],
            json!({"checkpoint_revision":seeded.checkpoint.revision.0,
            "inspection_digest":digest,"qualification":"visible_validated",
            "prior_publication_durability":"not_established","provider_outcome":"not_established"})
        );
        assert_eq!(new_manifest["saved_history"]["kind"], "root");
        assert_eq!(new_manifest["saved_history"]["turns"], 7);
        assert_eq!(
            new_manifest["saved_history"]["unsaved_partial"],
            "unavailable"
        );
        let saved: Value = serde_json::from_slice(&exact_snapshot).unwrap();
        assert_eq!(
            new_manifest["saved_history"]["watermark_revision"],
            saved["accounting_watermark"]["revision"]
        );
        assert_eq!(
            new_manifest["saved_history"]["watermark_full_cost_status"],
            saved["accounting_watermark"]["full_cost_status"]
        );
        assert_eq!(
            new_manifest["accounting"],
            json!({"container_scope":"owner","selected_baseline":"unknown_legacy",
            "selected_knownness":"uncertain","pending_retained":true})
        );
        assert!(
            !f.home
                .join("projects")
                .join(format!("{SESSION}.jsonl"))
                .exists()
        );
        assert_eq!(
            new_manifest["legacy"],
            json!({"present":false,"reason":"not_present"})
        );
        let archive_member = format!(
            "history/archives/{}",
            seeded.archive.file_name().unwrap().to_str().unwrap()
        );
        let members = [
            ("snapshot/root.json", exact_snapshot.as_slice()),
            ("history/accounting.json", exact_accounting.as_slice()),
            (archive_member.as_str(), exact_archive.as_slice()),
        ];
        let files = new_manifest["files"].as_array().unwrap();
        assert_eq!(files.len(), members.len());
        let paths = files
            .iter()
            .map(|file| file["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        for (index, (path, bytes)) in members.into_iter().enumerate() {
            let matching = files
                .iter()
                .filter(|file| file["path"] == path)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["source_relative_path"], expected[index].0);
            assert_eq!(matching[0]["bytes"], bytes.len() as u64);
            assert_eq!(matching[0]["sha256"], expected[index].1);
            assert_eq!(matching[0]["sha256"], hex::encode(Sha256::digest(bytes)));
            assert_eq!(read_bounded(&destination.join(path), 256 * 1024), bytes);
            if path == archive_member {
                assert_eq!(matching[0]["record_id"], seeded.archive_id);
                assert_eq!(matching[0]["application"], "not_established");
            }
        }
        let (count, bytes) = recovery_export_private_tree(&destination);
        assert_eq!(count, 4);
        assert_eq!(receipt["included_files"], count);
        assert_eq!(receipt["included_bytes"], bytes);
        recovery_export_source_preserved(&f, &seeded, &selected_before, &wire);
        f.lease_released();
        recovery_export_no_stage(&f);
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn direct_status_can_inspect_pending_while_source_lease_is_busy_without_config_or_snapshot_decode()
     {
        if !dispatch_isolated(
            "recovery_baselines::direct_status_can_inspect_pending_while_source_lease_is_busy_without_config_or_snapshot_decode",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let lease = SessionLease::acquire(&f.home, SESSION, "held-recovery-source").unwrap();
        assert!(
            matches!(SessionLease::acquire(&f.home,SESSION,"competing"),Err(SessionLeaseError::Busy{session_id})if session_id==SESSION)
        );
        write_private(
            &f.home.join("providers.toml"),
            b"INVALID TOML RECOVERY_PRIVATE_PROVIDER_CONFIG",
        );
        write_private(
            &f.saved_path(),
            b"INVALID SNAPSHOT RECOVERY_PRIVATE_SNAPSHOT_BODY",
        );
        let before = snapshot(&f.home);
        let result = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert!(!result.stdout.contains(PRIVATE) && !result.stderr.contains(PRIVATE));
        assert!(
            !result.stdout.contains("RECOVERY_PRIVATE_PROVIDER_CONFIG")
                && !result.stderr.contains("RECOVERY_PRIVATE_PROVIDER_CONFIG")
        );
        assert!(
            !result.stdout.contains("RECOVERY_PRIVATE_SNAPSHOT_BODY")
                && !result.stderr.contains("RECOVERY_PRIVATE_SNAPSHOT_BODY")
        );
        let supported = if missing_recovery_command(&result) {
            false
        } else {
            assert!(result.status.success());
            assert!(result.stdout.len() <= 16 * 1024);
            let value: Value = serde_json::from_str(&result.stdout).unwrap();
            // These field names come from the preflight's human metadata contract;
            // root must pin the actual additive DTO before a future GREEN migration.
            assert_eq!(value["owner_session_id"], SESSION);
            assert_eq!(value["checkpoint_revision"], 4);
            assert!(result.stdout.contains(PENDING) && result.stdout.contains("uncertain"));
            true
        };
        assert_eq!(
            snapshot(&f.home),
            before,
            "metadata-only status must not acquire or rewrite the source lease or any directory"
        );
        assert_recovery_preserved(&f, &seeded, &before, &wire, false);
        drop(lease);
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
        assert!(
            supported,
            "metadata-only direct status is missing; it must work while source is Busy and without parsing provider config or saved body"
        );
    }

    #[test]
    fn direct_status_missing_and_unsafe_storage_never_create_or_repair_a_namespace() {
        if !dispatch_isolated(
            "recovery_baselines::direct_status_missing_and_unsafe_storage_never_create_or_repair_a_namespace",
        ) {
            return;
        }
        let mut f = Fixture::new();
        let original_home = f.home.clone();
        let before = snapshot(&original_home);
        f.home = f.root.join("missing-home");
        assert!(!f.home.exists());
        let missing = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert!(!f.home.exists());
        assert_eq!(snapshot(&original_home), before);
        assert!(!missing.status.success() || !missing.stdout.contains("fresh_known_zero"));
        f.home = original_home;
        let outside = f.root.join("private-accounting-marker");
        write_private(&outside, b"RECOVERY_PRIVATE_UNSAFE_TARGET");
        let history = f.home.join("context-history");
        assert!(!history.exists());
        symlink(&outside, &history).unwrap();
        let unsafe_before = snapshot(&f.home);
        let marker_before = read_bounded(&outside, 128);
        let unsafe_result = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert!(!unsafe_result.status.success());
        assert!(
            !unsafe_result
                .stdout
                .contains("RECOVERY_PRIVATE_UNSAFE_TARGET")
                && !unsafe_result
                    .stderr
                    .contains("RECOVERY_PRIVATE_UNSAFE_TARGET")
        );
        assert_eq!(snapshot(&f.home), unsafe_before);
        assert_eq!(read_bounded(&outside, 128), marker_before);
        assert!(
            fs::symlink_metadata(&history)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        f.binary_unchanged();
        let missing_feature =
            missing_recovery_command(&missing) || missing_recovery_command(&unsafe_result);
        assert!(
            !missing_feature,
            "new status grammar is absent; missing/unsafe non-creation controls alone are not metadata capability acceptance"
        );
    }

    // Appended status capability controls; the four retained baselines and
    // their helpers above remain unchanged.
    struct StatusBodyWatch(fs::File);
    impl StatusBodyWatch {
        #[allow(unsafe_code)]
        fn new(paths: &[&Path]) -> Self {
            use std::os::fd::{AsRawFd, FromRawFd};
            require_private_system_fixture();
            // SAFETY: a fresh owned descriptor transfers once into File; all
            // watched paths are private terminated paths kept alive here.
            let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(descriptor >= 0);
            let file = unsafe { fs::File::from_raw_fd(descriptor) };
            for path in paths {
                let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert!(
                    unsafe {
                        libc::inotify_add_watch(
                            file.as_raw_fd(),
                            path.as_ptr(),
                            libc::IN_ACCESS | libc::IN_OPEN,
                        )
                    } >= 0
                );
            }
            Self(file)
        }
        fn drain(&mut self) -> usize {
            let mut count = 0usize;
            let mut buffer = [0u8; 4096];
            loop {
                match self.0.read(&mut buffer) {
                    Ok(0) => return count,
                    Ok(read) => {
                        count = count.checked_add(read).unwrap();
                        assert!(count <= 16 * 1024, "status access-watch event bound");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return count,
                    Err(error) => panic!("private status access watch failed: {error}"),
                }
            }
        }
    }

    fn status_available(result: &CliResult) -> Value {
        assert_eq!(result.status.code(), Some(0));
        assert!(result.stderr.is_empty());
        assert!(result.stdout.len() <= 16 * 1024 && result.stdout.ends_with('\n'));
        let value: Value = serde_json::from_str(&result.stdout).unwrap();
        assert_eq!(value["schema"], "orbit.recovery-status/v1");
        assert_eq!(value["status"], "available");
        value
    }

    fn status_private(result: &CliResult, wire: &Wire) {
        for forbidden in [
            PRIVATE,
            "RECOVERY_PRIVATE_PROVIDER_CONFIG",
            "RECOVERY_PRIVATE_SNAPSHOT_BODY",
            "RECOVERY_PRIVATE_PROMPT_NO_DISPATCH",
            "RECOVERY_PRIVATE_STAGE_BODY",
            RAW_A,
            "foreign-synthetic-provider",
            "foreign-synthetic-model",
            "complete synthetic historical result",
            wire.url.as_str(),
            wire.authority.as_str(),
        ] {
            assert!(
                !result.stdout.contains(forbidden) && !result.stderr.contains(forbidden),
                "status exposed a private fixture marker"
            );
        }
    }

    #[test]
    fn status_cli_keeps_pending_and_prior_full_usage_separate_without_reading_private_bodies() {
        if !dispatch_isolated(
            "recovery_baselines::status_cli_keeps_pending_and_prior_full_usage_separate_without_reading_private_bodies",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let lease = SessionLease::acquire(&f.home, SESSION, "status-held-source").unwrap();
        assert!(
            matches!(SessionLease::acquire(&f.home, SESSION, "competing-status-control"),
            Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
        );
        write_private(
            &f.home.join("providers.toml"),
            b"INVALID TOML RECOVERY_PRIVATE_PROVIDER_CONFIG",
        );
        write_private(
            &f.saved_path(),
            b"INVALID SNAPSHOT RECOVERY_PRIVATE_SNAPSHOT_BODY",
        );
        let expected =
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
        assert_eq!(expected.checkpoint, seeded.checkpoint);
        let pending = expected.checkpoint.pending.as_ref().unwrap();
        let prior = expected.last_receipt.as_ref().unwrap();
        let before = snapshot(&f.home);
        let config = f.home.join("providers.toml");
        let saved = f.saved_path();
        let watched = [&config, &saved, &seeded.archive];
        let mut watch = StatusBodyWatch::new(&watched.map(|path| path.as_path()));
        for path in watched {
            assert!(!read_bounded(path, 256 * 1024).is_empty());
            assert!(
                watch.drain() > 0,
                "each watched body read must produce an actual event"
            );
        }

        let result = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert_eq!(
            watch.drain(),
            0,
            "actual status opened or read a private body"
        );
        status_private(&result, &wire);
        let value = status_available(&result);
        assert_eq!(value["owner_session_id"], SESSION);
        assert!(value["child_id"].is_null());
        assert_eq!(value["checkpoint_revision"], 4);
        assert_eq!(value["baseline"], "unknown_legacy");
        assert_eq!(value["accounting_scope"], "since_namespace_initialization");
        assert_eq!(value["totals"]["knownness"], "uncertain");
        for (name, totals) in [
            ("ordinary", seeded.checkpoint.totals.ordinary),
            ("housekeeping", seeded.checkpoint.totals.housekeeping),
        ] {
            assert_eq!(
                value["totals"][name],
                json!({"input_tokens":totals.input_tokens,
                "output_tokens":totals.output_tokens,"cost_microcents":totals.cost_microcents})
            );
        }
        assert!(value["totals"]["ordinary"]["cost_microcents"].is_null());
        assert_eq!(value["known_priced_subtotals"]["ordinary_microcents"], 0);
        assert_eq!(
            value["known_priced_subtotals"]["housekeeping_microcents"],
            7
        );
        assert_eq!(value["lifecycle"], "uncertain_receipt");
        assert_eq!(
            value["pending"]["reference"]["revision"],
            pending.reference.revision.0
        );
        assert_eq!(value["pending"]["reference"]["request_id"], PENDING);
        assert_eq!(
            value["pending"]["reference"]["intent_digest"],
            pending.reference.intent_digest
        );
        assert_eq!(value["pending"]["expected_previous_revision"], 2);
        assert_eq!(value["pending"]["purpose"], "ordinary");
        assert_eq!(value["pending"]["uncertain"], true);
        assert_eq!(
            value["pending"]["budget"]["binding_digest"],
            pending.intent.budget.binding_digest
        );
        assert_eq!(
            value["pending"]["budget"]["metadata_revision"],
            pending.intent.budget.metadata_revision
        );
        assert_eq!(
            value["pending"]["budget"]["policy_revision"],
            pending.intent.budget.policy_revision
        );
        let pending_receipt = &value["pending"]["receipt"];
        assert_eq!(pending_receipt["request_id"], PENDING);
        assert_eq!(pending_receipt["purpose"], "ordinary");
        assert_eq!(pending_receipt["knownness"], "uncertain");
        assert_eq!(pending_receipt["completed"], false);
        assert_eq!(pending_receipt["known_totals"]["input_tokens"], 0);
        assert_eq!(pending_receipt["known_totals"]["output_tokens"], 0);
        assert!(pending_receipt["known_totals"]["cost_microcents"].is_null());
        assert_eq!(
            pending_receipt["usage_qualification"],
            "provisional_observed"
        );
        assert_eq!(
            pending_receipt["observed_usage"],
            json!({"input_tokens":19,"output_tokens":5,
            "cache_read_tokens":3,"cache_write_tokens":2,"reasoning_tokens":4})
        );
        let prior_reference = expected.checkpoint.last_settlement.as_ref().unwrap();
        let last = &value["last_settlement"];
        assert_eq!(
            last["reference"]["revision"],
            prior_reference.reference.revision.0
        );
        assert_eq!(last["reference"]["request_id"], prior.request_id);
        assert_eq!(
            last["reference"]["intent_digest"],
            prior_reference.reference.intent_digest
        );
        assert_eq!(last["receipt_digest"], prior_reference.receipt_digest);
        assert_eq!(last["receipt"]["request_id"], prior.request_id);
        assert_ne!(prior.request_id, PENDING);
        assert_eq!(
            last["receipt"]["purpose"],
            match prior.purpose {
                AttemptPurpose::Ordinary => "ordinary",
                AttemptPurpose::Chunk => "chunk",
                AttemptPurpose::Merge => "merge",
            }
        );
        assert_eq!(last["receipt"]["knownness"], "known");
        assert_eq!(last["receipt"]["completed"], true);
        assert_eq!(
            last["receipt"]["known_totals"]["input_tokens"],
            prior.totals.input_tokens
        );
        assert_eq!(
            last["receipt"]["known_totals"]["output_tokens"],
            prior.totals.output_tokens
        );
        assert_eq!(last["receipt"]["known_totals"]["cost_microcents"], 7);
        assert_eq!(last["receipt"]["usage_qualification"], "validated_final");
        assert_eq!(
            last["receipt"]["observed_usage"],
            json!(prior.usage.unwrap())
        );
        assert!(last.get("budget").is_none());
        assert_eq!(value["inspection_digest"], expected.inspection_digest);
        let digest = value["inspection_digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            value["inspection"],
            json!({"qualification":"visible_validated",
            "prior_publication_durability":"not_established","provider_outcome":"not_established_by_inspection"})
        );

        let repeated = cli(
            &f,
            &["recovery", "status", "--json", "--session", SESSION],
            "",
        );
        assert_eq!(watch.drain(), 0);
        status_private(&repeated, &wire);
        assert_eq!(status_available(&repeated), value);
        let human = cli(&f, &["recovery", "status", "--session", SESSION], "");
        assert_eq!(watch.drain(), 0);
        assert_eq!(human.status.code(), Some(0));
        assert!(human.stderr.is_empty() && human.stdout.len() <= 16 * 1024);
        assert!(human.stdout.is_ascii() && !human.stdout.contains('\u{1b}'));
        status_private(&human, &wire);
        for required in [
            PENDING,
            prior.request_id.as_str(),
            "Pending attempt: unresolved",
            "Prior settlement:",
            "provisional_observed",
            "validated_final",
            "cache_read_tokens=3 cache_write_tokens=2 reasoning_tokens=4",
            "not established by inspection",
            digest,
        ] {
            assert!(
                human.stdout.contains(required),
                "human status omitted a required metadata qualification"
            );
        }
        drop(watch);
        assert_recovery_preserved(&f, &seeded, &before, &wire, false);
        drop(lease);
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn status_cli_distinguishes_untracked_writer_busy_and_unavailable_staging_without_repair() {
        if !dispatch_isolated(
            "recovery_baselines::status_cli_distinguishes_untracked_writer_busy_and_unavailable_staging_without_repair",
        ) {
            return;
        }
        let mut f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let before = snapshot(&f.home);
        let original_home = f.home.clone();
        f.home = f.root.join("absent-status-home");
        assert!(!f.home.exists());
        let missing = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert_eq!(missing.status.code(), Some(0));
        assert!(missing.stderr.is_empty() && missing.stdout.len() <= 512);
        let missing_value: Value = serde_json::from_str(&missing.stdout).unwrap();
        assert_eq!(missing_value["schema"], "orbit.recovery-status/v1");
        assert_eq!(missing_value["status"], "untracked");
        assert_eq!(missing_value["reason"], "accounting_missing");
        assert!(missing_value["code"].is_null());
        assert_eq!(missing_value.as_object().unwrap().len(), 7);
        for field in [
            "checkpoint_revision",
            "baseline",
            "totals",
            "lifecycle",
            "inspection_digest",
            "pending",
        ] {
            assert!(missing_value.get(field).is_none());
        }
        assert!(!f.home.exists());
        f.home = original_home;
        assert_eq!(snapshot(&f.home), before);

        let path = f
            .home
            .join("context-history")
            .join(SESSION)
            .join(".history.lock");
        let descriptor = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .unwrap();
        let metadata = descriptor.metadata().unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (
                fs::symlink_metadata(&path).unwrap().dev(),
                fs::symlink_metadata(&path).unwrap().ino()
            )
        );
        assert!(metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600);
        rustix::fs::flock(
            &descriptor,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        assert_eq!(
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None),
            Err(orbit_engine::HistoryError::Busy)
        );
        let busy = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert_eq!(busy.status.code(), Some(2));
        assert!(busy.stderr.is_empty() && busy.stdout.len() <= 512);
        let busy_value: Value = serde_json::from_str(&busy.stdout).unwrap();
        assert_eq!(busy_value["status"], "busy");
        assert_eq!(busy_value["code"], "ORBIT-E0400");
        assert_eq!(busy_value["reason"], "history_writer_busy");
        assert_eq!(busy_value.as_object().unwrap().len(), 7);
        assert!(
            busy_value.get("totals").is_none() && busy_value.get("inspection_digest").is_none()
        );
        assert_eq!(snapshot(&f.home), before);
        rustix::fs::flock(&descriptor, rustix::fs::FlockOperation::Unlock).unwrap();
        drop(descriptor);
        assert_recovery_preserved(&f, &seeded, &before, &wire, false);
        f.lease_released();

        // An owned inert stage is an explicit fixture mutation. Preserve the
        // whole staged tree exactly across status; no cleanup/repair is allowed.
        let stage = f
            .home
            .join("context-history")
            .join(SESSION)
            .join(".stage-status-control");
        write_private(&stage, b"RECOVERY_PRIVATE_STAGE_BODY");
        let staged_before = snapshot(&f.home);
        let staged = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        assert_eq!(staged.status.code(), Some(2));
        assert!(staged.stderr.is_empty() && staged.stdout.len() <= 512);
        let staged_value: Value = serde_json::from_str(&staged.stdout).unwrap();
        assert_eq!(staged_value["status"], "unavailable");
        assert_eq!(staged_value["reason"], "inspection_uncertain");
        assert_eq!(staged_value.as_object().unwrap().len(), 7);
        assert!(staged_value.get("pending").is_none() && staged_value.get("totals").is_none());
        assert_eq!(snapshot(&f.home), staged_before);
        for result in [&missing, &busy, &staged] {
            status_private(result, &wire);
        }
        assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
        assert_eq!(wire.requests.lock().unwrap().len(), 1);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn status_cli_strict_grammar_rejects_help_prompt_overrides_and_duplicates_before_startup() {
        if !dispatch_isolated(
            "recovery_baselines::status_cli_strict_grammar_rejects_help_prompt_overrides_and_duplicates_before_startup",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(Vec::new());
        f.configure(&wire);
        if !f.home.join("sessions").exists() {
            private_directory(&f.home.join("sessions"));
        }
        write_private(
            &f.home.join("providers.toml"),
            b"INVALID TOML RECOVERY_PRIVATE_PROVIDER_CONFIG",
        );
        write_private(
            &f.saved_path(),
            b"INVALID SNAPSHOT RECOVERY_PRIVATE_SNAPSHOT_BODY",
        );
        let before = snapshot(&f.home);
        let config = f.home.join("providers.toml");
        let saved = f.saved_path();
        let mut watch = StatusBodyWatch::new(&[&config, &saved]);
        for path in [&config, &saved] {
            assert!(!read_bounded(path, 256).is_empty());
            assert!(watch.drain() > 0);
        }
        let home = f.home.to_str().unwrap();
        let vectors: [&[&str]; 7] = [
            &[
                "recovery",
                "status",
                "--session",
                SESSION,
                "--json",
                "--json",
            ],
            &[
                "--help",
                "recovery",
                "status",
                "--session",
                SESSION,
                "--json",
            ],
            &[
                "-p",
                "RECOVERY_PRIVATE_PROMPT_NO_DISPATCH",
                "recovery",
                "status",
                "--session",
                SESSION,
            ],
            &[
                "--model",
                "RECOVERY_PRIVATE_PROVIDER_CONFIG",
                "--provider",
                "RECOVERY_PRIVATE_PROVIDER_CONFIG",
                "recovery",
                "status",
                "--session",
                SESSION,
            ],
            &["--home", home, "recovery", "status", "--session", SESSION],
            &[
                "recovery",
                "status",
                "--session",
                SESSION,
                "--child",
                "not-a-canonical-child",
            ],
            &["recovery", "status", "--session", SESSION, "--help"],
        ];
        for args in vectors {
            let result = cli(&f, args, "");
            assert_eq!(
                watch.drain(),
                0,
                "invalid status reached a private body consumer"
            );
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty() && result.stderr.len() <= 512);
            assert!(
                result
                    .stderr
                    .starts_with("ORBIT-E1101: recovery_status_usage; usage: orbit ")
            );
            status_private(&result, &wire);
            assert_eq!(snapshot(&f.home), before);
            // The preservation snapshot deliberately reads these same bodies.
            // Drain its positively observed events only AFTER the independent
            // zero-event CLI assertion above, before the next CLI launch.
            assert!(watch.drain() > 0);
            assert!(!f.home.join("context-history").exists());
            assert!(
                !f.home.join("sessions/.leases").exists()
                    || fs::read_dir(f.home.join("sessions/.leases"))
                        .unwrap()
                        .next()
                        .is_none()
            );
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            assert!(wire.requests.lock().unwrap().is_empty());
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        }
        drop(watch);
        wire.finish();
        f.binary_unchanged();
    }
    fn recovery_export_cli(
        f: &Fixture,
        destination: &Path,
        revision: u64,
        digest: &str,
    ) -> CliResult {
        let revision = revision.to_string();
        cli(
            f,
            &[
                "recovery",
                "export",
                "--session",
                SESSION,
                "--expect-revision",
                &revision,
                "--expect-inspection",
                digest,
                "--to",
                destination.to_str().unwrap(),
                "--json",
            ],
            "",
        )
    }

    fn recovery_export_json(
        result: &CliResult,
        expected_status: &str,
        expected_code: i32,
    ) -> Value {
        assert_eq!(result.status.code(), Some(expected_code));
        assert!(result.stderr.is_empty());
        assert!(result.stdout.len() <= 16 * 1024 && result.stdout.ends_with('\n'));
        let value: Value = serde_json::from_str(&result.stdout).unwrap();
        assert_eq!(value["schema"], "orbit.recovery-export-result/v1");
        assert_eq!(value["command"], "recovery_export");
        assert_eq!(value["status"], expected_status);
        assert_eq!(value["owner_session_id"], SESSION);
        assert!(value["child_id"].is_null());
        assert_eq!(value["provider_outcome"], "not_established");
        assert_eq!(value["prior_source_durability"], "not_established");
        value
    }

    fn recovery_export_source_preserved(
        f: &Fixture,
        seed: &Seed,
        before: &BTreeMap<PathBuf, Stamp>,
        wire: &Wire,
    ) {
        assert_eq!(
            startup_tree_without_expected_descriptor_changes(&snapshot(&f.home)),
            startup_tree_without_expected_descriptor_changes(before)
        );
        assert_eq!(f.checkpoint(), seed.checkpoint);
        assert_eq!(
            load_compaction_source(&f.home, SESSION, None, &seed.archive_id).unwrap(),
            seed.original
        );
        assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
        assert_eq!(wire.requests.lock().unwrap().len(), 1);
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
    }

    fn recovery_export_private_tree(root: &Path) -> (usize, u64) {
        let owner = fs::symlink_metadata(root).unwrap().uid();
        let mut pending = vec![root.to_path_buf()];
        let mut files = 0usize;
        let mut bytes = 0u64;
        let mut entries = 0usize;
        while let Some(path) = pending.pop() {
            entries += 1;
            assert!(entries <= 80);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.uid(), owner);
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                assert_eq!(metadata.mode() & 0o777, 0o700);
                for entry in fs::read_dir(path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
            } else {
                assert!(metadata.is_file());
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(metadata.mode() & 0o777, 0o600);
                files += 1;
                bytes = bytes.checked_add(metadata.len()).unwrap();
                assert!(files <= 72 && bytes <= 256 * 1024 * 1024);
            }
        }
        (files, bytes)
    }

    fn recovery_export_no_stage(f: &Fixture) {
        assert!(!fs::read_dir(&f.root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".recovery-stage-")
        }));
    }

    #[test]
    fn recovery_export_cli_preserves_exact_typed_originals_pending_evidence_and_legacy_without_replay()
     {
        if !dispatch_isolated(
            "recovery_baselines::recovery_export_cli_preserves_exact_typed_originals_pending_evidence_and_legacy_without_replay",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let projects = f.home.join("projects");
        if !projects.exists() {
            private_directory(&projects);
        }
        let legacy = projects.join(format!("{SESSION}.jsonl"));
        let legacy_bytes =
            b"inert legacy bytes, not a replay command\nRECOVERY_PRIVATE_OPAQUE_ORIGINAL\n";
        write_private(&legacy, legacy_bytes);
        write_private(
            &f.home.join("providers.toml"),
            b"INVALID TOML RECOVERY_PRIVATE_PROVIDER_CONFIG",
        );
        let before = snapshot(&f.home);
        let saved_bytes = read_bounded(&f.saved_path(), 256 * 1024);
        let accounting_bytes = read_bounded(&f.accounting_path(), 128 * 1024);
        let archive_bytes = read_bounded(&seeded.archive, 256 * 1024);
        assert!(String::from_utf8_lossy(&archive_bytes).contains(PRIVATE));
        let status = cli(
            &f,
            &["recovery", "status", "--session", SESSION, "--json"],
            "",
        );
        let status = status_available(&status);
        assert_eq!(status["checkpoint_revision"], 4);
        let digest = status["inspection_digest"].as_str().unwrap();
        let destination = f.root.join("saved-recovery");
        assert!(!destination.exists());
        let result = recovery_export_cli(&f, &destination, 4, digest);
        status_private(&result, &wire);
        let receipt = recovery_export_json(&result, "published", 0);
        assert!(receipt["reason"].is_null());
        assert_eq!(receipt["expected_revision"], 4);
        assert_eq!(receipt["expected_inspection"], digest);
        assert_eq!(receipt["publication_qualification"], "published_synced");
        let artifact = &receipt["artifact"];
        assert_eq!(artifact["target"], destination.to_str().unwrap());
        assert_eq!(artifact["owner_session_id"], SESSION);
        assert_eq!(artifact["checkpoint_revision"], 4);
        assert_eq!(artifact["inspection_digest"], digest);
        assert!(artifact["retained_stage"].is_null());
        let stage = artifact["intended_stage_basename"].as_str().unwrap();
        assert_eq!(stage.len(), 80);
        assert!(stage.starts_with(".recovery-stage-"));
        assert!(!f.root.join(stage).exists());
        let manifest_bytes = read_bounded(&destination.join("manifest.json"), 128 * 1024);
        assert_eq!(
            artifact["manifest_sha256"],
            hex::encode(Sha256::digest(&manifest_bytes))
        );
        let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest["schema"], "orbit.recovery-export/v1");
        assert_eq!(
            manifest["source"],
            json!({"owner_session_id":SESSION,"child_id":null})
        );
        assert_eq!(
            manifest["capture"],
            json!({"checkpoint_revision":4,"inspection_digest":digest,
            "qualification":"visible_validated","prior_publication_durability":"not_established","provider_outcome":"not_established"})
        );
        assert_eq!(manifest["saved_history"]["kind"], "root");
        assert_eq!(manifest["saved_history"]["turns"], 7);
        assert_eq!(manifest["saved_history"]["unsaved_partial"], "unavailable");
        let saved: Value = serde_json::from_slice(&saved_bytes).unwrap();
        assert_eq!(
            manifest["saved_history"]["watermark_revision"],
            saved["accounting_watermark"]["revision"]
        );
        assert_eq!(manifest["accounting"]["container_scope"], "owner");
        assert_eq!(
            manifest["accounting"]["selected_baseline"],
            "unknown_legacy"
        );
        assert_eq!(manifest["accounting"]["selected_knownness"], "uncertain");
        assert_eq!(manifest["accounting"]["pending_retained"], true);
        assert_eq!(manifest["legacy"], json!({"present":true,"reason":null}));
        let archive_member = format!(
            "history/archives/{}",
            seeded.archive.file_name().unwrap().to_str().unwrap()
        );
        let expected = [
            ("snapshot/root.json", saved_bytes.as_slice()),
            ("history/accounting.json", accounting_bytes.as_slice()),
            (archive_member.as_str(), archive_bytes.as_slice()),
            ("history/legacy.jsonl", legacy_bytes.as_slice()),
        ];
        let files = manifest["files"].as_array().unwrap();
        assert_eq!(files.len(), expected.len());
        let mut paths = files
            .iter()
            .map(|entry| entry["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        let original_order = paths.clone();
        paths.sort_unstable();
        assert_eq!(paths, original_order);
        for (path, expected_bytes) in expected {
            let matching = files
                .iter()
                .filter(|entry| entry["path"] == path)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["bytes"], expected_bytes.len() as u64);
            assert_eq!(
                matching[0]["sha256"],
                hex::encode(Sha256::digest(expected_bytes))
            );
            assert_eq!(
                read_bounded(&destination.join(path), 256 * 1024),
                expected_bytes
            );
            if path == archive_member {
                assert_eq!(matching[0]["application"], "not_established");
            }
        }
        let (count, bytes) = recovery_export_private_tree(&destination);
        assert_eq!(count, 5);
        assert_eq!(receipt["included_files"], count);
        assert_eq!(receipt["included_bytes"], bytes);
        recovery_export_source_preserved(&f, &seeded, &before, &wire);
        f.lease_released();
        recovery_export_no_stage(&f);
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn recovery_export_cli_refuses_stale_revision_and_digest_without_payload_or_provider_effects() {
        if !dispatch_isolated(
            "recovery_baselines::recovery_export_cli_refuses_stale_revision_and_digest_without_payload_or_provider_effects",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let inspected =
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
        let before = snapshot(&f.home);
        let stale_digest = "f".repeat(64);
        for (name, revision, digest) in [
            ("stale-revision", 5, inspected.inspection_digest.as_str()),
            ("stale-digest", 4, stale_digest.as_str()),
        ] {
            let destination = f.root.join(name);
            let result = recovery_export_cli(&f, &destination, revision, digest);
            status_private(&result, &wire);
            let value = recovery_export_json(&result, "conflict", 2);
            assert_eq!(value["reason"], "recovery_inspection_conflict");
            assert!(value["artifact"].is_null() && value["included_files"].is_null());
            assert_eq!(value["publication_qualification"], "not_established");
            assert!(!destination.exists());
            recovery_export_no_stage(&f);
            recovery_export_source_preserved(&f, &seeded, &before, &wire);
        }
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
    }

    #[test]
    fn recovery_export_cli_never_takes_a_busy_source_or_replaces_an_existing_output() {
        if !dispatch_isolated(
            "recovery_baselines::recovery_export_cli_never_takes_a_busy_source_or_replaces_an_existing_output",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        let seeded = seed(&f, &wire);
        let inspected =
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
        let lease = SessionLease::acquire(&f.home, SESSION, "held-export-source").unwrap();
        let before = snapshot(&f.home);
        let absent = f.root.join("busy-export");
        let busy = recovery_export_cli(&f, &absent, 4, &inspected.inspection_digest);
        status_private(&busy, &wire);
        let value = recovery_export_json(&busy, "busy", 2);
        assert_eq!(value["reason"], "recovery_session_busy");
        assert!(value["artifact"].is_null() && !absent.exists());
        assert!(
            matches!(SessionLease::acquire(&f.home, SESSION, "still-held"), Err(SessionLeaseError::Busy { session_id }) if session_id==SESSION)
        );
        recovery_export_source_preserved(&f, &seeded, &before, &wire);
        drop(lease);
        let existing = f.root.join("existing-recovery");
        private_directory(&existing);
        write_private(&existing.join("sentinel"), b"keep existing output exact");
        let output_before = snapshot(&existing);
        let source_before = snapshot(&f.home);
        let result = recovery_export_cli(&f, &existing, 4, &inspected.inspection_digest);
        status_private(&result, &wire);
        let value = recovery_export_json(&result, "unavailable", 2);
        assert_eq!(value["reason"], "recovery_destination_exists");
        assert!(value["artifact"].is_null());
        assert_eq!(snapshot(&existing), output_before);
        recovery_export_source_preserved(&f, &seeded, &source_before, &wire);
        f.lease_released();
        recovery_export_no_stage(&f);
        wire.finish();
        f.binary_unchanged();
    }
    // Snapshot-only fixtures. Public checked RECORD constructors validate all
    // digests; no private hash algorithm or live authority factory is copied.
    fn ordered_snapshot_object(fields: &[(&str, String)]) -> String {
        let fields = fields
            .iter()
            .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
            .collect::<Vec<_>>();
        format!("{{{}}}", fields.join(","))
    }
    fn snapshot_scalar(value: impl serde::Serialize) -> String {
        serde_json::to_string(&value).unwrap()
    }
    fn snapshot_reference(reference: &orbit_engine::compaction::AttemptRef) -> String {
        ordered_snapshot_object(&[
            ("revision", snapshot_scalar(reference.revision.0)),
            ("request_id", snapshot_scalar(&reference.request_id)),
            ("intent_digest", snapshot_scalar(&reference.intent_digest)),
        ])
    }
    fn snapshot_record(record: &orbit_engine::retry::RefusalRecord) -> String {
        let intent = record.intent();
        let binding = record.binding();
        let budget = ordered_snapshot_object(&[
            (
                "binding_digest",
                snapshot_scalar(&intent.budget.binding_digest),
            ),
            (
                "metadata_revision",
                snapshot_scalar(&intent.budget.metadata_revision),
            ),
            (
                "policy_revision",
                snapshot_scalar(&intent.budget.policy_revision),
            ),
        ]);
        let intent = ordered_snapshot_object(&[
            (
                "owner_session_id",
                snapshot_scalar(&intent.owner_session_id),
            ),
            ("child_id", snapshot_scalar(&intent.child_id)),
            ("request_id", snapshot_scalar(&intent.request_id)),
            ("purpose", snapshot_scalar("ordinary")),
            ("budget", budget),
        ]);
        let binding = ordered_snapshot_object(&[
            ("request_id", snapshot_scalar(binding.request_id())),
            ("decision_id", snapshot_scalar(binding.decision_id())),
            ("attempt_id", snapshot_scalar(binding.attempt_id())),
            (
                "provider_digest",
                snapshot_scalar(binding.provider_digest()),
            ),
            ("model_digest", snapshot_scalar(binding.model_digest())),
            ("route_digest", snapshot_scalar(binding.route_digest())),
            ("body_digest", snapshot_scalar(binding.body_digest())),
            (
                "adapter_identity_sha256",
                snapshot_scalar(binding.adapter_identity_sha256()),
            ),
            ("policy_digest", snapshot_scalar(binding.policy_digest())),
            ("digest", snapshot_scalar(binding.digest())),
        ]);
        ordered_snapshot_object(&[
            ("intent", intent),
            ("attempt", snapshot_reference(record.attempt())),
            ("binding", binding),
            (
                "observation_digest",
                snapshot_scalar(record.observation_digest()),
            ),
            ("status", snapshot_scalar(record.status())),
            (
                "response_body_bytes",
                snapshot_scalar(record.response_body_bytes()),
            ),
            ("digest", snapshot_scalar(record.digest())),
        ])
    }
    fn seed_retained_refusal_snapshot(
        f: &Fixture,
        wire: &Wire,
        baseline: AccountingBaseline,
        later_success: bool,
        uncertain: bool,
    ) -> (
        Vec<u8>,
        orbit_cli::context_history::DetailedAccountingInspection,
    ) {
        use orbit_engine::compaction::{AccountingRevision, AttemptRef};
        use orbit_engine::context_budget::BudgetIdentity;
        use orbit_engine::retry::{OrdinaryAttemptBindingRecord, RefusalRecord, RefusalRollup};
        assert!(!uncertain || later_success);
        f.configure(wire);
        let lease = SessionLease::acquire(&f.home, SESSION, "checked-snapshot-fixture").unwrap();
        let transcript = vec![
            orbit_engine::user_message(PRIVATE),
            orbit_engine::assistant_message("saved synthetic answer"),
        ];
        lease
            .save(&SessionFile::from_chat(
                SESSION,
                RAW_A,
                &wire.url,
                "provider_a",
                &transcript,
                1,
                11,
                3,
                7,
            ))
            .unwrap();
        let journal = context_journal(&f.home, SESSION, None).unwrap();
        journal.initialize_accounting(baseline).unwrap();
        let intent = |request: &str| AttemptIntent {
            owner_session_id: SESSION.into(),
            child_id: None,
            request_id: request.into(),
            purpose: AttemptPurpose::Ordinary,
            budget: BudgetIdentity {
                binding_digest: "a".repeat(64),
                metadata_revision: "metadata".into(),
                policy_revision: "policy".into(),
            },
        };
        if later_success {
            let reference = journal
                .begin_attempt(AccountingRevision(0), &intent("success"))
                .unwrap();
            let receipt = RequestAccountingReceipt {
                request_id: "success".into(),
                purpose: AttemptPurpose::Ordinary,
                totals: AccountingTotals {
                    input_tokens: 11,
                    output_tokens: 3,
                    cost_microcents: Some(7),
                },
                usage: Some(ProviderUsage {
                    input_tokens: 11,
                    output_tokens: 3,
                    ..Default::default()
                }),
                knownness: AccountingKnownness::Known,
                completed: true,
            };
            journal.settle_attempt(&reference, &receipt).unwrap();
            if uncertain {
                let reference = journal
                    .begin_attempt(AccountingRevision(2), &intent("pending"))
                    .unwrap();
                journal
                    .settle_attempt(
                        &reference,
                        &RequestAccountingReceipt {
                            request_id: "pending".into(),
                            purpose: AttemptPurpose::Ordinary,
                            totals: AccountingTotals {
                                input_tokens: 0,
                                output_tokens: 0,
                                cost_microcents: None,
                            },
                            usage: None,
                            knownness: AccountingKnownness::Uncertain,
                            completed: false,
                        },
                    )
                    .unwrap();
            }
        }
        let intent = intent("refused");
        let reference = AttemptRef {
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
        let record =
            RefusalRecord::new(intent, reference, binding, "9".repeat(64), 503, 0).unwrap();
        let rollup = RefusalRollup::first(record.clone()).unwrap();
        let mut raw = String::from_utf8(read_bounded(&f.accounting_path(), 128 * 1024)).unwrap();
        // Preserve the existing private codec's canonical key order. The
        // controlled revision shifts insert one older, retained refusal.
        if uncertain {
            raw = raw
                .replacen("\"revision\":4", "\"revision\":6", 1)
                .replacen("\"revision\":3", "\"revision\":5", 1)
                .replacen("\"revision\":1", "\"revision\":3", 1);
        } else if later_success {
            raw = raw
                .replacen("\"revision\":2", "\"revision\":4", 1)
                .replacen("\"revision\":1", "\"revision\":3", 1);
        } else {
            raw = raw.replacen("\"revision\":0", "\"revision\":2", 1);
            let last = ordered_snapshot_object(&[
                ("reference", snapshot_reference(record.attempt())),
                ("refused", snapshot_record(&record)),
            ]);
            raw = raw.replacen("\"last\":null", &format!("\"last\":{last}"), 1);
        }
        if baseline == AccountingBaseline::FreshKnownZero {
            raw = raw.replacen(
                if later_success {
                    "\"cost_microcents\":7"
                } else {
                    "\"cost_microcents\":0"
                },
                "\"cost_microcents\":null",
                1,
            );
            if !uncertain {
                raw = raw.replacen(
                    "\"knownness\":\"known\"",
                    "\"knownness\":\"unknown_usage\"",
                    1,
                );
            }
        }
        let rollup = ordered_snapshot_object(&[
            ("count", snapshot_scalar(rollup.count())),
            ("chain_digest", snapshot_scalar(rollup.chain_digest())),
            (
                "previous_chain_digest",
                snapshot_scalar(rollup.previous_chain_digest()),
            ),
            ("latest", snapshot_record(rollup.latest())),
        ]);
        let entry_end = raw.rfind("}]}").unwrap();
        raw.insert_str(entry_end, &format!(",\"refusals\":{rollup}"));
        assert!(raw.len() <= 128 * 1024);
        write_private(&f.accounting_path(), raw.as_bytes());
        drop(journal);
        drop(lease);
        let inspection =
            orbit_cli::context_history::inspect_accounting_detailed(&f.home, SESSION, None)
                .unwrap();
        assert_eq!(inspection.checkpoint.refusals().unwrap().latest(), &record);
        assert_eq!(
            orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None),
            Err(orbit_engine::compaction::HistoryError::InvalidRecord)
        );
        (raw.into_bytes(), inspection)
    }

    #[test]
    fn qualified_refusal_status_and_inert_export_preserve_exact_snapshot_and_independent_uncertainty()
     {
        if !dispatch_isolated(
            "recovery_baselines::qualified_refusal_status_and_inert_export_preserve_exact_snapshot_and_independent_uncertainty",
        ) {
            return;
        }
        for (baseline, later, uncertain, knownness) in [
            (
                AccountingBaseline::FreshKnownZero,
                false,
                false,
                "unknown_usage",
            ),
            (
                AccountingBaseline::FreshKnownZero,
                true,
                false,
                "unknown_usage",
            ),
            (AccountingBaseline::UnknownLegacy, true, true, "uncertain"),
        ] {
            let f = Fixture::new();
            let mut wire = Wire::new(Vec::new());
            let (accounting, inspection) =
                seed_retained_refusal_snapshot(&f, &wire, baseline, later, uncertain);
            let before = snapshot(&f.home);
            let result = cli(
                &f,
                &["recovery", "status", "--session", SESSION, "--json"],
                "",
            );
            status_private(&result, &wire);
            let value = status_available(&result);
            assert_eq!(value["totals"]["knownness"], knownness);
            assert!(value["totals"]["ordinary"]["cost_microcents"].is_null());
            assert_eq!(value["retained_refusal"]["count"], 1);
            assert_eq!(value["retained_refusal"]["status"], 503);
            for key in [
                "generation_final_refusal",
                "billing_unknown",
                "usage_unknown",
                "policy_assumption",
                "visible_validated",
            ] {
                assert_eq!(value["retained_refusal"][key], true);
            }
            assert_eq!(
                value["retained_refusal"]["latest_settlement_digest"],
                inspection.checkpoint.refusals().unwrap().latest().digest()
            );
            if later {
                assert_eq!(value["last_settlement"]["receipt"]["completed"], true);
                assert_eq!(value["known_priced_subtotals"]["ordinary_microcents"], 7);
            } else {
                assert_eq!(
                    value["last_settlement"]["disposition"],
                    "final_generation_refusal"
                );
                assert!(value["last_settlement"].get("receipt").is_none());
            }
            if uncertain {
                assert_eq!(value["lifecycle"], "uncertain_receipt");
            }
            let text = cli(&f, &["recovery", "status", "--session", SESSION], "");
            assert_eq!(text.status.code(), Some(0));
            assert!(text.stderr.is_empty());
            assert!(text.stdout.contains("generation_final_refusal=true billing_unknown=true usage_unknown=true policy_assumption=true visible_validated=true"));
            assert!(!text.stdout.contains(PRIVATE) && !text.stdout.contains(&wire.url));
            assert_eq!(snapshot(&f.home), before);
            let destination = f.root.join("qualified-export");
            let stale = recovery_export_cli(
                &f,
                &destination,
                inspection.checkpoint.revision().0 + 1,
                &inspection.inspection_digest,
            );
            recovery_export_json(&stale, "conflict", 2);
            assert!(!destination.exists());
            recovery_export_no_stage(&f);
            let exported = recovery_export_cli(
                &f,
                &destination,
                inspection.checkpoint.revision().0,
                &inspection.inspection_digest,
            );
            recovery_export_json(&exported, "published", 0);
            assert_eq!(
                read_bounded(&destination.join("history/accounting.json"), 128 * 1024),
                accounting
            );
            let manifest: Value = serde_json::from_slice(&read_bounded(
                &destination.join("manifest.json"),
                128 * 1024,
            ))
            .unwrap();
            assert_eq!(
                manifest["accounting"]["retained_refusal"],
                value["retained_refusal"]
            );
            assert_eq!(manifest["accounting"]["selected_knownness"], knownness);
            assert_eq!(manifest["accounting"]["pending_retained"], uncertain);
            assert_eq!(
                manifest["capture"]["prior_publication_durability"],
                "not_established"
            );
            assert_eq!(manifest["capture"]["provider_outcome"], "not_established");
            assert_eq!(read_bounded(&f.accounting_path(), 128 * 1024), accounting);
            assert_eq!(
                orbit_cli::context_history::inspect_accounting_detailed(&f.home, SESSION, None)
                    .unwrap(),
                inspection
            );
            let published_before = snapshot(&destination);
            let duplicate = recovery_export_cli(
                &f,
                &destination,
                inspection.checkpoint.revision().0,
                &inspection.inspection_digest,
            );
            recovery_export_json(&duplicate, "unavailable", 2);
            assert_eq!(snapshot(&destination), published_before);
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            assert!(wire.requests.lock().unwrap().is_empty());
            f.lease_released();
            wire.finish();
            f.binary_unchanged();
        }
    }
}
