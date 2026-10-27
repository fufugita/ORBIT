// Managed worker cases do not establish PTY or terminal-cell behavior.
#![cfg(target_os = "linux")]

mod frontend_manual_baselines {
    use orbit_adapter::types::ChatMessage;
    use orbit_cli::context_history::{context_journal, load_compaction_source};
    use orbit_cli::daemon::{OwnerConfig, OwnerError, OwnerRuntime, TurnState, UnixServer};
    use orbit_cli::phase_routing::SelectionOrigin;
    use orbit_cli::session_accounting::{FullCostStatus, RootOrigin, prepare_root};
    use orbit_cli::sessions::{self, SessionFile, SessionLease, SessionLeaseError};
    use orbit_cli::tool_runtime::PermissionScope;
    use orbit_cli::tui_worker::TuiTurnConfig;
    use orbit_engine::{AccountingBaseline, AccountingCheckpoint};
    use orbit_hud_tui::msg::{
        ContextProjection, ManualOutcome, ProjectionReason, SessionProjection,
    };
    use orbit_hud_tui::worker::{
        CancelHandle, ManualAction, ManualOperation, WorkerCommand, WorkerCtx,
    };
    use orbit_hud_tui::{ApprovalRegistry, bus::Bus, msg::Msg};
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
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    const MAX_BODY: usize = 4 * 1024 * 1024;
    const MAX_REQUESTS: usize = 4;
    const SESSION: &str = "frontend-manual";
    const RAW_A: &str = "model-a";
    const SUMMARY: &str = "private summary of closed historical work";
    const GATED: &str = "Manual compaction is temporarily unavailable while durable history integration is completed. Automatic compaction remains available during prompts.";

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

    struct Cwd(PathBuf);
    impl Cwd {
        fn enter(path: &Path) -> Self {
            let old = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self(old)
        }
    }
    impl Drop for Cwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
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
        status: u16,
        final_byte: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
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
                status: 200,
                final_byte: None,
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
        barrier: mpsc::Sender<mpsc::Sender<()>>,
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
            Self::with_lifetimes(responses, hold_headers, marker, 20, 25)
        }
        fn for_many_cli_launches(responses: Vec<Response>) -> Self {
            // Each launch retains its full real-binary pre/post checks. Only
            // the ten-launch grammar control needs a longer owned listener.
            Self::with_lifetimes(responses, false, None, 115, 120)
        }
        fn with_lifetimes(
            responses: Vec<Response>,
            hold_headers: bool,
            marker: Option<PathBuf>,
            server_seconds: u64,
            watchdog_seconds: u64,
        ) -> Self {
            assert!(
                server_seconds > 0 && server_seconds < watchdog_seconds && watchdog_seconds <= 120
            );
            let (watchdog, receive) = std::sync::mpsc::channel();
            let watchdog_thread = std::thread::spawn(move || {
                if matches!(
                    receive.recv_timeout(Duration::from_secs(watchdog_seconds)),
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
            let (barrier, barriers) = mpsc::channel::<mpsc::Sender<()>>();
            let thread = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(server_seconds);
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
                            if let Some((observed, release)) = response.final_byte {
                                if response.pause || response.body.is_empty() {
                                    return Err("invalid final byte hold");
                                }
                                write!(socket, "HTTP/1.1 {} Refused\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n", response.status)
                                    .map_err(|_| "held response header")?;
                                let (prefix, tail) = response.body.as_bytes().split_at(length - 1);
                                socket
                                    .write_all(prefix)
                                    .map_err(|_| "held response prefix")?;
                                socket.flush().map_err(|_| "held response flush")?;
                                observed.send(()).map_err(|_| "held observation")?;
                                release
                                    .recv_timeout(Duration::from_secs(3))
                                    .map_err(|_| "held response release bound")?;
                                socket.write_all(tail).map_err(|_| "held final byte")?;
                                socket.flush().map_err(|_| "held final flush")?;
                                continue;
                            }
                            let status = if response.status == 200 {
                                "200 OK".to_owned()
                            } else {
                                format!("{} Refused", response.status)
                            };
                            if let Err(error) = write!(
                                socket,
                                "HTTP/1.1 {status}\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{}",
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
                            while let Ok(ack) = barriers.try_recv() {
                                ack.send(()).map_err(|_| "barrier receiver")?;
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
                requests,
                connections,
                stop,
                thread: Some(thread),
                watchdog: Some(watchdog),
                watchdog_thread: Some(watchdog_thread),
                barrier,
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
                done.send(()).expect("fixture watchdog receiver closed");
            }
            if let Some(thread) = self.watchdog_thread.take() {
                thread.join().expect("fixture watchdog thread panic");
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
                .join(format!("f-{}", ulid::Ulid::new()));
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
        fn configure(&self, wire: &Wire) {
            let model = |id: &str, input: u64, price: u64| {
                json!({
                    "id":id,"max_output_tokens":73,"context_limits":{"input_tokens":input},
                    "pricing":{"input_per_million_microdollars":0,"output_per_million_microdollars":0,
                        "cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,
                        "reasoning_per_million_microdollars":0,"request_flat_microdollars":price},
                    "billing":{"version":2,"input_per_million_microdollars":0,
                        "output_per_million_microdollars":0,"cache_read_per_million_microdollars":0,
                        "cache_write_per_million_microdollars":0,"request_flat_microdollars":price,
                        "reasoning_counter_basis":"included_in_output","reasoning_rate_policy":"output_rate"}
                })
            };
            let value = json!({"provider":[{"name":"provider_a","kind":"openai-compatible","url":wire.url,
                "models":[model(RAW_A,10_000,5),model("summary-model",64_000,7)]}],
                "roles":{"main":format!("provider_a/{RAW_A}"),"compaction":"provider_a/summary-model"}});
            let parsed: orbit_cli::config::ProvidersConfig = serde_json::from_value(value).unwrap();
            write_private(
                &self.home.join("providers.toml"),
                toml::to_string(&parsed).unwrap(),
            );
        }
        fn seed(&self, wire: &Wire) -> (Vec<ChatMessage>, AccountingCheckpoint) {
            let mut source = Vec::new();
            for index in 0..3 {
                source.push(orbit_engine::user_message(format!(
                    "{}old user {index}",
                    "u".repeat(12_000)
                )));
                source.push(orbit_engine::assistant_message(format!(
                    "{}old answer {index}",
                    "a".repeat(12_000)
                )));
            }
            for index in 0..2 {
                source.push(orbit_engine::user_message(format!(
                    "exact recent question {index}"
                )));
                source.push(orbit_engine::assistant_message(format!(
                    "exact recent answer {index}"
                )));
            }
            let mut saved = SessionFile::from_chat(
                SESSION,
                RAW_A,
                &wire.url,
                "provider_a",
                &source,
                7,
                100,
                40,
                60,
            )
            .with_selection_origin(SelectionOrigin::SavedExplicit);
            saved.bind_workspace(&self.workspace).unwrap();
            let lease =
                SessionLease::acquire(&self.home, SESSION, "frontend-baseline-seed").unwrap();
            lease.save(&saved).unwrap();
            prepare_root(&lease, &mut saved, RootOrigin::RestoredOrLegacy).unwrap();
            let checkpoint = self.checkpoint();
            assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
            assert_eq!(checkpoint.revision.0, 0);
            assert!(checkpoint.pending.is_none());
            assert_eq!(
                saved
                    .accounting_watermark
                    .as_ref()
                    .unwrap()
                    .full_cost_status,
                FullCostStatus::UnknownLegacy
            );
            (source, checkpoint)
        }
        fn turn(&self, saved: &SessionFile) -> TuiTurnConfig {
            TuiTurnConfig {
                home: self.home.clone(),
                session_id: saved.session_id.clone(),
                gate: saved.gate.clone(),
                model: saved.model.clone(),
                effort: saved.effort.clone(),
                provider_id: saved.provider.clone(),
                auto_tools: false,
                scope: PermissionScope::default(),
                initial_transcript: saved.transcript.clone(),
                initial_turns: saved.turns,
                initial_input_tokens: saved.input_tokens,
                initial_output_tokens: saved.output_tokens,
                initial_cost_microcents: saved.cost_microcents,
            }
        }
        fn saved(&self) -> SessionFile {
            sessions::load_session(&self.home, SESSION).unwrap()
        }
        fn checkpoint(&self) -> AccountingCheckpoint {
            context_journal(&self.home, SESSION, None)
                .unwrap()
                .accounting_checkpoint()
                .unwrap()
        }
        fn archives(&self) -> Vec<PathBuf> {
            let directory = self
                .home
                .join("context-history")
                .join(SESSION)
                .join("archives");
            fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect()
        }
        fn assert_old_refusal_preserved(
            &self,
            source: &[ChatMessage],
            checkpoint: &AccountingCheckpoint,
        ) {
            let saved = self.saved();
            assert_eq!(saved.transcript, source);
            assert_eq!(saved.session_id, SESSION);
            assert_eq!(saved.provider, "provider_a");
            assert_eq!(saved.model, RAW_A);
            assert_eq!(saved.selection_origin, Some(SelectionOrigin::SavedExplicit));
            assert_eq!(saved.effort, None);
            assert_eq!(
                (
                    saved.turns,
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (7, 100, 40, 60)
            );
            assert_eq!(self.checkpoint(), *checkpoint);
            assert_eq!(
                saved
                    .accounting_watermark
                    .as_ref()
                    .unwrap()
                    .full_cost_status,
                FullCostStatus::UnknownLegacy
            );
            assert!(self.archives().is_empty());
            assert!(fs::read_dir(&self.workspace).unwrap().next().is_none());
        }
        fn assert_positive(&self, wire: &Wire, original: &[ChatMessage]) {
            let calls = wire.requests.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].target,
                "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
            );
            assert_eq!(calls[0].body["model"], "summary-model");
            assert_eq!(calls[0].body["max_tokens"], 73);
            assert!(
                calls[0]
                    .body
                    .get("tools")
                    .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
            );
            assert_eq!(
                calls[0]
                    .headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [wire.authority.as_str()]
            );
            assert!(
                !calls[0]
                    .headers
                    .iter()
                    .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
            );
            drop(calls);
            let files = self.archives();
            assert_eq!(files.len(), 1);
            let record = files[0].file_stem().unwrap().to_str().unwrap();
            assert_eq!(
                load_compaction_source(&self.home, SESSION, None, record).unwrap(),
                original
            );
            let saved = self.saved();
            assert_ne!(saved.transcript, original);
            assert!(saved.transcript.ends_with(&original[original.len() - 4..]));
            assert!(
                !saved
                    .transcript
                    .iter()
                    .any(|message| message.content == "/compact")
            );
            assert_eq!(
                (
                    saved.turns,
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (7, 111, 47, 67)
            );
            let checkpoint = self.checkpoint();
            assert_eq!(checkpoint.revision.0, 2);
            assert!(checkpoint.pending.is_none());
            assert_eq!(checkpoint.baseline, AccountingBaseline::UnknownLegacy);
            assert_eq!(
                checkpoint
                    .known_priced_subtotals
                    .unwrap()
                    .ordinary_microcents,
                0
            );
            assert_eq!(
                checkpoint
                    .known_priced_subtotals
                    .unwrap()
                    .housekeeping_microcents,
                7
            );
            assert_eq!(
                saved.accounting_watermark.unwrap().full_cost_status,
                FullCostStatus::UnknownLegacy
            );
            assert!(fs::read_dir(&self.workspace).unwrap().next().is_none());
        }
        fn lease_released(&self) {
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                match SessionLease::acquire(&self.home, SESSION, "frontend-baseline-closed") {
                    Ok(lease) => {
                        drop(lease);
                        return;
                    }
                    Err(SessionLeaseError::Busy { session_id })
                        if session_id == SESSION && Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("source lease did not release cleanly: {error}"),
                }
            }
        }
        fn binary_unchanged(&self) {
            assert_eq!(binary_fingerprint(&self.binary), self.binary_before);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Tui {
        bus: Bus,
        commands: Option<mpsc::Sender<WorkerCommand>>,
        cancel: CancelHandle,
    }
    impl Tui {
        fn start(f: &Fixture) -> Self {
            let (lease, saved) =
                SessionLease::acquire_and_load(&f.home, SESSION, "frontend-baseline-tui").unwrap();
            let (bus, sender) = Bus::new();
            let (commands, command_rx) = mpsc::channel();
            let cancel = orbit_cli::tui_worker::make_spawner_owned(f.turn(&saved), lease)(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                commands.clone(),
            )
            .unwrap();
            assert!(
                matches!(SessionLease::acquire(&f.home,SESSION,"must-be-busy"),
                Err(SessionLeaseError::Busy { session_id }) if session_id==SESSION)
            );
            Self {
                bus,
                commands: Some(commands),
                cancel,
            }
        }
        fn initial(&self) -> SessionProjection {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                match self.bus.try_recv() {
                    Some(Msg::SessionProjection(projection))
                        if matches!(projection.reason, ProjectionReason::Initial) =>
                    {
                        assert_eq!(projection.binding.session_id, SESSION);
                        assert_eq!(projection.binding.generation, 1);
                        return projection;
                    }
                    Some(Msg::BackendError(error)) | Some(Msg::BackendNotice(error)) => {
                        panic!("worker initialization: {error}")
                    }
                    Some(Msg::OrdinaryTurnEnded { .. }) => {
                        panic!("ordinary result before Initial binding")
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
                assert!(
                    Instant::now() < end,
                    "worker did not publish its actual Initial binding"
                );
            }
        }
        fn compact_gate(&self) -> (bool, usize, usize, usize) {
            let initial = self.initial();
            let operation =
                ManualOperation::new(initial.binding, ManualAction::Compact, 1).unwrap();
            self.commands
                .as_ref()
                .unwrap()
                .send(WorkerCommand::Compact(operation.clone()))
                .unwrap();
            let (projection, ordinary, plans, tools) = self.manual_terminal(&operation);
            if let Some(projection) = projection {
                assert!(
                    matches!(&projection.reason, ProjectionReason::Manual { operation: observed, outcome: ManualOutcome::Completed, applied: true } if observed == &operation)
                );
                assert_eq!(projection.binding, *operation.source());
                assert_eq!(projection.turns, 7);
                assert_eq!(projection.context, ContextProjection::Unavailable);
                (false, ordinary, plans, tools)
            } else {
                (true, ordinary, plans, tools)
            }
        }
        fn manual_terminal(
            &self,
            operation: &ManualOperation,
        ) -> (Option<SessionProjection>, usize, usize, usize) {
            let end = Instant::now() + Duration::from_secs(10);
            let (mut ordinary, mut plans, mut tools) = (0, 0, 0);
            loop {
                match self.bus.try_recv() {
                    Some(Msg::SystemMessage(text)) if text == GATED => {
                        return (None, ordinary, plans, tools);
                    }
                    Some(Msg::SessionProjection(projection)) => {
                        if matches!(&projection.reason, ProjectionReason::Manual { operation: observed, .. } if observed == operation)
                        {
                            return (Some(projection), ordinary, plans, tools);
                        }
                        assert!(
                            !matches!(projection.reason, ProjectionReason::Manual { .. }),
                            "unmatched manual terminal cannot complete this operation"
                        );
                    }
                    Some(Msg::ResponseFinished { .. }) => ordinary += 1,
                    Some(Msg::PlanReady(_)) => plans += 1,
                    Some(Msg::ToolCallStarted { .. }) => tools += 1,
                    Some(Msg::BackendNotice(_)) => {
                        panic!("unexpected notice during manual operation")
                    }
                    Some(Msg::OrdinaryTurnEnded { .. }) => {
                        panic!("manual operation emitted ordinary result")
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
                assert!(
                    Instant::now() < end,
                    "exact operation/session manual terminal was not observed"
                );
            }
        }
        fn close(mut self, f: &Fixture) {
            self.commands.take();
            f.lease_released();
            while let Some(event) = self.bus.try_recv() {
                assert!(
                    !matches!(
                        event,
                        Msg::BackendNotice(_)
                            | Msg::OrdinaryTurnEnded { .. }
                            | Msg::ResponseFinished { .. }
                            | Msg::PlanReady(_)
                            | Msg::ToolCallStarted { .. }
                            | Msg::SessionProjection(SessionProjection {
                                reason: ProjectionReason::Manual { .. },
                                ..
                            })
                    ),
                    "ordinary/tool event escaped after the exact manual gate notice"
                );
            }
        }
    }
    impl Drop for Tui {
        fn drop(&mut self) {
            (self.cancel)();
            self.commands.take();
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

    fn real_terminal(f: &Fixture, mode: &str) -> Value {
        // This exact private /etc + inherited-descriptor guard must run before
        // starting Python, importing the verified cell parser or opening a PTY.
        require_private_system_fixture();
        f.binary_unchanged();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let output = Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-B"])
            .arg(repository.join("scripts/fixtures/context_manual_pty.py"))
            .arg("--binary")
            .arg(&f.binary)
            .arg("--home")
            .arg(&f.home)
            .arg("--workspace")
            .arg(&f.workspace)
            .args(["--session", SESSION, "--mode", mode])
            .arg("--post-marker")
            .arg(f.root.join("pty-post"))
            .arg("--dependency-root")
            .arg(repository.join("target/orbit-manual-pty-python-08384617c293"))
            .args([
                "--manifest-sha256",
                "08384617c293016b1d5a30652fcb9c696164085f7e535e0e65087c10ca727b57",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .envs(
                [
                    "HOME",
                    "TMPDIR",
                    "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME",
                    "XDG_DATA_HOME",
                    "XDG_STATE_HOME",
                    "XDG_RUNTIME_DIR",
                    "ORBIT_ACTIVATION_ROOT",
                    "ORBIT_ACTIVATION_PARENT_MOUNT_FD",
                    "ORBIT_ACTIVATION_PARENT_USER_FD",
                    "ORBIT_ACTIVATION_MANAGED_MARKER",
                    "ORBIT_ACTIVATION_ISOLATED",
                    "ORBIT_ACTIVATION_RUNNER_DEPTH",
                ]
                .map(|name| {
                    (
                        name,
                        std::env::var_os(name).expect("private terminal setting missing"),
                    )
                }),
            )
            .current_dir(&f.workspace)
            .stdin(Stdio::null())
            .process_group(0)
            .output()
            .expect("guarded terminal fixture did not start");
        assert!(
            output.stdout.len() <= 64 * 1024 && output.stderr.len() <= 16 * 1024,
            "bounded terminal fixture receipt"
        );
        let receipt: Value = serde_json::from_slice(&output.stdout)
            .expect("terminal fixture did not return a structured receipt");
        assert_eq!(receipt["schema"], "orbit.context-manual-pty/v1");
        assert_eq!(receipt["mode"], mode);
        let line = format!("ORBIT_CONTEXT_MANUAL_PTY {receipt}\n");
        std::io::stdout().lock().write_all(line.as_bytes()).unwrap();
        if receipt["status"] == "NOTRUN" {
            assert_eq!(output.status.code(), Some(77));
            assert_eq!(receipt["pty_started"], false);
            panic!(
                "ORBIT_MANUAL_PTY_NOTRUN: missing required terminal capability; no actual PTY pass"
            );
        }
        assert!(
            output.status.success(),
            "guarded terminal fixture: {}",
            receipt["reason"]
        );
        assert_eq!(receipt["status"], "TEST_PASSED");
        for field in [
            "private_guard",
            "pty_started",
            "cells_observed",
            "process_reaped",
            "owned_process_cleanup",
            "binary_unchanged",
            "dependency_tree_reverified",
        ] {
            assert_eq!(receipt[field], true, "terminal receipt proof: {field}");
        }
        assert_eq!(receipt["process_exit"], 0);
        assert!(
            receipt["output_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= 2 * 1024 * 1024)
        );
        assert!(
            receipt["terminal_cells"]
                .as_str()
                .is_some_and(|cells| !cells.is_empty())
        );
        assert_eq!(
            receipt["dependency_manifest_sha256"],
            "08384617c293016b1d5a30652fcb9c696164085f7e535e0e65087c10ca727b57"
        );
        assert!(
            receipt["cell_checks"]
                .as_array()
                .is_some_and(|checks| checks.len() >= 4)
        );
        if mode == "clear" {
            let barrier = &receipt["clear_source_barrier"];
            assert_eq!(barrier["phase"], "after_initial_before_clear");
            for digests in [
                &barrier["prelaunch"],
                &barrier["before_clear"],
                &receipt["clear_source_after_clear"],
                &receipt["clear_source_after_quit"],
            ] {
                let object = digests.as_object().expect("bounded clear source digests");
                assert_eq!(object.len(), 2);
                for (name, maximum) in [("snapshot", 64 * 1024 * 1024), ("accounting", 128 * 1024)]
                {
                    assert!(
                        digests[name]["bytes"]
                            .as_u64()
                            .is_some_and(|bytes| bytes > 0 && bytes <= maximum)
                    );
                    assert!(
                        digests[name]["sha256"]
                            .as_str()
                            .is_some_and(|digest| digest.len() == 64
                                && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    );
                }
            }
            for fields in [
                &barrier["startup_changed_fields"],
                &receipt["clear_source_after_clear_changed_fields"],
                &receipt["clear_source_after_quit_changed_fields"],
            ] {
                assert!(fields.as_array().is_some_and(|fields| fields.len() <= 32
                    && fields.iter().all(|name| name.as_str().is_some_and(|name| {
                        !name.is_empty()
                            && name.len() <= 64
                            && name
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    }))));
            }
            assert_eq!(receipt["clear_source_preserved_after_clear"], true);
            assert_eq!(receipt["clear_source_preserved_after_quit"], true);
            assert_eq!(receipt["clear_source_after_clear"], barrier["before_clear"]);
            assert_eq!(receipt["clear_source_after_quit"], barrier["before_clear"]);
            let checks = receipt["cell_checks"].as_array().unwrap();
            for check in [
                "old_source_captured_after_initial_before_clear",
                "old_source_barrier_bytes_preserved_after_clear",
                "old_source_barrier_bytes_preserved_after_quit",
                "fresh_clear_view_without_old_source_cells",
            ] {
                assert!(checks.iter().any(|value| value == check));
            }
        }
        f.binary_unchanged();
        receipt
    }

    struct Serving {
        runtime: Option<OwnerRuntime>,
        stop: orbit_provider_http::CancelToken,
        thread: Option<std::thread::JoinHandle<Result<(), OwnerError>>>,
    }
    impl Serving {
        fn start(f: &Fixture) -> Self {
            let (lease, saved) =
                SessionLease::acquire_and_load(&f.home, SESSION, "frontend-baseline-owner")
                    .unwrap();
            let runtime =
                OwnerRuntime::start(OwnerConfig::new(f.turn(&saved), f.workspace.clone()), lease)
                    .unwrap();
            let server = UnixServer::bind(&f.root.join("owner.sock"), runtime.handle()).unwrap();
            let stop = orbit_provider_http::CancelToken::new();
            let cloned = stop.clone();
            let thread = std::thread::spawn(move || server.run(&cloned));
            Self {
                runtime: Some(runtime),
                stop,
                thread: Some(thread),
            }
        }
        fn close(mut self) {
            self.stop.cancel();
            self.thread.take().unwrap().join().unwrap().unwrap();
            self.runtime.take().unwrap().shutdown().unwrap();
        }
    }
    impl Drop for Serving {
        fn drop(&mut self) {
            self.stop.cancel();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            if let Some(runtime) = self.runtime.take() {
                let _ = runtime.shutdown();
            }
        }
    }

    #[test]
    fn initial_observer_rejects_backend_notice_without_waiting() {
        if !dispatch_isolated(
            "frontend_manual_baselines::initial_observer_rejects_backend_notice_without_waiting",
        ) {
            return;
        }
        require_private_system_fixture();
        let (bus, sender) = Bus::new();
        orbit_hud_tui::emit_notice(&sender, "synthetic startup notice");
        let tui = Tui {
            bus,
            commands: None,
            cancel: Arc::new(|| {}),
        };
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tui.initial()))
            .expect_err("initial observer must reject the actual notice");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert_eq!(
            message, "worker initialization: synthetic startup notice",
            "a timeout assertion is not notice handling"
        );
        assert!(tui.bus.try_recv().is_none());
    }

    #[test]
    fn managed_tui_compact_reaches_service_instead_of_gate_notice() {
        if !dispatch_isolated(
            "frontend_manual_baselines::managed_tui_compact_reaches_service_instead_of_gate_notice",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (original, before) = f.seed(&wire);
        let tui = Tui::start(&f);
        let (gated, ordinary, plans, tools) = tui.compact_gate();
        tui.close(&f);
        wire.finish();
        assert_eq!(ordinary, 0);
        assert_eq!(plans, 0);
        assert_eq!(tools, 0);
        if gated {
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            assert!(wire.requests.lock().unwrap().is_empty());
            f.assert_old_refusal_preserved(&original, &before);
        } else {
            assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
            f.assert_positive(&wire, &original);
        }
        f.lease_released();
        f.binary_unchanged();
        assert!(
            !gated,
            "manual TUI capability missing: exact gated SystemMessage, 0 POST, retained full typed source/bill, released lease"
        );
    }

    #[test]
    fn actual_repl_compact_invokes_shared_service_without_a_prompt_turn() {
        if !dispatch_isolated(
            "frontend_manual_baselines::actual_repl_compact_invokes_shared_service_without_a_prompt_turn",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (original, before) = f.seed(&wire);
        let result = cli(
            &f,
            &["chat", "--no-tui", "--resume", SESSION, "--bare"],
            "/compact\nexit\n",
        );
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
        let calls = wire.requests.lock().unwrap().len();
        if calls == 0 {
            assert!(result.status.success());
            assert!(
                result
                    .stderr
                    .contains("unknown command: /compact; try /help")
            );
            f.assert_old_refusal_preserved(&original, &before);
        } else {
            assert!(result.status.success());
            f.assert_positive(&wire, &original);
        }
        assert_eq!(
            calls, 1,
            "manual REPL capability missing: command was refused with 0 POST after safe cleanup"
        );
    }

    #[test]
    fn actual_compact_session_command_invokes_shared_service() {
        if !dispatch_isolated(
            "frontend_manual_baselines::actual_compact_session_command_invokes_shared_service",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (original, before) = f.seed(&wire);
        let snapshot_before =
            fs::read(f.home.join("sessions").join(format!("{SESSION}.json"))).unwrap();
        let result = cli(&f, &["compact", "--session", SESSION, "--json"], "");
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
        let calls = wire.requests.lock().unwrap().len();
        if calls == 0 {
            assert_eq!(result.status.code(), Some(2));
            assert!(
                result.stderr.contains("ORBIT-E1101")
                    && result.stderr.contains("unsupported command compact")
            );
            assert_eq!(
                fs::read(f.home.join("sessions").join(format!("{SESSION}.json"))).unwrap(),
                snapshot_before
            );
            f.assert_old_refusal_preserved(&original, &before);
        } else {
            assert!(result.status.success());
            let value: Value = serde_json::from_str(&result.stdout).unwrap();
            assert_eq!(value["schema"], "orbit.cli/v1");
            assert_eq!(value["command"], "compact");
            assert_eq!(value["session"], SESSION);
            assert_eq!(value["status"], "completed");
            assert_eq!(value["applied"], true);
            assert_eq!(value["snapshot_saved"], true);
            assert_eq!(value["turns"], 7);
            assert_eq!(value["accounting_revision"], 2);
            assert_eq!(value["full_cost_status"], "unknown_legacy");
            assert!(!result.stdout.contains(SUMMARY));
            f.assert_positive(&wire, &original);
        }
        assert_eq!(
            calls, 1,
            "direct compact capability missing: existing binary rejected the command with 0 POST after safe cleanup"
        );
    }

    #[test]
    fn actual_attach_compact_routes_one_explicit_owner_intent() {
        if !dispatch_isolated(
            "frontend_manual_baselines::actual_attach_compact_routes_one_explicit_owner_intent",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (original, before) = f.seed(&wire);
        let serving = Serving::start(&f);
        let handle = serving.runtime.as_ref().unwrap().handle();
        assert!(
            matches!(SessionLease::acquire(&f.home,SESSION,"must-still-be-busy"),
            Err(SessionLeaseError::Busy { session_id }) if session_id==SESSION)
        );
        let held = orbit_cli::attach::AttachClient::connect(&f.root.join("owner.sock"), true, None)
            .unwrap();
        assert!(matches!(
            handle.claim_controller(),
            Err(OwnerError::ControllerBusy)
        ));
        drop(held);
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            match handle.claim_controller() {
                Ok(controller) => {
                    drop(controller);
                    break;
                }
                Err(OwnerError::ControllerBusy) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("controller release failed: {error}"),
            }
        }
        let mut output = Vec::new();
        let result = orbit_cli::attach::run_with_io(
            &f.root.join("owner.sock"),
            &mut std::io::Cursor::new(b"/compact\n/detach\n"),
            &mut output,
        );
        assert!(output.len() <= 128 * 1024);
        let refused =
            matches!(&result,Err(OwnerError::Invalid(text)) if text=="unknown attach command");
        if result.is_ok() {
            let end = Instant::now() + Duration::from_secs(10);
            while handle.snapshot().unwrap().state == TurnState::Running {
                assert!(
                    Instant::now() < end,
                    "accepted attach operation did not terminate"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        } else {
            assert!(refused, "unexpected attach failure");
        }
        let snapshot = handle.snapshot().unwrap();
        if refused {
            assert_eq!(snapshot.turns, 7);
            assert!(snapshot.requests.is_empty());
            assert_eq!(snapshot.state, TurnState::Idle);
        }
        serving.close();
        f.lease_released();
        wire.finish();
        f.binary_unchanged();
        let calls = wire.requests.lock().unwrap().len();
        if calls == 0 {
            assert!(refused);
            f.assert_old_refusal_preserved(&original, &before);
        } else {
            f.assert_positive(&wire, &original);
        }
        assert_eq!(
            calls, 1,
            "attach compact capability missing: unknown slash, 0 POST, original typed source/bill preserved after safe cleanup"
        );
    }
    fn assert_terminal_only(tui: &Tui, operation: &ManualOperation) -> SessionProjection {
        let (view, ordinary, plans, tools) = tui.manual_terminal(operation);
        assert_eq!((ordinary, plans, tools), (0, 0, 0));
        view.expect("an exact gated message cannot satisfy implemented manual work")
    }

    #[test]
    fn direct_manual_rejects_complete_invalid_grammar_before_source_effects() {
        if !dispatch_isolated(
            "frontend_manual_baselines::direct_manual_rejects_complete_invalid_grammar_before_source_effects",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::for_many_cli_launches(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let before = fs::read(f.home.join("sessions").join(format!("{SESSION}.json"))).unwrap();
        let accounting = fs::read(
            f.home
                .join("context-history")
                .join(SESSION)
                .join("accounting.json"),
        )
        .unwrap();
        for args in [
            vec!["compact"],
            vec!["compact", "--session"],
            vec!["compact", "--session", "--json"],
            vec!["compact", "--session", SESSION, "--session", SESSION],
            vec!["compact", "--session", SESSION, "--json", "--json"],
            vec!["compact", "--session", SESSION, "--provider", "unrelated"],
            vec!["compact", "--session", SESSION, "-p", "do not send"],
            vec!["compact", "--session", SESSION, "--"],
            vec!["compact", "--session", "invalid/id"],
            vec!["compact", "--session", "name.json.json"],
        ] {
            let result = cli(&f, &args, "");
            assert_eq!(result.status.code(), Some(2));
            assert!(result.stdout.is_empty());
            assert!(!result.stderr.is_empty());
            assert_eq!(
                fs::read(f.home.join("sessions").join(format!("{SESSION}.json"))).unwrap(),
                before
            );
            assert_eq!(
                fs::read(
                    f.home
                        .join("context-history")
                        .join(SESSION)
                        .join("accounting.json")
                )
                .unwrap(),
                accounting
            );
        }
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        f.assert_old_refusal_preserved(&source, &checkpoint);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn direct_manual_empty_and_system_only_are_local_noops_with_unchanged_legacy_prefix() {
        if !dispatch_isolated(
            "frontend_manual_baselines::direct_manual_empty_and_system_only_are_local_noops_with_unchanged_legacy_prefix",
        ) {
            return;
        }
        for system in [false, true] {
            let f = Fixture::new();
            let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
            f.configure(&wire);
            let (_, checkpoint) = f.seed(&wire);
            let (lease, mut saved) =
                SessionLease::acquire_and_load(&f.home, SESSION, "seed-noop").unwrap();
            saved.transcript.clear();
            if system {
                let mut message = orbit_engine::user_message("fixed system only");
                message.role = orbit_adapter::types::ChatRole::System;
                saved.transcript.push(message);
            }
            lease.save(&saved).unwrap();
            let source = saved.transcript.clone();
            drop(lease);
            let result = cli(&f, &["compact", "--session", SESSION, "--json"], "");
            assert!(result.status.success());
            let value: Value = serde_json::from_str(&result.stdout).unwrap();
            assert_eq!(value["status"], "completed");
            assert_eq!(value["applied"], false);
            assert_eq!(value["snapshot_saved"], true);
            assert_eq!(value["turns"], 7);
            assert_eq!(value["full_cost_status"], "unknown_legacy");
            assert_eq!(
                (
                    value["usage"]["input_tokens"].as_u64(),
                    value["usage"]["output_tokens"].as_u64(),
                    value["cost_microcents"].as_u64()
                ),
                (Some(100), Some(40), Some(60))
            );
            wire.finish();
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            f.assert_old_refusal_preserved(&source, &checkpoint);
            f.lease_released();
            f.binary_unchanged();
        }
    }

    #[test]
    fn direct_manual_busy_and_missing_never_create_a_second_owner_or_request() {
        if !dispatch_isolated(
            "frontend_manual_baselines::direct_manual_busy_and_missing_never_create_a_second_owner_or_request",
        ) {
            return;
        }
        let f = Fixture::new();
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let (lease, _) = SessionLease::acquire_and_load(&f.home, SESSION, "held-source").unwrap();
        let busy = cli(&f, &["compact", "--session", SESSION, "--json"], "");
        assert_eq!(busy.status.code(), Some(2));
        assert!(busy.stdout.is_empty());
        drop(lease);
        let missing = cli(
            &f,
            &["compact", "--session", "missing-manual", "--json"],
            "",
        );
        assert_eq!(missing.status.code(), Some(2));
        assert!(!f.home.join("sessions/missing-manual.json").exists());
        assert!(!f.home.join("context-history/missing-manual").exists());
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        f.assert_old_refusal_preserved(&source, &checkpoint);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn direct_manual_paid_length_and_empty_summary_keep_full_source_and_housekeeping_bill_once() {
        if !dispatch_isolated(
            "frontend_manual_baselines::direct_manual_paid_length_and_empty_summary_keep_full_source_and_housekeeping_bill_once",
        ) {
            return;
        }
        for (text, reason) in [("private truncated summary", "length"), ("", "stop")] {
            let f = Fixture::new();
            let mut wire = Wire::new(vec![Response::text(
                text,
                reason,
                Some(json!({"prompt_tokens":11,"completion_tokens":7,"total_tokens":18})),
            )]);
            f.configure(&wire);
            let (source, _) = f.seed(&wire);
            let result = cli(&f, &["compact", "--session", SESSION, "--json"], "");
            assert_eq!(result.status.code(), Some(1));
            let value: Value = serde_json::from_str(&result.stdout).unwrap();
            assert_eq!(value["status"], "failed");
            assert_eq!(value["applied"], false);
            assert_eq!(value["snapshot_saved"], true);
            assert_eq!(value["full_cost_status"], "unknown_legacy");
            assert!(!result.stdout.contains("private truncated summary"));
            wire.finish();
            assert_eq!(wire.requests.lock().unwrap().len(), 1);
            let saved = f.saved();
            assert_eq!(saved.transcript, source);
            assert_eq!(
                (
                    saved.turns,
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (7, 111, 47, 67)
            );
            let checkpoint = f.checkpoint();
            assert_eq!(checkpoint.revision.0, 2);
            assert!(checkpoint.pending.is_none());
            let priced = checkpoint.known_priced_subtotals.unwrap();
            assert_eq!(
                (priced.ordinary_microcents, priced.housekeeping_microcents),
                (0, 7)
            );
            assert!(f.archives().is_empty());
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
            f.lease_released();
            f.binary_unchanged();
        }
    }

    #[test]
    fn managed_manual_early_cancel_retains_intent_binding_and_source_with_no_provider_work() {
        if !dispatch_isolated(
            "frontend_manual_baselines::managed_manual_early_cancel_retains_intent_binding_and_source_with_no_provider_work",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let tui = Tui::start(&f);
        let initial = tui.initial();
        let operation = ManualOperation::new(initial.binding, ManualAction::Compact, 1).unwrap();
        assert!(operation.cancel().unwrap());
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::Compact(operation.clone()))
            .unwrap();
        let view = assert_terminal_only(&tui, &operation);
        assert!(matches!(
            view.reason,
            ProjectionReason::Manual {
                outcome: ManualOutcome::Cancelled,
                applied: false,
                ..
            }
        ));
        assert_eq!(view.context, ContextProjection::PreserveUnchanged);
        assert!(!operation.cancel().unwrap());
        assert_eq!(
            (
                view.turns,
                view.input_tokens,
                view.output_tokens,
                view.cost_microcents
            ),
            (7, 100, 40, 60)
        );
        tui.close(&f);
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        f.assert_old_refusal_preserved(&source, &checkpoint);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn managed_manual_held_header_cancel_keeps_uncertain_receipt_and_original_without_ordinary_turn()
     {
        if !dispatch_isolated(
            "frontend_manual_baselines::managed_manual_held_header_cancel_keeps_uncertain_receipt_and_original_without_ordinary_turn",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::with_held_headers(vec![Response::complete(SUMMARY)], true);
        f.configure(&wire);
        let (source, _) = f.seed(&wire);
        let tui = Tui::start(&f);
        let initial = tui.initial();
        let operation = ManualOperation::new(initial.binding, ManualAction::Compact, 1).unwrap();
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::Compact(operation.clone()))
            .unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while wire.requests.lock().unwrap().is_empty() {
            assert!(Instant::now() < end, "provider POST not observed");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(operation.cancel().unwrap());
        let view = assert_terminal_only(&tui, &operation);
        assert!(matches!(
            view.reason,
            ProjectionReason::Manual {
                outcome: ManualOutcome::Unknown,
                applied: false,
                ..
            }
        ));
        assert_eq!(view.context, ContextProjection::PreserveUnchanged);
        assert!(!operation.cancel().unwrap());
        assert_eq!(
            view.cost,
            orbit_hud_tui::msg::CostQualification::Uncertain { revision: 2 }
        );
        tui.close(&f);
        wire.finish();
        assert_eq!(wire.requests.lock().unwrap().len(), 1);
        let saved = f.saved();
        assert_eq!(saved.transcript, source);
        assert_eq!(
            (
                saved.turns,
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (7, 100, 40, 60)
        );
        let checkpoint = f.checkpoint();
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            checkpoint.totals.knownness,
            orbit_engine::AccountingKnownness::Uncertain
        );
        assert_eq!(checkpoint.totals.housekeeping.cost_microcents, None);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            0
        );
        assert!(f.archives().is_empty());
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn managed_clear_starts_qualified_fresh_identity_without_summary_and_preserves_old_bytes() {
        if !dispatch_isolated(
            "frontend_manual_baselines::managed_clear_starts_qualified_fresh_identity_without_summary_and_preserves_old_bytes",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let tui = Tui::start(&f);
        let initial = tui.initial();
        let saved_path = f.home.join("sessions").join(format!("{SESSION}.json"));
        let before = fs::read(&saved_path).unwrap();
        let accounting_path = f
            .home
            .join("context-history")
            .join(SESSION)
            .join("accounting.json");
        let accounting_before = fs::read(&accounting_path).unwrap();
        let operation = ManualOperation::new(initial.binding, ManualAction::Clear, 1).unwrap();
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::ClearSession(operation.clone()))
            .unwrap();
        let view = assert_terminal_only(&tui, &operation);
        assert!(
            matches!(&view.reason,ProjectionReason::Manual{operation:ticket,outcome:ManualOutcome::Completed,applied:true} if ticket==&operation)
        );
        assert_ne!(view.binding.session_id, SESSION);
        assert_eq!(view.binding.generation, 2);
        assert!(view.lines.is_empty());
        assert_eq!(view.context, ContextProjection::Unavailable);
        assert_eq!(
            (
                view.turns,
                view.input_tokens,
                view.output_tokens,
                view.cost_microcents
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            view.cost,
            orbit_hud_tui::msg::CostQualification::Known { revision: 0 }
        );
        let target = view.binding.session_id.clone();
        tui.close(&f);
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&saved_path).unwrap(), before);
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_before);
        f.assert_old_refusal_preserved(&source, &checkpoint);
        let end = Instant::now() + Duration::from_secs(3);
        let (lease, fresh) = loop {
            match SessionLease::acquire_and_load(&f.home, &target, "verify-clear") {
                Ok(value) => break value,
                Err(SessionLeaseError::Busy { session_id })
                    if session_id == target && Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("fresh target lease did not release: {error}"),
            }
        };
        assert!(fresh.transcript.is_empty());
        assert_eq!(
            (
                fresh.turns,
                fresh.input_tokens,
                fresh.output_tokens,
                fresh.cost_microcents
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            fresh.workspace,
            Some(fs::canonicalize(&f.workspace).unwrap())
        );
        assert_eq!(f.saved().workspace, fresh.workspace);
        assert_eq!(fresh.provider, "provider_a");
        assert_eq!(fresh.model, RAW_A);
        assert_eq!(fresh.gate, wire.url);
        assert_eq!(fresh.selection_origin, Some(SelectionOrigin::SavedExplicit));
        assert_eq!(fresh.effort, None);
        let new = context_journal(&f.home, &target, None)
            .unwrap()
            .accounting_checkpoint()
            .unwrap();
        assert_eq!(new.baseline, AccountingBaseline::FreshKnownZero);
        assert_eq!(new.revision.0, 0);
        assert!(new.pending.is_none());
        drop(lease);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn attach_compact_lost_ack_names_exact_intent_and_never_resubmits() {
        if !dispatch_isolated(
            "frontend_manual_baselines::attach_compact_lost_ack_names_exact_intent_and_never_resubmits",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, _) = f.seed(&wire);
        let serving = Serving::start(&f);
        let handle = serving.runtime.as_ref().unwrap().handle();
        let proxy_path = f.root.join("ack.sock");
        let listener = std::os::unix::net::UnixListener::bind(&proxy_path).unwrap();
        fs::set_permissions(&proxy_path, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = f.root.join("owner.sock");
        let frames = Arc::new(AtomicUsize::new(0));
        let captured = frames.clone();
        let proxy = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(5);
            let (mut downstream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < end, "owned proxy accept deadline");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("proxy accept: {error}"),
                }
            };
            downstream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            downstream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let upstream = std::os::unix::net::UnixStream::connect(target).unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            upstream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut input = std::io::BufReader::new(downstream.try_clone().unwrap());
            let mut upstream = std::io::BufReader::new(upstream);
            let frame = |reader: &mut std::io::BufReader<std::os::unix::net::UnixStream>| {
                let mut bytes = Vec::new();
                let mut limited = Read::by_ref(reader).take(256 * 1024 + 1);
                std::io::BufRead::read_until(&mut limited, b'\n', &mut bytes).unwrap();
                assert!(bytes.len() <= 256 * 1024 && bytes.last() == Some(&b'\n'));
                bytes
            };
            for index in 0..2 {
                let request = frame(&mut input);
                let value: Value = serde_json::from_slice(&request).unwrap();
                assert_eq!(
                    value["request"]["type"],
                    if index == 0 { "hello" } else { "action" }
                );
                if index == 1 {
                    assert_eq!(value["request"]["action"]["type"], "compact");
                }
                upstream.get_mut().write_all(&request).unwrap();
                upstream.get_mut().flush().unwrap();
                captured.fetch_add(1, Ordering::SeqCst);
                let response = frame(&mut upstream);
                let value: Value = serde_json::from_slice(&response).unwrap();
                assert_eq!(value["ok"], true);
                if index == 0 {
                    downstream.write_all(&response).unwrap();
                    downstream.flush().unwrap();
                }
            }
            // The real owner has acknowledged its durable intent. This owned
            // proxy drops only that ACK, never an action or a provider reply.
        });
        let mut client = orbit_cli::attach::AttachClient::connect(&proxy_path, true, None).unwrap();
        let id = ulid::Ulid::new().to_string();
        let action = orbit_cli::daemon::OwnerAction::Compact {
            request_id: id.clone(),
        };
        let error = client.send(action.clone()).unwrap_err();
        assert!(
            matches!(error,OwnerError::Runtime(ref text) if text.contains(&id)&&text.contains("without resubmitting"))
        );
        assert!(client.send(action.clone()).is_err());
        drop(client);
        proxy.join().unwrap();
        assert_eq!(frames.load(Ordering::SeqCst), 2);
        let end = Instant::now() + Duration::from_secs(3);
        let mut controller = loop {
            match handle.claim_controller() {
                Ok(value) => break value,
                Err(OwnerError::ControllerBusy) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("controller did not release: {error}"),
            }
        };
        assert!(controller.send(action).unwrap().duplicate);
        drop(controller);
        let end = Instant::now() + Duration::from_secs(10);
        while handle.snapshot().unwrap().state == TurnState::Running {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
        let snapshot = handle.snapshot().unwrap();
        assert_eq!(snapshot.requests.len(), 1);
        assert_eq!(
            snapshot.requests[&id].kind,
            orbit_cli::daemon::RequestKind::Compact
        );
        assert_eq!(snapshot.turns, 7);
        serving.close();
        wire.finish();
        f.assert_positive(&wire, &source);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn real_terminal_compact_reaches_checked_cells_and_exact_durable_summary() {
        if !dispatch_isolated(
            "frontend_manual_baselines::real_terminal_compact_reaches_checked_cells_and_exact_durable_summary",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::with_post_marker(
            vec![Response::complete(SUMMARY)],
            false,
            Some(f.root.join("pty-post")),
        );
        f.configure(&wire);
        let (source, _) = f.seed(&wire);
        let receipt = real_terminal(&f, "success");
        assert!(
            receipt["terminal_cells"]
                .as_str()
                .unwrap()
                .contains("context compacted")
        );
        wire.finish();
        f.assert_positive(&wire, &source);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn closed_manual_handle_cannot_cancel_the_next_actual_summary_operation() {
        if !dispatch_isolated(
            "frontend_manual_baselines::closed_manual_handle_cannot_cancel_the_next_actual_summary_operation",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::new(vec![Response::complete(SUMMARY)]);
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let tui = Tui::start(&f);
        let initial = tui.initial();
        let first =
            ManualOperation::new(initial.binding.clone(), ManualAction::Compact, 1).unwrap();
        assert!(first.cancel().unwrap());
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::Compact(first.clone()))
            .unwrap();
        let refused = assert_terminal_only(&tui, &first);
        assert!(matches!(
            refused.reason,
            ProjectionReason::Manual {
                outcome: ManualOutcome::Cancelled,
                applied: false,
                ..
            }
        ));
        assert!(!first.cancel().unwrap());
        assert!(wire.requests.lock().unwrap().is_empty());
        f.assert_old_refusal_preserved(&source, &checkpoint);
        let next = ManualOperation::new(initial.binding, ManualAction::Compact, 2).unwrap();
        tui.commands
            .as_ref()
            .unwrap()
            .send(WorkerCommand::Compact(next.clone()))
            .unwrap();
        assert!(!first.cancel().unwrap());
        let completed = assert_terminal_only(&tui, &next);
        assert!(matches!(
            completed.reason,
            ProjectionReason::Manual {
                outcome: ManualOutcome::Completed,
                applied: true,
                ..
            }
        ));
        assert!(!next.cancel().unwrap());
        tui.close(&f);
        wire.finish();
        f.assert_positive(&wire, &source);
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn real_terminal_escape_after_observed_post_retains_uncertain_original_and_cells() {
        if !dispatch_isolated(
            "frontend_manual_baselines::real_terminal_escape_after_observed_post_retains_uncertain_original_and_cells",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::with_post_marker(
            vec![Response::complete(SUMMARY)],
            true,
            Some(f.root.join("pty-post")),
        );
        f.configure(&wire);
        let (source, _) = f.seed(&wire);
        let receipt = real_terminal(&f, "escape");
        assert!(
            receipt["terminal_cells"]
                .as_str()
                .unwrap()
                .contains("accounting uncertain")
        );
        wire.finish();
        assert_eq!(wire.requests.lock().unwrap().len(), 1);
        let saved = f.saved();
        assert_eq!(saved.transcript, source);
        assert_eq!(
            (
                saved.turns,
                saved.input_tokens,
                saved.output_tokens,
                saved.cost_microcents
            ),
            (7, 100, 40, 60)
        );
        assert_eq!(
            saved.accounting_watermark.unwrap().full_cost_status,
            FullCostStatus::Uncertain
        );
        let checkpoint = f.checkpoint();
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(
            checkpoint.totals.knownness,
            orbit_engine::AccountingKnownness::Uncertain
        );
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .housekeeping_microcents,
            0
        );
        assert!(f.archives().is_empty());
        assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
        f.lease_released();
        f.binary_unchanged();
    }

    #[test]
    fn real_terminal_clear_shows_fresh_known_zero_and_preserves_old_source_bytes() {
        if !dispatch_isolated(
            "frontend_manual_baselines::real_terminal_clear_shows_fresh_known_zero_and_preserves_old_source_bytes",
        ) {
            return;
        }
        let f = Fixture::new();
        let _cwd = Cwd::enter(&f.workspace);
        let mut wire = Wire::with_post_marker(
            vec![Response::complete(SUMMARY)],
            false,
            Some(f.root.join("pty-post")),
        );
        f.configure(&wire);
        let (source, checkpoint) = f.seed(&wire);
        let read_source = |path: &Path, maximum: u64| {
            let before = fs::symlink_metadata(path).unwrap();
            assert!(before.is_file() && !before.file_type().is_symlink());
            assert_eq!(before.nlink(), 1);
            assert_eq!(before.mode() & 0o777, 0o600);
            assert_eq!(
                before.uid(),
                fs::metadata(std::env::var_os("HOME").unwrap())
                    .unwrap()
                    .uid()
            );
            assert!(before.len() <= maximum);
            let mut file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .unwrap();
            let identity = |value: &fs::Metadata| {
                (
                    value.dev(),
                    value.ino(),
                    value.mode(),
                    value.uid(),
                    value.gid(),
                    value.nlink(),
                    value.len(),
                    value.mtime(),
                    value.mtime_nsec(),
                    value.ctime(),
                    value.ctime_nsec(),
                )
            };
            assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(maximum + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes.len() as u64, before.len());
            assert_eq!(identity(&file.metadata().unwrap()), identity(&before));
            assert_eq!(
                identity(&fs::symlink_metadata(path).unwrap()),
                identity(&before)
            );
            bytes
        };
        let old_snapshot = f.home.join("sessions").join(format!("{SESSION}.json"));
        let old_bytes = read_source(&old_snapshot, 64 * 1024 * 1024);
        let old_accounting = f
            .home
            .join("context-history")
            .join(SESSION)
            .join("accounting.json");
        let old_journal = read_source(&old_accounting, 128 * 1024);
        let receipt = real_terminal(&f, "clear");
        let cells = receipt["terminal_cells"].as_str().unwrap();
        assert!(cells.contains("$0.0000") && cells.contains("ctx unknown"));
        wire.finish();
        assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
        f.lease_released();
        let after_bytes = read_source(&old_snapshot, 64 * 1024 * 1024);
        let after_journal = read_source(&old_accounting, 128 * 1024);
        let prelaunch = &receipt["clear_source_barrier"]["prelaunch"];
        let after_quit = &receipt["clear_source_after_quit"];
        for (name, before, after) in [
            ("snapshot", &old_bytes, &after_bytes),
            ("accounting", &old_journal, &after_journal),
        ] {
            assert_eq!(
                prelaunch[name]["sha256"],
                hex::encode(Sha256::digest(before))
            );
            assert_eq!(prelaunch[name]["bytes"], before.len() as u64);
            assert_eq!(
                after_quit[name]["sha256"],
                hex::encode(Sha256::digest(after))
            );
            assert_eq!(after_quit[name]["bytes"], after.len() as u64);
        }
        let mut before_value: Value = serde_json::from_slice(&old_bytes).unwrap();
        let mut after_value: Value = serde_json::from_slice(&after_bytes).unwrap();
        let before_object = before_value.as_object().unwrap();
        let after_object = after_value.as_object().unwrap();
        assert!(before_object.len() <= 32 && after_object.len() <= 32);
        let fields = before_object
            .keys()
            .chain(after_object.keys())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            fields.len() <= 32
                && fields.iter().all(|name| !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
        );
        let changed_fields = fields
            .into_iter()
            .filter(|name| before_object.get(*name) != after_object.get(*name))
            .cloned()
            .collect::<Vec<_>>();
        let diagnostic = json!({"prelaunch":prelaunch,"before_clear":receipt["clear_source_barrier"]["before_clear"],
            "after_quit":after_quit,"startup_changed_fields":receipt["clear_source_barrier"]["startup_changed_fields"],
            "prelaunch_to_after_quit_changed_fields":changed_fields});
        let startup_fields = receipt["clear_source_barrier"]["startup_changed_fields"]
            .as_array()
            .unwrap();
        assert!(
            startup_fields.is_empty()
                || (startup_fields.len() == 1 && startup_fields[0] == "updated_at"),
            "startup changed more than its saved timestamp: {diagnostic}"
        );
        assert!(
            json!(changed_fields) == receipt["clear_source_barrier"]["startup_changed_fields"],
            "source differences do not match the observed startup barrier: {diagnostic}"
        );
        for value in [&before_value, &after_value] {
            assert!(
                value["updated_at"]
                    .as_str()
                    .is_some_and(|timestamp| !timestamp.is_empty() && timestamp.len() <= 128),
                "saved timestamp must retain its original string type: {diagnostic}"
            );
        }
        before_value
            .as_object_mut()
            .unwrap()
            .remove("updated_at")
            .unwrap();
        after_value
            .as_object_mut()
            .unwrap()
            .remove("updated_at")
            .unwrap();
        assert!(
            before_value == after_value,
            "old saved source fields changed: {diagnostic}"
        );
        // Resume can refresh updated_at before Initial. Once that actual view
        // is observed, clear and shutdown must preserve the exact saved bytes.
        let before_clear = &receipt["clear_source_barrier"]["before_clear"];
        assert_eq!(receipt["clear_source_after_clear"], *before_clear);
        assert_eq!(*after_quit, *before_clear);
        assert_eq!(before_clear["accounting"], prelaunch["accounting"]);
        assert!(
            after_journal == old_journal,
            "old accounting bytes changed: {diagnostic}"
        );
        f.assert_old_refusal_preserved(&source, &checkpoint);
        let saved = sessions::list_sessions(&f.home).unwrap();
        assert_eq!(saved.len(), 2);
        let fresh = saved
            .iter()
            .find(|saved| saved.session_id != SESSION)
            .unwrap();
        assert!(fresh.transcript.is_empty());
        assert_eq!(
            (
                fresh.turns,
                fresh.input_tokens,
                fresh.output_tokens,
                fresh.cost_microcents
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            fresh.workspace,
            Some(fs::canonicalize(&f.workspace).unwrap())
        );
        assert_eq!(f.saved().workspace, fresh.workspace);
        assert_eq!(fresh.provider, "provider_a");
        assert_eq!(fresh.model, RAW_A);
        assert_eq!(fresh.gate, wire.url);
        assert_eq!(fresh.selection_origin, Some(SelectionOrigin::SavedExplicit));
        assert_eq!(fresh.effort, None);
        assert_eq!(
            fresh
                .accounting_watermark
                .as_ref()
                .unwrap()
                .full_cost_status,
            FullCostStatus::Known
        );
        let lease =
            SessionLease::acquire(&f.home, &fresh.session_id, "verify-pty-clear-release").unwrap();
        let target = context_journal(&f.home, &fresh.session_id, None)
            .unwrap()
            .accounting_checkpoint()
            .unwrap();
        assert_eq!(target.baseline, AccountingBaseline::FreshKnownZero);
        assert_eq!(target.revision.0, 0);
        assert!(target.pending.is_none());
        drop(lease);
        f.binary_unchanged();
    }
    mod plain_signal_baselines {
        use super::*;
        use std::os::unix::process::ExitStatusExt;

        const SIGNAL_CAPTURE_LIMIT: u64 = 2 * 1024 * 1024;

        fn signal_read_owned(f: &Fixture, path: &Path, limit: u64) -> Vec<u8> {
            assert!(path.starts_with(&f.root));
            let before = fs::symlink_metadata(path).unwrap();
            assert!(before.is_file() && !before.file_type().is_symlink());
            assert_eq!(before.nlink(), 1);
            assert_eq!(before.mode() & 0o777, 0o600);
            assert_eq!(before.uid(), fs::metadata(&f.root).unwrap().uid());
            assert!(before.len() <= limit);
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .unwrap();
            let opened = file.metadata().unwrap();
            assert_eq!((opened.dev(), opened.ino()), (before.dev(), before.ino()));
            assert_eq!(opened.nlink(), 1);
            assert_eq!(opened.mode() & 0o777, 0o600);
            let mut bytes = Vec::new();
            file.take(limit.checked_add(1).unwrap())
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() as u64 <= limit);
            let after = fs::symlink_metadata(path).unwrap();
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            assert_eq!(after.nlink(), 1);
            assert_eq!(after.mode() & 0o777, 0o600);
            assert_eq!(after.uid(), before.uid());
            assert!(after.len() <= limit);
            bytes
        }

        fn signal_snapshot_path(f: &Fixture) -> PathBuf {
            f.home.join("sessions").join(format!("{SESSION}.json"))
        }

        fn signal_accounting_path(f: &Fixture) -> PathBuf {
            f.home
                .join("context-history")
                .join(SESSION)
                .join("accounting.json")
        }

        fn signal_without_timestamp(bytes: &[u8]) -> Value {
            let mut value: Value = serde_json::from_slice(bytes).unwrap();
            let stamp = value["updated_at"].as_str().unwrap();
            assert!(!stamp.is_empty() && stamp.len() <= 128);
            value.as_object_mut().unwrap().remove("updated_at");
            value
        }

        struct SignalCli {
            child: CliProcess,
            open_input: Option<std::process::ChildStdin>,
            paths: [PathBuf; 2],
        }

        impl SignalCli {
            fn start(f: &Fixture, args: &[&str], open_input: bool) -> Self {
                require_private_system_fixture();
                f.binary_unchanged();
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
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("LANG", "C.UTF-8")
                    .env("TERM", "dumb")
                    .env("NO_COLOR", "1")
                    .current_dir(&f.workspace)
                    .stdin(if open_input {
                        Stdio::piped()
                    } else {
                        Stdio::null()
                    })
                    .stdout(
                        fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(&paths[0])
                            .unwrap(),
                    )
                    .stderr(
                        fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(&paths[1])
                            .unwrap(),
                    )
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
                let input = child.0.stdin.take();
                assert_eq!(input.is_some(), open_input);
                Self {
                    child,
                    open_input: input,
                    paths,
                }
            }

            fn live(&mut self) {
                assert!(
                    self.child.0.try_wait().unwrap().is_none(),
                    "real CLI exited before signal boundary"
                );
                for path in &self.paths {
                    assert!(fs::metadata(path).unwrap().len() <= SIGNAL_CAPTURE_LIMIT);
                }
            }

            fn terminate(&mut self) {
                self.live();
                assert!(
                    Command::new("/bin/kill")
                        .args(["-TERM", "--", &self.child.0.id().to_string()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success(),
                    "actual signal delivery to owned unreaped CLI failed"
                );
            }

            fn finish(mut self, f: &Fixture, pipe_must_remain_open: bool) -> CliResult {
                assert_eq!(self.open_input.is_some(), pipe_must_remain_open);
                let end = Instant::now() + Duration::from_secs(15);
                let status = loop {
                    for path in &self.paths {
                        assert!(fs::metadata(path).unwrap().len() <= SIGNAL_CAPTURE_LIMIT);
                    }
                    if let Some(status) = self.child.0.try_wait().unwrap() {
                        break status;
                    }
                    assert!(
                        Instant::now() < end,
                        "CLI signal completion deadline (fixture failure)"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                };
                // The REPL's pipe writer is still owned and open after actual exit.
                assert_eq!(self.open_input.is_some(), pipe_must_remain_open);
                let stdout =
                    String::from_utf8(signal_read_owned(f, &self.paths[0], SIGNAL_CAPTURE_LIMIT))
                        .unwrap();
                let stderr =
                    String::from_utf8(signal_read_owned(f, &self.paths[1], SIGNAL_CAPTURE_LIMIT))
                        .unwrap();
                assert!(
                    stdout.len().checked_add(stderr.len()).unwrap() as u64
                        <= 2 * SIGNAL_CAPTURE_LIMIT
                );
                CliResult {
                    status,
                    stdout,
                    stderr,
                }
            }
        }

        fn signal_assert_source(f: &Fixture, source: &[ChatMessage]) -> SessionFile {
            let saved = f.saved();
            assert_eq!(saved.session_id, SESSION);
            assert_eq!(saved.provider, "provider_a");
            assert_eq!(saved.model, RAW_A);
            assert_eq!(saved.selection_origin, Some(SelectionOrigin::SavedExplicit));
            assert_eq!(saved.effort, None);
            assert_eq!(saved.transcript, source);
            assert_eq!(
                (
                    saved.turns,
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (7, 100, 40, 60)
            );
            assert!(f.archives().is_empty());
            assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
            saved
        }

        fn signal_assert_ledger(f: &Fixture, expected_egress: usize) -> Vec<String> {
            let records = orbit_ledger::verify_ledger(&f.home.join("ledger"))
                .unwrap()
                .0;
            let mut ids = Vec::new();
            for record in records {
                match record.record.event {
                    orbit_ledger::LedgerEvent::EgressIntent(intent) => {
                        assert_eq!(intent.session_id, SESSION);
                        ids.push(intent.decision_id);
                    }
                    orbit_ledger::LedgerEvent::ToolIntent(_)
                    | orbit_ledger::LedgerEvent::ToolVerdict(_)
                    | orbit_ledger::LedgerEvent::ToolResult(_) => {
                        panic!("signal fixture performed a tool effect")
                    }
                    _ => {}
                }
            }
            assert_eq!(ids.len(), expected_egress);
            ids
        }

        fn signal_assert_no_runtime_error(capture: &CliResult) {
            for unexpected in [
                "process signal cleanup failed:",
                "session not saved:",
                "ORBIT-E0400:",
                "ORBIT-E1101:",
            ] {
                assert!(
                    !capture.stderr.contains(unexpected),
                    "unexpected runtime diagnostic: {unexpected}"
                );
            }
        }

        fn signal_remove_fixture(f: Fixture) {
            let path = f.root.clone();
            drop(f);
            assert!(
                matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "owned fixture cleanup failed"
            );
        }

        #[test]
        fn direct_compact_sigterm_at_real_summary_headers_saves_uncertainty_and_exits143() {
            if !dispatch_isolated(
                "frontend_manual_baselines::plain_signal_baselines::direct_compact_sigterm_at_real_summary_headers_saves_uncertainty_and_exits143",
            ) {
                return;
            }
            let f = Fixture::new();
            let mut wire =
                Wire::with_lifetimes(vec![Response::complete(SUMMARY)], true, None, 115, 120);
            f.configure(&wire);
            let (source, baseline) = f.seed(&wire);
            let before = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
            let mut process =
                SignalCli::start(&f, &["compact", "--session", SESSION, "--json"], false);
            let end = Instant::now() + Duration::from_secs(5);
            while wire.requests.lock().unwrap().is_empty() {
                process.live();
                assert!(
                    Instant::now() < end,
                    "real summary POST was not observed (fixture failure)"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            process.live();
            assert!(
                matches!(SessionLease::acquire(&f.home, SESSION, "signal-positive-live-owner"), Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
            );
            {
                let calls = wire.requests.lock().unwrap();
                assert_eq!(calls.len(), 1);
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                assert_eq!(
                    calls[0].target,
                    "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
                );
                assert_eq!(calls[0].body["model"], "summary-model");
                assert_eq!(calls[0].body["max_tokens"], 73);
                assert!(
                    calls[0]
                        .body
                        .get("tools")
                        .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
                );
                assert_eq!(
                    calls[0]
                        .headers
                        .iter()
                        .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                        .collect::<Vec<_>>(),
                    [wire.authority.as_str()]
                );
                assert!(
                    !calls[0]
                        .headers
                        .iter()
                        .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
                );
            }
            let active_saved_bytes = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
            assert_eq!(
                signal_without_timestamp(&before),
                signal_without_timestamp(&active_saved_bytes)
            );
            let active_saved = signal_assert_source(&f, &source);
            let active_accounting = signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024);
            let active = f.checkpoint();
            assert_eq!(active.owner_session_id, SESSION);
            assert!(active.child_id.is_none());
            assert_eq!(active.revision.0, 1);
            assert_eq!(active.baseline, baseline.baseline);
            assert_eq!(active.totals, baseline.totals);
            assert_eq!(
                active.known_priced_subtotals,
                baseline.known_priced_subtotals
            );
            assert!(active.last_settlement.is_none());
            let active_pending = active.pending.as_ref().unwrap();
            assert!(!active_pending.uncertain);
            assert_eq!(
                active_pending.intent.purpose,
                orbit_engine::AttemptPurpose::Chunk
            );
            assert_eq!(active_pending.intent.owner_session_id, SESSION);
            assert!(active_pending.intent.child_id.is_none());
            assert_eq!(
                active_pending.intent.request_id,
                active_pending.reference.request_id
            );
            assert_eq!(
                signal_assert_ledger(&f, 1),
                std::slice::from_ref(&active_pending.reference.request_id)
            );
            process.terminate();
            let capture = process.finish(&f, false);
            signal_assert_no_runtime_error(&capture);
            f.lease_released();
            let after_saved = signal_assert_source(&f, &source);
            let after_saved_bytes = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
            let after_accounting = signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024);
            let after = f.checkpoint();
            assert_eq!(after.owner_session_id, active.owner_session_id);
            assert_eq!(after.child_id, active.child_id);
            assert_eq!(after.baseline, active.baseline);
            assert_eq!(after.known_priced_subtotals, active.known_priced_subtotals);
            assert!(after.last_settlement.is_none());
            let pending = after.pending.as_ref().unwrap();
            assert_eq!(pending.reference, active_pending.reference);
            assert_eq!(pending.intent, active_pending.intent);
            let raw: Value = serde_json::from_slice(&after_accounting).unwrap();
            assert_eq!(raw["version"], 1);
            assert_eq!(raw["owner"], SESSION);
            assert_eq!(raw["entries"].as_array().unwrap().len(), 1);
            assert_eq!(raw["entries"][0]["namespace"], json!({"kind":"owner"}));
            let finalized_uncertainty = if after.revision.0 == 1 {
                assert_eq!(after, active);
                assert_eq!(after_saved_bytes, active_saved_bytes);
                assert_eq!(after_accounting, active_accounting);
                assert!(raw["entries"][0]["pending"]["uncertain_receipt"].is_null());
                false
            } else {
                assert_eq!(after.revision.0, 2);
                assert!(pending.uncertain);
                assert_eq!(after.totals.ordinary, active.totals.ordinary);
                assert_eq!(
                    after.totals.housekeeping,
                    orbit_engine::AccountingTotals {
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microcents: None
                    }
                );
                assert_eq!(
                    after.totals.knownness,
                    orbit_engine::AccountingKnownness::Uncertain
                );
                let receipt = &raw["entries"][0]["pending"]["uncertain_receipt"];
                assert_eq!(receipt["request_id"], active_pending.reference.request_id);
                assert_eq!(receipt["purpose"], "chunk");
                assert_eq!(receipt["knownness"], "uncertain");
                assert_eq!(receipt["completed"], false);
                assert!(
                    receipt["usage"].is_null()
                        || receipt["usage"]
                            == json!({"input_tokens":0,"output_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0})
                );
                assert_eq!(
                    receipt["totals"],
                    json!({"input_tokens":0,"output_tokens":0,"cost_microcents":null})
                );
                let mut expected = active_saved.accounting_watermark.clone().unwrap();
                expected.revision = 2;
                expected.full_cost_status = FullCostStatus::Uncertain;
                assert_eq!(after_saved.accounting_watermark, Some(expected));
                let mut normalized = signal_without_timestamp(&after_saved_bytes);
                normalized["accounting_watermark"] =
                    signal_without_timestamp(&active_saved_bytes)["accounting_watermark"].clone();
                assert_eq!(normalized, signal_without_timestamp(&active_saved_bytes));
                let output: Value = serde_json::from_str(&capture.stdout).unwrap();
                assert_eq!(output["command"], "compact");
                assert_eq!(output["status"], "unknown");
                assert_eq!(output["reason"], "cancelled");
                assert_eq!(output["applied"], false);
                assert_eq!(output["snapshot_saved"], true);
                true
            };
            assert_eq!(
                signal_assert_ledger(&f, 1),
                std::slice::from_ref(&active_pending.reference.request_id)
            );
            wire.finish();
            assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
            assert_eq!(wire.requests.lock().unwrap().len(), 1);
            f.binary_unchanged();
            signal_remove_fixture(f);
            assert_eq!(
                (
                    capture.status.signal(),
                    capture.status.code(),
                    finalized_uncertainty
                ),
                (None, Some(143), true),
                "direct compaction lacks graceful SIGTERM publication: all real source, pending/accounting, one POST, lease, binary and cleanup controls reached"
            );
        }

        #[test]
        fn plain_repl_idle_open_stdin_sigterm_preserves_source_and_exits143() {
            if !dispatch_isolated(
                "frontend_manual_baselines::plain_signal_baselines::plain_repl_idle_open_stdin_sigterm_preserves_source_and_exits143",
            ) {
                return;
            }
            let f = Fixture::new();
            let mut wire = Wire::with_lifetimes(Vec::new(), false, None, 115, 120);
            f.configure(&wire);
            let (source, before_checkpoint) = f.seed(&wire);
            let before = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
            let before_accounting = signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024);
            let mut process = SignalCli::start(
                &f,
                &["chat", "--no-tui", "--resume", SESSION, "--bare"],
                true,
            );
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                process.live();
                // NO_COLOR selects the actual HUD Plain mode, whose banner is stderr.
                let out = signal_read_owned(&f, &process.paths[1], SIGNAL_CAPTURE_LIMIT);
                if std::str::from_utf8(&out)
                    .is_ok_and(|text| text.contains("type /help for commands, exit to quit"))
                {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "actual plain REPL startup banner missing (fixture failure)"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(process.open_input.is_some());
            assert!(
                matches!(SessionLease::acquire(&f.home, SESSION, "signal-positive-idle-owner"), Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
            );
            let active_saved = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
            assert_eq!(
                signal_without_timestamp(&before),
                signal_without_timestamp(&active_saved)
            );
            signal_assert_source(&f, &source);
            assert_eq!(f.checkpoint(), before_checkpoint);
            assert_eq!(
                signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024),
                before_accounting
            );
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            assert!(wire.requests.lock().unwrap().is_empty());
            signal_assert_ledger(&f, 0);
            process.terminate();
            let capture = process.finish(&f, true);
            signal_assert_no_runtime_error(&capture);
            f.lease_released();
            signal_assert_source(&f, &source);
            assert_eq!(f.checkpoint(), before_checkpoint);
            assert_eq!(
                signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024),
                active_saved
            );
            assert_eq!(
                signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024),
                before_accounting
            );
            signal_assert_ledger(&f, 0);
            wire.finish();
            assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
            assert!(wire.requests.lock().unwrap().is_empty());
            f.binary_unchanged();
            signal_remove_fixture(f);
            assert_eq!(
                (capture.status.signal(), capture.status.code()),
                (None, Some(143)),
                "plain idle REPL lacks graceful SIGTERM exit while its pipe stays open: all real source/accounting, zero POST, lease, binary and cleanup controls reached"
            );
        }

        mod signal_capabilities {
            use super::*;

            #[derive(Clone, Copy)]
            enum Signal {
                Int,
                Term,
                Hup,
            }
            impl Signal {
                fn argument(self) -> &'static str {
                    match self {
                        Self::Int => "-INT",
                        Self::Term => "-TERM",
                        Self::Hup => "-HUP",
                    }
                }
                fn code(self) -> i32 {
                    match self {
                        Self::Int => 130,
                        Self::Term => 143,
                        Self::Hup => 129,
                    }
                }
            }

            fn deliver(process: &mut SignalCli, signal: Signal) {
                process.live();
                assert!(
                    Command::new("/bin/kill")
                        .args([signal.argument(), "--", &process.child.0.id().to_string()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success(),
                    "signal delivery to the owned unreaped CLI failed"
                );
            }

            fn wait_text(f: &Fixture, process: &mut SignalCli, text: &str) {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    process.live();
                    let bytes = signal_read_owned(f, &process.paths[1], SIGNAL_CAPTURE_LIMIT);
                    if std::str::from_utf8(&bytes).is_ok_and(|value| value.contains(text)) {
                        return;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "actual CLI diagnostic missing (fixture failure)"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
            }

            fn wait_input_poll(process: &mut SignalCli) {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    process.live();
                    // This is the still-owned leader's main thread, not a
                    // guessed delay after its banner or a background watcher.
                    let mut text = String::new();
                    fs::File::open(format!("/proc/{}/syscall", process.child.0.id()))
                        .expect("owned CLI syscall observer unavailable (fixture failure)")
                        .take(1025)
                        .read_to_string(&mut text)
                        .unwrap();
                    assert!(text.len() <= 1024, "owned syscall observer bound");
                    process.live();
                    let number = text
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<libc::c_long>().ok());
                    let polling = number == Some(libc::SYS_ppoll);
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    let polling = polling || number == Some(libc::SYS_poll);
                    if polling {
                        return;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "owned CLI did not enter its input poll (fixture failure)"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
            }

            fn wait_plain_ready(f: &Fixture, process: &mut SignalCli) {
                wait_text(f, process, "type /help for commands, exit to quit");
                wait_input_poll(process);
                assert!(
                    matches!(SessionLease::acquire(&f.home, SESSION, "signal-capability-live"),
                    Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
                );
            }

            fn write_input(process: &mut SignalCli, bytes: &[u8]) {
                process.live();
                let input = process.open_input.as_mut().unwrap();
                input.write_all(bytes).unwrap();
                input.flush().unwrap();
            }

            fn queued_bytes(process: &SignalCli) -> usize {
                rustix::io::ioctl_fionread(process.open_input.as_ref().unwrap()).unwrap() as usize
            }

            fn assert_clean_signal(capture: &CliResult, signal: Signal) {
                signal_assert_no_runtime_error(capture);
                for diagnostic in [
                    "session accounting inspection failed",
                    "publication or inspection failed",
                    "input failed:",
                    "approval input failed:",
                    "ORBIT-E0401:",
                ] {
                    assert!(
                        !capture.stderr.contains(diagnostic),
                        "unexpected runtime diagnostic: {diagnostic}"
                    );
                }
                assert_eq!(
                    (capture.status.signal(), capture.status.code()),
                    (None, Some(signal.code()))
                );
            }

            fn assert_chat_summary(capture: &CliResult, uncertain: bool) {
                let summaries = capture
                    .stdout
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter(|value| value["command"] == "chat")
                    .collect::<Vec<_>>();
                assert_eq!(summaries.len(), 1);
                let value = &summaries[0];
                assert_eq!(value["schema"], "orbit.cli/v1");
                assert_eq!(value["status"], "cancelled");
                assert_eq!(value["session"], SESSION);
                assert_eq!(value["turns"], 7);
                assert_eq!(
                    value["usage"],
                    json!({"input_tokens":100,"output_tokens":40})
                );
                assert_eq!(value["cost_microcents"], 60);
                assert_eq!(
                    value["full_cost_status"],
                    if uncertain {
                        "uncertain"
                    } else {
                        "unknown_legacy"
                    }
                );
            }

            fn wait_one_post(process: &mut SignalCli, wire: &Wire, model: &str) {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    process.live();
                    let count = wire.requests.lock().unwrap().len();
                    assert!(count <= 1, "unexpected provider replay before signal");
                    if count == 1 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "actual provider POST missing (fixture failure)"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                let calls = wire.requests.lock().unwrap();
                assert_eq!(calls.len(), 1);
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                let call = &calls[0];
                assert_eq!(
                    call.target,
                    "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
                );
                assert_eq!(call.body["model"], model);
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
                if model == "summary-model" {
                    assert!(
                        call.body
                            .get("tools")
                            .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
                    );
                }
            }

            fn assert_active_attempt(
                f: &Fixture,
                baseline: &AccountingCheckpoint,
                purpose: orbit_engine::AttemptPurpose,
            ) -> AccountingCheckpoint {
                assert!(
                    matches!(SessionLease::acquire(&f.home, SESSION, "signal-capability-request-owner"),
                    Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
                );
                let active = f.checkpoint();
                assert_eq!(active.owner_session_id, SESSION);
                assert!(active.child_id.is_none());
                assert_eq!(active.revision.0, 1);
                assert_eq!(active.baseline, baseline.baseline);
                assert_eq!(active.totals, baseline.totals);
                assert_eq!(
                    active.known_priced_subtotals,
                    baseline.known_priced_subtotals
                );
                assert!(active.last_settlement.is_none());
                let pending = active.pending.as_ref().unwrap();
                assert!(!pending.uncertain);
                assert_eq!(pending.intent.purpose, purpose);
                assert_eq!(pending.intent.owner_session_id, SESSION);
                assert!(pending.intent.child_id.is_none());
                assert_eq!(pending.intent.request_id, pending.reference.request_id);
                assert_eq!(
                    signal_assert_ledger(f, 1),
                    std::slice::from_ref(&pending.reference.request_id)
                );
                active
            }

            fn assert_uncertain_attempt(
                f: &Fixture,
                active: &AccountingCheckpoint,
                active_saved: &[u8],
                expected_source: &[ChatMessage],
            ) {
                let after = f.checkpoint();
                let pending = active.pending.as_ref().unwrap();
                let mut expected = active.clone();
                expected.revision.0 = 2;
                expected.pending.as_mut().unwrap().uncertain = true;
                expected.totals.knownness = orbit_engine::AccountingKnownness::Uncertain;
                let ordinary = pending.intent.purpose == orbit_engine::AttemptPurpose::Ordinary;
                if ordinary {
                    expected.totals.ordinary.cost_microcents = None;
                } else {
                    expected.totals.housekeeping.cost_microcents = None;
                }
                assert_eq!(after, expected);
                let saved = signal_assert_source(f, expected_source);
                let before: SessionFile = serde_json::from_slice(active_saved).unwrap();
                assert_eq!(saved.gate, before.gate);
                let mut watermark = before.accounting_watermark.unwrap();
                watermark.revision = 2;
                watermark.full_cost_status = FullCostStatus::Uncertain;
                assert_eq!(saved.accounting_watermark, Some(watermark.clone()));
                let bytes = signal_read_owned(f, &signal_snapshot_path(f), 128 * 1024);
                let mut expected_saved = signal_without_timestamp(active_saved);
                expected_saved["transcript"] = serde_json::to_value(expected_source).unwrap();
                expected_saved["accounting_watermark"] = serde_json::to_value(watermark).unwrap();
                assert!(
                    signal_without_timestamp(&bytes) == expected_saved,
                    "signal changed unexpected saved fields"
                );
                let accounting = signal_read_owned(f, &signal_accounting_path(f), 128 * 1024);
                let raw: Value = serde_json::from_slice(&accounting).unwrap();
                assert_eq!(raw["version"], 1);
                assert_eq!(raw["owner"], SESSION);
                assert_eq!(raw["entries"].as_array().unwrap().len(), 1);
                assert_eq!(raw["entries"][0]["namespace"], json!({"kind":"owner"}));
                let receipt = &raw["entries"][0]["pending"]["uncertain_receipt"];
                assert_eq!(receipt["request_id"], pending.reference.request_id);
                assert_eq!(
                    receipt["purpose"],
                    if ordinary { "ordinary" } else { "chunk" }
                );
                assert_eq!(receipt["knownness"], "uncertain");
                assert_eq!(receipt["completed"], false);
                assert_eq!(
                    receipt["totals"],
                    json!({"input_tokens":0,"output_tokens":0,"cost_microcents":null})
                );
                assert!(
                    receipt["usage"].is_null()
                        || receipt["usage"]
                            == json!({"input_tokens":0,"output_tokens":0,
                    "cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":0})
                );
                assert_eq!(
                    signal_assert_ledger(f, 1),
                    std::slice::from_ref(&pending.reference.request_id)
                );
            }

            fn refuse_pending_replay(f: &Fixture, wire: &Wire) {
                let snapshot = signal_read_owned(f, &signal_snapshot_path(f), 128 * 1024);
                let accounting = signal_read_owned(f, &signal_accounting_path(f), 128 * 1024);
                let checkpoint = f.checkpoint();
                let process = SignalCli::start(
                    f,
                    &["chat", "--no-tui", "--resume", SESSION, "--bare"],
                    false,
                );
                let capture = process.finish(f, false);
                assert_eq!(
                    (capture.status.signal(), capture.status.code()),
                    (None, Some(2))
                );
                assert!(capture.stderr.contains(
                    "pending uncertain request requires explicit inspection before admission"
                ));
                assert!(!capture.stderr.contains("process signal cleanup failed:"));
                assert!(
                    signal_read_owned(f, &signal_snapshot_path(f), 128 * 1024) == snapshot,
                    "pending replay refusal changed saved bytes"
                );
                assert_eq!(
                    signal_read_owned(f, &signal_accounting_path(f), 128 * 1024),
                    accounting
                );
                assert_eq!(f.checkpoint(), checkpoint);
                f.lease_released();
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                assert_eq!(wire.requests.lock().unwrap().len(), 1);
                signal_assert_ledger(f, 1);
            }

            fn manual_case(exact: &str, signal: Signal, repl: bool) {
                if !dispatch_isolated(exact) {
                    return;
                }
                let f = Fixture::new();
                let mut wire =
                    Wire::with_lifetimes(vec![Response::complete(SUMMARY)], true, None, 115, 120);
                f.configure(&wire);
                let (source, baseline) = f.seed(&wire);
                let before = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                let mut process = if repl {
                    SignalCli::start(
                        &f,
                        &["chat", "--no-tui", "--resume", SESSION, "--bare"],
                        true,
                    )
                } else {
                    SignalCli::start(&f, &["compact", "--session", SESSION, "--json"], false)
                };
                if repl {
                    wait_plain_ready(&f, &mut process);
                    write_input(&mut process, b"/compact\n");
                }
                wait_one_post(&mut process, &wire, "summary-model");
                let active_saved = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                assert!(
                    signal_without_timestamp(&before) == signal_without_timestamp(&active_saved),
                    "manual startup changed unexpected saved fields"
                );
                let saved = signal_assert_source(&f, &source);
                assert_eq!(saved.gate, wire.url);
                let active =
                    assert_active_attempt(&f, &baseline, orbit_engine::AttemptPurpose::Chunk);
                deliver(&mut process, signal);
                let capture = process.finish(&f, repl);
                assert_clean_signal(&capture, signal);
                f.lease_released();
                assert_uncertain_attempt(&f, &active, &active_saved, &source);
                if repl {
                    assert!(capture.stdout.contains(
                        "compaction: unknown (cancelled); applied=false, snapshot_saved=true"
                    ));
                    assert_chat_summary(&capture, true);
                } else {
                    let output: Value = serde_json::from_str(&capture.stdout).unwrap();
                    assert_eq!(output["command"], "compact");
                    assert_eq!(output["status"], "unknown");
                    assert_eq!(output["reason"], "cancelled");
                    assert_eq!(output["applied"], false);
                    assert_eq!(output["snapshot_saved"], true);
                    assert_eq!(output["full_cost_status"], "uncertain");
                }
                refuse_pending_replay(&f, &wire);
                wire.finish();
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                assert_eq!(wire.requests.lock().unwrap().len(), 1);
                f.binary_unchanged();
                signal_remove_fixture(f);
            }

            enum IdleBoundary {
                Empty,
                Partial,
                RecoverableError,
            }

            fn idle_case(exact: &str, signal: Signal, boundary: IdleBoundary) {
                if !dispatch_isolated(exact) {
                    return;
                }
                let f = Fixture::new();
                let mut wire = Wire::with_lifetimes(Vec::new(), false, None, 115, 120);
                f.configure(&wire);
                let (source, checkpoint) = f.seed(&wire);
                let before = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                let accounting = signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024);
                let mut process = SignalCli::start(
                    &f,
                    &["chat", "--no-tui", "--resume", SESSION, "--bare"],
                    true,
                );
                wait_plain_ready(&f, &mut process);
                match boundary {
                    IdleBoundary::Empty => {}
                    IdleBoundary::RecoverableError => {
                        write_input(&mut process, b"/compact extra\n");
                        wait_text(&f, &mut process, "usage: /compact");
                        wait_input_poll(&mut process);
                        assert_eq!(queued_bytes(&process), 0);
                    }
                    IdleBoundary::Partial => {
                        const PARTIAL: &[u8] = b"an unfinished user line without a newline";
                        write_input(&mut process, PARTIAL);
                        let deadline = Instant::now() + Duration::from_secs(5);
                        loop {
                            process.live();
                            let remaining = queued_bytes(&process);
                            assert!(remaining <= PARTIAL.len());
                            if remaining == 0 {
                                break;
                            }
                            assert!(
                                Instant::now() < deadline,
                                "partial input was not consumed (fixture failure)"
                            );
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        wait_input_poll(&mut process);
                        assert_eq!(queued_bytes(&process), 0);
                    }
                }
                process.live();
                let active = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                assert!(
                    signal_without_timestamp(&before) == signal_without_timestamp(&active),
                    "idle startup changed unexpected saved fields"
                );
                let saved = signal_assert_source(&f, &source);
                assert_eq!(saved.gate, wire.url);
                assert_eq!(f.checkpoint(), checkpoint);
                assert_eq!(
                    signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024),
                    accounting
                );
                assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
                assert!(wire.requests.lock().unwrap().is_empty());
                signal_assert_ledger(&f, 0);
                deliver(&mut process, signal);
                let capture = process.finish(&f, true);
                assert_clean_signal(&capture, signal);
                assert_chat_summary(&capture, false);
                f.lease_released();
                signal_assert_source(&f, &source);
                assert_eq!(f.checkpoint(), checkpoint);
                assert!(
                    signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024) == active,
                    "idle signal changed saved bytes"
                );
                assert_eq!(
                    signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024),
                    accounting
                );
                signal_assert_ledger(&f, 0);
                wire.finish();
                assert_eq!(wire.connections.load(Ordering::SeqCst), 0);
                assert!(wire.requests.lock().unwrap().is_empty());
                f.binary_unchanged();
                signal_remove_fixture(f);
            }

            fn finish_with_queued_input(
                mut process: SignalCli,
                f: &Fixture,
                expected: usize,
            ) -> CliResult {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    for path in &process.paths {
                        assert!(fs::metadata(path).unwrap().len() <= SIGNAL_CAPTURE_LIMIT);
                    }
                    if process.child.0.try_wait().unwrap().is_some() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "ordinary signal completion deadline (fixture failure)"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert_eq!(
                    queued_bytes(&process),
                    expected,
                    "queued later prompt was consumed after cancellation"
                );
                process.finish(f, true)
            }

            fn ordinary_case(exact: &str) {
                if !dispatch_isolated(exact) {
                    return;
                }
                const PROMPT: &str = "perform only this first ordinary request";
                const LATER: &str = "never admit this queued later prompt";
                let f = Fixture::new();
                let mut wire =
                    Wire::with_lifetimes(vec![Response::complete("unused")], true, None, 115, 120);
                f.configure(&wire);
                let config_path = f.home.join("providers.toml");
                let mut config: orbit_cli::config::ProvidersConfig =
                    toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
                config.provider[0].models[0]
                    .context_limits
                    .as_mut()
                    .unwrap()
                    .input_tokens = Some(64_000);
                write_private(&config_path, toml::to_string(&config).unwrap());
                let source = vec![
                    orbit_engine::user_message("a small prior question"),
                    orbit_engine::assistant_message("a small prior answer"),
                ];
                let mut saved = SessionFile::from_chat(
                    SESSION,
                    RAW_A,
                    &wire.url,
                    "provider_a",
                    &source,
                    7,
                    100,
                    40,
                    60,
                )
                .with_selection_origin(SelectionOrigin::SavedExplicit);
                saved.bind_workspace(&f.workspace).unwrap();
                let lease =
                    SessionLease::acquire(&f.home, SESSION, "ordinary-signal-seed").unwrap();
                lease.save(&saved).unwrap();
                prepare_root(&lease, &mut saved, RootOrigin::RestoredOrLegacy).unwrap();
                drop(lease);
                let baseline = f.checkpoint();
                assert_eq!(baseline.baseline, AccountingBaseline::UnknownLegacy);
                assert_eq!(baseline.revision.0, 0);
                assert!(baseline.pending.is_none());
                let before = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                let mut process = SignalCli::start(
                    &f,
                    &["chat", "--no-tui", "--resume", SESSION, "--bare"],
                    true,
                );
                wait_plain_ready(&f, &mut process);
                let active_saved = signal_read_owned(&f, &signal_snapshot_path(&f), 128 * 1024);
                assert!(
                    signal_without_timestamp(&before) == signal_without_timestamp(&active_saved),
                    "ordinary startup changed unexpected saved fields"
                );
                signal_assert_source(&f, &source);
                write_input(&mut process, format!("{PROMPT}\n{LATER}\n").as_bytes());
                wait_one_post(&mut process, &wire, RAW_A);
                let active =
                    assert_active_attempt(&f, &baseline, orbit_engine::AttemptPurpose::Ordinary);
                assert_eq!(queued_bytes(&process), LATER.len() + 1);
                {
                    let calls = wire.requests.lock().unwrap();
                    let messages = calls[0].body["messages"].as_array().unwrap();
                    assert_eq!(
                        messages
                            .iter()
                            .filter(
                                |message| message["role"] == "user" && message["content"] == PROMPT
                            )
                            .count(),
                        1
                    );
                    assert!(!messages.iter().any(|message| message["content"] == LATER));
                }
                deliver(&mut process, Signal::Term);
                let capture = finish_with_queued_input(process, &f, LATER.len() + 1);
                assert_clean_signal(&capture, Signal::Term);
                assert_chat_summary(&capture, true);
                assert!(capture.stderr.contains("turn cancelled"));
                f.lease_released();
                let mut expected = source;
                expected.push(orbit_engine::user_message(PROMPT));
                assert_uncertain_attempt(&f, &active, &active_saved, &expected);
                assert!(
                    !f.saved()
                        .transcript
                        .iter()
                        .any(|message| message.content == LATER)
                );
                refuse_pending_replay(&f, &wire);
                wire.finish();
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                assert_eq!(wire.requests.lock().unwrap().len(), 1);
                f.binary_unchanged();
                signal_remove_fixture(f);
            }

            #[test]
            fn direct_compact_sigint_retains_uncertain_source() {
                manual_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::direct_compact_sigint_retains_uncertain_source",
                    Signal::Int,
                    false,
                );
            }
            #[test]
            fn direct_compact_sighup_retains_uncertain_source() {
                manual_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::direct_compact_sighup_retains_uncertain_source",
                    Signal::Hup,
                    false,
                );
            }
            #[test]
            fn repl_compact_sigint_retains_uncertain_source() {
                manual_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_compact_sigint_retains_uncertain_source",
                    Signal::Int,
                    true,
                );
            }
            #[test]
            fn repl_compact_sigterm_retains_uncertain_source() {
                manual_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_compact_sigterm_retains_uncertain_source",
                    Signal::Term,
                    true,
                );
            }
            #[test]
            fn repl_compact_sighup_retains_uncertain_source() {
                manual_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_compact_sighup_retains_uncertain_source",
                    Signal::Hup,
                    true,
                );
            }
            #[test]
            fn repl_idle_sigint_preserves_source() {
                idle_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_idle_sigint_preserves_source",
                    Signal::Int,
                    IdleBoundary::Empty,
                );
            }
            #[test]
            fn repl_idle_sighup_preserves_source() {
                idle_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_idle_sighup_preserves_source",
                    Signal::Hup,
                    IdleBoundary::Empty,
                );
            }
            #[test]
            fn repl_partial_line_sigterm_does_not_admit_the_unfinished_prompt() {
                idle_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_partial_line_sigterm_does_not_admit_the_unfinished_prompt",
                    Signal::Term,
                    IdleBoundary::Partial,
                );
            }
            #[test]
            fn repl_idle_after_recoverable_compact_error_sigterm_is_cancelled() {
                idle_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_idle_after_recoverable_compact_error_sigterm_is_cancelled",
                    Signal::Term,
                    IdleBoundary::RecoverableError,
                );
            }
            #[test]
            fn repl_ordinary_sigterm_keeps_pending_and_does_not_consume_the_next_prompt() {
                ordinary_case(
                    "frontend_manual_baselines::plain_signal_baselines::signal_capabilities::repl_ordinary_sigterm_keeps_pending_and_does_not_consume_the_next_prompt",
                );
            }
        }
        mod approval_pty_capability {
            use super::*;

            const PROMPT: &str = "request the one approval fixture command";
            const CALL: &str = "approval-capability-call";
            const ARGUMENTS: &str =
                r#"{"command":"printf approval-must-not-run > approval-must-not-exist.txt"}"#;
            const SCRIPT_SHA256: &str =
                "ab7e43dd01c5a2bf12aabb9c7ad788d68caa99d0564309478ee71f4bfc0aca1f";

            fn script_stamp(
                value: &fs::Metadata,
            ) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
                (
                    value.dev(),
                    value.ino(),
                    value.mode(),
                    value.uid(),
                    value.gid(),
                    value.nlink(),
                    value.len(),
                    value.mtime(),
                    value.mtime_nsec(),
                    value.ctime(),
                    value.ctime_nsec(),
                )
            }
            fn read_script(path: &Path) -> (fs::Metadata, Vec<u8>) {
                let before = fs::symlink_metadata(path).unwrap();
                assert!(path.is_absolute() && path.canonicalize().unwrap() == path);
                assert!(
                    before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1
                );
                assert_eq!(
                    before.uid(),
                    fs::metadata(std::env::var_os("HOME").unwrap())
                        .unwrap()
                        .uid()
                );
                assert!(
                    before.mode() & 0o022 == 0 && before.len() > 0 && before.len() <= 64 * 1024
                );
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)
                    .unwrap();
                assert_eq!(
                    script_stamp(&file.metadata().unwrap()),
                    script_stamp(&before)
                );
                let mut bytes = Vec::new();
                (&mut file)
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes.len() as u64, before.len());
                assert_eq!(
                    script_stamp(&file.metadata().unwrap()),
                    script_stamp(&before)
                );
                assert_eq!(
                    script_stamp(&fs::symlink_metadata(path).unwrap()),
                    script_stamp(&before)
                );
                (before, bytes)
            }

            fn publish_signal(directory: &Path, bytes: &[u8]) {
                let staged = directory.join(".signal.pending");
                let target = directory.join("signal");
                assert!(
                    matches!(fs::symlink_metadata(&target), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                );
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&staged)
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.flush().unwrap();
                drop(file);
                // One producer owns this private barrier name. Atomic visibility avoids
                // a reader observing a partially written command; no product I/O here.
                fs::rename(staged, target).unwrap();
            }

            struct Driver {
                child: CliProcess,
                control: PathBuf,
                out: PathBuf,
                err: PathBuf,
            }
            impl Drop for Driver {
                fn drop(&mut self) {
                    if matches!(self.child.0.try_wait(), Ok(None)) {
                        // Let Python run its owned CLI-group/PTY finally path before
                        // CliProcess's last-resort kill of the Python group. No control
                        // overwrites a signal already issued by the normal test path.
                        if matches!(fs::symlink_metadata(self.control.join("signal")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                        {
                            let staged = self.control.join(".abort.pending");
                            if let Ok(mut file) = fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .mode(0o600)
                                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                .open(&staged)
                                && file
                                    .write_all(b"abort-owned-fixture\n")
                                    .and_then(|_| file.flush())
                                    .is_ok()
                            {
                                let _ = fs::rename(staged, self.control.join("signal"));
                            }
                        }
                        let deadline = Instant::now() + Duration::from_secs(8);
                        while matches!(self.child.0.try_wait(), Ok(None))
                            && Instant::now() < deadline
                        {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                }
            }
            impl Driver {
                fn start(f: &Fixture, script: &Path, test_binary: &Path) -> Self {
                    require_private_system_fixture();
                    f.binary_unchanged();
                    let control = f.root.join("approval-pty");
                    private_directory(&control);
                    let out = f.root.join("approval-python.out");
                    let err = f.root.join("approval-python.err");
                    write_private(&out, b"");
                    write_private(&err, b"");
                    let mut command = Command::new("/usr/bin/python3");
                    command
                        .args(["-I", "-S", "-B"])
                        .arg(script)
                        .arg("--binary")
                        .arg(&f.binary)
                        .arg("--test-binary")
                        .arg(test_binary)
                        .arg("--home")
                        .arg(&f.home)
                        .arg("--workspace")
                        .arg(&f.workspace)
                        .arg("--control-dir")
                        .arg(&control)
                        .args(["--session", SESSION])
                        .arg("--poll-syscall")
                        .arg(libc::SYS_ppoll.to_string())
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin")
                        .env("LANG", "C.UTF-8")
                        .current_dir(&f.workspace)
                        .stdin(Stdio::null())
                        .stdout(
                            fs::OpenOptions::new()
                                .write(true)
                                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                .open(&out)
                                .unwrap(),
                        )
                        .stderr(
                            fs::OpenOptions::new()
                                .write(true)
                                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                .open(&err)
                                .unwrap(),
                        )
                        .process_group(0);
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    command
                        .arg("--poll-syscall")
                        .arg(libc::SYS_poll.to_string());
                    for name in [
                        "HOME",
                        "TMPDIR",
                        "XDG_CONFIG_HOME",
                        "XDG_CACHE_HOME",
                        "XDG_DATA_HOME",
                        "XDG_STATE_HOME",
                        "XDG_RUNTIME_DIR",
                        "ORBIT_ACTIVATION_ROOT",
                        "ORBIT_ACTIVATION_PARENT_MOUNT_FD",
                        "ORBIT_ACTIVATION_PARENT_USER_FD",
                        "ORBIT_ACTIVATION_MANAGED_MARKER",
                        "ORBIT_ACTIVATION_ISOLATED",
                        "ORBIT_ACTIVATION_RUNNER_DEPTH",
                    ] {
                        command.env(
                            name,
                            std::env::var_os(name).expect("private terminal setting missing"),
                        );
                    }
                    Self {
                        child: CliProcess(command.spawn().unwrap()),
                        control,
                        out,
                        err,
                    }
                }
                fn ready(&mut self, f: &Fixture) -> Value {
                    let deadline = Instant::now() + Duration::from_secs(35);
                    loop {
                        assert!(fs::metadata(&self.out).unwrap().len() <= 64 * 1024);
                        assert!(fs::metadata(&self.err).unwrap().len() <= 16 * 1024);
                        assert!(
                            self.child.0.try_wait().unwrap().is_none(),
                            "approval PTY driver exited before its real prompt barrier"
                        );
                        match fs::symlink_metadata(self.control.join("ready.json")) {
                            Ok(_) => break,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => panic!("private approval barrier metadata: {error}"),
                        }
                        assert!(
                            Instant::now() < deadline,
                            "actual approval PTY barrier deadline (fixture failure)"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    serde_json::from_slice(&signal_read_owned(
                        f,
                        &self.control.join("ready.json"),
                        4096,
                    ))
                    .unwrap()
                }
                fn finish(&mut self, f: &Fixture) -> Value {
                    let deadline = Instant::now() + Duration::from_secs(35);
                    let status = loop {
                        assert!(fs::metadata(&self.out).unwrap().len() <= 64 * 1024);
                        assert!(fs::metadata(&self.err).unwrap().len() <= 16 * 1024);
                        if let Some(status) = self.child.0.try_wait().unwrap() {
                            break status;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "approval PTY final deadline (fixture failure)"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    };
                    let raw = signal_read_owned(f, &self.out, 64 * 1024);
                    let err = signal_read_owned(f, &self.err, 16 * 1024);
                    assert!(
                        err.is_empty(),
                        "approval fixture emitted an unstructured diagnostic"
                    );
                    let receipt: Value =
                        serde_json::from_slice(&raw).expect("approval fixture structured receipt");
                    std::io::stdout()
                        .lock()
                        .write_all(
                            format!("ORBIT_CONTEXT_PLAIN_APPROVAL_PTY {receipt}\n").as_bytes(),
                        )
                        .unwrap();
                    assert!(
                        status.success(),
                        "approval PTY fixture failed: {}",
                        receipt["reason"]
                    );
                    assert_eq!(receipt["schema"], "orbit.context-plain-approval-pty/v1");
                    assert_eq!(receipt["status"], "TEST_PASSED");
                    receipt
                }
            }

            fn assert_known_completed_request(
                inspection: &orbit_cli::context_history::AccountingInspection,
            ) {
                use orbit_engine::{AccountingKnownness, AttemptPurpose};
                let checkpoint = &inspection.checkpoint;
                assert_eq!(checkpoint.owner_session_id, SESSION);
                assert!(checkpoint.child_id.is_none());
                assert_eq!(checkpoint.baseline, AccountingBaseline::FreshKnownZero);
                assert_eq!(checkpoint.revision.0, 2);
                assert!(
                    checkpoint.pending.is_none(),
                    "completed provider usage must not become a cancelled pending request"
                );
                assert!(inspection.pending_receipt.is_none());
                assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Known);
                assert_eq!(
                    checkpoint.totals.ordinary,
                    orbit_engine::AccountingTotals {
                        input_tokens: 11,
                        output_tokens: 7,
                        cost_microcents: Some(5)
                    }
                );
                assert_eq!(
                    checkpoint.totals.housekeeping,
                    orbit_engine::AccountingTotals::known_zero()
                );
                assert_eq!(
                    checkpoint.known_priced_subtotals,
                    Some(orbit_engine::KnownPricedSubtotals {
                        ordinary_microcents: 5,
                        housekeeping_microcents: 0
                    })
                );
                let last = inspection.last_receipt.as_ref().unwrap();
                assert_eq!(last.purpose, AttemptPurpose::Ordinary);
                assert_eq!(last.knownness, AccountingKnownness::Known);
                assert!(last.completed);
                assert_eq!(
                    last.usage,
                    Some(orbit_adapter::types::ProviderUsage {
                        input_tokens: 11,
                        output_tokens: 7,
                        cache_read_tokens: 0,
                        cache_write_tokens: 0,
                        reasoning_tokens: 0
                    })
                );
                assert_eq!(last.totals, checkpoint.totals.ordinary);
                assert_eq!(
                    checkpoint
                        .last_settlement
                        .as_ref()
                        .unwrap()
                        .reference
                        .request_id,
                    last.request_id
                );
            }

            #[test]
            fn plain_repl_sigterm_at_real_tty_approval_preserves_known_bill_and_denied_tool_group()
            {
                if !dispatch_isolated(
                    "frontend_manual_baselines::plain_signal_baselines::approval_pty_capability::plain_repl_sigterm_at_real_tty_approval_preserves_known_bill_and_denied_tool_group",
                ) {
                    return;
                }
                // No source/provider/terminal/dependency access before this real guard.
                require_private_system_fixture();
                let f = Fixture::new();
                let test_binary = std::env::current_exe().unwrap();
                let test_before = binary_fingerprint(&test_binary);
                let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap();
                let script = repository.join("scripts/fixtures/context_plain_approval_pty.py");
                let (script_before, script_bytes) = read_script(&script);
                assert_eq!(hex::encode(Sha256::digest(&script_bytes)), SCRIPT_SHA256);
                let event = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":CALL,"type":"function","function":{"name":"Bash","arguments":ARGUMENTS}}]},"finish_reason":"tool_calls"}],
                    "usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
                let response = Response {
                    body: format!("data: {event}\n\ndata: [DONE]\n\n"),
                    pause: false,
                    status: 200,
                    final_byte: None,
                };
                let mut wire = Wire::with_lifetimes(vec![response], false, None, 115, 120);
                f.configure(&wire);
                let provider_path = f.home.join("providers.toml");
                let mut config: orbit_cli::config::ProvidersConfig =
                    toml::from_str(&fs::read_to_string(&provider_path).unwrap()).unwrap();
                config.provider[0].models[0]
                    .context_limits
                    .as_mut()
                    .unwrap()
                    .input_tokens = Some(64_000);
                write_private(&provider_path, toml::to_string(&config).unwrap());
                let providers_before = signal_read_owned(&f, &provider_path, 128 * 1024);
                let mut fresh = SessionFile::from_chat(
                    SESSION,
                    RAW_A,
                    &wire.url,
                    "provider_a",
                    &[],
                    0,
                    0,
                    0,
                    0,
                )
                .with_selection_origin(SelectionOrigin::SavedExplicit);
                fresh.bind_workspace(&f.workspace).unwrap();
                let lease = SessionLease::acquire(&f.home, SESSION, "approval-pty-seed").unwrap();
                prepare_root(&lease, &mut fresh, RootOrigin::FreshCandidate).unwrap();
                assert_eq!(lease.load().unwrap().transcript, Vec::<ChatMessage>::new());
                drop(lease);
                let mut driver = Driver::start(&f, &script, &test_binary);
                let ready = driver.ready(&f);
                assert_eq!(ready["schema"], "orbit.context-plain-approval-pty/v1");
                assert_eq!(ready["boundary"], "actual_plain_approval_input_poll");
                assert_eq!(ready["binary_sha256"], hex::encode(&f.binary_before.digest));
                assert_eq!(
                    ready["test_binary_sha256"],
                    hex::encode(&test_before.digest)
                );
                assert!(ready["cli_pid"].as_u64().is_some_and(|pid| pid > 0));
                assert!(
                    matches!(SessionLease::acquire(&f.home, SESSION, "approval-pty-live-owner"), Err(SessionLeaseError::Busy { session_id }) if session_id == SESSION)
                );
                let inspection =
                    orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
                assert_known_completed_request(&inspection);
                let accounting_before_signal =
                    signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024);
                let records = orbit_ledger::verify_ledger(&f.home.join("ledger"))
                    .unwrap()
                    .0;
                let intents = records
                    .iter()
                    .filter_map(|read| match &read.record.event {
                        orbit_ledger::LedgerEvent::ToolIntent(value) => Some(value),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(intents.len(), 1);
                assert_eq!(intents[0].session_id, SESSION);
                assert_eq!(intents[0].call_id, CALL);
                assert_eq!(intents[0].tool_name, "Bash");
                assert_eq!(
                    intents[0].arguments_sha256,
                    hex::encode(Sha256::digest(ARGUMENTS.as_bytes()))
                );
                assert_eq!(intents[0].arguments_bytes, ARGUMENTS.len() as u64);
                let decision = intents[0].decision_id.clone();
                assert!(!records.iter().any(|read| matches!(
                    read.record.event,
                    orbit_ledger::LedgerEvent::ToolVerdict(_)
                        | orbit_ledger::LedgerEvent::ToolResult(_)
                        | orbit_ledger::LedgerEvent::AuthorityGrant(_)
                )));
                assert!(fs::read_dir(&f.workspace).unwrap().next().is_none());
                assert!(f.archives().is_empty());
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                assert_eq!(wire.requests.lock().unwrap().len(), 1);
                publish_signal(&driver.control, b"send-owned-sigterm\n");
                let receipt = driver.finish(&f);
                for field in [
                    "private_guard",
                    "pty_started",
                    "intent_written",
                    "actual_approval_prompt",
                    "actual_input_poll",
                    "actual_stdin_tty",
                    "no_tool_child_at_approval",
                    "sigterm_delivered_to_owned_unreaped_cli",
                    "process_reaped",
                    "pty_held_through_exit",
                    "terminal_flags_unchanged",
                    "no_tool_child_after_exit",
                    "owned_process_cleanup",
                    "terminal_fds_closed",
                    "binary_unchanged",
                    "test_binary_unchanged",
                ] {
                    assert_eq!(receipt[field], true, "approval PTY evidence: {field}");
                }
                assert_eq!(receipt["binary_sha256"], ready["binary_sha256"]);
                assert_eq!(receipt["test_binary_sha256"], ready["test_binary_sha256"]);
                assert_eq!(receipt["signal_count"], 1);
                assert_eq!(receipt["approval_answers_written"], 0);
                assert_eq!(receipt["input_bytes_written"], PROMPT.len() + 1);
                let output =
                    signal_read_owned(&f, &driver.control.join("pty.bin"), 2 * 1024 * 1024);
                assert_eq!(receipt["output_bytes"], output.len());
                assert_eq!(
                    receipt["output_sha256"],
                    hex::encode(Sha256::digest(&output))
                );
                assert!(
                    ready["output_bytes"]
                        .as_u64()
                        .is_some_and(|size| size > 0 && size <= output.len() as u64)
                );
                let prefix = &output[..ready["output_bytes"].as_u64().unwrap() as usize];
                assert_eq!(ready["output_sha256"], hex::encode(Sha256::digest(prefix)));
                let terminal = std::str::from_utf8(&output).unwrap();
                assert_eq!(terminal.matches("approval needed: Bash").count(), 1);
                assert!(terminal.contains("n deny: ") && terminal.contains("turn cancelled"));
                for unexpected in [
                    "process signal cleanup failed:",
                    "session not saved:",
                    "session accounting inspection failed",
                    "input failed:",
                    "approval input failed:",
                    "ORBIT-E0400:",
                    "ORBIT-E0401:",
                    "ORBIT-E1101:",
                ] {
                    assert!(
                        !terminal.contains(unexpected),
                        "unexpected runtime diagnostic: {unexpected}"
                    );
                }
                f.lease_released();
                let after =
                    orbit_cli::context_history::inspect_accounting(&f.home, SESSION, None).unwrap();
                assert_eq!(after, inspection);
                assert_known_completed_request(&after);
                assert_eq!(
                    signal_read_owned(&f, &signal_accounting_path(&f), 128 * 1024),
                    accounting_before_signal
                );
                let saved = f.saved();
                assert_eq!(
                    (
                        saved.turns,
                        saved.input_tokens,
                        saved.output_tokens,
                        saved.cost_microcents
                    ),
                    (0, 11, 7, 5)
                );
                assert_eq!(saved.session_id, SESSION);
                assert_eq!(saved.provider, "provider_a");
                assert_eq!(saved.model, RAW_A);
                assert_eq!(saved.gate, wire.url);
                assert_eq!(saved.selection_origin, Some(SelectionOrigin::SavedExplicit));
                let watermark = saved.accounting_watermark.as_ref().unwrap();
                assert_eq!(watermark.owner_session_id, SESSION);
                assert!(watermark.child_id.is_none());
                assert_eq!(watermark.revision, 2);
                assert_eq!(watermark.full_cost_status, FullCostStatus::Known);
                assert_eq!(
                    (
                        watermark.known_input_tokens,
                        watermark.known_output_tokens,
                        watermark.known_ordinary_microcents,
                        watermark.known_housekeeping_microcents
                    ),
                    (11, 7, 5, 0)
                );
                assert_eq!(saved.transcript.len(), 3);
                assert_eq!(saved.transcript[0], orbit_engine::user_message(PROMPT));
                let assistant = &saved.transcript[1];
                assert_eq!(assistant.role, orbit_adapter::types::ChatRole::Assistant);
                assert_eq!(
                    assistant.tool_calls.as_ref().unwrap(),
                    &[orbit_adapter::types::ToolCallMessage {
                        id: CALL.into(),
                        name: "Bash".into(),
                        arguments: ARGUMENTS.into()
                    }]
                );
                let result = &saved.transcript[2];
                assert_eq!(result.role, orbit_adapter::types::ChatRole::Tool);
                assert_eq!(result.tool_call_id.as_deref(), Some(CALL));
                assert_eq!(result.tool_result.as_deref(), Some(result.content.as_str()));
                assert!(orbit_tools::result_is_denial(&result.content));
                assert_eq!(
                    orbit_tools::denial_reason(&result.content).as_deref(),
                    Some("operator denied")
                );
                let records = orbit_ledger::verify_ledger(&f.home.join("ledger"))
                    .unwrap()
                    .0;
                let mut tool_kinds = Vec::new();
                let mut egress = Vec::new();
                for read in &records {
                    match &read.record.event {
                        orbit_ledger::LedgerEvent::EgressIntent(value) => {
                            assert_eq!(value.session_id, SESSION);
                            egress.push(value.decision_id.clone());
                        }
                        orbit_ledger::LedgerEvent::ToolIntent(value) => {
                            assert_eq!(value.decision_id, decision);
                            assert_eq!(value.call_id, CALL);
                            tool_kinds.push("intent");
                        }
                        orbit_ledger::LedgerEvent::ToolVerdict(value) => {
                            assert_eq!(value.session_id, SESSION);
                            assert_eq!(value.decision_id, decision);
                            assert_eq!(value.call_id, CALL);
                            assert_eq!(value.tool_name, "Bash");
                            assert!(!value.allowed);
                            assert_eq!(value.reason, "operator denied");
                            tool_kinds.push("verdict");
                        }
                        orbit_ledger::LedgerEvent::ToolResult(value) => {
                            assert_eq!(value.session_id, SESSION);
                            assert_eq!(value.decision_id, decision);
                            assert_eq!(value.call_id, CALL);
                            assert_eq!(value.tool_name, "Bash");
                            assert_eq!(value.status, "denied");
                            assert_eq!(
                                value.output_sha256,
                                hex::encode(Sha256::digest(result.content.as_bytes()))
                            );
                            assert_eq!(value.output_bytes, result.content.len() as u64);
                            tool_kinds.push("result");
                        }
                        orbit_ledger::LedgerEvent::AuthorityGrant(_) => {
                            panic!("signal supplied no approval grant")
                        }
                        _ => {}
                    }
                }
                assert_eq!(tool_kinds, ["intent", "verdict", "result"]);
                assert_eq!(
                    egress,
                    [after.last_receipt.as_ref().unwrap().request_id.clone()]
                );
                assert_eq!(
                    signal_read_owned(&f, &provider_path, 128 * 1024),
                    providers_before
                );
                assert!(
                    fs::read_dir(&f.workspace).unwrap().next().is_none(),
                    "denied Bash must not spawn or write a workspace/grant file"
                );
                assert!(f.archives().is_empty());
                wire.finish();
                assert_eq!(wire.connections.load(Ordering::SeqCst), 1);
                let requests = wire.requests.lock().unwrap();
                assert_eq!(
                    requests.len(),
                    1,
                    "no second provider request after completed-response approval cancellation"
                );
                assert_eq!(
                    requests[0].target,
                    "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
                );
                assert_eq!(requests[0].body["model"], RAW_A);
                assert_eq!(requests[0].body["max_tokens"], 73);
                assert!(
                    requests[0].body["tools"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|tool| tool["function"]["name"] == "Bash")
                );
                assert_eq!(
                    requests[0].body["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|message| message["role"] == "user" && message["content"] == PROMPT)
                        .count(),
                    1
                );
                assert_eq!(
                    requests[0]
                        .headers
                        .iter()
                        .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                        .collect::<Vec<_>>(),
                    [wire.authority.as_str()]
                );
                assert!(
                    !requests[0]
                        .headers
                        .iter()
                        .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
                );
                drop(requests);
                f.binary_unchanged();
                assert_eq!(binary_fingerprint(&test_binary), test_before);
                let (script_after, script_after_bytes) = read_script(&script);
                assert_eq!(script_after_bytes, script_bytes);
                assert_eq!(script_stamp(&script_after), script_stamp(&script_before));
                assert_eq!(
                    receipt["process_exit"], 143,
                    "real software SIGTERM, with the PTY held open, must terminate normally"
                );
                drop(driver);
                signal_remove_fixture(f);
            }
        }
    }

    mod refusal_policy_frontends {
        use super::*;
        use orbit_adapter::types::{ChatRole, ProviderUsage};
        use orbit_cli::context_history::{
            DetailedAccountingInspection, inspect_accounting_detailed,
        };
        use orbit_cli::tool_runtime::{
            self, ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants,
        };
        use orbit_engine::retry::{DetailedLastSettlement, adapter_identity_digest};
        use orbit_engine::{AccountingKnownness, AttemptPurpose, KnownPricedSubtotals};
        use orbit_hud_tui::msg::CostQualification;
        use orbit_hud_tui::worker::{ForegroundKind, ForegroundOperation};

        const PROMPT: &str = "observe the retained source";
        const ANSWER: &str = "the retained source is verified";
        const MODEL_B: &str = "model-b";

        fn isolated(name: &str) -> bool {
            dispatch_isolated(&format!(
                "frontend_manual_baselines::refusal_policy_frontends::{name}"
            ))
        }
        fn refusal(status: u16) -> Response {
            assert!(matches!(status, 500 | 503));
            Response {
                body: "{\"error\":{\"message\":\"declared final refusal\"}}".into(),
                pause: false,
                status,
                final_byte: None,
            }
        }
        fn paid(text: &str) -> Response {
            Response::text(
                text,
                "stop",
                Some(
                    json!({"prompt_tokens":14,"completion_tokens":7,"total_tokens":21,
                "prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":5}}),
                ),
            )
        }
        fn held_refusal() -> (Response, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (observed, notice) = mpsc::channel();
            let (release, receive) = mpsc::channel();
            let mut response = refusal(503);
            response.final_byte = Some((observed, receive));
            (response, notice, release)
        }
        fn barrier(wire: &Wire) -> usize {
            let (send, receive) = mpsc::channel();
            wire.barrier.send(send).unwrap();
            receive.recv_timeout(Duration::from_secs(3)).unwrap();
            wire.requests.lock().unwrap().len()
        }
        fn configure(f: &Fixture, wire: &Wire, input: u64, route: bool) {
            f.configure(wire);
            let path = f.home.join("providers.toml");
            let mut value: Value =
                serde_json::to_value(orbit_cli::config::ProvidersConfig::load(&f.home).unwrap())
                    .unwrap();
            value["provider"][0]["models"][0]["context_limits"]["input_tokens"] = json!(input);
            value["provider"][0]["models"][0]["pricing"]["request_flat_microdollars"] = json!(13);
            value["provider"][0]["models"][0]["billing"]["request_flat_microdollars"] = json!(13);
            value["provider"][0]["models"][1]["pricing"]["request_flat_microdollars"] = json!(17);
            value["provider"][0]["models"][1]["billing"]["request_flat_microdollars"] = json!(17);
            let mut second = value["provider"][0].clone();
            second["name"] = json!("provider_b");
            second["models"] = json!([value["provider"][0]["models"][0].clone()]);
            second["models"][0]["id"] = json!(MODEL_B);
            value["provider"].as_array_mut().unwrap().push(second);
            value["roles"]["explore"] = json!(format!("provider_a/{RAW_A}"));
            value["roles"]["subagent"] = json!(format!("provider_a/{RAW_A}"));
            if route {
                value["routing"] = json!({"phases":{"coding":{"default":format!("provider_b/{MODEL_B}")}},
                    "phase_keywords":{"clear":true,"coding":["implement"]}});
            }
            let parsed: orbit_cli::config::ProvidersConfig = serde_json::from_value(value).unwrap();
            write_private(&path, toml::to_string(&parsed).unwrap());
        }
        fn input_window(f: &Fixture, input: u64) {
            let path = f.home.join("providers.toml");
            let mut config = orbit_cli::config::ProvidersConfig::load(&f.home).unwrap();
            config.provider[0].models[0]
                .context_limits
                .as_mut()
                .unwrap()
                .input_tokens = Some(input);
            write_private(&path, toml::to_string(&config).unwrap());
        }
        fn policy(
            f: &Fixture,
            provider: &str,
            model: &str,
            name: &str,
        ) -> orbit_engine::retry::RetryPolicyBinding {
            let turn = orbit_cli::checked_model_turn(
                &f.home,
                &format!("{provider}/{model}"),
                None,
                None,
                false,
            )
            .unwrap();
            let body = toml::to_string(&json!({"version":1,"final_rejection":[{"id":name,"provider":provider,"model":model,
                "endpoint":turn.gate,"adapter_identity_sha256":adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
                "statuses":[500,503],"scope":"ordinary","generation":"final_rejection","billing":"unknown",
                "allow_uncapped_retry":true,"max_attempts":2}]})).unwrap();
            write_private(&f.home.join("provider-policies.toml"), body);
            orbit_cli::provider_policies::load_for_config(&f.home, &turn)
                .unwrap()
                .expect("selected policy not loaded")
        }
        fn fresh(f: &Fixture, wire: &Wire) -> (SessionLease, SessionFile) {
            let lease = SessionLease::acquire(&f.home, SESSION, "retry-fresh-bootstrap").unwrap();
            assert!(lease.load_optional().unwrap().is_none());
            let mut saved =
                SessionFile::from_chat(SESSION, RAW_A, &wire.url, "provider_a", &[], 0, 0, 0, 0)
                    .with_selection_origin(SelectionOrigin::Default);
            saved.bind_workspace(&f.workspace).unwrap();
            let accounting = prepare_root(&lease, &mut saved, RootOrigin::FreshCandidate).unwrap();
            assert_eq!(
                accounting
                    .namespace()
                    .checkpoint_detailed()
                    .unwrap()
                    .baseline(),
                AccountingBaseline::FreshKnownZero
            );
            assert_eq!(saved.accounting_watermark.as_ref().unwrap().revision, 0);
            drop(accounting);
            (lease, saved)
        }
        fn start_tui(f: &Fixture, lease: SessionLease, saved: &SessionFile) -> Tui {
            let (bus, sender) = Bus::new();
            let (commands, command_rx) = mpsc::channel();
            let cancel = orbit_cli::tui_worker::make_spawner_owned(f.turn(saved), lease)(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                commands.clone(),
            )
            .unwrap();
            assert!(matches!(
                SessionLease::acquire(&f.home, SESSION, "second-owner"),
                Err(SessionLeaseError::Busy { .. })
            ));
            Tui {
                bus,
                commands: Some(commands),
                cancel,
            }
        }
        fn start_serving(f: &Fixture, lease: SessionLease, saved: &SessionFile) -> Serving {
            let runtime =
                OwnerRuntime::start(OwnerConfig::new(f.turn(saved), f.workspace.clone()), lease)
                    .unwrap();
            let server = UnixServer::bind(&f.root.join("owner.sock"), runtime.handle()).unwrap();
            let stop = orbit_provider_http::CancelToken::new();
            let cloned = stop.clone();
            let thread = std::thread::spawn(move || server.run(&cloned));
            Serving {
                runtime: Some(runtime),
                stop,
                thread: Some(thread),
            }
        }
        fn begin(
            tui: &Tui,
            binding: &orbit_hud_tui::worker::SessionBinding,
            id: u64,
            text: &str,
        ) -> ForegroundOperation {
            let operation =
                ForegroundOperation::new(binding.clone(), ForegroundKind::Prompt, id).unwrap();
            tui.commands
                .as_ref()
                .unwrap()
                .send(WorkerCommand::Bound {
                    operation: operation.clone(),
                    command: Box::new(WorkerCommand::Prompt(text.into())),
                })
                .unwrap();
            operation
        }
        struct Terminal {
            projection: SessionProjection,
            finished: usize,
            retries: usize,
        }
        fn terminal(tui: &Tui, operation: &ForegroundOperation) -> Terminal {
            // A prompt owns one typed ordinary end plus one finish before
            // its projection; a control operation owns only the projection.
            let expect_ordinary = operation.kind() == ForegroundKind::Prompt;
            let end = Instant::now() + Duration::from_secs(10);
            let (mut finished, mut retries, mut ordinary_ends) = (0, 0, 0);
            loop {
                match tui.bus.try_recv() {
                    Some(Msg::OrdinaryTurnEnded {
                        operation: observed,
                        ..
                    }) => {
                        assert_eq!(&observed, operation);
                        assert_eq!(
                            (ordinary_ends, finished),
                            (0, 0),
                            "typed end must be unique and before finish"
                        );
                        ordinary_ends += 1;
                    }
                    Some(Msg::BackendNotice(_)) => {
                        panic!("unexpected notice during bound retry fixture")
                    }
                    Some(Msg::ResponseFinished { .. }) => {
                        assert_eq!(ordinary_ends, 1);
                        finished += 1;
                    }
                    Some(Msg::Status(text)) if text.starts_with("retry ") => retries += 1,
                    Some(Msg::SessionProjection(projection)) if matches!(&projection.reason, ProjectionReason::Operation { operation: observed } if observed == operation) =>
                    {
                        assert_eq!(projection.binding, *operation.source());
                        assert_eq!(
                            (ordinary_ends, finished),
                            if expect_ordinary { (1, 1) } else { (0, 0) }
                        );
                        return Terminal {
                            projection,
                            finished,
                            retries,
                        };
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
                assert!(
                    Instant::now() < end,
                    "exact bound operation did not terminate"
                );
            }
        }
        /// A re-sent consumed operation is refused at admission: the worker
        /// answers with the projection alone — no ordinary end, no finish,
        /// no new provider traffic.
        fn terminal_projection_only(tui: &Tui, operation: &ForegroundOperation) -> Terminal {
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                match tui.bus.try_recv() {
                    Some(Msg::OrdinaryTurnEnded { .. }) | Some(Msg::ResponseFinished { .. }) => {
                        panic!("a refused re-send produced ordinary traffic")
                    }
                    Some(Msg::SessionProjection(projection)) if matches!(&projection.reason, ProjectionReason::Operation { operation: observed } if observed == operation) =>
                    {
                        assert_eq!(projection.binding, *operation.source());
                        return Terminal {
                            projection,
                            finished: 0,
                            retries: 0,
                        };
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
                assert!(Instant::now() < end, "refused re-send did not terminate");
            }
        }
        fn close_single_operation(mut tui: Tui, f: &Fixture, operation: &ForegroundOperation) {
            tui.commands.take();
            f.lease_released();
            while let Some(event) = tui.bus.try_recv() {
                assert!(
                    !matches!(
                        &event,
                        Msg::SessionProjection(SessionProjection {
                            reason: ProjectionReason::Operation { operation: observed },
                            ..
                        }) if observed == operation
                    ),
                    "duplicate final projection for the exact bound operation"
                );
                assert!(
                    !matches!(
                        event,
                        Msg::BackendNotice(_)
                            | Msg::OrdinaryTurnEnded { .. }
                            | Msg::ResponseFinished { .. }
                            | Msg::PlanReady(_)
                            | Msg::ToolCallStarted { .. }
                            | Msg::SessionProjection(SessionProjection {
                                reason: ProjectionReason::Manual { .. },
                                ..
                            })
                    ),
                    "ordinary/tool event escaped after the exact bound operation"
                );
            }
        }
        fn wait_retry(tui: &Tui) {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                match tui.bus.try_recv() {
                    Some(Msg::Status(text)) if text.starts_with("retry ") => return,
                    Some(
                        Msg::OrdinaryTurnEnded { .. }
                        | Msg::ResponseFinished { .. }
                        | Msg::SessionProjection(SessionProjection {
                            reason: ProjectionReason::Operation { .. },
                            ..
                        }),
                    ) => panic!("operation ended before retry observation"),
                    Some(Msg::BackendNotice(_)) => {
                        panic!("unexpected notice while waiting for retry")
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
                assert!(Instant::now() < end, "actual retry event absent");
            }
        }
        fn view(f: &Fixture, child: Option<&str>) -> DetailedAccountingInspection {
            inspect_accounting_detailed(&f.home, SESSION, child).unwrap()
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
        fn qualified(
            f: &Fixture,
            child: Option<&str>,
            successes: u64,
        ) -> DetailedAccountingInspection {
            let observed = view(f, child);
            let checkpoint = &observed.checkpoint;
            assert_eq!(checkpoint.owner_session_id(), SESSION);
            assert_eq!(checkpoint.child_id(), child);
            assert_eq!(checkpoint.baseline(), AccountingBaseline::FreshKnownZero);
            assert!(checkpoint.pending().is_none());
            assert_eq!(checkpoint.refusals().unwrap().count(), 1);
            assert_eq!(
                checkpoint.totals().knownness,
                AccountingKnownness::UnknownUsage
            );
            assert_eq!(
                (
                    checkpoint.totals().ordinary.input_tokens,
                    checkpoint.totals().ordinary.output_tokens,
                    checkpoint.totals().ordinary.cost_microcents
                ),
                (11 * successes, 7 * successes, None)
            );
            assert_eq!(
                checkpoint.known_priced_subtotals(),
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 13 * successes,
                    housekeeping_microcents: 0
                })
            );
            assert_eq!(
                observed.last_legacy_receipt.as_ref().unwrap().usage,
                Some(usage())
            );
            let refusal = checkpoint.refusals().unwrap().latest();
            let Some(DetailedLastSettlement::Legacy(last)) = checkpoint.last_settlement() else {
                panic!("real success settlement absent")
            };
            assert_ne!(refusal.attempt().request_id, last.reference.request_id);
            assert_ne!(refusal.binding().decision_id(), last.reference.request_id);
            if child.is_none() {
                let saved = f.saved();
                assert_eq!(
                    (
                        saved.input_tokens,
                        saved.output_tokens,
                        saved.cost_microcents
                    ),
                    (11 * successes, 7 * successes, 13 * successes)
                );
                let watermark = saved.accounting_watermark.unwrap();
                assert_eq!(watermark.revision, checkpoint.revision().0);
                assert_eq!(watermark.full_cost_status, FullCostStatus::UnknownUsage);
            }
            observed
        }
        fn captures(wire: &Wire, models: &[&str]) {
            assert_eq!(barrier(wire), models.len());
            let requests = wire.requests.lock().unwrap();
            for (request, model) in requests.iter().zip(models) {
                assert_eq!(
                    request.target,
                    "POST /tenant/v1/chat/completions?scope=compaction HTTP/1.1"
                );
                assert_eq!(request.body["model"], *model);
                assert_eq!(request.body["max_tokens"], 73);
                assert_eq!(
                    request
                        .headers
                        .iter()
                        .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                        .collect::<Vec<_>>(),
                    [wire.authority.as_str()]
                );
                assert!(
                    !request
                        .headers
                        .iter()
                        .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
                );
            }
        }
        fn original_once(f: &Fixture, text: &str, answer: &str) {
            let saved = f.saved();
            assert_eq!(
                saved
                    .transcript
                    .iter()
                    .filter(|message| message.role == ChatRole::User && message.content == text)
                    .count(),
                1
            );
            assert_eq!(
                saved
                    .transcript
                    .iter()
                    .filter(
                        |message| message.role == ChatRole::Assistant && message.content == answer
                    )
                    .count(),
                1
            );
        }
        fn owner_done(
            handle: &orbit_cli::daemon::OwnerHandle,
            id: &str,
        ) -> orbit_cli::daemon::OwnerSnapshot {
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                let snapshot = handle.snapshot().unwrap();
                if snapshot.current_request.as_deref() == Some(id)
                    && matches!(snapshot.state, TurnState::Idle | TurnState::Interrupted)
                    && snapshot.requests.get(id).is_some_and(|record| {
                        !matches!(
                            record.state,
                            orbit_cli::daemon::RequestState::Accepted
                                | orbit_cli::daemon::RequestState::Running
                        )
                    })
                {
                    return snapshot;
                }
                assert!(
                    Instant::now() < end,
                    "owner operation deadline: id={id:?}, current={:?}, owner={:?}, request={:?}",
                    snapshot.current_request,
                    snapshot.state,
                    snapshot.requests.get(id).map(|record| record.state)
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn actual_decisions(f: &Fixture, session: &str) -> Vec<String> {
            orbit_ledger::verify_ledger(&f.home.join("ledger"))
                .unwrap()
                .0
                .into_iter()
                .filter_map(|entry| match entry.record.event {
                    orbit_ledger::LedgerEvent::EgressIntent(event)
                        if event.session_id == session =>
                    {
                        Some(event.decision_id)
                    }
                    _ => None,
                })
                .collect()
        }
        fn unique_decisions(f: &Fixture, session: &str, count: usize) {
            let ids = actual_decisions(f, session);
            assert_eq!(ids.len(), count);
            let unique: std::collections::BTreeSet<_> = ids.iter().collect();
            assert_eq!(unique.len(), count);
        }
        fn manual_archive(
            f: &Fixture,
            original: &[ChatMessage],
            prior: &DetailedAccountingInspection,
        ) {
            let observed = view(f, None);
            let checkpoint = &observed.checkpoint;
            assert!(checkpoint.pending().is_none());
            assert_eq!(checkpoint.baseline(), AccountingBaseline::UnknownLegacy);
            assert_eq!(checkpoint.refusals(), prior.checkpoint.refusals());
            assert_eq!(
                checkpoint.known_priced_subtotals(),
                Some(KnownPricedSubtotals {
                    ordinary_microcents: 13,
                    housekeeping_microcents: 17
                })
            );
            assert_eq!(checkpoint.totals().housekeeping.cost_microcents, None);
            assert_eq!(
                checkpoint.totals().knownness,
                AccountingKnownness::UnknownLegacy
            );
            let receipt = observed.last_legacy_receipt.as_ref().unwrap();
            assert_ne!(receipt.purpose, AttemptPurpose::Ordinary);
            assert_eq!(receipt.usage, Some(usage()));
            assert!(receipt.completed);
            assert_eq!(receipt.totals.cost_microcents, Some(17));
            let archives = f.archives();
            assert_eq!(archives.len(), 1);
            let record = archives[0].file_stem().unwrap().to_str().unwrap();
            assert_eq!(
                load_compaction_source(&f.home, SESSION, None, record).unwrap(),
                original
            );
            let saved = f.saved();
            assert_ne!(saved.transcript, original);
            assert_eq!(saved.turns, 8);
            assert!(saved.transcript.ends_with(&original[original.len() - 4..]));
            original_once(f, PROMPT, ANSWER);
            assert_eq!(
                (
                    saved.input_tokens,
                    saved.output_tokens,
                    saved.cost_microcents
                ),
                (122, 54, 90)
            );
            let anchor = saved.accounting_watermark.unwrap();
            assert_eq!(anchor.full_cost_status, FullCostStatus::UnknownLegacy);
            assert_eq!(anchor.revision, checkpoint.revision().0);
            assert!(matches!(
                checkpoint.last_settlement(),
                Some(DetailedLastSettlement::Legacy(_))
            ));
            unique_decisions(f, SESSION, 3);
        }
        struct Approve;
        impl ApprovalChannel for Approve {
            fn ask(&mut self, _: &ApprovalRequest, _: bool) -> ApprovalVerdict {
                ApprovalVerdict::AllowOnce
            }
        }
        fn task(f: &Fixture, cx: &orbit_tools::ToolContext, args: Value) -> Value {
            let call = orbit_cli::PendingToolCall {
                index: 0,
                id: ulid::Ulid::new().to_string(),
                name: "Task".into(),
                arguments: serde_json::to_vec(&args).unwrap(),
            };
            let (output, _) = tool_runtime::execute_call(
                &f.home,
                SESSION,
                "parent-decision",
                &call,
                true,
                false,
                &mut Approve,
                &mut AutoGrants::new(),
                &PermissionScope::default(),
                cx,
            )
            .unwrap();
            serde_json::from_str(&output).unwrap()
        }
        fn task_context(f: &Fixture) -> orbit_tools::ToolContext {
            let cx =
                orbit_tools::ToolContext::new(f.home.clone(), SESSION.into(), f.workspace.clone());
            let parent = orbit_cli::checked_model_turn(
                &f.home,
                &format!("provider_a/{RAW_A}"),
                None,
                None,
                false,
            )
            .unwrap();
            tool_runtime::remember_turn_config(&cx, &parent);
            cx
        }
        fn child_id(result: &Value) -> &str {
            let id = match result["ok"].as_bool() {
                Some(true) => result["result"]["agent_id"].as_str(),
                Some(false) => result["agent_id"].as_str(),
                None => panic!("Task result lacks a boolean status"),
            };
            id.expect("Task result lost its actual agent identity")
        }

        #[test]
        fn managed_tui_policy_retry_preserves_ticket_and_known_subtotal_qualification() {
            if !isolated(
                "managed_tui_policy_retry_preserves_ticket_and_known_subtotal_qualification",
            ) {
                return;
            }
            for status in [500, 503] {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let mut wire = Wire::new(vec![refusal(status), paid(ANSWER)]);
                configure(&f, &wire, 128_000, false);
                let selected_policy = policy(&f, "provider_a", RAW_A, "tui-selected");
                let (lease, saved) = fresh(&f, &wire);
                let tui = start_tui(&f, lease, &saved);
                let initial = tui.initial();
                assert_eq!(initial.cost, CostQualification::Known { revision: 0 });
                let operation = begin(&tui, &initial.binding, 1, PROMPT);
                let ended = terminal(&tui, &operation);
                assert_eq!((ended.finished, ended.retries), (1, 1));
                assert_eq!(ended.projection.turns, 1);
                let observed = qualified(&f, None, 1);
                let binding = observed.checkpoint.refusals().unwrap().latest().binding();
                assert_eq!(binding.provider_digest(), selected_policy.provider_digest());
                assert_eq!(binding.model_digest(), selected_policy.model_digest());
                assert_eq!(binding.policy_digest(), selected_policy.policy_digest());
                unique_decisions(&f, SESSION, 2);
                assert_eq!(
                    ended.projection.cost,
                    CostQualification::UnknownUsage {
                        revision: observed.checkpoint.revision().0
                    }
                );
                assert_eq!(ended.projection.cost_microcents, 13);
                assert!(
                    operation
                        .start(&WorkerCommand::Prompt(PROMPT.into()))
                        .is_err()
                );
                assert!(operation.finish_unstarted().is_err());
                original_once(&f, PROMPT, ANSWER);
                captures(&wire, &[RAW_A, RAW_A]);
                close_single_operation(tui, &f, &operation);
                wire.finish();
                f.binary_unchanged();
            }
        }

        #[test]
        fn managed_tui_policy_switch_and_cancel_do_not_reuse_operation_authority() {
            if !isolated("managed_tui_policy_switch_and_cancel_do_not_reuse_operation_authority") {
                return;
            }
            // A held complete refusal freezes the first binding; a new prompt reloads None.
            {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let (held, notice, release) = held_refusal();
                let mut wire = Wire::new(vec![held, paid(ANSWER), paid("new explicit input")]);
                configure(&f, &wire, 128_000, true);
                policy(&f, "provider_b", MODEL_B, "tui-route");
                let (lease, saved) = fresh(&f, &wire);
                let tui = start_tui(&f, lease, &saved);
                let initial = tui.initial();
                let closed =
                    ManualOperation::new(initial.binding.clone(), ManualAction::Compact, 91)
                        .unwrap();
                assert!(closed.cancel().unwrap());
                tui.commands
                    .as_ref()
                    .unwrap()
                    .send(WorkerCommand::Compact(closed.clone()))
                    .unwrap();
                assert_terminal_only(&tui, &closed);
                assert!(!closed.cancel().unwrap());
                let first = begin(&tui, &initial.binding, 1, "implement first route");
                notice.recv_timeout(Duration::from_secs(3)).unwrap();
                fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
                release.send(()).unwrap();
                let ended = terminal(&tui, &first);
                assert_eq!((ended.finished, ended.retries), (1, 1));
                assert!(!closed.cancel().unwrap());
                assert!(first.finish_unstarted().is_err());
                tui.commands
                    .as_ref()
                    .unwrap()
                    .send(WorkerCommand::Bound {
                        operation: first.clone(),
                        command: Box::new(WorkerCommand::Prompt("must never resubmit".into())),
                    })
                    .unwrap();
                let stale = terminal_projection_only(&tui, &first);
                assert_eq!((stale.finished, stale.retries), (0, 0));
                assert_eq!(barrier(&wire), 2);
                let second = begin(&tui, &initial.binding, 2, "implement new explicit input");
                assert!(!closed.cancel().unwrap());
                let ended = terminal(&tui, &second);
                assert_eq!((ended.finished, ended.retries), (1, 0));
                let inspected = qualified(&f, None, 2);
                assert_eq!(
                    inspected
                        .checkpoint
                        .refusals()
                        .unwrap()
                        .latest()
                        .binding()
                        .adapter_identity_sha256(),
                    adapter_identity_digest(&orbit_provider_http::openai::openai_identity())
                );
                captures(&wire, &[MODEL_B, MODEL_B, MODEL_B]);
                tui.close(&f);
                wire.finish();
                f.binary_unchanged();
            }
            // Cancel only after the real refusal settlement and Retrying event.
            {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let mut wire = Wire::new(vec![refusal(503)]);
                configure(&f, &wire, 128_000, false);
                policy(&f, "provider_a", RAW_A, "cancel");
                let (lease, saved) = fresh(&f, &wire);
                let tui = start_tui(&f, lease, &saved);
                let initial = tui.initial();
                let operation = begin(&tui, &initial.binding, 1, PROMPT);
                wait_retry(&tui);
                let settled = view(&f, None);
                assert!(settled.checkpoint.pending().is_none());
                assert_eq!(settled.checkpoint.refusals().unwrap().count(), 1);
                assert!(matches!(
                    settled.checkpoint.last_settlement(),
                    Some(DetailedLastSettlement::FinalRefusal(_))
                ));
                (tui.cancel)();
                let ended = terminal(&tui, &operation);
                assert_eq!(ended.finished, 1);
                assert_eq!(
                    ended.projection.cost,
                    CostQualification::UnknownUsage {
                        revision: settled.checkpoint.revision().0
                    }
                );
                assert_eq!(view(&f, None).checkpoint, settled.checkpoint);
                unique_decisions(&f, SESSION, 1);
                captures(&wire, &[RAW_A]);
                tui.close(&f);
                wire.finish();
                f.binary_unchanged();
            }
            // Explicit model choice suppresses the phase, and malformed policy stops before send.
            {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let mut wire = Wire::new(vec![refusal(503), paid(ANSWER)]);
                configure(&f, &wire, 128_000, true);
                policy(&f, "provider_a", RAW_A, "explicit");
                let (lease, saved) = fresh(&f, &wire);
                let tui = start_tui(&f, lease, &saved);
                let initial = tui.initial();
                let select =
                    ForegroundOperation::new(initial.binding.clone(), ForegroundKind::Control, 1)
                        .unwrap();
                tui.commands
                    .as_ref()
                    .unwrap()
                    .send(WorkerCommand::Bound {
                        operation: select.clone(),
                        command: Box::new(WorkerCommand::SetModel(format!("provider_a/{RAW_A}"))),
                    })
                    .unwrap();
                terminal(&tui, &select);
                let operation = begin(&tui, &initial.binding, 2, "implement selected route");
                terminal(&tui, &operation);
                qualified(&f, None, 1);
                let checkpoint = view(&f, None).checkpoint;
                write_private(&f.home.join("provider-policies.toml"), "not valid policy");
                let malformed = fs::read(f.home.join("provider-policies.toml")).unwrap();
                let operation = begin(&tui, &initial.binding, 3, "implement retained error intent");
                terminal(&tui, &operation);
                assert_eq!(view(&f, None).checkpoint, checkpoint);
                assert_eq!(
                    fs::read(f.home.join("provider-policies.toml")).unwrap(),
                    malformed
                );
                captures(&wire, &[RAW_A, RAW_A]);
                assert_eq!(
                    f.saved()
                        .transcript
                        .iter()
                        .filter(|m| m.role == ChatRole::User
                            && m.content == "implement retained error intent")
                        .count(),
                    1
                );
                policy(&f, "provider_a", RAW_A, "unsafe-storage");
                fs::set_permissions(
                    f.home.join("provider-policies.toml"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
                let operation = begin(&tui, &initial.binding, 4, "unsafe policy retained intent");
                terminal(&tui, &operation);
                assert_eq!(view(&f, None).checkpoint, checkpoint);
                assert_eq!(barrier(&wire), 2);
                assert_eq!(
                    fs::metadata(f.home.join("provider-policies.toml"))
                        .unwrap()
                        .mode()
                        & 0o777,
                    0o644
                );
                tui.close(&f);
                wire.finish();
                f.binary_unchanged();
            }
        }

        #[test]
        fn unmanaged_tui_facade_refuses_matching_policy_before_executor_or_provider_effects() {
            if !isolated(
                "unmanaged_tui_facade_refuses_matching_policy_before_executor_or_provider_effects",
            ) {
                return;
            }
            let f = Fixture::new();
            let _cwd = Cwd::enter(&f.workspace);
            let mut wire = Wire::new(vec![paid(ANSWER)]);
            configure(&f, &wire, 128_000, false);
            policy(&f, "provider_a", RAW_A, "unmanaged");
            let marker = f.root.join("prompt-hook");
            let command = format!("printf called > '{}'", marker.display());
            write_private(&f.home.join("settings.toml"),toml::to_string(&json!({"hooks":[{"event":"UserPromptSubmit","command":command,"timeout_secs":2}]})).unwrap());
            let saved =
                SessionFile::from_chat(SESSION, RAW_A, &wire.url, "provider_a", &[], 0, 0, 0, 0);
            let config = f.turn(&saved);
            let (bus, sender) = Bus::new();
            let mut transcript = Vec::new();
            let mut grants = AutoGrants::new();
            grants.grant("Read");
            grants.grant_rule("Bash", "cargo test *");
            let mut scope =
                PermissionScope::from_flags(Some("acceptEdits"), Some("Read,Bash"), Some("Write"));
            let before_scope = format!("{scope:?}");
            let cx =
                orbit_tools::ToolContext::new(f.home.clone(), SESSION.into(), f.workspace.clone());
            let invoke = |transcript: &mut Vec<ChatMessage>,
                          grants: &mut AutoGrants,
                          scope: &mut PermissionScope| {
                orbit_cli::tui_worker::run_tui_turn(
                    &config,
                    transcript,
                    PROMPT,
                    None,
                    &sender,
                    &ApprovalRegistry::new(),
                    &orbit_provider_http::CancelToken::new(),
                    0,
                    grants,
                    "",
                    false,
                    scope,
                    &cx,
                )
            };
            assert_eq!(
                invoke(&mut transcript, &mut grants, &mut scope).unwrap_err(),
                "final-rejection retry requires managed session accounting"
            );
            assert!(transcript.is_empty());
            assert!(!marker.exists());
            assert!(
                !f.home
                    .join("sessions")
                    .join(format!("{SESSION}.json"))
                    .exists()
            );
            assert!(grants.is_granted("Read"));
            assert!(grants.rule_granted("Bash", "cargo test crate"));
            assert_eq!(format!("{scope:?}"), before_scope);
            assert_eq!(barrier(&wire), 0);
            write_private(&f.home.join("provider-policies.toml"), "malformed policy");
            assert_eq!(
                invoke(&mut transcript, &mut grants, &mut scope).unwrap_err(),
                "provider policy document is invalid"
            );
            assert!(transcript.is_empty());
            assert!(!marker.exists());
            assert_eq!(barrier(&wire), 0);
            fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
            let valid_providers = fs::read(f.home.join("providers.toml")).unwrap();
            input_window(&f, 0);
            assert!(invoke(&mut transcript, &mut grants, &mut scope).is_err());
            assert!(transcript.is_empty());
            assert!(!marker.exists());
            assert_eq!(barrier(&wire), 0);
            assert!(grants.is_granted("Read"));
            assert!(grants.rule_granted("Bash", "cargo test crate"));
            assert_eq!(format!("{scope:?}"), before_scope);
            assert!(
                !f.home
                    .join("sessions/.leases")
                    .join(format!("{SESSION}.lock"))
                    .exists()
            );
            write_private(&f.home.join("providers.toml"), &valid_providers);
            assert_eq!(
                fs::read(f.home.join("providers.toml")).unwrap(),
                valid_providers
            );
            assert!(invoke(&mut transcript, &mut grants, &mut scope).unwrap().0);
            assert!(marker.is_file());
            assert_eq!(
                transcript
                    .iter()
                    .filter(|m| m.role == ChatRole::User && m.content == PROMPT)
                    .count(),
                1
            );
            while bus.try_recv().is_some() {}
            captures(&wire, &[RAW_A]);
            wire.finish();
            f.binary_unchanged();
        }

        #[test]
        fn manual_summary_after_real_refusal_keeps_one_summary_attempt_and_archive() {
            if !isolated("manual_summary_after_real_refusal_keeps_one_summary_attempt_and_archive")
            {
                return;
            }
            for owner in [false, true] {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let mut wire = Wire::new(vec![refusal(503), paid(ANSWER), paid(SUMMARY)]);
                configure(&f, &wire, 128_000, false);
                let (_history, _legacy) = f.seed(&wire);
                policy(&f, "provider_a", RAW_A, "ordinary-only");
                if owner {
                    let serving = Serving::start(&f);
                    let handle = serving.runtime.as_ref().unwrap().handle();
                    let mut controller = handle.claim_controller().unwrap();
                    controller
                        .send(orbit_cli::daemon::OwnerAction::Prompt {
                            request_id: "manual-prefix".into(),
                            text: PROMPT.into(),
                        })
                        .unwrap();
                    let ended = owner_done(&handle, "manual-prefix");
                    assert_eq!(
                        ended.requests["manual-prefix"].state,
                        orbit_cli::daemon::RequestState::Completed
                    );
                    let original = f.saved().transcript;
                    let prior = view(&f, None);
                    assert_eq!(prior.checkpoint.refusals().unwrap().count(), 1);
                    assert_eq!(
                        prior
                            .checkpoint
                            .known_priced_subtotals()
                            .unwrap()
                            .ordinary_microcents,
                        13
                    );
                    input_window(&f, 10_000);
                    write_private(
                        &f.home.join("provider-policies.toml"),
                        "invalid ordinary policy must not affect summary",
                    );
                    drop(controller);
                    let mut client = orbit_cli::attach::AttachClient::connect(
                        &f.root.join("owner.sock"),
                        true,
                        None,
                    )
                    .unwrap();
                    let ack = client
                        .send(orbit_cli::daemon::OwnerAction::Compact {
                            request_id: "one-summary".into(),
                        })
                        .unwrap();
                    assert!(!ack.duplicate);
                    let ended = owner_done(&handle, "one-summary");
                    assert_eq!(
                        ended.requests["one-summary"].state,
                        orbit_cli::daemon::RequestState::Completed
                    );
                    assert_eq!(ended.turns, 8);
                    assert_eq!(
                        ended.accounting.unwrap().full_cost_status,
                        FullCostStatus::UnknownLegacy
                    );
                    manual_archive(&f, &original, &prior);
                    drop(client);
                    serving.close();
                } else {
                    let tui = Tui::start(&f);
                    let initial = tui.initial();
                    let operation = begin(&tui, &initial.binding, 1, PROMPT);
                    let ended = terminal(&tui, &operation);
                    assert_eq!((ended.finished, ended.retries), (1, 1));
                    let original = f.saved().transcript;
                    let prior = view(&f, None);
                    assert_eq!(prior.checkpoint.refusals().unwrap().count(), 1);
                    input_window(&f, 10_000);
                    fs::remove_file(f.home.join("provider-policies.toml")).unwrap();
                    let manual =
                        ManualOperation::new(initial.binding, ManualAction::Compact, 2).unwrap();
                    tui.commands
                        .as_ref()
                        .unwrap()
                        .send(WorkerCommand::Compact(manual.clone()))
                        .unwrap();
                    let ended = assert_terminal_only(&tui, &manual);
                    assert!(matches!(
                        ended.reason,
                        ProjectionReason::Manual {
                            outcome: ManualOutcome::Completed,
                            applied: true,
                            ..
                        }
                    ));
                    assert_eq!(ended.cost_microcents, 90);
                    assert!(matches!(
                        ended.cost,
                        CostQualification::UnknownHistory { .. }
                    ));
                    assert!(!manual.cancel().unwrap());
                    manual_archive(&f, &original, &prior);
                    tui.close(&f);
                }
                captures(&wire, &[RAW_A, RAW_A, "summary-model"]);
                wire.finish();
                f.binary_unchanged();
            }
            // An admitted incomplete summary cannot borrow the ordinary retry policy.
            {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let partial = Response {
                    body: format!(
                        "data: {}\n\n",
                        json!({"choices":[{"index":0,"delta":{"content":"partial summary"}}]})
                    ),
                    pause: true,
                    status: 200,
                    final_byte: None,
                };
                let mut wire = Wire::new(vec![refusal(503), paid(ANSWER), partial]);
                configure(&f, &wire, 128_000, false);
                f.seed(&wire);
                policy(&f, "provider_a", RAW_A, "summary-negative");
                let tui = Tui::start(&f);
                let initial = tui.initial();
                let operation = begin(&tui, &initial.binding, 1, PROMPT);
                terminal(&tui, &operation);
                let original = f.saved().transcript;
                let prior = view(&f, None);
                input_window(&f, 10_000);
                let manual =
                    ManualOperation::new(initial.binding, ManualAction::Compact, 2).unwrap();
                tui.commands
                    .as_ref()
                    .unwrap()
                    .send(WorkerCommand::Compact(manual.clone()))
                    .unwrap();
                let end = Instant::now() + Duration::from_secs(3);
                while wire.requests.lock().unwrap().len() < 3 {
                    assert!(Instant::now() < end);
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert!(manual.cancel().unwrap());
                let ended = assert_terminal_only(&tui, &manual);
                assert!(matches!(
                    ended.reason,
                    ProjectionReason::Manual { applied: false, .. }
                ));
                assert_eq!(f.saved().transcript, original);
                assert!(f.archives().is_empty());
                let after = view(&f, None);
                assert_eq!(after.checkpoint.refusals(), prior.checkpoint.refusals());
                assert!(
                    after.checkpoint.pending().is_some()
                        || after.checkpoint.totals().knownness == AccountingKnownness::Uncertain
                );
                tui.close(&f);
                wire.finish();
                let captured = wire.requests.lock().unwrap();
                assert_eq!(captured.len(), 3);
                assert_eq!(
                    captured
                        .iter()
                        .map(|call| call.body["model"].as_str().unwrap())
                        .collect::<Vec<_>>(),
                    [RAW_A, RAW_A, "summary-model"]
                );
                drop(captured);
                assert_eq!(f.saved().turns, 8);
                f.binary_unchanged();
            }
        }

        #[test]
        fn task_uses_child_final_route_policy_and_keeps_parent_accounting_separate() {
            if !isolated("task_uses_child_final_route_policy_and_keeps_parent_accounting_separate")
            {
                return;
            }
            for matching_child in [false, true] {
                let f = Fixture::new();
                let _cwd = Cwd::enter(&f.workspace);
                let replies = if matching_child {
                    vec![refusal(503), paid(ANSWER)]
                } else {
                    vec![refusal(503)]
                };
                let mut wire = Wire::new(replies);
                configure(&f, &wire, 128_000, true);
                if matching_child {
                    policy(&f, "provider_b", MODEL_B, "own-child");
                } else {
                    policy(&f, "provider_a", RAW_A, "parent-only");
                }
                let (parent, _saved) = fresh(&f, &wire);
                let parent_before = view(&f, None).checkpoint;
                let cx = task_context(&f);
                let result = task(
                    &f,
                    &cx,
                    json!({"agent":"Explore","prompt":"implement child route"}),
                );
                let id = child_id(&result);
                let store = orbit_engine::agent_store::AgentStore::new(&f.home, SESSION).unwrap();
                let child = store.load(id).unwrap();
                assert_eq!(child.owner_session_id, SESSION);
                assert_eq!(child.model, format!("provider_b/{MODEL_B}"));
                assert_eq!(child.agent_type, "Explore");
                assert_eq!(child.turns, 1);
                assert_eq!(
                    child
                        .transcript
                        .iter()
                        .filter(|m| m.role == ChatRole::User
                            && m.content.contains("implement child route"))
                        .count(),
                    1
                );
                let checkpoint = view(&f, Some(id));
                assert_eq!(checkpoint.checkpoint.child_id(), Some(id));
                assert_eq!(view(&f, None).checkpoint, parent_before);
                assert!(matches!(
                    SessionLease::acquire(&f.home, SESSION, "parent-stays-owned"),
                    Err(SessionLeaseError::Busy { .. })
                ));
                if matching_child {
                    assert_eq!(result["ok"], true, "{result}");
                    assert_eq!(
                        child.status,
                        orbit_engine::agent_store::AgentStatus::Completed
                    );
                    qualified(&f, Some(id), 1);
                    unique_decisions(&f, id, 2);
                    captures(&wire, &[MODEL_B, MODEL_B]);
                } else {
                    assert_eq!(result["ok"], false, "{result}");
                    assert_eq!(
                        child.status,
                        orbit_engine::agent_store::AgentStatus::Interrupted
                    );
                    assert!(checkpoint.checkpoint.refusals().is_none());
                    assert!(
                        checkpoint.checkpoint.pending().is_some()
                            || checkpoint.checkpoint.totals().knownness
                                == AccountingKnownness::Uncertain
                    );
                    unique_decisions(&f, id, 1);
                    captures(&wire, &[MODEL_B]);
                }
                drop(parent);
                wire.finish();
                f.binary_unchanged();
            }
        }

        #[test]
        fn resumed_task_reloads_own_policy_without_replaying_old_intent() {
            if !isolated("resumed_task_reloads_own_policy_without_replaying_old_intent") {
                return;
            }
            let f = Fixture::new();
            let _cwd = Cwd::enter(&f.workspace);
            let mut wire = Wire::new(vec![refusal(500), paid(ANSWER), paid("new resume answer")]);
            configure(&f, &wire, 128_000, true);
            policy(&f, "provider_b", MODEL_B, "resume-child");
            let (parent, _saved) = fresh(&f, &wire);
            let parent_before = view(&f, None).checkpoint;
            let cx = task_context(&f);
            let first = task(
                &f,
                &cx,
                json!({"agent":"Explore","prompt":"implement original child"}),
            );
            assert_eq!(first["ok"], true, "{first}");
            let id = child_id(&first).to_owned();
            let before = qualified(&f, Some(&id), 1);
            let decisions_before = actual_decisions(&f, &id);
            assert_eq!(decisions_before.len(), 2);
            // A parent/sibling declaration remains present but is no authority for this child.
            policy(&f, "provider_a", RAW_A, "parent-unmatched");
            let path = f.home.join("providers.toml");
            let mut settings: Value =
                serde_json::to_value(orbit_cli::config::ProvidersConfig::load(&f.home).unwrap())
                    .unwrap();
            settings["routing"]["phases"]["coding"]["default"] =
                json!(format!("provider_a/{RAW_A}"));
            let parsed: orbit_cli::config::ProvidersConfig =
                serde_json::from_value(settings).unwrap();
            write_private(&path, toml::to_string(&parsed).unwrap());
            let store = orbit_engine::agent_store::AgentStore::new(&f.home, SESSION).unwrap();
            store
                .enqueue(&id, "explicitly queued context for the next resume", None)
                .unwrap();
            assert_eq!(barrier(&wire), 2);
            assert_eq!(store.load(&id).unwrap().turns, 1);
            let result = task(
                &f,
                &cx,
                json!({"agent":"Explore","resume":id,"prompt":"new explicit resume input"}),
            );
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(child_id(&result), id);
            let child = store.load(&id).unwrap();
            assert_eq!(
                child.status,
                orbit_engine::agent_store::AgentStatus::Completed
            );
            assert_eq!(child.turns, 2);
            assert_eq!(child.model, format!("provider_b/{MODEL_B}"));
            assert!(child.inbox.is_empty());
            assert_eq!(
                child
                    .transcript
                    .iter()
                    .filter(|m| m.role == ChatRole::User
                        && m.content.contains("implement original child"))
                    .count(),
                1
            );
            assert_eq!(
                child
                    .transcript
                    .iter()
                    .filter(|m| m.role == ChatRole::User
                        && m.content.contains("new explicit resume input"))
                    .count(),
                1
            );
            assert!(child.transcript.iter().any(|m| {
                m.content
                    .contains("explicitly queued context for the next resume")
            }));
            let after = qualified(&f, Some(&id), 2);
            assert_eq!(after.checkpoint.refusals(), before.checkpoint.refusals());
            assert_eq!(view(&f, None).checkpoint, parent_before);
            let ids = actual_decisions(&f, &id);
            assert_eq!(&ids[..2], decisions_before.as_slice());
            unique_decisions(&f, &id, 3);
            captures(&wire, &[MODEL_B, MODEL_B, MODEL_B]);
            drop(parent);
            wire.finish();
            f.binary_unchanged();
        }

        #[test]
        fn qualified_frontend_snapshots_preserve_unknown_cost_and_cold_context() {
            if !isolated("qualified_frontend_snapshots_preserve_unknown_cost_and_cold_context") {
                return;
            }
            let f = Fixture::new();
            let _cwd = Cwd::enter(&f.workspace);
            let mut wire = Wire::new(vec![refusal(503), paid(ANSWER)]);
            configure(&f, &wire, 128_000, false);
            policy(&f, "provider_a", RAW_A, "cold-view");
            let (lease, saved) = fresh(&f, &wire);
            let tui = start_tui(&f, lease, &saved);
            let initial = tui.initial();
            let operation = begin(&tui, &initial.binding, 1, PROMPT);
            let final_view = terminal(&tui, &operation).projection;
            let observed = qualified(&f, None, 1);
            unique_decisions(&f, SESSION, 2);
            tui.close(&f);
            let tui = Tui::start(&f);
            let cold = tui.initial();
            assert_eq!(cold.cost, final_view.cost);
            assert_eq!(cold.cost_microcents, 13);
            assert_eq!(cold.cost.revision(), Some(observed.checkpoint.revision().0));
            assert_eq!(cold.context, ContextProjection::Unavailable);
            assert_eq!(cold.turns, 1);
            let path = f
                .home
                .join("context-history")
                .join(SESSION)
                .join("accounting.json");
            let original_bytes = fs::read(&path).unwrap();
            let original_text = String::from_utf8(original_bytes.clone()).unwrap();
            let control_command = || {
                let command = WorkerCommand::Effort(String::new());
                assert_eq!(command.foreground_kind(), Some(ForegroundKind::Control));
                command
            };
            for (index, kind) in ["missing", "wrong-owner", "revision-conflict"]
                .into_iter()
                .enumerate()
            {
                let retained = f.root.join(format!("retained-accounting-{index}"));
                if kind == "missing" {
                    fs::rename(&path, &retained).unwrap();
                } else {
                    let corrupted = if kind == "wrong-owner" {
                        let from = format!("\"owner\":\"{SESSION}\"");
                        assert_eq!(original_text.matches(&from).count(), 1);
                        original_text.replacen(&from, "\"owner\":\"wrong-owner\"", 1)
                    } else {
                        let from = format!("\"revision\":{}", observed.checkpoint.revision().0);
                        assert!(original_text.contains(&from));
                        original_text.replacen(
                            &from,
                            &format!("\"revision\":{}", observed.checkpoint.revision().0 + 1),
                            1,
                        )
                    };
                    write_private(&path, corrupted);
                }
                let operation = ForegroundOperation::new(
                    cold.binding.clone(),
                    ForegroundKind::Control,
                    10 + index as u64,
                )
                .unwrap();
                tui.commands
                    .as_ref()
                    .unwrap()
                    .send(WorkerCommand::Bound {
                        operation: operation.clone(),
                        command: Box::new(control_command()),
                    })
                    .unwrap();
                let invalid = terminal(&tui, &operation);
                assert_eq!(invalid.projection.cost, CostQualification::Unavailable);
                assert_eq!(invalid.projection.context, ContextProjection::Unavailable);
                assert_eq!(invalid.finished, 0);
                if kind == "missing" {
                    fs::rename(retained, &path).unwrap();
                } else {
                    write_private(&path, &original_bytes);
                }
                assert_eq!(fs::read(&path).unwrap(), original_bytes);
            }
            let restored =
                ForegroundOperation::new(cold.binding.clone(), ForegroundKind::Control, 20)
                    .unwrap();
            tui.commands
                .as_ref()
                .unwrap()
                .send(WorkerCommand::Bound {
                    operation: restored.clone(),
                    command: Box::new(control_command()),
                })
                .unwrap();
            assert_eq!(terminal(&tui, &restored).projection.cost, cold.cost);
            assert_eq!(view(&f, None).checkpoint, observed.checkpoint);
            tui.close(&f);
            let (lease, saved) =
                SessionLease::acquire_and_load(&f.home, SESSION, "cold-owner").unwrap();
            let serving = start_serving(&f, lease, &saved);
            let handle = serving.runtime.as_ref().unwrap().handle();
            let snapshot = handle.snapshot().unwrap();
            let account = snapshot.accounting.unwrap();
            assert_eq!(account.full_cost_status, FullCostStatus::UnknownUsage);
            assert_eq!(account.revision, observed.checkpoint.revision().0);
            assert_eq!(snapshot.cost_microcents, 13);
            let expired = orbit_cli::daemon::EventCursor {
                instance: "different-owner-instance".into(),
                sequence: 0,
            };
            let recovered = handle
                .subscribe(Some(&expired))
                .unwrap()
                .recovery
                .snapshot
                .unwrap();
            assert_eq!(recovered.accounting, Some(account));
            assert_eq!(recovered.cost_microcents, 13);
            let client = orbit_cli::attach::AttachClient::connect(
                &f.root.join("owner.sock"),
                false,
                Some(&expired),
            )
            .unwrap();
            assert_eq!(
                client.recovery.snapshot.as_ref().unwrap().accounting,
                Some(account)
            );
            drop(client);
            serving.close();
            assert_eq!(view(&f, None).checkpoint, observed.checkpoint);
            captures(&wire, &[RAW_A, RAW_A]);
            wire.finish();
            f.binary_unchanged();
            // A saved watermark ahead of its real checkpoint cannot establish a qualified owner.
            let lease = SessionLease::acquire(&f.home, SESSION, "conflicting-watermark").unwrap();
            let mut saved = lease.load().unwrap();
            saved.accounting_watermark.as_mut().unwrap().revision += 1;
            lease.save(&saved).unwrap();
            let result =
                OwnerRuntime::start(OwnerConfig::new(f.turn(&saved), f.workspace.clone()), lease);
            assert!(
                result.is_err(),
                "revision-conflicting saved metadata cannot create a qualified owner"
            );
        }
    }
}
