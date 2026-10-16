#![deny(unsafe_code)]

use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, MAX_PROVIDER_RECORD_BYTES, ProviderAuthIdentity, ProviderCredentialRevision,
    ProviderCredentialStore,
};
use orbit_engine::{ProviderKind, TurnConfig, TurnOutcome};
use orbit_provider_http::CancelToken;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const DECLARED_ENV: &str = "ORBIT_CREDENTIAL_FIXTURE_TOKEN";
const OTHER_ENV: &str = "ORBIT_CREDENTIAL_FIXTURE_OTHER_TOKEN";
const AMBIENT_KEY: &str = "orbit-fixture-ambient-7c5ee196";
const SAVED_KEY: &str = "orbit-fixture-saved-f931daa4";
const ENV_KEY: &str = "orbit-fixture-environment-53f4e755";
const CHILD_CASE: &str = "ORBIT_CREDENTIAL_FIXTURE_CHILD";
const CHILD_HOME: &str = "ORBIT_CREDENTIAL_FIXTURE_HOME";
const WIRE_QUERY: &str = "scope=synthetic&escaped=a%2Fb%26c%3Dd%2Be&space=a+b";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-credentials-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join("ledger"))
            .unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Each test reruns itself in a child with an empty inherited environment.
// Command::env keeps these tests safe to run concurrently without mutating ENV.
fn isolated(name: &str, env: &[(&str, &str)], test: impl FnOnce(&Path)) {
    isolated_with_env(
        name,
        |command| {
            for (key, value) in env {
                command.env(key, value);
            }
        },
        test,
    );
}

fn isolated_with_env(name: &str, configure: impl FnOnce(&mut Command), test: impl FnOnce(&Path)) {
    if std::env::var(CHILD_CASE).ok().as_deref() == Some(name) {
        let home = PathBuf::from(std::env::var_os(CHILD_HOME).unwrap());
        test(&home);
        return;
    }
    let home = Home::new();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .arg("--exact")
        .arg(name)
        .arg("--nocapture")
        .env_clear()
        .env(CHILD_CASE, name)
        .env(CHILD_HOME, &home.0)
        .env("HOME", &home.0)
        .env("ORBIT_TEST_FIRST_BYTE_TIMEOUT_MS", "1500")
        .env("ORBIT_TEST_IDLE_TIMEOUT_MS", "1500")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure(&mut child);
    let mut child = child.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            let mut diagnostics = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            for secret in [SAVED_KEY, ENV_KEY, AMBIENT_KEY] {
                diagnostics = diagnostics.replace(secret, "[redacted fixture key]");
            }
            assert!(
                status.success(),
                "isolated credential case failed: {name}\n{diagnostics}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated credential case exceeded its deadline: {name}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct CapturedRequest {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
            .collect()
    }
}

struct Provider {
    url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
}

impl Provider {
    fn new() -> Self {
        Self::with_reply(concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"fixture response\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n"
        ))
    }

    fn anthropic() -> Self {
        Self::with_reply(concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"fixture-message\",\"role\":\"assistant\",\"type\":\"message\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"fixture response\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        ))
    }

    fn with_reply(body: &'static str) -> Self {
        Self::with_response(body, "text/event-stream", None)
    }

    fn ollama() -> Self {
        Self::with_response(
            concat!(
                "{\"message\":{\"role\":\"assistant\",\"content\":\"fixture response\"},",
                "\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":1,\"eval_count\":1}\n"
            ),
            "application/x-ndjson",
            None,
        )
    }

    fn redirect(location: String) -> Self {
        Self::with_response("", "text/plain", Some(location))
    }

    fn with_response(body: &'static str, media: &'static str, redirect: Option<String>) -> Self {
        let (watchdog, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(Duration::from_secs(18)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("credential fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        captured.lock().unwrap().push(read_request(&mut stream));
                        let (status, location) = match &redirect {
                            Some(location) => (
                                "307 Temporary Redirect",
                                format!("Location: {location}\r\n"),
                            ),
                            None => ("200 OK", String::new()),
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status}\r\n{location}Content-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("credential fixture accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
            watchdog: Some(watchdog),
        }
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16_384 && Instant::now() < deadline);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    let mut lines = header.lines();
    let target = lines.next().unwrap().to_owned();
    assert!(target.starts_with("POST /") || target.starts_with("POST http://127.0.0.1:"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .unwrap()
        .1
        .parse()
        .unwrap();
    assert!(length < 1024 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    CapturedRequest {
        target,
        headers,
        body,
    }
}

fn config(provider: &Provider, credential_env: Option<&str>) -> TurnConfig {
    TurnConfig {
        provider_id: "credential-fixture".into(),
        gate: provider.url.clone(),
        model: "fixture-model".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: credential_env.map(str::to_owned),
        pricing: None,
        max_output_tokens: 2048,
        sampling: None,
        effort: None,
        supported_efforts: None,
    }
}

fn dispatch(
    home: &Path,
    config: &TurnConfig,
) -> (Result<TurnOutcome, (&'static str, String)>, Vec<String>) {
    let mut events = Vec::new();
    let result = orbit_engine::run_dispatch(
        home,
        config,
        "credential boundary fixture prompt",
        None,
        Some(&mut |event| events.push(format!("{event:?}"))),
        CancelToken::new(),
        Vec::new(),
        "credential-fixture",
        "credential-fixture-session",
    );
    (result, events)
}

fn identity(config: &TurnConfig) -> ProviderAuthIdentity {
    let kind = match config.kind {
        ProviderKind::OpenAiCompatible => "openai-compatible",
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::Ollama => "ollama",
    };
    let endpoint = url::Url::parse(&config.gate).unwrap();
    ProviderAuthIdentity::new(
        &config.provider_id,
        kind,
        endpoint.as_str(),
        config.credential_env.as_deref(),
    )
    .unwrap()
}

fn save_key(home: &Path, config: &TurnConfig) -> (PathBuf, ProviderCredentialRevision) {
    let identity = identity(config);
    let saved = ProviderCredentialStore::new(home)
        .unwrap()
        .save(
            &identity,
            SecretBytes::new(SAVED_KEY.as_bytes().to_vec()),
            ExpectedRevision::Absent,
        )
        .unwrap();
    let record = home
        .join("auth/providers")
        .join(format!("{}.credential", identity.binding_id()));
    assert_eq!(
        std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
        0o600
    );
    (record, saved.revision)
}

fn assert_secret_free(bytes: &[u8]) {
    for secret in [SAVED_KEY, ENV_KEY, AMBIENT_KEY] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()),
            "fabricated credential escaped its permitted authentication boundary"
        );
    }
}

fn assert_ledger_secret_free(directory: &Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_ledger_secret_free(&path);
        } else {
            assert_secret_free(&std::fs::read(path).unwrap());
        }
    }
}

fn assert_public_secret_free(
    home: &Path,
    config: &TurnConfig,
    result: &Result<TurnOutcome, (&'static str, String)>,
    events: &[String],
) {
    assert_secret_free(format!("{config:?}\n{result:?}\n{events:?}").as_bytes());
    assert_ledger_secret_free(&home.join("ledger"));
}

#[derive(PartialEq, Eq)]
struct CredentialSnapshot {
    path: PathBuf,
    mode: u32,
    link: Option<PathBuf>,
    bytes: Vec<u8>,
}

fn credential_snapshot(home: &Path) -> Vec<CredentialSnapshot> {
    fn visit(path: &Path, entries: &mut Vec<CredentialSnapshot>) {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("credential fixture snapshot failed: {error}"),
        };
        let is_link = metadata.file_type().is_symlink();
        entries.push(CredentialSnapshot {
            path: path.to_path_buf(),
            mode: metadata.permissions().mode(),
            link: is_link.then(|| std::fs::read_link(path).unwrap()),
            bytes: if metadata.is_file() && !is_link {
                std::fs::read(path).unwrap()
            } else {
                Vec::new()
            },
        });
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = Vec::new();
    visit(&home.join("auth"), &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn assert_preio_refusal(home: &Path, config: &TurnConfig, providers: &[&Provider]) {
    let before = credential_snapshot(home);
    let (result, events) = dispatch(home, config);
    assert_public_secret_free(home, config, &result, &events);
    assert!(result.is_err(), "credential boundary must refuse locally");
    for provider in providers {
        assert_eq!(provider.count(), 0, "credential refusal reached a provider");
    }
    assert!(events.is_empty(), "pre-I/O refusal emitted provider events");
    assert_eq!(std::fs::read_dir(home.join("ledger")).unwrap().count(), 0);
    assert!(
        credential_snapshot(home) == before,
        "credential refusal changed existing credential bytes, modes or links"
    );
}

enum ExpectedAuth<'a> {
    None,
    Bearer(&'a str),
    ApiKey(&'a str),
}

fn assert_request(
    home: &Path,
    config: &TurnConfig,
    provider: &Provider,
    auth: ExpectedAuth<'_>,
    target: &str,
) {
    let (result, events) = dispatch(home, config);
    assert_public_secret_free(home, config, &result, &events);
    assert!(
        result.is_ok(),
        "matching selected credential dispatch should succeed: {:?}",
        result.as_ref().err()
    );
    assert_eq!(result.unwrap().output, "fixture response");
    assert!(!events.is_empty());
    let requests = provider.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "matching dispatch must send exactly one request"
    );
    let request = &requests[0];
    assert_eq!(request.target, target);
    assert_eq!(
        request.header("host"),
        [provider.url.trim_start_matches("http://")]
    );
    let expected = match auth {
        ExpectedAuth::None => None,
        ExpectedAuth::Bearer(secret) => Some(("authorization", format!("Bearer {secret}"))),
        ExpectedAuth::ApiKey(secret) => Some(("x-api-key", secret.to_owned())),
    };
    for name in ["authorization", "x-api-key"] {
        let values = request.header(name);
        if let Some((expected_name, expected_value)) = &expected
            && name == *expected_name
        {
            assert!(
                values.len() == 1 && values[0] == expected_value.as_str(),
                "matching dispatch did not send exactly the selected credential header"
            );
            continue;
        }
        assert!(
            values.is_empty(),
            "dispatch sent an unexpected credential header"
        );
    }
    for (name, value) in &request.headers {
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "x-api-key"
        ) {
            assert_secret_free(value.as_bytes());
        }
    }
    assert_secret_free(&request.body);
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["model"].as_str(), Some(config.model.as_str()));
}

#[test]
fn selected_initial_boundary_no_auth_does_not_inherit_ambient_gate_token() {
    isolated(
        "selected_initial_boundary_no_auth_does_not_inherit_ambient_gate_token",
        &[("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
        |home| {
            let provider = Provider::new();
            assert_request(
                home,
                &config(&provider, None),
                &provider,
                ExpectedAuth::None,
                "POST /v1/chat/completions HTTP/1.1",
            );
        },
    );
}

#[test]
fn selected_initial_boundary_missing_declared_auth_refuses_before_io() {
    isolated(
        "selected_initial_boundary_missing_declared_auth_refuses_before_io",
        &[("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
        |home| {
            let provider = Provider::new();
            assert_preio_refusal(home, &config(&provider, Some(DECLARED_ENV)), &[&provider]);
        },
    );
}

#[test]
fn selected_saved_key_matches_canonical_root_and_exact_bearer_header() {
    isolated(
        "selected_saved_key_matches_canonical_root_and_exact_bearer_header",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(SAVED_KEY),
                "POST /v1/chat/completions HTTP/1.1",
            );
            assert!(
                std::fs::read(record).unwrap() == before,
                "dispatch changed the saved binding"
            );
        },
    );
}

#[test]
fn selected_saved_key_matches_exact_custom_endpoint_path() {
    isolated(
        "selected_saved_key_matches_exact_custom_endpoint_path",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.gate = format!("{}/owned/v1/", provider.url);
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(SAVED_KEY),
                "POST /owned/v1/chat/completions HTTP/1.1",
            );
        },
    );
}

#[test]
fn selected_saved_anthropic_key_uses_exact_api_key_header() {
    isolated(
        "selected_saved_anthropic_key_uses_exact_api_key_header",
        &[],
        |home| {
            let provider = Provider::anthropic();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.kind = ProviderKind::Anthropic;
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::ApiKey(SAVED_KEY),
                "POST /v1/messages HTTP/1.1",
            );
        },
    );
}

#[test]
fn selected_nonempty_environment_overrides_saved_key_without_replacing_it() {
    isolated(
        "selected_nonempty_environment_overrides_saved_key_without_replacing_it",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(ENV_KEY),
                "POST /v1/chat/completions HTTP/1.1",
            );
            assert!(
                std::fs::read(record).unwrap() == before,
                "ENV override replaced the saved binding"
            );
        },
    );
}

#[test]
fn selected_empty_environment_falls_back_to_exact_saved_binding() {
    isolated(
        "selected_empty_environment_falls_back_to_exact_saved_binding",
        &[(DECLARED_ENV, "")],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(SAVED_KEY),
                "POST /v1/chat/completions HTTP/1.1",
            );
        },
    );
}

#[test]
fn selected_invalid_environment_refuses_before_io_without_saved_fallback() {
    isolated(
        "selected_invalid_environment_refuses_before_io_without_saved_fallback",
        &[(
            DECLARED_ENV,
            "orbit-fixture-environment-53f4e755\r\nInjected: fixture",
        )],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == before,
                "invalid ENV changed the saved binding"
            );
        },
    );
}

#[test]
fn selected_non_utf8_environment_refuses_before_io_without_saved_fallback() {
    isolated_with_env(
        "selected_non_utf8_environment_refuses_before_io_without_saved_fallback",
        |command| {
            command.env(DECLARED_ENV, OsString::from_vec(vec![0xff, b'x']));
        },
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == before,
                "invalid ENV changed the saved binding"
            );
        },
    );
}

#[test]
fn selected_changed_endpoint_port_cannot_reuse_saved_key() {
    isolated(
        "selected_changed_endpoint_port_cannot_reuse_saved_key",
        &[],
        |home| {
            let original = Provider::new();
            let selected = Provider::new();
            save_key(home, &config(&original, Some(DECLARED_ENV)));
            assert_preio_refusal(
                home,
                &config(&selected, Some(DECLARED_ENV)),
                &[&original, &selected],
            );
        },
    );
}

#[test]
fn selected_changed_endpoint_path_cannot_reuse_saved_key() {
    isolated(
        "selected_changed_endpoint_path_cannot_reuse_saved_key",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.gate = format!("{}/original/v1", provider.url);
            save_key(home, &config);
            config.gate = format!("{}/selected/v1", provider.url);
            assert_preio_refusal(home, &config, &[&provider]);
        },
    );
}

#[test]
fn selected_changed_provider_id_cannot_reuse_saved_key() {
    isolated(
        "selected_changed_provider_id_cannot_reuse_saved_key",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            save_key(home, &config);
            config.provider_id = "other-credential-fixture".into();
            assert_preio_refusal(home, &config, &[&provider]);
        },
    );
}

#[test]
fn selected_changed_provider_kind_cannot_reuse_saved_key() {
    isolated(
        "selected_changed_provider_kind_cannot_reuse_saved_key",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            save_key(home, &config);
            config.kind = ProviderKind::Anthropic;
            assert_preio_refusal(home, &config, &[&provider]);
        },
    );
}

#[test]
fn selected_changed_environment_reference_cannot_reuse_saved_key() {
    isolated(
        "selected_changed_environment_reference_cannot_reuse_saved_key",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            save_key(home, &config);
            config.credential_env = Some(OTHER_ENV.into());
            assert_preio_refusal(home, &config, &[&provider]);
        },
    );
}

#[test]
fn selected_no_auth_ignores_saved_binding_and_ambient_credentials() {
    isolated(
        "selected_no_auth_ignores_saved_binding_and_ambient_credentials",
        &[(DECLARED_ENV, ENV_KEY), ("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            config.credential_env = None;
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::None,
                "POST /v1/chat/completions HTTP/1.1",
            );
            assert!(
                std::fs::read(record).unwrap() == before,
                "no-auth dispatch changed another binding"
            );
        },
    );
}

#[test]
fn selected_symlinked_auth_directory_refuses_before_io() {
    isolated(
        "selected_symlinked_auth_directory_refuses_before_io",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            let original = home.join("auth-original");
            std::fs::rename(home.join("auth"), &original).unwrap();
            symlink(&original, home.join("auth")).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(original.join("providers").join(record.file_name().unwrap()))
                    .unwrap()
                    == before,
                "refusal changed the original binding"
            );
        },
    );
}

#[test]
fn selected_insecure_provider_directory_mode_refuses_before_io() {
    isolated(
        "selected_insecure_provider_directory_mode_refuses_before_io",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            std::fs::set_permissions(
                home.join("auth/providers"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == before,
                "refusal changed the saved binding"
            );
        },
    );
}

#[test]
fn selected_insecure_record_mode_refuses_before_io() {
    isolated(
        "selected_insecure_record_mode_refuses_before_io",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == before,
                "refusal changed the saved binding"
            );
        },
    );
}

#[test]
fn selected_symlinked_record_refuses_before_io_and_preserves_target() {
    isolated(
        "selected_symlinked_record_refuses_before_io_and_preserves_target",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            let target = home.join("original.credential");
            std::fs::rename(&record, &target).unwrap();
            symlink(&target, &record).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(target).unwrap() == before,
                "refusal changed the symlink target"
            );
        },
    );
}

#[test]
fn selected_hardlinked_record_refuses_before_io_and_preserves_bytes() {
    isolated(
        "selected_hardlinked_record_refuses_before_io_and_preserves_bytes",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let before = std::fs::read(&record).unwrap();
            let alias = home.join("linked.credential");
            std::fs::hard_link(&record, &alias).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == before,
                "refusal changed a hardlinked binding"
            );
            assert!(
                std::fs::read(alias).unwrap() == before,
                "refusal changed its linked bytes"
            );
        },
    );
}

#[test]
fn selected_truncated_record_refuses_before_io_and_preserves_bytes() {
    isolated(
        "selected_truncated_record_refuses_before_io_and_preserves_bytes",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let mut truncated = std::fs::read(&record).unwrap();
            truncated.truncate(17);
            std::fs::write(&record, &truncated).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == truncated,
                "refusal replaced the truncated record"
            );
        },
    );
}

#[test]
fn selected_oversized_record_refuses_before_io_and_preserves_bytes() {
    isolated(
        "selected_oversized_record_refuses_before_io_and_preserves_bytes",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, _) = save_key(home, &config);
            let oversized = vec![b'x'; MAX_PROVIDER_RECORD_BYTES + 1];
            std::fs::write(&record, &oversized).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(record).unwrap() == oversized,
                "refusal replaced the oversized record"
            );
        },
    );
}

#[test]
fn selected_embedded_identity_mismatch_refuses_before_io() {
    isolated(
        "selected_embedded_identity_mismatch_refuses_before_io",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            let (original, _) = save_key(home, &config);
            let before = std::fs::read(&original).unwrap();
            config.provider_id = "other-credential-fixture".into();
            let selected = home
                .join("auth/providers")
                .join(format!("{}.credential", identity(&config).binding_id()));
            std::fs::write(&selected, &before).unwrap();
            std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_preio_refusal(home, &config, &[&provider]);
            assert!(
                std::fs::read(original).unwrap() == before,
                "refusal changed the original binding"
            );
            assert!(
                std::fs::read(selected).unwrap() == before,
                "refusal replaced the mismatched record"
            );
        },
    );
}

#[test]
fn selected_stale_replacement_preserves_and_dispatches_current_key() {
    isolated(
        "selected_stale_replacement_preserves_and_dispatches_current_key",
        &[],
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            let (record, first_revision) = save_key(home, &config);
            let store = ProviderCredentialStore::new(home).unwrap();
            let current = store
                .save(
                    &identity(&config),
                    SecretBytes::new(ENV_KEY.as_bytes().to_vec()),
                    ExpectedRevision::Exact(first_revision),
                )
                .unwrap();
            assert!(current.changed);
            let before = std::fs::read(&record).unwrap();
            let error = store
                .save(
                    &identity(&config),
                    SecretBytes::new(AMBIENT_KEY.as_bytes().to_vec()),
                    ExpectedRevision::Exact(first_revision),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                orbit_adapter::provider_credentials::ProviderCredentialError::StaleRevision
            ));
            assert_secret_free(format!("{error:?} {error}").as_bytes());
            assert!(
                std::fs::read(&record).unwrap() == before,
                "stale replacement changed the saved binding"
            );
            let status = store.status_with(&identity(&config), |_| Ok(None));
            assert_secret_free(format!("{status:?}").as_bytes());
            assert!(
                matches!(status, orbit_adapter::provider_credentials::ProviderCredentialStatus::Available { revision: Some(revision), .. } if revision == current.revision)
            );
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(ENV_KEY),
                "POST /v1/chat/completions HTTP/1.1",
            );
            assert!(
                std::fs::read(record).unwrap() == before,
                "dispatch changed the preserved saved binding"
            );
        },
    );
}

#[test]
fn endpoint_query_engine_openai_saved_key_exact_target() {
    isolated(
        "endpoint_query_engine_openai_saved_key_exact_target",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.gate = format!("{}/tenant/v1?{WIRE_QUERY}", provider.url);
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(SAVED_KEY),
                &format!("POST /tenant/v1/chat/completions?{WIRE_QUERY} HTTP/1.1"),
            );
        },
    );
}

#[test]
fn endpoint_query_engine_anthropic_saved_key_exact_target() {
    isolated(
        "endpoint_query_engine_anthropic_saved_key_exact_target",
        &[],
        |home| {
            let provider = Provider::anthropic();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.kind = ProviderKind::Anthropic;
            config.gate = format!("{}/tenant/v1?{WIRE_QUERY}", provider.url);
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::ApiKey(SAVED_KEY),
                &format!("POST /tenant/v1/messages?{WIRE_QUERY} HTTP/1.1"),
            );
        },
    );
}

fn query_ollama_case(home: &Path, base: &str, target: &str) {
    let provider = Provider::ollama();
    let mut config = config(&provider, None);
    config.kind = ProviderKind::Ollama;
    config.gate = format!("{}{base}?{WIRE_QUERY}", provider.url);
    assert_request(
        home,
        &config,
        &provider,
        ExpectedAuth::None,
        &format!("POST {target}?{WIRE_QUERY} HTTP/1.1"),
    );
}

#[test]
fn endpoint_query_engine_ollama_bare_host_no_auth() {
    isolated(
        "endpoint_query_engine_ollama_bare_host_no_auth",
        &[],
        |home| {
            query_ollama_case(home, "", "/api/chat");
        },
    );
}

#[test]
fn endpoint_query_engine_ollama_proxy_base_no_auth() {
    isolated(
        "endpoint_query_engine_ollama_proxy_base_no_auth",
        &[],
        |home| {
            query_ollama_case(home, "/proxy", "/proxy/api/chat");
        },
    );
}

#[test]
fn endpoint_query_engine_ollama_explicit_api_no_duplication() {
    isolated(
        "endpoint_query_engine_ollama_explicit_api_no_duplication",
        &[],
        |home| {
            query_ollama_case(home, "/proxy/api", "/proxy/api/chat");
        },
    );
}

#[test]
fn endpoint_query_engine_changed_query_cannot_reuse_saved_key() {
    isolated(
        "endpoint_query_engine_changed_query_cannot_reuse_saved_key",
        &[],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.gate = format!("{}/v1?scope=first", provider.url);
            save_key(home, &config);
            config.gate = format!("{}/v1?scope=second", provider.url);
            assert_preio_refusal(home, &config, &[&provider]);
        },
    );
}

fn invalid_gate_case(home: &Path, suffix: &str) {
    let provider = Provider::new();
    let mut config = config(&provider, Some(DECLARED_ENV));
    config.gate = format!("{}{suffix}", provider.url);
    let (result, events) = dispatch(home, &config);
    assert!(result.is_err(), "ambiguous raw URL must fail locally");
    let (code, message) = result.unwrap_err();
    assert_eq!(code, "ORBIT-E0401");
    assert!(!message.contains("scope=") && !message.contains("synthetic-query-token"));
    assert!(!message.contains(&provider.url));
    assert!(events.is_empty());
    assert_eq!(provider.count(), 0);
    assert_eq!(std::fs::read_dir(home.join("ledger")).unwrap().count(), 0);
    assert_secret_free(message.as_bytes());
    assert_ledger_secret_free(&home.join("ledger"));
}

#[test]
fn endpoint_query_engine_sensitive_query_refuses_before_http() {
    isolated(
        "endpoint_query_engine_sensitive_query_refuses_before_http",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            invalid_gate_case(home, "/v1?api_key=synthetic-query-token");
        },
    );
}

#[test]
fn endpoint_query_engine_raw_newline_refuses_before_url_parse() {
    isolated(
        "endpoint_query_engine_raw_newline_refuses_before_url_parse",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            invalid_gate_case(home, "/v1?scope=syn\nthetic");
        },
    );
}

#[test]
fn endpoint_query_engine_raw_tab_refuses_before_url_parse() {
    isolated(
        "endpoint_query_engine_raw_tab_refuses_before_url_parse",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            invalid_gate_case(home, "/v1?scope=syn\tthetic");
        },
    );
}

#[test]
fn endpoint_query_engine_raw_backslash_refuses_before_url_parse() {
    isolated(
        "endpoint_query_engine_raw_backslash_refuses_before_url_parse",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            invalid_gate_case(home, "/tenant\\v1?scope=synthetic");
        },
    );
}

#[test]
fn endpoint_query_engine_ambiguous_queries_refuse_before_http() {
    isolated(
        "endpoint_query_engine_ambiguous_queries_refuse_before_http",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            for suffix in [
                "/v1?",
                "/v1?scope=%GG",
                "/v1?scope=one&scope=two",
                "/v1?scope=one&%73cope=two",
            ] {
                invalid_gate_case(home, suffix);
            }
        },
    );
}

#[test]
fn endpoint_query_engine_all_dialects_refuse_redirect_trap() {
    isolated(
        "endpoint_query_engine_all_dialects_refuse_redirect_trap",
        &[],
        |home| {
            for kind in [
                ProviderKind::OpenAiCompatible,
                ProviderKind::Anthropic,
                ProviderKind::Ollama,
            ] {
                let trap = match kind {
                    ProviderKind::Anthropic => Provider::anthropic(),
                    ProviderKind::Ollama => Provider::ollama(),
                    _ => Provider::new(),
                };
                let provider =
                    Provider::redirect(format!("{}/redirect-trap?scope=other", trap.url));
                let mut config = config(
                    &provider,
                    if matches!(kind, ProviderKind::Ollama) {
                        None
                    } else {
                        Some(DECLARED_ENV)
                    },
                );
                config.kind = kind;
                config.gate = format!("{}?scope=synthetic", provider.url);
                if !matches!(kind, ProviderKind::Ollama) {
                    save_key(home, &config);
                }
                let (result, events) = dispatch(home, &config);
                assert_eq!(provider.count(), 1);
                assert_eq!(trap.count(), 0, "redirect escaped the registered authority");
                assert!(result.is_err(), "redirect cannot complete a turn");
                assert_public_secret_free(home, &config, &result, &events);
                assert_eq!(
                    result.unwrap_err().0,
                    "E0411",
                    "redirect refusal must not be retryable"
                );
            }
        },
    );
}

#[test]
fn endpoint_query_engine_ambient_proxy_cannot_replace_exact_destination() {
    let proxy = Provider::new();
    isolated_with_env(
        "endpoint_query_engine_ambient_proxy_cannot_replace_exact_destination",
        |child| {
            child
                .env("HTTP_PROXY", &proxy.url)
                .env("http_proxy", &proxy.url)
                .env("ALL_PROXY", &proxy.url)
                .env("all_proxy", &proxy.url)
                .env("NO_PROXY", "")
                .env("no_proxy", "");
        },
        |home| {
            let provider = Provider::new();
            let config = config(&provider, Some(DECLARED_ENV));
            save_key(home, &config);
            assert_request(
                home,
                &config,
                &provider,
                ExpectedAuth::Bearer(SAVED_KEY),
                "POST /v1/chat/completions HTTP/1.1",
            );
        },
    );
    assert_eq!(
        proxy.count(),
        0,
        "ambient proxy received an admitted request"
    );
}

#[test]
fn endpoint_query_engine_zero_port_refuses_before_credentials_or_ledger() {
    isolated(
        "endpoint_query_engine_zero_port_refuses_before_credentials_or_ledger",
        &[(DECLARED_ENV, ENV_KEY)],
        |home| {
            let provider = Provider::new();
            let mut config = config(&provider, Some(DECLARED_ENV));
            config.gate = "http://127.0.0.1:0/v1?scope=synthetic".into();
            let before = credential_snapshot(home);
            let (result, events) = dispatch(home, &config);
            let (code, message) = result.unwrap_err();
            assert_eq!(code, "ORBIT-E0401");
            assert!(message.starts_with("provider endpoint "));
            assert!(!message.contains("scope=") && !message.contains("127.0.0.1"));
            assert_secret_free(message.as_bytes());
            assert!(events.is_empty());
            assert_eq!(provider.count(), 0);
            assert_eq!(std::fs::read_dir(home.join("ledger")).unwrap().count(), 0);
            assert!(credential_snapshot(home) == before);
        },
    );
}
