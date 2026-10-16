#![cfg(target_os = "linux")]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::ProviderCredentialSource;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, ProviderAuthIdentity, ProviderCredentialError, ProviderCredentialStore,
};
use orbit_cli::config::{ModelEntry, Pricing, ProviderConfig, ProvidersConfig};
use orbit_cli::onboarding::provider_login::{
    BrowserOpenOutcome, LoopbackTestTransport, OPENROUTER_PROVIDER_URL,
};
use orbit_cli::onboarding::provider_login::{LoginError, LoginMode};
use orbit_cli::onboarding::{
    AuthorizationOpener, LoginServiceFactory, ModelDiscovery, ModelDiscoveryFactory,
    OnboardingError, ProviderLoginMethod, ProviderLoginRequest, ProviderLoginServiceFactory,
    SetupTerminal, collect_onboarding_with_services, collect_provider_login,
    collect_provider_login_with_services, commit_onboarding, commit_provider_logout,
    plan_provider_logout,
};
use orbit_cli::provider_discovery::{
    DiscoveredCatalog, DiscoveredDetails, DiscoveredModel, DiscoveryCompleteness, DiscoveryProfile,
    MetadataSource,
};
use orbit_cli::setup::{SetupRequest, apply_setup, plan_setup, plan_setup_with_main};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

const OLD_KEY: &str = "synthetic-previous-login-key-173592";
const NEW_KEY: &str = "synthetic-new-login-key-683491";
const AUTH_CODE: &str = "synthetic-authorization-code-839241";

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    provider: ProviderConfig,
}
impl Fixture {
    fn new(saved: bool) -> Self {
        let root = std::env::temp_dir().join(format!("orbit-login-ui-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        let provider = ProviderConfig {
            name: "fixture".into(),
            kind: "openai-compatible".into(),
            url: "http://127.0.0.1:9/v1".into(),
            env: Some(format!("ORBIT_LOGIN_TEST_{}", ulid::Ulid::new())),
            models: vec![ModelEntry {
                id: "family/raw".into(),
                label: None,
                pricing: Pricing::default(),
                max_output_tokens: Some(4000),
                context_window: Some(32000),
                sampling: None,
                supported_efforts: None,
                default_effort: None,
            }],
        };
        apply_setup(
            &plan_setup_with_main(
                &home,
                &SetupRequest {
                    provider: Some(provider.clone()),
                    ..Default::default()
                },
                Some("fixture/family/raw"),
            )
            .unwrap(),
        )
        .unwrap();
        let result = Self {
            root,
            home,
            provider,
        };
        if saved {
            result
                .store()
                .save(
                    &result.identity(),
                    SecretBytes::new(OLD_KEY.as_bytes().to_vec()),
                    ExpectedRevision::Absent,
                )
                .unwrap();
        }
        result
    }
    fn store(&self) -> ProviderCredentialStore {
        ProviderCredentialStore::new(&self.home).unwrap()
    }
    fn identity(&self) -> ProviderAuthIdentity {
        auth_identity(&self.provider)
    }
    fn config(&self) -> ProvidersConfig {
        ProvidersConfig::load_from_str(
            &std::fs::read_to_string(self.home.join("providers.toml")).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn auth_identity(provider: &ProviderConfig) -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap()
}
fn snapshot(home: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(home, home, &mut result);
    result
}
struct Terminal {
    input: VecDeque<String>,
    output: String,
    authorization: Option<Url>,
    challenge: Option<Arc<Mutex<Option<String>>>>,
    before_confirm: Option<Box<dyn FnOnce()>>,
    _owner: Rc<()>,
}
impl Terminal {
    fn new(values: &[&str]) -> Self {
        Self {
            input: values.iter().map(|value| value.to_string()).collect(),
            output: String::new(),
            authorization: None,
            challenge: None,
            before_confirm: None,
            _owner: Rc::new(()),
        }
    }
}
impl SetupTerminal for Terminal {
    fn message(&mut self, message: &str) -> Result<(), OnboardingError> {
        if let Some(raw) = message.strip_prefix("Authorize with the provider: ") {
            let authorization = Url::parse(raw).unwrap();
            if let Some(challenge) = &self.challenge {
                *challenge.lock().unwrap() = Some(query(&authorization, "code_challenge"));
            }
            self.authorization = Some(authorization);
        }
        self.output.push_str(message);
        self.output.push('\n');
        Ok(())
    }
    fn line(&mut self, prompt: &str, _max: usize) -> Result<String, OnboardingError> {
        if prompt.starts_with("Save provider")
            && let Some(check) = self.before_confirm.take()
        {
            check();
        }
        self.output.push_str(prompt);
        self.input.pop_front().ok_or(OnboardingError::Canceled)
    }
    fn hidden(&mut self, prompt: &str, _max: usize) -> Result<SecretBytes, OnboardingError> {
        self.output.push_str(prompt);
        Ok(SecretBytes::new(
            self.input
                .pop_front()
                .ok_or(OnboardingError::Canceled)?
                .into_bytes(),
        ))
    }
    fn hidden_until(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Instant,
    ) -> Result<SecretBytes, OnboardingError> {
        assert!(Instant::now() < deadline && deadline <= Instant::now() + Duration::from_secs(10));
        let code = self.hidden(prompt, max)?;
        assert!(code.len() <= max);
        Ok(code)
    }
}
fn key_request() -> ProviderLoginRequest {
    ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Key),
        mode: LoginMode::Loopback,
        open_browser: false,
    }
}

#[test]
fn existing_provider_key_login_is_unpublished_until_confirmed_and_preserves_models_and_default() {
    let fixture = Fixture::new(true);
    let before = snapshot(&fixture.home);
    let mut terminal = Terminal::new(&[NEW_KEY, "yes"]);
    let draft =
        collect_provider_login(&fixture.home, "fixture", &key_request(), &mut terminal).unwrap();
    assert_eq!(snapshot(&fixture.home), before);
    assert_ne!(draft.provider().env, fixture.provider.env);
    let id = draft.auth_identity().unwrap();
    let receipt = commit_onboarding(draft).unwrap();
    let config = fixture.config();
    assert_eq!(config.provider[0].models, fixture.provider.models);
    assert_eq!(config.roles.main, "fixture/family/raw");
    assert_eq!(receipt.connectivity, "not_tested");
    let resolved = fixture.store().resolve_with(&id, |_| Ok(None)).unwrap();
    assert!(resolved.into_secret().unwrap().expose() == NEW_KEY.as_bytes());
    assert!(!terminal.output.contains(NEW_KEY));
    assert!(!serde_json::to_string(&receipt).unwrap().contains(NEW_KEY));
}

#[test]
fn declined_provider_login_preserves_old_key_config_identity_and_every_file() {
    let fixture = Fixture::new(true);
    let before = snapshot(&fixture.home);
    let mut terminal = Terminal::new(&[NEW_KEY, "no"]);
    assert!(matches!(
        collect_provider_login(&fixture.home, "fixture", &key_request(), &mut terminal),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&fixture.home), before);
    assert!(!terminal.output.contains(NEW_KEY));
}

#[test]
fn configured_custom_endpoint_does_not_gain_browser_login_from_its_display_name() {
    let fixture = Fixture::new(true);
    let mut named_like_provider = fixture.provider.clone();
    named_like_provider.name = "openrouter".into();
    apply_setup(
        &plan_setup(
            &fixture.home,
            &SetupRequest {
                provider: Some(named_like_provider),
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap();
    let before = snapshot(&fixture.home);
    let request = ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Browser),
        mode: LoginMode::Headless,
        open_browser: false,
    };
    let mut terminal = Terminal::new(&[]);
    assert!(matches!(
        collect_provider_login(&fixture.home, "openrouter", &request, &mut terminal),
        Err(OnboardingError::Login(LoginError::UnsupportedProvider))
    ));
    assert_eq!(snapshot(&fixture.home), before);
    assert!(!terminal.output.contains("API key"));
}

#[test]
fn logout_removes_only_exact_current_private_binding_and_preserves_provider_configuration() {
    let fixture = Fixture::new(true);
    let config = std::fs::read(fixture.home.join("providers.toml")).unwrap();
    let mut other = fixture.provider.clone();
    other.name = "other".into();
    apply_setup(
        &plan_setup(
            &fixture.home,
            &SetupRequest {
                provider: Some(other.clone()),
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap();
    let config_with_other = std::fs::read(fixture.home.join("providers.toml")).unwrap();
    assert_ne!(config, config_with_other);
    fixture
        .store()
        .save(
            &auth_identity(&other),
            SecretBytes::new(b"synthetic-other-key".to_vec()),
            ExpectedRevision::Absent,
        )
        .unwrap();
    let plan = plan_provider_logout(&fixture.home, "fixture").unwrap();
    let receipt = commit_provider_logout(plan).unwrap();
    assert!(receipt.removed);
    assert_eq!(
        std::fs::read(fixture.home.join("providers.toml")).unwrap(),
        config_with_other
    );
    assert!(
        fixture
            .store()
            .resolve_with(&fixture.identity(), |_| Ok(None))
            .is_err()
    );
    assert!(
        fixture
            .store()
            .resolve_with(&auth_identity(&other), |_| Ok(None))
            .unwrap()
            .into_secret()
            .unwrap()
            .expose()
            == b"synthetic-other-key"
    );
}

#[test]
fn logout_absent_binding_creates_no_auth_store_and_preserves_all_existing_bytes() {
    let fixture = Fixture::new(false);
    let before = snapshot(&fixture.home);
    let receipt =
        commit_provider_logout(plan_provider_logout(&fixture.home, "fixture").unwrap()).unwrap();
    assert!(!receipt.removed);
    assert!(!fixture.home.join("auth").exists());
    assert_eq!(snapshot(&fixture.home), before);
}

#[test]
fn logout_planning_refuses_an_existing_store_without_its_lock_without_repairing_it() {
    let fixture = Fixture::new(true);
    let lock = fixture.home.join("auth/providers/store.lock");
    std::fs::remove_file(&lock).unwrap();
    let before = snapshot(&fixture.home);
    assert!(plan_provider_logout(&fixture.home, "fixture").is_err());
    assert!(
        !lock.exists(),
        "logout planning repaired an unconfirmed credential store"
    );
    assert_eq!(snapshot(&fixture.home), before);
}

#[test]
fn env_login_summary_refuses_missing_store_lock_without_preconfirmation_repair() {
    let fixture = Fixture::new(true);
    let lock = fixture.home.join("auth/providers/store.lock");
    std::fs::remove_file(&lock).unwrap();
    let before = snapshot(&fixture.home);
    let reference = fixture.provider.env.as_deref().unwrap();
    let mut terminal = Terminal::new(&[reference, "no"]);
    let request = ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Env),
        mode: LoginMode::Loopback,
        open_browser: false,
    };
    let result = collect_provider_login(&fixture.home, "fixture", &request, &mut terminal);
    assert!(
        !lock.exists(),
        "ENV login summary repaired an unconfirmed credential store"
    );
    assert_eq!(snapshot(&fixture.home), before);
    assert!(matches!(
        result,
        Err(OnboardingError::Credential(
            ProviderCredentialError::UnsafeFile
        ))
    ));
    assert!(!terminal.output.contains("Save provider login?"));
}

#[test]
fn logout_refuses_changed_config_before_removing_saved_key() {
    let fixture = Fixture::new(true);
    let plan = plan_provider_logout(&fixture.home, "fixture").unwrap();
    let path = fixture.home.join("providers.toml");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("\n[concurrent]\nchanged=true\n");
    std::fs::write(&path, text).unwrap();
    let expected = snapshot(&fixture.home);
    assert!(matches!(
        commit_provider_logout(plan),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(snapshot(&fixture.home), expected);
    assert!(
        fixture
            .store()
            .resolve_with(&fixture.identity(), |_| Ok(None))
            .unwrap()
            .into_secret()
            .unwrap()
            .expose()
            == OLD_KEY.as_bytes()
    );
}

#[test]
fn logout_refuses_changed_credential_revision_without_clobbering_new_key() {
    let fixture = Fixture::new(true);
    let old = fixture
        .store()
        .resolve_with(&fixture.identity(), |_| Ok(None))
        .unwrap()
        .revision()
        .unwrap();
    let plan = plan_provider_logout(&fixture.home, "fixture").unwrap();
    fixture
        .store()
        .save(
            &fixture.identity(),
            SecretBytes::new(NEW_KEY.as_bytes().to_vec()),
            ExpectedRevision::Exact(old),
        )
        .unwrap();
    let expected = snapshot(&fixture.home);
    assert!(commit_provider_logout(plan).is_err());
    assert_eq!(snapshot(&fixture.home), expected);
    assert!(
        fixture
            .store()
            .resolve_with(&fixture.identity(), |_| Ok(None))
            .unwrap()
            .into_secret()
            .unwrap()
            .expose()
            == NEW_KEY.as_bytes()
    );
}

fn query(url: &Url, key: &str) -> String {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .unwrap()
        .1
        .into_owned()
}

fn read_http(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(750)))?;
    stream.set_write_timeout(Some(Duration::from_millis(750)))?;
    let mut bytes = Vec::new();
    let mut part = [0; 1024];
    loop {
        let count = stream.read(&mut part)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&part[..count]);
        if bytes.len() > 32768 {
            return Err(std::io::Error::other("bounded request"));
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).map_err(std::io::Error::other)?;
            let size = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + size {
                break;
            }
        }
    }
    Ok(bytes)
}

struct ProtocolFixture {
    address: SocketAddr,
    challenge: Arc<Mutex<Option<String>>>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
impl ProtocolFixture {
    fn new(exchange_ok: bool) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let challenge: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let expected = challenge.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                let bytes = match read_http(&mut stream) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                if bytes.is_empty() {
                    continue;
                }
                let end = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap();
                let head = std::str::from_utf8(&bytes[..end]).unwrap();
                let (status, body) = if head.starts_with("POST /api/v1/auth/keys HTTP/1.1\r\n") {
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes[end + 4..]).unwrap();
                    assert_eq!(body.as_object().unwrap().len(), 3);
                    assert!(body["code"].as_str() == Some(AUTH_CODE));
                    assert!(body["code_challenge_method"].as_str() == Some("S256"));
                    let verifier = body["code_verifier"].as_str().unwrap();
                    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                    assert!(expected.lock().unwrap().as_deref() == Some(actual.as_str()));
                    assert!(!head.to_ascii_lowercase().contains("authorization:"));
                    if exchange_ok {
                        (200, serde_json::json!({"key": NEW_KEY}).to_string())
                    } else {
                        (401, "{}".into())
                    }
                } else {
                    assert!(head.starts_with("GET /api/v1/models HTTP/1.1\r\n"));
                    assert!(
                        head.lines()
                            .any(|line| line == format!("Authorization: Bearer {NEW_KEY}"))
                    );
                    (
                        200,
                        "{\"data\":[{\"id\":\"family/raw\",\"context_length\":32000}]}".into(),
                    )
                };
                captured.lock().unwrap().push(bytes);
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            address,
            challenge,
            requests,
            stop,
            join: Some(join),
        }
    }
    fn transport(&self) -> LoopbackTestTransport {
        LoopbackTestTransport::new(Url::parse(&format!("http://{}/", self.address)).unwrap())
            .unwrap()
            .with_timeouts(
                Duration::from_secs(3),
                Duration::from_secs(1),
                Duration::from_millis(200),
            )
            .unwrap()
    }
    fn factory(&self, callback: bool) -> (ProviderLoginServiceFactory, Rc<RefCell<Option<Url>>>) {
        let authorization = Rc::new(RefCell::new(None));
        let opener = CaptureOpener {
            authorization: authorization.clone(),
            challenge: self.challenge.clone(),
            callback,
            join: None,
        };
        (
            ProviderLoginServiceFactory::with_loopback_test_transport(
                self.transport(),
                Box::new(opener),
            ),
            authorization,
        )
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
impl Drop for ProtocolFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(50));
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

// Rc deliberately keeps this opener on its original thread. Only its bounded,
// owned local callback client is moved into a worker and joined on drop.
struct CaptureOpener {
    authorization: Rc<RefCell<Option<Url>>>,
    challenge: Arc<Mutex<Option<String>>>,
    callback: bool,
    join: Option<thread::JoinHandle<bool>>,
}
impl AuthorizationOpener for CaptureOpener {
    fn open(&mut self, authorization: &Url) -> Result<BrowserOpenOutcome, OnboardingError> {
        *self.authorization.borrow_mut() = Some(authorization.clone());
        *self.challenge.lock().unwrap() = Some(query(authorization, "code_challenge"));
        if self.callback {
            let mut callback = Url::parse(&query(authorization, "callback_url")).unwrap();
            let port = callback.port().unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", &query(authorization, "state"))
                .append_pair("code", AUTH_CODE);
            self.join = Some(thread::spawn(move || {
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                let mut stream =
                    TcpStream::connect_timeout(&address, Duration::from_millis(500)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let request = format!(
                    "GET {}?{} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n",
                    callback.path(),
                    callback.query().unwrap()
                );
                stream.write_all(request.as_bytes()).unwrap();
                let mut response = Vec::new();
                stream.take(8192).read_to_end(&mut response).unwrap();
                response.starts_with(b"HTTP/1.1 200 OK")
            }));
        }
        Ok(BrowserOpenOutcome::ManualOpenRequired)
    }
}
impl Drop for CaptureOpener {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            assert!(join.join().unwrap());
        }
    }
}

struct WizardDiscovery {
    address: SocketAddr,
}
struct WizardCatalog {
    address: SocketAddr,
    secret: SecretBytes,
}
impl ModelDiscoveryFactory for WizardDiscovery {
    fn open(
        &mut self,
        home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
    ) -> Result<Box<dyn ModelDiscovery>, OnboardingError> {
        assert_eq!(provider.url.trim_end_matches('/'), OPENROUTER_PROVIDER_URL);
        assert_eq!(profile, DiscoveryProfile::OpenRouter);
        let id = auth_identity(provider);
        let resolved =
            ProviderCredentialStore::new(home)?.resolve_with_draft(&id, draft, |_| Ok(None))?;
        assert_eq!(resolved.source(), ProviderCredentialSource::Draft);
        let secret = resolved.into_secret().unwrap();
        assert!(secret.expose() == NEW_KEY.as_bytes());
        Ok(Box::new(WizardCatalog {
            address: self.address,
            secret,
        }))
    }
}
impl ModelDiscovery for WizardCatalog {
    fn credential_source(&self) -> ProviderCredentialSource {
        ProviderCredentialSource::Draft
    }
    fn catalog(&mut self) -> Result<DiscoveredCatalog, OnboardingError> {
        let mut stream =
            TcpStream::connect_timeout(&self.address, Duration::from_millis(500)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let key = std::str::from_utf8(self.secret.expose()).unwrap();
        let request = format!(
            "GET /api/v1/models HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {key}\r\nConnection: close\r\n\r\n",
            self.address
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.take(32768).read_to_end(&mut response).unwrap();
        let end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        let body: serde_json::Value = serde_json::from_slice(&response[end + 4..]).unwrap();
        Ok(DiscoveredCatalog {
            models: vec![DiscoveredModel {
                id: body["data"][0]["id"].as_str().unwrap().into(),
                label: None,
                context_window: body["data"][0]["context_length"].as_u64(),
                max_output_tokens: None,
                source: MetadataSource::OpenRouterModels,
                metadata_valid: true,
                unrecognized_fields: vec![],
            }],
            completeness: DiscoveryCompleteness::Complete,
            issues: vec![],
            pages_fetched: 1,
        })
    }
    fn details(
        &mut self,
        selected: &[DiscoveredModel],
        _refresh: bool,
    ) -> Result<DiscoveredDetails, OnboardingError> {
        Ok(DiscoveredDetails {
            models: selected.to_vec(),
            completeness: DiscoveryCompleteness::Complete,
            issues: vec![],
            considered: selected.len(),
            attempted: 0,
        })
    }
}

fn absent_home() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("orbit-browser-wizard-{}", ulid::Ulid::new()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    (root.clone(), root.join("home"))
}
struct RemoveRoot(PathBuf);
impl Drop for RemoveRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn assert_private_output(output: &str) {
    assert!(!output.contains(AUTH_CODE) && !output.contains(NEW_KEY) && !output.contains(OLD_KEY));
    assert!(!output.contains("code_verifier"));
}
fn assert_saved_official(home: &Path) {
    let config = ProvidersConfig::load_from_str(
        &std::fs::read_to_string(home.join("providers.toml")).unwrap(),
    )
    .unwrap();
    let provider = config
        .provider
        .iter()
        .find(|provider| provider.name == "browserfixture")
        .unwrap();
    assert_eq!(provider.url.trim_end_matches('/'), OPENROUTER_PROVIDER_URL);
    assert_eq!(provider.models[0].id, "family/raw");
    assert_eq!(config.roles.main, "browserfixture/family/raw");
    let resolved = ProviderCredentialStore::new(home)
        .unwrap()
        .resolve_with(&auth_identity(provider), |_| Ok(None))
        .unwrap();
    assert_eq!(resolved.source(), ProviderCredentialSource::Saved);
    assert!(resolved.into_secret().unwrap().expose() == NEW_KEY.as_bytes());
    let public = std::fs::read_to_string(home.join("providers.toml")).unwrap();
    assert_private_output(&public);
}

struct ChildGuard(Option<std::process::Child>);
impl ChildGuard {
    fn wait(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let child = self.0.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "restart helper exceeded deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn assert_restart(home: &Path) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "broker_restart_child",
            "--nocapture",
        ])
        .env_clear()
        .env("ORBIT_LOGIN_RESTART_HOME", home)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ChildGuard(Some(command.spawn().unwrap())).wait();
}
#[test]
#[ignore = "fresh-process helper invoked by the browser wizard tests"]
fn broker_restart_child() {
    let Some(home) = std::env::var_os("ORBIT_LOGIN_RESTART_HOME") else {
        return;
    };
    assert_saved_official(Path::new(&home));
}

#[test]
fn loopback_browser_setup_discovers_with_draft_then_saves_exact_official_binding_for_restart() {
    let protocol = ProtocolFixture::new(true);
    let (root, home) = absent_home();
    let _cleanup = RemoveRoot(root);
    let (mut login, authorization) = protocol.factory(true);
    let mut discovery = WizardDiscovery {
        address: protocol.address,
    };
    let mut terminal = Terminal::new(&[
        "browserfixture",
        "",
        "browser",
        "loopback",
        "discover",
        "1",
        "yes",
        "family/raw",
        "yes",
    ]);
    let unpublished = home.clone();
    terminal.before_confirm = Some(Box::new(move || assert!(!unpublished.exists())));
    let draft = collect_onboarding_with_services(
        &home,
        Some("openrouter"),
        &mut terminal,
        &mut discovery,
        &mut login,
    )
    .unwrap();
    assert!(!home.exists() && protocol.count() == 2);
    assert_private_output(&terminal.output);
    assert!(
        terminal
            .output
            .contains("Open the same authorization URL manually")
    );
    let url = authorization.borrow().clone().unwrap();
    let port = Url::parse(&query(&url, "callback_url"))
        .unwrap()
        .port()
        .unwrap();
    assert!(
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(100)
        )
        .is_err()
    );
    let receipt = commit_onboarding(draft).unwrap();
    assert!(receipt.authentication_online);
    assert_eq!(receipt.catalog_status, "complete");
    assert_eq!(receipt.connectivity, "not_tested");
    assert_private_output(&serde_json::to_string(&receipt).unwrap());
    assert_saved_official(&home);
    assert_restart(&home);
}

#[tokio::test(flavor = "current_thread")]
async fn headless_browser_setup_works_inside_runtime_with_non_send_terminal_and_restarts() {
    let protocol = ProtocolFixture::new(true);
    let (root, home) = absent_home();
    let _cleanup = RemoveRoot(root);
    let (mut login, authorization) = protocol.factory(false);
    let mut discovery = WizardDiscovery {
        address: protocol.address,
    };
    let mut terminal = Terminal::new(&[
        "browserfixture",
        "",
        "browser",
        "headless",
        AUTH_CODE,
        "discover",
        "1",
        "yes",
        "family/raw",
        "yes",
    ]);
    terminal.challenge = Some(protocol.challenge.clone());
    let draft = collect_onboarding_with_services(
        &home,
        Some("openrouter"),
        &mut terminal,
        &mut discovery,
        &mut login,
    )
    .unwrap();
    assert!(
        authorization.borrow().is_none(),
        "headless login must not invoke an opener"
    );
    assert!(!home.exists() && protocol.count() == 2);
    let url = terminal.authorization.as_ref().unwrap();
    assert!(
        url.query_pairs()
            .all(|(key, _)| key != "callback_url" && key != "state")
    );
    assert_private_output(&terminal.output);
    commit_onboarding(draft).unwrap();
    assert_saved_official(&home);
    assert_restart(&home);
}

#[test]
fn headless_browser_decline_after_exchange_and_catalog_leaves_no_home_or_private_key() {
    let protocol = ProtocolFixture::new(true);
    let (root, home) = absent_home();
    let _cleanup = RemoveRoot(root);
    let (mut login, _) = protocol.factory(false);
    let mut discovery = WizardDiscovery {
        address: protocol.address,
    };
    let mut terminal = Terminal::new(&[
        "browserfixture",
        "",
        "browser",
        "headless",
        AUTH_CODE,
        "discover",
        "1",
        "yes",
        "family/raw",
        "no",
    ]);
    terminal.challenge = Some(protocol.challenge.clone());
    assert!(matches!(
        collect_onboarding_with_services(
            &home,
            Some("openrouter"),
            &mut terminal,
            &mut discovery,
            &mut login
        ),
        Err(OnboardingError::Canceled)
    ));
    assert!(!home.exists() && protocol.count() == 2);
    assert_private_output(&terminal.output);
}

fn official_existing(fixture: &Fixture) {
    let mut provider = fixture.provider.clone();
    provider.url = OPENROUTER_PROVIDER_URL.into();
    apply_setup(
        &plan_setup(
            &fixture.home,
            &SetupRequest {
                provider: Some(provider.clone()),
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap();
    fixture
        .store()
        .save(
            &auth_identity(&provider),
            SecretBytes::new(OLD_KEY.as_bytes().to_vec()),
            ExpectedRevision::Absent,
        )
        .unwrap();
}
fn browser_request() -> ProviderLoginRequest {
    ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Browser),
        mode: LoginMode::Headless,
        open_browser: false,
    }
}

#[test]
fn cancel_headless_input_preserves_existing_identity_config_and_all_old_key_bytes() {
    let fixture = Fixture::new(true);
    official_existing(&fixture);
    let protocol = ProtocolFixture::new(true);
    let (mut login, _) = protocol.factory(false);
    let before = snapshot(&fixture.home);
    let mut terminal = Terminal::new(&[]);
    terminal.challenge = Some(protocol.challenge.clone());
    assert!(matches!(
        collect_provider_login_with_services(
            &fixture.home,
            "fixture",
            &browser_request(),
            &mut terminal,
            &mut login
        ),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&fixture.home), before);
    assert_eq!(protocol.count(), 0);
    assert_private_output(&terminal.output);
}

#[test]
fn failed_browser_exchange_preserves_existing_files_and_reports_no_secret_response() {
    let fixture = Fixture::new(true);
    official_existing(&fixture);
    let protocol = ProtocolFixture::new(false);
    let (mut login, _) = protocol.factory(false);
    let before = snapshot(&fixture.home);
    let mut terminal = Terminal::new(&[AUTH_CODE]);
    terminal.challenge = Some(protocol.challenge.clone());
    assert!(matches!(
        collect_provider_login_with_services(
            &fixture.home,
            "fixture",
            &browser_request(),
            &mut terminal,
            &mut login
        ),
        Err(OnboardingError::Login(LoginError::HttpStatus(401)))
    ));
    assert_eq!(snapshot(&fixture.home), before);
    assert_eq!(protocol.count(), 1);
    assert_private_output(&terminal.output);
}

#[test]
fn successful_browser_exchange_stays_unpublished_when_existing_login_is_declined() {
    let fixture = Fixture::new(true);
    official_existing(&fixture);
    let protocol = ProtocolFixture::new(true);
    let (mut login, _) = protocol.factory(false);
    let before = snapshot(&fixture.home);
    let mut terminal = Terminal::new(&[AUTH_CODE, "no"]);
    terminal.challenge = Some(protocol.challenge.clone());
    assert!(matches!(
        collect_provider_login_with_services(
            &fixture.home,
            "fixture",
            &browser_request(),
            &mut terminal,
            &mut login
        ),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&fixture.home), before);
    assert_eq!(protocol.count(), 1);
    assert_private_output(&terminal.output);
}

#[test]
fn fresh_key_login_refuses_stale_config_without_publishing_new_reference() {
    let fixture = Fixture::new(true);
    let mut terminal = Terminal::new(&[NEW_KEY, "yes"]);
    let draft =
        collect_provider_login(&fixture.home, "fixture", &key_request(), &mut terminal).unwrap();
    let path = fixture.home.join("providers.toml");
    let mut config = std::fs::read_to_string(&path).unwrap();
    config.push_str("\n[concurrent]\nchanged=true\n");
    std::fs::write(&path, config).unwrap();
    let expected = snapshot(&fixture.home);
    assert!(matches!(
        commit_onboarding(draft),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(snapshot(&fixture.home), expected);
    assert!(
        fixture
            .store()
            .resolve_with(&fixture.identity(), |_| Ok(None))
            .unwrap()
            .into_secret()
            .unwrap()
            .expose()
            == OLD_KEY.as_bytes()
    );
}

#[test]
fn consumed_typed_test_factory_refuses_instead_of_falling_back_to_production() {
    let protocol = ProtocolFixture::new(true);
    let (mut factory, _) = protocol.factory(false);
    let mut provider = Fixture::new(false).provider.clone();
    provider.url = OPENROUTER_PROVIDER_URL.into();
    drop(factory.open(&provider, LoginMode::Headless).unwrap());
    assert!(matches!(
        factory.open(&provider, LoginMode::Headless),
        Err(OnboardingError::Invalid(_))
    ));
    assert_eq!(protocol.count(), 0);
}

#[test]
fn generic_terminal_fails_closed_when_bounded_hidden_input_is_not_implemented() {
    struct UnboundedTerminal;
    impl SetupTerminal for UnboundedTerminal {
        fn message(&mut self, _: &str) -> Result<(), OnboardingError> {
            Ok(())
        }
        fn line(&mut self, _: &str, _: usize) -> Result<String, OnboardingError> {
            panic!("unbounded input called")
        }
        fn hidden(&mut self, _: &str, _: usize) -> Result<SecretBytes, OnboardingError> {
            panic!("unbounded hidden input called")
        }
    }
    assert!(matches!(
        UnboundedTerminal.hidden_until("code", 4096, Instant::now() + Duration::from_secs(1)),
        Err(OnboardingError::Invalid(_))
    ));
}

#[test]
#[ignore = "real terminal deadline helper invoked by its parent test"]
fn hidden_deadline_child() {
    if std::env::var_os("ORBIT_LOGIN_DEADLINE_CHILD").is_none() {
        return;
    }
    let mut terminal = orbit_cli::onboarding::StdSetupTerminal::new().unwrap();
    assert!(matches!(
        terminal.hidden_until(
            "Deadline code (hidden): ",
            4096,
            Instant::now() + Duration::from_millis(600)
        ),
        Err(OnboardingError::Login(LoginError::DeadlineExceeded))
    ));
}

#[test]
#[allow(unsafe_code)] // Owned test PTY descriptors and borrowed terminal attributes only.
fn actual_terminal_expires_partial_hidden_code_without_echo_and_restores_attributes() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty writes two live integers, optional name/termios/winsize
    // outputs are null, and successful descriptors are immediately owned below.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: each successful openpty descriptor is unique and transferred once.
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    // SAFETY: slave is the other unique live descriptor returned by openpty.
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let attributes = || {
        let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: slave remains open and attributes is a correctly aligned,
        // writable termios output. Initialization is assumed only on success.
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), attributes.as_mut_ptr()) },
            0
        );
        // SAFETY: successful tcgetattr initialized the complete output aggregate.
        let attributes = unsafe { attributes.assume_init() };
        (
            attributes.c_iflag,
            attributes.c_oflag,
            attributes.c_cflag,
            attributes.c_lflag,
            attributes.c_cc,
            attributes.c_ispeed,
            attributes.c_ospeed,
        )
    };
    let original = attributes();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "hidden_deadline_child",
            "--nocapture",
        ])
        .env_clear()
        .env("ORBIT_LOGIN_DEADLINE_CHILD", "1")
        .env("TERM", "xterm")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    let mut child = ChildGuard(Some(command.spawn().unwrap()));
    let end = Instant::now() + Duration::from_secs(4);
    let mut output = Vec::new();
    let mut sent = false;
    loop {
        let mut ready = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: ready is one writable pollfd, master is borrowed and stays open.
        let result = unsafe { libc::poll(&mut ready, 1, 20) };
        assert!(result >= 0);
        if result > 0 && ready.revents & libc::POLLIN != 0 {
            let mut buffer = [0u8; 4096];
            let count = master.read(&mut buffer).unwrap();
            output.extend_from_slice(&buffer[..count]);
            assert!(output.len() <= 32768);
        }
        if !sent
            && output
                .windows(b"Deadline code (hidden): ".len())
                .any(|window| window == b"Deadline code (hidden): ")
        {
            master.write_all(&[b'z'; 768]).unwrap();
            sent = true;
        }
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < end,
            "hidden input did not expire without a newline"
        );
    }
    assert!(sent);
    assert_eq!(attributes(), original);
    assert!(!output.windows(64).any(|window| window == [b'z'; 64]));
}
