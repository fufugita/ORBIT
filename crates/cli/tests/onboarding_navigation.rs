#![cfg(target_os = "linux")]
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, ProviderAuthIdentity, ProviderCredentialRevision, ProviderCredentialSource,
    ProviderCredentialStatus, ProviderCredentialStore,
};
use orbit_cli::config::{ProviderConfig, ProvidersConfig};
use orbit_cli::onboarding::*;
use orbit_cli::provider_discovery::*;
use orbit_cli::setup::{SetupRequest, apply_setup, plan_setup};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

const SECRET: &str = "synthetic-navigation-private-key-736182";
struct Fixture {
    root: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-navigation-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            home: root.join("home"),
            root,
        }
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

struct Terminal {
    input: VecDeque<String>,
    output: String,
    hidden_reads: usize,
    first_review: Option<Box<dyn FnOnce()>>,
}
impl Terminal {
    fn new(values: &[&str]) -> Self {
        Self {
            input: values.iter().map(|v| (*v).to_owned()).collect(),
            output: String::new(),
            hidden_reads: 0,
            first_review: None,
        }
    }
    fn read(&mut self, max: usize) -> Result<String, OnboardingError> {
        let next = self.input.pop_front().ok_or(OnboardingError::Canceled)?;
        if next.len() > max {
            return Err(OnboardingError::Invalid("Synthetic input exceeds bounds"));
        }
        Ok(next)
    }
}
impl SetupTerminal for Terminal {
    fn message(&mut self, value: &str) -> Result<(), OnboardingError> {
        self.output.push_str(value);
        self.output.push('\n');
        Ok(())
    }
    fn line(&mut self, prompt: &str, max: usize) -> Result<String, OnboardingError> {
        self.output.push_str(prompt);
        if prompt.starts_with("Save provider")
            && let Some(action) = self.first_review.take()
        {
            action();
        }
        self.read(max)
    }
    fn hidden(&mut self, prompt: &str, max: usize) -> Result<SecretBytes, OnboardingError> {
        self.output.push_str(prompt);
        self.hidden_reads += 1;
        Ok(SecretBytes::new(self.read(max)?.into_bytes()))
    }
    fn hidden_until(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Instant,
    ) -> Result<SecretBytes, OnboardingError> {
        assert!(Instant::now() < deadline);
        self.hidden(prompt, max)
    }
}

#[derive(Default, Debug)]
struct Calls {
    open: usize,
    catalog: usize,
    details: usize,
    login: usize,
    exchange: usize,
    browser: usize,
    draft_bound: bool,
}
struct Discovery {
    calls: Rc<RefCell<Calls>>,
    allow: bool,
}
struct Catalog {
    calls: Rc<RefCell<Calls>>,
}
impl ModelDiscoveryFactory for Discovery {
    fn open(
        &mut self,
        _home: &Path,
        provider: &ProviderConfig,
        _profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
    ) -> Result<Box<dyn ModelDiscovery>, OnboardingError> {
        assert!(
            self.allow,
            "manual navigation must never initiate discovery"
        );
        let expected = ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            &provider.url,
            provider.env.as_deref(),
        )
        .unwrap();
        let mut calls = self.calls.borrow_mut();
        calls.open += 1;
        calls.draft_bound = draft.is_some_and(|(identity, key)| {
            *identity == expected && key.expose() == SECRET.as_bytes()
        });
        Ok(Box::new(Catalog {
            calls: self.calls.clone(),
        }))
    }
}
fn observed() -> DiscoveredModel {
    DiscoveredModel {
        id: "family/raw".into(),
        label: Some("Fixture model".into()),
        context_window: Some(32000),
        max_output_tokens: Some(4000),
        source: MetadataSource::GenericOpenAiModels,
        metadata_valid: true,
        unrecognized_fields: Vec::new(),
        evidence: None,
    }
}
impl ModelDiscovery for Catalog {
    fn credential_source(&self) -> ProviderCredentialSource {
        ProviderCredentialSource::Draft
    }
    fn catalog(&mut self) -> Result<DiscoveredCatalog, OnboardingError> {
        self.calls.borrow_mut().catalog += 1;
        Ok(DiscoveredCatalog {
            models: vec![observed()],
            completeness: DiscoveryCompleteness::Complete,
            issues: Vec::new(),
            pages_fetched: 1,
        })
    }
    fn details(
        &mut self,
        selected: &[DiscoveredModel],
        refresh: bool,
    ) -> Result<DiscoveredDetails, OnboardingError> {
        assert!(!refresh);
        self.calls.borrow_mut().details += 1;
        Ok(DiscoveredDetails {
            models: selected.to_vec(),
            completeness: DiscoveryCompleteness::Complete,
            issues: Vec::new(),
            considered: selected.len(),
            attempted: 0,
        })
    }
}
struct Login {
    calls: Rc<RefCell<Calls>>,
    allow: bool,
}
struct Authorization {
    calls: Rc<RefCell<Calls>>,
    url: url::Url,
}
impl LoginServiceFactory for Login {
    fn open(
        &mut self,
        _provider: &ProviderConfig,
        mode: provider_login::LoginMode,
    ) -> Result<Box<dyn LoginService>, OnboardingError> {
        assert!(
            self.allow,
            "navigation must not implicitly initiate sign-in"
        );
        assert_eq!(mode, provider_login::LoginMode::Headless);
        self.calls.borrow_mut().login += 1;
        Ok(Box::new(Authorization {
            calls: self.calls.clone(),
            url: url::Url::parse("https://provider.example/authorize").unwrap(),
        }))
    }
}
impl LoginService for Authorization {
    fn authorization_url(&self) -> &url::Url {
        &self.url
    }
    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn open_browser(&mut self) -> Result<provider_login::BrowserOpenOutcome, OnboardingError> {
        self.calls.borrow_mut().browser += 1;
        Ok(provider_login::BrowserOpenOutcome::ManualOpenRequired)
    }
    fn finish_callback(&mut self) -> Result<SecretBytes, OnboardingError> {
        panic!("headless fixture must not wait for a callback")
    }
    fn finish_headless(&mut self, code: SecretBytes) -> Result<SecretBytes, OnboardingError> {
        assert_eq!(code.expose(), b"synthetic-code");
        self.calls.borrow_mut().exchange += 1;
        Ok(SecretBytes::new(SECRET.as_bytes().to_vec()))
    }
}
fn services(allow_discovery: bool, allow_login: bool) -> (Discovery, Login, Rc<RefCell<Calls>>) {
    let calls = Rc::new(RefCell::new(Calls::default()));
    (
        Discovery {
            calls: calls.clone(),
            allow: allow_discovery,
        },
        Login {
            calls: calls.clone(),
            allow: allow_login,
        },
        calls,
    )
}
fn assert_private_saved(f: &Fixture, draft: OnboardingDraft, terminal: &Terminal) {
    assert!(
        !f.home.exists(),
        "collecting an unpublished draft must not create a home"
    );
    let identity = draft.auth_identity().unwrap();
    let receipt = commit_onboarding(draft).unwrap();
    let credential = ProviderCredentialStore::new(&f.home)
        .unwrap()
        .resolve_with(&identity, |_| Ok(None))
        .unwrap();
    assert_eq!(
        credential.into_secret().unwrap().expose(),
        SECRET.as_bytes()
    );
    assert!(!terminal.output.contains(SECRET));
    assert!(!serde_json::to_string(&receipt).unwrap().contains(SECRET));
}

fn seed_existing_provider(
    fixture: &Fixture,
) -> (
    ProviderConfig,
    ProviderAuthIdentity,
    ProviderCredentialRevision,
) {
    let config = ProvidersConfig::load_from_str(
        r#"
[[provider]]
name = "fixture"
kind = "openai-compatible"
url = "https://provider.example/v1"
env = "ORBIT_AUTH_OLD"

[[provider.models]]
id = "model"
"#,
    )
    .unwrap();
    config.save_atomic(&fixture.home).unwrap();
    apply_setup(&plan_setup(&fixture.home, &SetupRequest::default()).unwrap()).unwrap();
    let provider = config.provider[0].clone();
    let identity = ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap();
    let saved = ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .save(
            &identity,
            SecretBytes::new(b"synthetic-old-credential-6418".to_vec()),
            ExpectedRevision::Absent,
        )
        .unwrap();
    (provider, identity, saved.revision)
}

fn saved_status(fixture: &Fixture, identity: &ProviderAuthIdentity) -> ProviderCredentialStatus {
    ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .status_read_only_with(identity, |_| Ok(None))
}

#[test]
fn saved_key_env_collision_is_corrected_before_secret_entry_and_publication() {
    let fixture = Fixture::new();
    let (_old_provider, old_identity, old_revision) = seed_existing_provider(&fixture);
    let new_env = format!("ORBIT_AUTH_NEXT_{}", ulid::Ulid::new());
    let (mut discovery, mut login, calls) = services(false, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "yes",
        "openai-compatible",
        "https://provider.example/v1",
        "key-env",
        "ORBIT_AUTH_OLD",
        "retry",
        &new_env,
        SECRET,
        "manual",
        "model-v2",
        "no",
        "yes",
    ]);

    let draft = collect_onboarding_with_services(
        &fixture.home,
        None,
        &mut terminal,
        &mut discovery,
        &mut login,
    )
    .unwrap();

    assert!(
        terminal
            .output
            .contains("Choose a new private credential ENV name to rotate a saved key")
    );
    assert_eq!(terminal.hidden_reads, 1);
    assert_eq!(
        (
            calls.borrow().open,
            calls.borrow().catalog,
            calls.borrow().login
        ),
        (0, 0, 0)
    );
    assert!(matches!(
        saved_status(&fixture, &old_identity),
        ProviderCredentialStatus::Available { revision, .. } if revision == Some(old_revision)
    ));
    assert!(!terminal.output.contains(SECRET));
    assert_eq!(draft.provider().env.as_deref(), Some(new_env.as_str()));
    assert!(terminal.input.is_empty());

    commit_onboarding(draft).unwrap();

    assert!(matches!(
        saved_status(&fixture, &old_identity),
        ProviderCredentialStatus::Missing
    ));
    let new_identity = ProviderAuthIdentity::new(
        "fixture",
        "openai-compatible",
        "https://provider.example/v1",
        Some(&new_env),
    )
    .unwrap();
    assert!(matches!(
        saved_status(&fixture, &new_identity),
        ProviderCredentialStatus::Available { .. }
    ));
}

#[test]
fn provider_key_rotation_retires_old_record_only_after_new_config_is_published() {
    let fixture = Fixture::new();
    let (_old_provider, old_identity, _old_revision) = seed_existing_provider(&fixture);
    let mut terminal = Terminal::new(&["synthetic-new-credential-9821", "yes"]);
    let request = ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Key),
        mode: provider_login::LoginMode::Loopback,
        open_browser: false,
    };
    let (_discovery, mut login, _) = services(false, false);
    let draft = collect_provider_login_with_services(
        &fixture.home,
        "fixture",
        &request,
        &mut terminal,
        &mut login,
    )
    .unwrap();
    let new_env = draft.provider().env.clone().unwrap();
    let new_identity = ProviderAuthIdentity::new(
        &draft.provider().name,
        &draft.provider().kind,
        &draft.provider().url,
        Some(&new_env),
    )
    .unwrap();
    assert_ne!(new_identity, old_identity);

    commit_onboarding(draft).unwrap();

    assert!(matches!(
        saved_status(&fixture, &old_identity),
        ProviderCredentialStatus::Missing
    ));
    let new_credential = ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .resolve_with(&new_identity, |_| Ok(None))
        .unwrap();
    assert_eq!(
        new_credential.into_secret().unwrap().expose(),
        b"synthetic-new-credential-9821"
    );
    assert_eq!(
        fixture.config().provider[0].env.as_deref(),
        Some(new_env.as_str())
    );
    assert!(!terminal.output.contains("synthetic-new-credential-9821"));
}

#[test]
fn provider_login_revision_drift_is_stale_and_preserves_both_records() {
    let fixture = Fixture::new();
    let (_old_provider, old_identity, original_revision) = seed_existing_provider(&fixture);
    let mut terminal = Terminal::new(&["synthetic-new-credential-9821", "yes"]);
    let request = ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Key),
        mode: provider_login::LoginMode::Loopback,
        open_browser: false,
    };
    let (_discovery, mut login, _) = services(false, false);
    let draft = collect_provider_login_with_services(
        &fixture.home,
        "fixture",
        &request,
        &mut terminal,
        &mut login,
    )
    .unwrap();
    let new_identity = ProviderAuthIdentity::new(
        &draft.provider().name,
        &draft.provider().kind,
        &draft.provider().url,
        draft.provider().env.as_deref(),
    )
    .unwrap();

    let changed = ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .save(
            &old_identity,
            SecretBytes::new(b"synthetic-newer-old-credential-1137".to_vec()),
            ExpectedRevision::Exact(original_revision),
        )
        .unwrap();
    assert_ne!(changed.revision, original_revision);

    assert!(matches!(
        commit_onboarding(draft),
        Err(OnboardingError::Stale)
    ));
    assert!(matches!(
        saved_status(&fixture, &old_identity),
        ProviderCredentialStatus::Available {
            revision: Some(revision),
            ..
        } if revision == changed.revision
    ));
    assert!(matches!(
        saved_status(&fixture, &new_identity),
        ProviderCredentialStatus::Missing
    ));
}

#[test]
fn canceling_provider_key_rotation_keeps_the_old_private_record() {
    let fixture = Fixture::new();
    let (_old_provider, old_identity, old_revision) = seed_existing_provider(&fixture);
    let mut terminal = Terminal::new(&["synthetic-new-credential-9821", "no"]);
    let request = ProviderLoginRequest {
        method: Some(ProviderLoginMethod::Key),
        mode: provider_login::LoginMode::Loopback,
        open_browser: false,
    };
    let (_discovery, mut login, _) = services(false, false);
    assert!(matches!(
        collect_provider_login_with_services(
            &fixture.home,
            "fixture",
            &request,
            &mut terminal,
            &mut login,
        ),
        Err(OnboardingError::Canceled)
    ));
    assert!(matches!(
        saved_status(&fixture, &old_identity),
        ProviderCredentialStatus::Available {
            revision: Some(revision),
            ..
        } if revision == old_revision
    ));
}

#[test]
fn numbered_selector_preserves_exact_identity_before_aliases_or_labels() {
    let mut terminal = Terminal::new(&["Display only", "2"]);
    let choices = [
        SetupChoice {
            id: "2",
            label: "Numeric identity",
            detail: None,
        },
        SetupChoice {
            id: "other",
            label: "Display only",
            detail: None,
        },
    ];
    assert_eq!(
        terminal.select("Pick", &choices, None, false).unwrap(),
        SetupSelection::Chosen("2".into())
    );
    assert!(terminal.output.contains("Choose an offered"));
}
#[test]
fn numbered_selector_current_back_cancel_and_eof_are_explicit() {
    let choices = [SetupChoice {
        id: "provider/raw",
        label: "Model",
        detail: None,
    }];
    assert_eq!(
        Terminal::new(&[""])
            .select("Pick", &choices, Some("provider/raw"), true)
            .unwrap(),
        SetupSelection::Chosen("provider/raw".into())
    );
    assert_eq!(
        Terminal::new(&["", "back"])
            .select("Pick", &choices, None, true)
            .unwrap(),
        SetupSelection::Back
    );
    assert_eq!(
        Terminal::new(&["cancel"])
            .select("Pick", &choices, None, false)
            .unwrap(),
        SetupSelection::Canceled
    );
    assert!(matches!(
        Terminal::new(&[]).select("Pick", &choices, None, true),
        Err(OnboardingError::Canceled)
    ));
}
#[test]
fn choice_labels_cannot_inject_terminal_controls_or_change_selected_identity() {
    let choices = [SetupChoice {
        id: "provider/raw",
        label: "bad\x1b[31m\nlabel\u{202e}",
        detail: Some("description\x07"),
    }];
    let mut terminal = Terminal::new(&["1"]);
    assert_eq!(
        terminal.select("Pick", &choices, None, false).unwrap(),
        SetupSelection::Chosen("provider/raw".into())
    );
    assert!(!terminal.output.contains('\x1b'));
    assert!(!terminal.output.contains('\x07'));
    assert!(!terminal.output.contains('\u{202e}'));
}
#[test]
fn discovery_back_and_keep_preserve_one_catalog_and_exact_private_binding() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(true, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "discover",
        "generic",
        "1",
        "yes",
        "family/raw",
        "back",
        "back",
        "back",
        "keep",
        "keep",
        "keep",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    let calls = calls.borrow();
    assert_eq!(
        (calls.open, calls.catalog, calls.details, calls.login),
        (1, 1, 1, 0)
    );
    assert!(calls.draft_bound);
    assert_eq!(terminal.hidden_reads, 1);
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
    assert_eq!(f.config().roles.main, "fixture/family/raw");
}
#[test]
fn browser_back_and_keep_do_not_reopen_or_exchange_authorization() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(false, true);
    let mut terminal = Terminal::new(&[
        "openrouter",
        "",
        "",
        "browser",
        "headless",
        "synthetic-code",
        "manual",
        "family/raw",
        "yes",
        "family/raw",
        "back",
        "back",
        "back",
        "keep",
        "keep",
        "keep",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    let calls = calls.borrow();
    assert_eq!(
        (calls.login, calls.exchange, calls.browser, calls.open),
        (1, 1, 0, 0)
    );
    assert_eq!(terminal.hidden_reads, 1);
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
}
#[test]
fn unchanged_identity_edit_keeps_collected_key_without_another_authentication() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(false, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "manual",
        "family/raw",
        "yes",
        "family/raw",
        "back",
        "back",
        "back",
        "back",
        "edit",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "keep",
        "keep",
        "keep",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert_eq!(terminal.hidden_reads, 1);
    assert_eq!(calls.borrow().open, 0);
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
}
#[test]
fn editing_authentication_discards_old_secret_models_and_default() {
    let f = Fixture::new();
    let (mut discovery, mut login, _) = services(false, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "manual",
        "old/raw",
        "yes",
        "old/raw",
        "back",
        "back",
        "back",
        "edit",
        "none",
        "manual",
        "new/raw",
        "yes",
        "new/raw",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert!(draft.provider().env.is_none());
    assert_eq!(draft.provider().models.len(), 1);
    assert_eq!(draft.provider().models[0].id, "new/raw");
    commit_onboarding(draft).unwrap();
    let cfg = f.config();
    assert_eq!(cfg.roles.main, "fixture/new/raw");
    assert!(cfg.provider[0].env.is_none());
    assert!(!f.home.join("auth/providers").exists());
    assert!(!terminal.output.contains(SECRET));
    assert!(terminal.input.is_empty());
}
#[test]
fn changing_provider_identity_invalidates_the_old_credential_binding() {
    let f = Fixture::new();
    let (mut discovery, mut login, _) = services(false, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "manual",
        "old/raw",
        "yes",
        "old/raw",
        "back",
        "back",
        "back",
        "back",
        "edit",
        "changed",
        "openai-compatible",
        "http://127.0.0.1:9/v2",
        "none",
        "manual",
        "new/raw",
        "no",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert_eq!(draft.provider().name, "changed");
    assert_eq!(draft.provider().url, "http://127.0.0.1:9/v2");
    assert!(draft.provider().env.is_none());
    commit_onboarding(draft).unwrap();
    assert!(f.config().roles.main.is_empty());
    assert!(!f.home.join("auth/providers").exists());
    assert!(terminal.input.is_empty());
}
#[test]
fn pure_field_and_catalog_correction_never_refetches_or_saves_a_partial_draft() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(true, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "bad-url",
        "retry",
        "http://127.0.0.1:9/v1",
        "key",
        "",
        "retry",
        SECRET,
        "discover",
        "wrong-schema",
        "retry",
        "generic",
        "0",
        "retry",
        "1",
        "yes",
        "missing/raw",
        "family/raw",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert_eq!(
        (
            calls.borrow().open,
            calls.borrow().catalog,
            calls.borrow().details
        ),
        (1, 1, 1)
    );
    assert_eq!(terminal.hidden_reads, 2);
    assert_eq!(terminal.output.matches("Provider name").count(), 1);
    assert_eq!(terminal.output.matches("Base URL").count(), 2);
    assert_eq!(terminal.output.matches("Correct this field").count(), 4);
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
}
#[test]
fn cancel_after_cached_back_navigation_keeps_an_absent_home_absent() {
    let f = Fixture::new();
    let (mut discovery, mut login, _) = services(false, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "manual",
        "family/raw",
        "no",
        "back",
        "back",
        "back",
        "cancel",
    ]);
    assert!(matches!(
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login),
        Err(OnboardingError::Canceled)
    ));
    assert!(!f.home.exists());
    assert!(!terminal.output.contains(SECRET));
}
#[test]
fn revision_drift_after_back_is_terminal_without_replaying_discovery_or_publishing_key() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(true, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "discover",
        "generic",
        "1",
        "no",
        "back",
        "keep",
    ]);
    let home = f.home.clone();
    terminal.first_review = Some(Box::new(move || {
        apply_setup(&plan_setup(&home, &SetupRequest::default()).unwrap()).unwrap();
    }));
    assert!(matches!(
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(
        (
            calls.borrow().open,
            calls.borrow().catalog,
            calls.borrow().details
        ),
        (1, 1, 1)
    );
    assert!(!f.home.join("auth/providers").exists());
    assert!(!f.home.join("providers.toml").exists());
}

#[test]
fn invalid_preset_identity_can_go_back_and_choose_a_different_provider_without_effects() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(false, false);
    let mut terminal = Terminal::new(&[
        "",
        "bad-url",
        "back",
        "custom",
        "changed",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "manual",
        "new/raw",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_services(
        &f.home,
        Some("openrouter"),
        &mut terminal,
        &mut discovery,
        &mut login,
    )
    .unwrap();
    assert_eq!(draft.provider().name, "changed");
    assert!(draft.provider().env.is_none());
    assert!(!f.home.exists());
    assert!(terminal.output.contains("Provider (name or number)"));
    assert!(terminal.input.is_empty());
    assert_eq!(terminal.hidden_reads, 0);
    assert_eq!((calls.borrow().open, calls.borrow().login), (0, 0));
    commit_onboarding(draft).unwrap();
    assert_eq!(f.config().provider[0].models[0].id, "new/raw");
    assert!(!f.home.join("auth/providers").exists());
}
#[test]
fn invalid_auth_and_manual_models_back_return_to_cached_previous_stage_without_publication() {
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "custom",
                "fixture",
                "openai-compatible",
                "http://127.0.0.1:9/v1",
                "key",
                "",
                "back",
                "cancel",
            ],
            "Provider identity draft",
        ),
        (
            &[
                "custom",
                "fixture",
                "openai-compatible",
                "http://127.0.0.1:9/v1",
                "key",
                SECRET,
                "manual",
                "",
                "back",
                "cancel",
            ],
            "Authentication draft",
        ),
    ];
    for (answers, previous_stage) in cases {
        let f = Fixture::new();
        let (mut discovery, mut login, calls) = services(false, false);
        let mut terminal = Terminal::new(answers);
        assert!(matches!(
            collect_onboarding_with_services(
                &f.home,
                None,
                &mut terminal,
                &mut discovery,
                &mut login
            ),
            Err(OnboardingError::Canceled)
        ));
        assert!(terminal.output.contains(*previous_stage));
        assert_eq!(terminal.hidden_reads, 1);
        assert!(terminal.input.is_empty());
        assert!(!f.home.exists());
        assert!(!terminal.output.contains(SECRET));
        assert_eq!((calls.borrow().open, calls.borrow().login), (0, 0));
    }
}
#[test]
fn invalid_catalog_back_keeps_authentication_but_never_repeats_discovery() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(true, false);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "discover",
        "generic",
        "0",
        "back",
        "keep",
        "manual",
        "new/raw",
        "no",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert_eq!(
        (
            calls.borrow().open,
            calls.borrow().catalog,
            calls.borrow().details,
            calls.borrow().login
        ),
        (1, 1, 0, 0)
    );
    assert_eq!(terminal.hidden_reads, 1);
    assert!(terminal.output.contains("Authentication draft"));
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
    assert_eq!(f.config().provider[0].models[0].id, "new/raw");
}
#[test]
fn invalid_default_and_review_back_preserve_completed_drafts_without_recollecting_secrets() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(false, false);
    let env_name = format!("ORBIT_REVIEW_{}", ulid::Ulid::new());
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key-env",
        &env_name,
        SECRET,
        "manual",
        "family/raw",
        "maybe",
        "back",
        "keep",
        "no",
        "maybe",
        "back",
        "keep",
        "yes",
    ]);
    let draft =
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login)
            .unwrap();
    assert_eq!(terminal.hidden_reads, 1);
    assert_eq!((calls.borrow().open, calls.borrow().login), (0, 0));
    assert!(terminal.output.contains("No authentication"));
    assert!(
        terminal
            .output
            .contains(&format!("Credential ENV name: {env_name}"))
    );
    assert!(terminal.output.contains("Models (1):\n  - family/raw"));
    assert!(!terminal.output.contains(SECRET));
    assert!(terminal.output.contains("Model selection draft"));
    assert!(terminal.output.contains("Default model draft"));
    assert_eq!(terminal.output.matches("Raw model IDs").count(), 1);
    assert!(terminal.input.is_empty());
    assert_private_saved(&f, draft, &terminal);
    assert!(f.config().roles.main.is_empty());
}

#[test]
fn hosted_provider_does_not_offer_no_authentication() {
    let f = Fixture::new();
    let (mut discovery, mut login, calls) = services(false, false);
    let mut terminal = Terminal::new(&["openrouter", "", "", "cancel"]);

    assert!(matches!(
        collect_onboarding_with_services(&f.home, None, &mut terminal, &mut discovery, &mut login),
        Err(OnboardingError::Canceled)
    ));
    assert!(!terminal.output.contains("No authentication"));
    assert_eq!(terminal.hidden_reads, 0);
    assert_eq!((calls.borrow().open, calls.borrow().login), (0, 0));
    assert!(!f.home.exists());
}
#[test]
fn cancel_at_each_pure_field_recovery_has_no_publication_or_provider_effect() {
    let cases: &[&[&str]] = &[
        &["custom", "bad name"],
        &["custom", "fixture", "openai-compatible", "bad-url"],
        &[
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "key",
            "",
        ],
        &[
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "key",
            SECRET,
            "manual",
            "",
        ],
        &[
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "key",
            SECRET,
            "manual",
            "family/raw",
            "maybe",
        ],
        &[
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "key",
            SECRET,
            "manual",
            "family/raw",
            "no",
            "maybe",
        ],
    ];
    for prefix in cases {
        let f = Fixture::new();
        let (mut discovery, mut login, calls) = services(false, false);
        let mut answers = prefix.to_vec();
        answers.push("cancel");
        let mut terminal = Terminal::new(&answers);
        assert!(matches!(
            collect_onboarding_with_services(
                &f.home,
                None,
                &mut terminal,
                &mut discovery,
                &mut login
            ),
            Err(OnboardingError::Canceled)
        ));
        assert!(terminal.output.contains("Correct this field"));
        assert!(terminal.input.is_empty());
        assert!(!f.home.exists());
        assert!(!terminal.output.contains(SECRET));
        assert_eq!((calls.borrow().open, calls.borrow().login), (0, 0));
    }
}
