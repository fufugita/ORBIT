#![cfg(target_os = "linux")]
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::ProviderCredentialError;
use orbit_adapter::provider_credentials::{ProviderCredentialSource, ProviderCredentialStore};
use orbit_cli::config::ProvidersConfig;
use orbit_cli::onboarding::{
    OnboardingError, SetupTerminal, collect_onboarding, commit_onboarding, parse_manual_models,
};
use orbit_cli::setup::{SetupRequest, apply_setup, plan_setup};
use std::collections::{BTreeMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SECRET: &str = "synthetic-onboarding-private-key-984713";
struct Fixture {
    root: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-onboarding-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            home: root.join("home"),
            root,
        }
    }
    fn init(&self) {
        apply_setup(&plan_setup(&self.home, &SetupRequest::default()).unwrap()).unwrap();
    }
    fn config(&self) -> ProvidersConfig {
        ProvidersConfig::load_from_str(
            &std::fs::read_to_string(self.home.join("providers.toml")).unwrap(),
        )
        .unwrap()
    }
    fn write_config(&self, value: &str) {
        let path = self.home.join("providers.toml");
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn snapshot(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        if !path.exists() {
            return;
        }
        for child in std::fs::read_dir(path).unwrap() {
            let path = child.unwrap().path();
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
    visit(path, path, &mut result);
    result
}

struct Terminal {
    input: VecDeque<String>,
    output: String,
}
impl Terminal {
    fn new(values: &[&str]) -> Self {
        Self {
            input: values.iter().map(|s| s.to_string()).collect(),
            output: String::new(),
        }
    }
    fn next(&mut self, max: usize) -> Result<String, OnboardingError> {
        let value = self.input.pop_front().ok_or(OnboardingError::Canceled)?;
        if value.len() > max {
            return Err(OnboardingError::Invalid("Input exceeds its byte limit"));
        }
        Ok(value)
    }
}
impl SetupTerminal for Terminal {
    fn message(&mut self, text: &str) -> Result<(), OnboardingError> {
        self.output.push_str(text);
        self.output.push('\n');
        Ok(())
    }
    fn line(&mut self, prompt: &str, max: usize) -> Result<String, OnboardingError> {
        self.output.push_str(prompt);
        self.next(max)
    }
    fn hidden(&mut self, prompt: &str, max: usize) -> Result<SecretBytes, OnboardingError> {
        self.output.push_str(prompt);
        Ok(SecretBytes::new(self.next(max)?.into_bytes()))
    }
}
fn key_answers() -> Vec<&'static str> {
    vec![
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        SECRET,
        "manual",
        "family/raw,other/raw",
        "yes",
        "family/raw",
        "yes",
    ]
}
fn env_answers() -> Vec<&'static str> {
    vec![
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "env",
        "FIXTURE_ONBOARDING_ABSENT",
        "manual",
        "family/raw",
        "yes",
        "family/raw",
        "yes",
    ]
}

#[test]
fn commit_private_key_and_qualified_main_survive_new_resolver() {
    let f = Fixture::new();
    let mut terminal = Terminal::new(&key_answers());
    let draft = collect_onboarding(&f.home, None, &mut terminal).unwrap();
    assert!(!f.home.exists());
    let id = draft.auth_identity().unwrap();
    let reference = draft.provider().env.clone().unwrap();
    assert!(reference.starts_with("ORBIT_AUTH_"));
    let receipt = commit_onboarding(draft).unwrap();
    assert!(receipt.setup.initialized);
    assert_eq!(receipt.main.as_deref(), Some("fixture/family/raw"));
    let config = f.config();
    assert_eq!(config.roles.main, "fixture/family/raw");
    assert_eq!(config.provider[0].models[0].id, "family/raw");
    assert!(config.provider[0].models[0].supported_efforts.is_none());
    let resolved = ProviderCredentialStore::new(&f.home)
        .unwrap()
        .resolve_with(&id, |_| Ok(None))
        .unwrap();
    assert_eq!(resolved.source(), ProviderCredentialSource::Saved);
    assert_eq!(resolved.into_secret().unwrap().expose(), SECRET.as_bytes());
    assert!(!terminal.output.contains(SECRET));
    assert!(!serde_json::to_string(&receipt).unwrap().contains(SECRET));
    for (path, data) in snapshot(&f.home) {
        if !path.starts_with("auth/providers") {
            assert!(
                !data
                    .windows(SECRET.len())
                    .any(|part| part == SECRET.as_bytes())
            );
        }
    }
    for file in std::fs::read_dir(f.home.join("auth/providers")).unwrap() {
        assert_eq!(
            file.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn commit_missing_env_keeps_actionable_reference_without_inventing_auth() {
    let f = Fixture::new();
    let mut terminal = Terminal::new(&env_answers());
    let receipt =
        commit_onboarding(collect_onboarding(&f.home, None, &mut terminal).unwrap()).unwrap();
    assert!(!receipt.credential_ready);
    assert_eq!(receipt.credential_source, "environment reference");
    assert_eq!(
        f.config().provider[0].env.as_deref(),
        Some("FIXTURE_ONBOARDING_ABSENT")
    );
    assert!(!f.home.join("auth").exists());
    assert!(terminal.output.contains("Connectivity: not tested"));
}

#[test]
fn commit_canceled_at_every_prompt_preserves_fresh_home_absence() {
    let values = key_answers();
    for end in 0..values.len() {
        let f = Fixture::new();
        let mut terminal = Terminal::new(&values[..end]);
        assert!(matches!(
            collect_onboarding(&f.home, None, &mut terminal),
            Err(OnboardingError::Canceled)
        ));
        assert!(!f.home.exists(), "cancellation boundary {end}");
        assert!(!terminal.output.contains(SECRET));
    }
}

#[test]
fn commit_final_empty_or_declined_answer_is_not_consent() {
    for last in ["", "no"] {
        let f = Fixture::new();
        let mut values = key_answers();
        *values.last_mut().unwrap() = last;
        assert!(matches!(
            collect_onboarding(&f.home, None, &mut Terminal::new(&values)),
            Err(OnboardingError::Canceled)
        ));
        assert!(!f.home.exists());
    }
}

#[test]
fn commit_existing_identity_preserved_after_secret_then_eof() {
    let f = Fixture::new();
    f.init();
    let before = snapshot(&f.home);
    let mut values = key_answers();
    values.truncate(6);
    assert!(matches!(
        collect_onboarding(&f.home, None, &mut Terminal::new(&values)),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&f.home), before);
}

#[test]
fn commit_stale_revision_refuses_before_private_record_creation() {
    let f = Fixture::new();
    f.init();
    let draft = collect_onboarding(&f.home, None, &mut Terminal::new(&key_answers())).unwrap();
    f.write_config("[unrelated]\nchanged = true\n");
    let before = snapshot(&f.home);
    assert!(matches!(
        commit_onboarding(draft),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(snapshot(&f.home), before);
    assert!(!f.home.join("auth").exists());
}

#[test]
fn commit_provider_replacement_requires_separate_yes() {
    let f = Fixture::new();
    commit_onboarding(
        collect_onboarding(&f.home, None, &mut Terminal::new(&env_answers())).unwrap(),
    )
    .unwrap();
    let before = snapshot(&f.home);
    let mut terminal = Terminal::new(&["custom", "fixture", "no"]);
    assert!(matches!(
        collect_onboarding(&f.home, None, &mut terminal),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&f.home), before);
    assert!(!terminal.output.contains("API key"));
}

#[test]
fn commit_main_replacement_decline_preserves_whole_config() {
    let f = Fixture::new();
    commit_onboarding(
        collect_onboarding(&f.home, None, &mut Terminal::new(&env_answers())).unwrap(),
    )
    .unwrap();
    let before = snapshot(&f.home);
    let values = [
        "custom",
        "second",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "manual",
        "new/raw",
        "yes",
        "new/raw",
        "no",
    ];
    assert!(matches!(
        collect_onboarding(&f.home, None, &mut Terminal::new(&values)),
        Err(OnboardingError::Canceled)
    ));
    assert_eq!(snapshot(&f.home), before);
}

#[test]
fn commit_replacement_merges_existing_models_metadata_and_unrelated_settings() {
    let f = Fixture::new();
    f.init();
    f.write_config(
        r#"
[unrelated]
keep = "unchanged"
[roles]
main = "fixture/family/raw"
subagent = "fixture/family/raw"
[[provider]]
name = "fixture"
kind = "openai-compatible"
url = "http://127.0.0.1:9/v1"
[[provider.models]]
id = "family/raw"
label = "Preserved"
context_window = 64000
max_output_tokens = 8000
supported_efforts = []
vendor_hint = "retained-model-extension"
[provider.models.sampling]
temperature = 0.3
vendor_sampling_hint = "retained-sampling-extension"
[provider.models.pricing]
input_per_million_microdollars = 123
vendor_pricing_hint = "retained-pricing-extension"
"#,
    );
    let identity_before = std::fs::read(f.home.join("pib.json")).unwrap();
    let model_before = f.config().provider[0].models[0].clone();
    let values = [
        "custom",
        "fixture",
        "yes",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "manual",
        "family/raw,new/raw",
        "no",
        "yes",
    ];
    commit_onboarding(collect_onboarding(&f.home, None, &mut Terminal::new(&values)).unwrap())
        .unwrap();
    let cfg = f.config();
    assert_eq!(cfg.provider[0].models[0], model_before);
    assert_eq!(cfg.provider[0].models[1].id, "new/raw");
    assert_eq!(cfg.roles.main, "fixture/family/raw");
    assert_eq!(cfg.roles.subagent, "fixture/family/raw");
    assert_eq!(
        std::fs::read(f.home.join("pib.json")).unwrap(),
        identity_before
    );
    let value: toml::Value =
        toml::from_str(&std::fs::read_to_string(f.home.join("providers.toml")).unwrap()).unwrap();
    assert_eq!(value["unrelated"]["keep"].as_str(), Some("unchanged"));
    let raw_model = &value["provider"][0]["models"][0];
    assert_eq!(
        raw_model["vendor_hint"].as_str(),
        Some("retained-model-extension")
    );
    assert_eq!(
        raw_model["pricing"]["vendor_pricing_hint"].as_str(),
        Some("retained-pricing-extension")
    );
    assert_eq!(
        raw_model["sampling"]["vendor_sampling_hint"].as_str(),
        Some("retained-sampling-extension")
    );
    assert_eq!(raw_model["supported_efforts"].as_array().unwrap().len(), 0);
}

#[test]
fn commit_invalid_endpoint_or_key_never_initializes() {
    for endpoint in [
        "relative/path",
        "https://user:password@example.invalid",
        "https://example.invalid?api_key=synthetic",
    ] {
        let f = Fixture::new();
        let values = ["custom", "fixture", "openai-compatible", endpoint];
        assert!(collect_onboarding(&f.home, None, &mut Terminal::new(&values)).is_err());
        assert!(!f.home.exists());
    }
    for key in ["", " ", "control\nkey"] {
        let f = Fixture::new();
        let mut values = key_answers();
        values[5] = key;
        assert!(collect_onboarding(&f.home, None, &mut Terminal::new(&values)).is_err());
        assert!(!f.home.exists());
    }
}

#[test]
fn commit_raw_model_parser_preserves_slashes_and_unknown_metadata() {
    let models = parse_manual_models("owner/family/model,second/id").unwrap();
    assert_eq!(models[0].id, "owner/family/model");
    assert!(models[0].context_window.is_none());
    assert!(models[0].supported_efforts.is_none());
    for invalid in ["", "same,same", "a,,b", "with space", "control\nvalue"] {
        assert!(parse_manual_models(invalid).is_err());
    }
}

#[test]
fn commit_explicit_no_auth_does_not_read_or_create_private_binding() {
    let f = Fixture::new();
    let values = [
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "manual",
        "family/raw",
        "no",
        "yes",
    ];
    let draft = collect_onboarding(&f.home, None, &mut Terminal::new(&values)).unwrap();
    assert_eq!(
        draft.resolve_credential().unwrap().source(),
        ProviderCredentialSource::None
    );
    let receipt = commit_onboarding(draft).unwrap();
    assert_eq!(receipt.credential_source, "no authentication");
    assert!(f.config().provider[0].env.is_none());
    assert!(!f.home.join("auth").exists());
}

#[test]
fn commit_nested_credential_publication_uncertainty_has_recovery_error_code() {
    let error = OnboardingError::Credential(ProviderCredentialError::PublicationUncertain);
    assert_eq!(error.code(), "ORBIT-E1105");
    assert_eq!(OnboardingError::PublicationUncertain.code(), "ORBIT-E1105");
    assert_eq!(
        OnboardingError::Credential(ProviderCredentialError::InvalidKey).code(),
        "ORBIT-E1101"
    );
    assert!(!error.to_string().contains(SECRET));
}
