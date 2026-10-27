#![cfg(target_os = "linux")]
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{ProviderAuthIdentity, ProviderCredentialSource};
use orbit_cli::config::{ModelEntry, Pricing, ProviderConfig, ProvidersConfig};
use orbit_cli::onboarding::*;
use orbit_cli::provider_discovery::*;
use orbit_cli::setup::{SetupRequest, apply_setup, plan_setup};
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("orbit-discovery-wizard-{}", ulid::Ulid::new()));
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
    fn seed(&self, provider: ProviderConfig) {
        apply_setup(
            &plan_setup(
                &self.home,
                &SetupRequest {
                    provider: Some(provider),
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// Intentionally !Send: terminal callbacks must remain with their original owner.
struct Terminal {
    input: VecDeque<String>,
    output: String,
    _owner: Rc<()>,
}
impl Terminal {
    fn new(values: &[&str]) -> Self {
        Self {
            input: values.iter().map(|value| value.to_string()).collect(),
            output: String::new(),
            _owner: Rc::new(()),
        }
    }
    fn read(&mut self, max: usize) -> Result<String, OnboardingError> {
        let value = self.input.pop_front().ok_or(OnboardingError::Canceled)?;
        if value.len() > max {
            return Err(OnboardingError::Invalid("Input exceeds bound"));
        }
        Ok(value)
    }
}
impl SetupTerminal for Terminal {
    fn message(&mut self, message: &str) -> Result<(), OnboardingError> {
        self.output.push_str(message);
        self.output.push('\n');
        Ok(())
    }
    fn line(&mut self, prompt: &str, max: usize) -> Result<String, OnboardingError> {
        self.output.push_str(prompt);
        self.read(max)
    }
    fn hidden(&mut self, prompt: &str, max: usize) -> Result<SecretBytes, OnboardingError> {
        self.output.push_str(prompt);
        Ok(SecretBytes::new(self.read(max)?.into_bytes()))
    }
}

#[derive(Clone)]
struct Opened {
    profile: DiscoveryProfile,
    provider: ProviderConfig,
    draft_present: bool,
    exact_draft: bool,
}
#[derive(Default)]
struct Capture {
    opened: Vec<Opened>,
    detail_ids: Vec<Vec<String>>,
    refresh: Vec<bool>,
    dropped: usize,
}
struct Factory {
    catalog: DiscoveredCatalog,
    details: Option<Vec<DiscoveredModel>>,
    capture: Arc<Mutex<Capture>>,
    on_catalog: Option<Box<dyn FnOnce()>>,
    fail_open: bool,
    fail_catalog: bool,
    cancel_catalog: bool,
    source: ProviderCredentialSource,
}
impl Factory {
    fn new(models: Vec<DiscoveredModel>) -> Self {
        Self {
            catalog: DiscoveredCatalog {
                models,
                completeness: DiscoveryCompleteness::Complete,
                issues: vec![],
                pages_fetched: 1,
            },
            details: None,
            capture: Arc::new(Mutex::new(Capture::default())),
            on_catalog: None,
            fail_open: false,
            fail_catalog: false,
            cancel_catalog: false,
            source: ProviderCredentialSource::None,
        }
    }
}
struct Session {
    catalog: Option<DiscoveredCatalog>,
    details: Option<Vec<DiscoveredModel>>,
    capture: Arc<Mutex<Capture>>,
    on_catalog: Option<Box<dyn FnOnce()>>,
    fail: bool,
    canceled: bool,
    source: ProviderCredentialSource,
}
impl ModelDiscoveryFactory for Factory {
    fn open(
        &mut self,
        _home: &Path,
        provider: &ProviderConfig,
        profile: DiscoveryProfile,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
    ) -> Result<Box<dyn ModelDiscovery>, OnboardingError> {
        let expected = ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            &provider.url,
            provider.env.as_deref(),
        )
        .unwrap();
        self.capture.lock().unwrap().opened.push(Opened {
            profile,
            provider: provider.clone(),
            draft_present: draft.is_some(),
            exact_draft: draft.is_none_or(|(id, _)| id == &expected),
        });
        if self.fail_open {
            return Err(OnboardingError::Invalid("Synthetic discovery unavailable"));
        }
        Ok(Box::new(Session {
            catalog: Some(self.catalog.clone()),
            details: self.details.clone(),
            capture: self.capture.clone(),
            on_catalog: self.on_catalog.take(),
            fail: self.fail_catalog,
            canceled: self.cancel_catalog,
            source: self.source,
        }))
    }
}
impl ModelDiscovery for Session {
    fn credential_source(&self) -> ProviderCredentialSource {
        self.source
    }
    fn catalog(&mut self) -> Result<DiscoveredCatalog, OnboardingError> {
        if let Some(action) = self.on_catalog.take() {
            action();
        }
        if self.canceled {
            return Err(OnboardingError::Canceled);
        }
        if self.fail {
            return Err(OnboardingError::Invalid("Synthetic catalog unavailable"));
        }
        Ok(self.catalog.take().unwrap())
    }
    fn details(
        &mut self,
        selected: &[DiscoveredModel],
        refresh: bool,
    ) -> Result<DiscoveredDetails, OnboardingError> {
        let mut capture = self.capture.lock().unwrap();
        capture
            .detail_ids
            .push(selected.iter().map(|model| model.id.clone()).collect());
        capture.refresh.push(refresh);
        Ok(DiscoveredDetails {
            models: self.details.take().unwrap_or_else(|| selected.to_vec()),
            completeness: DiscoveryCompleteness::Complete,
            issues: vec![],
            considered: selected.len(),
            attempted: selected
                .iter()
                .filter(|model| refresh || model.needs_detail())
                .count(),
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.capture.lock().unwrap().dropped += 1;
    }
}

fn observed(id: &str) -> DiscoveredModel {
    DiscoveredModel {
        id: id.into(),
        label: None,
        context_window: Some(32000),
        max_output_tokens: Some(4000),
        source: MetadataSource::OpenRouterModels,
        metadata_valid: true,
        unrecognized_fields: vec![],
        evidence: None,
    }
}
fn declared(id: &str) -> ModelEntry {
    ModelEntry {
        context_limits: None,
        id: id.into(),
        label: None,
        pricing: None,
        billing: None,
        context_window: None,
        max_output_tokens: None,
        sampling: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        default_effort: None,
    }
}
fn provider(models: Vec<ModelEntry>) -> ProviderConfig {
    ProviderConfig {
        name: "fixture".into(),
        kind: "openai-compatible".into(),
        url: "http://127.0.0.1:9/v1".into(),
        env: None,
        models,
    }
}
fn direct_answers() -> Vec<&'static str> {
    vec![
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "discover",
        "openrouter",
        "1",
        "yes",
        "family/raw",
        "yes",
    ]
}

#[test]
fn manual_default_does_not_construct_or_call_discovery_and_decline_writes_nothing() {
    let fixture = Fixture::new();
    let mut factory = Factory::new(vec![observed("must-not-fetch")]);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "",
        "family/raw",
        "no",
        "no",
    ]);
    assert!(matches!(
        collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory),
        Err(OnboardingError::Canceled)
    ));
    assert!(factory.capture.lock().unwrap().opened.is_empty());
    assert!(!fixture.home.exists());
}

#[test]
fn explicit_catalog_selection_preserves_raw_id_limits_and_no_writes_before_confirmed_commit() {
    let fixture = Fixture::new();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    let mut terminal = Terminal::new(&direct_answers());
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    assert!(!fixture.home.exists());
    assert_eq!(draft.provider().models[0].id, "family/raw");
    assert_eq!(draft.provider().models[0].context_window, Some(32000));
    assert_eq!(draft.provider().models[0].max_output_tokens, Some(4000));
    assert!(draft.provider().models[0].supported_efforts.is_none());
    let receipt = commit_onboarding(draft).unwrap();
    assert_eq!(receipt.catalog_status, "complete");
    assert_eq!(receipt.connectivity, "not_tested");
    assert_eq!(receipt.metadata_saved, Some(true));
    assert!(receipt.warnings.is_empty());
    let config = fixture.config();
    assert_eq!(config.roles.main, "fixture/family/raw");
    assert_eq!(config.provider[0].models[0].context_window, Some(32000));
    assert_eq!(
        load_model_provenance(&fixture.home, &config.provider[0])
            .unwrap()
            .len(),
        1
    );
    let capture = factory.capture.lock().unwrap();
    assert_eq!(capture.opened.len(), 1);
    assert_eq!(capture.opened[0].profile, DiscoveryProfile::OpenRouter);
    assert_eq!(capture.detail_ids, vec![vec!["family/raw".to_string()]]);
    assert_eq!(capture.refresh, vec![false]);
    assert_eq!(capture.dropped, 1);
    assert!(
        terminal
            .output
            .contains("Completion connectivity: not tested")
    );
}

#[test]
fn custom_openai_requires_explicit_schema_choice_not_name_or_hostname_guess() {
    let fixture = Fixture::new();
    let mut model = observed("family/raw");
    model.source = MetadataSource::GenericOpenAiModels;
    model.context_window = None;
    model.max_output_tokens = None;
    let mut factory = Factory::new(vec![model]);
    let mut terminal = Terminal::new(&[
        "custom",
        "openrouter",
        "openai-compatible",
        "https://openrouter.ai/api/v1",
        "none",
        "discover",
        "generic",
        "1",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    assert!(draft.provider().models[0].context_window.is_none());
    assert_eq!(
        factory.capture.lock().unwrap().opened[0].profile,
        DiscoveryProfile::GenericOpenAi
    );
    assert!(!fixture.home.exists());
}

#[test]
fn catalog_above_128_entries_can_page_filter_and_select_an_exact_later_id() {
    let fixture = Fixture::new();
    let models = (0..200)
        .map(|index| observed(&format!("vendor/raw{index}")))
        .collect();
    let mut factory = Factory::new(models);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "discover",
        "openrouter",
        "next",
        "prev",
        "filter raw139",
        "1",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    assert_eq!(draft.provider().models.len(), 1);
    assert_eq!(draft.provider().models[0].id, "vendor/raw139");
    assert!(terminal.output.contains("Catalog page 2/10"));
    assert!(
        terminal
            .output
            .contains("Catalog page 1/1 (1 matching models)")
    );
    assert!(!fixture.home.exists());
}

#[test]
fn incomplete_catalog_requires_explicit_partial_consent_or_manual_fallback() {
    for consent in ["yes", "no"] {
        let fixture = Fixture::new();
        let mut factory = Factory::new(vec![observed("family/raw")]);
        factory.catalog.completeness = DiscoveryCompleteness::Incomplete;
        let mut values = vec![
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "none",
            "discover",
            "openrouter",
            consent,
        ];
        values.extend(if consent == "yes" {
            vec!["1", "no", "yes"]
        } else {
            vec!["manual/raw", "no", "yes"]
        });
        let mut terminal = Terminal::new(&values);
        let receipt = commit_onboarding(
            collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt.catalog_status,
            if consent == "yes" {
                "incomplete"
            } else {
                "manual_fallback"
            }
        );
        assert_eq!(
            fixture.config().provider[0].models[0].id,
            if consent == "yes" {
                "family/raw"
            } else {
                "manual/raw"
            }
        );
    }
}

#[test]
fn fetch_failure_offers_manual_input_while_user_cancellation_does_not_fall_back() {
    let fixture = Fixture::new();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    factory.fail_catalog = true;
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "none",
        "discover",
        "openrouter",
        "manual/raw",
        "no",
        "yes",
    ]);
    let receipt = commit_onboarding(
        collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt.catalog_status, "manual_fallback");
    assert!(terminal.output.contains("Discovery unavailable"));
    let other = Fixture::new();
    let mut canceled = Factory::new(vec![observed("family/raw")]);
    canceled.cancel_catalog = true;
    let mut terminal = Terminal::new(&direct_answers());
    assert!(matches!(
        collect_onboarding_with_discovery(&other.home, None, &mut terminal, &mut canceled),
        Err(OnboardingError::Canceled)
    ));
    assert!(!other.home.exists());
    assert!(!terminal.output.contains("Raw model IDs"));
    assert_eq!(canceled.capture.lock().unwrap().dropped, 1);
}

#[test]
fn empty_catalog_and_explicit_manual_switch_preserve_a_usable_offline_path() {
    for empty in [false, true] {
        let fixture = Fixture::new();
        let mut factory = Factory::new(if empty {
            vec![]
        } else {
            vec![observed("family/raw")]
        });
        let mut values = vec![
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "none",
            "discover",
            "openrouter",
        ];
        if !empty {
            values.push("manual");
        }
        values.extend(["manual/raw", "no", "yes"]);
        let mut terminal = Terminal::new(&values);
        let draft =
            collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
                .unwrap();
        assert_eq!(draft.provider().models[0].id, "manual/raw");
        assert!(!fixture.home.exists());
        assert!(factory.capture.lock().unwrap().detail_ids.is_empty());
    }
}

#[test]
fn every_selected_unknown_anthropic_model_is_submitted_for_details_together() {
    let fixture = Fixture::new();
    let mut first = observed("family/one");
    first.source = MetadataSource::AnthropicModels;
    first.context_window = None;
    first.max_output_tokens = None;
    let mut second = first.clone();
    second.id = "family/two".into();
    let mut factory = Factory::new(vec![first.clone(), second.clone()]);
    first.source = MetadataSource::AnthropicModelDetail;
    first.context_window = Some(50000);
    first.max_output_tokens = Some(5000);
    second.source = MetadataSource::AnthropicModelDetail;
    second.context_window = Some(60000);
    second.max_output_tokens = Some(6000);
    factory.details = Some(vec![first, second]);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "anthropic",
        "http://127.0.0.1:9/v1",
        "none",
        "discover",
        "1,2",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    assert_eq!(draft.provider().models[0].context_window, Some(50000));
    assert_eq!(draft.provider().models[1].context_window, Some(60000));
    assert_eq!(
        factory.capture.lock().unwrap().detail_ids,
        vec![vec!["family/one".to_string(), "family/two".to_string()]]
    );
}

#[test]
fn stale_change_during_fetch_is_refused_before_confirmation_or_key_publication() {
    let fixture = Fixture::new();
    fixture.seed(provider(vec![declared("old/raw")]));
    let path = fixture.home.join("providers.toml");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("\n[unrelated]\nexternal_edit=true\n");
    let expected = text.clone();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    factory.on_catalog = Some(Box::new(move || std::fs::write(&path, text).unwrap()));
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "yes",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        "synthetic-draft-key",
        "discover",
        "openrouter",
        "1",
        "no",
        "yes",
    ]);
    assert!(matches!(
        collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(
        std::fs::read_to_string(fixture.home.join("providers.toml")).unwrap(),
        expected
    );
    assert!(!fixture.home.join("auth").exists());
}

#[test]
fn fresh_private_candidate_uses_its_exact_new_reference_for_discovery() {
    let fixture = Fixture::new();
    let mut old = provider(vec![declared("old/raw")]);
    old.env = Some("ORBIT_WIZARD_OLD_UNSET".into());
    fixture.seed(old);
    let mut factory = Factory::new(vec![observed("family/raw")]);
    factory.source = ProviderCredentialSource::Draft;
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "yes",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        "synthetic-private-key",
        "discover",
        "openrouter",
        "1",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    let capture = factory.capture.lock().unwrap();
    let opened = &capture.opened[0];
    assert!(opened.draft_present && opened.exact_draft);
    assert!(
        opened
            .provider
            .env
            .as_ref()
            .unwrap()
            .starts_with("ORBIT_AUTH_")
    );
    assert!(opened.provider.env.as_deref() != Some("ORBIT_WIZARD_OLD_UNSET"));
    assert_eq!(opened.provider.env, draft.provider().env);
    assert!(!terminal.output.contains("synthetic-private-key"));
    assert!(!fixture.home.join("auth").exists());
}

#[test]
fn optional_metadata_failure_keeps_successful_provider_and_private_key() {
    let fixture = Fixture::new();
    fixture.seed(provider(vec![declared("old/raw")]));
    std::fs::write(fixture.home.join("metadata"), b"occupied").unwrap();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    factory.source = ProviderCredentialSource::Draft;
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "yes",
        "openai-compatible",
        "http://127.0.0.1:9/v1",
        "key",
        "synthetic-private-key",
        "discover",
        "openrouter",
        "1",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    let id = draft.auth_identity().unwrap();
    let receipt = commit_onboarding(draft).unwrap();
    assert_eq!(receipt.metadata_saved, Some(false));
    assert!(!receipt.warnings.is_empty());
    assert!(
        fixture.config().provider[0]
            .models
            .iter()
            .any(|model| model.id == "family/raw")
    );
    let resolved = orbit_adapter::provider_credentials::ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .resolve_with(&id, |_| Ok(None))
        .unwrap();
    assert!(resolved.into_secret().unwrap().expose() == b"synthetic-private-key");
    let mut observed = observed("family/raw");
    observed.context_window = Some(64000);
    let mut refresh = Factory::new(vec![observed]);
    let next = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut refresh,
    )
    .unwrap();
    let model = next
        .provider()
        .models
        .iter()
        .find(|model| model.id == "family/raw")
        .unwrap();
    assert_eq!(model.context_window, Some(32000));
}

#[test]
fn refresh_preserves_explicit_effort_pricing_sampling_and_unfamiliar_raw_fields() {
    let fixture = Fixture::new();
    let mut model = declared("family/raw");
    let high = orbit_adapter::types::EffortValue::Level("high".into());
    model.supported_efforts = Some(vec![
        orbit_adapter::types::EffortValue::Level("low".into()),
        high.clone(),
    ]);
    model.default_effort = Some(high);
    model.pricing = Some(Pricing::default());
    let pricing = model
        .pricing
        .as_mut()
        .expect("declared model carries legacy pricing");
    pricing.input_per_million_microdollars = Some(123456);
    pricing.output_per_million_microdollars = Some(654321);
    model.sampling = Some(orbit_cli::config::SamplingOverride {
        temperature: Some(0.4),
        top_p: Some(0.8),
    });
    fixture.seed(provider(vec![model.clone()]));
    let path = fixture.home.join("providers.toml");
    let mut raw: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let target = raw["provider"][0]["models"][0].as_table_mut().unwrap();
    target.insert(
        "future_model_hint".into(),
        toml::Value::String("keep".into()),
    );
    target
        .get_mut("pricing")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("future_rate_hint".into(), toml::Value::Integer(42));
    target
        .get_mut("sampling")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "future_sampling_hint".into(),
            toml::Value::String("keep".into()),
        );
    std::fs::write(&path, toml::to_string(&raw).unwrap()).unwrap();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    assert_eq!(
        draft.provider().models[0].supported_efforts,
        model.supported_efforts
    );
    assert_eq!(
        draft.provider().models[0].default_effort,
        model.default_effort
    );
    assert_eq!(draft.provider().models[0].pricing, model.pricing);
    assert_eq!(draft.provider().models[0].sampling, model.sampling);
    commit_provider_refresh(draft).unwrap();
    let saved: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        saved["provider"][0]["models"][0]["future_model_hint"].as_str(),
        Some("keep")
    );
    assert_eq!(
        saved["provider"][0]["models"][0]["pricing"]["future_rate_hint"].as_integer(),
        Some(42)
    );
    assert_eq!(
        saved["provider"][0]["models"][0]["sampling"]["future_sampling_hint"].as_str(),
        Some("keep")
    );
}

#[test]
fn refresh_without_provenance_preserves_manual_limits_and_all_explicit_effort_fields() {
    let fixture = Fixture::new();
    let mut model = declared("family/raw");
    model.context_window = Some(77777);
    model.max_output_tokens = Some(7777);
    model.supported_efforts = Some(vec![]);
    model.default_effort = None;
    fixture.seed(provider(vec![model.clone()]));
    let before = std::fs::read(fixture.home.join("providers.toml")).unwrap();
    let mut factory = Factory::new(vec![observed("family/raw")]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    assert_eq!(draft.provider().models[0], model);
    assert_eq!(
        std::fs::read(fixture.home.join("providers.toml")).unwrap(),
        before
    );
    let receipt = commit_provider_refresh(draft).unwrap();
    assert_eq!(receipt.connectivity, "not_tested");
    assert_eq!(fixture.config().provider[0].models[0], model);
    assert_eq!(factory.capture.lock().unwrap().refresh, vec![true]);
}

#[test]
fn refresh_updates_only_unchanged_auto_fields_after_a_manual_override() {
    let fixture = Fixture::new();
    let mut initial = Factory::new(vec![observed("family/raw")]);
    let mut terminal = Terminal::new(&direct_answers());
    commit_onboarding(
        collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut initial)
            .unwrap(),
    )
    .unwrap();
    let path = fixture.home.join("providers.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("max_output_tokens = 4000"));
    std::fs::write(
        &path,
        text.replace("max_output_tokens = 4000", "max_output_tokens = 7777"),
    )
    .unwrap();
    let mut updated = observed("family/raw");
    updated.context_window = Some(64000);
    updated.max_output_tokens = Some(8000);
    let mut factory = Factory::new(vec![updated]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    assert_eq!(draft.provider().models[0].context_window, Some(64000));
    assert_eq!(draft.provider().models[0].max_output_tokens, Some(7777));
    commit_provider_refresh(draft).unwrap();
    assert_eq!(
        fixture.config().provider[0].models[0].max_output_tokens,
        Some(7777)
    );
}

#[test]
fn refresh_stale_change_after_fetch_preserves_the_external_configuration() {
    let fixture = Fixture::new();
    fixture.seed(provider(vec![declared("family/raw")]));
    let mut factory = Factory::new(vec![observed("family/raw")]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    let path = fixture.home.join("providers.toml");
    let mut changed = std::fs::read_to_string(&path).unwrap();
    changed.push_str("\n[external]\nchanged=true\n");
    std::fs::write(&path, &changed).unwrap();
    assert!(matches!(
        commit_provider_refresh(draft),
        Err(OnboardingError::Stale)
    ));
    assert_eq!(std::fs::read_to_string(path).unwrap(), changed);
    assert!(!fixture.home.join("metadata").exists());
}

#[test]
fn invalid_catalog_metadata_does_not_acquire_authoritative_limits() {
    let fixture = Fixture::new();
    let mut bad = observed("family/raw");
    bad.metadata_valid = false;
    let mut factory = Factory::new(vec![bad]);
    let mut terminal = Terminal::new(&direct_answers());
    let draft = collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory)
        .unwrap();
    assert!(draft.provider().models[0].context_window.is_none());
    assert!(draft.provider().models[0].max_output_tokens.is_none());
    assert!(terminal.output.contains("context unknown; output unknown"));
    assert!(!terminal.output.contains("context 32000"));
}

#[test]
fn catalog_selection_refuses_duplicate_or_over_128_numbers_before_publication() {
    for selection in [
        "1,1".to_string(),
        (1..=129)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ] {
        let fixture = Fixture::new();
        let mut factory = Factory::new(
            (0..200)
                .map(|index| observed(&format!("family/raw{index}")))
                .collect(),
        );
        let mut values: Vec<String> = vec![
            "custom",
            "fixture",
            "openai-compatible",
            "http://127.0.0.1:9/v1",
            "none",
            "discover",
            "openrouter",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        values.push(selection);
        values.push("cancel".to_owned());
        let refs: Vec<_> = values.iter().map(String::as_str).collect();
        let mut terminal = Terminal::new(&refs);
        assert!(matches!(
            collect_onboarding_with_discovery(&fixture.home, None, &mut terminal, &mut factory),
            Err(OnboardingError::Canceled)
        ));
        assert!(terminal.input.is_empty());
        assert!(
            terminal
                .output
                .contains("Select 1..128 distinct catalog numbers")
        );
        assert!(terminal.output.contains("Correct this field: "));
        let capture = factory.capture.lock().unwrap();
        assert_eq!(capture.opened.len(), 1);
        assert!(capture.detail_ids.is_empty());
        assert_eq!(capture.dropped, 1);
        assert!(!fixture.home.exists());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_discovery_runtime_is_scoped_outside_an_existing_tokio_runtime() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    struct Server {
        addr: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
        count: Arc<AtomicUsize>,
        join: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
        }
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    let join = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while bytes.len() < 8192
                        && !bytes.windows(4).any(|window| window == b"\r\n\r\n")
                    {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(length) => bytes.extend_from_slice(&chunk[..length]),
                        }
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    assert!(
                        std::str::from_utf8(&bytes)
                            .unwrap()
                            .starts_with("GET /v1/models HTTP/1.1\r\n")
                    );
                    captured.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{"data":[{"id":"family/raw","context_length":32000,"top_provider":{"max_completion_tokens":4000}}]}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(_) => break,
            }
        }
    });
    let server = Server {
        addr,
        stop,
        count,
        join: Some(join),
    };
    let fixture = Fixture::new();
    let endpoint = format!("http://{}/v1", server.addr);
    let mut terminal = Terminal::new(&[
        "custom",
        "fixture",
        "openai-compatible",
        &endpoint,
        "none",
        "discover",
        "openrouter",
        "1",
        "no",
        "yes",
    ]);
    let draft = collect_onboarding(&fixture.home, None, &mut terminal).unwrap();
    assert!(!fixture.home.exists());
    assert_eq!(draft.provider().models[0].id, "family/raw");
    assert_eq!(draft.provider().models[0].context_window, Some(32000));
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    drop(draft);
    drop(server);
}

fn seeded_manual_policy_fixture() -> Fixture {
    let fixture = Fixture::new();
    let mut configured = provider(vec![declared("family/raw")]);
    configured.models[0].context_window = None;
    let id = ProviderAuthIdentity::new(
        &configured.name,
        &configured.kind,
        &configured.url,
        configured.env.as_deref(),
    )
    .unwrap();
    let mut first_observation = serde_json::to_value(observed("family/raw")).unwrap();
    let context = first_observation["context_window"].clone();
    let output = first_observation["max_output_tokens"].clone();
    let source = first_observation["source"].clone();
    first_observation["evidence"] = serde_json::json!({
        "context_limit": {
            "value": context, "observed_at_unix": 111, "source": source,
            "schema": "open_router_models_fields_v1", "semantics": "unspecified",
            "confidence": "advertised_unspecified"
        },
        "output_limit": {
            "value": output, "observed_at_unix": 222, "source": source,
            "schema": "open_router_models_fields_v1", "semantics": "unspecified",
            "confidence": "advertised_unspecified"
        }
    });
    let first_observation: DiscoveredModel = serde_json::from_value(first_observation).unwrap();
    let first = merge_discovered_model(&configured.models[0], &first_observation, None, &id);
    configured.models[0] = first.model;
    fixture.seed(configured.clone());
    save_model_provenance(&fixture.home, &configured, &[first.provenance.unwrap()]).unwrap();
    configured.models[0].context_window = Some(77777);
    let config = ProvidersConfig {
        provider: vec![configured],
        ..Default::default()
    };
    config.save_atomic(&fixture.home).unwrap();
    let mut next = observed("family/raw");
    next.context_window = Some(64000);
    let mut factory = Factory::new(vec![next]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    let receipt = commit_provider_refresh(draft).unwrap();
    assert_eq!(receipt.metadata_saved, Some(true));
    let configured = fixture.config();
    let provider = &configured.provider[0];
    let record = load_model_provenance(&fixture.home, provider)
        .unwrap()
        .remove(0);
    assert_eq!(
        serde_json::to_value(record).unwrap()["manual_input_tokens"],
        77777,
        "refresh must persist the exact configured manual input policy"
    );
    assert_eq!(
        serde_json::to_value(
            load_model_provenance(&fixture.home, provider)
                .unwrap()
                .remove(0)
        )
        .unwrap()["observed"]["evidence"]["output_limit"]["observed_at_unix"],
        222,
        "the caller fixture must retain actual historical evidence before testing preservation"
    );
    fixture
}

#[test]
fn refresh_invalid_or_unfetched_observation_preserves_existing_manual_policy_receipt() {
    for missing_catalog_id in [false, true] {
        let fixture = seeded_manual_policy_fixture();
        let before_provider = fixture.config().provider.remove(0);
        let before = load_model_provenance(&fixture.home, &before_provider).unwrap();
        let mut invalid = observed("family/raw");
        invalid.metadata_valid = false;
        let mut factory = Factory::new(if missing_catalog_id {
            vec![]
        } else {
            vec![invalid]
        });
        let draft = prepare_provider_refresh_with_discovery(
            &fixture.home,
            "fixture",
            DiscoveryProfile::OpenRouter,
            &mut factory,
        )
        .unwrap();
        let receipt = commit_provider_refresh(draft).unwrap();
        assert_eq!(receipt.metadata_saved, Some(true));
        assert_eq!(receipt.connectivity, "not_tested");
        let after_provider = fixture.config().provider.remove(0);
        assert_eq!(after_provider.models[0].context_window, Some(77777));
        let after = load_model_provenance(&fixture.home, &after_provider).unwrap();
        assert_eq!(
            after, before,
            "merge refusal must retain the original record and its ages/policy"
        );
        assert_eq!(
            serde_json::to_value(&after[0]).unwrap()["manual_input_tokens"],
            77777
        );
    }
}

#[test]
fn refresh_valid_absent_context_retains_manual_policy_separately_from_new_numeric_observation() {
    let fixture = seeded_manual_policy_fixture();
    let mut next = observed("family/raw");
    next.context_window = None;
    next.max_output_tokens = Some(8000);
    let mut factory = Factory::new(vec![next]);
    let draft = prepare_provider_refresh_with_discovery(
        &fixture.home,
        "fixture",
        DiscoveryProfile::OpenRouter,
        &mut factory,
    )
    .unwrap();
    let receipt = commit_provider_refresh(draft).unwrap();
    assert_eq!(receipt.metadata_saved, Some(true));
    let provider = fixture.config().provider.remove(0);
    assert_eq!(provider.models[0].context_window, Some(77777));
    assert_eq!(provider.models[0].max_output_tokens, Some(8000));
    let record = load_model_provenance(&fixture.home, &provider)
        .unwrap()
        .remove(0);
    assert_eq!(record.observed.context_window, None);
    assert_eq!(record.last_applied_context_window, None);
    assert_eq!(
        serde_json::to_value(&record).unwrap()["manual_input_tokens"],
        77777
    );
}
