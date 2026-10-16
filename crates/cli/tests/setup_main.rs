#![cfg(target_os = "linux")]

// Compile the publication hook locally to exercise failures after config replacement.
pub use orbit_cli::{
    config, phase_routing, presets, profile_commands, provider_discovery, tool_runtime,
};
#[path = "../src/customization.rs"]
#[allow(dead_code)]
mod customization;
#[path = "../src/onboarding.rs"]
#[allow(dead_code)]
mod onboarding;
#[path = "../src/setup.rs"]
#[allow(dead_code)]
mod setup;

use customization::{Error, PublicationPoint, with_test_hook};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{ProviderCredentialSource, ProviderCredentialStore};
use setup::{SetupRequest, apply_setup, plan_setup, plan_setup_with_main};
use std::cell::Cell;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-setup-main-{}", ulid::Ulid::new()));
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

    fn write_config(&self, text: &str) {
        let path = self.home.join("providers.toml");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn raw(&self) -> String {
        std::fs::read_to_string(self.home.join("providers.toml")).unwrap()
    }

    fn value(&self) -> toml::Value {
        toml::from_str(&self.raw()).unwrap()
    }

    fn config(&self) -> config::ProvidersConfig {
        config::ProvidersConfig::load_from_str(&self.raw()).unwrap()
    }

    fn identity(&self) -> Vec<Vec<u8>> {
        [
            "trust/operator.key",
            "trust/manifest.json",
            "pib.json",
            "ledger/segments/0000000000000000.log",
        ]
        .into_iter()
        .map(|path| std::fs::read(self.home.join(path)).unwrap())
        .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn provider() -> config::ProviderConfig {
    serde_json::from_value(serde_json::json!({
        "name": "fixture", "kind": "openai-compatible", "url": "https://provider.invalid/v1/",
        "models": [{"id": "owner/family/raw"}, {"id": "second/raw"}]
    }))
    .unwrap()
}

fn request(provider: config::ProviderConfig) -> SetupRequest {
    SetupRequest {
        provider: Some(provider),
        ..Default::default()
    }
}

fn configured() -> Fixture {
    let f = Fixture::new();
    apply_setup(
        &plan_setup_with_main(
            &f.home,
            &request(provider()),
            Some("fixture/owner/family/raw"),
        )
        .unwrap(),
    )
    .unwrap();
    f
}

#[test]
fn setup_main_provider_and_default_are_one_complete_candidate_publication() {
    let f = Fixture::new();
    let plan = plan_setup_with_main(
        &f.home,
        &request(provider()),
        Some("fixture/owner/family/raw"),
    )
    .unwrap();
    assert!(!f.home.exists());
    let publications = Rc::new(Cell::new(0));
    let count = publications.clone();
    let home = f.home.clone();
    let receipt = with_test_hook(
        move |point, path| {
            if point == PublicationPoint::Published && path == home {
                count.set(count.get() + 1);
                let text = std::fs::read_to_string(home.join("providers.toml")).unwrap();
                let candidate = config::ProvidersConfig::load_from_str(&text).unwrap();
                assert_eq!(candidate.roles.main, "fixture/owner/family/raw");
                assert_eq!(candidate.provider[0].models[0].id, "owner/family/raw");
            }
        },
        || apply_setup(&plan),
    )
    .unwrap();
    assert!(receipt.initialized && receipt.config_changed);
    assert_eq!(publications.get(), 1);
}

#[test]
fn setup_main_patch_preserves_other_roles_routes_and_identity() {
    let f = configured();
    f.write_config(&format!("{}\n[unrelated]\nkeep = 'unchanged'\n", f.raw()));
    let mut value = f.value();
    value["roles"].as_table_mut().unwrap().insert(
        "subagent".into(),
        toml::Value::String("fixture/owner/family/raw".into()),
    );
    value["roles"]
        .as_table_mut()
        .unwrap()
        .insert("future_role".into(), toml::Value::String("keep".into()));
    value.as_table_mut().unwrap().insert(
        "routing".into(),
        toml::Value::Table(
            [
                (
                    "easy".into(),
                    toml::Value::String("fixture/owner/family/raw".into()),
                ),
                (
                    "future_route".into(),
                    toml::Value::String("preserved".into()),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    );
    f.write_config(&toml::to_string(&value).unwrap());
    let before = f.identity();
    apply_setup(
        &plan_setup_with_main(
            &f.home,
            &SetupRequest::default(),
            Some("fixture/second/raw"),
        )
        .unwrap(),
    )
    .unwrap();
    let value = f.value();
    assert_eq!(value["roles"]["main"].as_str(), Some("fixture/second/raw"));
    assert_eq!(
        value["roles"]["subagent"].as_str(),
        Some("fixture/owner/family/raw")
    );
    assert_eq!(value["roles"]["future_role"].as_str(), Some("keep"));
    assert_eq!(
        value["routing"]["easy"].as_str(),
        Some("fixture/owner/family/raw")
    );
    assert_eq!(value["routing"]["future_route"].as_str(), Some("preserved"));
    assert_eq!(value["unrelated"]["keep"].as_str(), Some("unchanged"));
    assert_eq!(f.identity(), before);
}

#[test]
fn setup_main_legacy_plan_setup_preserves_existing_default() {
    let f = configured();
    let before = f.raw();
    let plan = plan_setup(&f.home, &SetupRequest::default()).unwrap();
    assert!(!plan.config_changed);
    let receipt = apply_setup(&plan).unwrap();
    assert!(receipt.reused && !receipt.config_changed);
    assert_eq!(f.raw(), before);
    assert_eq!(f.config().roles.main, "fixture/owner/family/raw");
}

#[test]
fn setup_main_invalid_or_unqualified_targets_refuse_before_home_creation() {
    for main in [
        "",
        "raw",
        "owner/family/raw",
        "fixture/missing",
        "unknown/owner/family/raw",
        " fixture/owner/family/raw",
        "fixture/owner/family/raw ",
        "fixture/owner\nraw",
    ] {
        let f = Fixture::new();
        assert!(plan_setup_with_main(&f.home, &request(provider()), Some(main)).is_err());
        assert!(!f.home.exists());
    }
}

#[test]
fn setup_main_stale_candidate_cannot_overwrite_concurrent_default() {
    let f = configured();
    let stale = plan_setup_with_main(
        &f.home,
        &SetupRequest::default(),
        Some("fixture/second/raw"),
    )
    .unwrap();
    let changed = f.raw().replace(
        "main = \"fixture/owner/family/raw\"",
        "main = \"fixture/second/raw\"",
    );
    assert_ne!(changed, f.raw());
    f.write_config(&changed);
    let before = f.identity();
    assert!(matches!(apply_setup(&stale), Err(Error::Busy)));
    assert_eq!(f.raw(), changed);
    assert_eq!(f.identity(), before);
}

#[test]
fn setup_main_patch_is_private_and_nonserialized() {
    let f = Fixture::new();
    let plan = plan_setup_with_main(
        &f.home,
        &request(provider()),
        Some("fixture/owner/family/raw"),
    )
    .unwrap();
    let json = serde_json::to_value(&plan).unwrap();
    assert!(json.get("main").is_none());
    assert!(!json.to_string().contains("fixture/owner/family/raw"));
    assert!(!f.home.exists());
}

#[test]
fn setup_main_respects_shared_config_lock_without_partial_default_write() {
    let f = configured();
    let plan = plan_setup_with_main(
        &f.home,
        &SetupRequest::default(),
        Some("fixture/second/raw"),
    )
    .unwrap();
    let before = f.raw();
    let directory = customization::Directory::open(&f.home, true).unwrap();
    let _lock = customization::Lock::acquire(&directory, ".config.lock").unwrap();
    assert!(matches!(apply_setup(&plan), Err(Error::Busy)));
    assert_eq!(f.raw(), before);
}

fn metadata_fixture() -> Fixture {
    let f = Fixture::new();
    f.init();
    f.write_config(
        r#"
[unrelated]
keep = "top-level"
[[provider]]
name = "fixture"
kind = "openai-compatible"
url = "https://provider.invalid/v1/"
provider_note = "provider-metadata"
[[provider.models]]
id = "owner/family/raw"
label = "Old label"
context_window = 64000
max_output_tokens = 8000
supported_efforts = ["high"]
default_effort = "high"
model_note = "first-model"
[provider.models.sampling]
temperature = 0.2
[provider.models.extensions]
vendor = "preserved-extension"
[provider.models.pricing]
input_per_million_microcents = 123
output_per_million_microcents = 456
cache_read_per_million_microcents = 12
request_flat_microcents = 9
pricing_note = "preserved-pricing"
[provider.models.pricing.vendor]
unit = "credits"
[[provider.models]]
id = "second/raw"
model_note = "second-model"
"#,
    );
    f
}

#[test]
fn setup_main_replacement_preserves_unknown_model_and_nested_pricing_metadata() {
    let f = metadata_fixture();
    let mut incoming = f.config().provider.remove(0);
    incoming.models[0].label = Some("New label".into());
    incoming.models[0].pricing.input_per_million_microdollars = 777;
    let request = request(incoming);
    apply_setup(
        &plan_setup_with_main(&f.home, &request, Some("fixture/owner/family/raw")).unwrap(),
    )
    .unwrap();
    let value = f.value();
    let model = &value["provider"][0]["models"][0];
    assert_eq!(model["model_note"].as_str(), Some("first-model"));
    assert_eq!(
        model["extensions"]["vendor"].as_str(),
        Some("preserved-extension")
    );
    assert_eq!(
        model["pricing"]["pricing_note"].as_str(),
        Some("preserved-pricing")
    );
    assert_eq!(model["pricing"]["vendor"]["unit"].as_str(), Some("credits"));
    assert_eq!(
        model["pricing"]["input_per_million_microdollars"].as_integer(),
        Some(777)
    );
    assert_eq!(model["label"].as_str(), Some("New label"));
    assert_eq!(
        value["provider"][0]["provider_note"].as_str(),
        Some("provider-metadata")
    );
    assert_eq!(value["unrelated"]["keep"].as_str(), Some("top-level"));
}

#[test]
fn setup_main_incoming_known_optional_fields_and_pricing_aliases_replace_old_values() {
    let f = metadata_fixture();
    let mut incoming = f.config().provider.remove(0);
    let model = &mut incoming.models[0];
    model.label = None;
    model.context_window = None;
    model.max_output_tokens = None;
    model.sampling = None;
    model.supported_efforts = None;
    model.default_effort = None;
    model.pricing = config::Pricing::default();
    apply_setup(&plan_setup(&f.home, &request(incoming)).unwrap()).unwrap();
    let value = f.value();
    let model = value["provider"][0]["models"][0].as_table().unwrap();
    for field in [
        "label",
        "context_window",
        "max_output_tokens",
        "sampling",
        "supported_efforts",
        "default_effort",
    ] {
        assert!(!model.contains_key(field), "known removed field {field}");
    }
    let pricing = model["pricing"].as_table().unwrap();
    for alias in [
        "input_per_million_microcents",
        "output_per_million_microcents",
        "cache_read_per_million_microcents",
        "request_flat_microcents",
    ] {
        assert!(!pricing.contains_key(alias), "old pricing alias {alias}");
    }
    assert_eq!(
        pricing["input_per_million_microdollars"].as_integer(),
        Some(0)
    );
    assert_eq!(
        pricing["output_per_million_microdollars"].as_integer(),
        Some(0)
    );
    assert!(!pricing.contains_key("cache_read_per_million_microdollars"));
    assert_eq!(pricing["pricing_note"].as_str(), Some("preserved-pricing"));
}

#[test]
fn setup_main_model_metadata_follows_exact_raw_id_when_reordered() {
    let f = metadata_fixture();
    let mut incoming = f.config().provider.remove(0);
    incoming.models.reverse();
    apply_setup(&plan_setup(&f.home, &request(incoming)).unwrap()).unwrap();
    let value = f.value();
    assert_eq!(
        value["provider"][0]["models"][0]["id"].as_str(),
        Some("second/raw")
    );
    assert_eq!(
        value["provider"][0]["models"][0]["model_note"].as_str(),
        Some("second-model")
    );
    assert_eq!(
        value["provider"][0]["models"][1]["id"].as_str(),
        Some("owner/family/raw")
    );
    assert_eq!(
        value["provider"][0]["models"][1]["model_note"].as_str(),
        Some("first-model")
    );
}

#[test]
fn setup_main_scripted_model_list_omits_removed_ids_and_does_not_match_suffixes() {
    let f = metadata_fixture();
    let mut incoming = provider();
    incoming.models[0].id = "family/raw".into();
    incoming.models.truncate(1);
    apply_setup(&plan_setup(&f.home, &request(incoming)).unwrap()).unwrap();
    let value = f.value();
    let models = value["provider"][0]["models"].as_array().unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["id"].as_str(), Some("family/raw"));
    assert!(models[0].get("model_note").is_none());
    assert!(models[0].get("extensions").is_none());
    assert!(models[0]["pricing"].get("pricing_note").is_none());
}

#[test]
fn setup_main_post_config_identity_verification_failure_is_publication_uncertain() {
    let f = configured();
    let plan = plan_setup_with_main(
        &f.home,
        &SetupRequest::default(),
        Some("fixture/second/raw"),
    )
    .unwrap();
    let home = f.home.clone();
    let result = with_test_hook(
        move |point, path| {
            if point == PublicationPoint::Published && path == home {
                std::fs::write(
                    home.join("pib.json"),
                    b"invalid-identity-after-config-publication",
                )
                .unwrap();
            }
        },
        || apply_setup(&plan),
    );
    assert!(matches!(result, Err(Error::PublicationUncertain(_))));
    assert_eq!(f.config().roles.main, "fixture/second/raw");
}

struct Terminal(VecDeque<String>);

impl Terminal {
    fn next(&mut self, max: usize) -> Result<String, onboarding::OnboardingError> {
        let value = self
            .0
            .pop_front()
            .ok_or(onboarding::OnboardingError::Canceled)?;
        if value.len() > max {
            return Err(onboarding::OnboardingError::Invalid(
                "Input exceeds its byte limit",
            ));
        }
        Ok(value)
    }
}

impl onboarding::SetupTerminal for Terminal {
    fn message(&mut self, _: &str) -> Result<(), onboarding::OnboardingError> {
        Ok(())
    }
    fn line(&mut self, _: &str, max: usize) -> Result<String, onboarding::OnboardingError> {
        self.next(max)
    }
    fn hidden(&mut self, _: &str, max: usize) -> Result<SecretBytes, onboarding::OnboardingError> {
        Ok(SecretBytes::new(self.next(max)?.into_bytes()))
    }
}

#[test]
fn setup_main_wizard_retains_private_key_when_post_config_verification_fails() {
    let f = Fixture::new();
    f.init();
    let secret = "synthetic-post-publication-key";
    let answers = [
        "custom",
        "fixture",
        "openai-compatible",
        "https://provider.invalid/v1/",
        "key",
        secret,
        "manual",
        "owner/family/raw",
        "yes",
        "owner/family/raw",
        "yes",
    ];
    let mut terminal = Terminal(answers.into_iter().map(str::to_owned).collect());
    let draft = onboarding::collect_onboarding(&f.home, None, &mut terminal).unwrap();
    let identity = draft.auth_identity().unwrap();
    let reference = draft.provider().env.clone();
    let home = f.home.clone();
    let result = with_test_hook(
        move |point, path| {
            if point == PublicationPoint::Published && path == home {
                std::fs::write(
                    home.join("pib.json"),
                    b"invalid-identity-after-config-publication",
                )
                .unwrap();
            }
        },
        || onboarding::commit_onboarding(draft),
    );
    assert!(matches!(
        result,
        Err(onboarding::OnboardingError::PublicationUncertain)
    ));
    assert_eq!(f.config().roles.main, "fixture/owner/family/raw");
    assert_eq!(f.config().provider[0].env, reference);
    let resolved = ProviderCredentialStore::new(&f.home)
        .unwrap()
        .resolve_with(&identity, |_| Ok(None))
        .unwrap();
    assert_eq!(resolved.source(), ProviderCredentialSource::Saved);
    assert_eq!(resolved.into_secret().unwrap().expose(), secret.as_bytes());
}
