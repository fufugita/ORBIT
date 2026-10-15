#![cfg(target_os = "linux")]
pub use orbit_cli::profile_commands;
#[path = "../src/customization.rs"]
#[allow(dead_code)]
mod customization;
#[path = "../src/setup.rs"]
#[allow(dead_code)]
mod setup;
use customization::Error;
pub use orbit_cli::{config, phase_routing, tool_runtime};
use setup::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
struct Fixture {
    root: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-setup-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        Self { root, home }
    }
    fn init(&self) -> SetupReceipt {
        apply_setup(&plan_setup(&self.home, &SetupRequest::default()).unwrap()).unwrap()
    }
    fn identity(&self) -> Vec<Vec<u8>> {
        [
            "trust/operator.key",
            "trust/manifest.json",
            "pib.json",
            "ledger/segments/0000000000000000.log",
        ]
        .into_iter()
        .map(|p| std::fs::read(self.home.join(p)).unwrap())
        .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn provider() -> config::ProviderConfig {
    serde_json::from_value(serde_json::json!({"name":"example","kind":"openai-compatible","url":"http://127.0.0.1:9/v1","models":[{"id":"family/model-a"}]})).unwrap()
}
fn request() -> SetupRequest {
    SetupRequest {
        provider: Some(provider()),
        ..Default::default()
    }
}
fn invalid(mutator: impl FnOnce(&mut config::ProviderConfig)) {
    let f = Fixture::new();
    let mut p = provider();
    mutator(&mut p);
    assert!(plan_setup(
        &f.home,
        &SetupRequest {
            provider: Some(p),
            ..Default::default()
        }
    )
    .is_err());
    assert!(!f.home.exists());
}
#[test]
fn fresh_offline_identity_uses_real_formats() {
    let f = Fixture::new();
    let r = f.init();
    assert!(r.initialized);
    assert_eq!(verify_identity(&f.home).unwrap().pib_id, r.pib_id);
    assert!(verify_bounded_ledger(&f.home).unwrap().0 >= 2);
    assert_eq!(
        std::fs::metadata(f.home.join("pib.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn empty_existing_trust_directory_initializes_without_replacing_directory() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    std::fs::create_dir(&f.home).unwrap();
    std::fs::set_permissions(&f.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(f.home.join("trust")).unwrap();
    std::fs::set_permissions(f.home.join("trust"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let inode = std::fs::metadata(f.home.join("trust")).unwrap().ino();
    let first = f.init();
    assert!(first.initialized);
    assert_eq!(verify_identity(&f.home).unwrap().pib_id, first.pib_id);
    assert_eq!(
        std::fs::metadata(f.home.join("trust")).unwrap().ino(),
        inode
    );
    let identity = f.identity();
    assert!(f.init().reused);
    assert_eq!(identity, f.identity());
}

#[test]
fn existing_folder_trust_is_preserved_when_identity_is_first_initialized() {
    let f = Fixture::new();
    std::fs::create_dir(&f.home).unwrap();
    std::fs::set_permissions(&f.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(f.home.join("trust")).unwrap();
    std::fs::set_permissions(f.home.join("trust"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = f.home.join("trust/folders.json");
    let bytes = b"{\"schema\":\"fixture\",\"trusted\":[] }\n";
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.init().initialized);
    assert!(verify_identity(&f.home).is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
#[test]
fn repeated_init_preserves_identity_and_ledger_bytes() {
    let f = Fixture::new();
    let first = f.init();
    let bytes = f.identity();
    let second = f.init();
    assert!(!second.initialized);
    assert!(second.reused);
    assert_eq!(second.pib_id, first.pib_id);
    assert_eq!(f.identity(), bytes);
}
#[test]
fn legacy_public_pib_metadata_is_preserved_without_rekeying() {
    let f = Fixture::new();
    f.init();
    std::fs::set_permissions(
        f.home.join("pib.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let before = f.identity();
    let receipt = f.init();
    assert!(receipt.reused);
    assert_eq!(f.identity(), before);
    assert_eq!(
        std::fs::metadata(f.home.join("pib.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}
#[test]
fn unchanged_complete_home_does_not_create_lock_files() {
    let f = Fixture::new();
    f.init();
    for name in [".setup.lock", ".config.lock"] {
        std::fs::remove_file(f.home.join(name)).unwrap();
    }
    let before = f.identity();
    assert!(f.init().reused);
    assert_eq!(f.identity(), before);
    assert!(!f.home.join(".setup.lock").exists());
    assert!(!f.home.join(".config.lock").exists());
}
#[test]
fn add_provider_preserves_complete_identity_and_unrelated_settings() {
    let f = Fixture::new();
    f.init();
    let before = f.identity();
    std::fs::write(
        f.home.join("providers.toml"),
        "[unrelated]\nkeep='original'\n",
    )
    .unwrap();
    std::fs::set_permissions(
        f.home.join("providers.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let r = apply_setup(&plan_setup(&f.home, &request()).unwrap()).unwrap();
    assert!(r.config_changed);
    assert_eq!(f.identity(), before);
    let raw = std::fs::read_to_string(f.home.join("providers.toml")).unwrap();
    let value: toml::Value = toml::from_str(&raw).unwrap();
    assert_eq!(value["unrelated"]["keep"].as_str(), Some("original"));
    assert_eq!(
        config::ProvidersConfig::load(&f.home).unwrap().provider[0].models[0].id,
        "family/model-a"
    );
}
#[test]
fn partial_identity_refuses_regeneration_without_mutation() {
    let f = Fixture::new();
    f.init();
    std::fs::remove_file(f.home.join("pib.json")).unwrap();
    let key = std::fs::read(f.home.join("trust/operator.key")).unwrap();
    assert!(matches!(
        plan_setup(&f.home, &request()),
        Err(Error::Invalid(_))
    ));
    assert!(!f.home.join("pib.json").exists());
    assert_eq!(
        std::fs::read(f.home.join("trust/operator.key")).unwrap(),
        key
    );
    assert!(repair_dry_run(&f.home)
        .unwrap()
        .missing
        .contains(&"pib.json".into()));
}
#[test]
fn relative_url_fails_before_home() {
    invalid(|p| p.url = "relative/path".into());
}
#[test]
fn embedded_url_credentials_fail_before_home() {
    invalid(|p| p.url = "https://user:private@example.invalid/v1".into());
}
#[test]
fn url_fragment_fails_before_home() {
    invalid(|p| p.url = "https://example.invalid/#private".into());
}
#[test]
fn invalid_env_reference_fails_before_home() {
    invalid(|p| p.env = Some("KEY=value".into()));
}
#[test]
fn invalid_model_id_fails_before_home() {
    invalid(|p| p.models[0].id = "bad\nmodel".into());
}
#[test]
fn unknown_provider_kind_fails_before_home() {
    invalid(|p| p.kind = "unknown".into());
}
#[test]
fn malformed_existing_config_remains_byte_identical() {
    let f = Fixture::new();
    f.init();
    std::fs::write(f.home.join("providers.toml"), b"[broken").unwrap();
    std::fs::set_permissions(
        f.home.join("providers.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let before = f.identity();
    assert!(plan_setup(&f.home, &request()).is_err());
    assert_eq!(f.identity(), before);
    assert_eq!(
        std::fs::read(f.home.join("providers.toml")).unwrap(),
        b"[broken"
    );
}
#[test]
fn concurrent_stale_setup_plan_cannot_reinitialize() {
    let f = Fixture::new();
    let one = plan_setup(&f.home, &request()).unwrap();
    let two = plan_setup(&f.home, &request()).unwrap();
    let first = apply_setup(&one).unwrap();
    let bytes = f.identity();
    assert!(matches!(apply_setup(&two), Err(Error::Busy)));
    assert_eq!(f.identity(), bytes);
    assert_eq!(verify_identity(&f.home).unwrap().pib_id, first.pib_id);
}
#[test]
fn symlink_home_fails_before_writing_outside() {
    let f = Fixture::new();
    let target = f.root.join("outside");
    std::fs::create_dir(&target).unwrap();
    symlink(&target, &f.home).unwrap();
    assert!(plan_setup(&f.home, &request()).is_err());
    assert_eq!(std::fs::read_dir(target).unwrap().count(), 0);
}
#[test]
fn repair_dry_run_only_diagnoses_missing_identity() {
    let f = Fixture::new();
    let r = repair_dry_run(&f.home).unwrap();
    assert_eq!(r.missing.len(), 4);
    assert!(r.refuses_identity_regeneration);
    assert!(!f.home.exists());
}
#[test]
fn unknown_routing_choice_fails_before_home() {
    let f = Fixture::new();
    let mut r = request();
    r.routing
        .insert("unrecognized".into(), "example/family/model-a".into());
    assert!(plan_setup(&f.home, &r).is_err());
    assert!(!f.home.exists());
}
#[test]
fn modified_signed_manifest_is_refused_without_rekey() {
    let f = Fixture::new();
    f.init();
    let key = std::fs::read(f.home.join("trust/operator.key")).unwrap();
    let path = f.home.join("trust/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["body"]["version"] = "tampered".into();
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(plan_setup(&f.home, &request()).is_err());
    assert_eq!(
        std::fs::read(f.home.join("trust/operator.key")).unwrap(),
        key
    );
}
#[test]
fn setup_lock_refuses_concurrent_writer() {
    let f = Fixture::new();
    f.init();
    let plan = plan_setup(&f.home, &request()).unwrap();
    let d = customization::Directory::open(&f.home, true).unwrap();
    let _lock = customization::Lock::acquire(&d, ".setup.lock").unwrap();
    assert!(matches!(apply_setup(&plan), Err(Error::Busy)));
    assert!(!f.home.join("providers.toml").exists());
}
#[test]
fn interrupted_identity_publication_retains_staged_recovery_material() {
    let f = Fixture::new();
    let plan = plan_setup(&f.home, &request()).unwrap();
    let home = f.home.clone();
    let result = customization::with_test_hook(
        move |point, path| {
            if point == customization::PublicationPoint::Published
                && path
                    .file_name()
                    .is_some_and(|p| p.to_string_lossy().starts_with(".setup-stage-"))
            {
                let target = home.join("pib.json");
                std::fs::write(&target, b"concurrent artifact").unwrap();
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        },
        || apply_setup(&plan),
    );
    assert!(matches!(result, Err(Error::PublicationUncertain(_))));
    assert!(f.home.join("trust/operator.key").exists());
    assert!(!f.home.join("ledger").exists());
    let staged = std::fs::read_dir(&f.home)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with(".setup-stage-"))
        .unwrap();
    assert!(staged.path().join("pib.json").is_file());
    assert!(staged.path().join("ledger/segments").is_dir());
    assert!(plan_setup(&f.home, &request()).is_err());
}
#[test]
fn repeated_identical_provider_setup_is_noop() {
    let f = Fixture::new();
    apply_setup(&plan_setup(&f.home, &request()).unwrap()).unwrap();
    let identity = f.identity();
    let cfg = std::fs::read(f.home.join("providers.toml")).unwrap();
    let next = plan_setup(&f.home, &request()).unwrap();
    assert!(!next.initialize);
    assert!(!next.config_changed);
    apply_setup(&next).unwrap();
    assert_eq!(f.identity(), identity);
    assert_eq!(std::fs::read(f.home.join("providers.toml")).unwrap(), cfg);
}

#[test]
fn credential_query_refuses_before_home_and_preserves_existing_identity_and_config() {
    let f = Fixture::new();
    let keys = [
        "api_key",
        "%61Pi%2DKey",
        "token",
        "Access.Token",
        "refresh_token",
        "password",
        "secret",
        "client_secret",
        "authorization",
        "auth",
        "key",
    ];
    for key in keys {
        let mut request = request();
        request.provider.as_mut().unwrap().url =
            format!("https://example.invalid/v1?{key}=PRIVATE_QUERY_CREDENTIAL");
        let error = plan_setup(&f.home, &request).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        assert!(!error.to_string().contains("PRIVATE_QUERY_CREDENTIAL"));
        assert!(!f.home.exists());
    }
    let mut allowed = request();
    allowed.provider.as_mut().unwrap().url =
        "https://example.invalid/v1?api-version=2026-01-01".into();
    apply_setup(&plan_setup(&f.home, &allowed).unwrap()).unwrap();
    let identity = f.identity();
    let bytes = std::fs::read(f.home.join("providers.toml")).unwrap();
    for key in keys {
        let mut invalid = request();
        invalid.provider.as_mut().unwrap().url =
            format!("https://example.invalid/v1?{key}=PRIVATE_QUERY_CREDENTIAL");
        let error = plan_setup(&f.home, &invalid).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_QUERY_CREDENTIAL"));
        assert_eq!(f.identity(), identity);
        assert_eq!(std::fs::read(f.home.join("providers.toml")).unwrap(), bytes);
    }
    assert!(config::ProvidersConfig::load(&f.home).unwrap().provider[0]
        .url
        .contains("api-version=2026-01-01"));
}
