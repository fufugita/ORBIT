#![cfg(target_os = "linux")]
use orbit_cli::mods;
use orbit_cli::{cli_release_commands as commands, config};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("orbit-release-commands-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            home: root.join("home"),
            work: root.join("engagement"),
            root,
        }
    }
    fn identity(&self) -> Vec<Vec<u8>> {
        [
            "trust/operator.key",
            "trust/manifest.json",
            "pib.json",
            "ledger/segments/0000000000000000.log",
        ]
        .iter()
        .map(|p| std::fs::read(self.home.join(p)).unwrap())
        .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
fn provider() -> Vec<String> {
    args(&[
        "--provider",
        "fixture",
        "--gate",
        "http://127.0.0.1:9/v1",
        "--model",
        "family/a,family/b",
        "--credential-env",
        "FIXTURE_PROVIDER_KEY",
    ])
}

#[test]
fn command_setup_repeat_preserves_exact_identity_and_legacy_receipt() {
    let f = Fixture::new();
    let first = commands::init(&f.home, &args(&["--no-provider"])).unwrap();
    assert_eq!(first["schema"], "orbit.cli/v1");
    assert_eq!(first["command"], "init");
    assert_eq!(first["status"], "ok");
    assert_eq!(first["trust_root_verified"], true);
    assert!(first["pib_id"].as_str().unwrap().starts_with("pib-"));
    assert_eq!(first["ledger"], f.home.join("ledger").to_str().unwrap());
    let before = f.identity();
    let second = commands::setup(&f.home, &args(&["--json"])).unwrap();
    assert_eq!(second["reused"], true);
    assert_eq!(second["pib_id"], first["pib_id"]);
    assert_eq!(before, f.identity());
}
#[test]
fn command_legacy_manual_provider_flags_preserve_raw_models_and_env_reference() {
    let f = Fixture::new();
    commands::init(&f.home, &provider()).unwrap();
    let cfg = config::ProvidersConfig::load_from_str(
        &std::fs::read_to_string(f.home.join("providers.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(cfg.provider[0].models[0].id, "family/a");
    assert_eq!(cfg.provider[0].models[1].id, "family/b");
    assert_eq!(cfg.provider[0].env.as_deref(), Some("FIXTURE_PROVIDER_KEY"));
}
#[test]
fn command_unknown_option_fails_before_home_creation() {
    let f = Fixture::new();
    assert!(commands::setup(&f.home, &args(&["--unknown"])).is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_duplicate_option_fails_before_home_creation() {
    let f = Fixture::new();
    assert!(commands::init(&f.home, &args(&["--no-provider", "--no-provider"])).is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_partial_provider_arguments_fail_before_home_creation() {
    let f = Fixture::new();
    assert!(commands::init(
        &f.home,
        &args(&["--provider", "fixture", "--gate", "http://127.0.0.1:9"])
    )
    .is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_conflicting_provider_modes_fail_before_home_creation() {
    let f = Fixture::new();
    let mut flags = provider();
    flags.push("--no-provider".into());
    assert!(commands::setup(&f.home, &flags).is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_embedded_credential_failure_does_not_echo_it_or_create_home() {
    let f = Fixture::new();
    let mut flags = provider();
    flags[3] = "http://user:syntheticCredential@127.0.0.1:9".into();
    let error = commands::setup(&f.home, &flags).unwrap_err();
    assert!(!error.1.contains("syntheticCredential"));
    assert!(!f.home.exists());
}
#[test]
fn command_empty_model_entry_fails_before_home_creation() {
    let f = Fixture::new();
    let mut flags = provider();
    flags[5] = "family/a,".into();
    assert!(commands::setup(&f.home, &flags).is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_setup_dry_run_has_real_plan_and_no_files() {
    let f = Fixture::new();
    let mut flags = provider();
    flags.push("--dry-run".into());
    let value = commands::setup(&f.home, &flags).unwrap();
    assert_eq!(value["status"], "dry_run");
    assert_eq!(value["plan"]["initialize"], true);
    assert_eq!(value["plan"]["config_changed"], true);
    assert!(!f.home.exists());
}
#[test]
fn command_repair_requires_dry_run_and_never_creates_home() {
    let f = Fixture::new();
    assert!(commands::setup(&f.home, &args(&["repair"])).is_err());
    let value = commands::setup(&f.home, &args(&["repair", "--dry-run", "--json"])).unwrap();
    assert_eq!(value["report"]["refuses_identity_regeneration"], true);
    assert!(value["report"]["missing"].as_array().unwrap().len() >= 3);
    assert!(!f.home.exists());
}
#[test]
fn command_guided_manual_input_returns_exact_offline_request() {
    let mut reader =
        Cursor::new(b"fixture\nhttp://127.0.0.1:9/v1\n\nfamily/raw\nFIXTURE_PROVIDER_KEY\n");
    let mut output = Vec::new();
    let request = commands::guided_request(&mut reader, &mut output).unwrap();
    let provider = request.provider.unwrap();
    assert_eq!(provider.models[0].id, "family/raw");
    assert_eq!(provider.env.as_deref(), Some("FIXTURE_PROVIDER_KEY"));
    let guidance = String::from_utf8(output).unwrap();
    assert!(guidance.contains("no discovery or provider request"));
    assert!(!guidance.contains("family/raw"));
}
#[test]
fn command_guided_oversized_input_is_refused_boundedly() {
    let mut reader = Cursor::new(vec![b'a'; 5000]);
    let mut output = Vec::new();
    assert!(commands::guided_request(&mut reader, &mut output).is_err());
    assert!(output.len() < 1024);
}
#[test]
fn command_explicit_discovery_marker_never_defaults_on() {
    assert!(!commands::parse_setup(&[]).unwrap().interactive_provider);
    assert!(
        commands::parse_setup(&args(&["--interactive-provider"]))
            .unwrap()
            .interactive_provider
    );
    assert!(commands::parse_setup(&args(&["--interactive-provider", "--guided"])).is_err());
}
#[test]
fn command_doctor_missing_home_is_read_only_and_honest() {
    let f = Fixture::new();
    let value = commands::doctor(&f.home, &args(&["--json"])).unwrap();
    assert_eq!(value["report"]["ready"], false);
    assert_eq!(value["report"]["checks"][0]["status"], "missing");
    assert!(!f.home.exists());
    let text = commands::human_report(&value);
    assert!(text.contains("No provider or configured server was contacted"));
}
#[test]
fn command_doctor_unknown_and_duplicate_options_are_refused() {
    let f = Fixture::new();
    assert!(commands::doctor(&f.home, &args(&["--unknown"])).is_err());
    assert!(commands::doctor(&f.home, &args(&["--json", "--json"])).is_err());
    assert!(!f.home.exists());
}
#[test]
fn command_pentest_dry_run_writes_neither_workspace_nor_home() {
    let f = Fixture::new();
    let value = commands::pentest(
        &f.home,
        &args(&[
            "init",
            f.work.to_str().unwrap(),
            "--profile",
            "standard",
            "--dry-run",
            "--json",
        ]),
    )
    .unwrap();
    assert_eq!(value["report"]["dry_run"], true);
    assert!(!f.home.exists());
    assert!(!f.work.exists());
}
#[test]
fn command_pentest_repeat_preserves_user_evidence_and_report() {
    let f = Fixture::new();
    let flags = args(&["init", f.work.to_str().unwrap(), "--profile", "standard"]);
    commands::pentest(&f.home, &flags).unwrap();
    std::fs::write(f.work.join("evidence/raw.bin"), b"original evidence").unwrap();
    std::fs::write(f.work.join("reports/report.md"), b"operator report").unwrap();
    let repeat = commands::pentest(&f.home, &flags).unwrap();
    assert_eq!(
        std::fs::read(f.work.join("evidence/raw.bin")).unwrap(),
        b"original evidence"
    );
    assert_eq!(
        std::fs::read(f.work.join("reports/report.md")).unwrap(),
        b"operator report"
    );
    assert!(!repeat["report"]["conflicts"].as_array().unwrap().is_empty());
    assert!(!f.home.exists());
}
#[test]
fn command_pentest_templates_are_six_real_named_workflows() {
    let f = Fixture::new();
    let value = commands::pentest(&f.home, &args(&["templates", "--json"])).unwrap();
    let list = value["templates"].as_array().unwrap();
    assert_eq!(list.len(), 6);
    assert!(list.iter().any(|v| v["id"] == "validate-finding"));
    assert!(commands::human_report(&value).contains("scope-review"));
    assert!(!f.home.exists());
}
#[test]
fn command_pentest_status_counts_real_files_without_initializing_home() {
    let f = Fixture::new();
    commands::pentest(&f.home, &args(&["init", f.work.to_str().unwrap()])).unwrap();
    std::fs::write(f.work.join("evidence/one"), b"a").unwrap();
    let value = commands::pentest(
        &f.home,
        &args(&["status", f.work.to_str().unwrap(), "--json"]),
    )
    .unwrap();
    assert_eq!(value["report"]["scope_valid"], true);
    assert_eq!(value["report"]["evidence"]["files"], 1);
    assert!(!f.home.exists());
}
#[test]
fn command_pentest_invalid_complete_request_cannot_create_destination() {
    let f = Fixture::new();
    assert!(commands::pentest(
        &f.home,
        &args(&["init", f.work.to_str().unwrap(), "--profile", "unknown"])
    )
    .is_err());
    assert!(!f.work.exists());
    assert!(commands::pentest(
        &f.home,
        &args(&["init", f.work.to_str().unwrap(), "--unknown"])
    )
    .is_err());
    assert!(!f.work.exists());
}

fn make_bundle(f: &Fixture, name: &str, default_on: bool) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = f.home.join("mods").join(name);
    std::fs::create_dir_all(path.join("commands")).unwrap();
    for dir in [
        &f.home,
        f.home.join("mods").as_path(),
        path.as_path(),
        path.join("commands").as_path(),
    ] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (relative, contents) in [
        (
            "mod.toml",
            format!("description=\"Fixture bundle\"\ndefault={default_on}\nversion=\"1\"\n"),
        ),
        ("instructions.md", "Local inert guidance\n".into()),
        (
            "commands/review.md",
            "Review the recorded evidence\n".into(),
        ),
    ] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(relative))
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
    }
    path
}
#[test]
fn command_mod_validation_preserves_existing_names_and_generic_metadata() {
    let f = Fixture::new();
    make_bundle(&f, "My theme", true);
    let status = mods::validation_status(&f.home).unwrap();
    assert_eq!(status.bundles, 1);
    assert_eq!(status.commands, 1);
    assert_eq!(status.enabled, vec!["My theme"]);
    let loaded = mods::load_all(&f.home);
    assert_eq!(loaded[0].name, "My theme");
    assert_eq!(
        loaded[0].commands["review"],
        "Review the recorded evidence\n"
    );
}
#[test]
fn command_mod_malformed_enabled_metadata_never_enables_defaults_or_changes_bytes() {
    let f = Fixture::new();
    make_bundle(&f, "fixture", true);
    let path = f.home.join("mods/enabled.json");
    let bytes = b"{\"enabled\": [";
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = mods::load_all(&f.home);
    assert!(mods::initial_enabled(&f.home, &loaded).is_empty());
    assert!(mods::read_enabled_checked(&f.home).is_err());
    assert!(mods::read_enabled_checked(&f.home)
        .unwrap_err()
        .contains("metadata is malformed"));
    assert!(mods::validation_status(&f.home).is_err());
    assert!(mods::toggle(&f.home, &loaded, "fixture").is_err());
    assert!(mods::write_enabled(&f.home, &mods::EnabledSet::default()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!f.home.join("mods/.enabled.lock").exists());
}
#[test]
fn command_mod_legacy_public_enabled_file_is_replaced_privately_and_atomically() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    make_bundle(&f, "fixture", false);
    let path = f.home.join("mods/enabled.json");
    std::fs::write(&path, b"{\"enabled\":[]}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();
    mods::write_enabled(
        &f.home,
        &mods::EnabledSet {
            enabled: vec!["fixture".into()],
        },
    )
    .unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        mods::read_enabled_checked(&f.home)
            .unwrap()
            .unwrap()
            .enabled,
        vec!["fixture"]
    );
    assert!(!std::fs::read_dir(f.home.join("mods"))
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with(".enabled-")));
}
#[test]
fn command_mod_toggle_respects_real_default_state() {
    let f = Fixture::new();
    make_bundle(&f, "fixture", true);
    let loaded = mods::load_all(&f.home);
    assert!(!mods::toggle(&f.home, &loaded, "fixture").unwrap());
    assert!(mods::initial_enabled(&f.home, &loaded).is_empty());
    assert!(mods::toggle(&f.home, &loaded, "fixture").unwrap());
    assert_eq!(mods::initial_enabled(&f.home, &loaded), vec!["fixture"]);
}
#[test]
fn command_mod_lock_contention_preserves_enabled_bytes() {
    let f = Fixture::new();
    make_bundle(&f, "fixture", false);
    mods::write_enabled(&f.home, &mods::EnabledSet::default()).unwrap();
    let path = f.home.join("mods/enabled.json");
    let before = std::fs::read(&path).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.home.join("mods/.enabled.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert!(mods::write_enabled(
        &f.home,
        &mods::EnabledSet {
            enabled: vec!["fixture".into()]
        }
    )
    .is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}
#[test]
fn command_mod_enabled_symlink_is_refused_without_touching_target() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    make_bundle(&f, "fixture", false);
    let outside = f.root.join("outside");
    std::fs::write(&outside, b"{\"enabled\":[]}").unwrap();
    symlink(&outside, f.home.join("mods/enabled.json")).unwrap();
    assert!(mods::write_enabled(
        &f.home,
        &mods::EnabledSet {
            enabled: vec!["fixture".into()]
        }
    )
    .is_err());
    assert_eq!(std::fs::read(outside).unwrap(), b"{\"enabled\":[]}");
}
#[test]
fn command_mod_enabled_hardlink_is_refused_without_touching_target() {
    let f = Fixture::new();
    make_bundle(&f, "fixture", false);
    let outside = f.root.join("outside");
    std::fs::write(&outside, b"{\"enabled\":[]}").unwrap();
    std::fs::hard_link(&outside, f.home.join("mods/enabled.json")).unwrap();
    assert!(mods::write_enabled(&f.home, &mods::EnabledSet::default()).is_err());
    assert_eq!(std::fs::read(outside).unwrap(), b"{\"enabled\":[]}");
}
#[test]
fn command_mod_invalid_instruction_utf8_is_reported_and_never_loaded() {
    let f = Fixture::new();
    let path = make_bundle(&f, "fixture", true);
    std::fs::write(path.join("instructions.md"), [0xff, 0xfe]).unwrap();
    assert!(mods::validation_status(&f.home).is_err());
    assert!(mods::load_all(&f.home).is_empty());
}
#[test]
fn command_mod_invalid_command_utf8_is_reported_and_never_loaded() {
    let f = Fixture::new();
    let path = make_bundle(&f, "fixture", true);
    std::fs::write(path.join("commands/review.md"), [0xff, 0xfe]).unwrap();
    assert!(mods::validation_status(&f.home).is_err());
    assert!(mods::load_all(&f.home).is_empty());
}
#[test]
fn command_mod_duplicate_enabled_names_are_rejected_before_publishing() {
    let f = Fixture::new();
    make_bundle(&f, "fixture", false);
    assert!(mods::write_enabled(
        &f.home,
        &mods::EnabledSet {
            enabled: vec!["fixture".into(), "fixture".into()]
        }
    )
    .is_err());
    assert!(!f.home.join("mods/enabled.json").exists());
}
#[test]
fn command_engagement_real_project_loaders_require_explicit_folder_trust() {
    struct Cwd(PathBuf);
    impl Drop for Cwd {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }
    let f = Fixture::new();
    commands::setup(&f.home, &[]).unwrap();
    commands::pentest(&f.home, &args(&["init", f.work.to_str().unwrap()])).unwrap();
    let _cwd = Cwd(std::env::current_dir().unwrap());
    std::env::set_current_dir(&f.work).unwrap();
    let trust = orbit_tools::permissions::FolderTrust::new(f.home.clone());
    assert!(!trust.is_trusted(&f.work));
    assert!(orbit_engine::skills::load_skills(&f.home, false).is_empty());
    assert!(!orbit_engine::skills::load_agents(&f.home, false)
        .iter()
        .any(|a| a.name == "triage"));
    trust.trust(&f.work).unwrap();
    let trusted = trust.is_trusted(&f.work);
    assert!(trusted);
    let skills = orbit_engine::skills::load_skills(&f.home, trusted);
    assert_eq!(skills.len(), 6);
    let agent = orbit_engine::skills::load_agents(&f.home, trusted)
        .into_iter()
        .find(|a| a.name == "triage")
        .unwrap();
    assert!(agent.model.is_empty());
    assert_eq!(agent.tools, vec!["Read", "Glob", "Grep"]);
    assert!(!f.home.join("customization.json").exists());
}
