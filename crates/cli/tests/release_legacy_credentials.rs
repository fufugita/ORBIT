#![cfg(unix)]
#![deny(unsafe_code)]

use orbit_cli::tool_runtime::subagent_turn_config;
use orbit_cli::{checked_model_turn, engine_turn_config, try_engine_turn_config};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_CASE: &str = "ORBIT_LEGACY_BUILDER_FIXTURE_CHILD";
const CHILD_HOME: &str = "ORBIT_LEGACY_BUILDER_FIXTURE_HOME";
const AMBIENT_KEY: &str = "synthetic-legacy-builder-key-bf7264";
const DECLARED_REFERENCE: &str = "ORBIT_LEGACY_BUILDER_DECLARED_KEY";
const GATE: &str = "http://127.0.0.1:9/v1";
const RAW_MODEL: &str = "vendor/raw";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-legacy-builder-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Each ENV variant runs in its own child. No test mutates process-wide ENV.
fn isolated(
    test_name: &str,
    variant: &str,
    environment: &[(&str, &str)],
    check: impl FnOnce(&Path),
) {
    let selected = format!("{test_name}/{variant}");
    if let Some(child_case) = std::env::var_os(CHILD_CASE) {
        if child_case == selected.as_str() {
            check(Path::new(&std::env::var_os(CHILD_HOME).unwrap()));
        }
        return;
    }
    let home = Home::new();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env_clear()
        .env(CHILD_CASE, &selected)
        .env(CHILD_HOME, &home.0)
        .env("HOME", &home.0)
        .env("ORBIT_MODEL", RAW_MODEL)
        .env("ORBIT_PROVIDER", "legacy-provider")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if variant != "missing_gate" {
        command.env("ORBIT_GATE_URL", GATE);
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            let diagnostics = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .replace(AMBIENT_KEY, "[redacted fixture key]");
            assert!(
                status.success(),
                "isolated builder case failed: {selected}\n{diagnostics}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated builder case exceeded its deadline: {selected}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn configured_no_auth(home: &Path) {
    let path = home.join("providers.toml");
    std::fs::write(
        &path,
        format!(
            "[[provider]]\nname='configured'\nkind='openai-compatible'\nurl='{GATE}'\n[[provider.models]]\nid='{RAW_MODEL}'\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn legacy_builder_configured_no_auth_ignores_ambient_gate_key() {
    isolated(
        "legacy_builder_configured_no_auth_ignores_ambient_gate_key",
        "configured",
        &[("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
        |home| {
            configured_no_auth(home);
            let selected =
                checked_model_turn(home, "configured/vendor/raw", None, None, false).unwrap();
            assert_eq!(selected.provider_id, "configured");
            assert_eq!(selected.model, RAW_MODEL);
            assert!(selected.credential_env.is_none());
            let checked =
                try_engine_turn_config(home, "configured", GATE, RAW_MODEL, None, None).unwrap();
            assert!(checked.credential_env.is_none());
            assert!(
                engine_turn_config(home, "configured", GATE, RAW_MODEL, None, None)
                    .credential_env
                    .is_none()
            );
            assert!(!home.join("auth").exists());
            assert!(!home.join("ledger").exists());
        },
    );
}

#[test]
fn legacy_builder_absent_or_empty_gate_key_keeps_unauthenticated_path() {
    for (variant, environment) in [
        ("absent", Vec::new()),
        ("empty", vec![("ORBIT_GATE_TOKEN", "")]),
    ] {
        isolated(
            "legacy_builder_absent_or_empty_gate_key_keeps_unauthenticated_path",
            variant,
            &environment,
            |home| {
                let checked =
                    checked_model_turn(home, RAW_MODEL, Some("legacy-provider"), Some(GATE), false)
                        .unwrap();
                assert!(checked.credential_env.is_none());
                assert!(
                    try_engine_turn_config(home, "legacy-provider", GATE, RAW_MODEL, None, None)
                        .unwrap()
                        .credential_env
                        .is_none()
                );
                let fallback = subagent_turn_config(home);
                assert!(fallback.credential_env.is_none());
                assert_eq!(fallback.provider_id, "legacy-provider");
                assert_eq!(fallback.model, RAW_MODEL);
                assert_eq!(fallback.gate, GATE);
                assert!(std::fs::read_dir(home).unwrap().next().is_none());
            },
        );
    }
}

#[test]
fn legacy_builder_nonempty_gate_key_is_explicit_and_fallback_honors_declared_reference() {
    for (variant, environment, expected_fallback) in [
        (
            "legacy",
            vec![("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
            "ORBIT_GATE_TOKEN",
        ),
        (
            "declared",
            vec![
                ("ORBIT_GATE_TOKEN", AMBIENT_KEY),
                ("ORBIT_CREDENTIAL_ENV", DECLARED_REFERENCE),
            ],
            DECLARED_REFERENCE,
        ),
    ] {
        isolated(
            "legacy_builder_nonempty_gate_key_is_explicit_and_fallback_honors_declared_reference",
            variant,
            &environment,
            |home| {
                let selected =
                    checked_model_turn(home, RAW_MODEL, Some("legacy-provider"), Some(GATE), false)
                        .unwrap();
                assert_eq!(selected.credential_env.as_deref(), Some("ORBIT_GATE_TOKEN"));
                let checked =
                    try_engine_turn_config(home, "legacy-provider", GATE, RAW_MODEL, None, None)
                        .unwrap();
                assert_eq!(checked.credential_env.as_deref(), Some("ORBIT_GATE_TOKEN"));
                let explicit = try_engine_turn_config(
                    home,
                    "legacy-provider",
                    GATE,
                    RAW_MODEL,
                    Some(DECLARED_REFERENCE),
                    None,
                )
                .unwrap();
                assert_eq!(explicit.credential_env.as_deref(), Some(DECLARED_REFERENCE));
                assert_eq!(
                    subagent_turn_config(home).credential_env.as_deref(),
                    Some(expected_fallback)
                );
                assert!(std::fs::read_dir(home).unwrap().next().is_none());
            },
        );
    }
}

#[test]
fn legacy_builder_missing_endpoint_never_selects_an_implicit_local_service() {
    isolated(
        "legacy_builder_missing_endpoint_never_selects_an_implicit_local_service",
        "missing_gate",
        &[("ORBIT_GATE_TOKEN", AMBIENT_KEY)],
        |home| {
            let fallback = subagent_turn_config(home);
            assert!(url::Url::parse(&fallback.gate).is_err());
            assert_eq!(fallback.credential_env.as_deref(), Some("ORBIT_GATE_TOKEN"));
            assert!(std::fs::read_dir(home).unwrap().next().is_none());
        },
    );
}
