#![cfg(target_os = "linux")]
pub use orbit_cli::mods;
pub use orbit_cli::profile_commands;
#[path = "../src/customization.rs"]
#[allow(dead_code)]
mod customization;
#[path = "../src/doctor.rs"]
#[allow(dead_code)]
mod doctor;
#[path = "../src/setup.rs"]
#[allow(dead_code)]
mod setup;
use doctor::*;
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, ProviderAuthIdentity, ProviderCredentialRevision, ProviderCredentialStore,
};
pub use orbit_cli::{config, lsp, phase_routing, provider_policies, tool_runtime};
use std::ffi::OsString;
use std::net::TcpListener;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("orbit-doctor-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let provider=serde_json::from_value(serde_json::json!({"name":"example","url":"http://127.0.0.1:9","models":[{"id":"family/model-a"}]})).unwrap();
        let request = setup::SetupRequest {
            provider: Some(provider),
            ..Default::default()
        };
        setup::apply_setup(&setup::plan_setup(&home, &request).unwrap()).unwrap();
        Self {
            root,
            home,
            workspace,
        }
    }
    fn report(&self) -> DoctorReport {
        doctor(&self.home, &self.workspace)
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        let p = self.home.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn status(&self, id: &str) -> CheckStatus {
        self.report()
            .checks
            .into_iter()
            .find(|c| c.id == id)
            .unwrap()
            .status
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn valid_identity_reports_verified_and_provider_not_tested() {
    let f = Fixture::new();
    let r = f.report();
    assert!(r.ready);
    assert_eq!(f.status("identity"), CheckStatus::Ready);
    assert_eq!(f.status("providers"), CheckStatus::Configured);
    assert_eq!(f.status("provider.connectivity"), CheckStatus::NotTested);
}
#[test]
fn missing_home_is_read_only() {
    let f = Fixture::new();
    let missing = f.root.join("absent");
    let r = doctor(&missing, &f.workspace);
    assert!(!r.ready);
    assert_eq!(r.checks[0].status, CheckStatus::Missing);
    assert!(!missing.exists());
}
#[test]
fn insecure_home_is_invalid_without_chmod() {
    let f = Fixture::new();
    std::fs::set_permissions(&f.home, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!f.report().ready);
    assert_eq!(
        std::fs::metadata(&f.home).unwrap().permissions().mode() & 0o777,
        0o755
    );
}
#[test]
fn invalid_signature_is_not_ready() {
    let f = Fixture::new();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.home.join("trust/manifest.json")).unwrap())
            .unwrap();
    manifest["signature"] = "00".repeat(64).into();
    f.write(
        "trust/manifest.json",
        serde_json::to_vec(&manifest).unwrap(),
    );
    assert_eq!(f.status("identity"), CheckStatus::Invalid);
    assert!(!f.report().ready);
}
#[test]
fn torn_ledger_is_invalid_without_repair() {
    let f = Fixture::new();
    let path = f.home.join("ledger/segments/0000000000000000.log");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(255);
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(f.status("ledger"), CheckStatus::Invalid);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
fn malformed_provider_config_is_invalid() {
    let f = Fixture::new();
    f.write("providers.toml", b"[broken");
    assert_eq!(f.status("providers"), CheckStatus::Invalid);
    assert!(!f.report().ready);
}
#[test]
fn oversized_configuration_is_bounded() {
    let f = Fixture::new();
    f.write("providers.toml", vec![b' '; 128 * 1024 + 1]);
    assert_eq!(f.status("providers"), CheckStatus::Invalid);
    assert!(serde_json::to_vec(&f.report()).unwrap().len() < 128 * 1024);
}
#[test]
fn fabricated_credential_value_never_appears() {
    const CHILD: &str = "ORBIT_DOCTOR_CREDENTIAL_CHILD";
    const ENV: &str = "ORBIT_DOCTOR_CREDENTIAL_VALUE";
    const SECRET: &str = "fabricated-private-value-9837142";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let environment = CredentialEnvironment::new();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fabricated_credential_value_never_appears",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", &environment.0)
            .env("TMPDIR", &environment.0)
            .env(CHILD, "1")
            .env(ENV, SECRET)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated credential check timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let json = stdout
            .lines()
            .find_map(|line| {
                line.split_once("ORBIT_DOCTOR_REPORT=")
                    .map(|(_, json)| json)
            })
            .expect("child must return the measured report");
        let report: DoctorReport = serde_json::from_str(json).unwrap();
        assert!(report.ready);
        assert!(!report.checks.is_empty());
        assert_eq!(
            report
                .checks
                .iter()
                .find(|check| check.id == "credential.0")
                .unwrap()
                .status,
            CheckStatus::Ready
        );
        assert!(!stdout.contains(SECRET));
        return;
    }
    let f = Fixture::new();
    assert_eq!(std::env::var(ENV).unwrap(), SECRET);
    let mut cfg = config::ProvidersConfig::load(&f.home).unwrap();
    cfg.provider[0].env = Some(ENV.into());
    f.write("providers.toml", toml::to_string(&cfg).unwrap());
    let report = f.report();
    assert_eq!(f.status("credential.0"), CheckStatus::Ready);
    let bytes = serde_json::to_string(&report).unwrap();
    assert!(!bytes.contains(SECRET));
    println!("ORBIT_DOCTOR_REPORT={bytes}");
}
#[test]
fn missing_credential_presence_is_missing() {
    let f = Fixture::new();
    let mut cfg = config::ProvidersConfig::load(&f.home).unwrap();
    cfg.provider[0].env = Some(format!("ORBIT_DOCTOR_MISSING_{}", ulid::Ulid::new()));
    f.write("providers.toml", toml::to_string(&cfg).unwrap());
    assert_eq!(f.status("credential.0"), CheckStatus::Missing);
    assert!(!f.report().ready);
}
#[test]
fn configured_executable_is_never_launched() {
    let f = Fixture::new();
    let executable = f.root.join("configured-tool");
    let marker = f.root.join("spawned");
    std::fs::write(
        &executable,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    f.write(
        "mcp.json",
        serde_json::to_vec(&serde_json::json!({"servers":{"fixture":{"command":executable}}}))
            .unwrap(),
    );
    assert_eq!(f.status("mcp.0"), CheckStatus::NotTested);
    assert!(!marker.exists());
}
#[test]
fn absent_executable_is_unavailable() {
    let f = Fixture::new();
    f.write(
        "mcp.json",
        br#"{"servers":{"fixture":{"command":"/absent/fixture"}}}"#,
    );
    assert_eq!(f.status("mcp.0"), CheckStatus::Unavailable);
}
#[test]
fn invalid_integration_json_is_visible() {
    let f = Fixture::new();
    f.write("mcp.json", b"{broken");
    assert_eq!(f.status("mcp"), CheckStatus::Invalid);
}
#[test]
fn malformed_lsp_toml_is_visible() {
    let f = Fixture::new();
    f.write("lsp.toml", b"[broken");
    assert_eq!(f.status("lsp"), CheckStatus::Invalid);
}
#[test]
fn malformed_profile_does_not_reset_file() {
    let f = Fixture::new();
    f.write("customization.json", b"{broken");
    assert_eq!(f.status("customization"), CheckStatus::Invalid);
    assert_eq!(
        std::fs::read(f.home.join("customization.json")).unwrap(),
        b"{broken"
    );
}
#[test]
fn path_locator_rejects_symlink_and_nonexecutable() {
    let f = Fixture::new();
    let plain = f.root.join("plain");
    std::fs::write(&plain, b"data").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(find_executable(&plain.to_string_lossy(), None).is_none());
    let link = f.root.join("alias");
    symlink(Path::new("/bin/sh"), &link).unwrap();
    assert!(find_executable(&link.to_string_lossy(), None).is_none());
}
#[test]
fn browser_without_bundle_metadata_is_not_tested() {
    let f = Fixture::new();
    let cli = f.root.join("orbit");
    let web = f.root.join("orbit-web");
    for p in [&cli, &web] {
        std::fs::write(p, b"fixture executable bytes").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(browser_check(&cli).status, CheckStatus::NotTested);
    std::fs::remove_file(web).unwrap();
    assert_eq!(browser_check(&cli).status, CheckStatus::Unavailable);
}
#[test]
fn trusted_project_integrations_are_inspected_without_launch() {
    let f = Fixture::new();
    let project = f.workspace.join(".orbit");
    std::fs::create_dir(&project).unwrap();
    let executable = f.root.join("project-tool");
    let marker = f.root.join("project-spawned");
    std::fs::write(
        &executable,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        project.join("mcp.json"),
        serde_json::to_vec(&serde_json::json!({"servers":{"fixture":{"command":executable}}}))
            .unwrap(),
    )
    .unwrap();
    orbit_tools::permissions::FolderTrust::new(f.home.clone())
        .trust(&f.workspace)
        .unwrap();
    assert_eq!(f.status("project.mcp.0"), CheckStatus::NotTested);
    assert!(!marker.exists());
}
#[test]
fn untrusted_project_configuration_is_not_activated_or_parsed() {
    let f = Fixture::new();
    let project = f.workspace.join(".orbit");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("mcp.json"), b"{not valid").unwrap();
    let report = f.report();
    assert!(
        report
            .checks
            .iter()
            .find(|c| c.id == "project.trust")
            .unwrap()
            .detail
            .contains("untrusted")
    );
    assert!(
        !report
            .checks
            .iter()
            .any(|c| c.id.starts_with("project.mcp"))
    );
}
#[test]
fn matching_bundle_hashes_and_version_are_verified_without_execution() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    let cli = f.root.join("orbit");
    let web = f.root.join("orbit-web");
    let mut components = serde_json::Map::new();
    for path in [&cli, &web] {
        let bytes = b"#!/bin/sh\nexit 71\n";
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
        components.insert(
            path.file_name().unwrap().to_str().unwrap().into(),
            serde_json::json!({"size":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))}),
        );
    }
    std::fs::write(f.root.join("manifest.json"),serde_json::to_vec(&serde_json::json!({"schema_version":1,"version":env!("CARGO_PKG_VERSION"),"target":native_target(),"components":components,"signature":"absent"})).unwrap()).unwrap();
    assert_eq!(browser_check(&cli).status, CheckStatus::Ready);
    std::fs::set_permissions(&web, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(web, b"tampered executable bytes").unwrap();
    assert_eq!(browser_check(&cli).status, CheckStatus::Invalid);
}

const CREDENTIAL_ENV: &str = "ORBIT_DOCTOR_EXACT_CREDENTIAL";
const SAVED_CREDENTIAL: &str = "synthetic-doctor-private-key-714b8960";
const ENV_CREDENTIAL: &str = "synthetic-doctor-env-key-947ba510";
const AMBIENT_CREDENTIAL: &str = "synthetic-doctor-ambient-key-12d87b91";
const CREDENTIAL_CHILD: &str = "ORBIT_DOCTOR_STATUS_CHILD";

struct CredentialEnvironment(PathBuf);
impl CredentialEnvironment {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-doctor-env-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for CredentialEnvironment {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated_credential_status(name: &str, environment: &[(&str, OsString)], check: impl FnOnce()) {
    if std::env::var(CREDENTIAL_CHILD).as_deref() == Ok(name) {
        check();
        return;
    }
    let private_environment = CredentialEnvironment::new();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env_clear()
        .env(CREDENTIAL_CHILD, name)
        .env("HOME", &private_environment.0)
        .env("TMPDIR", &private_environment.0)
        .env("XDG_CONFIG_HOME", private_environment.0.join("xdg-config"))
        .env("XDG_CACHE_HOME", private_environment.0.join("xdg-cache"))
        .env("XDG_DATA_HOME", private_environment.0.join("xdg-data"))
        .env("CODEX_HOME", private_environment.0.join("codex"))
        .env("CLAUDE_CONFIG_DIR", private_environment.0.join("claude"))
        .env("HERMES_HOME", private_environment.0.join("hermes"))
        .current_dir(&private_environment.0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (key, value) in environment {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated doctor status exceeded its deadline: {name}");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    let mut diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [SAVED_CREDENTIAL, ENV_CREDENTIAL, AMBIENT_CREDENTIAL] {
        diagnostics = diagnostics.replace(secret, "[redacted fixture key]");
    }
    assert!(
        output.status.success(),
        "isolated doctor status failed: {name}\n{diagnostics}"
    );
}

#[derive(PartialEq, Eq)]
struct CredentialFileSnapshot {
    path: PathBuf,
    mode: u32,
    uid: u32,
    links: u64,
    inode: u64,
    bytes: Vec<u8>,
    target: Option<PathBuf>,
}

fn credential_files(root: &Path) -> Vec<CredentialFileSnapshot> {
    fn visit(root: &Path, path: &Path, result: &mut Vec<CredentialFileSnapshot>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let is_link = metadata.file_type().is_symlink();
        result.push(CredentialFileSnapshot {
            path: path.strip_prefix(root).unwrap().to_path_buf(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            links: metadata.nlink(),
            inode: metadata.ino(),
            bytes: if metadata.is_file() && !is_link {
                std::fs::read(path).unwrap()
            } else {
                Vec::new()
            },
            target: is_link.then(|| std::fs::read_link(path).unwrap()),
        });
        if metadata.is_dir() && !is_link {
            for child in std::fs::read_dir(path).unwrap() {
                visit(root, &child.unwrap().path(), result);
            }
        }
    }
    let mut result = Vec::new();
    visit(root, root, &mut result);
    result.sort_by(|left, right| left.path.cmp(&right.path));
    result
}

fn configured_credential(fixture: &Fixture) -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
    providers.provider[0].url = format!("http://{}/v1", listener.local_addr().unwrap());
    providers.provider[0].env = Some(CREDENTIAL_ENV.into());
    fixture.write("providers.toml", toml::to_string(&providers).unwrap());
    listener
}

fn selected_credential(fixture: &Fixture) -> ProviderAuthIdentity {
    let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
    let provider = &providers.provider[0];
    let endpoint = config::validate_provider_endpoint(&provider.url).unwrap();
    ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        endpoint.as_str(),
        provider.env.as_deref(),
    )
    .unwrap()
}

fn save_credential(fixture: &Fixture) -> (PathBuf, ProviderCredentialRevision) {
    let identity = selected_credential(fixture);
    let saved = ProviderCredentialStore::new(&fixture.home)
        .unwrap()
        .save(
            &identity,
            SecretBytes::new(SAVED_CREDENTIAL.as_bytes().to_vec()),
            ExpectedRevision::Absent,
        )
        .unwrap();
    (
        fixture
            .home
            .join("auth/providers")
            .join(format!("{}.credential", identity.binding_id())),
        saved.revision,
    )
}

fn readonly_credential_report(
    fixture: &Fixture,
    listener: &TcpListener,
    home: &Path,
) -> DoctorReport {
    let before = credential_files(&fixture.root);
    let report = doctor(home, &fixture.workspace);
    assert!(
        credential_files(&fixture.root) == before,
        "doctor changed fixture files, modes, links or inodes"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "offline doctor contacted a provider"
    );
    let bytes = serde_json::to_vec(&report).unwrap();
    for secret in [SAVED_CREDENTIAL, ENV_CREDENTIAL, AMBIENT_CREDENTIAL] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()),
            "doctor serialized a credential value"
        );
    }
    assert_eq!(
        report
            .checks
            .iter()
            .find(|check| check.id == "provider.connectivity")
            .unwrap()
            .status,
        CheckStatus::NotTested
    );
    report
}

fn credential_check(report: &DoctorReport) -> &DoctorCheck {
    report
        .checks
        .iter()
        .find(|check| check.id == "credential.0")
        .unwrap()
}

#[test]
fn saved_private_credential_is_ready_without_environment_or_file_changes() {
    isolated_credential_status(
        "saved_private_credential_is_ready_without_environment_or_file_changes",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            save_credential(&fixture);
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert!(report.ready);
            assert_eq!(credential_check(&report).status, CheckStatus::Ready);
            assert!(
                credential_check(&report)
                    .detail
                    .contains("saved private key")
            );
        },
    );
}

#[test]
fn relative_home_uses_the_same_exact_saved_credential() {
    isolated_credential_status(
        "relative_home_uses_the_same_exact_saved_credential",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            save_credential(&fixture);
            let current = std::env::current_dir().unwrap();
            let relative = fixture.home.strip_prefix(&current).unwrap();
            assert!(!relative.is_absolute());
            let report = readonly_credential_report(&fixture, &listener, relative);
            assert_eq!(credential_check(&report).status, CheckStatus::Ready);
            assert!(
                credential_check(&report)
                    .detail
                    .contains("saved private key")
            );
        },
    );
}

#[test]
fn environment_override_is_ready_even_when_unused_saved_record_is_corrupt() {
    isolated_credential_status(
        "environment_override_is_ready_even_when_unused_saved_record_is_corrupt",
        &[(CREDENTIAL_ENV, ENV_CREDENTIAL.into())],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let (record, _) = save_credential(&fixture);
            std::fs::write(record, b"invalid-unused-saved-record").unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert!(report.ready);
            assert_eq!(credential_check(&report).status, CheckStatus::Ready);
            assert!(
                credential_check(&report)
                    .detail
                    .contains("environment override")
            );
        },
    );
}

#[test]
fn empty_environment_uses_saved_key_then_reports_removed_binding_missing() {
    isolated_credential_status(
        "empty_environment_uses_saved_key_then_reports_removed_binding_missing",
        &[(CREDENTIAL_ENV, OsString::new())],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let (_, revision) = save_credential(&fixture);
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Ready);
            assert!(
                credential_check(&report)
                    .detail
                    .contains("saved private key")
            );
            ProviderCredentialStore::new(&fixture.home)
                .unwrap()
                .remove(
                    &selected_credential(&fixture),
                    ExpectedRevision::Exact(revision),
                )
                .unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Missing);
            assert!(!report.ready);
        },
    );
}

#[test]
fn invalid_nonempty_environment_does_not_fall_back_to_saved_key() {
    isolated_credential_status(
        "invalid_nonempty_environment_does_not_fall_back_to_saved_key",
        &[(CREDENTIAL_ENV, "invalid\r\nheader".into())],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            save_credential(&fixture);
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(!report.ready);
        },
    );
}

#[test]
fn non_utf8_environment_is_invalid_without_saved_fallback() {
    isolated_credential_status(
        "non_utf8_environment_is_invalid_without_saved_fallback",
        &[(CREDENTIAL_ENV, OsString::from_vec(vec![0xff, b'x']))],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            save_credential(&fixture);
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(!report.ready);
        },
    );
}

#[test]
fn corrupted_saved_record_is_invalid_without_repair() {
    isolated_credential_status(
        "corrupted_saved_record_is_invalid_without_repair",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let (record, _) = save_credential(&fixture);
            std::fs::write(record, b"truncated-private-record").unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(credential_check(&report).detail.contains("storage"));
            assert!(!report.ready);
        },
    );
}

#[test]
fn missing_store_lock_is_invalid_and_never_created_by_doctor() {
    isolated_credential_status(
        "missing_store_lock_is_invalid_and_never_created_by_doctor",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            save_credential(&fixture);
            let lock = fixture.home.join("auth/providers/store.lock");
            std::fs::remove_file(&lock).unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(!report.ready);
            assert!(!lock.exists());
        },
    );
}

#[test]
fn symlinked_saved_record_is_invalid_without_following_or_replacing_it() {
    isolated_credential_status(
        "symlinked_saved_record_is_invalid_without_following_or_replacing_it",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let (record, _) = save_credential(&fixture);
            let target = fixture.root.join("owned-record-target");
            std::fs::rename(&record, &target).unwrap();
            symlink(&target, &record).unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(!report.ready);
        },
    );
}

#[test]
fn benign_query_is_part_of_the_exact_saved_binding() {
    isolated_credential_status(
        "benign_query_is_part_of_the_exact_saved_binding",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            providers.provider[0].url.push_str("?tenant=first");
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            let (record, _) = save_credential(&fixture);
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Ready);
            providers.provider[0].url = providers.provider[0]
                .url
                .replace("tenant=first", "tenant=second");
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Missing);
            assert!(!report.ready);
            let misplaced = fixture.home.join("auth/providers").join(format!(
                "{}.credential",
                selected_credential(&fixture).binding_id()
            ));
            std::fs::copy(record, &misplaced).unwrap();
            std::fs::set_permissions(&misplaced, std::fs::Permissions::from_mode(0o600)).unwrap();
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(credential_check(&report).status, CheckStatus::Invalid);
            assert!(!report.ready);
        },
    );
}

#[test]
fn no_auth_ignores_saved_storage_and_all_ambient_credential_values() {
    isolated_credential_status(
        "no_auth_ignores_saved_storage_and_all_ambient_credential_values",
        &[
            (CREDENTIAL_ENV, ENV_CREDENTIAL.into()),
            ("ORBIT_GATE_TOKEN", AMBIENT_CREDENTIAL.into()),
        ],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let (record, _) = save_credential(&fixture);
            std::fs::write(record, b"unused-invalid-private-record").unwrap();
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            providers.provider[0].env = None;
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert!(report.ready);
            assert_eq!(credential_check(&report).status, CheckStatus::Configured);
            assert!(
                credential_check(&report)
                    .detail
                    .contains("no authentication")
            );
        },
    );
}

#[test]
fn credential_query_is_invalid_and_never_echoed_by_doctor() {
    isolated_credential_status(
        "credential_query_is_invalid_and_never_echoed_by_doctor",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            providers.provider[0]
                .url
                .push_str(&format!("?api_key={SAVED_CREDENTIAL}"));
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            assert_eq!(
                report
                    .checks
                    .iter()
                    .find(|check| check.id == "provider.0")
                    .unwrap()
                    .status,
                CheckStatus::Invalid
            );
            assert!(!report.checks.iter().any(|check| check.id == "credential.0"));
            assert!(!report.ready);
        },
    );
}

#[test]
fn streamable_http_mcp_is_configured_without_executable_or_requests() {
    isolated_credential_status(
        "streamable_http_mcp_is_configured_without_executable_or_requests",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            fixture.write(
                "mcp.json",
                serde_json::to_vec(&serde_json::json!({"servers":{"docs":{
                    "transport":"streamable-http",
                    "url":format!("http://{}/mcp", listener.local_addr().unwrap()),
                    "headers":{"Authorization":format!("Bearer {ENV_CREDENTIAL}")}
                }}}))
                .unwrap(),
            );
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            let check = report
                .checks
                .iter()
                .find(|check| check.id == "mcp.0")
                .unwrap();
            assert_eq!(check.status, CheckStatus::Configured);
            assert!(check.detail.contains("connectivity not tested"));
            assert_eq!(
                report
                    .checks
                    .iter()
                    .find(|check| check.id == "mcp.connectivity")
                    .unwrap()
                    .status,
                CheckStatus::NotTested
            );
        },
    );
}

#[test]
fn sse_mcp_is_configured_without_executable_or_requests() {
    isolated_credential_status(
        "sse_mcp_is_configured_without_executable_or_requests",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            fixture.write(
                "mcp.json",
                serde_json::to_vec(&serde_json::json!({"servers":{"docs":{
                    "transport":"sse",
                    "url":format!("http://{}/events", listener.local_addr().unwrap())
                }}}))
                .unwrap(),
            );
            let report = readonly_credential_report(&fixture, &listener, &fixture.home);
            let check = report
                .checks
                .iter()
                .find(|check| check.id == "mcp.0")
                .unwrap();
            assert_eq!(check.status, CheckStatus::Configured);
            assert!(check.detail.contains("connectivity not tested"));
            assert_eq!(
                report
                    .checks
                    .iter()
                    .find(|check| check.id == "mcp.connectivity")
                    .unwrap()
                    .status,
                CheckStatus::NotTested
            );
        },
    );
}

#[test]
fn malformed_remote_mcp_urls_are_invalid_without_requests_or_file_changes() {
    isolated_credential_status(
        "malformed_remote_mcp_urls_are_invalid_without_requests_or_file_changes",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let address = listener.local_addr().unwrap();
            for transport in ["streamable-http", "sse"] {
                for endpoint in [
                    "not-a-url".to_owned(),
                    format!("http://user:{SAVED_CREDENTIAL}@{address}/mcp"),
                    format!("http://{address}/mcp#fragment"),
                    "http://remote.example/mcp".to_owned(),
                ] {
                    fixture.write(
                        "mcp.json",
                        serde_json::to_vec(&serde_json::json!({"servers":{"docs":{
                            "transport":transport,
                            "url":endpoint
                        }}}))
                        .unwrap(),
                    );
                    let report = readonly_credential_report(&fixture, &listener, &fixture.home);
                    assert_eq!(
                        report
                            .checks
                            .iter()
                            .find(|check| check.id == "mcp.0")
                            .unwrap()
                            .status,
                        CheckStatus::Invalid
                    );
                    assert_eq!(
                        report
                            .checks
                            .iter()
                            .find(|check| check.id == "mcp.connectivity")
                            .unwrap()
                            .status,
                        CheckStatus::NotTested
                    );
                }
            }
        },
    );
}

#[test]
fn complete_doctor_report_stays_bounded_with_sixty_four_valid_providers() {
    isolated_credential_status(
        "complete_doctor_report_stays_bounded_with_sixty_four_valid_providers",
        &[],
        || {
            let fixture = Fixture::new();
            let listener = configured_credential(&fixture);
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let template = providers.provider[0].clone();
            providers.provider = (0..64)
                .map(|index| {
                    let mut provider = template.clone();
                    provider.name = format!("capacity-{index}");
                    provider.env = None;
                    provider.models[0].id = format!("capacity-model-{index}");
                    setup::validate_provider(&provider).unwrap();
                    provider
                })
                .collect();
            providers.roles.main = "capacity-0/capacity-model-0".into();
            let raw = toml::to_string(&providers).unwrap();
            let settings = phase_routing::parse_settings(&raw).unwrap();
            phase_routing::validate_settings(&providers, &settings).unwrap();
            assert_eq!(providers.provider.len(), 64);
            fixture.write("providers.toml", raw);

            let before = credential_files(&fixture.root);
            let report = doctor(&fixture.home, &fixture.workspace);
            assert!(
                credential_files(&fixture.root) == before,
                "doctor changed fixture files, modes, links or inodes"
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "offline doctor contacted a provider"
            );
            assert_eq!(
                report
                    .checks
                    .iter()
                    .find(|check| check.id == "providers")
                    .unwrap()
                    .status,
                CheckStatus::Configured
            );
            assert_eq!(
                report
                    .checks
                    .iter()
                    .find(|check| check.id == "provider.0")
                    .unwrap()
                    .status,
                CheckStatus::Configured
            );
            assert_eq!(credential_check(&report).status, CheckStatus::Configured);
            let limits = report
                .checks
                .iter()
                .find(|check| check.id == "limits")
                .unwrap();
            assert_eq!(limits.status, CheckStatus::Invalid);
            assert!(limits.required);
            assert_eq!(limits.detail, "Readiness checks truncated at 128");
            assert!(!report.ready);
            assert!(
                report.checks.len() <= 128,
                "complete doctor report has {} checks; maximum is 128",
                report.checks.len()
            );
        },
    );
}

const RETRY_PRIVATE_MARKER: &str = "retry-private-";

fn retry_adapter_identity() -> String {
    orbit_engine::retry::adapter_identity_digest(&orbit_provider_http::openai::openai_identity())
}

fn retry_check<'a>(report: &'a DoctorReport, id: &str) -> &'a DoctorCheck {
    let mut checks = report.checks.iter().filter(|check| check.id == id);
    let check = checks
        .next()
        .unwrap_or_else(|| panic!("missing check: {id}"));
    assert!(checks.next().is_none(), "duplicate check: {id}");
    check
}

fn retry_policy_check(report: &DoctorReport, status: CheckStatus, required: bool) -> &DoctorCheck {
    let check = retry_check(report, "retry.policy");
    assert_eq!(check.status, status);
    assert_eq!(check.required, required);
    check
}

fn retry_fixture() -> (Fixture, TcpListener) {
    let fixture = Fixture::new();
    let listener = configured_credential(&fixture);
    let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
    providers.provider[0].name = "retry-private-provider".into();
    providers.provider[0].models[0].id = "retry-private-model".into();
    providers.provider[0].url = format!(
        "http://{}/v1/retry-private-endpoint?tenant=retry-private-query",
        listener.local_addr().unwrap()
    );
    providers.provider[0].env = None;
    providers.roles.main.clear();
    fixture.write("providers.toml", toml::to_string(&providers).unwrap());
    (fixture, listener)
}

fn retry_declaration(provider: &config::ProviderConfig, attempts: u32) -> serde_json::Value {
    use orbit_engine::retry::{
        FinalRejectionContract, FinalRejectionPolicy, FinalRejectionSelector,
    };
    let selector = FinalRejectionSelector::new(
        provider.name.clone(),
        provider.models[0].id.clone(),
        provider.url.clone(),
        retry_adapter_identity(),
    )
    .unwrap();
    selector.canonical_endpoint().unwrap();
    let policy = FinalRejectionPolicy::new(
        format!("retry-private-policy-{}", provider.name),
        selector.clone(),
        vec![429, 503],
        FinalRejectionContract::new("ordinary", "final_rejection", "unknown", true).unwrap(),
        attempts,
    )
    .unwrap();
    serde_json::json!({
        "id": policy.id(),
        "provider": selector.provider(),
        "model": selector.model(),
        "endpoint": selector.endpoint(),
        "adapter_identity_sha256": selector.adapter_identity_sha256(),
        "statuses": [429, 503],
        "scope": "ordinary",
        "generation": "final_rejection",
        "billing": "unknown",
        "allow_uncapped_retry": true,
        "max_attempts": attempts
    })
}

fn retry_write_document(fixture: &Fixture, declarations: Vec<serde_json::Value>) {
    fixture.write(
        "provider-policies.toml",
        toml::to_string(&serde_json::json!({
            "version": 1,
            "final_rejection": declarations
        }))
        .unwrap(),
    );
}

fn retry_readonly_report(fixture: &Fixture, listener: &TcpListener) -> DoctorReport {
    let before = credential_files(&fixture.root);
    let report = doctor(&fixture.home, &fixture.workspace);
    assert!(
        credential_files(&fixture.root) == before,
        "doctor changed fixture files, modes, links or inodes"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "offline doctor contacted a provider"
    );
    let value = serde_json::to_value(&report).unwrap();
    let mut report_fields: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    report_fields.sort_unstable();
    assert_eq!(report_fields, ["checks", "ready", "schema_version"]);
    assert_eq!(report.schema_version, 1);
    for check in value["checks"].as_array().unwrap() {
        let mut fields: Vec<_> = check
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, ["detail", "id", "required", "status"]);
        assert!(check["detail"].as_str().unwrap().len() <= 256);
        assert!(check["id"].as_str().unwrap().len() <= 96);
    }
    let bytes = serde_json::to_string(&report).unwrap();
    assert!(!bytes.contains(RETRY_PRIVATE_MARKER));
    assert!(!bytes.contains(fixture.home.to_str().unwrap()));
    for secret in [SAVED_CREDENTIAL, ENV_CREDENTIAL, AMBIENT_CREDENTIAL] {
        assert!(
            !bytes.contains(secret),
            "doctor serialized a credential value"
        );
    }
    assert!(report.checks.len() <= 128);
    if report.checks.len() < 128 {
        let connectivity = retry_check(&report, "provider.connectivity");
        assert_eq!(connectivity.status, CheckStatus::NotTested);
        assert!(!connectivity.required);
    }
    report
}

fn retry_rows_before_provider(report: &DoctorReport) {
    let index = |id: &str| {
        report
            .checks
            .iter()
            .position(|check| check.id == id)
            .unwrap()
    };
    assert_eq!(index("retry.openai_adapter_identity"), index("home") + 1);
    assert!(index("retry.openai_adapter_identity") < index("provider.0"));
    assert!(index("retry.policy") < index("provider.0"));
    let identity = retry_check(report, "retry.openai_adapter_identity");
    assert_eq!(identity.status, CheckStatus::Configured);
    assert!(!identity.required);
    assert!(identity.detail.contains(retry_adapter_identity().as_str()));
}

fn retry_many_providers(fixture: &Fixture) -> config::ProvidersConfig {
    let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
    let template = providers.provider[0].clone();
    providers.provider = (0..64)
        .map(|index| {
            let mut provider = template.clone();
            provider.name = format!("retry-private-provider-{index}");
            provider.models[0].id = format!("retry-private-model-{index}");
            setup::validate_provider(&provider).unwrap();
            provider
        })
        .collect();
    providers.roles.main = format!(
        "{}/{}",
        providers.provider[0].name, providers.provider[0].models[0].id
    );
    let raw = toml::to_string(&providers).unwrap();
    let settings = phase_routing::parse_settings(&raw).unwrap();
    phase_routing::validate_settings(&providers, &settings).unwrap();
    fixture.write("providers.toml", raw);
    providers
}

#[test]
fn retry_identity_and_ordinary_browser_report_preserve_existing_fields() {
    isolated_credential_status(
        "retry_identity_and_ordinary_browser_report_preserve_existing_fields",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            retry_rows_before_provider(&report);
            let identity = retry_adapter_identity();
            assert_eq!(identity.len(), 64);
            assert!(
                identity
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            let row = retry_check(&report, "retry.openai_adapter_identity");
            assert!(row.detail.contains("OpenAI-compatible"));
            assert!(row.detail.contains(identity.as_str()));
            let expected = browser_check(&std::env::current_exe().unwrap());
            let actual = retry_check(&report, "browser");
            assert_eq!(actual.id, expected.id);
            assert_eq!(actual.status, expected.status);
            assert_eq!(actual.detail, expected.detail);
            assert_eq!(actual.required, expected.required);
        },
    );
}

#[test]
fn missing_and_empty_retry_policies_remain_optional_and_ready() {
    isolated_credential_status(
        "missing_and_empty_retry_policies_remain_optional_and_ready",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let path = fixture.home.join("provider-policies.toml");
            assert!(!path.exists());
            let missing = retry_readonly_report(&fixture, &listener);
            assert!(missing.ready);
            let detail = retry_policy_check(&missing, CheckStatus::NotTested, false)
                .detail
                .clone();
            assert!(!path.exists());
            retry_write_document(&fixture, Vec::new());
            let empty = retry_readonly_report(&fixture, &listener);
            assert!(empty.ready);
            assert_eq!(
                retry_policy_check(&empty, CheckStatus::NotTested, false).detail,
                detail
            );
        },
    );
}

#[test]
fn matching_retry_policy_is_optional_bounded_and_redacted() {
    isolated_credential_status(
        "matching_retry_policy_is_optional_bounded_and_redacted",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            retry_write_document(&fixture, vec![retry_declaration(&providers.provider[0], 4)]);
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            retry_rows_before_provider(&report);
            let row = retry_policy_check(&report, CheckStatus::Configured, false);
            for meaning in [
                "main/default",
                "total max_attempts=4",
                "managed uncapped ordinary",
                "smaller caller ceilings",
                "generation-refusal assumption",
                "usage/billing unknown",
                "connectivity untested",
            ] {
                assert!(
                    row.detail.contains(meaning),
                    "missing policy scope: {meaning}"
                );
            }
        },
    );
}

#[test]
fn inactive_retry_policies_share_one_generic_optional_diagnostic() {
    isolated_credential_status(
        "inactive_retry_policies_share_one_generic_optional_diagnostic",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let absent = retry_readonly_report(&fixture, &listener);
            let generic = retry_policy_check(&absent, CheckStatus::NotTested, false)
                .detail
                .clone();
            let declaration = retry_declaration(&providers.provider[0], 3);
            let mut stale = retry_adapter_identity().into_bytes();
            stale[0] = if stale[0] == b'a' { b'b' } else { b'a' };
            let stale = String::from_utf8(stale).unwrap();
            for (field, replacement) in [
                ("provider", "retry-private-other-provider".to_owned()),
                ("model", "retry-private-other-model".to_owned()),
                (
                    "endpoint",
                    format!("{}&region=retry-private-other", providers.provider[0].url),
                ),
                ("adapter_identity_sha256", stale),
            ] {
                let mut inactive = declaration.clone();
                inactive[field] = replacement.into();
                retry_write_document(&fixture, vec![inactive]);
                let report = retry_readonly_report(&fixture, &listener);
                assert!(report.ready);
                assert_eq!(
                    retry_policy_check(&report, CheckStatus::NotTested, false).detail,
                    generic
                );
            }
            let mut unsupported = providers;
            unsupported.provider[0].kind = "anthropic".into();
            fixture.write("providers.toml", toml::to_string(&unsupported).unwrap());
            retry_write_document(&fixture, vec![declaration]);
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            assert_eq!(
                retry_policy_check(&report, CheckStatus::NotTested, false).detail,
                generic
            );
        },
    );
}

#[test]
fn invalid_inactive_retry_declaration_still_fails_whole_file_validation() {
    isolated_credential_status(
        "invalid_inactive_retry_declaration_still_fails_whole_file_validation",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let mut declaration = retry_declaration(&providers.provider[0], 3);
            declaration["provider"] = "retry-private-inactive-provider".into();
            declaration["max_attempts"] = 1.into();
            retry_write_document(&fixture, vec![declaration]);
            let report = retry_readonly_report(&fixture, &listener);
            assert!(!report.ready);
            retry_rows_before_provider(&report);
            let row = retry_policy_check(&report, CheckStatus::Invalid, true);
            assert!(row.detail.contains("invalid or unsafe"));
        },
    );
}

#[test]
fn unsafe_and_malformed_retry_policies_are_redacted_and_never_repaired() {
    isolated_credential_status(
        "unsafe_and_malformed_retry_policies_are_redacted_and_never_repaired",
        &[],
        || {
            let mut generic = None;
            for variant in [
                "malformed",
                "encoding",
                "mode",
                "symlink",
                "oversize",
                "directory",
            ] {
                let (fixture, listener) = retry_fixture();
                let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
                retry_write_document(&fixture, vec![retry_declaration(&providers.provider[0], 3)]);
                let path = fixture.home.join("provider-policies.toml");
                match variant {
                    "malformed" => {
                        fixture.write("provider-policies.toml", b"[retry-private-malformed")
                    }
                    "encoding" => {
                        fixture.write("provider-policies.toml", b"retry-private-encoding\xff")
                    }
                    "mode" => {
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                            .unwrap()
                    }
                    "symlink" => {
                        let target = fixture.root.join("retry-private-policy-target");
                        std::fs::rename(&path, &target).unwrap();
                        symlink(&target, &path).unwrap();
                    }
                    "oversize" => {
                        fixture.write("provider-policies.toml", vec![b'x'; 128 * 1024 + 1])
                    }
                    "directory" => {
                        std::fs::remove_file(&path).unwrap();
                        std::fs::DirBuilder::new()
                            .mode(0o700)
                            .create(&path)
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                let report = retry_readonly_report(&fixture, &listener);
                assert!(!report.ready);
                let row = retry_policy_check(&report, CheckStatus::Invalid, true);
                if let Some(expected) = &generic {
                    assert_eq!(&row.detail, expected);
                } else {
                    generic = Some(row.detail.clone());
                }
                retry_rows_before_provider(&report);
            }
        },
    );
}

#[test]
fn explicit_main_role_selects_its_own_retry_declaration() {
    isolated_credential_status(
        "explicit_main_role_selects_its_own_retry_declaration",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let mut second = providers.provider[0].clone();
            second.name = "retry-private-second-provider".into();
            second.models[0].id = "retry-private-second-model".into();
            providers.roles.main = format!("{}/{}", second.name, second.models[0].id);
            providers.provider.push(second);
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            retry_write_document(
                &fixture,
                vec![
                    retry_declaration(&providers.provider[0], 3),
                    retry_declaration(&providers.provider[1], 6),
                ],
            );
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            let row = retry_policy_check(&report, CheckStatus::Configured, false);
            assert!(row.detail.contains("total max_attempts=6"));
            assert!(!row.detail.contains("max_attempts=3"));
        },
    );
}

#[test]
fn default_main_selects_the_first_declared_model_retry_policy() {
    isolated_credential_status(
        "default_main_selects_the_first_declared_model_retry_policy",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let mut second = providers.provider[0].clone();
            second.name = "retry-private-second-provider".into();
            second.models[0].id = "retry-private-second-model".into();
            providers.provider.push(second);
            assert!(providers.roles.main.is_empty());
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            retry_write_document(
                &fixture,
                vec![
                    retry_declaration(&providers.provider[0], 3),
                    retry_declaration(&providers.provider[1], 6),
                ],
            );
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            assert!(
                retry_policy_check(&report, CheckStatus::Configured, false)
                    .detail
                    .contains("total max_attempts=3")
            );
        },
    );
}

#[test]
fn default_main_skips_empty_earlier_catalog_before_retry_selection() {
    isolated_credential_status(
        "default_main_skips_empty_earlier_catalog_before_retry_selection",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let mut second = providers.provider[0].clone();
            second.name = "retry-private-second-provider".into();
            second.models[0].id = "retry-private-second-model".into();
            providers.provider[0].models.clear();
            providers.provider.push(second);
            assert!(providers.roles.main.is_empty());
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            retry_write_document(&fixture, vec![retry_declaration(&providers.provider[1], 6)]);
            let report = retry_readonly_report(&fixture, &listener);
            assert!(!report.ready);
            let invalid = retry_check(&report, "provider.0");
            assert_eq!(invalid.status, CheckStatus::Invalid);
            assert!(invalid.required);
            assert!(
                retry_policy_check(&report, CheckStatus::Configured, false)
                    .detail
                    .contains("total max_attempts=6")
            );
            retry_rows_before_provider(&report);
        },
    );
}

#[test]
fn ambiguous_main_role_does_not_choose_an_arbitrary_retry_policy_owner() {
    isolated_credential_status(
        "ambiguous_main_role_does_not_choose_an_arbitrary_retry_policy_owner",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            let mut second = providers.provider[0].clone();
            second.name = "retry-private-second-provider".into();
            providers.roles.main = second.models[0].id.clone();
            providers.provider.push(second);
            assert!(phase_routing::resolve_model(&providers, &providers.roles.main, None).is_err());
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            retry_write_document(
                &fixture,
                vec![
                    retry_declaration(&providers.provider[0], 3),
                    retry_declaration(&providers.provider[1], 6),
                ],
            );
            let report = retry_readonly_report(&fixture, &listener);
            assert!(!report.ready);
            let row = retry_policy_check(&report, CheckStatus::Unavailable, false);
            assert!(row.detail.contains("could not be resolved"));
            let routing = retry_check(&report, "routing");
            assert_eq!(routing.status, CheckStatus::Invalid);
            assert!(routing.required);
        },
    );
}

#[test]
fn absent_or_invalid_default_does_not_fabricate_retry_selection() {
    isolated_credential_status(
        "absent_or_invalid_default_does_not_fabricate_retry_selection",
        &[],
        || {
            let mut generic = None;
            for empty_catalog in [false, true] {
                let (fixture, listener) = retry_fixture();
                let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
                if empty_catalog {
                    providers.provider.clear();
                } else {
                    providers.roles.main = "retry-private-undeclared-model".into();
                }
                fixture.write("providers.toml", toml::to_string(&providers).unwrap());
                fixture.write("provider-policies.toml", b"[retry-private-not-checked");
                let report = retry_readonly_report(&fixture, &listener);
                assert!(!report.ready);
                let row = retry_policy_check(&report, CheckStatus::Unavailable, false);
                if let Some(expected) = &generic {
                    assert_eq!(&row.detail, expected);
                } else {
                    generic = Some(row.detail.clone());
                }
                assert!(
                    !report
                        .checks
                        .iter()
                        .any(|check| check.id == "retry.policy" && check.required)
                );
            }
        },
    );
}

#[test]
fn many_provider_retry_failure_is_visible_before_the_capacity_limit() {
    isolated_credential_status(
        "many_provider_retry_failure_is_visible_before_the_capacity_limit",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            retry_many_providers(&fixture);
            fixture.write(
                "provider-policies.toml",
                b"[retry-private-invalid-before-capacity",
            );
            let report = retry_readonly_report(&fixture, &listener);
            assert!(!report.ready);
            retry_policy_check(&report, CheckStatus::Invalid, true);
            retry_rows_before_provider(&report);
            let limit = retry_check(&report, "limits");
            assert_eq!(limit.status, CheckStatus::Invalid);
            assert!(limit.required);
            assert_eq!(report.checks.len(), 128);
        },
    );
}

#[test]
fn many_provider_optional_retry_rows_remain_visible_before_capacity() {
    isolated_credential_status(
        "many_provider_optional_retry_rows_remain_visible_before_capacity",
        &[],
        || {
            for matching_policy in [false, true] {
                let (fixture, listener) = retry_fixture();
                let providers = retry_many_providers(&fixture);
                if matching_policy {
                    retry_write_document(
                        &fixture,
                        vec![retry_declaration(&providers.provider[0], 4)],
                    );
                }
                let report = retry_readonly_report(&fixture, &listener);
                assert!(!report.ready);
                retry_policy_check(
                    &report,
                    if matching_policy {
                        CheckStatus::Configured
                    } else {
                        CheckStatus::NotTested
                    },
                    false,
                );
                retry_rows_before_provider(&report);
                let limit = retry_check(&report, "limits");
                assert_eq!(limit.status, CheckStatus::Invalid);
                assert!(limit.required);
                assert!(
                    report
                        .checks
                        .iter()
                        .filter(|check| check.required && check.id != "limits")
                        .all(|check| matches!(
                            check.status,
                            CheckStatus::Ready | CheckStatus::Configured
                        ))
                );
                assert_eq!(report.checks.len(), 128);
            }
        },
    );
}

#[test]
fn documented_retry_policy_loads_after_current_identity_substitution() {
    isolated_credential_status(
        "documented_retry_policy_loads_after_current_identity_substitution",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let example = include_str!("../../../README.md")
                .split("```toml\n")
                .filter_map(|tail| tail.split_once("```").map(|(block, _)| block))
                .find(|block| block.contains("[[final_rejection]]"))
                .expect("README must contain the optional retry policy example");
            let raw = example.replace(
                "COPY_THE_64_HEX_SHA256_SHOWN_BY_ORBIT_DOCTOR",
                &retry_adapter_identity(),
            );
            let mut providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            providers.provider[0].name = "work".into();
            providers.provider[0].models[0].id = "family/model".into();
            providers.provider[0].url = "https://provider.example/v1".into();
            providers.roles.main = "work/family/model".into();
            fixture.write("providers.toml", toml::to_string(&providers).unwrap());
            fixture.write("provider-policies.toml", raw);
            let selected = phase_routing::resolve_model(&providers, &providers.roles.main, None)
                .unwrap()
                .turn_config(None)
                .unwrap();
            let before = credential_files(&fixture.root);
            let binding = provider_policies::load_for_config(&fixture.home, &selected)
                .unwrap()
                .expect("substituted README example must match its configured model");
            assert_eq!(binding.max_attempts(), 2);
            assert_eq!(binding.adapter_identity_sha256(), retry_adapter_identity());
            assert!(credential_files(&fixture.root) == before);
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            assert_eq!(
                std::fs::metadata(fixture.home.join("provider-policies.toml"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let report = retry_readonly_report(&fixture, &listener);
            assert!(report.ready);
            assert!(
                retry_policy_check(&report, CheckStatus::Configured, false)
                    .detail
                    .contains("total max_attempts=2")
            );
        },
    );
}

struct RetryDoctorCliChild {
    unreaped: Option<std::process::Child>,
    stdout: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Drop for RetryDoctorCliChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.unreaped.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for reader in [self.stdout.take(), self.stderr.take()]
            .into_iter()
            .flatten()
        {
            let _ = reader.join();
        }
    }
}

fn retry_cli_doctor(
    fixture: &Fixture,
    environment_home: &Path,
    explicit_home: bool,
    json: bool,
    deadline: std::time::Instant,
) -> std::process::Output {
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    const STDOUT_CAP: usize = 64 * 1024;
    const STDERR_CAP: usize = 16 * 1024;
    assert!(
        std::time::Instant::now() < deadline,
        "doctor CLI aggregate deadline expired"
    );
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_orbit"));
    if explicit_home {
        command.arg("--home").arg(&fixture.home);
    }
    command
        .arg("doctor")
        .arg("--workspace")
        .arg(&fixture.workspace);
    if json {
        command.arg("--json");
    }
    command
        .env_clear()
        .env("HOME", &fixture.root)
        .env("TMPDIR", &fixture.root)
        .env("XDG_CONFIG_HOME", fixture.root.join("xdg-config"))
        .env("XDG_CACHE_HOME", fixture.root.join("xdg-cache"))
        .env("XDG_DATA_HOME", fixture.root.join("xdg-data"))
        .env("CODEX_HOME", fixture.root.join("codex"))
        .env("CLAUDE_CONFIG_DIR", fixture.root.join("claude"))
        .env("HERMES_HOME", fixture.root.join("hermes"))
        .env("ORBIT_HOME", environment_home)
        .current_dir(&fixture.root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut owned = RetryDoctorCliChild {
        unreaped: Some(command.spawn().unwrap()),
        stdout: None,
        stderr: None,
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let capture = |stream: Box<dyn Read + Send>, cap: usize| {
        let overflow = Arc::clone(&overflow);
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut stream = stream.take((cap + 1) as u64);
            let mut bytes = vec![0; cap + 1];
            let mut length = 0;
            loop {
                let read = stream.read(&mut bytes[length..])?;
                if read == 0 {
                    break;
                }
                length += read;
                if length > cap {
                    overflow.store(true, Ordering::Release);
                    break;
                }
            }
            bytes.truncate(length);
            Ok(bytes)
        })
    };
    let stdout = owned.unreaped.as_mut().unwrap().stdout.take().unwrap();
    owned.stdout = Some(capture(Box::new(stdout), STDOUT_CAP));
    let stderr = owned.unreaped.as_mut().unwrap().stderr.take().unwrap();
    owned.stderr = Some(capture(Box::new(stderr), STDERR_CAP));
    let status = loop {
        assert!(
            !overflow.load(Ordering::Acquire),
            "doctor CLI output exceeded its capture cap"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "doctor CLI exceeded its aggregate deadline"
        );
        if let Some(status) = owned.unreaped.as_mut().unwrap().try_wait().unwrap() {
            let _ = owned.unreaped.take();
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let stdout = owned.stdout.take().unwrap().join().unwrap().unwrap();
    let stderr = owned.stderr.take().unwrap().join().unwrap().unwrap();
    assert!(
        std::time::Instant::now() < deadline,
        "doctor CLI capture exceeded its aggregate deadline"
    );
    assert!(
        stdout.len() <= STDOUT_CAP,
        "doctor CLI stdout exceeded its capture cap"
    );
    assert!(
        stderr.len() <= STDERR_CAP,
        "doctor CLI stderr exceeded its capture cap"
    );
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn normal_cli_doctor_selects_private_home_and_reports_retry_policy() {
    isolated_credential_status(
        "normal_cli_doctor_selects_private_home_and_reports_retry_policy",
        &[],
        || {
            let (fixture, listener) = retry_fixture();
            let providers = config::ProvidersConfig::load(&fixture.home).unwrap();
            retry_write_document(&fixture, vec![retry_declaration(&providers.provider[0], 2)]);
            orbit_tools::permissions::FolderTrust::new(fixture.home.clone())
                .trust(&fixture.workspace)
                .unwrap();
            let wrong_home = fixture.root.join("wrong-orbit-home");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&wrong_home)
                .unwrap();
            let before = credential_files(&fixture.root);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let json = retry_cli_doctor(&fixture, &wrong_home, true, true, deadline);
            let human = retry_cli_doctor(&fixture, &fixture.home, false, false, deadline);
            assert!(
                credential_files(&fixture.root) == before,
                "normal doctor CLI changed fixture state"
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "normal doctor CLI contacted a provider"
            );
            assert!(std::fs::read_dir(&wrong_home).unwrap().next().is_none());
            for output in [&json, &human] {
                for bytes in [&output.stdout, &output.stderr] {
                    let text = std::str::from_utf8(bytes).unwrap();
                    for secret in [
                        RETRY_PRIVATE_MARKER,
                        SAVED_CREDENTIAL,
                        ENV_CREDENTIAL,
                        AMBIENT_CREDENTIAL,
                    ] {
                        assert!(
                            !text.contains(secret),
                            "normal doctor CLI revealed a private marker"
                        );
                    }
                    assert!(!text.contains(fixture.home.to_str().unwrap()));
                }
                assert!(
                    output.status.success(),
                    "normal doctor CLI did not report ready"
                );
            }
            let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
            let mut fields: Vec<_> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            assert_eq!(fields, ["command", "report", "schema"]);
            assert_eq!(value["schema"], "orbit.cli/v1");
            assert_eq!(value["command"], "doctor");
            let report: DoctorReport = serde_json::from_value(value["report"].clone()).unwrap();
            assert_eq!(report.schema_version, 1);
            assert!(report.ready);
            retry_rows_before_provider(&report);
            assert!(
                retry_check(&report, "project.trust")
                    .detail
                    .contains("already exists")
            );
            let policy = retry_policy_check(&report, CheckStatus::Configured, false);
            assert!(policy.detail.contains("total max_attempts=2"));
            let human = std::str::from_utf8(&human.stdout).unwrap();
            assert!(human.contains("Ready for a configured local session"));
            assert!(human.contains(retry_adapter_identity().as_str()));
            assert!(human.contains("retry.policy: configured"));
            assert!(human.contains(policy.detail.as_str()));
        },
    );
}
