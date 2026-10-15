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
pub use orbit_cli::{config, lsp, phase_routing, tool_runtime};
use std::os::unix::fs::{PermissionsExt, symlink};
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
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fabricated_credential_value_never_appears",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(ENV, SECRET)
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
