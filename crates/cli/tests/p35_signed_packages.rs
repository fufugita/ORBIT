#![cfg(target_os = "linux")]

#[path = "../src/signed_packages.rs"]
mod signed_packages;

use ed25519_dalek::{Signer, SigningKey};
use orbit_ledger::{verify_ledger, LedgerEvent, LedgerWriter};
use orbit_plugin::{sign_manifest, PluginManifest};
use sha2::{Digest, Sha256};
use signed_packages::{
    catalog, install, read_install_inputs, status, trust_issuer, with_test_hook, PackageError,
    PackageStatus, TestPoint,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    home: PathBuf,
    manifest: PluginManifest,
    bytes: Vec<u8>,
}
impl Fixture {
    fn new(imports: Vec<String>) -> Self {
        let home = std::env::temp_dir().join(format!("orbit-signed-package-{}", ulid::Ulid::new()));
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = b"\0asm\x01\0\0\0signed fixture".to_vec();
        let manifest = sign_manifest(
            "example",
            "1.0.0",
            &SigningKey::from_bytes(&[37; 32]),
            &bytes,
            imports,
        );
        Self {
            home,
            manifest,
            bytes,
        }
    }
    fn trust(&self) {
        trust_issuer(&self.home, &self.manifest.issuer_public_key).unwrap();
    }
    fn no_install(&self) {
        assert!(!self.home.join("signed-packages").exists());
        assert!(!self.home.join("ledger").exists());
        assert!(catalog(&self.home, None).unwrap().packages.is_empty());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[test]
fn durable_install_saved_bytes_real_event_and_fresh_process_catalog() {
    if let Some(action) = std::env::var_os("ORBIT_PACKAGE_PROBE_ACTION") {
        run_probe(&action.to_string_lossy());
        return;
    }
    if let Some(home) = std::env::var_os("ORBIT_PACKAGE_CATALOG_CHILD") {
        let page = catalog(&PathBuf::from(home), None).unwrap();
        assert_eq!(page.packages.len(), 1);
        let package = &page.packages[0];
        assert_eq!(package.status, PackageStatus::Verified);
        assert_eq!(package.name, "example");
        assert_eq!(package.version, "1.0.0");
        assert_eq!(
            package.ledger_record_hash,
            std::env::var("ORBIT_PACKAGE_EXPECTED_HASH").unwrap()
        );
        assert_eq!(
            package.content_digest,
            hex::encode(Sha256::digest(b"\0asm\x01\0\0\0signed fixture"))
        );
        return;
    }
    let f = Fixture::new(vec!["wasi:http/proxy".into()]);
    f.trust();
    let manifest_path = f.home.join("fixture-manifest.json");
    let package_path = f.home.join("fixture-package.wasm");
    std::fs::write(&manifest_path, serde_json::to_vec(&f.manifest).unwrap()).unwrap();
    std::fs::write(&package_path, &f.bytes).unwrap();
    let (manifest, bytes) = read_install_inputs(&manifest_path, &package_path).unwrap();
    assert_eq!(manifest, f.manifest);
    assert_eq!(bytes, f.bytes);
    let receipt = install(&f.home, &manifest, &bytes, true).unwrap();
    assert!(!receipt.reused);
    let saved = f
        .home
        .join("signed-packages/content")
        .join(format!("{}.blob", receipt.content_digest));
    assert_eq!(std::fs::read(&saved).unwrap(), f.bytes);
    assert_eq!(
        std::fs::metadata(saved).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (records, _) = verify_ledger(&f.home.join("ledger")).unwrap();
    let record = records
        .iter()
        .find(|record| record.self_hash == receipt.ledger_record_hash)
        .unwrap();
    let LedgerEvent::PluginInstall(payload) = &record.record.event else {
        panic!("not installation proof")
    };
    assert_eq!(payload.install_id, receipt.install_id);
    assert_eq!(payload.name, f.manifest.name);
    assert_eq!(payload.version, f.manifest.version);
    assert_eq!(payload.issuer_public_key, f.manifest.issuer_public_key);
    assert_eq!(
        payload.manifest_digest,
        hex::encode(Sha256::digest(
            orbit_plugin::canonical::canonical_bytes(&f.manifest).unwrap()
        ))
    );
    assert_eq!(payload.content_digest, f.manifest.content_digest);
    assert_eq!(payload.package_bytes, f.bytes.len() as u64);
    assert!(payload.operator_confirmed);
    // The same test executes only its catalog branch in a separate process.
    // Its output is suppressed so only substantive parent cases are counted.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable_install_saved_bytes_real_event_and_fresh_process_catalog",
            "--test-threads=1",
        ])
        .env("ORBIT_PACKAGE_CATALOG_CHILD", &f.home)
        .env("ORBIT_PACKAGE_EXPECTED_HASH", &receipt.ledger_record_hash)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "fresh catalog child failed: {status}");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("fresh catalog child exceeded bounded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn durable_install_refuses_invalid_signature_without_mutation() {
    let mut f = Fixture::new(vec![]);
    f.trust();
    let replacement = if f.manifest.signature.starts_with('0') {
        "1"
    } else {
        "0"
    };
    f.manifest.signature.replace_range(0..1, replacement);
    assert!(install(&f.home, &f.manifest, &f.bytes, true)
        .unwrap_err()
        .to_string()
        .contains("signature"));
    f.no_install();
}

#[test]
fn durable_install_refuses_changed_content_without_mutation() {
    let mut f = Fixture::new(vec![]);
    f.trust();
    f.bytes.push(1);
    assert!(install(&f.home, &f.manifest, &f.bytes, true)
        .unwrap_err()
        .to_string()
        .contains("digest"));
    f.no_install();
}

#[test]
fn durable_install_refuses_disallowed_import_without_mutation() {
    let f = Fixture::new(vec!["wasi:filesystem/types".into()]);
    f.trust();
    assert!(install(&f.home, &f.manifest, &f.bytes, true)
        .unwrap_err()
        .to_string()
        .contains("import"));
    f.no_install();
}

#[test]
fn durable_install_refuses_untrusted_issuer_without_mutation() {
    let f = Fixture::new(vec![]);
    assert!(install(&f.home, &f.manifest, &f.bytes, true)
        .unwrap_err()
        .to_string()
        .contains("trusted"));
    f.no_install();
}

#[test]
fn durable_install_refuses_absent_confirmation_without_mutation() {
    let f = Fixture::new(vec![]);
    f.trust();
    let error = install(&f.home, &f.manifest, &f.bytes, false).unwrap_err();
    assert_eq!(error.code(), "ORBIT-E1101");
    assert!(error.to_string().contains("confirmation"));
    f.no_install();
}

fn write_inputs(f: &Fixture) {
    std::fs::write(
        f.home.join("fixture-manifest.json"),
        serde_json::to_vec(&f.manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(f.home.join("fixture-package.wasm"), &f.bytes).unwrap();
}
fn installation_count(f: &Fixture) -> usize {
    verify_ledger(&f.home.join("ledger"))
        .unwrap()
        .0
        .iter()
        .filter(|r| matches!(r.record.event, LedgerEvent::PluginInstall(_)))
        .count()
}
fn saved_index(f: &Fixture, id: &str) -> PathBuf {
    f.home
        .join("signed-packages/installed")
        .join(format!("{id}.json"))
}
fn assert_verified(f: &Fixture) {
    let page = catalog(&f.home, None).unwrap();
    assert_eq!(page.packages.len(), 1);
    assert_eq!(page.packages[0].status, PackageStatus::Verified);
}
fn private_empty(path: &Path) {
    std::fs::write(path, "").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Probe {
    child: Child,
    marker: PathBuf,
    receipt: PathBuf,
}
impl Probe {
    fn spawn(f: &Fixture, action: &str) -> Self {
        write_inputs(f);
        Self::spawn_existing_inputs(f, action)
    }
    fn spawn_existing_inputs(f: &Fixture, action: &str) -> Self {
        let marker = f.home.join(format!(".probe-marker-{}", ulid::Ulid::new()));
        let receipt = f.home.join(format!(".probe-receipt-{}", ulid::Ulid::new()));
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "durable_install_saved_bytes_real_event_and_fresh_process_catalog",
                "--test-threads=1",
            ])
            .env("ORBIT_PACKAGE_PROBE_ACTION", action)
            .env("ORBIT_PACKAGE_PROBE_HOME", &f.home)
            .env("ORBIT_PACKAGE_PROBE_MARKER", &marker)
            .env("ORBIT_PACKAGE_PROBE_RECEIPT", &receipt)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            marker,
            receipt,
        }
    }
    fn ready(&mut self) -> PathBuf {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.marker.exists() {
                let text = std::fs::read_to_string(&self.marker).unwrap();
                if !text.is_empty() {
                    assert!(
                        self.child.try_wait().unwrap().is_none(),
                        "probe must be alive at seam"
                    );
                    return PathBuf::from(text);
                }
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "probe exited before reaching actual seam"
            );
            assert!(Instant::now() < deadline, "probe seam deadline exceeded");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn kill_at_seam(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
        assert!(!self.receipt.exists());
    }
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "probe failed: {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "probe completion deadline exceeded"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.receipt.exists(),
            "probe must execute its assertions and publish a fresh receipt"
        );
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn run_probe(action: &str) {
    let home = PathBuf::from(std::env::var_os("ORBIT_PACKAGE_PROBE_HOME").unwrap());
    let receipt = PathBuf::from(std::env::var_os("ORBIT_PACKAGE_PROBE_RECEIPT").unwrap());
    let inputs = read_install_inputs(
        &home.join("fixture-manifest.json"),
        &home.join("fixture-package.wasm"),
    );
    if action == "read-refusal" {
        assert!(inputs.is_err());
        std::fs::write(receipt, "bounded input refused").unwrap();
        return;
    }
    let (manifest, bytes) = inputs.unwrap();
    if action == "install" {
        let result = install(&home, &manifest, &bytes, true).unwrap();
        std::fs::write(receipt, serde_json::to_vec(&result).unwrap()).unwrap();
        return;
    }
    let marker = PathBuf::from(std::env::var_os("ORBIT_PACKAGE_PROBE_MARKER").unwrap());
    let action = action.to_string();
    with_test_hook(
        move |point, path| {
            let matches = match action.as_str() {
                "content-staged" => {
                    point == TestPoint::ImmutableStaged
                        && path.parent().is_some_and(|p| p.ends_with("content"))
                }
                "manifest-staged" => {
                    point == TestPoint::ImmutableStaged
                        && path.parent().is_some_and(|p| p.ends_with("manifests"))
                }
                "ledger-acknowledged" => point == TestPoint::LedgerAcknowledged,
                "index-published" => point == TestPoint::IndexPublished,
                _ => panic!("unknown probe action"),
            };
            if matches {
                std::fs::write(&marker, path.as_os_str().as_encoded_bytes()).unwrap();
                loop {
                    std::thread::park();
                }
            }
        },
        || {
            install(&home, &manifest, &bytes, true).unwrap();
        },
    );
    panic!("crash seam was not reached");
}

#[test]
fn uppercase_signature_preserves_legacy_verification_and_literal_digest() {
    let mut f = Fixture::new(vec![]);
    f.trust();
    f.manifest.signature = f.manifest.signature.to_ascii_uppercase();
    f.manifest.verify_issuer_signature().unwrap();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let path = f
        .home
        .join("signed-packages/manifests")
        .join(format!("{}.json", receipt.manifest_digest));
    let saved: PluginManifest = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(saved, f.manifest);
    assert_eq!(
        receipt.manifest_digest,
        hex::encode(Sha256::digest(
            orbit_plugin::canonical::canonical_bytes(&f.manifest).unwrap()
        ))
    );
    assert_verified(&f);
}

#[test]
fn uppercase_signed_issuer_and_mixed_case_legacy_trust_are_compatible() {
    let mut f = Fixture::new(vec![]);
    f.manifest.issuer_public_key = f.manifest.issuer_public_key.to_ascii_uppercase();
    let unsigned = serde_json::json!({"name":f.manifest.name,"version":f.manifest.version,"issuer_public_key":f.manifest.issuer_public_key,
        "content_digest":f.manifest.content_digest,"declared_imports":f.manifest.declared_imports});
    f.manifest.signature = hex::encode(
        SigningKey::from_bytes(&[37; 32])
            .sign(&orbit_plugin::canonical::canonical_bytes(&unsigned).unwrap())
            .to_bytes(),
    );
    f.manifest.verify_issuer_signature().unwrap();
    std::fs::create_dir(f.home.join("mods")).unwrap();
    std::fs::set_permissions(f.home.join("mods"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mixed: String = f
        .manifest
        .issuer_public_key
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    std::fs::write(
        f.home.join("mods/issuers.txt"),
        format!("# legacy issuer\n{mixed}\n"),
    )
    .unwrap();
    std::fs::set_permissions(
        f.home.join("mods/issuers.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::write(f.home.join("mods/instructions.md"), "keep instructions").unwrap();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    assert_eq!(receipt.issuer_public_key, f.manifest.issuer_public_key);
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].issuer_public_key,
        f.manifest.issuer_public_key
    );
    assert_verified(&f);
    assert_eq!(
        std::fs::read_to_string(f.home.join("mods/instructions.md")).unwrap(),
        "keep instructions"
    );
}

fn old_two_link_crash_recovery(action: &str) {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new(vec![]);
    f.trust();
    let mut child = Probe::spawn(&f, action);
    let temporary = child.ready();
    let (directory, name) = if action == "content-staged" {
        ("content", format!("{}.blob", f.manifest.content_digest))
    } else {
        (
            "manifests",
            format!(
                "{}.json",
                hex::encode(Sha256::digest(
                    orbit_plugin::canonical::canonical_bytes(&f.manifest).unwrap()
                ))
            ),
        )
    };
    let final_path = f.home.join("signed-packages").join(directory).join(name);
    // Reproduce the previous publisher's physical two-name window using its
    // actual fsynced private temporary inode, then kill that owned process.
    std::fs::hard_link(&temporary, &final_path).unwrap();
    assert_eq!(
        std::fs::metadata(&temporary).unwrap().ino(),
        std::fs::metadata(&final_path).unwrap().ino()
    );
    assert_eq!(std::fs::metadata(&final_path).unwrap().nlink(), 2);
    child.kill_at_seam();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    assert!(!receipt.reused);
    assert!(!temporary.exists());
    assert_eq!(std::fs::metadata(final_path).unwrap().nlink(), 1);
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}
#[test]
fn killed_content_two_link_publisher_recovers_exact_installation() {
    old_two_link_crash_recovery("content-staged");
}
#[test]
fn killed_manifest_two_link_publisher_recovers_exact_installation() {
    old_two_link_crash_recovery("manifest-staged");
}

#[test]
fn foreign_hard_link_stays_refused_on_catalog_and_retry() {
    let f = Fixture::new(vec![]);
    f.trust();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let content = f
        .home
        .join("signed-packages/content")
        .join(format!("{}.blob", receipt.content_digest));
    std::fs::hard_link(content, f.home.join("foreign-link")).unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::Tampered
    );
    assert!(matches!(
        install(&f.home, &f.manifest, &f.bytes, true),
        Err(PackageError::Storage(_))
    ));
    assert_eq!(installation_count(&f), 1);
}

#[test]
fn atomic_immutable_publication_is_single_link_and_never_clobbers() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new(vec![]);
    f.trust();
    let parent = f.home.join("signed-packages/content");
    let digest = f.manifest.content_digest.clone();
    let mut seen = false;
    let error = with_test_hook(
        move |point, path| {
            if !seen
                && point == TestPoint::ImmutableStaged
                && path.parent() == Some(parent.as_path())
            {
                seen = true;
                std::fs::write(parent.join(format!("{digest}.blob")), "foreign bytes").unwrap();
                std::fs::set_permissions(
                    parent.join(format!("{digest}.blob")),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                assert_eq!(std::fs::metadata(path).unwrap().nlink(), 1);
            }
        },
        || install(&f.home, &f.manifest, &f.bytes, true),
    )
    .unwrap_err();
    assert!(matches!(error, PackageError::Storage(_)));
    assert_eq!(
        std::fs::read_to_string(
            f.home
                .join("signed-packages/content")
                .join(format!("{}.blob", f.manifest.content_digest))
        )
        .unwrap(),
        "foreign bytes"
    );
    assert!(!f.home.join("ledger").exists());
    assert!(catalog(&f.home, None).unwrap().packages.is_empty());

    // The successful no-replace branch publishes both content and manifest
    // directly as single-link inodes, with no second-name crash window.
    std::fs::remove_file(
        f.home
            .join("signed-packages/content")
            .join(format!("{}.blob", f.manifest.content_digest)),
    )
    .unwrap();
    let published = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed = published.clone();
    with_test_hook(
        move |point, path| {
            if point == TestPoint::ImmutablePublished {
                assert_eq!(std::fs::metadata(path).unwrap().nlink(), 1);
                observed.set(observed.get() + 1);
            }
        },
        || install(&f.home, &f.manifest, &f.bytes, true),
    )
    .unwrap();
    assert_eq!(published.get(), 2);
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}

#[test]
fn detached_proof_segment_is_never_catalog_verified() {
    let f = Fixture::new(vec![]);
    f.trust();
    install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let mut replaced = false;
    let page = with_test_hook(
        move |point, path| {
            if !replaced && point == (TestPoint::ProofOpened { durable: false }) {
                replaced = true;
                std::fs::rename(path, path.with_extension("detached")).unwrap();
                private_empty(path);
            }
        },
        || catalog(&f.home, None),
    )
    .unwrap();
    assert_eq!(page.packages[0].status, PackageStatus::InvalidProof);
    assert!(verify_ledger(&f.home.join("ledger"))
        .unwrap()
        .0
        .iter()
        .all(|r| !matches!(r.record.event, LedgerEvent::PluginInstall(_))));
}

#[test]
fn detached_durable_proof_segment_refuses_install_reuse_and_index_change() {
    let f = Fixture::new(vec![]);
    f.trust();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let index = saved_index(&f, &receipt.install_id);
    let previous = std::fs::read(&index).unwrap();
    let mut replaced = false;
    let error = with_test_hook(
        move |point, path| {
            if !replaced && point == (TestPoint::ProofChecked { durable: true }) {
                replaced = true;
                std::fs::rename(path, path.with_extension("detached")).unwrap();
                private_empty(path);
            }
        },
        || install(&f.home, &f.manifest, &f.bytes, true),
    )
    .unwrap_err();
    assert!(error.to_string().contains("identity"), "{error}");
    assert_eq!(std::fs::read(index).unwrap(), previous);
    // The writer opened a later segment before the replacement. Its chain
    // linkage also refuses the detached earlier installation on a fresh read.
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::InvalidProof
    );
}

#[test]
fn changed_complete_proof_segment_set_is_never_verified() {
    let f = Fixture::new(vec![]);
    f.trust();
    install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let mut added = false;
    let page = with_test_hook(
        move |point, path| {
            if !added && point == (TestPoint::ProofChecked { durable: false }) {
                added = true;
                private_empty(&path.parent().unwrap().join("0000000000000001.log"));
            }
        },
        || catalog(&f.home, None),
    )
    .unwrap();
    assert_eq!(page.packages[0].status, PackageStatus::InvalidProof);
}

fn issuer_publication_fault(after: bool) {
    let f = Fixture::new(vec![]);
    f.trust();
    std::fs::write(f.home.join("mods/instructions.md"), "keep instructions").unwrap();
    let previous = std::fs::read(f.home.join("mods/issuers.txt")).unwrap();
    let home = f.home.clone();
    let mut changed = false;
    let error = with_test_hook(
        move |point, _| {
            if !changed
                && point
                    == if after {
                        TestPoint::IssuerPublished
                    } else {
                        TestPoint::IssuerBeforePublish
                    }
            {
                changed = true;
                std::fs::rename(home.join("mods"), home.join("saved-mods")).unwrap();
                std::fs::create_dir(home.join("mods")).unwrap();
                std::fs::set_permissions(home.join("mods"), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
        },
        || trust_issuer(&f.home, &"ab".repeat(32)),
    )
    .unwrap_err();
    let actual = std::fs::read(f.home.join("saved-mods/issuers.txt")).unwrap();
    if after {
        assert!(matches!(error, PackageError::PublicationUncertain(_)));
        assert!(String::from_utf8(actual)
            .unwrap()
            .contains(&"ab".repeat(32)));
    } else {
        assert!(matches!(error, PackageError::Storage(_)));
        assert_eq!(actual, previous);
    }
    assert_eq!(
        std::fs::read_to_string(f.home.join("saved-mods/instructions.md")).unwrap(),
        "keep instructions"
    );
}
#[test]
fn issuer_failure_before_publication_keeps_previous_bytes() {
    issuer_publication_fault(false);
}
#[test]
fn issuer_failure_after_publication_reports_uncertainty_with_changed_bytes() {
    issuer_publication_fault(true);
}

#[test]
fn exact_retry_reuses_one_full_typed_proof_and_index() {
    let f = Fixture::new(vec![]);
    f.trust();
    let first = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let second = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    assert!(second.reused);
    assert_eq!(first.install_id, second.install_id);
    assert_eq!(first.ledger_record_hash, second.ledger_record_hash);
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}

#[test]
fn concurrent_real_processes_serialize_to_one_installation_proof() {
    let f = Fixture::new(vec![]);
    f.trust();
    let mut first = Probe::spawn(&f, "install");
    let mut second = Probe::spawn_existing_inputs(&f, "install");
    first.finish();
    second.finish();
    let a: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&first.receipt).unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&second.receipt).unwrap()).unwrap();
    assert_eq!(a["install_id"], b["install_id"]);
    assert_eq!(a["ledger_record_hash"], b["ledger_record_hash"]);
    assert_eq!(
        [
            a["reused"].as_bool().unwrap(),
            b["reused"].as_bool().unwrap()
        ]
        .iter()
        .filter(|&&r| r)
        .count(),
        1
    );
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}

fn acknowledged_crash_retry(action: &str) {
    let f = Fixture::new(vec![]);
    f.trust();
    let mut child = Probe::spawn(&f, action);
    let seam = child.ready();
    assert_eq!(installation_count(&f), 1);
    if action == "ledger-acknowledged" {
        assert!(std::fs::read_dir(seam).unwrap().next().is_none());
    } else {
        assert!(seam.is_file());
        assert_verified(&f);
    }
    child.kill_at_seam();
    let result = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    assert!(result.reused);
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}
#[test]
fn killed_after_ledger_ack_recovers_index_from_exact_proof() {
    acknowledged_crash_retry("ledger-acknowledged");
}
#[test]
fn killed_after_index_publication_reuses_exact_installation() {
    acknowledged_crash_retry("index-published");
}

#[test]
fn live_store_lock_is_bounded_and_released_after_owned_process_death() {
    let f = Fixture::new(vec![]);
    f.trust();
    let mut child = Probe::spawn(&f, "ledger-acknowledged");
    child.ready();
    let started = Instant::now();
    assert!(matches!(
        install(&f.home, &f.manifest, &f.bytes, true),
        Err(PackageError::Busy)
    ));
    assert!(started.elapsed() < Duration::from_secs(3));
    child.kill_at_seam();
    assert!(
        install(&f.home, &f.manifest, &f.bytes, true)
            .unwrap()
            .reused
    );
    assert_eq!(installation_count(&f), 1);
    assert_verified(&f);
}

#[test]
fn busy_real_ledger_cannot_publish_an_installation_index() {
    let f = Fixture::new(vec![]);
    f.trust();
    let writer = LedgerWriter::open(&f.home.join("ledger"), "fixture-lock".into(), "1").unwrap();
    assert!(matches!(
        install(&f.home, &f.manifest, &f.bytes, true),
        Err(PackageError::Busy)
    ));
    assert_eq!(installation_count(&f), 0);
    assert!(catalog(&f.home, None).unwrap().packages.is_empty());
    drop(writer);
    install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    assert_eq!(installation_count(&f), 1);
}

#[test]
fn changed_index_directory_after_publication_reports_uncertainty_and_retries() {
    let f = Fixture::new(vec![]);
    f.trust();
    let home = f.home.clone();
    let mut changed = false;
    let error = with_test_hook(
        move |point, _| {
            if !changed && point == TestPoint::IndexPublished {
                changed = true;
                std::fs::rename(
                    home.join("signed-packages/installed"),
                    home.join("signed-packages/saved-index"),
                )
                .unwrap();
                std::fs::create_dir(home.join("signed-packages/installed")).unwrap();
                std::fs::set_permissions(
                    home.join("signed-packages/installed"),
                    std::fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            }
        },
        || install(&f.home, &f.manifest, &f.bytes, true),
    )
    .unwrap_err();
    assert!(matches!(error, PackageError::PublicationUncertain(_)));
    assert_eq!(installation_count(&f), 1);
    assert_eq!(
        std::fs::read_dir(f.home.join("signed-packages/saved-index"))
            .unwrap()
            .count(),
        1
    );
    std::fs::remove_dir(f.home.join("signed-packages/installed")).unwrap();
    std::fs::rename(
        f.home.join("signed-packages/saved-index"),
        f.home.join("signed-packages/installed"),
    )
    .unwrap();
    assert!(
        install(&f.home, &f.manifest, &f.bytes, true)
            .unwrap()
            .reused
    );
    assert_verified(&f);
}

#[test]
fn catalog_distinguishes_missing_tampered_and_untrusted_content() {
    let f = Fixture::new(vec![]);
    f.trust();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let content = f
        .home
        .join("signed-packages/content")
        .join(format!("{}.blob", receipt.content_digest));
    std::fs::remove_file(&content).unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::MissingContent
    );
    std::fs::write(&content, "tampered").unwrap();
    std::fs::set_permissions(&content, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::Tampered
    );
    std::fs::write(&content, &f.bytes).unwrap();
    std::fs::write(f.home.join("mods/issuers.txt"), "").unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::UntrustedIssuer
    );
}

#[test]
fn head_cache_is_not_proof_and_all_index_payload_fields_are_verified() {
    let f = Fixture::new(vec![]);
    f.trust();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let index = saved_index(&f, &receipt.install_id);
    let original = std::fs::read(&index).unwrap();
    std::fs::write(f.home.join("ledger/HEAD"), "f".repeat(64)).unwrap();
    assert_verified(&f);
    let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
    document["ledger_record_hash"] = serde_json::json!("f".repeat(64));
    std::fs::write(&index, serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::MissingProof
    );
    for (field, value) in [
        ("name", serde_json::json!("changed")),
        ("version", serde_json::json!("2")),
        ("issuer_public_key", serde_json::json!("a".repeat(64))),
        ("manifest_digest", serde_json::json!("a".repeat(64))),
        ("content_digest", serde_json::json!("a".repeat(64))),
        ("install_id", serde_json::json!("a".repeat(64))),
        ("package_bytes", serde_json::json!(99)),
        ("operator_confirmed", serde_json::json!(false)),
    ] {
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
        document["payload"][field] = value;
        std::fs::write(&index, serde_json::to_vec(&document).unwrap()).unwrap();
        assert_ne!(
            catalog(&f.home, None).unwrap().packages[0].status,
            PackageStatus::Verified,
            "field {field}"
        );
    }
    std::fs::write(&index, original).unwrap();
    std::fs::rename(f.home.join("ledger"), f.home.join("saved-ledger")).unwrap();
    assert_eq!(
        catalog(&f.home, None).unwrap().packages[0].status,
        PackageStatus::MissingProof
    );
}

#[test]
fn bounded_inputs_refuse_unknown_duplicate_oversize_symlink_and_fifo_files() {
    let f = Fixture::new(vec![]);
    write_inputs(&f);
    let manifest = f.home.join("fixture-manifest.json");
    let package = f.home.join("fixture-package.wasm");
    let mut json: serde_json::Value = serde_json::to_value(&f.manifest).unwrap();
    json["extra"] = serde_json::json!(true);
    std::fs::write(&manifest, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(read_install_inputs(&manifest, &package).is_err());
    let original = serde_json::to_string(&f.manifest).unwrap();
    std::fs::write(
        &manifest,
        original.replacen(
            "\"name\":\"example\"",
            "\"name\":\"example\",\"name\":\"other\"",
            1,
        ),
    )
    .unwrap();
    assert!(read_install_inputs(&manifest, &package).is_err());
    std::fs::write(&manifest, &original).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&package)
        .unwrap()
        .set_len((signed_packages::MAX_PACKAGE_BYTES + 1) as u64)
        .unwrap();
    assert!(read_install_inputs(&manifest, &package).is_err());
    std::fs::write(&package, &f.bytes).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&manifest)
        .unwrap()
        .set_len((signed_packages::MAX_MANIFEST_BYTES + 1) as u64)
        .unwrap();
    assert!(read_install_inputs(&manifest, &package).is_err());
    std::fs::write(&manifest, &original).unwrap();
    std::fs::rename(&package, f.home.join("saved-package")).unwrap();
    std::os::unix::fs::symlink(f.home.join("saved-package"), &package).unwrap();
    assert!(read_install_inputs(&manifest, &package).is_err());
    std::fs::remove_file(&package).unwrap();
    let path = std::ffi::CString::new(package.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: this NUL-free path is inside the owned private fixture; mkfifo
    // only creates that entry with mode0600 and does not open or block on it.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = Probe::spawn_existing_inputs(&f, "read-refusal");
    child.finish();
    assert!(!f.home.join("signed-packages").exists());
    assert!(!f.home.join("ledger").exists());
}

#[test]
fn traversal_metadata_and_oversize_bytes_refuse_before_store_creation() {
    let mut f = Fixture::new(vec![]);
    f.trust();
    f.manifest = sign_manifest(
        "../escape",
        "1",
        &SigningKey::from_bytes(&[37; 32]),
        &f.bytes,
        vec![],
    );
    assert!(matches!(
        install(&f.home, &f.manifest, &f.bytes, true),
        Err(PackageError::Metadata(_))
    ));
    f.no_install();
    f.manifest = sign_manifest(
        "example",
        "1",
        &SigningKey::from_bytes(&[37; 32]),
        &f.bytes,
        vec![],
    );
    assert!(matches!(
        install(
            &f.home,
            &f.manifest,
            &vec![0; signed_packages::MAX_PACKAGE_BYTES + 1],
            true
        ),
        Err(PackageError::Metadata(_))
    ));
    f.no_install();
}

#[test]
fn symlink_store_and_conflicting_immutable_bytes_never_authorize_success() {
    let f = Fixture::new(vec![]);
    f.trust();
    std::fs::create_dir(f.home.join("outside")).unwrap();
    std::os::unix::fs::symlink(f.home.join("outside"), f.home.join("signed-packages")).unwrap();
    assert!(install(&f.home, &f.manifest, &f.bytes, true).is_err());
    assert!(std::fs::read_dir(f.home.join("outside"))
        .unwrap()
        .next()
        .is_none());
    std::fs::remove_file(f.home.join("signed-packages")).unwrap();
    let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
    let index = saved_index(&f, &receipt.install_id);
    let before = std::fs::read(&index).unwrap();
    std::fs::write(
        f.home
            .join("signed-packages/content")
            .join(format!("{}.blob", receipt.content_digest)),
        "different",
    )
    .unwrap();
    assert!(install(&f.home, &f.manifest, &f.bytes, true).is_err());
    assert_eq!(std::fs::read(index).unwrap(), before);
    assert_eq!(installation_count(&f), 1);
}

#[test]
fn exact_status_filters_before_paging_over_genuine_substring_neighbors() {
    let mut selected = None;
    // Choose a fixture by actual public receipts; the test does not reproduce
    // the backend's identity algorithm or synthesize installed metadata.
    for version in 0..16 {
        let mut f = Fixture::new(vec![]);
        f.trust();
        f.manifest = sign_manifest(
            "example",
            &format!("1.0.0-{version}"),
            &SigningKey::from_bytes(&[37; 32]),
            &f.bytes,
            vec![],
        );
        let receipt = install(&f.home, &f.manifest, &f.bytes, true).unwrap();
        if selected
            .as_ref()
            .is_none_or(|(_, old): &(Fixture, signed_packages::InstallReceipt)| {
                receipt.install_id > old.install_id
            })
        {
            selected = Some((f, receipt));
        }
    }
    let (f, target) = selected.unwrap();
    let mut lower = 0;
    for n in 0..256 {
        let manifest = sign_manifest(
            &format!("example-neighbor-{n:03}"),
            "1",
            &SigningKey::from_bytes(&[37; 32]),
            &f.bytes,
            vec![],
        );
        let receipt = install(&f.home, &manifest, &f.bytes, true).unwrap();
        if receipt.install_id < target.install_id {
            lower += 1;
        }
        if lower >= 65 {
            break;
        }
    }
    assert!(
        lower >= 65,
        "fixture needs >64 genuinely installed lower-sorted neighbors"
    );
    let substring = catalog(&f.home, Some("example")).unwrap();
    assert_eq!(substring.packages.len(), 64);
    assert!(substring.truncated);
    assert!(substring.total > 64);
    assert!(substring.packages.iter().all(|p| p.name != "example"));
    let exact = status(&f.home, "example").unwrap();
    assert_eq!(exact.total, 1);
    assert!(!exact.truncated);
    assert_eq!(
        exact.packages[0].ledger_record_hash,
        target.ledger_record_hash
    );
    assert_eq!(exact.packages[0].status, PackageStatus::Verified);
    assert!(status(&f.home, "exam").unwrap().packages.is_empty());
}
