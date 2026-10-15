#![cfg(unix)]

use orbit_ledger::{LedgerEvent, LedgerWriter, PluginInstall, verify_ledger};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

struct Fixture {
    base: PathBuf,
    ledger: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("orbit-install-ledger-{}", ulid::Ulid::new()));
        let ledger = base.join("ledger");
        std::fs::create_dir_all(&base).unwrap();
        Self { base, ledger }
    }
    fn open(&self) -> LedgerWriter {
        LedgerWriter::open(&self.ledger, "fixture-writer".into(), "1").unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn install() -> PluginInstall {
    PluginInstall {
        install_id: "a".repeat(64),
        name: "example".into(),
        version: "1.0.0".into(),
        issuer_public_key: "b".repeat(64),
        manifest_digest: "c".repeat(64),
        content_digest: "d".repeat(64),
        package_bytes: 17,
        operator_confirmed: true,
    }
}

#[test]
fn installation_ack_reopens_with_exact_typed_payload_and_record_hash() {
    let f = Fixture::new();
    let mut writer = f.open();
    let payload = install();
    let hash = writer
        .append(LedgerEvent::PluginInstall(payload.clone()))
        .unwrap();
    drop(writer);
    let (records, head) = verify_ledger(&f.ledger).unwrap();
    assert_eq!(head, hash);
    let record = records
        .iter()
        .find(|record| record.self_hash == hash)
        .unwrap();
    assert_eq!(record.record.event, LedgerEvent::PluginInstall(payload));
    let bytes = serde_json::to_vec(&record.record.event).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["variant"], "plugin_install");
    assert!(value.get("content").is_none());
    assert!(value.get("path").is_none());
    let reopened = f.open();
    let (records, _) = verify_ledger(&f.ledger).unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record.record.event, LedgerEvent::PluginInstall(_)))
            .count(),
        1
    );
    drop(reopened);
}

#[test]
fn missing_segment_directory_sync_refuses_installation_ack() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    std::fs::rename(f.ledger.join("segments"), f.ledger.join("saved-segments")).unwrap();
    std::fs::write(f.ledger.join("segments"), "not a directory").unwrap();
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(error.to_string().contains("segment directory"), "{error}");
    assert_eq!(writer.head(), previous);
    std::fs::remove_file(f.ledger.join("segments")).unwrap();
    std::fs::rename(f.ledger.join("saved-segments"), f.ledger.join("segments")).unwrap();
    assert!(
        writer
            .append(LedgerEvent::PluginInstall(install()))
            .unwrap_err()
            .to_string()
            .contains("reopened")
    );
}

#[test]
fn missing_ledger_directory_sync_refuses_installation_ack() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    std::fs::rename(&f.ledger, f.base.join("saved-ledger")).unwrap();
    std::fs::write(&f.ledger, "not a directory").unwrap();
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(error.to_string().contains("directory"), "{error}");
    assert_eq!(writer.head(), previous);
}

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path) {
    std::fs::write(path, "").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn no_installation_proof(ledger: &Path) {
    let (records, _) = verify_ledger(ledger).unwrap();
    assert!(
        records
            .iter()
            .all(|record| !matches!(record.record.event, LedgerEvent::PluginInstall(_)))
    );
}

fn refused_writer_stays_poisoned(writer: &mut LedgerWriter) {
    assert!(
        writer
            .append(LedgerEvent::PluginInstall(install()))
            .unwrap_err()
            .to_string()
            .contains("reopened")
    );
    assert!(writer.fsync().unwrap_err().to_string().contains("reopened"));
}

#[test]
fn valid_segment_directory_replacement_refuses_ack_before_write() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    let saved = f.ledger.join("saved-segments");
    std::fs::rename(f.ledger.join("segments"), &saved).unwrap();
    private_directory(&f.ledger.join("segments"));
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("segment directory identity changed"),
        "{error}"
    );
    assert_eq!(writer.head(), previous);
    no_installation_proof(&f.ledger);
    std::fs::remove_dir(f.ledger.join("segments")).unwrap();
    std::fs::rename(saved, f.ledger.join("segments")).unwrap();
    no_installation_proof(&f.ledger);
    refused_writer_stays_poisoned(&mut writer);
}

#[test]
fn valid_ledger_directory_replacement_refuses_ack_before_publication() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    let saved = f.base.join("saved-ledger");
    std::fs::rename(&f.ledger, &saved).unwrap();
    private_directory(&f.ledger);
    private_directory(&f.ledger.join("segments"));
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ledger directory identity changed"),
        "{error}"
    );
    assert_eq!(writer.head(), previous);
    assert!(!f.ledger.join("HEAD").exists());
    no_installation_proof(&f.ledger);
    no_installation_proof(&saved);
    refused_writer_stays_poisoned(&mut writer);
}

#[test]
fn valid_parent_directory_replacement_refuses_ack_before_write() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    let saved = f.base.with_extension("saved-parent");
    std::fs::rename(&f.base, &saved).unwrap();
    private_directory(&f.base);
    private_directory(&f.ledger);
    private_directory(&f.ledger.join("segments"));
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ledger parent directory identity changed"),
        "{error}"
    );
    assert_eq!(writer.head(), previous);
    no_installation_proof(&f.ledger);
    no_installation_proof(&saved.join("ledger"));
    refused_writer_stays_poisoned(&mut writer);
    drop(writer);
    std::fs::remove_dir_all(saved).unwrap();
}

#[test]
fn replaced_writer_lock_refuses_old_writer_ack() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    std::fs::rename(f.ledger.join("writer.lock"), f.ledger.join("saved-lock")).unwrap();
    private_file(&f.ledger.join("writer.lock"));
    // The replacement really admits another writer; the old writer must
    // detect that its own held lock no longer governs this ledger.
    let replacement = f.open();
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(
        error.to_string().contains("writer lock identity changed"),
        "{error}"
    );
    assert_eq!(writer.head(), previous);
    no_installation_proof(&f.ledger);
    refused_writer_stays_poisoned(&mut writer);
    drop(replacement);
}

#[test]
fn replaced_active_segment_refuses_ack_before_write() {
    let f = Fixture::new();
    let mut writer = f.open();
    let previous = writer.head().to_string();
    let segment = writer.active_segment_path().to_path_buf();
    let saved = segment.with_extension("saved");
    std::fs::rename(&segment, &saved).unwrap();
    let original_bytes = std::fs::read(&saved).unwrap();
    private_file(&segment);
    let error = writer
        .append(LedgerEvent::PluginInstall(install()))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("active segment identity changed"),
        "{error}"
    );
    assert_eq!(writer.head(), previous);
    assert_eq!(std::fs::read(saved).unwrap(), original_bytes);
    no_installation_proof(&f.ledger);
    refused_writer_stays_poisoned(&mut writer);
}

#[test]
fn symlink_writer_lock_is_refused_without_changing_target() {
    let f = Fixture::new();
    private_directory(&f.ledger);
    let outside = f.base.join("outside");
    std::fs::write(&outside, "untouched").unwrap();
    std::os::unix::fs::symlink(&outside, f.ledger.join("writer.lock")).unwrap();
    assert!(LedgerWriter::open(&f.ledger, "fixture".into(), "1").is_err());
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "untouched");
}

#[test]
fn symlink_root_is_refused_without_changing_target_permissions() {
    let f = Fixture::new();
    let outside = f.base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&outside, &f.ledger).unwrap();
    assert!(LedgerWriter::open(&f.ledger, "fixture".into(), "1").is_err());
    assert_eq!(
        std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!outside.join("writer.lock").exists());
}
