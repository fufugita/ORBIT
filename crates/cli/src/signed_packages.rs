//! Durable signed package storage and a read-time verified installed catalog.
//! Package installation stores bytes and proof; it does not execute packages.

use orbit_ledger::{validate_record, LedgerEvent, LedgerRecord, LedgerWriter, PluginInstall};
use orbit_plugin::{PluginManifest, WasiHostAllowlist};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 32 * 1024;
const MAX_INDEX_BYTES: usize = 4096;
const MAX_ISSUERS_BYTES: usize = 32 * 1024;
const MAX_LEDGER_BYTES: usize = 128 * 1024 * 1024;
const MAX_SEGMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 1024;
const PAGE_SIZE: usize = 64;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestPoint {
    ImmutableStaged,
    ImmutablePublished,
    ProofOpened { durable: bool },
    ProofChecked { durable: bool },
    LedgerAcknowledged,
    IndexPublished,
    IssuerBeforePublish,
    IssuerPublished,
}
#[cfg(test)]
type TestHook = Box<dyn FnMut(TestPoint, &Path)>;
#[cfg(test)]
std::thread_local! { static TEST_HOOK: std::cell::RefCell<Option<TestHook>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub fn with_test_hook<T>(
    hook: impl FnMut(TestPoint, &Path) + 'static,
    work: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<TestHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| {
                slot.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(TEST_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    work()
}
fn test_point(point: TestPoint, path: &Path) {
    #[cfg(test)]
    TEST_HOOK.with(|slot| {
        let hook = slot.borrow_mut().take();
        if let Some(mut hook) = hook {
            hook(point, path);
            slot.replace(Some(hook));
        }
    });
    #[cfg(not(test))]
    let _ = (point, path);
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("package metadata: {0}")]
    Metadata(String),
    #[error("operator confirmation is required")]
    Confirmation,
    #[error("issuer is not trusted")]
    UntrustedIssuer,
    #[error("package signature: {0}")]
    Signature(String),
    #[error("package import: {0}")]
    Import(String),
    #[error("package content digest does not match signed manifest")]
    Digest,
    #[error("package storage: {0}")]
    Storage(String),
    #[error("package writer is busy")]
    Busy,
    #[error("package ledger: {0}")]
    Ledger(String),
    #[error("package publication is uncertain: {0}; retry the same operation")]
    PublicationUncertain(String),
}
impl PackageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Confirmation | Self::Metadata(_) => "ORBIT-E1101",
            Self::Signature(_) | Self::UntrustedIssuer | Self::Digest => "ORBIT-E0806",
            Self::Import(_) => "ORBIT-E0808",
            Self::Storage(_) => "ORBIT-E0401",
            Self::Busy | Self::Ledger(_) | Self::PublicationUncertain(_) => "ORBIT-E0811",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallReceipt {
    pub name: String,
    pub version: String,
    pub issuer_public_key: String,
    pub install_id: String,
    pub manifest_digest: String,
    pub content_digest: String,
    pub package_bytes: u64,
    pub ledger_record_hash: String,
    pub reused: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageStatus {
    Verified,
    MissingContent,
    Tampered,
    UntrustedIssuer,
    MissingProof,
    InvalidProof,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogEntry {
    pub name: String,
    pub version: String,
    pub issuer_public_key: String,
    pub install_id: String,
    pub manifest_digest: String,
    pub content_digest: String,
    pub package_bytes: u64,
    pub ledger_record_hash: String,
    pub status: PackageStatus,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct CatalogPage {
    pub packages: Vec<CatalogEntry>,
    pub total: usize,
    pub truncated: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInstall {
    v: String,
    payload: PluginInstall,
    ledger_record_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictManifest {
    name: String,
    version: String,
    issuer_public_key: String,
    content_digest: String,
    signature: String,
    declared_imports: Vec<String>,
}
impl From<StrictManifest> for PluginManifest {
    fn from(value: StrictManifest) -> Self {
        Self {
            name: value.name,
            version: value.version,
            issuer_public_key: value.issuer_public_key,
            content_digest: value.content_digest,
            signature: value.signature,
            declared_imports: value.declared_imports,
        }
    }
}

/// Read bounded regular no-follow inputs; reject extra or duplicate manifest fields.
pub fn read_install_inputs(
    manifest_path: &Path,
    package_path: &Path,
) -> Result<(PluginManifest, Vec<u8>), PackageError> {
    let manifest = parse_manifest(&read_file(manifest_path, MAX_MANIFEST_BYTES, false, false)?)?;
    validate_manifest(&manifest)?;
    let bytes = read_file(package_path, MAX_PACKAGE_BYTES, false, false)?;
    Ok((manifest, bytes))
}

/// Preserve the existing one-full-hex-key-per-line issuer list.
pub fn trusted_issuers(home: &Path) -> Result<Vec<String>, PackageError> {
    if !exists(home)? {
        return Ok(Vec::new());
    }
    let home = Directory::home(home)?;
    if !exists(&home.io()?.join("mods"))? {
        return Ok(Vec::new());
    }
    let mods = Directory::child(&home, "mods", false, false)?;
    let path = mods.io()?.join("issuers.txt");
    let result = if !exists(&path)? {
        Vec::new()
    } else {
        parse_issuers(&read_file(&path, MAX_ISSUERS_BYTES, true, false)?)?
    };
    home.validate()?;
    mods.validate()?;
    Ok(result)
}

/// Explicit operator trust uses private atomic persistence, compatible with mods.
pub fn trust_issuer(home: &Path, key: &str) -> Result<(), PackageError> {
    let key = key.trim().to_ascii_lowercase();
    if !hex_string(&key, 64) {
        return Err(PackageError::Metadata(
            "issuer key must be 32 bytes of hex".into(),
        ));
    }
    if !exists(home)? {
        std::fs::create_dir_all(home).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = open_directory(home)?;
            check_owner(&file.metadata().map_err(storage)?)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(storage)?;
        }
    }
    let home = Directory::home(home)?;
    let parent = Directory::open(
        home.canonical
            .parent()
            .ok_or_else(|| storage("home has no parent"))?,
        false,
        false,
    )?;
    let mut mods = Directory::child(&home, "mods", true, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        mods.file
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(storage)?;
        mods.private = true;
    }
    let lock = acquire_lock(&mods.io()?.join("issuers.lock"))?;
    let path = mods.io()?.join("issuers.txt");
    let mut issuers: BTreeSet<String> = if exists(&path)? {
        parse_issuers(&read_file(&path, MAX_ISSUERS_BYTES, true, false)?)?
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    };
    issuers.insert(key);
    if issuers.len() > 256 {
        return Err(PackageError::Metadata("too many trusted issuers".into()));
    }
    let text = format!("{}\n", issuers.into_iter().collect::<Vec<_>>().join("\n"));
    mods.sync()?;
    home.sync()?;
    parent.sync()?;
    parent.validate()?;
    home.validate()?;
    lock.validate()?;
    test_point(
        TestPoint::IssuerBeforePublish,
        &mods.requested.join("issuers.txt"),
    );
    atomic_file(&mods, "issuers.txt", text.as_bytes())?;
    test_point(
        TestPoint::IssuerPublished,
        &mods.requested.join("issuers.txt"),
    );
    (|| {
        mods.sync()?;
        home.sync()?;
        home.validate()?;
        mods.validate()?;
        parent.validate()?;
        lock.validate()
    })()
    .map_err(|e: PackageError| PackageError::PublicationUncertain(e.to_string()))
}

/// Validate first, persist immutable bytes, acknowledge a real event, then publish.
pub fn install(
    home: &Path,
    manifest: &PluginManifest,
    bytes: &[u8],
    confirmed: bool,
) -> Result<InstallReceipt, PackageError> {
    if !confirmed {
        return Err(PackageError::Confirmation);
    }
    validate_manifest(manifest)?;
    if bytes.is_empty() || bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::Metadata("package size outside bounds".into()));
    }
    manifest
        .verify_issuer_signature()
        .map_err(|e| PackageError::Signature(e.to_string()))?;
    WasiHostAllowlist::canonical()
        .validate(&manifest.declared_imports)
        .map_err(|e| PackageError::Import(e.to_string()))?;
    if sha(bytes) != manifest.content_digest {
        return Err(PackageError::Digest);
    }
    if !trusted_issuers(home)?.contains(&manifest.issuer_public_key.to_ascii_lowercase()) {
        return Err(PackageError::UntrustedIssuer);
    }
    let manifest_bytes = orbit_plugin::canonical::canonical_bytes(manifest)
        .map_err(|e| PackageError::Metadata(e.to_string()))?;
    let payload = intent(manifest, &manifest_bytes, bytes.len() as u64)?;
    let store = Store::open(home, true)?
        .ok_or_else(|| PackageError::Storage("store unavailable".into()))?;
    let lock = acquire_lock(&store.root.io()?.join("install.lock"))?;
    store.validate()?;
    lock.validate()?;
    immutable_file(
        &store.content,
        &format!("{}.blob", payload.content_digest),
        bytes,
    )?;
    immutable_file(
        &store.manifests,
        &format!("{}.json", payload.manifest_digest),
        &manifest_bytes,
    )?;
    store.sync()?;
    lock.validate()?;

    // Existing home/ledger is the sole authority. An actual OS lock bounds
    // concurrent callers; neither HEAD nor attach_ledger booleans are proof.
    let ledger_path = store.home.requested.join("ledger");
    // Bound and validate existing recovery inputs before the established
    // writer opens them. Readers keep their existing public API unchanged.
    read_proofs(&store.home, false)?;
    let mut writer = open_ledger(&ledger_path)?;
    let proofs = read_proofs(&store.home, true)?;
    let existing = proofs
        .iter()
        .find(|(_, event)| event.install_id == payload.install_id);
    let (hash, reused) = match existing {
        Some((hash, event)) if event == &payload => (hash.clone(), true),
        Some(_) => {
            return Err(PackageError::Ledger(
                "conflicting installation intent".into(),
            ));
        }
        None => (
            writer
                .append(LedgerEvent::PluginInstall(payload.clone()))
                .map_err(|e| PackageError::Ledger(e.to_string()))?,
            false,
        ),
    };
    let actual = read_proofs(&store.home, true)?;
    if actual.get(&hash) != Some(&payload) {
        return Err(PackageError::Ledger(
            "acknowledged event is missing from verified chain".into(),
        ));
    }
    if !trusted_issuers(&store.home.requested)?
        .contains(&payload.issuer_public_key.to_ascii_lowercase())
    {
        return Err(PackageError::UntrustedIssuer);
    }
    test_point(TestPoint::LedgerAcknowledged, &store.installed.requested);
    let record = StoredInstall {
        v: "orbit.signed-install/v1".into(),
        payload: payload.clone(),
        ledger_record_hash: hash.clone(),
    };
    let index_name = format!("{}.json", payload.install_id);
    let index_path = store.installed.io()?.join(&index_name);
    if exists(&index_path)? {
        let saved: StoredInstall =
            serde_json::from_slice(&read_file(&index_path, MAX_INDEX_BYTES, true, true)?)
                .map_err(|e| PackageError::Storage(format!("installed metadata: {e}")))?;
        if saved != record {
            return Err(PackageError::Storage(
                "conflicting installed metadata".into(),
            ));
        }
    }
    store.validate()?;
    lock.validate()?;
    atomic_file(
        &store.installed,
        &index_name,
        &orbit_plugin::canonical::canonical_bytes(&record)
            .map_err(|e| PackageError::Storage(e.to_string()))?,
    )?;
    test_point(
        TestPoint::IndexPublished,
        &store.installed.requested.join(&index_name),
    );
    store
        .validate()
        .map_err(|e| PackageError::PublicationUncertain(e.to_string()))?;
    lock.validate()
        .map_err(|e| PackageError::PublicationUncertain(e.to_string()))?;
    drop(writer);
    Ok(InstallReceipt {
        name: payload.name,
        version: payload.version,
        issuer_public_key: payload.issuer_public_key,
        install_id: payload.install_id,
        manifest_digest: payload.manifest_digest,
        content_digest: payload.content_digest,
        package_bytes: payload.package_bytes,
        ledger_record_hash: hash,
        reused,
    })
}

/// A bounded local catalog, with signature, bytes, issuer and real proof checked.
pub fn catalog(home: &Path, query: Option<&str>) -> Result<CatalogPage, PackageError> {
    let query = query.unwrap_or("");
    if query.len() > 128 || query.chars().any(char::is_control) {
        return Err(PackageError::Metadata(
            "catalog query outside bounds".into(),
        ));
    }
    catalog_selected(home, query, false)
}

/// Match the literal installed name before applying the catalog page bound.
pub fn status(home: &Path, name: &str) -> Result<CatalogPage, PackageError> {
    if !identifier(name) {
        return Err(PackageError::Metadata("package name outside bounds".into()));
    }
    catalog_selected(home, name, true)
}

fn catalog_selected(home: &Path, query: &str, exact: bool) -> Result<CatalogPage, PackageError> {
    let Some(store) = Store::open(home, false)? else {
        return Ok(CatalogPage::default());
    };
    let issuers = trusted_issuers(home)?;
    let proofs = read_proofs(&store.home, false);
    let names = names(&store.installed)?;
    let mut result = Vec::new();
    for name in names {
        if name.starts_with(".tmp-") {
            continue;
        }
        let id = name
            .strip_suffix(".json")
            .filter(|id| hex_string(id, 64))
            .unwrap_or("");
        let record = read_file(
            &store.installed.io()?.join(&name),
            MAX_INDEX_BYTES,
            true,
            true,
        )
        .and_then(|bytes| {
            serde_json::from_slice::<StoredInstall>(&bytes)
                .map_err(|e| PackageError::Storage(e.to_string()))
        });
        let mut entry = CatalogEntry {
            name: "<invalid package>".into(),
            version: String::new(),
            issuer_public_key: String::new(),
            install_id: id.into(),
            manifest_digest: String::new(),
            content_digest: String::new(),
            package_bytes: 0,
            ledger_record_hash: String::new(),
            status: PackageStatus::Tampered,
        };
        if let Ok(record) = record {
            if valid_payload(&record.payload)
                && record.v == "orbit.signed-install/v1"
                && record.payload.install_id == id
                && hex_string(&record.ledger_record_hash, 64)
            {
                let p = &record.payload;
                entry = CatalogEntry {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    issuer_public_key: p.issuer_public_key.clone(),
                    install_id: p.install_id.clone(),
                    manifest_digest: p.manifest_digest.clone(),
                    content_digest: p.content_digest.clone(),
                    package_bytes: p.package_bytes,
                    ledger_record_hash: record.ledger_record_hash.clone(),
                    status: PackageStatus::Tampered,
                };
                entry.status = package_status(&store, &record, &issuers, &proofs);
            }
        }
        let needle = query.to_ascii_lowercase();
        let contains = needle.is_empty()
            || [
                &entry.name,
                &entry.version,
                &entry.issuer_public_key,
                &entry.content_digest,
            ]
            .iter()
            .any(|text| text.to_ascii_lowercase().contains(&needle));
        if (exact && entry.name == query) || (!exact && contains) {
            result.push(entry);
        }
    }
    store.validate()?;
    let total = result.len();
    result.truncate(PAGE_SIZE);
    Ok(CatalogPage {
        packages: result,
        total,
        truncated: total > PAGE_SIZE,
    })
}

fn package_status(
    store: &Store,
    record: &StoredInstall,
    issuers: &[String],
    proofs: &Result<BTreeMap<String, PluginInstall>, PackageError>,
) -> PackageStatus {
    let p = &record.payload;
    let Ok(manifest_path) = store
        .manifests
        .io()
        .map(|dir| dir.join(format!("{}.json", p.manifest_digest)))
    else {
        return PackageStatus::Tampered;
    };
    let Ok(manifest_bytes) = read_file(&manifest_path, MAX_MANIFEST_BYTES, true, true) else {
        return PackageStatus::Tampered;
    };
    let Ok(manifest) = parse_manifest(&manifest_bytes) else {
        return PackageStatus::Tampered;
    };
    if validate_manifest(&manifest).is_err()
        || manifest.verify_issuer_signature().is_err()
        || WasiHostAllowlist::canonical()
            .validate(&manifest.declared_imports)
            .is_err()
    {
        return PackageStatus::Tampered;
    }
    let Ok(canonical) = orbit_plugin::canonical::canonical_bytes(&manifest) else {
        return PackageStatus::Tampered;
    };
    if sha(&canonical) != p.manifest_digest
        || intent(&manifest, &canonical, p.package_bytes).ok().as_ref() != Some(p)
    {
        return PackageStatus::Tampered;
    }
    if !issuers.contains(&p.issuer_public_key.to_ascii_lowercase()) {
        return PackageStatus::UntrustedIssuer;
    }
    let Ok(content_path) = store
        .content
        .io()
        .map(|dir| dir.join(format!("{}.blob", p.content_digest)))
    else {
        return PackageStatus::Tampered;
    };
    if matches!(exists(&content_path), Ok(false)) {
        return PackageStatus::MissingContent;
    }
    let Ok(bytes) = read_file(&content_path, MAX_PACKAGE_BYTES, true, true) else {
        return PackageStatus::Tampered;
    };
    if bytes.len() as u64 != p.package_bytes || sha(&bytes) != p.content_digest {
        return PackageStatus::Tampered;
    }
    match proofs {
        Ok(proofs) if proofs.get(&record.ledger_record_hash) == Some(p) => PackageStatus::Verified,
        Ok(_) => PackageStatus::MissingProof,
        Err(_) => PackageStatus::InvalidProof,
    }
}

fn intent(
    manifest: &PluginManifest,
    canonical: &[u8],
    package_bytes: u64,
) -> Result<PluginInstall, PackageError> {
    let manifest_digest = sha(canonical);
    let identity = serde_json::json!({ "v": "orbit.signed-intent/v1", "manifest_digest": manifest_digest,
        "content_digest": manifest.content_digest, "package_bytes": package_bytes, "operator_confirmed": true });
    let install_id = sha(&orbit_plugin::canonical::canonical_bytes(&identity)
        .map_err(|e| PackageError::Metadata(e.to_string()))?);
    Ok(PluginInstall {
        install_id,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        issuer_public_key: manifest.issuer_public_key.clone(),
        manifest_digest,
        content_digest: manifest.content_digest.clone(),
        package_bytes,
        operator_confirmed: true,
    })
}
fn valid_payload(p: &PluginInstall) -> bool {
    identifier(&p.name)
        && identifier(&p.version)
        && hex_string(&p.install_id, 64)
        && hex_string(&p.manifest_digest, 64)
        && hex_string(&p.content_digest, 64)
        && encoded_hex(&p.issuer_public_key, 64)
        && p.operator_confirmed
        && p.package_bytes > 0
        && p.package_bytes <= MAX_PACKAGE_BYTES as u64
}
fn validate_manifest(m: &PluginManifest) -> Result<(), PackageError> {
    if !identifier(&m.name)
        || !identifier(&m.version)
        || !encoded_hex(&m.issuer_public_key, 64)
        || !hex_string(&m.content_digest, 64)
        || !encoded_hex(&m.signature, 128)
        || m.declared_imports.len() > 32
        || m.declared_imports.iter().any(|s| {
            s.is_empty() || s.len() > 128 || !s.is_ascii() || s.chars().any(char::is_control)
        })
    {
        return Err(PackageError::Metadata(
            "signed manifest fields outside bounds".into(),
        ));
    }
    Ok(())
}
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 96
        && !text.starts_with('.')
        && !text.contains("..")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn hex_string(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encoded_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}
fn parse_manifest(bytes: &[u8]) -> Result<PluginManifest, PackageError> {
    serde_json::from_slice::<StrictManifest>(bytes)
        .map(Into::into)
        .map_err(|e| PackageError::Metadata(format!("manifest JSON: {e}")))
}
fn parse_issuers(bytes: &[u8]) -> Result<Vec<String>, PackageError> {
    let text = std::str::from_utf8(bytes).map_err(|e| PackageError::Storage(e.to_string()))?;
    let mut issuers = BTreeSet::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let key = line.to_ascii_lowercase();
        if !hex_string(&key, 64) {
            return Err(PackageError::Storage("malformed trusted issuer key".into()));
        }
        issuers.insert(key);
        if issuers.len() > 256 {
            return Err(PackageError::Storage("too many trusted issuers".into()));
        }
    }
    Ok(issuers.into_iter().collect())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn storage(error: impl std::fmt::Display) -> PackageError {
    PackageError::Storage(error.to_string())
}
fn exists(path: &Path) -> Result<bool, PackageError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(storage(e)),
    }
}

struct Directory {
    file: File,
    requested: PathBuf,
    canonical: PathBuf,
    owned: bool,
    private: bool,
}
impl Directory {
    fn home(path: &Path) -> Result<Self, PackageError> {
        Self::open(path, true, false)
    }
    fn open(path: &Path, owned: bool, private: bool) -> Result<Self, PackageError> {
        let requested = std::env::current_dir().map_err(storage)?.join(path);
        let file = open_directory(&requested)?;
        let canonical = std::fs::canonicalize(&requested).map_err(storage)?;
        let result = Self {
            file,
            requested,
            canonical,
            owned,
            private,
        };
        result.validate()?;
        Ok(result)
    }
    fn child(parent: &Self, name: &str, create: bool, private: bool) -> Result<Self, PackageError> {
        parent.validate()?;
        let path = parent.io()?.join(name);
        if create {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(storage(e)),
            }
        }
        let result = Self {
            file: open_directory(&path)?,
            requested: parent.requested.join(name),
            canonical: parent.canonical.join(name),
            owned: true,
            private,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), PackageError> {
        for path in [&self.requested, &self.canonical] {
            let current = open_directory(path)?;
            let actual = current.metadata().map_err(storage)?;
            let held = self.file.metadata().map_err(storage)?;
            if !same(&actual, &held) {
                return Err(storage("package directory identity changed"));
            }
            if self.owned {
                check_owner(&actual)?;
                check_mode(&actual, self.private)?;
            }
        }
        Ok(())
    }
    fn io(&self) -> Result<PathBuf, PackageError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
            if !same(
                &std::fs::metadata(&path).map_err(storage)?,
                &self.file.metadata().map_err(storage)?,
            ) {
                return Err(storage("directory FD path identity changed"));
            }
            Ok(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(storage("signed storage requires Linux directory FDs"))
        }
    }
    fn sync(&self) -> Result<(), PackageError> {
        self.file.sync_all().map_err(storage)
    }
}
struct Store {
    parent: Directory,
    home: Directory,
    root: Directory,
    content: Directory,
    manifests: Directory,
    installed: Directory,
}
impl Store {
    fn open(home: &Path, create: bool) -> Result<Option<Self>, PackageError> {
        if !exists(home)? {
            return Ok(None);
        }
        let home = Directory::home(home)?;
        if !create && !exists(&home.io()?.join("signed-packages"))? {
            return Ok(None);
        }
        let parent = Directory::open(
            home.canonical
                .parent()
                .ok_or_else(|| storage("home has no parent"))?,
            false,
            false,
        )?;
        let root = Directory::child(&home, "signed-packages", create, true)?;
        let content = Directory::child(&root, "content", create, true)?;
        let manifests = Directory::child(&root, "manifests", create, true)?;
        let installed = Directory::child(&root, "installed", create, true)?;
        let result = Self {
            parent,
            home,
            root,
            content,
            manifests,
            installed,
        };
        result.validate()?;
        Ok(Some(result))
    }
    fn validate(&self) -> Result<(), PackageError> {
        for dir in [
            &self.parent,
            &self.home,
            &self.root,
            &self.content,
            &self.manifests,
            &self.installed,
        ] {
            dir.validate()?;
        }
        Ok(())
    }
    fn sync(&self) -> Result<(), PackageError> {
        for dir in [
            &self.content,
            &self.manifests,
            &self.installed,
            &self.root,
            &self.home,
            &self.parent,
        ] {
            dir.sync()?;
        }
        self.validate()
    }
}
fn open_directory(path: &Path) -> Result<File, PackageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(storage)?;
    if !file.metadata().map_err(storage)?.is_dir() {
        return Err(storage("expected directory"));
    }
    Ok(file)
}
fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}
fn check_owner(metadata: &std::fs::Metadata) -> Result<(), PackageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory side effects.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid {
            return Err(storage("storage owner differs from operator"));
        }
    }
    Ok(())
}
fn check_mode(metadata: &std::fs::Metadata, private: bool) -> Result<(), PackageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & if private { 0o077 } else { 0o022 } != 0 {
            return Err(storage("unsafe storage permissions"));
        }
    }
    Ok(())
}
fn check_file(file: &File, owned: bool, private: bool) -> Result<(), PackageError> {
    let metadata = file.metadata().map_err(storage)?;
    if !metadata.is_file() {
        return Err(storage("expected a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(storage("file has multiple links"));
        }
    }
    if owned {
        check_owner(&metadata)?;
        check_mode(&metadata, private)?;
    }
    Ok(())
}
fn read_file(path: &Path, max: usize, owned: bool, private: bool) -> Result<Vec<u8>, PackageError> {
    let file = open_read_file(path)?;
    read_open_file(&file, max, owned, private)
}
fn open_read_file(path: &Path) -> Result<File, PackageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path).map_err(storage)
}
fn read_open_file(
    file: &File,
    max: usize,
    owned: bool,
    private: bool,
) -> Result<Vec<u8>, PackageError> {
    check_file(file, owned, private)?;
    read_contents(file, max)
}
fn read_contents(file: &File, max: usize) -> Result<Vec<u8>, PackageError> {
    if file.metadata().map_err(storage)?.len() > max as u64 {
        return Err(storage("file exceeds byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > max {
        return Err(storage("file exceeds byte bound"));
    }
    Ok(bytes)
}
struct PackageLock {
    file: File,
    path: PathBuf,
}
impl PackageLock {
    fn validate(&self) -> Result<(), PackageError> {
        let current = open_read_file(&self.path)?;
        check_file(&current, true, true)?;
        check_file(&self.file, true, true)?;
        if !same(
            &current.metadata().map_err(storage)?,
            &self.file.metadata().map_err(storage)?,
        ) {
            return Err(storage("package lock identity changed"));
        }
        Ok(())
    }
}
fn acquire_lock(path: &Path) -> Result<PackageLock, PackageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(storage)?;
    check_file(&file, true, true)?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: the owned live File FD is valid; LOCK_NB never blocks.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                let lock = PackageLock {
                    file,
                    path: path.to_path_buf(),
                };
                lock.validate()?;
                return Ok(lock);
            }
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
            ) {
                return Err(storage(error));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(storage("package locks require Unix"));
        }
        if Instant::now() >= deadline {
            return Err(PackageError::Busy);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn temporary_file(dir: &Directory) -> Result<(PathBuf, File), PackageError> {
    let path = dir.io()?.join(format!(".tmp-{}", ulid::Ulid::new()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path).map_err(storage)?;
    Ok((path, file))
}
fn immutable_file(dir: &Directory, name: &str, bytes: &[u8]) -> Result<(), PackageError> {
    dir.validate()?;
    let path = dir.io()?.join(name);
    if exists(&path)? {
        let file = reconcile_immutable(dir, name, bytes)?;
        file.sync_all().map_err(storage)?;
        dir.sync()?;
        return dir.validate();
    }
    let (temporary, mut file) = temporary_file(dir)?;
    let result = (|| {
        file.write_all(bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        test_point(
            TestPoint::ImmutableStaged,
            &dir.requested
                .join(temporary.file_name().expect("temporary name")),
        );
        dir.validate()?;
        let published = match rename_no_replace(dir, &temporary, name) {
            Ok(()) => file.try_clone().map_err(storage)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = reconcile_immutable(dir, name, bytes)?;
                existing.sync_all().map_err(storage)?;
                std::fs::remove_file(&temporary).map_err(storage)?;
                existing
            }
            Err(e) => return Err(storage(e)),
        };
        dir.sync()?;
        dir.validate()?;
        test_point(TestPoint::ImmutablePublished, &dir.requested.join(name));
        check_current_file(&path, &published)?;
        if read_file(&path, bytes.len(), true, true)? != bytes {
            return Err(storage("published immutable bytes changed"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

/// Recover only the previous publisher's complete two-name inode in this
/// private held directory. Foreign links and conflicting bytes stay refused.
fn reconcile_immutable(dir: &Directory, name: &str, expected: &[u8]) -> Result<File, PackageError> {
    use std::os::unix::fs::MetadataExt;
    let path = dir.io()?.join(name);
    let file = open_read_file(&path)?;
    let metadata = file.metadata().map_err(storage)?;
    if !metadata.is_file() {
        return Err(storage("expected immutable regular file"));
    }
    check_owner(&metadata)?;
    check_mode(&metadata, true)?;
    if !matches!(metadata.nlink(), 1 | 2) {
        return Err(storage("immutable file has foreign links"));
    }
    if read_contents(&file, expected.len())? != expected {
        return Err(storage("immutable object differs"));
    }
    if metadata.nlink() == 2 {
        let mut staging = Vec::new();
        for candidate in names(dir)? {
            if candidate == name {
                continue;
            }
            let Some(id) = candidate.strip_prefix(".tmp-") else {
                continue;
            };
            let Ok(id) = id.parse::<ulid::Ulid>() else {
                continue;
            };
            if candidate != format!(".tmp-{id}") {
                continue;
            }
            let entry = dir.io()?.join(&candidate);
            let temporary = open_read_file(&entry)?;
            let temporary_meta = temporary.metadata().map_err(storage)?;
            if same(&metadata, &temporary_meta) {
                check_owner(&temporary_meta)?;
                check_mode(&temporary_meta, true)?;
                if !temporary_meta.is_file() || temporary_meta.nlink() != 2 {
                    return Err(storage("unsafe staging link"));
                }
                staging.push((entry, temporary));
            }
        }
        if staging.len() != 1 {
            return Err(storage("immutable file has foreign links"));
        }
        let (temporary_path, temporary) = staging.pop().expect("one staging entry");
        dir.validate()?;
        if !same(
            &open_read_file(&path)?.metadata().map_err(storage)?,
            &metadata,
        ) || !same(
            &open_read_file(&temporary_path)?
                .metadata()
                .map_err(storage)?,
            &temporary.metadata().map_err(storage)?,
        ) || file.metadata().map_err(storage)?.nlink() != 2
        {
            return Err(storage("staging identity changed"));
        }
        std::fs::remove_file(temporary_path).map_err(storage)?;
        dir.sync()?;
    }
    check_file(&file, true, true)?;
    check_current_file(&path, &file)?;
    dir.validate()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn rename_no_replace(dir: &Directory, temporary: &Path, name: &str) -> std::io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
    let old = std::ffi::CString::new(temporary.file_name().expect("temporary name").as_bytes())?;
    let new = std::ffi::CString::new(name)?;
    // SAFETY: both names are NUL-free owned CStrings; the same live directory
    // FD anchors both entries. RENAME_NOREPLACE atomically refuses overwrite.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::renameat2(
            dir.file.as_raw_fd(),
            old.as_ptr(),
            dir.file.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(not(target_os = "linux"))]
fn rename_no_replace(_dir: &Directory, _temporary: &Path, _name: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-replace publication requires Linux",
    ))
}

fn check_current_file(path: &Path, held: &File) -> Result<(), PackageError> {
    let current = open_read_file(path)?;
    check_file(&current, true, true)?;
    check_file(held, true, true)?;
    if !same(
        &current.metadata().map_err(storage)?,
        &held.metadata().map_err(storage)?,
    ) {
        return Err(storage("proof file identity changed"));
    }
    Ok(())
}
fn atomic_file(dir: &Directory, name: &str, bytes: &[u8]) -> Result<(), PackageError> {
    dir.validate()?;
    let path = dir.io()?.join(name);
    if exists(&path)? {
        let _ = read_file(&path, MAX_ISSUERS_BYTES, true, false)?;
    }
    let (temporary, mut file) = temporary_file(dir)?;
    let result = (|| {
        file.write_all(bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        dir.validate()?;
        std::fs::rename(&temporary, &path).map_err(storage)?;
        dir.sync()
            .and_then(|()| dir.validate())
            .map_err(|e| PackageError::PublicationUncertain(e.to_string()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn names(dir: &Directory) -> Result<Vec<String>, PackageError> {
    dir.validate()?;
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir.io()?).map_err(storage)? {
        let name = entry
            .map_err(storage)?
            .file_name()
            .into_string()
            .map_err(|_| storage("non-text storage name"))?;
        if name.len() > 128 || result.len() >= MAX_FILES {
            return Err(storage("storage directory exceeds bound"));
        }
        result.push(name);
    }
    result.sort();
    Ok(result)
}
fn open_ledger(path: &Path) -> Result<LedgerWriter, PackageError> {
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match LedgerWriter::open(path, "signed-packages".into(), env!("CARGO_PKG_VERSION")) {
            Ok(writer) => return Ok(writer),
            Err(orbit_ledger::LedgerError::LedgerUnavailableAtBoot(message))
                if message.contains("writer.lock held") =>
            {
                if Instant::now() >= deadline {
                    return Err(PackageError::Busy);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(PackageError::Ledger(error.to_string())),
        }
    }
}
fn read_proofs(
    home: &Directory,
    durable: bool,
) -> Result<BTreeMap<String, PluginInstall>, PackageError> {
    if !exists(&home.io()?.join("ledger"))? {
        return Ok(BTreeMap::new());
    }
    let ledger = Directory::child(home, "ledger", false, true)?;
    let segments = Directory::child(&ledger, "segments", false, true)?;
    let mut proofs = BTreeMap::new();
    let mut intents: BTreeMap<String, PluginInstall> = BTreeMap::new();
    let mut prev = "0".repeat(64);
    let mut total = 0;
    let mut frames = 0;
    let segment_names = proof_names(&segments)?;
    let mut held_segments = Vec::new();
    for name in &segment_names {
        let Some(ordinal) = name.strip_suffix(".log") else {
            continue;
        };
        if !hex_string(ordinal, 16) || ordinal == "ffffffffffffffff" {
            return Err(PackageError::Ledger(
                "segment ordinal outside supported bounds".into(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let path = segments.io()?.join(name);
        let file = options.open(&path).map_err(storage)?;
        let original = file.metadata().map_err(storage)?;
        test_point(
            TestPoint::ProofOpened { durable },
            &segments.requested.join(name),
        );
        let bytes = read_open_file(&file, MAX_SEGMENT_BYTES, true, true)?;
        total += bytes.len();
        if total > MAX_LEDGER_BYTES {
            return Err(storage("ledger proof exceeds byte bound"));
        }
        let mut offset = 0;
        while offset < bytes.len() {
            frames += 1;
            if frames > 65_536 {
                return Err(PackageError::Ledger(
                    "ledger frame count exceeds bound".into(),
                ));
            }
            if bytes.len() - offset < 4 {
                return Err(PackageError::Ledger("torn proof frame".into()));
            }
            let len = u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("four-byte slice"),
            ) as usize;
            offset += 4;
            if len > MAX_FRAME_BYTES || len > bytes.len() - offset {
                return Err(PackageError::Ledger("proof frame outside bounds".into()));
            }
            let record: LedgerRecord = serde_json::from_slice(&bytes[offset..offset + len])
                .map_err(|e| PackageError::Ledger(e.to_string()))?;
            offset += len;
            let hash =
                validate_record(&record, &prev).map_err(|e| PackageError::Ledger(e.to_string()))?;
            if let LedgerEvent::PluginInstall(payload) = record.event {
                if record.ledger_hash_self.as_ref() != Some(&hash) {
                    return Err(PackageError::Ledger(
                        "installation proof lacks stored hash".into(),
                    ));
                }
                if intents
                    .get(&payload.install_id)
                    .is_some_and(|old| old != &payload)
                {
                    return Err(PackageError::Ledger("conflicting ledger intent".into()));
                }
                if intents.len() >= 4096 && !intents.contains_key(&payload.install_id) {
                    return Err(PackageError::Ledger(
                        "installation proof count exceeds bound".into(),
                    ));
                }
                intents.insert(payload.install_id.clone(), payload.clone());
                proofs.insert(hash.clone(), payload);
            }
            prev = hash;
        }
        if durable {
            check_current_file(&path, &file)?;
            file.sync_all().map_err(storage)?;
        }
        test_point(
            TestPoint::ProofChecked { durable },
            &segments.requested.join(name),
        );
        held_segments.push((name.clone(), file, original));
    }
    if durable {
        segments.sync()?;
        ledger.sync()?;
        home.sync()?;
    }
    segments.validate()?;
    ledger.validate()?;
    home.validate()?;
    if proof_names(&segments)? != segment_names {
        return Err(PackageError::Ledger("proof segment set changed".into()));
    }
    for (name, file, original) in held_segments {
        check_current_file(&segments.io()?.join(name), &file)?;
        if !unchanged_file(&original, &file.metadata().map_err(storage)?) {
            return Err(PackageError::Ledger(
                "proof segment changed during read".into(),
            ));
        }
    }
    Ok(proofs)
}

fn proof_names(segments: &Directory) -> Result<Vec<String>, PackageError> {
    let mut result = Vec::new();
    for name in names(segments)? {
        let Some(ordinal) = name.strip_suffix(".log") else {
            continue;
        };
        if !hex_string(ordinal, 16) || ordinal == "ffffffffffffffff" {
            return Err(PackageError::Ledger(
                "segment ordinal outside supported bounds".into(),
            ));
        }
        result.push(name);
    }
    Ok(result)
}
fn unchanged_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same(before, after)
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (before, after);
        false
    }
}
