//! Bounded publication of checked inert recovery data. Source capture and
//! authority checks belong to the caller; this module never opens source data.

use crate::session_accounting::FullCostStatus;
use orbit_engine::retry::{DetailedAccountingCheckpoint, RefusalRollup};
use orbit_engine::{AccountingBaseline, AccountingKnownness};
use serde::{Serialize, ser::SerializeStruct};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 72;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_ARCHIVES: usize = 64;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;

/// Mandatory identity of the caller's held, preflight-approved output parent.
/// Capturing this value does not replace retaining that Directory guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryDestinationParent {
    device: u64,
    inode: u64,
    owner: u32,
}

impl RecoveryDestinationParent {
    #[cfg(target_os = "linux")]
    fn from_opened(metadata: &std::fs::Metadata) -> Result<Self, RecoveryPublishCode> {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir() {
            return Err(RecoveryPublishCode::UnsafeStorage);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }
    pub(crate) fn capture(
        directory: &crate::customization::Directory,
    ) -> Result<Self, RecoveryPublishCode> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            directory
                .check()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let metadata = std::fs::metadata(
                directory
                    .io()
                    .map_err(|_| RecoveryPublishCode::UnsafeStorage)?
                    .join("."),
            )
            .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
                || metadata.nlink() < 2
            {
                return Err(RecoveryPublishCode::UnsafeStorage);
            }
            directory
                .check()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            Self::from_opened(&metadata)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err(RecoveryPublishCode::UnsupportedPlatform)
        }
    }
}

/// Caller-provided facts from checked, owned root capture. No model, endpoint,
/// credential, grant or raw message belongs in this metadata.
pub(crate) struct RecoveryExportMetadata {
    pub owner_session_id: String,
    pub checkpoint_revision: u64,
    pub inspection_digest: String,
    pub baseline: AccountingBaseline,
    pub knownness: AccountingKnownness,
    pub pending_retained: bool,
    pub retained_refusal: Option<RetainedRefusalQualification>,
    pub saved_turns: u64,
    pub watermark_revision: Option<u64>,
    pub watermark_full_cost_status: Option<FullCostStatus>,
}

/// Bounded retained snapshot qualification. No live observation, ACK or replay
/// authority can be obtained from this private export/status metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedRefusalQualification {
    rollup: RefusalRollup,
}
impl RetainedRefusalQualification {
    pub(crate) fn from_checkpoint(
        checkpoint: &DetailedAccountingCheckpoint,
    ) -> Result<Option<Self>, RecoveryPublishCode> {
        checkpoint
            .validate()
            .map_err(|_| RecoveryPublishCode::InvalidInput)?;
        checkpoint
            .refusals()
            .map(|rollup| {
                let value = Self {
                    rollup: rollup.clone(),
                };
                value.validate_for(
                    checkpoint.owner_session_id(),
                    checkpoint.child_id(),
                    checkpoint.revision().0,
                    checkpoint.totals().knownness,
                )?;
                Ok(value)
            })
            .transpose()
    }
    fn validate_for(
        &self,
        owner: &str,
        child: Option<&str>,
        revision: u64,
        knownness: AccountingKnownness,
    ) -> Result<(), RecoveryPublishCode> {
        self.rollup
            .validate()
            .map_err(|_| RecoveryPublishCode::InvalidInput)?;
        let latest = self.rollup.latest();
        if latest.intent().owner_session_id != owner
            || latest.intent().child_id.as_deref() != child
            || latest.attempt().revision.0 >= revision
            || knownness == AccountingKnownness::Known
        {
            return Err(RecoveryPublishCode::InvalidInput);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| RecoveryPublishCode::InvalidInput)?;
        if bytes.len() > 2048 {
            return Err(RecoveryPublishCode::BoundsExceeded);
        }
        Ok(())
    }
    pub(crate) fn count(&self) -> u64 {
        self.rollup.count()
    }
    pub(crate) fn chain_digest(&self) -> &str {
        self.rollup.chain_digest()
    }
    pub(crate) fn settlement_digest(&self) -> &str {
        self.rollup.latest().digest()
    }
    pub(crate) fn policy_digest(&self) -> &str {
        self.rollup.latest().binding().policy_digest()
    }
    pub(crate) fn status(&self) -> u16 {
        self.rollup.latest().status()
    }
}
impl Serialize for RetainedRefusalQualification {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.rollup.validate().map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("RetainedRefusalQualification", 11)?;
        state.serialize_field("generation_final_refusal", &true)?;
        state.serialize_field("billing_unknown", &true)?;
        state.serialize_field("usage_unknown", &true)?;
        state.serialize_field("policy_assumption", &true)?;
        state.serialize_field("visible_validated", &true)?;
        state.serialize_field("count", &self.rollup.count())?;
        state.serialize_field("chain_digest", self.rollup.chain_digest())?;
        state.serialize_field("previous_chain_digest", self.rollup.previous_chain_digest())?;
        state.serialize_field("latest_settlement_digest", self.rollup.latest().digest())?;
        state.serialize_field(
            "policy_digest",
            self.rollup.latest().binding().policy_digest(),
        )?;
        state.serialize_field("status", &self.rollup.latest().status())?;
        state.end()
    }
}

/// These bytes must already have passed the source codec and ownership checks.
/// Member paths are generated here; callers cannot supply arbitrary paths.
pub(crate) enum RecoveryPayload {
    RootSnapshot(Vec<u8>),
    Accounting(Vec<u8>),
    Archive {
        record_id: String,
        source_digest: String,
        candidate_digest: String,
        bytes: Vec<u8>,
    },
    LegacyJsonl(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryPublishCode {
    InvalidInput,
    BoundsExceeded,
    InvalidDestination,
    ExistingTarget,
    ExistingStage,
    UnsafeStorage,
    WriteFailed,
    SyncFailed,
    PublicationUncertain,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}
impl RecoveryPublishCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_recovery_payload",
            Self::BoundsExceeded => "recovery_export_bound",
            Self::InvalidDestination => "invalid_recovery_destination",
            Self::ExistingTarget => "recovery_destination_exists",
            Self::ExistingStage => "recovery_stage_exists",
            Self::UnsafeStorage => "unsafe_recovery_destination",
            Self::WriteFailed => "recovery_write_failed",
            Self::SyncFailed => "recovery_sync_failed",
            Self::PublicationUncertain => "recovery_publication_uncertain",
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => "recovery_publication_requires_linux",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryArtifactIdentity {
    pub destination: PathBuf,
    /// Intended deterministic stage path; this does not claim ownership.
    pub intended_stage: PathBuf,
    pub owner_session_id: String,
    pub checkpoint_revision: u64,
    pub inspection_digest: String,
    /// Hash of the intended exact manifest, including for an incomplete stage.
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncompleteRecoveryStage {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    /// False means the original inode is no longer proved at this pathname.
    /// This evidence never authorizes removal of the path.
    pub still_named: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryPublishError {
    pub code: RecoveryPublishCode,
    pub artifact: Option<Box<RecoveryArtifactIdentity>>,
    /// Present only for a stage whose create-only reservation succeeded.
    pub stage: Option<IncompleteRecoveryStage>,
}
impl std::fmt::Display for RecoveryPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code.as_str())
    }
}
impl std::error::Error for RecoveryPublishError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishedRecoveryExport {
    pub artifact: RecoveryArtifactIdentity,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Serialize)]
struct ManifestFile {
    kind: &'static str,
    path: String,
    source_relative_path: String,
    bytes: u64,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application: Option<&'static str>,
}
#[derive(Serialize)]
struct Manifest<'a> {
    schema: &'static str,
    source: ManifestSource<'a>,
    capture: ManifestCapture<'a>,
    saved_history: ManifestSavedHistory,
    accounting: ManifestAccounting,
    legacy: ManifestLegacy,
    files: Vec<&'a ManifestFile>,
}
#[derive(Serialize)]
struct ManifestSource<'a> {
    owner_session_id: &'a str,
    child_id: Option<&'a str>,
}
#[derive(Serialize)]
struct ManifestCapture<'a> {
    checkpoint_revision: u64,
    inspection_digest: &'a str,
    qualification: &'static str,
    prior_publication_durability: &'static str,
    provider_outcome: &'static str,
}
#[derive(Serialize)]
struct ManifestSavedHistory {
    kind: &'static str,
    turns: u64,
    watermark_revision: Option<u64>,
    watermark_full_cost_status: Option<&'static str>,
    unsaved_partial: &'static str,
}
#[derive(Serialize)]
struct ManifestAccounting {
    container_scope: &'static str,
    selected_baseline: &'static str,
    selected_knownness: &'static str,
    pending_retained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_refusal: Option<RetainedRefusalQualification>,
}
#[derive(Serialize)]
struct ManifestLegacy {
    present: bool,
    reason: Option<&'static str>,
}

struct PreparedPayload {
    manifest: ManifestFile,
    bytes: Vec<u8>,
}
struct PreparedExport {
    artifact: RecoveryArtifactIdentity,
    payloads: Vec<PreparedPayload>,
    manifest: Vec<u8>,
    total_bytes: u64,
    stage_name: String,
}

fn digest_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn owner_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn record_ok(value: &str) -> bool {
    value.strip_prefix("compact-").is_some_and(|id| {
        id.len() == 26 && ulid::Ulid::from_string(id).is_ok_and(|parsed| parsed.to_string() == id)
    })
}
fn add_bytes(total: &mut u64, bytes: u64, maximum: u64) -> Result<(), RecoveryPublishCode> {
    *total = total
        .checked_add(bytes)
        .filter(|value| *value <= maximum)
        .ok_or(RecoveryPublishCode::BoundsExceeded)?;
    Ok(())
}
fn destination_ok(destination: &Path) -> bool {
    destination.is_absolute()
        && destination
            .file_name()
            .is_some_and(|name| name.len() <= 255)
        && destination
            .to_str()
            .is_some_and(|text| text.len() <= 4096 && !text.chars().any(char::is_control))
        && destination
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

struct ManifestEncoder {
    bytes: Vec<u8>,
    exceeded: bool,
}
impl Write for ManifestEncoder {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > MAX_MANIFEST_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("recovery manifest bound"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn manifest_bytes(value: &impl Serialize) -> Result<Vec<u8>, RecoveryPublishCode> {
    let mut writer = ManifestEncoder {
        bytes: Vec::new(),
        exceeded: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            RecoveryPublishCode::BoundsExceeded
        } else {
            RecoveryPublishCode::InvalidInput
        }
    })?;
    Ok(writer.bytes)
}

fn prepare(
    destination: &Path,
    metadata: RecoveryExportMetadata,
    payloads: Vec<RecoveryPayload>,
) -> Result<PreparedExport, RecoveryPublishCode> {
    if !destination_ok(destination) {
        return Err(RecoveryPublishCode::InvalidDestination);
    }
    if !owner_ok(&metadata.owner_session_id)
        || !digest_ok(&metadata.inspection_digest)
        || metadata.watermark_revision.is_some() != metadata.watermark_full_cost_status.is_some()
    {
        return Err(RecoveryPublishCode::InvalidInput);
    }
    if let Some(refusal) = &metadata.retained_refusal {
        if (metadata.knownness == AccountingKnownness::Uncertain && !metadata.pending_retained)
            || (metadata.baseline == AccountingBaseline::UnknownLegacy
                && !matches!(
                    metadata.knownness,
                    AccountingKnownness::UnknownLegacy | AccountingKnownness::Uncertain
                ))
        {
            return Err(RecoveryPublishCode::InvalidInput);
        }
        refusal.validate_for(
            &metadata.owner_session_id,
            None,
            metadata.checkpoint_revision,
            metadata.knownness,
        )?;
    }
    if payloads.len() >= MAX_FILES {
        return Err(RecoveryPublishCode::BoundsExceeded);
    }
    let mut prepared = Vec::new();
    let mut paths = BTreeSet::new();
    let mut total = 0;
    let (mut roots, mut accounting, mut legacy, mut archives, mut archive_bytes) = (0, 0, 0, 0, 0);
    for payload in payloads {
        let (kind, path, source, bytes, limit, record, source_digest, candidate_digest) =
            match payload {
                RecoveryPayload::RootSnapshot(bytes) => {
                    roots += 1;
                    (
                        "root_snapshot",
                        "snapshot/root.json".to_owned(),
                        format!("sessions/{}.json", metadata.owner_session_id),
                        bytes,
                        64 * 1024 * 1024,
                        None,
                        None,
                        None,
                    )
                }
                RecoveryPayload::Accounting(bytes) => {
                    accounting += 1;
                    (
                        "accounting",
                        "history/accounting.json".to_owned(),
                        format!(
                            "context-history/{}/accounting.json",
                            metadata.owner_session_id
                        ),
                        bytes,
                        128 * 1024,
                        None,
                        None,
                        None,
                    )
                }
                RecoveryPayload::LegacyJsonl(bytes) => {
                    legacy += 1;
                    (
                        "legacy_jsonl",
                        "history/legacy.jsonl".to_owned(),
                        format!("projects/{}.jsonl", metadata.owner_session_id),
                        bytes,
                        32 * 1024 * 1024,
                        None,
                        None,
                        None,
                    )
                }
                RecoveryPayload::Archive {
                    record_id,
                    source_digest,
                    candidate_digest,
                    bytes,
                } => {
                    if !record_ok(&record_id)
                        || !digest_ok(&source_digest)
                        || !digest_ok(&candidate_digest)
                    {
                        return Err(RecoveryPublishCode::InvalidInput);
                    }
                    archives += 1;
                    add_bytes(&mut archive_bytes, bytes.len() as u64, MAX_ARCHIVE_BYTES)?;
                    (
                        "archive",
                        format!("history/archives/{record_id}.json"),
                        format!(
                            "context-history/{}/archives/{record_id}.json",
                            metadata.owner_session_id
                        ),
                        bytes,
                        32 * 1024 * 1024,
                        Some(record_id),
                        Some(source_digest),
                        Some(candidate_digest),
                    )
                }
            };
        if bytes.len() > limit || archives > MAX_ARCHIVES {
            return Err(RecoveryPublishCode::BoundsExceeded);
        }
        if bytes.is_empty() && kind != "legacy_jsonl" {
            return Err(RecoveryPublishCode::InvalidInput);
        }
        if !paths.insert(path.clone()) {
            return Err(RecoveryPublishCode::InvalidInput);
        }
        add_bytes(&mut total, bytes.len() as u64, MAX_PACKAGE_BYTES)?;
        prepared.push(PreparedPayload {
            manifest: ManifestFile {
                kind,
                path,
                source_relative_path: source,
                bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
                record_id: record,
                source_digest,
                candidate_digest,
                application: (kind == "archive").then_some("not_established"),
            },
            bytes,
        });
    }
    if roots != 1 || accounting != 1 || legacy > 1 {
        return Err(RecoveryPublishCode::InvalidInput);
    }
    prepared.sort_by(|left, right| left.manifest.path.cmp(&right.manifest.path));
    let baseline = match metadata.baseline {
        AccountingBaseline::FreshKnownZero => "fresh_known_zero",
        AccountingBaseline::UnknownLegacy => "unknown_legacy",
    };
    let knownness = match metadata.knownness {
        AccountingKnownness::Known => "known",
        AccountingKnownness::UnknownLegacy => "unknown_legacy",
        AccountingKnownness::UnknownUsage => "unknown_usage",
        AccountingKnownness::Uncertain => "uncertain",
    };
    let watermark = metadata
        .watermark_full_cost_status
        .map(|status| match status {
            FullCostStatus::Known => "known",
            FullCostStatus::UnknownLegacy => "unknown_legacy",
            FullCostStatus::UnknownUsage => "unknown_usage",
            FullCostStatus::Uncertain => "uncertain",
            FullCostStatus::Unpriced => "unpriced",
        });
    let manifest = manifest_bytes(&Manifest {
        schema: "orbit.recovery-export/v1",
        source: ManifestSource {
            owner_session_id: &metadata.owner_session_id,
            child_id: None,
        },
        capture: ManifestCapture {
            checkpoint_revision: metadata.checkpoint_revision,
            inspection_digest: &metadata.inspection_digest,
            qualification: "visible_validated",
            prior_publication_durability: "not_established",
            provider_outcome: "not_established",
        },
        saved_history: ManifestSavedHistory {
            kind: "root",
            turns: metadata.saved_turns,
            watermark_revision: metadata.watermark_revision,
            watermark_full_cost_status: watermark,
            unsaved_partial: "unavailable",
        },
        accounting: ManifestAccounting {
            container_scope: "owner",
            selected_baseline: baseline,
            selected_knownness: knownness,
            pending_retained: metadata.pending_retained,
            retained_refusal: metadata.retained_refusal.clone(),
        },
        legacy: ManifestLegacy {
            present: legacy == 1,
            reason: (legacy == 0).then_some("not_present"),
        },
        files: prepared.iter().map(|payload| &payload.manifest).collect(),
    })?;
    add_bytes(&mut total, manifest.len() as u64, MAX_PACKAGE_BYTES)?;
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest));
    let leaf = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RecoveryPublishCode::InvalidDestination)?;
    let mut hash = Sha256::new();
    hash.update(b"orbit-recovery-stage-v1\0");
    for field in [leaf.as_bytes(), manifest_sha256.as_bytes()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    let stage_name = format!(".recovery-stage-{}", hex::encode(hash.finalize()));
    let intended_stage = destination
        .parent()
        .ok_or(RecoveryPublishCode::InvalidDestination)?
        .join(&stage_name);
    Ok(PreparedExport {
        artifact: RecoveryArtifactIdentity {
            destination: destination.to_owned(),
            intended_stage,
            owner_session_id: metadata.owner_session_id,
            checkpoint_revision: metadata.checkpoint_revision,
            inspection_digest: metadata.inspection_digest,
            manifest_sha256,
        },
        payloads: prepared,
        manifest,
        total_bytes: total,
        stage_name,
    })
}

#[cfg(target_os = "linux")]
mod filesystem {
    use super::*;
    use crate::customization::Directory;
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, RenameFlags, Stat, fstat, mkdirat, openat, renameat_with,
        statat,
    };
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
    }
    fn identity(stat: &Stat) -> Identity {
        Identity {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
    fn directory_stat(stat: &Stat) -> Result<Identity, RecoveryPublishCode> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o700
            || stat.st_nlink < 2
        {
            return Err(RecoveryPublishCode::UnsafeStorage);
        }
        Ok(identity(stat))
    }
    fn file_stat(stat: &Stat, size: u64) -> Result<(), RecoveryPublishCode> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size < 0
            || stat.st_size as u64 != size
        {
            return Err(RecoveryPublishCode::UnsafeStorage);
        }
        Ok(())
    }
    fn same_file(left: &Stat, right: &Stat) -> bool {
        identity(left) == identity(right)
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }
    struct Parent {
        checked: Directory,
        file: File,
        identity: Identity,
    }
    impl Parent {
        fn open(
            path: &Path,
            expected: &RecoveryDestinationParent,
        ) -> Result<Self, RecoveryPublishCode> {
            let checked =
                Directory::open(path, true).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let io = checked
                .io()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?
                .join(".");
            let file = File::from(
                openat(
                    rustix::fs::CWD,
                    &io,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?,
            );
            let stat = fstat(&file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let identity = directory_stat(&stat)?;
            if identity.device != expected.device
                || identity.inode != expected.inode
                || stat.st_uid != expected.owner
            {
                return Err(RecoveryPublishCode::UnsafeStorage);
            }
            let result = Self {
                checked,
                file,
                identity,
            };
            result.check()?;
            Ok(result)
        }
        fn check(&self) -> Result<(), RecoveryPublishCode> {
            self.checked
                .check()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            Directory::open(self.checked.path(), true)
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let named = statat(
                rustix::fs::CWD,
                self.checked.path(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let held = fstat(&self.file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            if directory_stat(&named)? != self.identity || directory_stat(&held)? != self.identity {
                return Err(RecoveryPublishCode::UnsafeStorage);
            }
            self.checked
                .check()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)
        }
        fn absent(&self, name: &std::ffi::OsStr) -> Result<(), RecoveryPublishCode> {
            self.check()?;
            match statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => self.check(),
                Ok(_) => Err(RecoveryPublishCode::ExistingTarget),
                Err(_) => Err(RecoveryPublishCode::UnsafeStorage),
            }
        }
    }
    struct Node {
        file: File,
        identity: Identity,
    }
    impl Node {
        fn create(parent: &File, name: &str) -> Result<Self, RecoveryPublishCode> {
            mkdirat(parent, name, Mode::RWXU).map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    RecoveryPublishCode::ExistingStage
                } else {
                    RecoveryPublishCode::WriteFailed
                }
            })?;
            let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let expected = directory_stat(&named)?;
            let file = File::from(
                openat(
                    parent,
                    name,
                    OFlags::RDONLY
                        | OFlags::DIRECTORY
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?,
            );
            let result = Self {
                file,
                identity: expected,
            };
            result.check(parent, name)?;
            Ok(result)
        }
        fn check(&self, parent: &File, name: &str) -> Result<(), RecoveryPublishCode> {
            let held = fstat(&self.file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            if directory_stat(&held)? != self.identity || directory_stat(&named)? != self.identity {
                return Err(RecoveryPublishCode::UnsafeStorage);
            }
            Ok(())
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Slot {
        Root = 0,
        Snapshot = 1,
        History = 2,
        Archives = 3,
    }
    struct Written {
        slot: Slot,
        name: String,
        stat: Stat,
        size: u64,
        sha256: String,
    }
    struct Stage {
        name: String,
        nodes: Vec<Node>,
        written: Vec<Written>,
        written_bytes: u64,
        published: bool,
    }
    impl Stage {
        fn root(&self) -> &Node {
            &self.nodes[0]
        }
        fn reserve(parent: &Parent, name: &str) -> Result<Self, RecoveryPublishCode> {
            parent.check()?;
            let root = Node::create(&parent.file, name)?;
            parent.check()?;
            Ok(Self {
                name: name.to_owned(),
                nodes: vec![root],
                written: Vec::new(),
                written_bytes: 0,
                published: false,
            })
        }
        fn node(&self, slot: Slot) -> &Node {
            &self.nodes[slot as usize]
        }
        fn initialize(&mut self, parent: &Parent) -> Result<(), RecoveryPublishCode> {
            self.root().check(&parent.file, &self.name)?;
            self.nodes
                .push(Node::create(&self.root().file, "snapshot")?);
            self.nodes.push(Node::create(&self.root().file, "history")?);
            self.nodes
                .push(Node::create(&self.node(Slot::History).file, "archives")?);
            self.check(parent, &self.name)
        }
        fn check(&self, parent: &Parent, root_name: &str) -> Result<(), RecoveryPublishCode> {
            parent.check()?;
            self.root().check(&parent.file, root_name)?;
            self.node(Slot::Snapshot)
                .check(&self.root().file, "snapshot")?;
            self.node(Slot::History)
                .check(&self.root().file, "history")?;
            self.node(Slot::Archives)
                .check(&self.node(Slot::History).file, "archives")?;
            parent.check()
        }
        fn evidence(&self, parent: &Parent, path: &Path) -> IncompleteRecoveryStage {
            let still_named =
                parent.check().is_ok() && self.root().check(&parent.file, &self.name).is_ok();
            IncompleteRecoveryStage {
                path: path.to_owned(),
                device: self.root().identity.device,
                inode: self.root().identity.inode,
                still_named,
            }
        }
        fn write(
            &mut self,
            parent: &Parent,
            slot: Slot,
            name: &str,
            bytes: &[u8],
            sha256: &str,
        ) -> Result<(), RecoveryPublishCode> {
            if self.written.len() >= MAX_FILES {
                return Err(RecoveryPublishCode::BoundsExceeded);
            }
            let mut written_bytes = self.written_bytes;
            add_bytes(&mut written_bytes, bytes.len() as u64, MAX_PACKAGE_BYTES)?;
            self.check(parent, &self.name)?;
            let mut file = File::from(
                openat(
                    &self.node(slot).file,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|_| RecoveryPublishCode::WriteFailed)?,
            );
            file_stat(
                &fstat(&file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?,
                0,
            )?;
            file.write_all(bytes)
                .map_err(|_| RecoveryPublishCode::WriteFailed)?;
            file.sync_all()
                .map_err(|_| RecoveryPublishCode::SyncFailed)?;
            let stat = fstat(&file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            file_stat(&stat, bytes.len() as u64)?;
            let named = statat(&self.node(slot).file, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
            if !same_file(&stat, &named) {
                return Err(RecoveryPublishCode::UnsafeStorage);
            }
            self.written.push(Written {
                slot,
                name: name.to_owned(),
                stat,
                size: bytes.len() as u64,
                sha256: sha256.to_owned(),
            });
            self.written_bytes = written_bytes;
            self.check(parent, &self.name)
        }
        fn verify(
            &self,
            parent: &Parent,
            root_name: &str,
            hash_all: bool,
        ) -> Result<(), RecoveryPublishCode> {
            self.check(parent, root_name)?;
            for slot in [Slot::Root, Slot::Snapshot, Slot::History, Slot::Archives] {
                let mut expected: BTreeSet<String> = self
                    .written
                    .iter()
                    .filter(|file| file.slot == slot)
                    .map(|file| file.name.clone())
                    .collect();
                match slot {
                    Slot::Root => {
                        expected.insert("snapshot".into());
                        expected.insert("history".into());
                    }
                    Slot::History => {
                        expected.insert("archives".into());
                    }
                    _ => {}
                }
                let path = PathBuf::from(format!(
                    "/proc/self/fd/{}",
                    self.node(slot).file.as_raw_fd()
                ));
                let mut actual = BTreeSet::new();
                for item in
                    std::fs::read_dir(path).map_err(|_| RecoveryPublishCode::UnsafeStorage)?
                {
                    if actual.len() >= MAX_FILES + 3 {
                        return Err(RecoveryPublishCode::BoundsExceeded);
                    }
                    let item = item.map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                    let name = item
                        .file_name()
                        .into_string()
                        .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                    if !actual.insert(name) {
                        return Err(RecoveryPublishCode::UnsafeStorage);
                    }
                }
                if actual != expected {
                    return Err(RecoveryPublishCode::UnsafeStorage);
                }
            }
            for record in &self.written {
                let mut file = File::from(
                    openat(
                        &self.node(record.slot).file,
                        record.name.as_str(),
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| RecoveryPublishCode::UnsafeStorage)?,
                );
                let before = fstat(&file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                file_stat(&before, record.size)?;
                if !same_file(&record.stat, &before) {
                    return Err(RecoveryPublishCode::UnsafeStorage);
                }
                if hash_all || record.name == "manifest.json" {
                    let mut hashed = Sha256::new();
                    let mut count = 0;
                    let mut buffer = [0u8; 64 * 1024];
                    loop {
                        let remaining = record.size.saturating_sub(count);
                        let bound = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
                        let size = file
                            .read(&mut buffer[..bound])
                            .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                        if size == 0 {
                            break;
                        }
                        add_bytes(&mut count, size as u64, record.size)?;
                        hashed.update(&buffer[..size]);
                    }
                    if count != record.size || hex::encode(hashed.finalize()) != record.sha256 {
                        return Err(RecoveryPublishCode::UnsafeStorage);
                    }
                }
                let after = fstat(&file).map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                let named = statat(
                    &self.node(record.slot).file,
                    record.name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
                if !same_file(&before, &after) || !same_file(&after, &named) {
                    return Err(RecoveryPublishCode::UnsafeStorage);
                }
            }
            self.check(parent, root_name)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Point {
        StageCreated,
        BeforeRename,
        AfterRename,
    }
    fn failure(
        prepared: &PreparedExport,
        parent: &Parent,
        stage: Option<&Stage>,
        code: RecoveryPublishCode,
    ) -> RecoveryPublishError {
        RecoveryPublishError {
            code,
            artifact: Some(Box::new(prepared.artifact.clone())),
            stage: stage
                .filter(|stage| !stage.published)
                .map(|stage| stage.evidence(parent, &prepared.artifact.intended_stage)),
        }
    }
    pub(super) fn publish(
        prepared: PreparedExport,
        expected_parent: &RecoveryDestinationParent,
        hook: &mut impl FnMut(Point, &Path, &Path) -> Result<(), RecoveryPublishCode>,
    ) -> Result<PublishedRecoveryExport, RecoveryPublishError> {
        let parent_path = prepared
            .artifact
            .destination
            .parent()
            .expect("validated destination parent");
        let leaf = prepared
            .artifact
            .destination
            .file_name()
            .expect("validated destination leaf");
        let leaf_text = leaf.to_str().expect("validated UTF-8 destination leaf");
        let parent =
            Parent::open(parent_path, expected_parent).map_err(|code| RecoveryPublishError {
                code,
                artifact: Some(Box::new(prepared.artifact.clone())),
                stage: None,
            })?;
        parent
            .absent(leaf)
            .map_err(|code| failure(&prepared, &parent, None, code))?;
        let mut stage = Stage::reserve(&parent, &prepared.stage_name)
            .map_err(|code| failure(&prepared, &parent, None, code))?;
        let result = (|| {
            stage.initialize(&parent)?;
            hook(
                Point::StageCreated,
                &prepared.artifact.destination,
                &prepared.artifact.intended_stage,
            )?;
            for payload in &prepared.payloads {
                let (slot, name) = match payload.manifest.kind {
                    "root_snapshot" => (Slot::Snapshot, "root.json".to_owned()),
                    "accounting" => (Slot::History, "accounting.json".to_owned()),
                    "legacy_jsonl" => (Slot::History, "legacy.jsonl".to_owned()),
                    "archive" => (
                        Slot::Archives,
                        format!(
                            "{}.json",
                            payload
                                .manifest
                                .record_id
                                .as_deref()
                                .ok_or(RecoveryPublishCode::InvalidInput)?
                        ),
                    ),
                    _ => return Err(RecoveryPublishCode::InvalidInput),
                };
                stage.write(
                    &parent,
                    slot,
                    &name,
                    &payload.bytes,
                    &payload.manifest.sha256,
                )?;
            }
            stage.write(
                &parent,
                Slot::Root,
                "manifest.json",
                &prepared.manifest,
                &prepared.artifact.manifest_sha256,
            )?;
            for slot in [Slot::Archives, Slot::History, Slot::Snapshot, Slot::Root] {
                stage
                    .node(slot)
                    .file
                    .sync_all()
                    .map_err(|_| RecoveryPublishCode::SyncFailed)?;
            }
            hook(
                Point::BeforeRename,
                &prepared.artifact.destination,
                &prepared.artifact.intended_stage,
            )?;
            stage.verify(&parent, &stage.name, true)?;
            renameat_with(
                &parent.file,
                stage.name.as_str(),
                &parent.file,
                leaf,
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    RecoveryPublishCode::ExistingTarget
                } else {
                    RecoveryPublishCode::PublicationUncertain
                }
            })?;
            stage.published = true;
            hook(
                Point::AfterRename,
                &prepared.artifact.destination,
                &prepared.artifact.intended_stage,
            )
            .map_err(|_| RecoveryPublishCode::PublicationUncertain)?;
            stage
                .verify(&parent, leaf_text, false)
                .map_err(|_| RecoveryPublishCode::PublicationUncertain)?;
            parent
                .file
                .sync_all()
                .map_err(|_| RecoveryPublishCode::PublicationUncertain)?;
            parent
                .check()
                .map_err(|_| RecoveryPublishCode::PublicationUncertain)?;
            stage
                .check(&parent, leaf_text)
                .map_err(|_| RecoveryPublishCode::PublicationUncertain)?;
            if !matches!(
                statat(&parent.file, stage.name.as_str(), AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            ) {
                return Err(RecoveryPublishCode::PublicationUncertain);
            }
            Ok(())
        })();
        result.map_err(|code| failure(&prepared, &parent, Some(&stage), code))?;
        Ok(PublishedRecoveryExport {
            artifact: prepared.artifact,
            files: prepared.payloads.len() + 1,
            bytes: prepared.total_bytes,
        })
    }
}

/// Publish a complete checked root package. Failures never remove a final or
/// staged path, retry, select another target or mutate any source. An identical
/// failed intent reserves the same bounded stage name and cannot accumulate
/// new stages. Existing stages are never adopted as owned or complete.
/// The caller must pass its original held preflight parent's binding and retain
/// that Directory guard through this call; reopening a path is not authority.
pub(crate) fn publish_recovery_export(
    destination: &Path,
    expected_parent: &RecoveryDestinationParent,
    metadata: RecoveryExportMetadata,
    payloads: Vec<RecoveryPayload>,
) -> Result<PublishedRecoveryExport, RecoveryPublishError> {
    let prepared =
        prepare(destination, metadata, payloads).map_err(|code| RecoveryPublishError {
            code,
            artifact: None,
            stage: None,
        })?;
    #[cfg(target_os = "linux")]
    {
        filesystem::publish(prepared, expected_parent, &mut |_, _, _| Ok(()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(RecoveryPublishError {
            code: RecoveryPublishCode::UnsupportedPlatform,
            artifact: Some(Box::new(prepared.artifact)),
            stage: None,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

    // Preserve the existing fixture/control bodies while every actual publisher
    // entry now requires a real captured parent identity. No synthetic/default
    // identity or unbound production entry point exists.
    fn fixture_parent(
        destination: &Path,
    ) -> Result<(std::fs::File, RecoveryDestinationParent), RecoveryPublishCode> {
        if !destination_ok(destination) {
            return Err(RecoveryPublishCode::InvalidDestination);
        }
        // Inspect the real parent through an actual held file, including the
        // deliberately public/symlink fixtures. The actual publisher must still
        // reject their original paths/modes; the adapter never bypasses it.
        let directory = std::fs::File::open(
            destination
                .parent()
                .ok_or(RecoveryPublishCode::InvalidDestination)?,
        )
        .map_err(|_| RecoveryPublishCode::UnsafeStorage)?;
        let binding = RecoveryDestinationParent::from_opened(
            &directory
                .metadata()
                .map_err(|_| RecoveryPublishCode::UnsafeStorage)?,
        )?;
        Ok((directory, binding))
    }
    fn publish_recovery_export(
        destination: &Path,
        metadata: RecoveryExportMetadata,
        payloads: Vec<RecoveryPayload>,
    ) -> Result<PublishedRecoveryExport, RecoveryPublishError> {
        let (_directory, binding) =
            fixture_parent(destination).map_err(|code| RecoveryPublishError {
                code,
                artifact: None,
                stage: None,
            })?;
        super::publish_recovery_export(destination, &binding, metadata, payloads)
    }
    mod filesystem {
        pub(super) use super::super::filesystem::Point;
        use super::*;
        pub(super) fn publish(
            prepared: PreparedExport,
            hook: &mut impl FnMut(Point, &Path, &Path) -> Result<(), RecoveryPublishCode>,
        ) -> Result<PublishedRecoveryExport, RecoveryPublishError> {
            let (_directory, binding) =
                fixture_parent(&prepared.artifact.destination).map_err(|code| {
                    RecoveryPublishError {
                        code,
                        artifact: Some(Box::new(prepared.artifact.clone())),
                        stage: None,
                    }
                })?;
            super::super::filesystem::publish(prepared, &binding, hook)
        }
    }

    struct Tree {
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("orbit-recovery-publisher-{}", ulid::Ulid::new()));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            Self {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        fn target(&self) -> PathBuf {
            self.path.join("export")
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode
            }) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
    fn metadata() -> RecoveryExportMetadata {
        RecoveryExportMetadata {
            owner_session_id: "recovery-root".into(),
            checkpoint_revision: 7,
            inspection_digest: "a".repeat(64),
            baseline: AccountingBaseline::UnknownLegacy,
            knownness: AccountingKnownness::Uncertain,
            pending_retained: true,
            retained_refusal: None,
            saved_turns: 3,
            watermark_revision: Some(5),
            watermark_full_cost_status: Some(FullCostStatus::UnknownUsage),
        }
    }
    fn payloads() -> Vec<RecoveryPayload> {
        vec![
            RecoveryPayload::RootSnapshot(b"checked-snapshot-private-endpoint".to_vec()),
            RecoveryPayload::Accounting(b"checked-accounting-private-receipts".to_vec()),
        ]
    }
    fn archive(id: u128) -> RecoveryPayload {
        RecoveryPayload::Archive {
            record_id: format!("compact-{}", ulid::Ulid::from(id)),
            source_digest: "b".repeat(64),
            candidate_digest: "c".repeat(64),
            bytes: b"checked-original-archive".to_vec(),
        }
    }
    fn code(result: Result<PreparedExport, RecoveryPublishCode>) -> RecoveryPublishCode {
        result.err().expect("preparation must refuse")
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn publishes_exact_private_bytes_with_bounded_truthful_manifest() {
        let tree = Tree::new();
        let target = tree.target();
        let mut inputs = payloads();
        inputs.push(archive(1));
        inputs.push(RecoveryPayload::LegacyJsonl(b"raw\nlegacy\0bytes".to_vec()));
        let expected = prepare(&target, metadata(), inputs).unwrap();
        let manifest = expected.manifest.clone();
        let expected_bytes = expected.total_bytes;
        let body: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(body["source"]["owner_session_id"], "recovery-root");
        assert!(body["source"]["child_id"].is_null());
        assert_eq!(body["capture"]["qualification"], "visible_validated");
        assert_eq!(
            body["capture"]["prior_publication_durability"],
            "not_established"
        );
        assert_eq!(body["capture"]["provider_outcome"], "not_established");
        assert_eq!(body["saved_history"]["unsaved_partial"], "unavailable");
        assert_eq!(body["saved_history"]["watermark_revision"], 5);
        assert_eq!(body["accounting"]["selected_knownness"], "uncertain");
        assert_eq!(body["accounting"]["pending_retained"], true);
        let text = std::str::from_utf8(&manifest).unwrap();
        for private in [
            "private-endpoint",
            "private-receipts",
            "checked-original-archive",
            "raw\\nlegacy",
        ] {
            assert!(!text.contains(private));
        }
        let mut inputs = payloads();
        inputs.push(archive(1));
        inputs.push(RecoveryPayload::LegacyJsonl(b"raw\nlegacy\0bytes".to_vec()));
        let result = publish_recovery_export(&target, metadata(), inputs).unwrap();
        assert_eq!(result.files, 5);
        assert_eq!(result.bytes, expected_bytes);
        assert_eq!(
            result.artifact.manifest_sha256,
            hex::encode(Sha256::digest(&manifest))
        );
        assert_eq!(fs::read(target.join("manifest.json")).unwrap(), manifest);
        let manifest_stat = fs::symlink_metadata(target.join("manifest.json")).unwrap();
        assert_eq!(manifest_stat.mode() & 0o7777, 0o600);
        assert_eq!(manifest_stat.nlink(), 1);
        for payload in expected.payloads {
            let path = target.join(payload.manifest.path);
            assert_eq!(fs::read(&path).unwrap(), payload.bytes);
            let stat = fs::symlink_metadata(path).unwrap();
            assert!(stat.is_file());
            assert_eq!(stat.mode() & 0o7777, 0o600);
            assert_eq!(stat.nlink(), 1);
        }
        for name in ["", "snapshot", "history", "history/archives"] {
            let stat = fs::symlink_metadata(target.join(name)).unwrap();
            assert!(stat.is_dir());
            assert_eq!(stat.mode() & 0o7777, 0o700);
        }
        assert!(!result.artifact.intended_stage.exists());
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
    }

    #[test]
    fn manifest_is_deterministic_and_preserves_independent_watermark_facts() {
        let tree = Tree::new();
        let mut left = payloads();
        left.push(archive(2));
        left.push(archive(1));
        let mut right = payloads();
        right.push(archive(1));
        right.push(archive(2));
        right.reverse();
        let mut facts = metadata();
        facts.pending_retained = false;
        facts.watermark_revision = Some(9);
        let left = prepare(&tree.target(), facts, left).unwrap();
        let mut facts = metadata();
        facts.pending_retained = false;
        facts.watermark_revision = Some(9);
        let right = prepare(&tree.target(), facts, right).unwrap();
        assert_eq!(left.manifest, right.manifest);
        assert_eq!(left.stage_name, right.stage_name);
        let body: serde_json::Value = serde_json::from_slice(&left.manifest).unwrap();
        assert_eq!(body["capture"]["checkpoint_revision"], 7);
        assert_eq!(body["saved_history"]["watermark_revision"], 9);
        assert_eq!(body["accounting"]["pending_retained"], false);
        assert_eq!(body["files"][1]["application"], "not_established");
    }

    #[test]
    fn invalid_metadata_paths_and_payload_roles_refuse_before_creating_output() {
        let tree = Tree::new();
        let target = tree.target();
        let mut facts = metadata();
        facts.owner_session_id = "../escape".into();
        assert_eq!(
            code(prepare(&target, facts, payloads())),
            RecoveryPublishCode::InvalidInput
        );
        let mut facts = metadata();
        facts.inspection_digest = "A".repeat(64);
        assert_eq!(
            code(prepare(&target, facts, payloads())),
            RecoveryPublishCode::InvalidInput
        );
        let mut facts = metadata();
        facts.watermark_revision = None;
        assert_eq!(
            code(prepare(&target, facts, payloads())),
            RecoveryPublishCode::InvalidInput
        );
        for path in [
            PathBuf::from("relative/export"),
            tree.path.join("../export"),
            tree.path.join("bad\nname"),
        ] {
            assert_eq!(
                code(prepare(&path, metadata(), payloads())),
                RecoveryPublishCode::InvalidDestination
            );
        }
        assert_eq!(
            code(prepare(
                &target,
                metadata(),
                vec![RecoveryPayload::RootSnapshot(vec![1])]
            )),
            RecoveryPublishCode::InvalidInput
        );
        let mut inputs = payloads();
        inputs.push(RecoveryPayload::Accounting(vec![1]));
        assert_eq!(
            code(prepare(&target, metadata(), inputs)),
            RecoveryPublishCode::InvalidInput
        );
        let mut inputs = payloads();
        inputs.push(RecoveryPayload::Archive {
            record_id: "../escape".into(),
            source_digest: "b".repeat(64),
            candidate_digest: "c".repeat(64),
            bytes: vec![1],
        });
        assert_eq!(
            code(prepare(&target, metadata(), inputs)),
            RecoveryPublishCode::InvalidInput
        );
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 0);
    }

    #[test]
    fn per_file_count_manifest_and_checked_aggregate_bounds_are_exact() {
        let tree = Tree::new();
        let target = tree.target();
        let inputs = vec![
            RecoveryPayload::RootSnapshot(vec![1]),
            RecoveryPayload::Accounting(vec![1; 128 * 1024]),
        ];
        assert!(prepare(&target, metadata(), inputs).is_ok());
        let inputs = vec![
            RecoveryPayload::RootSnapshot(vec![1]),
            RecoveryPayload::Accounting(vec![1; 128 * 1024 + 1]),
        ];
        assert_eq!(
            code(prepare(&target, metadata(), inputs)),
            RecoveryPublishCode::BoundsExceeded
        );
        let inputs = (0..MAX_FILES)
            .map(|_| RecoveryPayload::RootSnapshot(vec![1]))
            .collect();
        assert_eq!(
            code(prepare(&target, metadata(), inputs)),
            RecoveryPublishCode::BoundsExceeded
        );
        let mut inputs = payloads();
        inputs.extend((0..64).map(archive));
        assert!(prepare(&target, metadata(), inputs).is_ok());
        let mut inputs = payloads();
        inputs.extend((0..65).map(archive));
        assert_eq!(
            code(prepare(&target, metadata(), inputs)),
            RecoveryPublishCode::BoundsExceeded
        );
        let mut total = MAX_PACKAGE_BYTES - 1;
        assert!(add_bytes(&mut total, 1, MAX_PACKAGE_BYTES).is_ok());
        assert_eq!(
            add_bytes(&mut total, 1, MAX_PACKAGE_BYTES),
            Err(RecoveryPublishCode::BoundsExceeded)
        );
        assert_eq!(total, MAX_PACKAGE_BYTES);
        let mut overflow = u64::MAX;
        assert_eq!(
            add_bytes(&mut overflow, 1, u64::MAX),
            Err(RecoveryPublishCode::BoundsExceeded)
        );
        assert_eq!(overflow, u64::MAX);
        let mut encoder = ManifestEncoder {
            bytes: Vec::new(),
            exceeded: false,
        };
        assert_eq!(
            encoder.write(&vec![0; MAX_MANIFEST_BYTES]).unwrap(),
            MAX_MANIFEST_BYTES
        );
        assert!(encoder.write(&[0]).is_err());
        assert!(encoder.exceeded);
        assert_eq!(encoder.bytes.len(), MAX_MANIFEST_BYTES);
        assert_eq!(
            manifest_bytes(&"x".repeat(MAX_MANIFEST_BYTES)),
            Err(RecoveryPublishCode::BoundsExceeded)
        );
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 0);
    }

    #[test]
    fn maximum_length_target_has_fixed_length_stage_bound_to_intent() {
        let tree = Tree::new();
        let first = tree.path.join("x".repeat(255));
        let prepared = prepare(&first, metadata(), payloads()).unwrap();
        assert_eq!(prepared.stage_name.len(), 80);
        let repeat = prepare(&first, metadata(), payloads()).unwrap();
        assert_eq!(prepared.stage_name, repeat.stage_name);
        let other = prepare(&tree.path.join("y".repeat(255)), metadata(), payloads()).unwrap();
        assert_ne!(prepared.stage_name, other.stage_name);
        let mut facts = metadata();
        facts.checkpoint_revision += 1;
        let revised = prepare(&first, facts, payloads()).unwrap();
        assert_ne!(prepared.stage_name, revised.stage_name);
        let result = publish_recovery_export(&first, metadata(), payloads()).unwrap();
        assert_eq!(result.artifact.destination, first);
        assert!(!result.artifact.intended_stage.exists());
    }

    #[test]
    fn existing_directory_file_and_dangling_target_are_never_adopted() {
        for kind in 0..3 {
            let tree = Tree::new();
            let target = tree.target();
            match kind {
                0 => DirBuilder::new().mode(0o700).create(&target).unwrap(),
                1 => private_file(&target, b"untouched"),
                _ => symlink("absent-destination", &target).unwrap(),
            }
            let before = fs::symlink_metadata(&target).unwrap();
            let failure = publish_recovery_export(&target, metadata(), payloads()).unwrap_err();
            assert_eq!(failure.code, RecoveryPublishCode::ExistingTarget);
            assert!(failure.stage.is_none());
            let after = fs::symlink_metadata(&target).unwrap();
            assert_eq!(
                (before.dev(), before.ino(), before.mode(), before.len()),
                (after.dev(), after.ino(), after.mode(), after.len())
            );
            if kind == 1 {
                assert_eq!(fs::read(&target).unwrap(), b"untouched");
            }
            if kind == 2 {
                assert_eq!(
                    fs::read_link(&target).unwrap(),
                    PathBuf::from("absent-destination")
                );
            }
            assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
        }
    }

    #[test]
    fn preexisting_stage_is_unowned_and_never_reused_or_removed() {
        let tree = Tree::new();
        let target = tree.target();
        let prepared = prepare(&target, metadata(), payloads()).unwrap();
        DirBuilder::new()
            .mode(0o700)
            .create(&prepared.artifact.intended_stage)
            .unwrap();
        let sentinel = prepared.artifact.intended_stage.join("sentinel");
        private_file(&sentinel, b"unowned");
        let failure = publish_recovery_export(&target, metadata(), payloads()).unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::ExistingStage);
        assert!(failure.stage.is_none());
        assert!(!target.exists());
        assert_eq!(fs::read(sentinel).unwrap(), b"unowned");
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
    }

    #[test]
    fn write_failure_retains_exact_incomplete_stage_and_repeat_cannot_accumulate() {
        let tree = Tree::new();
        let target = tree.target();
        let prepared = prepare(&target, metadata(), payloads()).unwrap();
        let expected = prepared.artifact.clone();
        let failure = filesystem::publish(prepared, &mut |point, _, _| {
            if point == filesystem::Point::StageCreated {
                Err(RecoveryPublishCode::WriteFailed)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::WriteFailed);
        assert_eq!(failure.artifact.as_deref(), Some(&expected));
        let stage = failure.stage.as_ref().unwrap();
        assert!(stage.still_named);
        assert_eq!(stage.path, expected.intended_stage);
        let named = fs::symlink_metadata(&stage.path).unwrap();
        assert_eq!((stage.device, stage.inode), (named.dev(), named.ino()));
        assert!(!stage.path.join("manifest.json").exists());
        assert!(!target.exists());
        assert_eq!(failure.to_string(), "recovery_write_failed");
        let repeat = publish_recovery_export(&target, metadata(), payloads()).unwrap_err();
        assert_eq!(repeat.code, RecoveryPublishCode::ExistingStage);
        assert!(repeat.stage.is_none());
        assert_eq!(repeat.artifact, Some(Box::new(expected)));
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
    }

    #[test]
    fn no_replace_rename_preserves_target_created_after_preflight() {
        let tree = Tree::new();
        let target = tree.target();
        let prepared = prepare(&target, metadata(), payloads()).unwrap();
        let expected = prepared.artifact.clone();
        let failure = filesystem::publish(prepared, &mut |point, target, _| {
            if point == filesystem::Point::BeforeRename {
                private_file(target, b"racing-target");
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::ExistingTarget);
        assert!(failure.stage.as_ref().unwrap().still_named);
        assert_eq!(fs::read(&target).unwrap(), b"racing-target");
        assert_eq!(
            hex::encode(Sha256::digest(
                fs::read(expected.intended_stage.join("manifest.json")).unwrap()
            )),
            expected.manifest_sha256
        );
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 2);
    }

    #[test]
    fn post_rename_failure_reports_same_artifact_without_deletion_or_retry() {
        let tree = Tree::new();
        let target = tree.target();
        let prepared = prepare(&target, metadata(), payloads()).unwrap();
        let expected = prepared.artifact.clone();
        let manifest = prepared.manifest.clone();
        let failure = filesystem::publish(prepared, &mut |point, _, _| {
            if point == filesystem::Point::AfterRename {
                Err(RecoveryPublishCode::SyncFailed)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::PublicationUncertain);
        assert_eq!(failure.artifact.as_deref(), Some(&expected));
        assert!(failure.stage.is_none());
        assert_eq!(fs::read(target.join("manifest.json")).unwrap(), manifest);
        assert!(!expected.intended_stage.exists());
        let repeat = publish_recovery_export(&target, metadata(), payloads()).unwrap_err();
        assert_eq!(repeat.code, RecoveryPublishCode::ExistingTarget);
        assert_eq!(repeat.artifact, Some(Box::new(expected)));
        assert!(repeat.stage.is_none());
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
    }

    #[test]
    fn stage_payload_tampering_and_unexpected_members_block_publication() {
        for extra in [false, true] {
            let tree = Tree::new();
            let target = tree.target();
            let prepared = prepare(&target, metadata(), payloads()).unwrap();
            let failure = filesystem::publish(prepared, &mut |point, _, stage| {
                if point == filesystem::Point::BeforeRename {
                    if extra {
                        private_file(&stage.join("unexpected"), b"not-a-package-member");
                    } else {
                        let path = stage.join("snapshot/root.json");
                        let mut bytes = fs::read(&path).unwrap();
                        bytes[0] ^= 1;
                        fs::write(path, bytes).unwrap();
                    }
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(failure.code, RecoveryPublishCode::UnsafeStorage);
            assert!(failure.stage.as_ref().unwrap().still_named);
            assert!(!target.exists());
            assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 1);
        }
    }

    #[test]
    fn stage_symlink_swap_and_parent_replacement_never_redirect_output() {
        let tree = Tree::new();
        let parent = tree.path.join("parent");
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let outside = tree.path.join("outside");
        DirBuilder::new().mode(0o700).create(&outside).unwrap();
        private_file(&outside.join("sentinel"), b"untouched");
        let target = parent.join("export");
        let prepared = prepare(&target, metadata(), payloads()).unwrap();
        let failure = filesystem::publish(prepared, &mut |point, _, stage| {
            if point == filesystem::Point::BeforeRename {
                fs::rename(stage.join("snapshot"), stage.join("displaced-snapshot")).unwrap();
                symlink(&outside, stage.join("snapshot")).unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::UnsafeStorage);
        assert!(!target.exists());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"untouched");
        let second = parent.join("second");
        let prepared = prepare(&second, metadata(), payloads()).unwrap();
        let old_parent = tree.path.join("old-parent");
        let failure = filesystem::publish(prepared, &mut |point, _, _| {
            if point == filesystem::Point::BeforeRename {
                fs::rename(&parent, &old_parent).unwrap();
                DirBuilder::new().mode(0o700).create(&parent).unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::UnsafeStorage);
        assert!(!failure.stage.as_ref().unwrap().still_named);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        assert!(!second.exists());
    }

    #[test]
    fn public_parent_and_symlink_ancestor_refuse_without_stage() {
        let tree = Tree::new();
        let public = tree.path.join("public");
        DirBuilder::new().mode(0o700).create(&public).unwrap();
        fs::set_permissions(&public, Permissions::from_mode(0o750)).unwrap();
        let failure =
            publish_recovery_export(&public.join("export"), metadata(), payloads()).unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::UnsafeStorage);
        assert!(failure.stage.is_none());
        assert_eq!(fs::read_dir(&public).unwrap().count(), 0);
        let linked = tree.path.join("linked");
        symlink(&tree.path, &linked).unwrap();
        let failure =
            publish_recovery_export(&linked.join("export"), metadata(), payloads()).unwrap_err();
        assert_eq!(failure.code, RecoveryPublishCode::UnsafeStorage);
        assert!(failure.stage.is_none());
        assert!(!tree.target().exists());
    }
    fn retained_snapshot_checkpoint() -> DetailedAccountingCheckpoint {
        use orbit_engine::compaction::{
            AccountingDelta, AccountingRevision, AttemptIntent, AttemptPurpose, AttemptRef,
            KnownPricedSubtotals,
        };
        use orbit_engine::context_budget::BudgetIdentity;
        use orbit_engine::retry::{
            DetailedLastSettlement, OrdinaryAttemptBindingRecord, RefusalRecord,
        };
        let intent = AttemptIntent {
            owner_session_id: "recovery-root".into(),
            child_id: None,
            request_id: "metadata-only-request".into(),
            purpose: AttemptPurpose::Ordinary,
            budget: BudgetIdentity {
                binding_digest: "a".repeat(64),
                metadata_revision: "metadata".into(),
                policy_revision: "policy".into(),
            },
        };
        let reference = AttemptRef {
            revision: AccountingRevision(1),
            request_id: intent.request_id.clone(),
            intent_digest: intent.digest().unwrap(),
        };
        let binding = OrdinaryAttemptBindingRecord::new(
            intent.request_id.clone(),
            "decision".into(),
            "attempt".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
        .unwrap();
        let record =
            RefusalRecord::new(intent, reference, binding, "9".repeat(64), 503, 0).unwrap();
        let rollup = RefusalRollup::first(record.clone()).unwrap();
        DetailedAccountingCheckpoint::new(
            "recovery-root".into(),
            None,
            AccountingRevision(2),
            AccountingBaseline::FreshKnownZero,
            record.totals_after(&AccountingDelta::known_zero()),
            None,
            Some(DetailedLastSettlement::FinalRefusal(record)),
            Some(KnownPricedSubtotals::known_zero()),
            Some(rollup),
        )
        .unwrap()
    }

    #[test]
    fn refusal_qualifier_is_bounded_checked_metadata_and_manifest_legacy_bytes_stay_omitted() {
        let tree = Tree::new();
        let checkpoint = retained_snapshot_checkpoint();
        let qualifier = RetainedRefusalQualification::from_checkpoint(&checkpoint)
            .unwrap()
            .unwrap();
        let raw = serde_json::to_vec(&qualifier).unwrap();
        assert!(raw.len() <= 2048);
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for key in [
            "generation_final_refusal",
            "billing_unknown",
            "usage_unknown",
            "policy_assumption",
            "visible_validated",
        ] {
            assert_eq!(value[key], true);
        }
        assert_eq!(value["count"], 1);
        assert_eq!(value["status"], 503);
        assert_eq!(
            value["latest_settlement_digest"],
            checkpoint.refusals().unwrap().latest().digest()
        );
        assert_eq!(
            value["policy_digest"],
            checkpoint
                .refusals()
                .unwrap()
                .latest()
                .binding()
                .policy_digest()
        );
        assert!(
            !String::from_utf8(raw)
                .unwrap()
                .contains("metadata-only-request")
        );
        let legacy = prepare(&tree.target(), metadata(), payloads()).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&legacy.manifest).unwrap();
        assert!(body["accounting"].get("retained_refusal").is_none());
        let old_accounting = br#"{"container_scope":"owner","selected_baseline":"unknown_legacy","selected_knownness":"uncertain","pending_retained":true}"#;
        let marker = String::from_utf8(legacy.manifest.clone()).unwrap();
        assert!(marker.contains(std::str::from_utf8(old_accounting).unwrap()));
        let mut qualified = metadata();
        qualified.checkpoint_revision = checkpoint.revision().0;
        qualified.baseline = checkpoint.baseline();
        qualified.knownness = checkpoint.totals().knownness;
        qualified.pending_retained = false;
        qualified.retained_refusal = Some(qualifier.clone());
        let prepared = prepare(&tree.target(), qualified, payloads()).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&prepared.manifest).unwrap();
        assert_eq!(body["accounting"]["retained_refusal"], value);
        assert_eq!(
            body["capture"]["prior_publication_durability"],
            "not_established"
        );
        assert_eq!(body["capture"]["provider_outcome"], "not_established");
        assert_eq!(
            qualifier.validate_for("other-root", None, 2, AccountingKnownness::UnknownUsage),
            Err(RecoveryPublishCode::InvalidInput)
        );
        assert_eq!(
            qualifier.validate_for("recovery-root", None, 1, AccountingKnownness::UnknownUsage),
            Err(RecoveryPublishCode::InvalidInput)
        );
        assert_eq!(
            qualifier.validate_for("recovery-root", None, 2, AccountingKnownness::Known),
            Err(RecoveryPublishCode::InvalidInput)
        );
        let mut mismatched = metadata();
        mismatched.knownness = AccountingKnownness::Known;
        mismatched.retained_refusal = Some(qualifier);
        assert!(matches!(
            prepare(&tree.target(), mismatched, payloads()),
            Err(RecoveryPublishCode::InvalidInput)
        ));
    }
}
