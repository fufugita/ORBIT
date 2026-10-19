//! Direct accounting status and explicit inert root export. Never admits work.

use crate::context_history::{DetailedAccountingInspection, InspectionQualification};
use crate::recovery::RetainedRefusalQualification;
use orbit_adapter::types::ProviderUsage;
use orbit_engine::compaction::{
    AccountingBaseline, AccountingKnownness, AccountingTotals, AttemptPurpose, AttemptRef,
    HistoryError, RequestAccountingReceipt,
};
use orbit_engine::retry::DetailedLastSettlement;
use serde::Serialize;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "orbit.recovery-status/v1";
const MAX_OUTPUT: usize = 16 * 1024;
const MAX_ERROR: usize = 512;
const USAGE: &str = "ORBIT-E1101: recovery_status_usage; usage: orbit [--home PATH] recovery status --session OWNER [--child CHILD] [--json] [--home PATH]; one --home maximum\n";
const OUTPUT_ERROR: &str =
    "ORBIT-E0400: output_bound_exceeded; Accounting status exceeds its output bound.\n";

// Selection only: none of these flags, except --home, is accepted by status.
// Keep operands opaque, especially arbitrary -p text and paths named recovery.
const VALUE_FLAGS: &[&str] = &[
    "--home",
    "--model",
    "--provider",
    "--gate",
    "--effort",
    "--resume",
    "--permission-mode",
    "--allowedTools",
    "--disallowedTools",
    "--output-format",
    "--json-schema",
    "--max-turns",
    "--max-cost",
    "--credential-env",
    "--url",
    "--name",
    "--kind",
    "--manifest",
    "--package",
    "--socket",
    "--session",
    "--worktree",
    "--easy",
    "--hard",
    "-p",
];

/// Handle a selected recovery command completely, before normal CLI startup.
/// Other commands return None without resolving a home or performing I/O.
pub fn try_run(args: &[String]) -> Option<i32> {
    if !selects_recovery(args) {
        return None;
    }
    if selects_export(args) {
        let parsed = match parse_export(args) {
            Ok(parsed) => parsed,
            Err(()) => return Some(write_output(Rendered::error(EXPORT_USAGE))),
        };
        let result = if parsed.child.is_some() {
            Err(ExportFailure::ChildUnavailable)
        } else {
            execute_export(&parsed, &crate::config::resolve_home(args))
        };
        return Some(write_output(render_export_result(&parsed, result)));
    }
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(()) => return Some(write_output(Rendered::error(USAGE))),
    };
    let home = crate::config::resolve_home(args);
    let result = crate::context_history::inspect_accounting_detailed(
        &home,
        &parsed.owner,
        parsed.child.as_deref(),
    )
    .map_err(Failure::History)
    .and_then(|inspection| project_detailed(&parsed, inspection));
    Some(write_output(render_result(&parsed, result)))
}

fn selects_recovery(args: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if VALUE_FLAGS.contains(&argument.as_str()) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return argument == "recovery";
        }
    }
    false
}

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    owner: String,
    child: Option<String>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Arguments, ()> {
    let mut index = 0;
    let mut home = false;
    if args.first().is_some_and(|value| value == "--home") {
        value(args, 1)?;
        home = true;
        index = 2;
    }
    if args.get(index).map(String::as_str) != Some("recovery")
        || args.get(index + 1).map(String::as_str) != Some("status")
    {
        return Err(());
    }
    index += 2;
    let mut owner = None;
    let mut child = None;
    let mut json = false;
    while let Some(argument) = args.get(index) {
        match argument.as_str() {
            "--home" if !home => {
                value(args, index + 1)?;
                home = true;
                index += 2;
            }
            "--session" if owner.is_none() => {
                let id = value(args, index + 1)?;
                if !valid_owner(id) {
                    return Err(());
                }
                owner = Some(id.to_owned());
                index += 2;
            }
            "--child" if child.is_none() => {
                let id = value(args, index + 1)?;
                if id.len() != 26
                    || !ulid::Ulid::from_string(id).is_ok_and(|parsed| parsed.to_string() == id)
                {
                    return Err(());
                }
                child = Some(id.to_owned());
                index += 2;
            }
            "--json" if !json => {
                json = true;
                index += 1;
            }
            _ => return Err(()),
        }
    }
    Ok(Arguments {
        owner: owner.ok_or(())?,
        child,
        json,
    })
}

fn value(args: &[String], index: usize) -> Result<&str, ()> {
    args.get(index)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or(())
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 128
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

const EXPORT_SCHEMA: &str = "orbit.recovery-export-result/v1";
const EXPORT_USAGE: &str = "ORBIT-E1101: recovery_export_usage; usage: orbit [--home PATH] recovery export --session OWNER --expect-revision REV --expect-inspection DIGEST --to ABSENT_DIRECTORY [--home PATH] [--json]; one --home maximum; child export unavailable\n";
const EXPORT_OUTPUT_ERROR: &str =
    "ORBIT-E0400: recovery_output_bound; Recovery export receipt exceeds its output bound.\n";
const MAX_EXPORT_PACKAGE: u64 = 256 * 1024 * 1024;
const MAX_EXPORT_MEMORY: u64 = 640 * 1024 * 1024;
// Covers bounded capture/accounting facts, cloned archive labels, manifest,
// publisher identity/verification buffers and final receipt, excluding raw data.
const EXPORT_METADATA_RESERVE: u64 = 4 * 1024 * 1024;
const MAX_EXPORT_SNAPSHOT: u64 = 64 * 1024 * 1024;
const MAX_EXPORT_ACCOUNTING: u64 = 128 * 1024;
const MAX_EXPORT_LEGACY: u64 = 32 * 1024 * 1024;
const MAX_EXPORT_ARCHIVES: u64 = 128 * 1024 * 1024;
const MAX_EXPORT_ARCHIVE: u64 = 32 * 1024 * 1024;

fn selects_export(args: &[String]) -> bool {
    let index = if args.first().is_some_and(|value| value == "--home") {
        2
    } else {
        0
    };
    args.get(index).map(String::as_str) == Some("recovery")
        && args.get(index + 1).map(String::as_str) == Some("export")
}

#[derive(Debug, PartialEq, Eq)]
struct ExportArguments {
    owner: String,
    child: Option<String>,
    expected_revision: u64,
    expected_inspection: String,
    destination: PathBuf,
    json: bool,
}

fn export_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn export_destination(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some_and(|name| name.len() <= 255)
        && path.to_str().is_some_and(|text| {
            text.len() <= 4096
                && !text.chars().any(char::is_control)
                && text
                    .split('/')
                    .skip(1)
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        })
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn parse_export(args: &[String]) -> Result<ExportArguments, ()> {
    let mut index = 0;
    let mut home = false;
    if args.first().is_some_and(|value| value == "--home") {
        value(args, 1)?;
        home = true;
        index = 2;
    }
    if args.get(index).map(String::as_str) != Some("recovery")
        || args.get(index + 1).map(String::as_str) != Some("export")
    {
        return Err(());
    }
    index += 2;
    let (mut owner, mut child, mut revision, mut inspection, mut destination) =
        (None, None, None, None, None);
    let mut json = false;
    while let Some(argument) = args.get(index) {
        match argument.as_str() {
            "--home" if !home => {
                value(args, index + 1)?;
                home = true;
                index += 2;
            }
            "--session" if owner.is_none() => {
                let id = value(args, index + 1)?;
                if !valid_owner(id) {
                    return Err(());
                }
                owner = Some(id.to_owned());
                index += 2;
            }
            "--child" if child.is_none() => {
                let id = value(args, index + 1)?;
                if id.len() != 26
                    || !ulid::Ulid::from_string(id).is_ok_and(|parsed| parsed.to_string() == id)
                {
                    return Err(());
                }
                child = Some(id.to_owned());
                index += 2;
            }
            "--expect-revision" if revision.is_none() => {
                let text = value(args, index + 1)?;
                if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(());
                }
                revision = Some(text.parse::<u64>().map_err(|_| ())?);
                index += 2;
            }
            "--expect-inspection" if inspection.is_none() => {
                let digest = value(args, index + 1)?;
                if !export_digest(digest) {
                    return Err(());
                }
                inspection = Some(digest.to_owned());
                index += 2;
            }
            "--to" if destination.is_none() => {
                let path = PathBuf::from(value(args, index + 1)?);
                if !export_destination(&path) {
                    return Err(());
                }
                destination = Some(path);
                index += 2;
            }
            "--json" if !json => {
                json = true;
                index += 1;
            }
            _ => return Err(()),
        }
    }
    Ok(ExportArguments {
        owner: owner.ok_or(())?,
        child,
        expected_revision: revision.ok_or(())?,
        expected_inspection: inspection.ok_or(())?,
        destination: destination.ok_or(())?,
        json,
    })
}

#[derive(Debug)]
enum ExportFailure {
    ChildUnavailable,
    MissingSource,
    UnsafeSource,
    InvalidSource,
    SourceUnavailable,
    SourceBusy,
    SourceChanged,
    UnsafeDestination,
    DestinationInSource,
    ExistingTarget,
    BufferBound,
    History(HistoryError),
    Publisher(Box<crate::recovery::RecoveryPublishError>),
}

impl ExportFailure {
    fn reason(&self) -> &'static str {
        match self {
            Self::ChildUnavailable => "recovery_child_export_unavailable",
            Self::MissingSource => "recovery_snapshot_missing",
            Self::UnsafeSource => "unsafe_recovery_source",
            Self::InvalidSource => "invalid_recovery_source",
            Self::SourceUnavailable => "recovery_source_unavailable",
            Self::SourceBusy => "recovery_session_busy",
            Self::SourceChanged => "recovery_source_changed",
            Self::UnsafeDestination => "unsafe_recovery_destination",
            Self::DestinationInSource => "recovery_destination_in_source",
            Self::ExistingTarget => "recovery_destination_exists",
            Self::BufferBound => "recovery_buffer_bound",
            Self::History(HistoryError::Missing) => "recovery_accounting_missing",
            Self::History(HistoryError::Busy) => "recovery_history_busy",
            Self::History(HistoryError::Unsafe) => "unsafe_recovery_history",
            Self::History(HistoryError::Uncertain) => "recovery_history_staging_unresolved",
            Self::History(HistoryError::InvalidRecord) => "invalid_recovery_history",
            Self::History(HistoryError::TooLarge | HistoryError::Full) => "recovery_history_bound",
            Self::History(HistoryError::Conflict | HistoryError::StaleNonApplying) => {
                "recovery_inspection_conflict"
            }
            Self::Publisher(failure) => failure.code.as_str(),
        }
    }
    fn status(&self) -> &'static str {
        match self {
            Self::SourceBusy | Self::History(HistoryError::Busy) => "busy",
            Self::SourceChanged
            | Self::History(HistoryError::Conflict | HistoryError::StaleNonApplying) => "conflict",
            Self::Publisher(failure)
                if failure.code == crate::recovery::RecoveryPublishCode::PublicationUncertain =>
            {
                "publication_uncertain"
            }
            _ => "unavailable",
        }
    }
    fn lease(error: crate::sessions::SessionLeaseError) -> Self {
        use crate::sessions::SessionLeaseError;
        match error {
            SessionLeaseError::Busy { .. } => Self::SourceBusy,
            SessionLeaseError::InvalidData(_) | SessionLeaseError::InvalidIdentity(_) => {
                Self::InvalidSource
            }
            SessionLeaseError::UnsafePath(_) => Self::UnsafeSource,
            SessionLeaseError::AlreadyExists { .. } => Self::SourceChanged,
            SessionLeaseError::Io(_) | SessionLeaseError::PublicationUncertain(_) => {
                Self::SourceUnavailable
            }
        }
    }
}

fn export_add(total: &mut u64, amount: u64, maximum: u64) -> Result<(), ExportFailure> {
    *total = total
        .checked_add(amount)
        .filter(|sum| *sum <= maximum)
        .ok_or(ExportFailure::BufferBound)?;
    Ok(())
}

// Raw captures, exact payload copies and conservative verification/codec
// buffers are accounted separately from output. This is a buffer policy, not
// a process RSS or allocator-capacity claim.
fn export_buffer_budget(
    snapshot: u64,
    accounting: u64,
    archives: &[u64],
    legacy: u64,
) -> Result<u64, ExportFailure> {
    if snapshot == 0
        || snapshot > MAX_EXPORT_SNAPSHOT
        || accounting == 0
        || accounting > MAX_EXPORT_ACCOUNTING
        || legacy > MAX_EXPORT_LEGACY
        || archives.len() > 64
    {
        return Err(ExportFailure::BufferBound);
    }
    let mut archive_total = 0;
    for &size in archives {
        if size == 0 || size > MAX_EXPORT_ARCHIVE {
            return Err(ExportFailure::BufferBound);
        }
        export_add(&mut archive_total, size, MAX_EXPORT_ARCHIVES)?;
    }
    let mut raw = 0;
    for size in [snapshot, accounting, archive_total, legacy] {
        export_add(&mut raw, size, MAX_EXPORT_PACKAGE)?;
    }
    let mut output = raw;
    export_add(&mut output, 128 * 1024, MAX_EXPORT_PACKAGE)?;
    let mut memory = EXPORT_METADATA_RESERVE;
    export_add(&mut memory, raw, MAX_EXPORT_MEMORY)?;
    export_add(&mut memory, raw, MAX_EXPORT_MEMORY)?;
    export_add(
        &mut memory,
        snapshot
            .max(legacy)
            .max(archives.iter().copied().max().unwrap_or(0)),
        MAX_EXPORT_MEMORY,
    )?;
    // History verification can visit an unselected sibling of maximum size.
    // Reserve its raw read, decoded content and canonical re-encode even if
    // every selected archive is tiny. Session/legacy verification streams 64 KiB;
    // the largest-source reserve above is deliberately conservative.
    for _ in 0..3 {
        export_add(&mut memory, MAX_EXPORT_ARCHIVE, MAX_EXPORT_MEMORY)?;
    }
    export_add(&mut memory, MAX_EXPORT_ACCOUNTING, MAX_EXPORT_MEMORY)?;
    Ok(memory)
}

fn absolute_export_home(home: &Path) -> Result<PathBuf, ExportFailure> {
    let absolute = if home.is_absolute() {
        home.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| ExportFailure::UnsafeSource)?
            .join(home)
    };
    let mut result = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => result.push(part),
            _ => return Err(ExportFailure::UnsafeSource),
        }
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
mod export_preflight {
    use super::*;
    use crate::customization::Directory;
    use std::os::unix::fs::MetadataExt;

    #[derive(PartialEq, Eq)]
    struct SnapshotStamp {
        device: u64,
        inode: u64,
        owner: u32,
        group: u32,
        mode: u32,
        links: u64,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl SnapshotStamp {
        fn checked(value: &std::fs::Metadata) -> Result<Self, ExportFailure> {
            if !value.is_file()
                || value.uid() != rustix::process::geteuid().as_raw()
                || value.nlink() != 1
                || value.mode() & 0o7077 != 0
            {
                return Err(ExportFailure::UnsafeSource);
            }
            if value.len() == 0 || value.len() > MAX_EXPORT_SNAPSHOT {
                return Err(ExportFailure::InvalidSource);
            }
            Ok(Self {
                device: value.dev(),
                inode: value.ino(),
                owner: value.uid(),
                group: value.gid(),
                mode: value.mode(),
                links: value.nlink(),
                bytes: value.len(),
                modified: (value.mtime(), value.mtime_nsec()),
                changed: (value.ctime(), value.ctime_nsec()),
            })
        }
    }

    pub(super) struct Source {
        home: Directory,
        sessions: Directory,
        name: String,
        stamp: SnapshotStamp,
    }
    impl Source {
        pub(super) fn open(home: &Path, owner: &str) -> Result<Self, ExportFailure> {
            let home = Directory::open(home, true).map_err(|_| ExportFailure::UnsafeSource)?;
            match std::fs::symlink_metadata(
                home.io()
                    .map_err(|_| ExportFailure::UnsafeSource)?
                    .join("sessions"),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(ExportFailure::MissingSource);
                }
                Err(_) => return Err(ExportFailure::UnsafeSource),
                Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                    return Err(ExportFailure::UnsafeSource);
                }
                Ok(_) => {}
            }
            let sessions = home
                .child("sessions", false)
                .map_err(|_| ExportFailure::UnsafeSource)?;
            let name = format!("{owner}.json");
            let metadata = std::fs::symlink_metadata(
                sessions
                    .io()
                    .map_err(|_| ExportFailure::UnsafeSource)?
                    .join(&name),
            )
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ExportFailure::MissingSource
                } else {
                    ExportFailure::UnsafeSource
                }
            })?;
            let stamp = SnapshotStamp::checked(&metadata)?;
            let result = Self {
                home,
                sessions,
                name,
                stamp,
            };
            result.check()?;
            Ok(result)
        }
        pub(super) fn check(&self) -> Result<(), ExportFailure> {
            self.home
                .check()
                .map_err(|_| ExportFailure::SourceChanged)?;
            self.sessions
                .check()
                .map_err(|_| ExportFailure::SourceChanged)?;
            Directory::open(self.home.path(), true).map_err(|_| ExportFailure::UnsafeSource)?;
            Directory::open(self.sessions.path(), true).map_err(|_| ExportFailure::UnsafeSource)?;
            let now = std::fs::symlink_metadata(
                self.sessions
                    .io()
                    .map_err(|_| ExportFailure::UnsafeSource)?
                    .join(&self.name),
            )
            .map_err(|_| ExportFailure::SourceChanged)?;
            if SnapshotStamp::checked(&now)? != self.stamp {
                return Err(ExportFailure::SourceChanged);
            }
            self.home
                .check()
                .map_err(|_| ExportFailure::SourceChanged)?;
            self.sessions
                .check()
                .map_err(|_| ExportFailure::SourceChanged)
        }
    }

    pub(super) struct Destination {
        directory: Directory,
        name: String,
        parent: crate::recovery::RecoveryDestinationParent,
    }
    impl Destination {
        pub(super) fn open(home: &Path, path: &Path) -> Result<Self, ExportFailure> {
            if path == home
                || ["sessions", "context-history", "agents", "projects"]
                    .iter()
                    .any(|name| path.starts_with(home.join(name)))
            {
                return Err(ExportFailure::DestinationInSource);
            }
            let parent = path.parent().ok_or(ExportFailure::UnsafeDestination)?;
            let directory =
                Directory::open(parent, true).map_err(|_| ExportFailure::UnsafeDestination)?;
            let mut critical = Vec::new();
            for name in ["sessions", "context-history", "agents", "projects"] {
                match std::fs::symlink_metadata(home.join(name)) {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                        critical.push((metadata.dev(), metadata.ino()))
                    }
                    _ => {}
                }
            }
            // Ancestor identities also reject a bind-mounted alias of a source
            // directory. Never canonicalize through a forbidden symlink.
            for ancestor in parent.ancestors() {
                let metadata = std::fs::symlink_metadata(ancestor)
                    .map_err(|_| ExportFailure::UnsafeDestination)?;
                if critical.contains(&(metadata.dev(), metadata.ino())) {
                    return Err(ExportFailure::DestinationInSource);
                }
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ExportFailure::UnsafeDestination)?
                .to_owned();
            let binding = crate::recovery::RecoveryDestinationParent::capture(&directory)
                .map_err(|_| ExportFailure::UnsafeDestination)?;
            let result = Self {
                directory,
                name,
                parent: binding,
            };
            result.check()?;
            Ok(result)
        }
        pub(super) fn parent(&self) -> &crate::recovery::RecoveryDestinationParent {
            &self.parent
        }
        pub(super) fn check(&self) -> Result<(), ExportFailure> {
            self.directory
                .check()
                .map_err(|_| ExportFailure::UnsafeDestination)?;
            Directory::open(self.directory.path(), true)
                .map_err(|_| ExportFailure::UnsafeDestination)?;
            let metadata = std::fs::metadata(
                self.directory
                    .io()
                    .map_err(|_| ExportFailure::UnsafeDestination)?
                    .join("."),
            )
            .map_err(|_| ExportFailure::UnsafeDestination)?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
                || metadata.nlink() < 2
            {
                return Err(ExportFailure::UnsafeDestination);
            }
            match std::fs::symlink_metadata(
                self.directory
                    .io()
                    .map_err(|_| ExportFailure::UnsafeDestination)?
                    .join(&self.name),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => return Err(ExportFailure::ExistingTarget),
                Err(_) => return Err(ExportFailure::UnsafeDestination),
            }
            self.directory
                .check()
                .map_err(|_| ExportFailure::UnsafeDestination)
        }
    }
}

fn execute_export(
    args: &ExportArguments,
    home: &Path,
) -> Result<crate::recovery::PublishedRecoveryExport, ExportFailure> {
    if args.child.is_some() {
        return Err(ExportFailure::ChildUnavailable);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = home;
        Err(ExportFailure::SourceUnavailable)
    }
    #[cfg(target_os = "linux")]
    {
        use crate::recovery::{RecoveryExportMetadata, RecoveryPayload};
        use sha2::{Digest, Sha256};
        let home = absolute_export_home(home)?;
        let source = export_preflight::Source::open(&home, &args.owner)?;
        let destination = export_preflight::Destination::open(&home, &args.destination)?;
        let lease = crate::sessions::SessionLease::acquire(&home, &args.owner, "recovery-export")
            .map_err(ExportFailure::lease)?;
        source.check()?;
        lease.verify_for_recovery().map_err(ExportFailure::lease)?;
        let snapshot = lease.capture_for_recovery().map_err(ExportFailure::lease)?;
        if snapshot.owner_session_id() != args.owner {
            return Err(ExportFailure::InvalidSource);
        }
        let history = crate::context_history::capture_for_recovery_detailed(
            &lease,
            orbit_engine::compaction::AccountingRevision(args.expected_revision),
            &args.expected_inspection,
        )
        .map_err(ExportFailure::History)?;
        let legacy = lease
            .capture_legacy_for_recovery()
            .map_err(ExportFailure::lease)?;
        let archive_sizes: Vec<u64> = history
            .archives()
            .iter()
            .map(|archive| archive.bytes().len() as u64)
            .collect();
        export_buffer_budget(
            snapshot.bytes().len() as u64,
            history.accounting_bytes().len() as u64,
            &archive_sizes,
            legacy.bytes().map_or(0, |bytes| bytes.len() as u64),
        )?;
        let inspection = history.inspection();
        let checkpoint = &inspection.checkpoint;
        let facts = snapshot.facts();
        if checkpoint.owner_session_id() != args.owner
            || checkpoint.child_id().is_some()
            || inspection.inspection_digest != args.expected_inspection
            || checkpoint.revision().0 != args.expected_revision
        {
            return Err(ExportFailure::InvalidSource);
        }
        let metadata = RecoveryExportMetadata {
            owner_session_id: args.owner.clone(),
            checkpoint_revision: checkpoint.revision().0,
            inspection_digest: inspection.inspection_digest.clone(),
            baseline: checkpoint.baseline(),
            knownness: checkpoint.totals().knownness,
            pending_retained: checkpoint.pending().is_some(),
            retained_refusal: RetainedRefusalQualification::from_checkpoint(checkpoint)
                .map_err(|_| ExportFailure::InvalidSource)?,
            saved_turns: facts.turns,
            watermark_revision: facts.watermark_revision,
            watermark_full_cost_status: facts.watermark_full_cost_status,
        };
        fn exact(bytes: &[u8], expected: &str) -> Result<Vec<u8>, ExportFailure> {
            let copy = bytes.to_vec();
            if hex::encode(Sha256::digest(&copy)) != expected {
                return Err(ExportFailure::SourceChanged);
            }
            Ok(copy)
        }
        let mut payloads = vec![
            RecoveryPayload::RootSnapshot(exact(snapshot.bytes(), snapshot.sha256())?),
            RecoveryPayload::Accounting(exact(
                history.accounting_bytes(),
                history.accounting_sha256(),
            )?),
        ];
        for archive in history.archives() {
            payloads.push(RecoveryPayload::Archive {
                record_id: archive.record_id().to_owned(),
                source_digest: archive.source_digest().to_owned(),
                candidate_digest: archive.candidate_digest().to_owned(),
                bytes: exact(archive.bytes(), archive.sha256())?,
            });
        }
        match (legacy.bytes(), legacy.sha256()) {
            (Some(bytes), Some(digest)) => {
                payloads.push(RecoveryPayload::LegacyJsonl(exact(bytes, digest)?))
            }
            (None, None) => {}
            _ => return Err(ExportFailure::InvalidSource),
        }
        // Every copy has completed before source rechecks. Retain the real lease
        // through publication, but release duplicate raw captures after checking.
        snapshot
            .verify_unchanged(&lease)
            .map_err(|_| ExportFailure::SourceChanged)?;
        legacy
            .verify_unchanged(&lease)
            .map_err(|_| ExportFailure::SourceChanged)?;
        history
            .verify_unchanged(&lease)
            .map_err(ExportFailure::History)?;
        source.check()?;
        destination.check()?;
        lease.verify_for_recovery().map_err(ExportFailure::lease)?;
        drop(legacy);
        drop(history);
        drop(snapshot);
        drop(source);
        let result = crate::recovery::publish_recovery_export(
            &args.destination,
            destination.parent(),
            metadata,
            payloads,
        )
        .map_err(|failure| ExportFailure::Publisher(Box::new(failure)));
        drop(lease);
        result
    }
}

fn export_artifact(
    identity: &crate::recovery::RecoveryArtifactIdentity,
    stage: Option<&crate::recovery::IncompleteRecoveryStage>,
) -> Option<serde_json::Value> {
    let basename = identity.intended_stage.file_name()?.to_str()?;
    if !export_destination(&identity.destination)
        || !valid_owner(&identity.owner_session_id)
        || !export_digest(&identity.inspection_digest)
        || !export_digest(&identity.manifest_sha256)
        || stage.is_some_and(|stage| stage.path != identity.intended_stage)
        || identity.intended_stage.parent() != identity.destination.parent()
        || basename.len() != 80
        || !basename
            .strip_prefix(".recovery-stage-")
            .is_some_and(export_digest)
    {
        return None;
    }
    let retained=stage.map(|stage|serde_json::json!({"basename":basename,"device":stage.device,"inode":stage.inode,"still_named":stage.still_named,"qualification":"incomplete_owned_stage"}));
    Some(
        serde_json::json!({"target":identity.destination,"owner_session_id":identity.owner_session_id,"child_id":null,
        "checkpoint_revision":identity.checkpoint_revision,"inspection_digest":identity.inspection_digest,"manifest_sha256":identity.manifest_sha256,
        "intended_stage_basename":basename,"retained_stage":retained}),
    )
}

fn render_export_result(
    args: &ExportArguments,
    result: Result<crate::recovery::PublishedRecoveryExport, ExportFailure>,
) -> Rendered {
    let (status, reason, artifact, files, bytes, qualification, exit) = match &result {
        Ok(done) => (
            "published",
            None,
            export_artifact(&done.artifact, None),
            Some(done.files),
            Some(done.bytes),
            "published_synced",
            0,
        ),
        Err(failure) => {
            let artifact = match failure {
                ExportFailure::Publisher(failure) => failure
                    .artifact
                    .as_ref()
                    .and_then(|identity| export_artifact(identity, failure.stage.as_ref())),
                _ => None,
            };
            (
                failure.status(),
                Some(failure.reason()),
                artifact,
                None,
                None,
                "not_established",
                2,
            )
        }
    };
    let value = serde_json::json!({"schema":EXPORT_SCHEMA,"command":"recovery_export","status":status,
        "owner_session_id":args.owner,"child_id":args.child,"expected_revision":args.expected_revision,"expected_inspection":args.expected_inspection,
        "reason":reason,"artifact":artifact,"included_files":files,"included_bytes":bytes,"publication_qualification":qualification,
        "provider_outcome":"not_established","prior_source_durability":"not_established"});
    let Some(json) = bounded_json(&value, MAX_OUTPUT) else {
        return Rendered::error(EXPORT_OUTPUT_ERROR);
    };
    if args.json {
        return Rendered {
            stdout: json,
            stderr: Vec::new(),
            exit_code: exit,
        };
    }
    if let Some(reason) = reason {
        let line = format!(
            "ORBIT-E0400: {reason}; Recovery export did not establish successful publication.\n"
        );
        if line.len() > MAX_ERROR {
            return Rendered::error(EXPORT_OUTPUT_ERROR);
        }
        // A prepared artifact is always reported as bounded structured data,
        // preserving an uncertain destination without a long human error line.
        Rendered {
            stdout: if value["artifact"].is_null() {
                Vec::new()
            } else {
                json
            },
            stderr: line.into_bytes(),
            exit_code: exit,
        }
    } else {
        let text = format!(
            "Recovery export published.\nTarget: \"{}\"\nOwner: {}\nCheckpoint revision: {}\nInspection digest: {}\nManifest SHA-256: {}\nFiles: {}; bytes: {}\n",
            human(args.destination.to_str().unwrap_or("")),
            args.owner,
            value["artifact"]["checkpoint_revision"],
            value["artifact"]["inspection_digest"]
                .as_str()
                .unwrap_or(""),
            value["artifact"]["manifest_sha256"].as_str().unwrap_or(""),
            files.unwrap_or(0),
            bytes.unwrap_or(0)
        );
        if text.len() > MAX_OUTPUT {
            return Rendered {
                stdout: json,
                stderr: Vec::new(),
                exit_code: exit,
            };
        }
        Rendered {
            stdout: text.into_bytes(),
            stderr: Vec::new(),
            exit_code: exit,
        }
    }
}

#[derive(Debug, Serialize)]
struct Totals {
    input_tokens: u64,
    output_tokens: u64,
    cost_microcents: Option<u64>,
}

impl From<AccountingTotals> for Totals {
    fn from(value: AccountingTotals) -> Self {
        Self {
            input_tokens: value.input_tokens,
            output_tokens: value.output_tokens,
            cost_microcents: value.cost_microcents,
        }
    }
}

#[derive(Debug, Serialize)]
struct Delta {
    knownness: &'static str,
    ordinary: Totals,
    housekeeping: Totals,
}

#[derive(Debug, Serialize)]
struct PricedSubtotals {
    ordinary_microcents: u64,
    housekeeping_microcents: u64,
}

#[derive(Debug, Serialize)]
struct Reference {
    revision: u64,
    request_id: String,
    intent_digest: String,
}

impl From<&AttemptRef> for Reference {
    fn from(value: &AttemptRef) -> Self {
        Self {
            revision: value.revision.0,
            request_id: value.request_id.clone(),
            intent_digest: value.intent_digest.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Budget {
    binding_digest: String,
    metadata_revision: String,
    policy_revision: String,
}

#[derive(Debug, Serialize)]
struct Usage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
}

impl From<ProviderUsage> for Usage {
    fn from(value: ProviderUsage) -> Self {
        Self {
            input_tokens: value.input_tokens,
            output_tokens: value.output_tokens,
            cache_read_tokens: value.cache_read_tokens,
            cache_write_tokens: value.cache_write_tokens,
            reasoning_tokens: value.reasoning_tokens,
        }
    }
}

#[derive(Debug, Serialize)]
struct Receipt {
    request_id: String,
    purpose: &'static str,
    knownness: &'static str,
    completed: bool,
    known_totals: Totals,
    observed_usage: Option<Usage>,
    usage_qualification: &'static str,
}

impl Receipt {
    fn from_checked(value: &RequestAccountingReceipt) -> Result<Self, Failure> {
        value.validate().map_err(|_| Failure::InvalidInspection)?;
        let usage_qualification = match (value.knownness, value.usage.is_some()) {
            (AccountingKnownness::Known, true) => "validated_final",
            (AccountingKnownness::Known, false) => "not_sent",
            (AccountingKnownness::UnknownUsage, true) => "observed_unvalidated",
            (AccountingKnownness::Uncertain, true) => "provisional_observed",
            (AccountingKnownness::UnknownUsage | AccountingKnownness::Uncertain, false) => {
                "not_observed"
            }
            (AccountingKnownness::UnknownLegacy, _) => return Err(Failure::InvalidInspection),
        };
        Ok(Self {
            request_id: value.request_id.clone(),
            purpose: purpose(value.purpose),
            knownness: knownness(value.knownness),
            completed: value.completed,
            known_totals: value.totals.into(),
            observed_usage: value.usage.map(Usage::from),
            usage_qualification,
        })
    }
}

#[derive(Debug, Serialize)]
struct Pending {
    reference: Reference,
    expected_previous_revision: u64,
    purpose: &'static str,
    budget: Budget,
    uncertain: bool,
    receipt: Option<Receipt>,
}

#[derive(Debug, Serialize)]
struct Settlement {
    reference: Reference,
    receipt_digest: String,
    receipt: Receipt,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum StatusSettlement {
    Legacy(Settlement),
    FinalRefusal {
        disposition: &'static str,
        reference: Reference,
        settlement_digest: String,
    },
}

#[derive(Debug, Serialize)]
struct Inspection {
    qualification: &'static str,
    prior_publication_durability: &'static str,
    provider_outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct Available {
    schema: &'static str,
    status: &'static str,
    owner_session_id: String,
    child_id: Option<String>,
    checkpoint_revision: u64,
    baseline: &'static str,
    accounting_scope: &'static str,
    totals: Delta,
    known_priced_subtotals: Option<PricedSubtotals>,
    lifecycle: &'static str,
    pending: Option<Pending>,
    last_settlement: Option<StatusSettlement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_refusal: Option<RetainedRefusalQualification>,
    inspection_digest: String,
    inspection: Inspection,
}

fn project_detailed(
    args: &Arguments,
    value: DetailedAccountingInspection,
) -> Result<Available, Failure> {
    let checkpoint = &value.checkpoint;
    checkpoint
        .validate()
        .map_err(|_| Failure::InvalidInspection)?;
    let retained_refusal = RetainedRefusalQualification::from_checkpoint(checkpoint)
        .map_err(|_| Failure::InvalidInspection)?;
    if checkpoint.owner_session_id() != args.owner || checkpoint.child_id() != args.child.as_deref()
    {
        return Err(Failure::InvalidInspection);
    }
    let last_settlement = match (checkpoint.last_settlement(), &value.last_legacy_receipt) {
        (None, None) => None,
        (Some(DetailedLastSettlement::Legacy(last)), Some(receipt))
            if last.reference.request_id == receipt.request_id
                && receipt.knownness != AccountingKnownness::Uncertain
                && receipt.digest().map_err(|_| Failure::InvalidInspection)?
                    == last.receipt_digest =>
        {
            Some(StatusSettlement::Legacy(Settlement {
                reference: (&last.reference).into(),
                receipt_digest: last.receipt_digest.clone(),
                receipt: Receipt::from_checked(receipt)?,
            }))
        }
        (Some(DetailedLastSettlement::FinalRefusal(record)), None) => {
            if checkpoint.refusals().map(|rollup| rollup.latest()) != Some(record) {
                return Err(Failure::InvalidInspection);
            }
            Some(StatusSettlement::FinalRefusal {
                disposition: "final_generation_refusal",
                reference: record.attempt().into(),
                settlement_digest: record.digest().into(),
            })
        }
        _ => return Err(Failure::InvalidInspection),
    };
    let (pending, lifecycle) = match (checkpoint.pending(), &value.pending_receipt) {
        (None, None) => (
            None,
            if last_settlement.is_some() {
                "settled"
            } else {
                "no_attempt"
            },
        ),
        (Some(pending), receipt) if pending.uncertain == receipt.is_some() => {
            if pending.intent.owner_session_id != args.owner
                || pending.intent.child_id != args.child
                || pending.intent.request_id != pending.reference.request_id
                || receipt.as_ref().is_some_and(|receipt| {
                    receipt.request_id != pending.reference.request_id
                        || receipt.purpose != pending.intent.purpose
                        || receipt.knownness != AccountingKnownness::Uncertain
                })
            {
                return Err(Failure::InvalidInspection);
            }
            let expected_previous_revision = pending
                .reference
                .revision
                .0
                .checked_sub(1)
                .ok_or(Failure::InvalidInspection)?;
            let budget = &pending.intent.budget;
            (
                Some(Pending {
                    reference: (&pending.reference).into(),
                    expected_previous_revision,
                    purpose: purpose(pending.intent.purpose),
                    budget: Budget {
                        binding_digest: budget.binding_digest.clone(),
                        metadata_revision: budget.metadata_revision.clone(),
                        policy_revision: budget.policy_revision.clone(),
                    },
                    uncertain: pending.uncertain,
                    receipt: receipt.as_ref().map(Receipt::from_checked).transpose()?,
                }),
                if pending.uncertain {
                    "uncertain_receipt"
                } else {
                    "begun_only"
                },
            )
        }
        _ => return Err(Failure::InvalidInspection),
    };
    let qualification = match value.qualification {
        InspectionQualification::VisibleValidated => "visible_validated",
    };
    Ok(Available {
        schema: SCHEMA,
        status: "available",
        owner_session_id: checkpoint.owner_session_id().to_owned(),
        child_id: checkpoint.child_id().map(str::to_owned),
        checkpoint_revision: checkpoint.revision().0,
        baseline: match checkpoint.baseline() {
            AccountingBaseline::FreshKnownZero => "fresh_known_zero",
            AccountingBaseline::UnknownLegacy => "unknown_legacy",
        },
        accounting_scope: "since_namespace_initialization",
        totals: Delta {
            knownness: knownness(checkpoint.totals().knownness),
            ordinary: checkpoint.totals().ordinary.into(),
            housekeeping: checkpoint.totals().housekeeping.into(),
        },
        known_priced_subtotals: checkpoint
            .known_priced_subtotals()
            .map(|value| PricedSubtotals {
                ordinary_microcents: value.ordinary_microcents,
                housekeeping_microcents: value.housekeeping_microcents,
            }),
        lifecycle,
        pending,
        last_settlement,
        retained_refusal,
        inspection_digest: value.inspection_digest,
        inspection: Inspection {
            qualification,
            prior_publication_durability: "not_established",
            provider_outcome: "not_established_by_inspection",
        },
    })
}

fn knownness(value: AccountingKnownness) -> &'static str {
    match value {
        AccountingKnownness::Known => "known",
        AccountingKnownness::UnknownLegacy => "unknown_legacy",
        AccountingKnownness::UnknownUsage => "unknown_usage",
        AccountingKnownness::Uncertain => "uncertain",
    }
}

fn purpose(value: AttemptPurpose) -> &'static str {
    match value {
        AttemptPurpose::Ordinary => "ordinary",
        AttemptPurpose::Chunk => "chunk",
        AttemptPurpose::Merge => "merge",
    }
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    History(HistoryError),
    InvalidInspection,
    OutputBound,
}

struct FailureDetails {
    status: &'static str,
    code: Option<&'static str>,
    reason: &'static str,
    message: &'static str,
    exit_code: i32,
}

impl Failure {
    fn details(self) -> FailureDetails {
        let (status, reason, message) = match self {
            Self::History(HistoryError::Missing) => {
                return FailureDetails {
                    status: "untracked",
                    code: None,
                    reason: "accounting_missing",
                    message: "No tracked accounting is available for this namespace.",
                    exit_code: 0,
                };
            }
            Self::History(HistoryError::Busy) => (
                "busy",
                "history_writer_busy",
                "Accounting inspection is busy; an existing history writer holds the lock.",
            ),
            Self::History(HistoryError::Unsafe) => (
                "unavailable",
                "unsafe_storage",
                "Accounting storage could not be safely inspected.",
            ),
            Self::History(HistoryError::Uncertain) => (
                "unavailable",
                "inspection_uncertain",
                "Accounting inspection is unavailable while storage has unresolved staging.",
            ),
            Self::History(HistoryError::InvalidRecord) | Self::InvalidInspection => (
                "unavailable",
                "invalid_accounting",
                "Accounting metadata did not pass validation.",
            ),
            Self::History(HistoryError::TooLarge) => (
                "unavailable",
                "accounting_size_exceeded",
                "Accounting metadata exceeds its inspection bound.",
            ),
            Self::History(HistoryError::Full) => (
                "unavailable",
                "accounting_capacity_exceeded",
                "Accounting metadata exceeds its codec capacity bound.",
            ),
            Self::History(HistoryError::Conflict) => (
                "unavailable",
                "inspection_conflict",
                "Accounting inspection could not establish consistent metadata.",
            ),
            Self::History(HistoryError::StaleNonApplying) => (
                "unavailable",
                "inspection_stale",
                "Accounting inspection could not establish current metadata.",
            ),
            Self::OutputBound => (
                "unavailable",
                "output_bound_exceeded",
                "Accounting status exceeds its output bound.",
            ),
        };
        FailureDetails {
            status,
            code: Some("ORBIT-E0400"),
            reason,
            message,
            exit_code: 2,
        }
    }
}

struct Rendered {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
}

impl Rendered {
    fn error(message: &str) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: message.as_bytes().to_vec(),
            exit_code: 2,
        }
    }
}

fn bounded_json(value: &impl Serialize, maximum: usize) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).ok()?;
    bytes.push(b'\n');
    (bytes.len() <= maximum).then_some(bytes)
}

fn render_result(args: &Arguments, result: Result<Available, Failure>) -> Rendered {
    match result {
        Ok(view) => {
            let bytes = if args.json {
                bounded_json(&view, MAX_OUTPUT)
            } else {
                let bytes = human_available(&view).into_bytes();
                (bytes.len() <= MAX_OUTPUT).then_some(bytes)
            };
            match bytes {
                Some(stdout) => Rendered {
                    stdout,
                    stderr: Vec::new(),
                    exit_code: 0,
                },
                None => render_failure(args, Failure::OutputBound),
            }
        }
        Err(failure) => render_failure(args, failure),
    }
}

fn render_failure(args: &Arguments, failure: Failure) -> Rendered {
    let details = failure.details();
    if args.json {
        // Value contains only bounded ASCII scope and fixed static messages.
        let mut bytes = serde_json::json!({
            "schema": SCHEMA, "status": details.status,
            "owner_session_id": args.owner, "child_id": args.child,
            "code": details.code, "reason": details.reason, "message": details.message,
        })
        .to_string()
        .into_bytes();
        bytes.push(b'\n');
        if bytes.len() > MAX_ERROR {
            return Rendered::error(OUTPUT_ERROR);
        }
        Rendered {
            stdout: bytes,
            stderr: Vec::new(),
            exit_code: details.exit_code,
        }
    } else {
        let line = match details.code {
            Some(code) => format!("{code}: {}; {}\n", details.reason, details.message),
            None => format!(
                "Accounting status: {}; {}\n",
                details.status, details.message
            ),
        };
        if line.len() > MAX_ERROR {
            return Rendered::error(OUTPUT_ERROR);
        }
        if details.exit_code == 0 {
            Rendered {
                stdout: line.into_bytes(),
                stderr: Vec::new(),
                exit_code: 0,
            }
        } else {
            Rendered::error(&line)
        }
    }
}

fn human(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn human_totals(output: &mut String, label: &str, totals: &Totals) {
    let _ = writeln!(
        output,
        "{label}: input_tokens={} output_tokens={} cost_microcents={}",
        totals.input_tokens,
        totals.output_tokens,
        optional_number(totals.cost_microcents)
    );
}

fn human_reference(output: &mut String, reference: &Reference) {
    let _ = writeln!(
        output,
        "  reference: revision={} request_id=\"{}\" intent_digest=\"{}\"",
        reference.revision,
        human(&reference.request_id),
        human(&reference.intent_digest)
    );
}

fn human_receipt(output: &mut String, receipt: &Receipt) {
    let _ = writeln!(
        output,
        "  receipt: request_id=\"{}\" purpose={} knownness={} completed={}",
        human(&receipt.request_id),
        receipt.purpose,
        receipt.knownness,
        receipt.completed
    );
    human_totals(output, "  receipt known totals", &receipt.known_totals);
    let _ = writeln!(
        output,
        "  usage qualification: {}",
        receipt.usage_qualification
    );
    if let Some(usage) = &receipt.observed_usage {
        let _ = writeln!(
            output,
            "  observed usage: input_tokens={} output_tokens={} cache_read_tokens={} cache_write_tokens={} reasoning_tokens={}",
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_tokens,
            usage.cache_write_tokens,
            usage.reasoning_tokens
        );
    } else {
        let _ = writeln!(output, "  observed usage: not observed");
    }
}

fn human_available(view: &Available) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Accounting status: available");
    let _ = writeln!(output, "Owner: \"{}\"", human(&view.owner_session_id));
    let _ = writeln!(
        output,
        "Child: {}",
        view.child_id.as_ref().map_or_else(
            || "none".to_owned(),
            |value| format!("\"{}\"", human(value))
        )
    );
    let _ = writeln!(output, "Checkpoint revision: {}", view.checkpoint_revision);
    let _ = writeln!(output, "Lifecycle: {}", view.lifecycle);
    let _ = writeln!(
        output,
        "Baseline: {}; recorded knownness: {}",
        view.baseline, view.totals.knownness
    );
    let _ = writeln!(
        output,
        "Recorded totals since namespace initialization; an untracked legacy prefix is not included."
    );
    human_totals(&mut output, "Ordinary", &view.totals.ordinary);
    human_totals(&mut output, "Housekeeping", &view.totals.housekeeping);
    if let Some(subtotals) = &view.known_priced_subtotals {
        let _ = writeln!(
            output,
            "Known priced subset: ordinary_microcents={} housekeeping_microcents={}",
            subtotals.ordinary_microcents, subtotals.housekeeping_microcents
        );
    } else {
        let _ = writeln!(output, "Known priced subset: unavailable");
    }
    if let Some(pending) = &view.pending {
        let _ = writeln!(
            output,
            "Pending attempt: unresolved; purpose={} uncertain={}",
            pending.purpose, pending.uncertain
        );
        human_reference(&mut output, &pending.reference);
        let _ = writeln!(
            output,
            "  expected previous revision: {}",
            pending.expected_previous_revision
        );
        let _ = writeln!(
            output,
            "  budget: binding_digest=\"{}\" metadata_revision=\"{}\" policy_revision=\"{}\"",
            human(&pending.budget.binding_digest),
            human(&pending.budget.metadata_revision),
            human(&pending.budget.policy_revision)
        );
        if let Some(receipt) = &pending.receipt {
            human_receipt(&mut output, receipt);
        } else {
            let _ = writeln!(
                output,
                "  no retained receipt; request outcome remains unresolved"
            );
        }
    } else {
        let _ = writeln!(output, "Pending attempt: none");
    }
    match &view.last_settlement {
        Some(StatusSettlement::Legacy(last)) => {
            let _ = writeln!(output, "Prior settlement:");
            human_reference(&mut output, &last.reference);
            let _ = writeln!(
                output,
                "  receipt digest: \"{}\"",
                human(&last.receipt_digest)
            );
            human_receipt(&mut output, &last.receipt);
        }
        Some(StatusSettlement::FinalRefusal {
            reference,
            settlement_digest,
            ..
        }) => {
            let _ = writeln!(
                output,
                "Prior settlement: final generation refusal; billing unknown; usage unknown; policy assumption"
            );
            human_reference(&mut output, reference);
            let _ = writeln!(
                output,
                "  settlement digest: \"{}\"",
                human(settlement_digest)
            );
        }
        None => {
            let _ = writeln!(output, "Prior settlement: none");
        }
    }
    if let Some(refusal) = &view.retained_refusal {
        let _ = writeln!(
            output,
            "Retained refusal: generation_final_refusal=true billing_unknown=true usage_unknown=true policy_assumption=true visible_validated=true count={} status={}",
            refusal.count(),
            refusal.status()
        );
        let _ = writeln!(
            output,
            "  chain digest: \"{}\"; latest settlement digest: \"{}\"; policy digest: \"{}\"",
            refusal.chain_digest(),
            refusal.settlement_digest(),
            refusal.policy_digest()
        );
        let _ = writeln!(
            output,
            "  Retained refusal metadata does not establish zero provider usage, prior durability or replay permission."
        );
    }
    let _ = writeln!(
        output,
        "Inspection digest: \"{}\"",
        human(&view.inspection_digest)
    );
    let _ = writeln!(
        output,
        "Inspection qualification: {}",
        view.inspection.qualification
    );
    let _ = writeln!(
        output,
        "Prior publication durability and provider outcome are not established by inspection."
    );
    let _ = writeln!(
        output,
        "This inspection grants no admission, settlement or replay permission."
    );
    output
}

fn write_output(output: Rendered) -> i32 {
    if !output.stdout.is_empty() {
        let mut stdout = std::io::stdout().lock();
        if stdout
            .write_all(&output.stdout)
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return 2;
        }
    }
    if !output.stderr.is_empty() {
        let mut stderr = std::io::stderr().lock();
        if stderr
            .write_all(&output.stderr)
            .and_then(|()| stderr.flush())
            .is_err()
        {
            return 2;
        }
    }
    output.exit_code
}

#[cfg(all(test, target_os = "linux"))]
mod export_tests {
    use super::*;
    use std::fs::{self, DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

    struct Tree {
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    impl Tree {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-recovery-command-{}", ulid::Ulid::new()));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            Self {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        fn home(&self) -> PathBuf {
            self.path.join("home")
        }
        fn source(&self) -> PathBuf {
            let home = self.home();
            DirBuilder::new().mode(0o700).create(&home).unwrap();
            DirBuilder::new()
                .mode(0o700)
                .create(home.join("sessions"))
                .unwrap();
            let path = home.join("sessions/owner.json");
            fs::write(&path, b"metadata-only preflight must not decode this").unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
            home
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
    fn args(destination: PathBuf) -> ExportArguments {
        ExportArguments {
            owner: "owner".into(),
            child: None,
            expected_revision: 7,
            expected_inspection: "a".repeat(64),
            destination,
            json: true,
        }
    }
    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }
    fn command() -> Vec<String> {
        words(&[
            "recovery",
            "export",
            "--session",
            "owner",
            "--expect-revision",
            "7",
            "--expect-inspection",
            &"a".repeat(64),
            "--to",
            "/private/export",
        ])
    }

    #[test]
    fn publisher_rejects_protected_projects_inode_swapped_into_approved_parent() {
        let tree = Tree::new();
        let home = tree.source();
        let projects = home.join("projects");
        DirBuilder::new().mode(0o700).create(&projects).unwrap();
        let original = b"exact original protected projects member";
        let member = projects.join("owner.jsonl");
        fs::write(&member, original).unwrap();
        fs::set_permissions(&member, Permissions::from_mode(0o600)).unwrap();
        let source_directory = fs::symlink_metadata(&projects).unwrap();
        let source_member = fs::symlink_metadata(&member).unwrap();
        let parent = tree.path.join("approved-output-parent");
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let target = parent.join("export");
        let destination = export_preflight::Destination::open(&home, &target).unwrap();
        destination.check().unwrap();
        // Deterministic gap between the real caller preflight and actual
        // publisher open. Keep its original Directory guard alive throughout.
        let displaced = tree.path.join("displaced-approved-parent");
        fs::rename(&parent, &displaced).unwrap();
        fs::rename(&projects, &parent).unwrap();
        let failure = crate::recovery::publish_recovery_export(
            &target,
            destination.parent(),
            crate::recovery::RecoveryExportMetadata {
                owner_session_id: "owner".into(),
                checkpoint_revision: 7,
                inspection_digest: "a".repeat(64),
                baseline: AccountingBaseline::UnknownLegacy,
                knownness: AccountingKnownness::UnknownLegacy,
                pending_retained: false,
                retained_refusal: None,
                saved_turns: 3,
                watermark_revision: None,
                watermark_full_cost_status: None,
            },
            vec![
                crate::recovery::RecoveryPayload::RootSnapshot(b"checked inert snapshot".to_vec()),
                crate::recovery::RecoveryPayload::Accounting(b"checked inert accounting".to_vec()),
            ],
        )
        .unwrap_err();
        assert_eq!(
            failure.code,
            crate::recovery::RecoveryPublishCode::UnsafeStorage
        );
        assert!(failure.stage.is_none());
        let artifact = failure.artifact.unwrap();
        assert_eq!(artifact.destination, target);
        assert!(!artifact.intended_stage.exists());
        assert!(!target.exists());
        assert!(destination.check().is_err());
        assert_eq!(fs::read_dir(&displaced).unwrap().count(), 0);
        let current_directory = fs::symlink_metadata(&parent).unwrap();
        assert_eq!(
            (
                current_directory.dev(),
                current_directory.ino(),
                current_directory.uid(),
                current_directory.mode(),
                current_directory.nlink()
            ),
            (
                source_directory.dev(),
                source_directory.ino(),
                source_directory.uid(),
                source_directory.mode(),
                source_directory.nlink()
            )
        );
        let members = fs::read_dir(&parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(members, [std::ffi::OsString::from("owner.jsonl")]);
        let moved_member = parent.join("owner.jsonl");
        assert_eq!(fs::read(&moved_member).unwrap(), original);
        let current_member = fs::symlink_metadata(moved_member).unwrap();
        assert_eq!(
            (
                current_member.dev(),
                current_member.ino(),
                current_member.uid(),
                current_member.gid(),
                current_member.mode(),
                current_member.nlink(),
                current_member.len(),
                current_member.mtime(),
                current_member.mtime_nsec(),
                current_member.ctime(),
                current_member.ctime_nsec()
            ),
            (
                source_member.dev(),
                source_member.ino(),
                source_member.uid(),
                source_member.gid(),
                source_member.mode(),
                source_member.nlink(),
                source_member.len(),
                source_member.mtime(),
                source_member.mtime_nsec(),
                source_member.ctime(),
                source_member.ctime_nsec()
            )
        );
    }

    #[test]
    fn strict_export_grammar_requires_complete_exact_flags_and_u64_digest_path() {
        let base = command();
        let parsed = parse_export(&base).unwrap();
        assert!(selects_recovery(&base));
        assert!(selects_export(&base));
        assert_eq!(parsed.expected_revision, 7);
        assert_eq!(parsed.expected_inspection, "a".repeat(64));
        assert_eq!(parsed.destination, PathBuf::from("/private/export"));
        let mut before = words(&["--home", "H"]);
        before.extend(base.clone());
        assert!(parse_export(&before).is_ok());
        let mut after = base.clone();
        after.extend(words(&["--json", "--home", "H"]));
        assert!(parse_export(&after).unwrap().json);
        for (flag, replacement) in [
            ("--expect-revision", "+1"),
            ("--expect-revision", "-1"),
            ("--expect-revision", "18446744073709551616"),
            ("--expect-inspection", &"A".repeat(64)),
            ("--session", "owner.json"),
            ("--to", "relative/export"),
            ("--to", "/private/../export"),
            ("--to", "/private/./export"),
            ("--to", "/private//export"),
            ("--to", "/private/export/"),
            ("--to", "/private/new\nline"),
        ] {
            let mut values = base.clone();
            let index = values.iter().position(|value| value == flag).unwrap();
            values[index + 1] = replacement.to_owned();
            assert!(
                parse_export(&values).is_err(),
                "accepted replacement for {flag}"
            );
        }
        for flag in [
            "--session",
            "--expect-revision",
            "--expect-inspection",
            "--to",
        ] {
            let mut missing = base.clone();
            let index = missing.iter().position(|value| value == flag).unwrap();
            missing.drain(index..=index + 1);
            assert!(parse_export(&missing).is_err());
            let mut duplicate = base.clone();
            duplicate.extend([base[index].clone(), base[index + 1].clone()]);
            assert!(parse_export(&duplicate).is_err());
        }
        for tail in [
            vec!["--json", "--json"],
            vec!["--help"],
            vec!["--"],
            vec!["extra"],
            vec!["--model", "provider-operand"],
            vec!["-p", "prompt"],
        ] {
            let mut values = base.clone();
            values.extend(words(&tail));
            assert!(parse_export(&values).is_err());
        }
        let mut duplicate_home = before;
        duplicate_home.extend(words(&["--home", "H"]));
        assert!(parse_export(&duplicate_home).is_err());
        let mut maximum = base;
        maximum[5] = u64::MAX.to_string();
        assert_eq!(parse_export(&maximum).unwrap().expected_revision, u64::MAX);
    }

    #[test]
    fn export_selection_keeps_prompt_and_path_operands_opaque() {
        for values in [
            vec!["-p", "recovery", "version"],
            vec!["--home", "recovery", "version"],
            vec!["--model", "recovery", "version"],
            vec!["version", "recovery", "export"],
        ] {
            let values = words(&values);
            assert!(!selects_recovery(&values));
            assert!(!selects_export(&values));
        }
        let status = words(&["recovery", "status", "--session", "owner"]);
        assert!(selects_recovery(&status));
        assert!(!selects_export(&status));
        assert!(parse(&status).is_ok());
        let mut prefix = words(&["--help"]);
        prefix.extend(command());
        assert!(selects_recovery(&prefix));
        assert!(!selects_export(&prefix));
        assert!(parse(&prefix).is_err());
    }

    #[test]
    fn unsupported_child_refuses_before_home_source_or_destination_access() {
        let tree = Tree::new();
        let mut values = command();
        values.extend(words(&["--child", "00000000000000000000000001"]));
        let mut parsed = parse_export(&values).unwrap();
        parsed.json = true;
        parsed.destination = tree.path.join("absent-parent/export");
        let result = execute_export(&parsed, &tree.home());
        assert_eq!(
            result.unwrap_err().reason(),
            "recovery_child_export_unavailable"
        );
        assert_eq!(fs::read_dir(&tree.path).unwrap().count(), 0);
        let rendered = render_export_result(&parsed, Err(ExportFailure::ChildUnavailable));
        assert_eq!(rendered.exit_code, 2);
        let value: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(value["reason"], "recovery_child_export_unavailable");
        assert!(value["artifact"].is_null());
    }

    #[test]
    fn metadata_and_output_preflight_failures_create_no_lease_or_source_namespace() {
        let tree = Tree::new();
        let home = tree.source();
        let destination = tree.path.join("export");
        DirBuilder::new().mode(0o700).create(&destination).unwrap();
        let failure = execute_export(&args(destination.clone()), &home).unwrap_err();
        assert_eq!(failure.reason(), "recovery_destination_exists");
        assert!(!home.join("sessions/.leases").exists());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        for destination in [
            home.clone(),
            home.join("sessions/new"),
            home.join("context-history/new"),
            home.join("agents/new"),
            home.join("projects/new"),
        ] {
            assert_eq!(
                execute_export(&args(destination), &home)
                    .unwrap_err()
                    .reason(),
                "recovery_destination_in_source"
            );
            assert!(!home.join("sessions/.leases").exists());
        }
        assert!(export_preflight::Destination::open(&home, &home.join("sessions-other")).is_ok());
        fs::remove_file(home.join("sessions/owner.json")).unwrap();
        assert_eq!(
            execute_export(&args(tree.path.join("fresh")), &home)
                .unwrap_err()
                .reason(),
            "recovery_snapshot_missing"
        );
        assert_eq!(fs::read_dir(home.join("sessions")).unwrap().count(), 0);
        assert!(!tree.path.join("fresh").exists());
    }

    #[test]
    fn unsafe_metadata_and_dangling_output_refuse_without_snapshot_body_read() {
        let tree = Tree::new();
        let home = tree.source();
        let snapshot = home.join("sessions/owner.json");
        let destination = tree.path.join("export");
        fs::set_permissions(&snapshot, Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            execute_export(&args(destination.clone()), &home)
                .unwrap_err()
                .reason(),
            "unsafe_recovery_source"
        );
        fs::set_permissions(&snapshot, Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&snapshot, home.join("sessions/second.json")).unwrap();
        assert_eq!(
            execute_export(&args(destination.clone()), &home)
                .unwrap_err()
                .reason(),
            "unsafe_recovery_source"
        );
        fs::remove_file(home.join("sessions/second.json")).unwrap();
        symlink("missing-output", &destination).unwrap();
        assert_eq!(
            execute_export(&args(destination.clone()), &home)
                .unwrap_err()
                .reason(),
            "recovery_destination_exists"
        );
        assert_eq!(
            fs::read_link(destination).unwrap(),
            PathBuf::from("missing-output")
        );
        assert!(!home.join("sessions/.leases").exists());
        assert_eq!(
            fs::read(snapshot).unwrap(),
            b"metadata-only preflight must not decode this"
        );
    }

    #[test]
    fn full_component_budget_fits_memory_policy_and_checked_overflow_refuses() {
        let sizes = [MAX_EXPORT_ARCHIVE; 4];
        let memory = export_buffer_budget(
            MAX_EXPORT_SNAPSHOT,
            MAX_EXPORT_ACCOUNTING,
            &sizes,
            MAX_EXPORT_LEGACY,
        )
        .unwrap();
        assert!(memory <= MAX_EXPORT_MEMORY);
        assert!(memory > MAX_EXPORT_PACKAGE);
        assert!(export_buffer_budget(MAX_EXPORT_SNAPSHOT + 1, 1, &[], 0).is_err());
        assert!(export_buffer_budget(1, MAX_EXPORT_ACCOUNTING + 1, &[], 0).is_err());
        assert!(export_buffer_budget(1, 1, &[MAX_EXPORT_ARCHIVE; 5], 0).is_err());
        assert!(export_buffer_budget(1, 1, &[1; 65], 0).is_err());
        assert!(export_buffer_budget(1, 1, &[], MAX_EXPORT_LEGACY + 1).is_err());
        let mut total = u64::MAX;
        assert!(export_add(&mut total, 1, u64::MAX).is_err());
        assert_eq!(total, u64::MAX);
    }

    fn identity(args: &ExportArguments) -> crate::recovery::RecoveryArtifactIdentity {
        crate::recovery::RecoveryArtifactIdentity {
            destination: args.destination.clone(),
            intended_stage: args
                .destination
                .parent()
                .unwrap()
                .join(format!(".recovery-stage-{}", "b".repeat(64))),
            owner_session_id: args.owner.clone(),
            checkpoint_revision: args.expected_revision,
            inspection_digest: args.expected_inspection.clone(),
            manifest_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn maximum_escaped_destination_and_retained_uncertainty_receipts_stay_bounded() {
        let segment = "\"\\".repeat(120);
        let destination = PathBuf::from(format!("/{}", vec![segment; 16].join("/")));
        assert!(export_destination(&destination));
        let mut parsed = args(destination);
        parsed.owner = "o".repeat(128);
        parsed.expected_revision = u64::MAX;
        let artifact = identity(&parsed);
        let stage = crate::recovery::IncompleteRecoveryStage {
            path: artifact.intended_stage.clone(),
            device: u64::MAX,
            inode: u64::MAX,
            still_named: true,
        };
        let failure = crate::recovery::RecoveryPublishError {
            code: crate::recovery::RecoveryPublishCode::SyncFailed,
            artifact: Some(Box::new(artifact.clone())),
            stage: Some(stage),
        };
        let rendered =
            render_export_result(&parsed, Err(ExportFailure::Publisher(Box::new(failure))));
        assert_eq!(rendered.exit_code, 2);
        assert!(rendered.stdout.len() <= MAX_OUTPUT);
        let value: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(
            value["artifact"]["target"],
            parsed.destination.to_str().unwrap()
        );
        assert_eq!(
            value["artifact"]["retained_stage"]["qualification"],
            "incomplete_owned_stage"
        );
        assert!(value["artifact"]["retained_stage"].get("path").is_none());
        let failure = crate::recovery::RecoveryPublishError {
            code: crate::recovery::RecoveryPublishCode::PublicationUncertain,
            artifact: Some(Box::new(artifact.clone())),
            stage: None,
        };
        parsed.json = false;
        let rendered =
            render_export_result(&parsed, Err(ExportFailure::Publisher(Box::new(failure))));
        assert!(rendered.stderr.len() <= MAX_ERROR);
        assert!(rendered.stdout.len() <= MAX_OUTPUT);
        let value: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(value["status"], "publication_uncertain");
        assert_eq!(
            value["artifact"]["manifest_sha256"],
            artifact.manifest_sha256
        );
        assert_eq!(value["publication_qualification"], "not_established");
        parsed.json = true;
        let done = crate::recovery::PublishedRecoveryExport {
            artifact,
            files: 72,
            bytes: MAX_EXPORT_PACKAGE,
        };
        let rendered = render_export_result(&parsed, Ok(done));
        assert_eq!(rendered.exit_code, 0);
        assert!(rendered.stdout.len() <= MAX_OUTPUT);
        let value: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(value["status"], "published");
        assert_eq!(value["included_files"], 72);
        assert_eq!(value["included_bytes"], MAX_EXPORT_PACKAGE);
    }
    #[test]
    fn detailed_export_history_verifier_rejects_identical_bytes_on_replaced_source_inode() {
        let tree = Tree::new();
        let home = tree.home();
        DirBuilder::new().mode(0o700).create(&home).unwrap();
        let lease =
            crate::sessions::SessionLease::acquire(&home, "owner", "detailed-consumer-test")
                .unwrap();
        let journal = crate::context_history::context_journal(&home, "owner", None).unwrap();
        journal
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let inspection =
            crate::context_history::inspect_accounting_detailed(&home, "owner", None).unwrap();
        let capture = crate::context_history::capture_for_recovery_detailed(
            &lease,
            inspection.checkpoint.revision(),
            &inspection.inspection_digest,
        )
        .unwrap();
        assert_eq!(capture.inspection(), &inspection);
        capture.verify_unchanged(&lease).unwrap();
        let path = home.join("context-history/owner/accounting.json");
        let original = fs::read(&path).unwrap();
        assert_eq!(capture.accounting_bytes(), original);
        let replacement = path.with_file_name("owned-identical-replacement");
        fs::write(&replacement, &original).unwrap();
        fs::set_permissions(&replacement, Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            capture.verify_unchanged(&lease),
            Err(HistoryError::Conflict)
        );
        assert_eq!(
            crate::context_history::inspect_accounting_detailed(&home, "owner", None).unwrap(),
            inspection
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_engine::compaction::{
        AccountingCheckpoint, AccountingDelta, AccountingRevision, AttemptIntent,
        KnownPricedSubtotals, PendingAttempt, SettledAttempt,
    };
    use orbit_engine::context_budget::BudgetIdentity;
    use serde_json::Value;

    const CHILD: &str = "00000000000000000000000001";

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn arguments(json: bool) -> Arguments {
        Arguments {
            owner: "owner".into(),
            child: None,
            json,
        }
    }

    use crate::context_history::AccountingInspection;
    fn project(args: &Arguments, value: AccountingInspection) -> Result<Available, Failure> {
        project_detailed(
            args,
            DetailedAccountingInspection {
                checkpoint: orbit_engine::retry::DetailedAccountingCheckpoint::from_legacy(
                    value.checkpoint,
                )
                .map_err(|_| Failure::InvalidInspection)?,
                pending_receipt: value.pending_receipt,
                last_legacy_receipt: value.last_receipt,
                inspection_digest: value.inspection_digest,
                qualification: value.qualification,
            },
        )
    }

    // Pure projection fixtures use actual public metadata types; these tests
    // claim no filesystem, publication or provider capability acceptance.
    fn empty_inspection() -> AccountingInspection {
        AccountingInspection {
            checkpoint: AccountingCheckpoint {
                owner_session_id: "owner".into(),
                child_id: None,
                revision: AccountingRevision(0),
                baseline: AccountingBaseline::FreshKnownZero,
                totals: AccountingDelta::known_zero(),
                pending: None,
                last_settlement: None,
                known_priced_subtotals: Some(KnownPricedSubtotals::known_zero()),
            },
            pending_receipt: None,
            last_receipt: None,
            inspection_digest: "c".repeat(64),
            qualification: InspectionQualification::VisibleValidated,
        }
    }

    fn final_receipt() -> RequestAccountingReceipt {
        RequestAccountingReceipt {
            request_id: "prior".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals {
                input_tokens: 11,
                output_tokens: 12,
                cost_microcents: Some(23),
            },
            usage: Some(ProviderUsage {
                input_tokens: 11,
                output_tokens: 12,
                cache_read_tokens: 5,
                cache_write_tokens: 3,
                reasoning_tokens: 2,
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        }
    }

    fn pending_inspection() -> AccountingInspection {
        let mut value = empty_inspection();
        let prior = final_receipt();
        value.checkpoint.revision = AccountingRevision(4);
        value.checkpoint.totals = AccountingDelta {
            ordinary: AccountingTotals {
                input_tokens: 11,
                output_tokens: 12,
                cost_microcents: None,
            },
            housekeeping: AccountingTotals::known_zero(),
            knownness: AccountingKnownness::Uncertain,
        };
        value.checkpoint.known_priced_subtotals = Some(KnownPricedSubtotals {
            ordinary_microcents: 23,
            housekeeping_microcents: 0,
        });
        value.checkpoint.last_settlement = Some(SettledAttempt {
            reference: AttemptRef {
                revision: AccountingRevision(1),
                request_id: "prior".into(),
                intent_digest: "a".repeat(64),
            },
            receipt_digest: prior.digest().unwrap(),
        });
        value.last_receipt = Some(prior);
        let intent = AttemptIntent {
            owner_session_id: "owner".into(),
            child_id: None,
            request_id: "pending".into(),
            purpose: AttemptPurpose::Chunk,
            budget: BudgetIdentity {
                binding_digest: "b".repeat(64),
                metadata_revision: "metadata-v1".into(),
                policy_revision: "policy-v1".into(),
            },
        };
        value.checkpoint.pending = Some(PendingAttempt {
            reference: AttemptRef {
                revision: AccountingRevision(3),
                request_id: "pending".into(),
                intent_digest: intent.digest().unwrap(),
            },
            intent,
            uncertain: true,
        });
        value.pending_receipt = Some(RequestAccountingReceipt {
            request_id: "pending".into(),
            purpose: AttemptPurpose::Chunk,
            totals: AccountingTotals {
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: None,
            },
            usage: Some(ProviderUsage {
                input_tokens: 31,
                output_tokens: 17,
                cache_read_tokens: 7,
                cache_write_tokens: 3,
                reasoning_tokens: 2,
            }),
            knownness: AccountingKnownness::Uncertain,
            completed: false,
        });
        value
    }

    fn json_result(args: &Arguments, inspection: AccountingInspection) -> Value {
        let result = render_result(args, project(args, inspection));
        assert_eq!(result.exit_code, 0);
        assert!(result.stderr.is_empty());
        assert!(result.stdout.len() <= MAX_OUTPUT);
        serde_json::from_slice(&result.stdout).unwrap()
    }

    #[test]
    fn strict_grammar_accepts_only_exact_scope_and_one_home_in_either_position() {
        for values in [
            vec!["recovery", "status", "--session", "owner"],
            vec!["--home", "H", "recovery", "status", "--session", "owner"],
            vec![
                "recovery",
                "status",
                "--json",
                "--home",
                "H",
                "--child",
                CHILD,
                "--session",
                "owner",
            ],
        ] {
            let args = words(&values);
            assert!(selects_recovery(&args));
            let parsed = parse(&args).unwrap();
            assert_eq!(parsed.owner, "owner");
            assert_eq!(parsed.json, values.contains(&"--json"));
        }
        assert!(
            parse(&words(&[
                "recovery",
                "status",
                "--session",
                &"a".repeat(128)
            ]))
            .is_ok()
        );
        for values in [
            vec!["recovery"],
            vec!["recovery", "export"],
            vec!["recovery", "status"],
            vec!["recovery", "--home", "H", "status", "--session", "owner"],
            vec!["recovery", "status", "--session", "owner.json"],
            vec!["recovery", "status", "--session", ""],
            vec!["recovery", "status", "--session", "../owner"],
            vec![
                "recovery",
                "status",
                "--session",
                "owner",
                "--session",
                "owner",
            ],
            vec![
                "recovery",
                "status",
                "--session",
                "owner",
                "--json",
                "--json",
            ],
            vec![
                "--home",
                "H",
                "recovery",
                "status",
                "--session",
                "owner",
                "--home",
                "H",
            ],
            vec!["recovery", "status", "--session", "owner", "--home", ""],
            vec![
                "recovery",
                "status",
                "--session",
                "owner",
                "--child",
                "0000000000000000000000000a",
            ],
            vec![
                "recovery",
                "status",
                "--session",
                "owner",
                "--child",
                CHILD,
                "--child",
                CHILD,
            ],
            vec!["recovery", "status", "--session=owner"],
            vec!["recovery", "status", "--session", "owner", "--"],
            vec!["recovery", "status", "--session", "owner", "extra"],
        ] {
            assert!(parse(&words(&values)).is_err(), "accepted {values:?}");
        }
        assert!(
            parse(&words(&[
                "recovery",
                "status",
                "--session",
                &"a".repeat(129)
            ]))
            .is_err()
        );
    }

    #[test]
    fn selected_help_prompt_and_override_combinations_never_fall_through() {
        for flag in ["--help", "-h", "--version", "-V", "--json", "--unknown"] {
            let args = words(&[flag, "recovery", "status", "--session", "owner"]);
            assert!(selects_recovery(&args));
            assert!(parse(&args).is_err());
        }
        for flag in VALUE_FLAGS {
            let args = words(&[flag, "operand", "recovery", "status", "--session", "owner"]);
            assert!(selects_recovery(&args));
            assert_eq!(parse(&args).is_ok(), *flag == "--home");
            let operand = words(&[flag, "recovery", "version"]);
            assert!(!selects_recovery(&operand));
        }
        for flag in [
            "--help",
            "-p",
            "--prompt",
            "--model",
            "--provider",
            "--continue",
            "--fork-session",
            "--output-format",
        ] {
            assert!(parse(&words(&["recovery", "status", "--session", "owner", flag])).is_err());
        }
        for values in [
            vec!["-p", "recovery"],
            vec!["web", "search", "recovery"],
            vec!["plugin", "add", "recovery"],
            vec!["compact", "--session", "recovery"],
        ] {
            assert!(!selects_recovery(&words(&values)));
        }
        assert!(USAGE.len() <= MAX_ERROR);
        assert!(!USAGE.contains("operand"));
    }

    #[test]
    fn missing_and_all_storage_errors_are_bounded_and_have_no_accounting_facts() {
        let mut args = Arguments {
            owner: "a".repeat(128),
            child: Some(CHILD.into()),
            json: true,
        };
        for error in [
            HistoryError::Missing,
            HistoryError::Busy,
            HistoryError::Unsafe,
            HistoryError::Uncertain,
            HistoryError::TooLarge,
            HistoryError::Full,
            HistoryError::InvalidRecord,
            HistoryError::Conflict,
            HistoryError::StaleNonApplying,
        ] {
            let result = render_failure(&args, Failure::History(error));
            assert!(result.stderr.is_empty());
            assert!(result.stdout.len() <= MAX_ERROR);
            let json: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 7);
            assert_eq!(json["owner_session_id"], args.owner);
            for field in [
                "checkpoint_revision",
                "baseline",
                "totals",
                "lifecycle",
                "pending",
                "inspection_digest",
                "inspection",
            ] {
                assert!(json.get(field).is_none());
            }
            assert_eq!(
                result.exit_code,
                if error == HistoryError::Missing { 0 } else { 2 }
            );
            if error == HistoryError::Missing {
                assert_eq!(json["status"], "untracked");
                assert!(json["code"].is_null());
            }
            args.json = false;
            let human = render_failure(&args, Failure::History(error));
            assert!(human.stdout.len() + human.stderr.len() <= MAX_ERROR);
            assert_eq!(human.exit_code, result.exit_code);
            args.json = true;
        }
    }

    #[test]
    fn fresh_known_zero_unknown_legacy_and_nullable_priced_subset_stay_distinct() {
        let args = arguments(true);
        let fresh = json_result(&args, empty_inspection());
        assert_eq!(fresh["baseline"], "fresh_known_zero");
        assert_eq!(fresh["lifecycle"], "no_attempt");
        assert_eq!(fresh["totals"]["ordinary"]["cost_microcents"], 0);
        assert_eq!(fresh["inspection_digest"], "c".repeat(64));
        assert_eq!(fresh["inspection"]["qualification"], "visible_validated");
        assert_eq!(
            fresh["inspection"]["prior_publication_durability"],
            "not_established"
        );
        let mut value = empty_inspection();
        value.checkpoint.baseline = AccountingBaseline::UnknownLegacy;
        value.checkpoint.totals = AccountingDelta::unknown_legacy();
        value.checkpoint.known_priced_subtotals = None;
        let legacy = json_result(&args, value);
        assert_eq!(legacy["baseline"], "unknown_legacy");
        assert_eq!(legacy["totals"]["knownness"], "unknown_legacy");
        assert!(legacy["known_priced_subtotals"].is_null());
        assert!(legacy["totals"]["ordinary"]["cost_microcents"].is_null());
    }

    #[test]
    fn pending_and_prior_receipts_keep_all_five_counters_and_budget_separate() {
        let args = arguments(true);
        let value = json_result(&args, pending_inspection());
        assert_eq!(value["lifecycle"], "uncertain_receipt");
        assert_eq!(value["pending"]["reference"]["request_id"], "pending");
        assert_eq!(value["pending"]["expected_previous_revision"], 2);
        assert_eq!(value["pending"]["purpose"], "chunk");
        assert_eq!(value["pending"]["budget"]["binding_digest"], "b".repeat(64));
        assert_eq!(
            value["pending"]["budget"]["metadata_revision"],
            "metadata-v1"
        );
        assert_eq!(value["pending"]["budget"]["policy_revision"], "policy-v1");
        let pending = &value["pending"]["receipt"];
        assert_eq!(pending["usage_qualification"], "provisional_observed");
        assert_eq!(pending["known_totals"]["input_tokens"], 0);
        let usage = pending["observed_usage"].as_object().unwrap();
        assert_eq!(usage.len(), 5);
        for (field, expected) in [
            ("input_tokens", 31),
            ("output_tokens", 17),
            ("cache_read_tokens", 7),
            ("cache_write_tokens", 3),
            ("reasoning_tokens", 2),
        ] {
            assert_eq!(usage[field], expected);
        }
        assert_eq!(value["totals"]["ordinary"]["input_tokens"], 11);
        assert_eq!(value["known_priced_subtotals"]["ordinary_microcents"], 23);
        let last = &value["last_settlement"];
        assert_eq!(last["reference"]["request_id"], "prior");
        assert_eq!(last["receipt"]["usage_qualification"], "validated_final");
        assert!(last.get("budget").is_none());
        assert!(last["receipt"].get("budget").is_none());
        let mut begun = pending_inspection();
        begun.pending_receipt = None;
        begun.checkpoint.pending.as_mut().unwrap().uncertain = false;
        begun.checkpoint.revision = AccountingRevision(3);
        begun.checkpoint.totals.knownness = AccountingKnownness::Known;
        let begun = json_result(&args, begun);
        assert_eq!(begun["lifecycle"], "begun_only");
        assert_eq!(begun["totals"]["knownness"], "known");
        assert!(begun["pending"]["receipt"].is_null());
        assert_eq!(begun["last_settlement"]["reference"]["request_id"], "prior");
    }

    #[test]
    fn usage_presence_knownness_and_completion_are_independent() {
        let mut receipt = final_receipt();
        receipt.completed = false;
        receipt.totals.cost_microcents = None;
        let mapped = Receipt::from_checked(&receipt).unwrap();
        assert_eq!(mapped.usage_qualification, "validated_final");
        assert!(!mapped.completed);
        assert!(mapped.known_totals.cost_microcents.is_none());
        receipt.usage = None;
        receipt.totals = AccountingTotals::known_zero();
        let mapped = Receipt::from_checked(&receipt).unwrap();
        assert_eq!(mapped.usage_qualification, "not_sent");
        assert!(mapped.observed_usage.is_none());
        for knownness in [
            AccountingKnownness::UnknownUsage,
            AccountingKnownness::Uncertain,
        ] {
            receipt.knownness = knownness;
            receipt.completed = knownness == AccountingKnownness::UnknownUsage;
            receipt.totals.cost_microcents = None;
            let mapped = Receipt::from_checked(&receipt).unwrap();
            assert_eq!(mapped.usage_qualification, "not_observed");
            receipt.usage = final_receipt().usage;
            let mapped = Receipt::from_checked(&receipt).unwrap();
            assert_eq!(
                mapped.usage_qualification,
                if receipt.completed {
                    "observed_unvalidated"
                } else {
                    "provisional_observed"
                }
            );
            receipt.usage = None;
        }
        receipt.knownness = AccountingKnownness::UnknownLegacy;
        assert!(Receipt::from_checked(&receipt).is_err());
    }

    #[test]
    fn settled_not_sent_is_distinct_from_begun_without_a_receipt() {
        let args = arguments(true);
        let mut value = empty_inspection();
        let receipt = RequestAccountingReceipt {
            request_id: "not-sent".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: AccountingTotals::known_zero(),
            usage: None,
            knownness: AccountingKnownness::Known,
            completed: false,
        };
        value.checkpoint.revision = AccountingRevision(2);
        value.checkpoint.last_settlement = Some(SettledAttempt {
            reference: AttemptRef {
                revision: AccountingRevision(1),
                request_id: receipt.request_id.clone(),
                intent_digest: "a".repeat(64),
            },
            receipt_digest: receipt.digest().unwrap(),
        });
        value.last_receipt = Some(receipt);
        let value = json_result(&args, value);
        assert_eq!(value["lifecycle"], "settled");
        assert!(value["pending"].is_null());
        assert_eq!(
            value["last_settlement"]["receipt"]["usage_qualification"],
            "not_sent"
        );
        assert_eq!(value["last_settlement"]["receipt"]["completed"], false);
        assert!(value["last_settlement"]["receipt"]["observed_usage"].is_null());
    }

    #[test]
    fn impossible_scope_receipt_and_reference_joins_fail_without_partial_facts() {
        let args = arguments(true);
        let mut bad = pending_inspection();
        bad.checkpoint.owner_session_id = "other".into();
        assert!(project(&args, bad).is_err());
        let mut bad = pending_inspection();
        bad.last_receipt = None;
        assert!(project(&args, bad).is_err());
        let mut bad = pending_inspection();
        bad.pending_receipt.as_mut().unwrap().request_id = "prior".into();
        assert!(project(&args, bad).is_err());
        let mut bad = pending_inspection();
        bad.checkpoint.pending.as_mut().unwrap().reference.revision = AccountingRevision(0);
        assert!(project(&args, bad).is_err());
        let mut bad = pending_inspection();
        bad.checkpoint.pending.as_mut().unwrap().uncertain = false;
        let result = render_result(&args, project(&args, bad));
        assert_eq!(result.exit_code, 2);
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["status"], "unavailable");
        assert!(value.get("pending").is_none());
    }

    #[test]
    fn human_output_is_terminal_inert_and_preserves_pending_qualifications() {
        let mut inspection = pending_inspection();
        let budget = &mut inspection
            .checkpoint
            .pending
            .as_mut()
            .unwrap()
            .intent
            .budget;
        budget.metadata_revision = "unicode\u{202e}revision".into();
        budget.policy_revision = String::new();
        let pending = inspection.checkpoint.pending.as_mut().unwrap();
        pending.reference.intent_digest = pending.intent.digest().unwrap();
        let args = arguments(false);
        let result = render_result(&args, project(&args, inspection));
        assert_eq!(result.exit_code, 0);
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("\\u{202e}"));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("Pending attempt: unresolved"));
        assert!(text.contains("Prior settlement:"));
        assert!(text.contains("cache_read_tokens=7 cache_write_tokens=3 reasoning_tokens=2"));
        assert!(text.contains("provisional_observed"));
        assert!(text.contains("not established by inspection"));
        assert_eq!(
            human("\u{1b}[2J\n\r\u{7f}\\\""),
            "\\u{1b}[2J\\n\\r\\u{7f}\\\\\\\""
        );
    }

    #[test]
    fn maximum_integers_remain_exact_and_oversize_rendering_never_truncates() {
        let args = arguments(true);
        let mut inspection = empty_inspection();
        inspection.checkpoint.totals.ordinary = AccountingTotals {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            cost_microcents: Some(u64::MAX),
        };
        let maximum = RequestAccountingReceipt {
            request_id: "maximum".into(),
            purpose: AttemptPurpose::Ordinary,
            totals: inspection.checkpoint.totals.ordinary,
            usage: Some(ProviderUsage {
                input_tokens: u64::MAX,
                output_tokens: u64::MAX,
                ..Default::default()
            }),
            knownness: AccountingKnownness::Known,
            completed: true,
        };
        inspection.checkpoint.revision = AccountingRevision(2);
        inspection.checkpoint.last_settlement = Some(SettledAttempt {
            reference: AttemptRef {
                revision: AccountingRevision(1),
                request_id: maximum.request_id.clone(),
                intent_digest: "a".repeat(64),
            },
            receipt_digest: maximum.digest().unwrap(),
        });
        inspection.checkpoint.known_priced_subtotals = Some(KnownPricedSubtotals {
            ordinary_microcents: u64::MAX,
            housekeeping_microcents: 0,
        });
        inspection.last_receipt = Some(maximum);
        let value = json_result(&args, inspection);
        assert_eq!(
            value["totals"]["ordinary"]["input_tokens"].as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            value["totals"]["ordinary"]["cost_microcents"].as_u64(),
            Some(u64::MAX)
        );
        assert!(bounded_json(&value, 8).is_none());
        // Pure renderer limit injection, not a claimed valid journal fixture.
        for json in [true, false] {
            let args = arguments(json);
            let mut view = project(&args, pending_inspection()).unwrap();
            view.pending.as_mut().unwrap().budget.policy_revision = "x".repeat(MAX_OUTPUT);
            let result = render_result(&args, Ok(view));
            assert_eq!(result.exit_code, 2);
            assert!(result.stdout.len() + result.stderr.len() <= MAX_ERROR);
            if json {
                let value: Value = serde_json::from_slice(&result.stdout).unwrap();
                assert_eq!(value["reason"], "output_bound_exceeded");
                assert!(value.get("pending").is_none());
            } else {
                assert!(result.stdout.is_empty());
            }
        }
    }

    #[test]
    fn maximum_valid_scope_and_revision_strings_fit_both_renderers() {
        let mut args = Arguments {
            owner: "o".repeat(128),
            child: Some(CHILD.into()),
            json: true,
        };
        let mut value = pending_inspection();
        value.checkpoint.owner_session_id = args.owner.clone();
        value.checkpoint.child_id = args.child.clone();
        let pending = value.checkpoint.pending.as_mut().unwrap();
        pending.intent.owner_session_id = args.owner.clone();
        pending.intent.child_id = args.child.clone();
        pending.intent.request_id = "p".repeat(256);
        pending.reference.request_id = pending.intent.request_id.clone();
        pending.intent.budget.metadata_revision = "\u{202e}".repeat(85);
        pending.intent.budget.policy_revision = "q".repeat(256);
        pending.reference.intent_digest = pending.intent.digest().unwrap();
        value.pending_receipt.as_mut().unwrap().request_id = pending.intent.request_id.clone();
        let last = value.checkpoint.last_settlement.as_mut().unwrap();
        last.reference.request_id = "r".repeat(256);
        let receipt = value.last_receipt.as_mut().unwrap();
        receipt.request_id = last.reference.request_id.clone();
        last.receipt_digest = receipt.digest().unwrap();
        let view = project(&args, value.clone()).unwrap();
        let json = render_result(&args, Ok(view));
        assert_eq!(json.exit_code, 0);
        let parsed: Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(parsed["owner_session_id"], args.owner);
        assert_eq!(
            parsed["pending"]["budget"]["policy_revision"],
            "q".repeat(256)
        );
        args.json = false;
        let rendered = render_result(&args, project(&args, value));
        assert_eq!(rendered.exit_code, 0);
        assert!(rendered.stdout.len() <= MAX_OUTPUT);
        assert!(rendered.stdout.is_ascii());
        assert!(rendered.stderr.is_empty());
    }
    fn refusal_inspection(
        baseline: AccountingBaseline,
        later_success: bool,
        uncertain: bool,
    ) -> DetailedAccountingInspection {
        use orbit_engine::retry::{
            DetailedAccountingCheckpoint, DetailedLastSettlement, OrdinaryAttemptBindingRecord,
            RefusalRecord, RefusalRollup,
        };
        let intent = AttemptIntent {
            owner_session_id: "owner".into(),
            child_id: None,
            request_id: "refused".into(),
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
        let mut totals = record.totals_after(&match baseline {
            AccountingBaseline::FreshKnownZero => AccountingDelta::known_zero(),
            AccountingBaseline::UnknownLegacy => AccountingDelta::unknown_legacy(),
        });
        let mut revision = 2;
        let mut last = DetailedLastSettlement::FinalRefusal(record.clone());
        let mut last_legacy_receipt = None;
        let mut priced = KnownPricedSubtotals::known_zero();
        if later_success {
            let receipt = final_receipt();
            totals = totals.checked_with(&receipt).unwrap();
            priced = priced.checked_with(&receipt).unwrap();
            last = DetailedLastSettlement::Legacy(SettledAttempt {
                reference: AttemptRef {
                    revision: AccountingRevision(3),
                    request_id: receipt.request_id.clone(),
                    intent_digest: "a".repeat(64),
                },
                receipt_digest: receipt.digest().unwrap(),
            });
            last_legacy_receipt = Some(receipt);
            revision = 4;
        }
        let mut pending = None;
        let mut pending_receipt = None;
        if uncertain {
            let legacy = pending_inspection();
            let mut current = legacy.checkpoint.pending.unwrap();
            current.reference.revision = AccountingRevision(revision + 1);
            let receipt = legacy.pending_receipt.unwrap();
            totals = totals.checked_with(&receipt).unwrap();
            pending = Some(current);
            pending_receipt = Some(receipt);
            revision += 2;
        }
        DetailedAccountingInspection {
            checkpoint: DetailedAccountingCheckpoint::new(
                "owner".into(),
                None,
                AccountingRevision(revision),
                baseline,
                totals,
                pending,
                Some(last),
                Some(priced),
                Some(RefusalRollup::first(record).unwrap()),
            )
            .unwrap(),
            pending_receipt,
            last_legacy_receipt,
            inspection_digest: "c".repeat(64),
            qualification: InspectionQualification::VisibleValidated,
        }
    }

    #[test]
    fn detailed_status_qualifies_retained_refusal_without_fabricating_receipt_or_usage() {
        for (baseline, later, uncertain, knownness) in [
            (
                AccountingBaseline::FreshKnownZero,
                false,
                false,
                "unknown_usage",
            ),
            (
                AccountingBaseline::FreshKnownZero,
                true,
                false,
                "unknown_usage",
            ),
            (
                AccountingBaseline::UnknownLegacy,
                true,
                false,
                "unknown_legacy",
            ),
            (AccountingBaseline::UnknownLegacy, true, true, "uncertain"),
        ] {
            let inspection = refusal_inspection(baseline, later, uncertain);
            let expected = inspection
                .checkpoint
                .refusals()
                .unwrap()
                .latest()
                .digest()
                .to_owned();
            let args = arguments(true);
            let result = render_result(&args, project_detailed(&args, inspection.clone()));
            assert_eq!(result.exit_code, 0);
            assert!(result.stderr.is_empty());
            assert!(result.stdout.len() <= MAX_OUTPUT);
            let value: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(value["totals"]["knownness"], knownness);
            assert!(value["totals"]["ordinary"]["cost_microcents"].is_null());
            assert_eq!(
                value["retained_refusal"]["latest_settlement_digest"],
                expected
            );
            for key in [
                "generation_final_refusal",
                "billing_unknown",
                "usage_unknown",
                "policy_assumption",
                "visible_validated",
            ] {
                assert_eq!(value["retained_refusal"][key], true);
            }
            assert_eq!(value["retained_refusal"]["status"], 503);
            if later {
                assert_eq!(value["last_settlement"]["receipt"]["completed"], true);
                assert_eq!(value["known_priced_subtotals"]["ordinary_microcents"], 23);
                assert!(value["last_settlement"].get("disposition").is_none());
            } else {
                assert_eq!(
                    value["last_settlement"]["disposition"],
                    "final_generation_refusal"
                );
                assert!(value["last_settlement"].get("receipt").is_none());
                assert!(value["last_settlement"].get("receipt_digest").is_none());
            }
            if uncertain {
                assert_eq!(value["lifecycle"], "uncertain_receipt");
            }
            assert_eq!(
                value["inspection"]["provider_outcome"],
                "not_established_by_inspection"
            );
            assert_eq!(
                value["inspection"]["prior_publication_durability"],
                "not_established"
            );
            let args = arguments(false);
            let result = render_result(&args, project_detailed(&args, inspection));
            assert_eq!(result.exit_code, 0);
            assert!(result.stdout.is_ascii());
            let text = String::from_utf8(result.stdout).unwrap();
            assert!(text.contains("generation_final_refusal=true billing_unknown=true usage_unknown=true policy_assumption=true visible_validated=true"));
            assert!(text.contains(
                "does not establish zero provider usage, prior durability or replay permission"
            ));
        }
        let legacy = json_result(&arguments(true), empty_inspection());
        assert!(legacy.get("retained_refusal").is_none());
    }
}
