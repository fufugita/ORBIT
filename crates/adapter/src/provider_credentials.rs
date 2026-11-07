//! Exact provider credential bindings and private local persistence.

use crate::SecretBytes;
#[cfg(windows)]
use orbit_platform::fs::FileSnapshot as Stat;
#[cfg(unix)]
use rustix::fd::OwnedFd;
#[cfg(unix)]
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, fsync, mkdirat, open,
    openat, renameat, statat, unlinkat,
};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use windows::{Directory, StoreLock};
use zeroize::Zeroizing;

pub const MAX_PROVIDER_KEY_BYTES: usize = 16 * 1024;
pub const MAX_PROVIDER_RECORD_BYTES: usize = 32 * 1024;
pub const MAX_PROVIDER_RECORDS: usize = 128;
const MAGIC: &[u8; 8] = b"ORBPRV1\0";
const LOCK_NAME: &str = "store.lock";
const LOCK_WAIT: Duration = Duration::from_millis(250);
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

/// The caller supplies an already validated, canonical selected endpoint.
/// Every field participates in the binding; there is no wildcard identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAuthIdentity {
    provider_id: String,
    kind: String,
    endpoint: String,
    env: Option<String>,
}

impl ProviderAuthIdentity {
    pub fn new(
        provider_id: &str,
        kind: &str,
        canonical_endpoint: &str,
        env: Option<&str>,
    ) -> Result<Self, ProviderCredentialError> {
        if !valid_provider_id(provider_id)
            || !valid_id(kind, 64)
            || !valid_endpoint(canonical_endpoint)
            || env.is_some_and(|name| !valid_env(name))
        {
            return Err(ProviderCredentialError::InvalidIdentity);
        }
        Ok(Self {
            provider_id: provider_id.to_owned(),
            kind: kind.to_owned(),
            endpoint: canonical_endpoint.to_owned(),
            env: env.map(str::to_owned),
        })
    }

    pub fn declared_env(&self) -> Option<&str> {
        self.env.as_deref()
    }

    pub fn binding_id(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"orbit.provider-credential.v1\0");
        for field in [&self.provider_id, &self.kind, &self.endpoint] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.update([u8::from(self.env.is_some())]);
        if let Some(env) = &self.env {
            hash.update((env.len() as u64).to_be_bytes());
            hash.update(env.as_bytes());
        }
        hex::encode(hash.finalize())
    }

    fn file_name(&self) -> String {
        format!("{}.credential", self.binding_id())
    }
}

impl std::fmt::Debug for ProviderAuthIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderAuthIdentity")
            .field("binding", &self.binding_id())
            .finish()
    }
}

/// Opaque version of one published binding; no key digest is exposed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderCredentialRevision([u8; 32]);

impl std::fmt::Debug for ProviderCredentialRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderCredentialRevision[opaque]")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedRevision {
    Absent,
    Exact(ProviderCredentialRevision),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCredentialSource {
    None,
    Environment,
    Draft,
    Saved,
}

/// Nonserializable, noncloneable secret material, scoped to one invocation.
pub struct ResolvedProviderCredential {
    secret: Option<SecretBytes>,
    source: ProviderCredentialSource,
    revision: Option<ProviderCredentialRevision>,
}

impl ResolvedProviderCredential {
    pub fn source(&self) -> ProviderCredentialSource {
        self.source
    }

    pub fn revision(&self) -> Option<ProviderCredentialRevision> {
        self.revision
    }

    pub fn into_secret(self) -> Option<SecretBytes> {
        self.secret
    }
}

impl std::fmt::Debug for ResolvedProviderCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedProviderCredential")
            .field("source", &self.source)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCredentialStatus {
    NoAuth,
    Available {
        source: ProviderCredentialSource,
        revision: Option<ProviderCredentialRevision>,
    },
    Missing,
    Invalid(ProviderCredentialError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCredentialSaveResult {
    pub revision: ProviderCredentialRevision,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCredentialRemoveResult {
    Removed,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderCredentialError {
    #[error("Provider credential identity is invalid")]
    InvalidIdentity,
    #[error("Provider credential must be bounded, nonempty header-safe UTF-8")]
    InvalidKey,
    #[error("Required provider authentication is unavailable")]
    Missing,
    #[error("Provider credential environment lookup failed")]
    EnvironmentUnavailable,
    #[error("Provider credential directory is unsafe")]
    UnsafeDirectory,
    #[error("Provider credential file is unsafe")]
    UnsafeFile,
    #[error("Provider credential path changed during access")]
    PathChanged,
    #[error("Provider credential record is invalid")]
    InvalidRecord,
    #[error("Provider credential record does not match the selected binding")]
    IdentityMismatch,
    #[error("Provider credential store exceeds its bounded size or count")]
    LimitExceeded,
    #[error("Provider credential revision changed; inspect before retrying")]
    StaleRevision,
    #[error("Provider credential store is busy; retry after the current operation")]
    Busy,
    #[error("Provider credential storage I/O failed")]
    Io,
    #[error("Provider credential publication may have committed; inspect before retrying")]
    PublicationUncertain,
}

/// Uses `home/auth/providers`; construction performs no I/O or mutation.
#[derive(Debug, Clone)]
pub struct ProviderCredentialStore {
    home: PathBuf,
}

impl ProviderCredentialStore {
    pub fn new(home: &Path) -> Result<Self, ProviderCredentialError> {
        if !home.is_absolute()
            || home == Path::new("/")
            || home
                .components()
                .any(|part| {
                    #[cfg(windows)]
                    if matches!(part, Component::Prefix(prefix) if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_))) {
                        return false;
                    }
                    !matches!(part, Component::RootDir | Component::Normal(_))
                })
            || (cfg!(windows) && home.file_name().is_none())
        {
            return Err(ProviderCredentialError::UnsafeDirectory);
        }
        Ok(Self {
            home: home.to_path_buf(),
        })
    }

    /// Lookup returns owned zeroizing bytes; no process ENV is read or changed here.
    pub fn resolve_with<F>(
        &self,
        identity: &ProviderAuthIdentity,
        lookup: F,
    ) -> Result<ResolvedProviderCredential, ProviderCredentialError>
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        self.resolve_with_draft(identity, None, lookup)
    }

    /// A draft participates only when its entire identity matches the candidate.
    /// Nonempty ENV always precedes both draft and saved sources.
    pub fn resolve_with_draft<F>(
        &self,
        identity: &ProviderAuthIdentity,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
        lookup: F,
    ) -> Result<ResolvedProviderCredential, ProviderCredentialError>
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        self.resolve_inner(identity, draft, lookup, true)
    }

    fn resolve_inner<F>(
        &self,
        identity: &ProviderAuthIdentity,
        draft: Option<(&ProviderAuthIdentity, &SecretBytes)>,
        mut lookup: F,
        create_lock: bool,
    ) -> Result<ResolvedProviderCredential, ProviderCredentialError>
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        let Some(env) = identity.declared_env() else {
            return Ok(resolved(None, ProviderCredentialSource::None, None));
        };
        if let Some(secret) = lookup(env)?
            && !secret.is_empty()
        {
            validate_key(secret.expose())?;
            return Ok(resolved(
                Some(secret),
                ProviderCredentialSource::Environment,
                None,
            ));
        }
        if let Some((draft_identity, secret)) = draft
            && draft_identity == identity
        {
            validate_key(secret.expose())?;
            return Ok(resolved(
                Some(SecretBytes::new(secret.expose().to_vec())),
                ProviderCredentialSource::Draft,
                None,
            ));
        }
        let Some(directory) = Directory::open(&self.home, false)? else {
            return Err(ProviderCredentialError::Missing);
        };
        let lock = if create_lock {
            StoreLock::acquire(&directory)?
        } else {
            StoreLock::acquire_existing(&directory)?
        };
        directory.count_records()?;
        let stored = directory.read(identity)?;
        lock.check()?;
        let stored = stored.ok_or(ProviderCredentialError::Missing)?;
        directory.check_record(identity, Some(&stored))?;
        Ok(resolved(
            Some(stored.secret),
            ProviderCredentialSource::Saved,
            Some(stored.revision),
        ))
    }

    pub fn status_with<F>(
        &self,
        identity: &ProviderAuthIdentity,
        lookup: F,
    ) -> ProviderCredentialStatus
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        match self.resolve_with(identity, lookup) {
            Ok(value) if value.source == ProviderCredentialSource::None => {
                ProviderCredentialStatus::NoAuth
            }
            Ok(value) => ProviderCredentialStatus::Available {
                source: value.source,
                revision: value.revision,
            },
            Err(ProviderCredentialError::Missing) => ProviderCredentialStatus::Missing,
            Err(error) => ProviderCredentialStatus::Invalid(error),
        }
    }

    /// Inspect local readiness without creating directories, lock files or records.
    /// An existing store without its checked lock is conservatively invalid.
    pub fn status_read_only_with<F>(
        &self,
        identity: &ProviderAuthIdentity,
        lookup: F,
    ) -> ProviderCredentialStatus
    where
        F: FnMut(&str) -> Result<Option<SecretBytes>, ProviderCredentialError>,
    {
        match self.resolve_inner(identity, None, lookup, false) {
            Ok(value) if value.source == ProviderCredentialSource::None => {
                ProviderCredentialStatus::NoAuth
            }
            Ok(value) => ProviderCredentialStatus::Available {
                source: value.source,
                revision: value.revision,
            },
            Err(ProviderCredentialError::Missing) => ProviderCredentialStatus::Missing,
            Err(error) => ProviderCredentialStatus::Invalid(error),
        }
    }

    pub fn save(
        &self,
        identity: &ProviderAuthIdentity,
        secret: SecretBytes,
        expected: ExpectedRevision,
    ) -> Result<ProviderCredentialSaveResult, ProviderCredentialError> {
        if identity.env.is_none() {
            return Err(ProviderCredentialError::InvalidIdentity);
        }
        validate_key(secret.expose())?;
        let directory =
            Directory::open(&self.home, true)?.ok_or(ProviderCredentialError::UnsafeDirectory)?;
        let lock = StoreLock::acquire(&directory)?;
        let count = directory.count_records()?;
        let current = directory.read(identity)?;
        check_revision(current.as_ref(), expected)?;
        if let Some(current) = &current {
            if current.secret.expose() == secret.expose() {
                lock.check()?;
                return Ok(ProviderCredentialSaveResult {
                    revision: current.revision,
                    changed: false,
                });
            }
        } else if count >= MAX_PROVIDER_RECORDS {
            return Err(ProviderCredentialError::LimitExceeded);
        }
        let revision = fresh_revision(identity);
        let bytes = encode(identity, revision, secret.expose())?;
        directory.publish(identity, &bytes, current.as_ref(), &lock)?;
        Ok(ProviderCredentialSaveResult {
            revision,
            changed: true,
        })
    }

    pub fn remove(
        &self,
        identity: &ProviderAuthIdentity,
        expected: ExpectedRevision,
    ) -> Result<ProviderCredentialRemoveResult, ProviderCredentialError> {
        if identity.env.is_none() {
            return Err(ProviderCredentialError::InvalidIdentity);
        }
        let Some(directory) = Directory::open(&self.home, false)? else {
            check_revision(None, expected)?;
            return Ok(ProviderCredentialRemoveResult::Absent);
        };
        let lock = StoreLock::acquire(&directory)?;
        directory.count_records()?;
        let current = directory.read(identity)?;
        check_revision(current.as_ref(), expected)?;
        let Some(current) = current else {
            return Ok(ProviderCredentialRemoveResult::Absent);
        };
        lock.check()?;
        directory.check_record(identity, Some(&current))?;
        #[cfg(windows)]
        directory.remove_record(identity, &current, &lock)?;
        #[cfg(unix)]
        unlinkat(&*directory.fd, identity.file_name(), AtFlags::empty())
            .map_err(|_| ProviderCredentialError::Io)?;
        // Unlink is a publication point too; never report definite failure after it.
        #[cfg(unix)]
        directory
            .sync()
            .and_then(|()| lock.check())
            .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
        Ok(ProviderCredentialRemoveResult::Removed)
    }
}

fn resolved(
    secret: Option<SecretBytes>,
    source: ProviderCredentialSource,
    revision: Option<ProviderCredentialRevision>,
) -> ResolvedProviderCredential {
    ResolvedProviderCredential {
        secret,
        source,
        revision,
    }
}

fn check_revision(
    current: Option<&Stored>,
    expected: ExpectedRevision,
) -> Result<(), ProviderCredentialError> {
    match (current, expected) {
        (None, ExpectedRevision::Absent) => Ok(()),
        (Some(record), ExpectedRevision::Exact(revision)) if record.revision == revision => Ok(()),
        _ => Err(ProviderCredentialError::StaleRevision),
    }
}

fn validate_key(bytes: &[u8]) -> Result<(), ProviderCredentialError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_KEY_BYTES {
        return Err(ProviderCredentialError::InvalidKey);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ProviderCredentialError::InvalidKey)?;
    if text.chars().any(char::is_control) || text.trim().is_empty() {
        return Err(ProviderCredentialError::InvalidKey);
    }
    Ok(())
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.contains('/')
        && !value.chars().any(char::is_control)
}

fn valid_id(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && value != "."
        && value != ".."
}

fn valid_env(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()))
}

fn valid_endpoint(value: &str) -> bool {
    if value.len() > 8192
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains(['\\', '#'])
    {
        return false;
    }
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, tail)) = ipv6.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let port = if tail.is_empty() {
            None
        } else {
            let Some(port) = tail.strip_prefix(':') else {
                return false;
            };
            Some(port)
        };
        (host, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        {
            return false;
        }
        (host, port)
    };
    if host.is_empty() || port.is_some_and(|p| p.is_empty() || p.parse::<u16>().is_err()) {
        return false;
    }
    // Canonical URLs have complete percent escapes; reject encoded control bytes too.
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let (Some(a), Some(b)) = (bytes.next(), bytes.next()) else {
                return false;
            };
            let (Some(a), Some(b)) = ((a as char).to_digit(16), (b as char).to_digit(16)) else {
                return false;
            };
            if (a * 16 + b) < 32 || a * 16 + b == 127 {
                return false;
            }
        }
    }
    true
}

fn fresh_revision(identity: &ProviderAuthIdentity) -> ProviderCredentialRevision {
    let mut hash = Sha256::new();
    hash.update(b"orbit.provider-revision.v1\0");
    hash.update(identity.binding_id().as_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_be_bytes(),
    );
    hash.update(std::process::id().to_be_bytes());
    hash.update(NEXT_STAGE.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    ProviderCredentialRevision(hash.finalize().into())
}

fn encode(
    identity: &ProviderAuthIdentity,
    revision: ProviderCredentialRevision,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialError> {
    // Allocate once: reallocation must not leave an unzeroized copy of a key.
    let size = MAGIC.len()
        + 32
        + 5 * 4
        + identity.provider_id.len()
        + identity.kind.len()
        + identity.endpoint.len()
        + identity.env.as_ref().map_or(0, String::len)
        + secret.len();
    if size > MAX_PROVIDER_RECORD_BYTES {
        return Err(ProviderCredentialError::LimitExceeded);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&revision.0);
    for field in [
        identity.provider_id.as_bytes(),
        identity.kind.as_bytes(),
        identity.endpoint.as_bytes(),
        identity.env.as_deref().unwrap_or_default().as_bytes(),
        secret,
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

struct Stored {
    revision: ProviderCredentialRevision,
    secret: SecretBytes,
    stat: Stat,
}

fn decode(
    bytes: &[u8],
    identity: &ProviderAuthIdentity,
    stat: Stat,
) -> Result<Stored, ProviderCredentialError> {
    if bytes.len() < 40 || &bytes[..8] != MAGIC {
        return Err(ProviderCredentialError::InvalidRecord);
    }
    let mut revision = [0; 32];
    revision.copy_from_slice(&bytes[8..40]);
    let mut rest = &bytes[40..];
    for expected in [
        identity.provider_id.as_bytes(),
        identity.kind.as_bytes(),
        identity.endpoint.as_bytes(),
        identity.env.as_deref().unwrap_or_default().as_bytes(),
    ] {
        if take_field(&mut rest)? != expected {
            return Err(ProviderCredentialError::IdentityMismatch);
        }
    }
    let key = take_field(&mut rest)?;
    if !rest.is_empty() {
        return Err(ProviderCredentialError::InvalidRecord);
    }
    validate_key(key).map_err(|_| ProviderCredentialError::InvalidRecord)?;
    Ok(Stored {
        revision: ProviderCredentialRevision(revision),
        secret: SecretBytes::new(key.to_vec()),
        stat,
    })
}

fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], ProviderCredentialError> {
    let header: [u8; 4] = rest
        .get(..4)
        .ok_or(ProviderCredentialError::InvalidRecord)?
        .try_into()
        .map_err(|_| ProviderCredentialError::InvalidRecord)?;
    let length = u32::from_be_bytes(header) as usize;
    *rest = &rest[4..];
    let field = rest
        .get(..length)
        .ok_or(ProviderCredentialError::InvalidRecord)?;
    *rest = &rest[length..];
    Ok(field)
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum DirectoryPolicy {
    Ancestor,
    Home,
    Private,
}

#[cfg(unix)]
#[derive(Clone)]
struct Binding {
    parent: Arc<OwnedFd>,
    child: Arc<OwnedFd>,
    name: OsString,
    policy: DirectoryPolicy,
}

#[cfg(unix)]
struct Directory {
    fd: Arc<OwnedFd>,
    bindings: Vec<Binding>,
}

#[cfg(unix)]
impl Directory {
    fn open(home: &Path, create: bool) -> Result<Option<Self>, ProviderCredentialError> {
        let root = open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProviderCredentialError::UnsafeDirectory)?;
        let mut current = Self {
            fd: Arc::new(root),
            bindings: Vec::new(),
        };
        let names: Vec<_> = home
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(name.to_os_string()),
                _ => None,
            })
            .collect();
        for (index, name) in names.iter().enumerate() {
            let policy = if index + 1 == names.len() {
                DirectoryPolicy::Home
            } else {
                DirectoryPolicy::Ancestor
            };
            let Some(child) = current.child(name.clone(), false, policy)? else {
                return Ok(None);
            };
            current = child;
        }
        for name in ["auth", "providers"] {
            let Some(child) =
                current.child(OsString::from(name), create, DirectoryPolicy::Private)?
            else {
                return Ok(None);
            };
            current = child;
        }
        current.check()?;
        Ok(Some(current))
    }

    fn child(
        &self,
        name: OsString,
        create: bool,
        policy: DirectoryPolicy,
    ) -> Result<Option<Self>, ProviderCredentialError> {
        self.check()?;
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut created = false;
        let fd = match openat(&*self.fd, name.as_os_str(), flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match mkdirat(&*self.fd, name.as_os_str(), Mode::from_raw_mode(0o700)) {
                    Ok(()) => created = true,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(ProviderCredentialError::Io),
                }
                openat(&*self.fd, name.as_os_str(), flags, Mode::empty())
                    .map_err(|_| ProviderCredentialError::UnsafeDirectory)?
            }
            Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
        };
        let fd = Arc::new(fd);
        let mut bindings = self.bindings.clone();
        bindings.push(Binding {
            parent: self.fd.clone(),
            child: fd.clone(),
            name,
            policy,
        });
        let result = Self { fd, bindings };
        result.check()?;
        if created {
            self.sync()?;
        }
        Ok(Some(result))
    }

    fn check(&self) -> Result<(), ProviderCredentialError> {
        for binding in &self.bindings {
            let named = statat(
                &*binding.parent,
                binding.name.as_os_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| ProviderCredentialError::PathChanged)?;
            let held = fstat(&*binding.child).map_err(|_| ProviderCredentialError::Io)?;
            if !same_inode(&held, &named) {
                return Err(ProviderCredentialError::PathChanged);
            }
            check_directory(&held, binding.policy)?;
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), ProviderCredentialError> {
        self.check()?;
        let fd = openat(
            &*self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProviderCredentialError::Io)?;
        fsync(&fd).map_err(|_| ProviderCredentialError::Io)?;
        self.check()
    }

    fn read(
        &self,
        identity: &ProviderAuthIdentity,
    ) -> Result<Option<Stored>, ProviderCredentialError> {
        self.check()?;
        let name = identity.file_name();
        let fd = match openat(
            &*self.fd,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ProviderCredentialError::UnsafeFile),
        };
        let before = fstat(&fd).map_err(|_| ProviderCredentialError::Io)?;
        check_file(&before)?;
        if before.st_size < 0 || before.st_size as u64 > MAX_PROVIDER_RECORD_BYTES as u64 {
            return Err(ProviderCredentialError::LimitExceeded);
        }
        let mut file = File::from(fd);
        // Read into fixed storage: growing a secret Vec could free unwiped memory.
        let mut bytes = Zeroizing::new(vec![0; MAX_PROVIDER_RECORD_BYTES + 1]);
        let mut length = 0;
        loop {
            let read = file
                .read(&mut bytes[length..])
                .map_err(|_| ProviderCredentialError::Io)?;
            if read == 0 {
                break;
            }
            length += read;
            if length == bytes.len() {
                return Err(ProviderCredentialError::LimitExceeded);
            }
        }
        bytes.truncate(length);
        let after = fstat(&file).map_err(|_| ProviderCredentialError::Io)?;
        let named = statat(&*self.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ProviderCredentialError::PathChanged)?;
        if bytes.len() as u64 != before.st_size as u64
            || !same_file(&before, &after)
            || !same_file(&after, &named)
        {
            return Err(ProviderCredentialError::PathChanged);
        }
        self.check()?;
        decode(&bytes, identity, after).map(Some)
    }

    fn check_record(
        &self,
        identity: &ProviderAuthIdentity,
        expected: Option<&Stored>,
    ) -> Result<(), ProviderCredentialError> {
        self.check()?;
        match (
            statat(&*self.fd, identity.file_name(), AtFlags::SYMLINK_NOFOLLOW),
            expected,
        ) {
            (Err(rustix::io::Errno::NOENT), None) => Ok(()),
            (Ok(named), Some(record)) if same_file(&named, &record.stat) => check_file(&named),
            _ => Err(ProviderCredentialError::PathChanged),
        }
    }

    fn count_records(&self) -> Result<usize, ProviderCredentialError> {
        self.check()?;
        let fd = openat(
            &*self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProviderCredentialError::Io)?;
        let dir = Dir::new(fd).map_err(|_| ProviderCredentialError::Io)?;
        let mut count = 0;
        let mut entries = 0;
        for entry in dir {
            let entry = entry.map_err(|_| ProviderCredentialError::Io)?;
            let name = entry.file_name();
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            entries += 1;
            if entries > MAX_PROVIDER_RECORDS * 2 + 1 {
                return Err(ProviderCredentialError::LimitExceeded);
            }
            let record = bytes.len() == 75
                && bytes.ends_with(b".credential")
                && bytes[..64].iter().all(u8::is_ascii_hexdigit);
            if !record && bytes != LOCK_NAME.as_bytes() && !bytes.starts_with(b".pending-") {
                return Err(ProviderCredentialError::UnsafeFile);
            }
            let stat = statat(&*self.fd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            check_file(&stat)?;
            if stat.st_size < 0 || stat.st_size as u64 > MAX_PROVIDER_RECORD_BYTES as u64 {
                return Err(ProviderCredentialError::LimitExceeded);
            }
            if record {
                count += 1;
            }
            if count > MAX_PROVIDER_RECORDS {
                return Err(ProviderCredentialError::LimitExceeded);
            }
        }
        self.check()?;
        Ok(count)
    }

    fn publish(
        &self,
        identity: &ProviderAuthIdentity,
        bytes: &[u8],
        current: Option<&Stored>,
        lock: &StoreLock<'_>,
    ) -> Result<(), ProviderCredentialError> {
        self.publish_with(identity, bytes, current, lock, || {})
    }

    fn publish_with<F: FnOnce()>(
        &self,
        identity: &ProviderAuthIdentity,
        bytes: &[u8],
        current: Option<&Stored>,
        lock: &StoreLock<'_>,
        after_rename: F,
    ) -> Result<(), ProviderCredentialError> {
        lock.check()?;
        let name = format!(
            ".pending-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        );
        let fd = openat(
            &*self.fd,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ProviderCredentialError::Io)?;
        let mut file = File::from(fd);
        let result = (|| {
            check_file(&fstat(&file).map_err(|_| ProviderCredentialError::Io)?)?;
            file.write_all(bytes)
                .map_err(|_| ProviderCredentialError::Io)?;
            file.sync_all().map_err(|_| ProviderCredentialError::Io)?;
            let held = fstat(&file).map_err(|_| ProviderCredentialError::Io)?;
            check_file(&held)?;
            let named = statat(&*self.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            if !same_file(&held, &named) {
                return Err(ProviderCredentialError::PathChanged);
            }
            lock.check()?;
            self.check_record(identity, current)?;
            renameat(&*self.fd, name.as_str(), &*self.fd, identity.file_name())
                .map_err(|_| ProviderCredentialError::Io)?;
            Ok(())
        })();
        if let Err(error) = result {
            // Remove only the exact still-bound inode created by this operation.
            if let (Ok(held), Ok(named)) = (
                fstat(&file),
                statat(&*self.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW),
            ) && same_inode(&held, &named)
                && self.check().is_ok()
            {
                let _ = unlinkat(&*self.fd, name.as_str(), AtFlags::empty());
            }
            return Err(error);
        }
        after_rename();
        self.sync()
            .and_then(|()| lock.check())
            .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
        let held = fstat(&file).map_err(|_| ProviderCredentialError::PublicationUncertain)?;
        let named = statat(&*self.fd, identity.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
        if !same_file(&held, &named) || check_file(&held).is_err() {
            return Err(ProviderCredentialError::PublicationUncertain);
        }
        Ok(())
    }
}

/// A single per-store lock precedes every record access; there are no nested locks.
#[cfg(unix)]
struct StoreLock<'a> {
    directory: &'a Directory,
    file: File,
}

#[cfg(unix)]
impl<'a> StoreLock<'a> {
    fn acquire(directory: &'a Directory) -> Result<Self, ProviderCredentialError> {
        Self::open(directory, true)
    }

    fn acquire_existing(directory: &'a Directory) -> Result<Self, ProviderCredentialError> {
        Self::open(directory, false)
    }

    fn open(directory: &'a Directory, create: bool) -> Result<Self, ProviderCredentialError> {
        directory.check()?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE;
        }
        let fd = openat(&*directory.fd, LOCK_NAME, flags, Mode::from_raw_mode(0o600))
            .map_err(|_| ProviderCredentialError::UnsafeFile)?;
        let file = File::from(fd);
        check_file(&fstat(&file).map_err(|_| ProviderCredentialError::Io)?)?;
        let result = Self { directory, file };
        result.check()?;
        let started = Instant::now();
        loop {
            match flock(&result.file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::WOULDBLOCK) | Err(rustix::io::Errno::INTR) => {
                    if started.elapsed() >= LOCK_WAIT {
                        return Err(ProviderCredentialError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(ProviderCredentialError::Io),
            }
        }
        result.check()?;
        Ok(result)
    }

    fn check(&self) -> Result<(), ProviderCredentialError> {
        self.directory.check()?;
        let held = fstat(&self.file).map_err(|_| ProviderCredentialError::Io)?;
        check_file(&held)?;
        let named = statat(&*self.directory.fd, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ProviderCredentialError::PathChanged)?;
        if !same_file(&held, &named) || held.st_size != 0 {
            return Err(ProviderCredentialError::PathChanged);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn check_directory(stat: &Stat, policy: DirectoryPolicy) -> Result<(), ProviderCredentialError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(ProviderCredentialError::UnsafeDirectory);
    }
    if !matches!(policy, DirectoryPolicy::Ancestor)
        && (stat.st_uid != rustix::process::geteuid().as_raw()
            || match policy {
                DirectoryPolicy::Private => stat.st_mode & 0o7777 != 0o700,
                _ => stat.st_mode & 0o7022 != 0,
            })
    {
        return Err(ProviderCredentialError::UnsafeDirectory);
    }
    Ok(())
}

#[cfg(unix)]
fn check_file(stat: &Stat) -> Result<(), ProviderCredentialError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(ProviderCredentialError::UnsafeFile);
    }
    Ok(())
}

#[cfg(unix)]
fn same_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && FileType::from_raw_mode(a.st_mode) == FileType::from_raw_mode(b.st_mode)
}

#[cfg(unix)]
fn same_file(a: &Stat, b: &Stat) -> bool {
    same_inode(a, b)
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

#[cfg(windows)]
mod windows {
    use super::*;
    use orbit_platform::fs::{
        Directory as PrivateDirectory, FileIdentity, InspectionLimits, LockMode, OwnedContainer,
        PrivateFileAccess, PublishError, RemovalError, StateLock,
    };
    use std::ffi::OsStr;
    use std::io;

    pub(super) struct Directory {
        home: OwnedContainer,
        auth: PrivateDirectory,
        records: PrivateDirectory,
    }

    impl Directory {
        pub(super) fn open(
            home: &Path,
            create: bool,
        ) -> Result<Option<Self>, ProviderCredentialError> {
            let container = match OwnedContainer::open(home) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
            };
            let auth_path = home.join("auth");
            let auth = match PrivateDirectory::open(&auth_path) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound && !create => {
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match PrivateDirectory::create(&auth_path) {
                        Ok(value) => value,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            PrivateDirectory::open(&auth_path)
                                .map_err(|_| ProviderCredentialError::UnsafeDirectory)?
                        }
                        Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
                    }
                }
                Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
            };
            container
                .check()
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            let records = match auth.child(OsStr::new("providers"), false) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound && !create => {
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match auth.child(OsStr::new("providers"), true) {
                        Ok(value) => value,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => auth
                            .child(OsStr::new("providers"), false)
                            .map_err(|_| ProviderCredentialError::UnsafeDirectory)?,
                        Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
                    }
                }
                Err(_) => return Err(ProviderCredentialError::UnsafeDirectory),
            };
            let value = Self {
                home: container,
                auth,
                records,
            };
            value.check()?;
            Ok(Some(value))
        }

        pub(super) fn check(&self) -> Result<(), ProviderCredentialError> {
            self.home
                .check()
                .and_then(|()| self.auth.check())
                .and_then(|()| self.records.check())
                .map_err(|_| ProviderCredentialError::PathChanged)
        }

        pub(super) fn read(
            &self,
            identity: &ProviderAuthIdentity,
        ) -> Result<Option<Stored>, ProviderCredentialError> {
            self.check()?;
            let name = identity.file_name();
            let mut file = match self.records.open_file(OsStr::new(&name)) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(ProviderCredentialError::UnsafeFile),
            };
            let before = file
                .snapshot()
                .map_err(|_| ProviderCredentialError::UnsafeFile)?;
            if before.length > MAX_PROVIDER_RECORD_BYTES as u64 {
                return Err(ProviderCredentialError::LimitExceeded);
            }
            // One fixed caller-owned allocation, zeroized on every return path.
            let mut bytes = Zeroizing::new(vec![0; MAX_PROVIDER_RECORD_BYTES + 1]);
            let mut length = 0;
            loop {
                let count = file
                    .read_into(&mut bytes[length..])
                    .map_err(|_| ProviderCredentialError::Io)?;
                if count == 0 {
                    break;
                }
                length += count;
                if length == bytes.len() {
                    return Err(ProviderCredentialError::LimitExceeded);
                }
            }
            let after = file
                .snapshot()
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            drop(file);
            let named = self
                .records
                .open_file(OsStr::new(&name))
                .and_then(|file| file.snapshot())
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            if length as u64 != before.length || before != after || after != named {
                return Err(ProviderCredentialError::PathChanged);
            }
            self.check()?;
            decode(&bytes[..length], identity, after).map(Some)
        }

        pub(super) fn check_record(
            &self,
            identity: &ProviderAuthIdentity,
            expected: Option<&Stored>,
        ) -> Result<(), ProviderCredentialError> {
            self.check()?;
            match (
                self.records.open_file(OsStr::new(&identity.file_name())),
                expected,
            ) {
                (Err(error), None) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                (Ok(file), Some(record)) => {
                    let snapshot = file
                        .snapshot()
                        .map_err(|_| ProviderCredentialError::UnsafeFile)?;
                    if snapshot == record.stat {
                        Ok(())
                    } else {
                        Err(ProviderCredentialError::PathChanged)
                    }
                }
                _ => Err(ProviderCredentialError::PathChanged),
            }
        }

        pub(super) fn count_records(&self) -> Result<usize, ProviderCredentialError> {
            self.check()?;
            let inspection = self
                .records
                .inspect_private_tree(InspectionLimits {
                    max_entries: MAX_PROVIDER_RECORDS * 2 + 1,
                    max_name_bytes: 128 * 1024,
                    max_depth: 1,
                })
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::InvalidInput {
                        ProviderCredentialError::LimitExceeded
                    } else {
                        ProviderCredentialError::UnsafeFile
                    }
                })?;
            let mut count = 0;
            for entry in inspection.entries {
                let name = entry
                    .relative_path
                    .to_str()
                    .ok_or(ProviderCredentialError::UnsafeFile)?;
                if entry.directory || entry.file_access != Some(PrivateFileAccess::FullControl) {
                    return Err(ProviderCredentialError::UnsafeFile);
                }
                let bytes = name.as_bytes();
                let record = bytes.len() == 75
                    && bytes.ends_with(b".credential")
                    && bytes[..64].iter().all(u8::is_ascii_hexdigit);
                // Uncertain replacement retains the foundation's checked backup.
                if !record
                    && name != LOCK_NAME
                    && !name.starts_with(".pending-")
                    && !name.starts_with(".previous-")
                {
                    return Err(ProviderCredentialError::UnsafeFile);
                }
                if entry
                    .snapshot
                    .ok_or(ProviderCredentialError::UnsafeFile)?
                    .length
                    > MAX_PROVIDER_RECORD_BYTES as u64
                {
                    return Err(ProviderCredentialError::LimitExceeded);
                }
                count += usize::from(record);
                if count > MAX_PROVIDER_RECORDS {
                    return Err(ProviderCredentialError::LimitExceeded);
                }
            }
            self.check()?;
            Ok(count)
        }

        pub(super) fn publish(
            &self,
            identity: &ProviderAuthIdentity,
            bytes: &[u8],
            current: Option<&Stored>,
            lock: &StoreLock<'_>,
        ) -> Result<(), ProviderCredentialError> {
            self.publish_with(identity, bytes, current, lock, || {})
        }

        pub(super) fn publish_with<F: FnOnce()>(
            &self,
            identity: &ProviderAuthIdentity,
            bytes: &[u8],
            current: Option<&Stored>,
            lock: &StoreLock<'_>,
            after_rename: F,
        ) -> Result<(), ProviderCredentialError> {
            lock.check()?;
            if !lock.exclusive {
                return Err(ProviderCredentialError::UnsafeFile);
            }
            let pending = format!(
                ".pending-{}-{}",
                std::process::id(),
                NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
            );
            let mut file = self
                .records
                .create_file(OsStr::new(&pending))
                .map_err(|_| ProviderCredentialError::Io)?;
            let candidate = file.identity();
            let prepared = file
                .write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProviderCredentialError::Io)
                .and_then(|()| lock.check())
                .and_then(|()| self.check_record(identity, current));
            if let Err(error) = prepared {
                drop(file);
                self.discard_candidate(&pending, candidate, lock);
                return Err(error);
            }
            let name = identity.file_name();
            let result = match current {
                Some(record) => self.records.replace(
                    &file,
                    OsStr::new(&name),
                    record.stat.identity,
                    &lock.guard,
                ),
                None => self.records.publish_new(&file, OsStr::new(&name)),
            };
            let publication = match result {
                Ok(value) => value,
                Err(PublishError::Unchanged(_)) => {
                    drop(file);
                    self.discard_candidate(&pending, candidate, lock);
                    return Err(ProviderCredentialError::Io);
                }
                Err(PublishError::Uncertain { .. }) => {
                    return Err(ProviderCredentialError::PublicationUncertain);
                }
            };
            // Close the DELETE-capable candidate before opening a no-delete-sharing reader.
            let published = file
                .snapshot()
                .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
            drop(file);
            after_rename();
            lock.check()
                .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
            let named = self
                .records
                .open_file(OsStr::new(&name))
                .and_then(|file| file.snapshot())
                .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
            if named != published || named.identity != publication.identity {
                return Err(ProviderCredentialError::PublicationUncertain);
            }
            // Domain acceptance precedes removal of the identity-bound old record.
            if let (Some(backup), Some(old)) = (publication.original_backup, current) {
                let file = self
                    .records
                    .open_for_rename(&backup, old.stat.identity, &lock.guard)
                    .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
                self.records
                    .remove_file(file)
                    .map_err(|_| ProviderCredentialError::PublicationUncertain)?;
            }
            lock.check()
                .map_err(|_| ProviderCredentialError::PublicationUncertain)
        }

        fn discard_candidate(&self, name: &str, expected: FileIdentity, lock: &StoreLock<'_>) {
            if lock.check().is_ok()
                && let Ok(file) =
                    self.records
                        .open_for_rename(OsStr::new(name), expected, &lock.guard)
            {
                let _ = self.records.remove_file(file);
            }
        }

        pub(super) fn remove_record(
            &self,
            identity: &ProviderAuthIdentity,
            current: &Stored,
            lock: &StoreLock<'_>,
        ) -> Result<(), ProviderCredentialError> {
            lock.check()?;
            let file = self
                .records
                .open_for_rename(
                    OsStr::new(&identity.file_name()),
                    current.stat.identity,
                    &lock.guard,
                )
                .map_err(|_| ProviderCredentialError::PathChanged)?;
            self.records
                .remove_file(file)
                .map_err(|error| match error {
                    RemovalError::Unchanged(_) => ProviderCredentialError::Io,
                    RemovalError::Uncertain { .. } => ProviderCredentialError::PublicationUncertain,
                })?;
            lock.check()
                .map_err(|_| ProviderCredentialError::PublicationUncertain)
        }
    }

    pub(super) struct StoreLock<'a> {
        directory: &'a Directory,
        guard: StateLock,
        exclusive: bool,
    }

    impl<'a> StoreLock<'a> {
        pub(super) fn acquire(directory: &'a Directory) -> Result<Self, ProviderCredentialError> {
            Self::open(directory, true)
        }
        pub(super) fn acquire_existing(
            directory: &'a Directory,
        ) -> Result<Self, ProviderCredentialError> {
            Self::open(directory, false)
        }
        fn open(directory: &'a Directory, create: bool) -> Result<Self, ProviderCredentialError> {
            directory.check()?;
            let started = Instant::now();
            let mode = if create {
                LockMode::Exclusive
            } else {
                LockMode::Shared
            };
            loop {
                let result = if create {
                    directory.records.try_lock(OsStr::new(LOCK_NAME), mode)
                } else {
                    directory
                        .records
                        .open_lock_existing(OsStr::new(LOCK_NAME), mode)
                };
                match result {
                    Ok(guard) => {
                        let result = Self {
                            directory,
                            guard,
                            exclusive: create,
                        };
                        result.check()?;
                        return Ok(result);
                    }
                    Err(error)
                        if error.raw_os_error() == Some(33)
                            || error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::Interrupted =>
                    {
                        if started.elapsed() >= LOCK_WAIT {
                            return Err(ProviderCredentialError::Busy);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return Err(ProviderCredentialError::UnsafeFile),
                }
            }
        }
        pub(super) fn check(&self) -> Result<(), ProviderCredentialError> {
            self.directory.check()?;
            // The held guard denies delete sharing, pins the name, and validates zero length.
            self.guard
                .check()
                .map_err(|_| ProviderCredentialError::PathChanged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::fs::{DirBuilder, OpenOptions};
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    struct Home(PathBuf);

    impl Home {
        fn new() -> Self {
            for _ in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "orbit-provider-held-test-{}-{}",
                    std::process::id(),
                    NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
                ));
                match create_directory(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => panic!("could not create disposable storage home"),
                }
            }
            panic!("disposable storage name limit reached")
        }

        fn store(&self) -> ProviderCredentialStore {
            ProviderCredentialStore::new(&self.0).unwrap()
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> ProviderAuthIdentity {
        ProviderAuthIdentity::new(
            "held-test",
            "openai-compatible",
            "https://provider.invalid/v1/",
            Some("TEST_TOKEN"),
        )
        .unwrap()
    }

    fn secret() -> SecretBytes {
        SecretBytes::new(b"synthetic-held-secret".to_vec())
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        #[cfg(unix)]
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
        }
        #[cfg(windows)]
        {
            let parent = orbit_platform::fs::Directory::open(path.parent().unwrap()).unwrap();
            let mut file = parent.create_file(path.file_name().unwrap()).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    #[test]
    fn provider_storage_held_directory_rejects_inode_substitution() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let providers = home.0.join("auth/providers");
            fs::rename(&providers, home.0.join("auth/retained")).unwrap();
            DirBuilder::new().mode(0o700).create(&providers).unwrap();
            assert_eq!(directory.check(), Err(ProviderCredentialError::PathChanged));
            assert!(home.0.join("auth/retained").exists());
        }
        #[cfg(windows)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let providers = home.0.join("auth/providers");
            let target = home.0.join("auth/retained");
            let before = object_identity(&providers);
            let security = acl_snapshot(&providers);
            blocked_rename(&providers, &target);
            assert!(create_directory(&providers).is_err());
            assert_eq!(directory.check(), Ok(()));
            assert_eq!(object_identity(&providers), before);
            assert_eq!(acl_snapshot(&providers), security);
            drop(directory);
            rename_roundtrip(&providers, &target, before, &security);
        }
    }

    #[test]
    fn provider_storage_held_home_rejects_root_substitution() {
        #[cfg(unix)]
        {
            let base = Home::new();
            let home = base.0.join("home");
            DirBuilder::new().mode(0o700).create(&home).unwrap();
            let directory = Directory::open(&home, true).unwrap().unwrap();
            fs::rename(&home, base.0.join("retained")).unwrap();
            DirBuilder::new().mode(0o700).create(&home).unwrap();
            assert_eq!(directory.check(), Err(ProviderCredentialError::PathChanged));
        }
        #[cfg(windows)]
        {
            let base = Home::new();
            let home = base.0.join("home");
            create_directory(&home).unwrap();
            let directory = Directory::open(&home, true).unwrap().unwrap();
            let target = base.0.join("retained");
            let before = object_identity(&home);
            let security = acl_snapshot(&home);
            blocked_rename(&home, &target);
            assert!(create_directory(&home).is_err());
            assert_eq!(directory.check(), Ok(()));
            assert_eq!(object_identity(&home), before);
            assert_eq!(acl_snapshot(&home), security);
            drop(directory);
            rename_roundtrip(&home, &target, before, &security);
        }
    }

    #[test]
    fn provider_storage_lock_rejects_named_inode_substitution() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let lock = StoreLock::acquire(&directory).unwrap();
            fs::rename(
                home.0.join("auth/providers/store.lock"),
                home.0.join("auth/providers/retained.lock"),
            )
            .unwrap();
            private_file(&home.0.join("auth/providers/store.lock"), b"");
            assert_eq!(lock.check(), Err(ProviderCredentialError::PathChanged));
        }
        #[cfg(windows)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let lock = StoreLock::acquire(&directory).unwrap();
            let path = home.0.join("auth/providers/store.lock");
            let target = home.0.join("auth/providers/retained.lock");
            let before = object_identity(&path);
            let security = acl_snapshot(&path);
            blocked_rename(&path, &target);
            assert_eq!(lock.check(), Ok(()));
            assert_eq!(object_identity(&path), before);
            assert_eq!(fs::metadata(&path).unwrap().len(), 0);
            assert_eq!(acl_snapshot(&path), security);
            drop(lock);
            rename_roundtrip(&path, &target, before, &security);
        }
    }

    #[test]
    fn provider_storage_record_recheck_rejects_inode_substitution() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let identity = identity();
            home.store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let directory = Directory::open(&home.0, false).unwrap().unwrap();
            let _lock = StoreLock::acquire(&directory).unwrap();
            let held = directory.read(&identity).unwrap().unwrap();
            let path = home.0.join("auth/providers").join(identity.file_name());
            let bytes = Zeroizing::new(fs::read(&path).unwrap());
            fs::rename(&path, home.0.join("auth/providers/retained.credential")).unwrap();
            private_file(&path, &bytes);
            assert_eq!(
                directory.check_record(&identity, Some(&held)),
                Err(ProviderCredentialError::PathChanged)
            );
        }
        #[cfg(windows)]
        {
            let home = Home::new();
            let identity = identity();
            home.store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let directory = Directory::open(&home.0, false).unwrap().unwrap();
            let _lock = StoreLock::acquire(&directory).unwrap();
            let held = directory.read(&identity).unwrap().unwrap();
            let path = home.0.join("auth/providers").join(identity.file_name());
            let bytes = Zeroizing::new(fs::read(&path).unwrap());
            let retained = home.0.join("auth/providers/retained.credential");
            fs::rename(&path, &retained).unwrap();
            private_file(&path, &bytes);
            assert_eq!(
                directory.check_record(&identity, Some(&held)),
                Err(ProviderCredentialError::PathChanged)
            );
            assert_eq!(*Zeroizing::new(fs::read(&retained).unwrap()), *bytes);
        }
    }

    #[test]
    fn provider_storage_foreign_ownership_is_rejected_without_privileged_fixture() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let mut stat = fstat(&*directory.fd).unwrap();
            stat.st_uid = stat.st_uid.wrapping_add(1);
            assert_eq!(
                check_directory(&stat, DirectoryPolicy::Private),
                Err(ProviderCredentialError::UnsafeDirectory)
            );
            let lock = StoreLock::acquire(&directory).unwrap();
            let mut stat = fstat(&lock.file).unwrap();
            stat.st_uid = stat.st_uid.wrapping_add(1);
            assert_eq!(check_file(&stat), Err(ProviderCredentialError::UnsafeFile));
        }
        #[cfg(windows)]
        {
            let home = Home::new();
            let directory = Directory::open(&home.0, true).unwrap().unwrap();
            let lock = StoreLock::acquire(&directory).unwrap();
            let owner = current_sid();
            let foreign_owner = "S-1-5-32-544";
            assert_ne!(owner, foreign_owner);
            let restore = format!("*{owner}");
            let providers = home.0.join("auth/providers");
            let original = acl_snapshot(&providers);
            assert_eq!(owner_sid(&providers), owner);
            icacls(&providers, &["/setowner", "*S-1-5-32-544"]);
            let foreign = acl_snapshot(&providers);
            assert_eq!(owner_sid(&providers), foreign_owner);
            assert_ne!(foreign, original);
            assert!(directory.check().is_err());
            assert_eq!(owner_sid(&providers), foreign_owner);
            assert_eq!(acl_snapshot(&providers), foreign);
            icacls(&providers, &["/setowner", &restore]);
            assert_eq!(owner_sid(&providers), owner);
            assert_eq!(acl_snapshot(&providers), original);
            let path = providers.join("store.lock");
            let original = acl_snapshot(&path);
            assert_eq!(owner_sid(&path), owner);
            icacls(&path, &["/setowner", "*S-1-5-32-544"]);
            let foreign = acl_snapshot(&path);
            assert_eq!(owner_sid(&path), foreign_owner);
            assert_ne!(foreign, original);
            assert_eq!(lock.check(), Err(ProviderCredentialError::PathChanged));
            assert_eq!(owner_sid(&path), foreign_owner);
            assert_eq!(acl_snapshot(&path), foreign);
            assert_eq!(fs::metadata(&path).unwrap().len(), 0);
            icacls(&path, &["/setowner", &restore]);
            assert_eq!(owner_sid(&path), owner);
            assert_eq!(acl_snapshot(&path), original);
        }
    }

    #[test]
    fn provider_storage_lock_wait_is_bounded_and_leaves_record_unchanged() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let identity = identity();
            home.store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let before = Zeroizing::new(
                fs::read(home.0.join("auth/providers").join(identity.file_name())).unwrap(),
            );
            let directory = Directory::open(&home.0, false).unwrap().unwrap();
            let _lock = StoreLock::acquire(&directory).unwrap();
            assert_eq!(
                home.store()
                    .resolve_with(&identity, |_| Ok(None))
                    .unwrap_err(),
                ProviderCredentialError::Busy
            );
            let after = Zeroizing::new(
                fs::read(home.0.join("auth/providers").join(identity.file_name())).unwrap(),
            );
            assert_eq!(*before, *after);
        }
        #[cfg(windows)]
        {
            use std::process::{Command, Stdio};
            let home = Home::new();
            let identity = identity();
            home.store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let path = home.0.join("auth/providers").join(identity.file_name());
            let before = Zeroizing::new(fs::read(&path).unwrap());
            let security = acl_snapshot(&path);
            let mut child = ChildGuard(Some(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "provider_credentials::tests::provider_storage_lock_child",
                        "--test-threads=1",
                    ])
                    .env("ORBIT_PROVIDER_STORAGE_CHILD", &home.0)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            ));
            let started = Instant::now();
            while !home.0.join("child-ready").exists() {
                assert!(child.child().try_wait().unwrap().is_none());
                assert!(started.elapsed() < Duration::from_secs(5));
                std::thread::sleep(Duration::from_millis(5));
            }
            let started = Instant::now();
            assert_eq!(
                home.store()
                    .resolve_with(&identity, |_| Ok(None))
                    .unwrap_err(),
                ProviderCredentialError::Busy
            );
            assert!(started.elapsed() >= LOCK_WAIT && started.elapsed() < Duration::from_secs(2));
            assert_eq!(*Zeroizing::new(fs::read(&path).unwrap()), *before);
            assert_eq!(acl_snapshot(&path), security);
            fs::write(home.0.join("child-release"), b"release").unwrap();
            let started = Instant::now();
            loop {
                if let Some(status) = child.child().try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(started.elapsed() < Duration::from_secs(5));
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                home.store()
                    .resolve_with(&identity, |_| Ok(None))
                    .unwrap()
                    .source(),
                ProviderCredentialSource::Saved
            );
        }
    }

    #[test]
    fn provider_storage_post_rename_failure_reports_uncertainty_and_retains_publication() {
        #[cfg(unix)]
        {
            let home = Home::new();
            let identity = identity();
            let first = home
                .store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let directory = Directory::open(&home.0, false).unwrap().unwrap();
            let lock = StoreLock::acquire(&directory).unwrap();
            let current = directory.read(&identity).unwrap().unwrap();
            assert_eq!(current.revision, first.revision);
            let replacement = SecretBytes::new(b"synthetic-replacement-secret".to_vec());
            let revision = fresh_revision(&identity);
            let bytes = encode(&identity, revision, replacement.expose()).unwrap();
            let result = directory.publish_with(&identity, &bytes, Some(&current), &lock, || {
                fs::rename(home.0.join("auth/providers"), home.0.join("auth/retained")).unwrap();
                DirBuilder::new()
                    .mode(0o700)
                    .create(home.0.join("auth/providers"))
                    .unwrap();
            });
            assert_eq!(result, Err(ProviderCredentialError::PublicationUncertain));
            let retained = home.0.join("auth/retained").join(identity.file_name());
            let retained_bytes = Zeroizing::new(fs::read(retained).unwrap());
            assert_eq!(*retained_bytes, *bytes);
            assert!(
                !home
                    .0
                    .join("auth/providers")
                    .join(identity.file_name())
                    .exists()
            );
        }
        #[cfg(windows)]
        {
            let home = Home::new();
            let identity = identity();
            let first = home
                .store()
                .save(&identity, secret(), ExpectedRevision::Absent)
                .unwrap();
            let directory = Directory::open(&home.0, false).unwrap().unwrap();
            let lock = StoreLock::acquire(&directory).unwrap();
            let current = directory.read(&identity).unwrap().unwrap();
            assert_eq!(current.revision, first.revision);
            let replacement = SecretBytes::new(b"synthetic-replacement-secret".to_vec());
            let bytes = encode(&identity, fresh_revision(&identity), replacement.expose()).unwrap();
            let providers = home.0.join("auth/providers");
            let original_policy = acl_snapshot(&providers);
            let mut callback_ran = false;
            let mut unsafe_policy = String::new();
            let result = directory.publish_with(&identity, &bytes, Some(&current), &lock, || {
                icacls(&providers, &["/grant", "*S-1-1-0:(OI)(CI)F"]);
                unsafe_policy = unsafe_directory_policy(&providers);
                assert_ne!(unsafe_policy, original_policy);
                callback_ran = true;
            });
            assert!(
                callback_ran,
                "must reach the intended post-publication hook"
            );
            assert!(!unsafe_policy.is_empty());
            assert_eq!(result, Err(ProviderCredentialError::PublicationUncertain));
            assert_eq!(unsafe_directory_policy(&providers), unsafe_policy);
            let retained = Zeroizing::new(fs::read(providers.join(identity.file_name())).unwrap());
            assert_eq!(*retained, *bytes);
            let backups: Vec<_> = fs::read_dir(&providers)
                .unwrap()
                .map(|v| v.unwrap().path())
                .filter(|v| {
                    v.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".previous-")
                })
                .collect();
            assert_eq!(backups.len(), 1);
            let original = Zeroizing::new(fs::read(&backups[0]).unwrap());
            assert_eq!(
                *original,
                *encode(&identity, first.revision, secret().expose()).unwrap()
            );
            icacls(&providers, &["/remove:g", "*S-1-1-0"]);
            assert_eq!(acl_snapshot(&providers), original_policy);
        }
    }
    #[cfg(unix)]
    fn create_directory(path: &Path) -> std::io::Result<()> {
        DirBuilder::new().mode(0o700).create(path)
    }

    #[cfg(windows)]
    fn create_directory(path: &Path) -> std::io::Result<()> {
        orbit_platform::fs::Directory::create(path).map(drop)
    }

    #[cfg(windows)]
    fn fixture_command(
        operation: &'static str,
        program: &Path,
        arguments: &[&std::ffi::OsStr],
        path: Option<&Path>,
    ) -> std::process::Output {
        use std::process::{Command, Stdio};
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = path {
            command.env("ORBIT_TEST_ACL_PATH", path);
        }
        let mut child = ChildGuard(Some(command.spawn().unwrap()));
        let started = Instant::now();
        loop {
            match child.child().try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => {
                    let cleanup = child.stop();
                    panic!("fixture polling failed: {error}; cleanup: {cleanup:?}");
                }
            }
            if started.elapsed() > Duration::from_secs(10) {
                let cleanup = child.stop();
                panic!("fixture command timed out; cleanup: {cleanup:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // The terminal state was observed before moving out of the ownership guard.
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        let diagnostic = |bytes: &[u8]| {
            let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
            let mut clipped = String::new();
            for character in text.chars() {
                let character =
                    if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                        '\u{fffd}'
                    } else {
                        character
                    };
                if clipped.len() + character.len_utf8() > 4096 {
                    break;
                }
                clipped.push(character);
            }
            clipped
        };
        assert!(
            output.status.success(),
            "native fixture command failed: program={} operation={operation} status={}\nstdout (at most 4096 bytes):\n{}\nstderr (at most 4096 bytes):\n{}",
            program.file_name().unwrap_or_default().to_string_lossy(),
            output.status,
            diagnostic(&output.stdout),
            diagnostic(&output.stderr)
        );
        assert!(output.stdout.len() <= 16384 && output.stderr.len() <= 16384);
        output
    }

    #[cfg(windows)]
    fn system_program(name: &str) -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join(name)
    }

    #[cfg(windows)]
    fn acl_snapshot(path: &Path) -> String {
        use std::ffi::OsStr;
        let output = fixture_command(
            "acl_snapshot",
            &system_program("WindowsPowerShell/v1.0/powershell.exe"),
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-Command"),
                OsStr::new(
                    "$ErrorActionPreference='Stop'; (Get-Acl -LiteralPath $env:ORBIT_TEST_ACL_PATH).Sddl",
                ),
            ],
            Some(path),
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[cfg(windows)]
    fn owner_sid(path: &Path) -> String {
        use std::ffi::OsStr;
        let output = fixture_command(
            "owner_sid",
            &system_program("WindowsPowerShell/v1.0/powershell.exe"),
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-Command"),
                OsStr::new(
                    "$ErrorActionPreference='Stop'; (Get-Acl -LiteralPath $env:ORBIT_TEST_ACL_PATH).GetOwner([Security.Principal.SecurityIdentifier]).Value",
                ),
            ],
            Some(path),
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[cfg(windows)]
    fn unsafe_directory_policy(path: &Path) -> String {
        use std::ffi::OsStr;
        let output = fixture_command(
            "unsafe_directory_policy",
            &system_program("WindowsPowerShell/v1.0/powershell.exe"),
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-Command"),
                OsStr::new(
                    "$ErrorActionPreference='Stop'; $acl=Get-Acl -LiteralPath $env:ORBIT_TEST_ACL_PATH; $allow=@($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' -and $_.AccessControlType -eq 'Allow' -and (([int]$_.PropagationFlags -band 2) -eq 0) -and (([int64]$_.FileSystemRights.value__ -band 2) -ne 0) }); if($allow.Count -lt 1){throw 'Missing effective Everyone write grant'}; $acl.Sddl",
                ),
            ],
            Some(path),
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[cfg(windows)]
    fn object_identity(path: &Path) -> orbit_platform::fs::FileIdentity {
        use orbit_platform::fs::SourceDirectory;
        if fs::symlink_metadata(path).unwrap().is_dir() {
            SourceDirectory::open(path).unwrap().identity()
        } else {
            SourceDirectory::open(path.parent().unwrap())
                .unwrap()
                .open_file(path.file_name().unwrap())
                .unwrap()
                .identity()
        }
    }

    #[cfg(windows)]
    fn blocked_rename(path: &Path, target: &Path) {
        assert!(!target.exists());
        let error = fs::rename(path, target).unwrap_err();
        eprintln!(
            "blocked rename native_error={:?} kind={:?}",
            error.raw_os_error(),
            error.kind()
        );
        assert!(error.raw_os_error().is_some());
        assert!(path.exists() && !target.exists());
    }

    #[cfg(windows)]
    fn rename_roundtrip(
        path: &Path,
        target: &Path,
        identity: orbit_platform::fs::FileIdentity,
        security: &str,
    ) {
        fs::rename(path, target).unwrap();
        assert!(!path.exists());
        assert_eq!(object_identity(target), identity);
        assert_eq!(acl_snapshot(target), security);
        fs::rename(target, path).unwrap();
        assert!(!target.exists());
        assert_eq!(object_identity(path), identity);
        assert_eq!(acl_snapshot(path), security);
    }

    #[cfg(windows)]
    fn icacls(path: &Path, arguments: &[&str]) {
        use std::ffi::OsStr;
        let mut args = vec![path.as_os_str()];
        args.extend(arguments.iter().map(OsStr::new));
        fixture_command("icacls", &system_program("icacls.exe"), &args, None);
    }

    #[cfg(windows)]
    fn current_sid() -> String {
        use std::ffi::OsStr;
        let output = fixture_command(
            "current_sid",
            &system_program("WindowsPowerShell/v1.0/powershell.exe"),
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-Command"),
                OsStr::new("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
            ],
            None,
        );
        let sid = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        assert!(
            sid.starts_with("S-1-5-")
                && sid
                    .bytes()
                    .all(|v| v.is_ascii_digit() || v == b'S' || v == b'-')
        );
        sid
    }

    #[cfg(windows)]
    struct ChildGuard(Option<std::process::Child>);

    #[cfg(windows)]
    impl ChildGuard {
        fn child(&mut self) -> &mut std::process::Child {
            self.0.as_mut().expect("owned fixture child")
        }
        fn stop(&mut self) -> Result<(), String> {
            let Some(child) = self.0.as_mut() else {
                return Ok(());
            };
            let mut failures = Vec::new();
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.0.take();
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => failures.push(format!("poll: {error}")),
            }
            if let Err(error) = child.kill() {
                failures.push(format!("kill: {error}"));
            }
            match child.wait() {
                Ok(_) => {
                    self.0.take();
                }
                Err(error) => failures.push(format!("wait: {error}")),
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        }
    }

    #[cfg(windows)]
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            use std::io::Write as _;
            if let Err(error) = self.stop() {
                let _ = writeln!(std::io::stderr(), "fixture child cleanup failed: {error}");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn provider_storage_lock_child() {
        let Some(path) = std::env::var_os("ORBIT_PROVIDER_STORAGE_CHILD") else {
            return;
        };
        let path = PathBuf::from(path);
        let directory = Directory::open(&path, false).unwrap().unwrap();
        let _lock = StoreLock::acquire(&directory).unwrap();
        fs::write(path.join("child-ready"), b"ready").unwrap();
        let started = Instant::now();
        while !path.join("child-release").exists() {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn provider_storage_roundtrip_binding_revision_and_precedence() {
        let home = Home::new();
        let store = home.store();
        let identity = identity();
        let saved = store
            .save(&identity, secret(), ExpectedRevision::Absent)
            .unwrap();
        let reopened = store.resolve_with(&identity, |_| Ok(None)).unwrap();
        assert_eq!(reopened.source(), ProviderCredentialSource::Saved);
        assert_eq!(reopened.revision(), Some(saved.revision));
        assert!(!format!("{reopened:?}").contains("synthetic-held-secret"));
        assert_eq!(reopened.into_secret().unwrap().expose(), secret().expose());
        assert!(
            !store
                .save(&identity, secret(), ExpectedRevision::Exact(saved.revision))
                .unwrap()
                .changed
        );
        let draft = SecretBytes::new(b"draft-test-secret".to_vec());
        assert_eq!(
            store
                .resolve_with_draft(&identity, Some((&identity, &draft)), |_| Ok(None))
                .unwrap()
                .source(),
            ProviderCredentialSource::Draft
        );
        assert_eq!(
            store
                .resolve_with_draft(&identity, Some((&identity, &draft)), |_| Ok(Some(
                    SecretBytes::new(b"env-test-secret".to_vec())
                )))
                .unwrap()
                .source(),
            ProviderCredentialSource::Environment
        );
        let other = ProviderAuthIdentity::new(
            "other-provider",
            "openai-compatible",
            "https://provider.invalid/v1/",
            Some("TEST_TOKEN"),
        )
        .unwrap();
        assert_eq!(
            store
                .resolve_with_draft(&identity, Some((&other, &draft)), |_| Ok(None))
                .unwrap()
                .source(),
            ProviderCredentialSource::Saved
        );
        assert_eq!(
            store.resolve_with(&other, |_| Ok(None)).unwrap_err(),
            ProviderCredentialError::Missing
        );
        let updated = store
            .save(&identity, draft, ExpectedRevision::Exact(saved.revision))
            .unwrap();
        assert_ne!(updated.revision, saved.revision);
        assert_eq!(
            store.remove(&identity, ExpectedRevision::Exact(saved.revision)),
            Err(ProviderCredentialError::StaleRevision)
        );
        assert_eq!(
            store
                .remove(&identity, ExpectedRevision::Exact(updated.revision))
                .unwrap(),
            ProviderCredentialRemoveResult::Removed
        );
    }

    #[test]
    fn provider_storage_read_only_status_preserves_missing_lock_and_records() {
        let home = Home::new();
        let store = home.store();
        let identity = identity();
        let saved = store
            .save(&identity, secret(), ExpectedRevision::Absent)
            .unwrap();
        let record = home.0.join("auth/providers").join(identity.file_name());
        let before = Zeroizing::new(fs::read(&record).unwrap());
        let lock = home.0.join("auth/providers/store.lock");
        fs::remove_file(&lock).unwrap();
        #[cfg(windows)]
        let security = acl_snapshot(&record);
        assert_eq!(
            store.status_read_only_with(&identity, |_| Ok(None)),
            ProviderCredentialStatus::Invalid(ProviderCredentialError::UnsafeFile)
        );
        assert!(!lock.exists());
        assert_eq!(*Zeroizing::new(fs::read(&record).unwrap()), *before);
        #[cfg(windows)]
        assert_eq!(acl_snapshot(&record), security);
        assert_eq!(
            store
                .resolve_with(&identity, |_| Ok(None))
                .unwrap()
                .revision(),
            Some(saved.revision)
        );
    }
}
