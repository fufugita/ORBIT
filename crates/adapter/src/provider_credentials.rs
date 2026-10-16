//! Exact provider credential bindings and private local persistence.

use crate::SecretBytes;
use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, fsync, mkdirat, open,
    openat, renameat, statat, unlinkat,
};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
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
        unlinkat(&*directory.fd, identity.file_name(), AtFlags::empty())
            .map_err(|_| ProviderCredentialError::Io)?;
        // Unlink is a publication point too; never report definite failure after it.
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

#[derive(Clone, Copy)]
enum DirectoryPolicy {
    Ancestor,
    Home,
    Private,
}

#[derive(Clone)]
struct Binding {
    parent: Arc<OwnedFd>,
    child: Arc<OwnedFd>,
    name: OsString,
    policy: DirectoryPolicy,
}

struct Directory {
    fd: Arc<OwnedFd>,
    bindings: Vec<Binding>,
}

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
struct StoreLock<'a> {
    directory: &'a Directory,
    file: File,
}

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

fn same_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && FileType::from_raw_mode(a.st_mode) == FileType::from_raw_mode(b.st_mode)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, DirBuilder, OpenOptions};
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
                match DirBuilder::new().mode(0o700).create(&path) {
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
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn provider_storage_held_directory_rejects_inode_substitution() {
        let home = Home::new();
        let directory = Directory::open(&home.0, true).unwrap().unwrap();
        let providers = home.0.join("auth/providers");
        fs::rename(&providers, home.0.join("auth/retained")).unwrap();
        DirBuilder::new().mode(0o700).create(&providers).unwrap();
        assert_eq!(directory.check(), Err(ProviderCredentialError::PathChanged));
        assert!(home.0.join("auth/retained").exists());
    }

    #[test]
    fn provider_storage_held_home_rejects_root_substitution() {
        let base = Home::new();
        let home = base.0.join("home");
        DirBuilder::new().mode(0o700).create(&home).unwrap();
        let directory = Directory::open(&home, true).unwrap().unwrap();
        fs::rename(&home, base.0.join("retained")).unwrap();
        DirBuilder::new().mode(0o700).create(&home).unwrap();
        assert_eq!(directory.check(), Err(ProviderCredentialError::PathChanged));
    }

    #[test]
    fn provider_storage_lock_rejects_named_inode_substitution() {
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

    #[test]
    fn provider_storage_record_recheck_rejects_inode_substitution() {
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

    #[test]
    fn provider_storage_foreign_ownership_is_rejected_without_privileged_fixture() {
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

    #[test]
    fn provider_storage_lock_wait_is_bounded_and_leaves_record_unchanged() {
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

    #[test]
    fn provider_storage_post_rename_failure_reports_uncertainty_and_retains_publication() {
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
}
