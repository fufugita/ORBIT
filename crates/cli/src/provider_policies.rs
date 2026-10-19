//! Optional, private policies for bounded ordinary-request retries.

use crate::customization::{Directory, read_regular};
use orbit_engine::dispatch::{ProviderKind, TurnConfig};
use orbit_engine::retry::{
    FinalRejectionContract, FinalRejectionPolicy, FinalRejectionSelector, RetryPolicyBinding,
    RetryPolicyError,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};

const FILE_NAME: &str = "provider-policies.toml";
const MAX_DOCUMENT_BYTES: usize = 131_072;
const MAX_DECLARATIONS: usize = 128;

/// A local configuration failure. Diagnostics never retain file contents or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    UnsafeStorage,
    TooLarge,
    InvalidEncoding,
    InvalidDocument,
    DuplicateSelector,
    InvalidSelection,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafeStorage => "provider policy storage is unsafe or unreadable",
            Self::TooLarge => "provider policy file exceeds its size limit",
            Self::InvalidEncoding => "provider policy file must be UTF-8",
            Self::InvalidDocument => "provider policy document is invalid",
            Self::DuplicateSelector => "provider policy selectors overlap",
            Self::InvalidSelection => "selected provider cannot use the provider policy",
        })
    }
}

impl std::error::Error for PolicyError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    #[serde(default)]
    final_rejection: Vec<Declaration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    id: String,
    provider: String,
    model: String,
    endpoint: String,
    adapter_identity_sha256: String,
    statuses: Vec<u16>,
    scope: String,
    generation: String,
    billing: String,
    allow_uncapped_retry: bool,
    max_attempts: u32,
}

fn declarations(bytes: &[u8]) -> Result<Vec<FinalRejectionPolicy>, PolicyError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| PolicyError::InvalidEncoding)?;
    // TOML errors may include source excerpts. Do not retain or format them.
    let document: Document = toml::from_str(source).map_err(|_| PolicyError::InvalidDocument)?;
    if document.version != 1 || document.final_rejection.len() > MAX_DECLARATIONS {
        return Err(PolicyError::InvalidDocument);
    }
    let mut ids = BTreeSet::new();
    let mut selectors = BTreeSet::new();
    let mut policies = Vec::with_capacity(document.final_rejection.len());
    for declaration in document.final_rejection {
        let selector = FinalRejectionSelector::new(
            declaration.provider,
            declaration.model,
            declaration.endpoint,
            declaration.adapter_identity_sha256,
        )
        .map_err(|_| PolicyError::InvalidDocument)?;
        let canonical_endpoint = selector
            .canonical_endpoint()
            .map_err(|_| PolicyError::InvalidDocument)?;
        let contract = FinalRejectionContract::new(
            &declaration.scope,
            &declaration.generation,
            &declaration.billing,
            declaration.allow_uncapped_retry,
        )
        .map_err(|_| PolicyError::InvalidDocument)?;
        let policy = FinalRejectionPolicy::new(
            declaration.id,
            selector,
            declaration.statuses,
            contract,
            declaration.max_attempts,
        )
        .map_err(|_| PolicyError::InvalidDocument)?;
        if !ids.insert(policy.id().to_owned()) {
            return Err(PolicyError::InvalidDocument);
        }
        let selector = policy.selector();
        if !selectors.insert((
            selector.provider().to_owned(),
            selector.model().to_owned(),
            canonical_endpoint,
            selector.adapter_identity_sha256().to_owned(),
        )) {
            return Err(PolicyError::DuplicateSelector);
        }
        policies.push(policy);
    }
    Ok(policies)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn file_stamp(path: &Path) -> Result<FileStamp, PolicyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| PolicyError::UnsafeStorage)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(PolicyError::UnsafeStorage);
        }
        if metadata.len() > MAX_DOCUMENT_BYTES as u64 {
            return Err(PolicyError::TooLarge);
        }
        Ok(FileStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(PolicyError::UnsafeStorage)
    }
}

fn check_home(directory: &Directory, home: &Path) -> Result<(), PolicyError> {
    directory.check().map_err(|_| PolicyError::UnsafeStorage)?;
    // Recheck privacy as well as identity; Directory::check checks identity only.
    Directory::open(home, true).map_err(|_| PolicyError::UnsafeStorage)?;
    directory.check().map_err(|_| PolicyError::UnsafeStorage)
}

fn check_absent_home(home: &Path) -> Result<(), PolicyError> {
    let absolute = if home.is_absolute() {
        home.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| PolicyError::UnsafeStorage)?
            .join(home)
    };
    let mut missing = absolute.as_path();
    loop {
        let parent = missing.parent().ok_or(PolicyError::UnsafeStorage)?;
        match std::fs::symlink_metadata(parent) {
            Ok(_) => {
                // Check every existing ancestor, including dangling symlinks.
                let directory =
                    Directory::open(parent, false).map_err(|_| PolicyError::UnsafeStorage)?;
                let suffix = absolute
                    .strip_prefix(parent)
                    .map_err(|_| PolicyError::UnsafeStorage)?;
                let Some(Component::Normal(name)) = suffix.components().next() else {
                    return Err(PolicyError::UnsafeStorage);
                };
                let first_missing = directory
                    .io()
                    .map_err(|_| PolicyError::UnsafeStorage)?
                    .join(name);
                match std::fs::symlink_metadata(first_missing) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return directory.check().map_err(|_| PolicyError::UnsafeStorage);
                    }
                    // A formerly absent component appeared or cannot be checked.
                    _ => return Err(PolicyError::UnsafeStorage),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = parent,
            Err(_) => return Err(PolicyError::UnsafeStorage),
        }
    }
}

/// Load one immutable policy for the final selected provider, without creating state.
///
/// The complete bounded document is validated even when no declaration matches.
/// Missing state returns `None`; present unsafe or malformed state is an error.
pub fn load_for_config(
    home: &Path,
    config: &TurnConfig,
) -> Result<Option<RetryPolicyBinding>, PolicyError> {
    if home.as_os_str().is_empty()
        || home
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(PolicyError::UnsafeStorage);
    }
    match std::fs::symlink_metadata(home) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check_absent_home(home)?;
            return Ok(None);
        }
        Err(_) => return Err(PolicyError::UnsafeStorage),
    }
    let directory = Directory::open(home, true).map_err(|_| PolicyError::UnsafeStorage)?;
    let file = directory
        .io()
        .map_err(|_| PolicyError::UnsafeStorage)?
        .join(FILE_NAME);
    match std::fs::symlink_metadata(&file) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check_home(&directory, home)?;
            return Ok(None);
        }
        Err(_) => return Err(PolicyError::UnsafeStorage),
    }
    let before = file_stamp(&file)?;
    let bytes =
        read_regular(&file, MAX_DOCUMENT_BYTES, true).map_err(|_| PolicyError::UnsafeStorage)?;
    if before != file_stamp(&file)? || bytes.len() as u64 != before.length {
        return Err(PolicyError::UnsafeStorage);
    }
    let policies = declarations(&bytes)?;
    let mut selected = None;
    if config.kind == ProviderKind::OpenAiCompatible {
        for declaration in policies {
            match RetryPolicyBinding::for_config(config, declaration) {
                Ok(binding) => {
                    if selected.replace(binding).is_some() {
                        return Err(PolicyError::DuplicateSelector);
                    }
                }
                Err(RetryPolicyError::SelectionMismatch | RetryPolicyError::UnsupportedAdapter) => {
                }
                Err(RetryPolicyError::InvalidSelection) => {
                    return Err(PolicyError::InvalidSelection);
                }
                Err(_) => return Err(PolicyError::InvalidDocument),
            }
        }
    }
    if before != file_stamp(&file)? {
        return Err(PolicyError::UnsafeStorage);
    }
    check_home(&directory, home)?;
    Ok(selected)
}
