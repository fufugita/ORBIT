//! Filesystem capabilities use held directory handles and explicit policies.

use std::ffi::OsStr;
use std::io;

/// Reject ambiguous names before passing a single component to an OS backend.
pub fn validate_component(name: &OsStr) -> io::Result<()> {
    let name = name.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "state names must be Unicode")
    })?;
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                matches!(
                    n,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        })
        || reserved
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ambiguous state component",
        ));
    }
    Ok(())
}

/// Stable transaction locks use a reserved, case-insensitive `.lock` suffix.
/// Data operations cannot rename, update or remove this namespace.
pub fn validate_lock_component(name: &OsStr) -> io::Result<()> {
    validate_component(name)?;
    if !name
        .to_str()
        .unwrap()
        .to_ascii_lowercase()
        .ends_with(".lock")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lock names must end in .lock",
        ));
    }
    Ok(())
}

pub fn validate_data_component(name: &OsStr) -> io::Result<()> {
    validate_component(name)?;
    if name
        .to_str()
        .unwrap()
        .to_ascii_lowercase()
        .ends_with(".lock")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved transaction-lock name",
        ));
    }
    Ok(())
}

/// The Windows implementation requires a local fixed NTFS volume. Other
/// platforms deliberately expose no successful storage fallback here.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    Directory, DirectoryEntry, Durability, EnumerationLimits, FileIdentity, FileSnapshot,
    InspectionLimits, LockMode, MutationFile, OwnedContainer, PrivateFile, PrivateFileAccess,
    PrivateTreeEntry, PrivateTreeInspection, Publication, PublicationState, PublishError, Removal,
    RemovalError, RemovalState, SourceDirectory, SourceFile, SourceSnapshot, StateLock, UpdateFile,
};
