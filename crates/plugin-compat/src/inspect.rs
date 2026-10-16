use crate::CompatError;
use crate::model::{InspectOptions, Inspection, SourceFile};
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_ENTRIES: usize = 4096;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 32;
const MAX_PATH_BYTES: usize = 1024;

/// Inspect a bounded immutable view of a local package without executing it.
///
/// No plugin, interpreter, credential environment or executable is loaded.
/// Source changes detected during the inventory require a fresh inspection.
pub fn inspect(source: &Path, options: &InspectOptions) -> Result<Inspection, CompatError> {
    let tree = SourceTree::read_named(source, None)?;
    crate::formats::normalize(&tree, options)
}

pub(crate) struct SourceTree {
    pub(crate) files: Vec<SourceFile>,
    pub(crate) bytes: BTreeMap<String, Vec<u8>>,
    pub(crate) source_digest: String,
    pub(crate) scm_excluded: bool,
    pub(crate) directories: BTreeSet<String>,
    pub(crate) directory_name: Option<String>,
}

impl SourceTree {
    pub(crate) fn read_named(
        source: &Path,
        inferred_name: Option<&str>,
    ) -> Result<Self, CompatError> {
        if let Some(name) = inferred_name {
            crate::formats::validate_legacy_id(name)?;
        }
        let root = open(
            source,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure("source_root_invalid"))?;
        let before = fstat(&root).map_err(|_| failure("source_read_failed"))?;
        let directory_name = if let Some(name) = inferred_name {
            Some(name.to_owned())
        } else {
            let canonical = source
                .canonicalize()
                .map_err(|_| failure("source_changed"))?;
            let named_root = open(
                &canonical,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failure("source_changed"))?;
            if !same_stat(
                &before,
                &fstat(&named_root).map_err(|_| failure("source_changed"))?,
            ) {
                return Err(failure("source_changed"));
            }
            canonical
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        };
        let mut inventory = Inventory {
            files: Vec::new(),
            bytes: BTreeMap::new(),
            names: BTreeSet::new(),
            directories: BTreeSet::new(),
            directory_paths: BTreeSet::new(),
            total_bytes: 0,
            entries: 0,
            root_device: before.st_dev,
            scm_excluded: false,
        };
        inventory.walk(&root, "", 0)?;
        if !same_stat(
            &before,
            &fstat(&root).map_err(|_| failure("source_read_failed"))?,
        ) {
            return Err(failure("source_changed"));
        }
        inventory.files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut digest = Sha256::new();
        digest.update(b"orbit-plugin-source-v1\0");
        for file in &inventory.files {
            digest.update((file.path.len() as u64).to_be_bytes());
            digest.update(file.path.as_bytes());
            digest.update(file.size.to_be_bytes());
            digest.update([u8::from(file.executable)]);
            digest.update(file.sha256.as_bytes());
        }
        Ok(Self {
            files: inventory.files,
            bytes: inventory.bytes,
            source_digest: hex::encode(digest.finalize()),
            scm_excluded: inventory.scm_excluded,
            directories: inventory.directory_paths,
            directory_name,
        })
    }

    pub(crate) fn text(&self, path: &str) -> Result<&str, CompatError> {
        let bytes = self
            .bytes
            .get(path)
            .ok_or_else(|| failure("source_component_missing"))?;
        std::str::from_utf8(bytes).map_err(|_| failure("source_text_invalid"))
    }

    pub(crate) fn contains(&self, path: &str) -> bool {
        self.bytes.contains_key(path)
    }
}

struct Inventory {
    files: Vec<SourceFile>,
    bytes: BTreeMap<String, Vec<u8>>,
    names: BTreeSet<String>,
    directories: BTreeSet<(u64, u64)>,
    directory_paths: BTreeSet<String>,
    total_bytes: u64,
    entries: usize,
    root_device: u64,
    scm_excluded: bool,
}

impl Inventory {
    fn walk(&mut self, directory: &OwnedFd, prefix: &str, depth: usize) -> Result<(), CompatError> {
        if depth > MAX_TREE_DEPTH {
            return Err(failure("source_depth_limit"));
        }
        self.directory_paths.insert(prefix.to_owned());
        let before = fstat(directory).map_err(|_| failure("source_read_failed"))?;
        if before.st_dev != self.root_device
            || !self.directories.insert((before.st_dev, before.st_ino))
        {
            return Err(failure("source_directory_alias"));
        }
        let read_fd = openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure("source_read_failed"))?;
        let entries = Dir::new(read_fd).map_err(|_| failure("source_read_failed"))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| failure("source_read_failed"))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| failure("source_path_invalid"))?;
            if name == "." || name == ".." {
                continue;
            }
            if name == ".git" {
                self.scm_excluded = true;
                continue;
            }
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(failure("source_entry_limit"));
            }
            if name.contains(['/', '\\']) || name.bytes().any(|b| b.is_ascii_control()) {
                return Err(failure("source_path_invalid"));
            }
            names.push(name.to_owned());
        }
        names.sort();
        for name in names {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if path.len() > MAX_PATH_BYTES {
                return Err(failure("source_path_limit"));
            }
            if !self.names.insert(path.to_lowercase()) {
                return Err(failure("source_case_collision"));
            }
            let declared = statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| failure("source_changed"))?;
            // O_PATH opens metadata handles only: a malicious special file is
            // never opened for reading while deciding which entry type it is.
            let child = openat(
                directory,
                name.as_str(),
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failure("source_changed"))?;
            let actual = fstat(&child).map_err(|_| failure("source_read_failed"))?;
            if !same_stat(&declared, &actual) {
                return Err(failure("source_changed"));
            }
            match FileType::from_raw_mode(actual.st_mode) {
                FileType::Directory => self.walk(&child, &path, depth + 1)?,
                FileType::RegularFile => self.read_file(&child, &path, &actual)?,
                _ => return Err(failure("source_entry_type")),
            }
            let after = statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| failure("source_changed"))?;
            if !same_stat(&actual, &after) {
                return Err(failure("source_changed"));
            }
        }
        if !same_stat(
            &before,
            &fstat(directory).map_err(|_| failure("source_read_failed"))?,
        ) {
            return Err(failure("source_changed"));
        }
        Ok(())
    }

    fn read_file(
        &mut self,
        handle: &OwnedFd,
        path: &str,
        before: &Stat,
    ) -> Result<(), CompatError> {
        if before.st_nlink != 1 {
            return Err(failure("source_hardlink"));
        }
        if before.st_size < 0 || before.st_size as u64 > MAX_FILE_BYTES {
            return Err(failure("source_file_limit"));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(before.st_size as u64)
            .ok_or_else(|| failure("source_size_limit"))?;
        if self.total_bytes > MAX_TREE_BYTES {
            return Err(failure("source_size_limit"));
        }
        // Reopen the already validated regular inode through its held metadata
        // handle. This kernel-provided fd link cannot be swapped by the package.
        let read_fd = open(
            format!("/proc/self/fd/{}", handle.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|_| failure("source_read_failed"))?;
        if !same_stat(
            before,
            &fstat(&read_fd).map_err(|_| failure("source_read_failed"))?,
        ) {
            return Err(failure("source_changed"));
        }
        let mut file = File::from(read_fd);
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("source_read_failed"))?;
        if bytes.len() as u64 != before.st_size as u64
            || !same_stat(
                before,
                &fstat(&file).map_err(|_| failure("source_read_failed"))?,
            )
        {
            return Err(failure("source_changed"));
        }
        self.files.push(SourceFile {
            path: path.to_owned(),
            sha256: hex::encode(Sha256::digest(&bytes)),
            size: bytes.len() as u64,
            executable: before.st_mode & 0o111 != 0,
        });
        self.bytes.insert(path.to_owned(), bytes);
        Ok(())
    }
}

fn same_stat(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn failure(code: &'static str) -> CompatError {
    let message = match code {
        "source_root_invalid" => {
            "Source must be a readable directory without a symbolic link at its root"
        }
        "source_component_missing" => {
            "A declared component is missing from the bounded package inventory"
        }
        "source_text_invalid" => "A component definition is not valid UTF-8",
        "source_changed" => {
            "Source changed during inspection; retry with a stable package directory"
        }
        "source_entry_type" => "Source contains a symbolic link or a non-regular asset",
        "source_hardlink" => {
            "Source contains a hard-linked file; copy it into a separate regular file"
        }
        "source_case_collision" => "Source contains paths that collide after case folding",
        "source_path_invalid" => "Source contains a non-portable path",
        "source_path_limit" => "A source path exceeds the byte limit",
        "source_depth_limit" => "Source exceeds the directory nesting limit",
        "source_directory_alias" => {
            "Source crosses a filesystem boundary or repeats a directory inode"
        }
        "source_entry_limit" => {
            "Source exceeds the entry limit; select the plugin package directory"
        }
        "source_file_limit" => "A source asset exceeds the byte limit",
        "source_size_limit" => "Source assets exceed the total byte limit",
        _ => "Source could not be read without following unsafe paths",
    };
    CompatError::new(code, message)
}
