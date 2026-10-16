use crate::CompatError;
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat, fchmod, flock, fstat,
    fsync, mkdirat, open, openat, renameat, renameat_with, statat, unlinkat,
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Binding {
    parent: Arc<OwnedFd>,
    name: OsString,
    child: Arc<OwnedFd>,
    private: bool,
}

/// Every path component remains bound to the directory inode first opened.
#[derive(Clone)]
pub(crate) struct Directory {
    fd: Arc<OwnedFd>,
    path: PathBuf,
    bindings: Vec<Binding>,
    private: bool,
}

pub(crate) fn absolute(path: &Path) -> Result<PathBuf, CompatError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| failure("store_path_invalid"))?
            .join(path)
    };
    if path
        .components()
        .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(failure("store_path_invalid"));
    }
    Ok(path)
}

impl Directory {
    pub(crate) fn open_optional(
        path: &Path,
        create: bool,
        private: bool,
    ) -> Result<Option<Self>, CompatError> {
        let path = absolute(path)?;
        let fd = Arc::new(
            open(
                "/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failure("store_read_failed"))?,
        );
        let mut directory = Self {
            fd,
            path: PathBuf::from("/"),
            bindings: Vec::new(),
            private: false,
        };
        for part in path.components() {
            if let Component::Normal(name) = part {
                let Some(next) = directory.child_os(name.to_os_string(), create, false)? else {
                    return Ok(None);
                };
                directory = next;
            }
        }
        directory.private = private;
        if let Some(binding) = directory.bindings.last_mut() {
            binding.private = private;
        }
        directory.check()?;
        Ok(Some(directory))
    }

    pub(crate) fn child(&self, name: &str, create: bool) -> Result<Option<Self>, CompatError> {
        valid_name(name)?;
        self.child_os(OsString::from(name), create, true)
    }

    fn child_os(
        &self,
        name: OsString,
        create: bool,
        private: bool,
    ) -> Result<Option<Self>, CompatError> {
        self.check()?;
        let mut created = false;
        let child = match openat(
            self.fd.as_ref(),
            name.as_os_str(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match mkdirat(
                    self.fd.as_ref(),
                    name.as_os_str(),
                    Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) => created = true,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(failure("store_write_failed")),
                }
                openat(
                    self.fd.as_ref(),
                    name.as_os_str(),
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failure("store_path_unsafe"))?
            }
            Err(_) => return Err(failure("store_path_unsafe")),
        };
        let fd = Arc::new(child);
        let mut bindings = self.bindings.clone();
        bindings.push(Binding {
            parent: self.fd.clone(),
            name: name.clone(),
            child: fd.clone(),
            private: private || created,
        });
        let result = Self {
            fd,
            path: self.path.join(name),
            bindings,
            private,
        };
        result.check()?;
        if created {
            check_owned(
                &fstat(result.fd.as_ref()).map_err(|_| failure("store_read_failed"))?,
                true,
                false,
            )?;
            self.sync()?;
            self.check()?;
        }
        Ok(Some(result))
    }

    pub(crate) fn check(&self) -> Result<(), CompatError> {
        for binding in &self.bindings {
            let named = statat(
                binding.parent.as_ref(),
                binding.name.as_os_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| failure("store_path_changed"))?;
            let held = fstat(binding.child.as_ref()).map_err(|_| failure("store_read_failed"))?;
            if !same_inode(&named, &held)
                || FileType::from_raw_mode(held.st_mode) != FileType::Directory
            {
                return Err(failure("store_path_changed"));
            }
            if binding.private {
                check_owned(&held, true, false)?;
            }
        }
        if self.private {
            check_owned(
                &fstat(self.fd.as_ref()).map_err(|_| failure("store_read_failed"))?,
                true,
                false,
            )?;
        }
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> Result<(u64, u64), CompatError> {
        self.check()?;
        let stat = fstat(self.fd.as_ref()).map_err(|_| failure("store_read_failed"))?;
        Ok((stat.st_dev, stat.st_ino))
    }

    pub(crate) fn held_path(&self) -> Result<PathBuf, CompatError> {
        self.check()?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/.",
            self.fd.as_raw_fd()
        )))
    }

    pub(crate) fn sync(&self) -> Result<(), CompatError> {
        self.check()?;
        let readable = openat(
            self.fd.as_ref(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failure("store_write_failed"))?;
        fsync(&readable).map_err(|_| failure("store_write_failed"))?;
        self.check()
    }

    pub(crate) fn read(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>, CompatError> {
        valid_name(name)?;
        self.check()?;
        let fd = match openat(
            self.fd.as_ref(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(failure("store_file_unsafe")),
        };
        let before = fstat(&fd).map_err(|_| failure("store_read_failed"))?;
        check_owned(&before, false, true)?;
        if before.st_size < 0 || before.st_size as u64 > limit as u64 {
            return Err(failure("store_index_limit"));
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("store_read_failed"))?;
        let after = fstat(&file).map_err(|_| failure("store_read_failed"))?;
        let named = statat(self.fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| failure("store_path_changed"))?;
        if bytes.len() as u64 != before.st_size as u64
            || !same_file(&before, &after)
            || !same_file(&after, &named)
        {
            return Err(failure("store_path_changed"));
        }
        self.check()?;
        Ok(Some(bytes))
    }

    pub(crate) fn write_new(
        &self,
        name: &str,
        bytes: &[u8],
        executable: bool,
    ) -> Result<(), CompatError> {
        valid_name(name)?;
        self.check()?;
        let fd = openat(
            self.fd.as_ref(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| failure("store_write_failed"))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|_| failure("store_write_failed"))?;
        fchmod(
            &file,
            Mode::from_raw_mode(if executable { 0o500 } else { 0o400 }),
        )
        .map_err(|_| failure("store_write_failed"))?;
        file.sync_all().map_err(|_| failure("store_write_failed"))?;
        let held = fstat(&file).map_err(|_| failure("store_read_failed"))?;
        check_owned(&held, false, true)?;
        let named = statat(self.fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| failure("store_path_changed"))?;
        if !same_file(&held, &named) {
            return Err(failure("store_path_changed"));
        }
        self.check()
    }

    pub(crate) fn verify_package_mode(
        &self,
        name: &str,
        executable: bool,
    ) -> Result<(), CompatError> {
        valid_name(name)?;
        self.check()?;
        let stat = statat(self.fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| failure("store_path_changed"))?;
        check_owned(&stat, false, true)?;
        if stat.st_mode & 0o7777 != if executable { 0o500 } else { 0o400 } {
            return Err(failure("store_file_unsafe"));
        }
        self.check()
    }

    pub(crate) fn publish_directory(
        &self,
        staged: &str,
        final_name: &str,
    ) -> Result<(), CompatError> {
        valid_name(staged)?;
        valid_name(final_name)?;
        self.check()?;
        renameat_with(
            self.fd.as_ref(),
            staged,
            self.fd.as_ref(),
            final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| failure("store_write_failed"))?;
        self.sync()
            .map_err(|_| failure("store_publication_uncertain"))
    }

    /// Rename is the publication point; errors after it must not be retried as failures.
    pub(crate) fn atomic_write(&self, name: &str, bytes: &[u8]) -> Result<(), CompatError> {
        valid_name(name)?;
        self.check()?;
        let temporary = temp_name("index");
        let fd = openat(
            self.fd.as_ref(),
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| failure("store_write_failed"))?;
        let mut file = File::from(fd);
        let prepare = (|| {
            file.write_all(bytes)
                .map_err(|_| failure("store_write_failed"))?;
            file.sync_all().map_err(|_| failure("store_write_failed"))?;
            self.check()?;
            // Refuse replacing a link, device or unowned index even under the lock.
            self.read(name, 256 * 1024)?;
            renameat(self.fd.as_ref(), temporary.as_str(), self.fd.as_ref(), name)
                .map_err(|_| failure("store_write_failed"))
        })();
        if let Err(error) = prepare {
            let _ = unlinkat(self.fd.as_ref(), temporary.as_str(), AtFlags::empty());
            return Err(error);
        }
        self.sync()
            .map_err(|_| failure("store_publication_uncertain"))
    }
}

pub(crate) struct MutationLock {
    directory: Directory,
    file: File,
}

/// Scope locks are ordered by physical identity, independent of path spelling.
pub(crate) struct MutationLocks {
    locks: Vec<MutationLock>,
}

impl MutationLocks {
    pub(crate) fn acquire(directories: &[Directory]) -> Result<Self, CompatError> {
        let mut ordered = directories
            .iter()
            .map(|directory| Ok((directory.identity()?, directory)))
            .collect::<Result<Vec<_>, CompatError>>()?;
        ordered.sort_by_key(|(identity, _)| *identity);
        if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(failure("store_scope_alias"));
        }
        let mut locks = Vec::with_capacity(ordered.len());
        for (_, directory) in ordered {
            locks.push(MutationLock::acquire(directory)?);
        }
        let result = Self { locks };
        result.check()?;
        Ok(result)
    }

    pub(crate) fn check(&self) -> Result<(), CompatError> {
        for lock in &self.locks {
            lock.check()?;
        }
        Ok(())
    }
}

impl MutationLock {
    pub(crate) fn acquire(directory: &Directory) -> Result<Self, CompatError> {
        directory.check()?;
        let fd = openat(
            directory.fd.as_ref(),
            "mutation.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| failure("store_file_unsafe"))?;
        let file = File::from(fd);
        check_owned(
            &fstat(&file).map_err(|_| failure("store_read_failed"))?,
            false,
            true,
        )?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| failure("store_busy"))?;
        let result = Self {
            directory: directory.clone(),
            file,
        };
        result.check()?;
        result.directory.sync()?;
        Ok(result)
    }

    pub(crate) fn check(&self) -> Result<(), CompatError> {
        self.directory.check()?;
        let held = fstat(&self.file).map_err(|_| failure("store_read_failed"))?;
        check_owned(&held, false, true)?;
        let named = statat(
            self.directory.fd.as_ref(),
            "mutation.lock",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| failure("store_path_changed"))?;
        if !same_inode(&held, &named) {
            return Err(failure("store_path_changed"));
        }
        Ok(())
    }
}

pub(crate) fn temp_name(kind: &str) -> String {
    format!(
        ".stage-{kind}-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

fn valid_name(name: &str) -> Result<(), CompatError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || name.bytes().any(|b| b.is_ascii_control())
    {
        return Err(failure("store_path_invalid"));
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

fn check_owned(stat: &Stat, directory: bool, single_link: bool) -> Result<(), CompatError> {
    let expected = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    if FileType::from_raw_mode(stat.st_mode) != expected
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7077 != 0
        || (single_link && stat.st_nlink != 1)
    {
        return Err(failure("store_file_unsafe"));
    }
    Ok(())
}

pub(crate) fn failure(code: &'static str) -> CompatError {
    CompatError::new(
        code,
        match code {
            "store_path_invalid" => "Managed storage requires normal absolute directory components",
            "store_path_unsafe" | "store_file_unsafe" => {
                "Managed content must be owned, private and free of links or special files"
            }
            "store_path_changed" => "A managed path changed; inspect the store before retrying",
            "store_busy" => "Another plugin mutation holds the store lock; retry after it finishes",
            "store_scope_alias" => {
                "User and project plugin scopes must have distinct physical storage roots"
            }
            "store_index_limit" => "The managed index exceeds its bounded size limit",
            "store_publication_uncertain" => {
                "Publication may have committed; read the store before retrying; previous content is retained"
            }
            "store_read_failed" => "Managed content could not be read safely",
            _ => "Managed content could not be written safely",
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{Directory, MutationLocks};

    #[test]
    fn scope_lock_order_uses_physical_identity_in_both_input_orders() {
        let temp = tempfile::tempdir().unwrap();
        let first = Directory::open_optional(&temp.path().join("first"), true, true)
            .unwrap()
            .unwrap();
        let second = Directory::open_optional(&temp.path().join("second"), true, true)
            .unwrap()
            .unwrap();
        let mut expected = [first.identity().unwrap(), second.identity().unwrap()];
        expected.sort();
        for directories in [
            [first.clone(), second.clone()],
            [second.clone(), first.clone()],
        ] {
            let held = MutationLocks::acquire(&directories).unwrap();
            let actual: Vec<_> = held
                .locks
                .iter()
                .map(|lock| lock.directory.identity().unwrap())
                .collect();
            assert_eq!(actual, expected);
            held.check().unwrap();
        }
    }

    #[test]
    fn duplicate_scope_inode_is_rejected_before_creating_a_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("scope");
        let first = Directory::open_optional(&path, true, true)
            .unwrap()
            .unwrap();
        let reopened = Directory::open_optional(&path, false, true)
            .unwrap()
            .unwrap();
        let error = MutationLocks::acquire(&[first, reopened]).err().unwrap();
        assert_eq!(error.code, "store_scope_alias");
        assert!(!path.join("mutation.lock").exists());
    }
}
