//! Private OAuth records. Hold the store directory and never follow record links.

#[cfg(unix)]
mod unix {
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, Stat, fstat, fsync, mkdirat, open, openat, renameat,
        statat, unlinkat,
    };
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::path::Path;

    fn unsafe_storage() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OAuth storage is not a private owned file or directory",
        )
    }

    fn directory(home: &Path, create: bool) -> io::Result<File> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = open(home, flags, Mode::empty())?;
        let info = fstat(&root)?;
        if info.st_uid != rustix::process::geteuid().as_raw() || info.st_mode & 0o7022 != 0 {
            return Err(unsafe_storage());
        }
        if create {
            match mkdirat(&root, "mcp-oauth", Mode::from_raw_mode(0o700)) {
                Ok(()) => fsync(&root)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let store = openat(&root, "mcp-oauth", flags, Mode::empty())?;
        let info = fstat(&store)?;
        if info.st_uid != rustix::process::geteuid().as_raw() || info.st_mode & 0o7777 != 0o700 {
            return Err(unsafe_storage());
        }
        Ok(File::from(store))
    }

    fn check_file(info: &Stat, limit: usize) -> io::Result<()> {
        if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile
            || info.st_uid != rustix::process::geteuid().as_raw()
            || info.st_mode & 0o7777 != 0o600
            || info.st_nlink != 1
            || info.st_size < 0
            || info.st_size as u64 > limit as u64
        {
            return Err(unsafe_storage());
        }
        Ok(())
    }

    fn unchanged(a: &Stat, b: &Stat) -> bool {
        a.st_dev == b.st_dev
            && a.st_ino == b.st_ino
            && a.st_uid == b.st_uid
            && a.st_mode == b.st_mode
            && a.st_nlink == b.st_nlink
            && a.st_size == b.st_size
            && a.st_mtime == b.st_mtime
            && a.st_mtime_nsec == b.st_mtime_nsec
            && a.st_ctime == b.st_ctime
            && a.st_ctime_nsec == b.st_ctime_nsec
    }

    pub(crate) fn read(home: &Path, name: &str, limit: usize) -> io::Result<Vec<u8>> {
        let store = directory(home, false)?;
        let file = File::from(openat(
            &store,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let before = fstat(&file)?;
        check_file(&before, limit)?;
        let mut bytes = Vec::new();
        (&file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit
            || bytes.len() as u64 != before.st_size as u64
            || !unchanged(&before, &fstat(&file)?)
        {
            return Err(unsafe_storage());
        }
        Ok(bytes)
    }

    pub(crate) fn write(home: &Path, name: &str, bytes: &[u8], limit: usize) -> io::Result<()> {
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OAuth record exceeds its byte limit",
            ));
        }
        let store = directory(home, true)?;
        match statat(&store, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => check_file(&info, limit)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let temporary = format!(".token-{}.tmp", ulid::Ulid::new());
        let mut file = File::from(openat(
            &store,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let result = (|| {
            check_file(&fstat(&file)?, limit)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            renameat(&store, temporary.as_str(), &store, name)?;
            fsync(&store)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat(&store, temporary.as_str(), AtFlags::empty());
        }
        result
    }

    pub(crate) fn remove(home: &Path, name: &str) -> io::Result<bool> {
        let store = directory(home, false)?;
        match statat(&store, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => check_file(&info, usize::MAX)?,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        unlinkat(&store, name, AtFlags::empty())?;
        fsync(&store)?;
        Ok(true)
    }
}

#[cfg(unix)]
pub(super) use unix::{read, remove, write};

#[cfg(not(unix))]
pub(super) fn read(_: &std::path::Path, _: &str, _: usize) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private MCP OAuth storage is not supported on this platform",
    ))
}

#[cfg(not(unix))]
pub(super) fn write(_: &std::path::Path, _: &str, _: &[u8], _: usize) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private MCP OAuth storage is not supported on this platform",
    ))
}

#[cfg(not(unix))]
pub(super) fn remove(_: &std::path::Path, _: &str) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private MCP OAuth storage is not supported on this platform",
    ))
}
