//! Handle-relative private storage on local fixed NTFS volumes.
//!
//! Every component is opened without following reparses. Directory and lock
//! handles exclude FILE_SHARE_DELETE, keeping their namespace identity held.
//! Files may be renamed only through their own held handles. Owner identity is
//! the effective TokenUser SID, never a token's default owner group.

use super::validate_component;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, Prefix};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume: u64,
    pub file: [u8; 16],
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: allocations stored here are returned by LocalAlloc APIs.
        unsafe { LocalFree(self.0) };
    }
}

struct Security {
    sid: Vec<u32>,
    descriptor: Vec<usize>,
}

impl Security {
    fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // Respect an impersonated ordinary-user token in native tests/callers.
        unsafe {
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
                let error = GetLastError();
                if error != ERROR_NO_TOKEN {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                ok(OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY,
                    &mut token,
                ))?;
            }
        }
        // SAFETY: successful token opening transfers one owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
        };
        let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        unsafe {
            ok(GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ))?;
        }
        // SAFETY: GetTokenInformation wrote a correctly sized/aligned TOKEN_USER.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let length = unsafe { GetLengthSid(user.User.Sid) };
        if length == 0 || length > 68 {
            return Err(invalid("invalid effective owner SID"));
        }
        let mut sid = vec![0u32; (length as usize).div_ceil(4)];
        unsafe { ok(CopySid(length, sid.as_mut_ptr().cast(), user.User.Sid))? };
        let mut string = null_mut();
        unsafe {
            ok(ConvertSidToStringSidW(
                sid.as_ptr().cast_mut().cast(),
                &mut string,
            ))?
        };
        let allocation = LocalAllocation(string.cast());
        let mut length = 0;
        // SAFETY: ConvertSidToStringSidW returns a NUL-terminated allocation.
        while unsafe { *string.add(length) } != 0 {
            length += 1;
        }
        let owner = String::from_utf16(unsafe { std::slice::from_raw_parts(string, length) })
            .map_err(|_| invalid("owner SID encoding"))?;
        drop(allocation);
        let sddl = wide(OsStr::new(&format!("O:{owner}D:P(A;OICI;FA;;;{owner})")));
        let mut descriptor = null_mut();
        let mut descriptor_length = 0;
        unsafe {
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                &mut descriptor_length,
            ))?
        };
        let allocation = LocalAllocation(descriptor);
        let mut owned = vec![0usize; (descriptor_length as usize).div_ceil(size_of::<usize>())];
        // The returned descriptor is self-relative; copy into aligned owned storage.
        unsafe {
            std::ptr::copy_nonoverlapping(
                descriptor.cast::<u8>(),
                owned.as_mut_ptr().cast(),
                descriptor_length as usize,
            )
        };
        drop(allocation);
        Ok(Self {
            sid,
            descriptor: owned,
        })
    }

    fn check(&self, handle: HANDLE) -> io::Result<()> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let _allocation = LocalAllocation(descriptor);
        let mut control = 0;
        let mut revision = 0;
        unsafe {
            ok(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?
        };
        if owner.is_null()
            || dacl.is_null()
            || unsafe { EqualSid(owner, self.sid.as_ptr().cast_mut().cast()) } == 0
            || control & SE_DACL_PROTECTED == 0
            || unsafe { (*dacl).AceCount } != 1
        {
            return Err(denied("state owner or private DACL changed"));
        }
        let mut ace = null_mut();
        unsafe { ok(GetAce(dacl, 0, &mut ace))? };
        // SAFETY: GetAce points to an OS-validated ACE; size is checked before
        // reading its SID, and only the ordinary access-allowed form is accepted.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0
            || (header.AceSize as usize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
            || header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
        {
            return Err(denied("unsupported state ACE"));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
        if allowed.Mask != FILE_ALL_ACCESS
            || unsafe { GetLengthSid(sid) } as usize
                > header.AceSize as usize - offset_of!(ACCESS_ALLOWED_ACE, SidStart)
            || unsafe { EqualSid(sid, self.sid.as_ptr().cast_mut().cast()) } == 0
        {
            return Err(denied("state DACL is not owner-only full control"));
        }
        Ok(())
    }
}

/// A complete chain of held, non-reparse directories to one private root.
pub struct Directory {
    chain: Vec<Arc<OwnedHandle>>,
    identity: FileIdentity,
    security: Security,
}

impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::absolute(path, false)
    }
    pub fn create(path: &Path) -> io::Result<Self> {
        Self::absolute(path, true)
    }

    fn absolute(path: &Path, create: bool) -> io::Result<Self> {
        let security = Security::current()?;
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => {
                    return Err(unsupported(
                        "state requires a local drive; UNC/device paths are unsupported",
                    ));
                }
            },
            _ => return Err(invalid("state root must be an absolute drive path")),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(invalid("drive-relative root"));
        }
        let names: Vec<_> = components
            .map(|component| match component {
                Component::Normal(name) => {
                    validate_component(name)?;
                    Ok(name.to_os_string())
                }
                _ => Err(invalid("ambiguous root path")),
            })
            .collect::<io::Result<_>>()?;
        if names.is_empty() {
            return Err(invalid("a drive root cannot be private state"));
        }
        let root = wide(OsStr::new(&format!("\\\\?\\{}:\\", char::from(drive))));
        let drive_path = wide(OsStr::new(&format!("{}:\\", char::from(drive))));
        if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != DRIVE_FIXED {
            return Err(unsupported("state requires a fixed local drive"));
        }
        let raw = unsafe {
            CreateFileW(
                root.as_ptr(),
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let first = unsafe { OwnedHandle::from_raw_handle(raw) };
        ensure_kind(first.as_raw_handle(), true)?;
        let mut filesystem = [0u16; 32];
        unsafe {
            ok(GetVolumeInformationByHandleW(
                first.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            ))?
        };
        if String::from_utf16_lossy(
            &filesystem[..filesystem
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(filesystem.len())],
        ) != "NTFS"
        {
            return Err(unsupported("state requires NTFS semantics"));
        }
        let mut chain = vec![Arc::new(first)];
        for (index, name) in names.iter().enumerate() {
            let last = index + 1 == names.len();
            let handle = relative(
                chain.last().unwrap().as_raw_handle(),
                name,
                true,
                if last && create {
                    FILE_CREATE
                } else {
                    FILE_OPEN
                },
                if last {
                    FILE_ALL_ACCESS & !DELETE
                } else {
                    FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
                },
                if last && create {
                    security.descriptor.as_ptr().cast()
                } else {
                    null()
                },
            )?;
            chain.push(Arc::new(handle));
        }
        let handle = chain.last().unwrap().as_raw_handle();
        security.check(handle)?;
        Ok(Self {
            identity: identity(handle)?,
            chain,
            security,
        })
    }

    fn handle(&self) -> HANDLE {
        self.chain.last().unwrap().as_raw_handle()
    }
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }
    pub fn check(&self) -> io::Result<()> {
        ensure_kind(self.handle(), true)?;
        if identity(self.handle())? != self.identity {
            return Err(denied("directory identity changed"));
        }
        self.security.check(self.handle())
    }

    pub fn child(&self, name: &OsStr, create: bool) -> io::Result<Self> {
        self.check()?;
        let security = Security::current()?;
        let handle = relative(
            self.handle(),
            name,
            true,
            if create { FILE_CREATE } else { FILE_OPEN },
            FILE_ALL_ACCESS & !DELETE,
            if create {
                security.descriptor.as_ptr().cast()
            } else {
                null()
            },
        )?;
        security.check(handle.as_raw_handle())?;
        let identity = identity(handle.as_raw_handle())?;
        let mut chain = self.chain.clone();
        chain.push(Arc::new(handle));
        Ok(Self {
            chain,
            identity,
            security,
        })
    }

    pub fn open_file(&self, name: &OsStr) -> io::Result<PrivateFile> {
        self.file(name, FILE_OPEN, false)
    }
    pub fn create_file(&self, name: &OsStr) -> io::Result<PrivateFile> {
        self.file(name, FILE_CREATE, true)
    }
    fn file(&self, name: &OsStr, disposition: u32, rename: bool) -> io::Result<PrivateFile> {
        self.check()?;
        let security = Security::current()?;
        let handle = relative(
            self.handle(),
            name,
            false,
            disposition,
            if rename {
                FILE_ALL_ACCESS
            } else {
                FILE_ALL_ACCESS & !DELETE
            },
            if disposition != FILE_OPEN {
                security.descriptor.as_ptr().cast()
            } else {
                null()
            },
        )?;
        security.check(handle.as_raw_handle())?;
        let identity = identity(handle.as_raw_handle())?;
        let file = File::from(handle);
        Ok(PrivateFile {
            file,
            identity,
            parent: self.identity,
            _anchors: self.chain.clone(),
            security,
        })
    }

    pub fn try_lock(&self, name: &OsStr, mode: LockMode) -> io::Result<StateLock> {
        let file = self.file(name, FILE_OPEN_IF, false)?;
        let mut overlap = OVERLAPPED::default();
        let flags = LOCKFILE_FAIL_IMMEDIATELY
            | if mode == LockMode::Exclusive {
                LOCKFILE_EXCLUSIVE_LOCK
            } else {
                0
            };
        unsafe {
            ok(LockFileEx(
                file.file.as_raw_handle(),
                flags,
                0,
                1,
                0,
                &mut overlap,
            ))?
        };
        Ok(StateLock { file, mode })
    }

    /// Publish a new name without replacing any existing object.
    pub fn publish_new(
        &self,
        file: &PrivateFile,
        name: &OsStr,
    ) -> Result<Publication, PublishError> {
        self.prepare(file, name)?;
        point("before_flush")?;
        file.sync_all()?;
        point("before_rename")?;
        self.rename(file, name)
            .map_err(|source| PublishError::Uncertain {
                source,
                state: PublicationState::NamespaceUnknown,
                original_backup: None,
            })?;
        if let Err(source) = point("after_rename").and_then(|()| file.sync_all()) {
            return Err(PublishError::Uncertain {
                source,
                state: PublicationState::NamePublished,
                original_backup: None,
            });
        }
        Ok(Publication {
            identity: file.identity,
            original_backup: None,
            durability: Durability::FileBuffersFlushed,
        })
    }

    /// Retain the expected original as a no-clobber backup before publication.
    /// The caller must keep that backup until its entire transaction is accepted.
    pub fn replace(
        &self,
        file: &PrivateFile,
        name: &OsStr,
        expected: FileIdentity,
        lock: &StateLock,
    ) -> Result<Publication, PublishError> {
        if lock.mode != LockMode::Exclusive || lock.file.parent != self.identity {
            return Err(denied("replacement requires this directory's exclusive lock").into());
        }
        lock.file.check()?;
        self.prepare(file, name)?;
        point("before_flush")?;
        file.sync_all()?;
        let original = self.file(name, FILE_OPEN, true)?;
        if original.identity != expected || original.identity == file.identity {
            return Err(denied("replacement identity changed").into());
        }
        let backup = loop {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let candidate = OsString::from(format!(
                ".previous-{}-{}",
                unsafe { GetCurrentProcessId() },
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match self.rename(&original, &candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(PublishError::Uncertain {
                        source,
                        state: PublicationState::NamespaceUnknown,
                        original_backup: Some(candidate),
                    });
                }
            }
        };
        if let Err(source) = point("before_rename").and_then(|()| self.rename(file, name)) {
            // A racing target is never overwritten during restoration.
            let restored = self.rename(&original, name).is_ok();
            return Err(PublishError::Uncertain {
                source,
                state: if restored {
                    PublicationState::OriginalRestored
                } else {
                    PublicationState::NamespaceUnknown
                },
                original_backup: if restored { None } else { Some(backup) },
            });
        }
        if let Err(source) = point("after_rename").and_then(|()| file.sync_all()) {
            return Err(PublishError::Uncertain {
                source,
                state: PublicationState::NamePublished,
                original_backup: Some(backup),
            });
        }
        Ok(Publication {
            identity: file.identity,
            original_backup: Some(backup),
            durability: Durability::FileBuffersFlushed,
        })
    }

    fn prepare(&self, file: &PrivateFile, name: &OsStr) -> io::Result<()> {
        validate_component(name)?;
        self.check()?;
        file.check()?;
        if file.parent != self.identity {
            return Err(denied("file belongs to another held directory"));
        }
        Ok(())
    }

    fn rename(&self, file: &PrivateFile, name: &OsStr) -> io::Result<()> {
        self.prepare(file, name)?;
        let name: Vec<u16> = name.encode_wide().collect();
        let bytes = offset_of!(FILE_RENAME_INFORMATION, FileName) + name.len() * 2;
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: storage is aligned and large enough for the variable tail;
        // both handles remain held, and every PrivateFile was opened with
        // FILE_SYNCHRONOUS_IO_NONALERT. Native FileRenameInformation accepts
        // this length-delimited single component relative to RootDirectory.
        let result = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = self.handle();
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
            NtSetInformationFile(
                file.file.as_raw_handle(),
                &mut status,
                info.cast(),
                bytes as u32,
                FileRenameInformation,
            )
        };
        if result < 0 {
            Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(result) } as i32,
            ))
        } else {
            Ok(())
        }
    }
}

pub struct PrivateFile {
    file: File,
    identity: FileIdentity,
    parent: FileIdentity,
    _anchors: Vec<Arc<OwnedHandle>>,
    security: Security,
}
impl PrivateFile {
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }
    pub fn check(&self) -> io::Result<()> {
        ensure_kind(self.file.as_raw_handle(), false)?;
        if identity(self.file.as_raw_handle())? != self.identity {
            return Err(denied("file identity changed"));
        }
        self.security.check(self.file.as_raw_handle())
    }
    pub fn read_limited(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
        self.check()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(invalid("state file exceeds read limit"));
        }
        Ok(bytes)
    }
    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        self.file.write_all(bytes)
    }
    pub fn sync_all(&self) -> io::Result<()> {
        self.check()?;
        self.file.sync_all()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockMode {
    Shared,
    Exclusive,
}
pub struct StateLock {
    file: PrivateFile,
    mode: LockMode,
}
impl Drop for StateLock {
    fn drop(&mut self) {
        let mut overlap = OVERLAPPED::default();
        unsafe { UnlockFileEx(self.file.file.as_raw_handle(), 0, 1, 0, &mut overlap) };
    }
}

/// The normal-user API acknowledges file-buffer flushing, not a volume flush
/// or a proven power-loss guarantee for directory metadata. Callers must retain
/// transaction recovery records/backups rather than infer a durable commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Durability {
    FileBuffersFlushed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    NamePublished,
    OriginalRestored,
    NamespaceUnknown,
}
#[derive(Debug)]
pub struct Publication {
    pub identity: FileIdentity,
    pub original_backup: Option<OsString>,
    pub durability: Durability,
}
#[derive(Debug)]
pub enum PublishError {
    Unchanged(io::Error),
    Uncertain {
        source: io::Error,
        state: PublicationState,
        original_backup: Option<OsString>,
    },
}
impl From<io::Error> for PublishError {
    fn from(error: io::Error) -> Self {
        Self::Unchanged(error)
    }
}
impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unchanged(e) => write!(f, "publication not started: {e}"),
            Self::Uncertain { source, .. } => write!(f, "publication requires recovery: {source}"),
        }
    }
}
impl std::error::Error for PublishError {}

fn relative(
    parent: HANDLE,
    name: &OsStr,
    directory: bool,
    disposition: u32,
    access: u32,
    descriptor: *const SECURITY_DESCRIPTOR,
) -> io::Result<OwnedHandle> {
    validate_component(name)?;
    let mut name: Vec<u16> = name.encode_wide().collect();
    let bytes = name
        .len()
        .checked_mul(2)
        .filter(|length| *length <= u16::MAX as usize)
        .ok_or_else(|| invalid("state component too long"))? as u16;
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: descriptor,
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut status,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition,
            FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    ensure_kind(handle.as_raw_handle(), directory)?;
    Ok(handle)
}
fn ensure_kind(handle: HANDLE, directory: bool) -> io::Result<()> {
    let tag: FILE_ATTRIBUTE_TAG_INFO = information(handle, FileAttributeTagInfo)?;
    let standard: FILE_STANDARD_INFO = information(handle, FileStandardInfo)?;
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || standard.Directory != directory
        || (!directory && standard.NumberOfLinks != 1)
        || standard.DeletePending
    {
        return Err(denied(
            "reparse, hardlink, deleted or unexpected state object",
        ));
    }
    Ok(())
}
fn identity(handle: HANDLE) -> io::Result<FileIdentity> {
    let info: FILE_ID_INFO = information(handle, FileIdInfo)?;
    Ok(FileIdentity {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}
fn information<T: Default>(handle: HANDLE, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    let mut value = T::default();
    unsafe {
        ok(GetFileInformationByHandleEx(
            handle,
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        ))?
    };
    Ok(value)
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn ok(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn point(_name: &'static str) -> io::Result<()> {
    #[cfg(test)]
    if FAILURE.with(|slot| slot.get() == Some(_name)) {
        return Err(io::Error::other("injected publication failure"));
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
mod tests {
    use super::*;

    struct RestoreIdentity;
    impl Drop for RestoreIdentity {
        fn drop(&mut self) {
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    fn restricted_identity() -> RestoreIdentity {
        let mut process_token = null_mut();
        unsafe {
            ok(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                &mut process_token,
            ))
            .unwrap();
        }
        let process_token = unsafe { OwnedHandle::from_raw_handle(process_token) };
        let mut admin = [0u32; 17];
        let mut size = size_of_val(&admin) as u32;
        unsafe {
            ok(CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                admin.as_mut_ptr().cast(),
                &mut size,
            ))
            .unwrap();
        }
        let disable = SID_AND_ATTRIBUTES {
            Sid: admin.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted = null_mut();
        unsafe {
            ok(CreateRestrictedToken(
                process_token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                1,
                &disable,
                0,
                null(),
                0,
                null(),
                &mut restricted,
            ))
            .unwrap();
        }
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        unsafe {
            ok(ImpersonateLoggedOnUser(restricted.as_raw_handle())).unwrap();
        }
        // Prove the effective token, rather than merely requesting restriction.
        let mut token = null_mut();
        unsafe {
            ok(OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY,
                1,
                &mut token,
            ))
            .unwrap();
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut member = 1;
        unsafe {
            ok(CheckTokenMembership(
                token.as_raw_handle(),
                admin.as_mut_ptr().cast(),
                &mut member,
            ))
            .unwrap();
        }
        assert_eq!(member, 0, "administrator SID remained enabled");
        RestoreIdentity
    }

    struct Home {
        base: std::path::PathBuf,
        directory: Option<Directory>,
    }
    impl Home {
        fn new() -> Self {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "orbit-fs-unit-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&base).unwrap();
            let directory = Directory::create(&base.join("state")).unwrap();
            Self {
                base,
                directory: Some(directory),
            }
        }
        fn dir(&self) -> &Directory {
            self.directory.as_ref().unwrap()
        }
        fn original(&self) -> FileIdentity {
            let mut original = self.dir().create_file(OsStr::new("record")).unwrap();
            original.write_all(b"original").unwrap();
            original.identity()
        }
        fn candidate(&self) -> PrivateFile {
            let mut candidate = self.dir().create_file(OsStr::new("candidate")).unwrap();
            candidate.write_all(b"replacement").unwrap();
            candidate
        }
        fn read(&self, name: &OsStr) -> Vec<u8> {
            self.dir()
                .open_file(name)
                .unwrap()
                .read_limited(1024)
                .unwrap()
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            FAILURE.with(|slot| slot.set(None));
            drop(self.directory.take());
            std::fs::remove_dir_all(&self.base).unwrap();
        }
    }

    #[test]
    fn private_storage_works_without_admin_group_or_privileges() {
        let _identity = restricted_identity();
        let home = Home::new();
        let candidate = home.candidate();
        let receipt = home
            .dir()
            .publish_new(&candidate, OsStr::new("record"))
            .unwrap();
        assert_eq!(receipt.durability, Durability::FileBuffersFlushed);
        drop(candidate);
        assert_eq!(home.read(OsStr::new("record")), b"replacement");
        drop(
            home.dir()
                .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
                .unwrap(),
        );
    }

    #[test]
    fn flush_failure_preserves_original_and_unpublished_candidate() {
        let home = Home::new();
        let expected = home.original();
        let candidate = home.candidate();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        FAILURE.with(|slot| slot.set(Some("before_flush")));
        assert!(matches!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), expected, &lock),
            Err(PublishError::Unchanged(_))
        ));
        FAILURE.with(|slot| slot.set(None));
        assert_eq!(home.read(OsStr::new("record")), b"original");
        let mut candidate = candidate;
        assert_eq!(candidate.read_limited(1024).unwrap(), b"replacement");
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
    }

    #[test]
    fn prepublication_failure_restores_expected_original() {
        let home = Home::new();
        let expected = home.original();
        let candidate = home.candidate();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        FAILURE.with(|slot| slot.set(Some("before_rename")));
        assert!(matches!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), expected, &lock),
            Err(PublishError::Uncertain {
                state: PublicationState::OriginalRestored,
                original_backup: None,
                ..
            })
        ));
        FAILURE.with(|slot| slot.set(None));
        assert_eq!(home.read(OsStr::new("record")), b"original");
    }

    #[test]
    fn postpublication_flush_failure_retains_original_backup() {
        let home = Home::new();
        let expected = home.original();
        let candidate = home.candidate();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        FAILURE.with(|slot| slot.set(Some("after_rename")));
        let error = home
            .dir()
            .replace(&candidate, OsStr::new("record"), expected, &lock)
            .unwrap_err();
        FAILURE.with(|slot| slot.set(None));
        let PublishError::Uncertain {
            state: PublicationState::NamePublished,
            original_backup: Some(backup),
            ..
        } = error
        else {
            panic!("wrong uncertain state: {error:?}");
        };
        drop(candidate);
        assert_eq!(home.read(OsStr::new("record")), b"replacement");
        assert_eq!(home.read(&backup), b"original");
        assert_eq!(home.dir().open_file(&backup).unwrap().identity(), expected);
    }
}
