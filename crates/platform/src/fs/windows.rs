//! Handle-relative private storage and read-only source access on local fixed NTFS volumes.
//!
//! Every component is opened without following reparses. Directory and lock
//! handles exclude FILE_SHARE_DELETE, keeping their namespace identity held.
//! Files may be renamed only through their own held handles. Owner identity is
//! the effective TokenUser SID, never a token's default owner group.

use super::{validate_component, validate_data_component, validate_lock_component};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, Prefix};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSnapshot {
    pub identity: FileIdentity,
    pub length: u64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
}

/// Owner-only file rights accepted by read-only privacy inspection. Mutation
/// APIs continue to require the original owner-only full-control descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateFileAccess {
    ReadOnly,
    ReadExecute,
    FullControl,
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: allocations stored here are returned by LocalAlloc APIs.
        unsafe { LocalFree(self.0) };
    }
}

#[derive(Clone)]
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
        self.check_owner_access(handle, false).map(|_| ())
    }

    fn check_owner_access(
        &self,
        handle: HANDLE,
        readable_file: bool,
    ) -> io::Result<PrivateFileAccess> {
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
        if unsafe { GetLengthSid(sid) } as usize
            > header.AceSize as usize - offset_of!(ACCESS_ALLOWED_ACE, SidStart)
            || unsafe { EqualSid(sid, self.sid.as_ptr().cast_mut().cast()) } == 0
        {
            return Err(denied("state DACL is not owner-only"));
        }
        if allowed.Mask == FILE_ALL_ACCESS {
            Ok(PrivateFileAccess::FullControl)
        } else if readable_file && allowed.Mask == FILE_GENERIC_READ {
            Ok(PrivateFileAccess::ReadOnly)
        } else if readable_file && allowed.Mask == FILE_GENERIC_READ | FILE_GENERIC_EXECUTE {
            Ok(PrivateFileAccess::ReadExecute)
        } else {
            Err(denied("unsupported owner-private access mask"))
        }
    }
}

/// A complete chain of held, non-reparse directories to one private root.
pub struct Directory {
    chain: Vec<Arc<OwnedHandle>>,
    identity: FileIdentity,
    security: Security,
    enumeration: Mutex<()>,
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
            enumeration: Mutex::new(()),
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
        validate_data_component(name)?;
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
        validate_data_component(&held_leaf(handle.as_raw_handle())?)?;
        security.check(handle.as_raw_handle())?;
        let identity = identity(handle.as_raw_handle())?;
        let mut chain = self.chain.clone();
        chain.push(Arc::new(handle));
        Ok(Self {
            chain,
            identity,
            security,
            enumeration: Mutex::new(()),
        })
    }

    pub fn open_file(&self, name: &OsStr) -> io::Result<PrivateFile> {
        validate_data_component(name)?;
        self.file(name, FILE_OPEN, false)
    }
    pub fn create_file(&self, name: &OsStr) -> io::Result<PrivateFile> {
        validate_data_component(name)?;
        self.file(name, FILE_CREATE, true)
    }
    fn file(&self, name: &OsStr, disposition: u32, rename: bool) -> io::Result<PrivateFile> {
        let access = if rename {
            FILE_ALL_ACCESS
        } else if disposition == FILE_OPEN {
            FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE
        } else {
            FILE_ALL_ACCESS & !DELETE
        };
        self.file_access(name, disposition, access)
    }

    fn file_access(&self, name: &OsStr, disposition: u32, access: u32) -> io::Result<PrivateFile> {
        self.check()?;
        let security = Security::current()?;
        let handle = relative(
            self.handle(),
            name,
            false,
            disposition,
            access,
            if disposition != FILE_OPEN {
                security.descriptor.as_ptr().cast()
            } else {
                null()
            },
        )?;
        let actual = held_leaf(handle.as_raw_handle())?;
        if validate_lock_component(name).is_ok() {
            validate_lock_component(&actual)?;
        } else {
            validate_data_component(&actual)?;
        }
        security.check(handle.as_raw_handle())?;
        let identity = identity(handle.as_raw_handle())?;
        let file = File::from(handle);
        Ok(PrivateFile {
            file,
            identity,
            parent: self.identity,
            _anchors: self.chain.clone(),
            security,
            writable_candidate: AtomicBool::new(disposition == FILE_CREATE),
            publication: Mutex::new(()),
        })
    }

    pub fn open_lock_existing(&self, name: &OsStr, mode: LockMode) -> io::Result<StateLock> {
        self.lock_file(name, mode, FILE_OPEN)
    }

    pub fn try_lock(&self, name: &OsStr, mode: LockMode) -> io::Result<StateLock> {
        self.lock_file(name, mode, FILE_OPEN_IF)
    }

    fn lock_file(&self, name: &OsStr, mode: LockMode, disposition: u32) -> io::Result<StateLock> {
        validate_lock_component(name)?;
        let file = if disposition == FILE_OPEN {
            self.file_access(
                name,
                FILE_OPEN,
                FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            )?
        } else {
            self.file(name, disposition, false)?
        };
        if file.snapshot()?.length != 0 {
            return Err(denied("transaction lock must be empty"));
        }
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
        let lock = StateLock { file, mode };
        lock.check()?;
        Ok(lock)
    }

    /// Publish a new name without replacing any existing object.
    pub fn publish_new(
        &self,
        file: &PrivateFile,
        name: &OsStr,
    ) -> Result<Publication, PublishError> {
        let _publication = file
            .publication
            .lock()
            .map_err(|_| io::Error::other("publication capability poisoned"))?;
        if !file.writable_candidate.load(Ordering::Relaxed) {
            return Err(denied("publication requires an unpublished candidate").into());
        }
        self.publish_checked(file, name)
    }

    fn publish_checked(
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
        let _publication = file
            .publication
            .lock()
            .map_err(|_| io::Error::other("publication capability poisoned"))?;
        if !file.writable_candidate.load(Ordering::Relaxed) {
            return Err(denied("replacement requires an unpublished candidate").into());
        }
        if lock.mode != LockMode::Exclusive || lock.file.parent != self.identity {
            return Err(denied("replacement requires this directory's exclusive lock").into());
        }
        lock.check()?;
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
        validate_data_component(name)?;
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
            file.writable_candidate.store(false, Ordering::Relaxed);
            Ok(())
        }
    }
}

impl Directory {
    fn require_lock(&self, lock: &StateLock, exclusive: bool) -> io::Result<()> {
        self.check()?;
        lock.check()?;
        if lock.file.parent != self.identity || (exclusive && lock.mode != LockMode::Exclusive) {
            return Err(denied(
                "operation requires the same directory's transaction lock",
            ));
        }
        Ok(())
    }

    /// Existing state is writable only while this borrowed exclusive guard lives.
    pub fn open_for_update<'lock>(
        &self,
        name: &OsStr,
        expected: FileIdentity,
        lock: &'lock StateLock,
    ) -> io::Result<UpdateFile<'lock>> {
        validate_data_component(name)?;
        self.require_lock(lock, true)?;
        let file = self.file_access(
            name,
            FILE_OPEN,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE,
        )?;
        if file.identity != expected {
            return Err(denied("update identity changed"));
        }
        Ok(UpdateFile { file, lock })
    }

    /// Reopen one expected private object for rename/delete, without a pathname
    /// escape. Release older reader handles before acquiring this capability.
    pub fn open_for_rename<'lock>(
        &self,
        name: &OsStr,
        expected: FileIdentity,
        lock: &'lock StateLock,
    ) -> io::Result<MutationFile<'lock>> {
        validate_data_component(name)?;
        self.require_lock(lock, true)?;
        let file = self.file(name, FILE_OPEN, true)?;
        if file.identity != expected {
            return Err(denied("mutation identity changed"));
        }
        Ok(MutationFile { file, lock })
    }

    /// Restore the selected held backup into an absent name. An occupied target
    /// is never replaced; retain its identity and the backup after uncertainty.
    pub fn restore_backup(
        &self,
        backup: MutationFile<'_>,
        name: &OsStr,
    ) -> Result<Publication, PublishError> {
        self.require_lock(backup.lock, true)?;
        self.publish_checked(&backup.file, name)
    }

    /// Consume a checked DELETE-capable file. A disposition acknowledgement is
    /// not a claim about power-loss durability or later namespace occupants.
    pub fn remove_file(&self, file: MutationFile<'_>) -> Result<Removal, RemovalError> {
        self.require_lock(file.lock, true)?;
        self.prepare(&file.file, OsStr::new("checked-removal"))?;
        let result = remove_handle(file.file.file.as_raw_handle(), file.file.identity);
        drop(file); // A disposition-marked handle is only closed, never reused.
        result
    }

    /// Remove only an expected private, empty child with no outstanding anchors.
    pub fn remove_empty_child(
        &self,
        name: &OsStr,
        expected: FileIdentity,
        lock: &StateLock,
    ) -> Result<Removal, RemovalError> {
        validate_data_component(name)?;
        self.require_lock(lock, true)?;
        let handle = relative(
            self.handle(),
            name,
            true,
            FILE_OPEN,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | DELETE,
            null(),
        )?;
        validate_data_component(&held_leaf(handle.as_raw_handle())?)?;
        self.security.check(handle.as_raw_handle())?;
        if identity(handle.as_raw_handle())? != expected {
            return Err(denied("child identity changed").into());
        }
        if !directory_entries(
            handle.as_raw_handle(),
            EnumerationLimits {
                max_entries: 1,
                max_name_bytes: 65536,
            },
        )?
        .is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                "private child is not empty",
            )
            .into());
        }
        let result = remove_handle(handle.as_raw_handle(), expected);
        drop(handle);
        result
    }

    /// A bounded snapshot under a shared/exclusive transaction guard. Entries
    /// are evidence only: mutation must reopen and verify the selected identity.
    pub fn enumerate(
        &self,
        limits: EnumerationLimits,
        lock: &StateLock,
    ) -> io::Result<Vec<DirectoryEntry>> {
        self.require_lock(lock, false)?;
        let _cursor = self
            .enumeration
            .lock()
            .map_err(|_| io::Error::other("directory cursor poisoned"))?;
        let raw = directory_entries(self.handle(), limits)?;
        let mut checked = Vec::with_capacity(raw.len());
        for entry in raw {
            let expected = FileIdentity {
                volume: self.identity.volume,
                file: entry.identity,
            };
            let handle = relative(
                self.handle(),
                &entry.name,
                entry.directory,
                FILE_OPEN,
                FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
                null(),
            )?;
            self.security.check(handle.as_raw_handle())?;
            if identity(handle.as_raw_handle())? != expected {
                return Err(denied("enumerated entry changed"));
            }
            checked.push(DirectoryEntry {
                name: entry.name,
                identity: expected,
                directory: entry.directory,
            });
        }
        Ok(checked)
    }

    /// Observe a bounded private tree without creating a transaction lock.
    /// This is read-only evidence; it is not an atomic namespace snapshot.
    pub fn inspect_private_tree(
        &self,
        limits: InspectionLimits,
    ) -> io::Result<PrivateTreeInspection> {
        self.check()?;
        if limits.max_entries == 0
            || limits.max_entries > 4096
            || limits.max_name_bytes == 0
            || limits.max_name_bytes > 1048576
            || limits.max_depth == 0
            || limits.max_depth > 128
        {
            return Err(invalid("invalid private inspection limits"));
        }
        let mut state = InspectionState {
            entries: Vec::new(),
            count: 0,
            name_bytes: 0,
        };
        inspect_directory(self, Path::new(""), 0, limits, &mut state)?;
        self.check()?;
        state
            .entries
            .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(PrivateTreeInspection {
            root_identity: self.identity,
            entries: state.entries,
        })
    }
}

fn open_owner_container(path: &Path) -> io::Result<OwnedContainer> {
    let security = Security::current()?;
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(unsupported("container requires a local drive")),
        },
        _ => return Err(invalid("container path must be an absolute drive path")),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("drive-relative container path"));
    }
    let names: Vec<_> = components
        .map(|component| match component {
            Component::Normal(name) => {
                validate_component(name)?;
                Ok(name.to_os_string())
            }
            _ => Err(invalid("ambiguous container path")),
        })
        .collect::<io::Result<_>>()?;
    if names.is_empty() {
        return Err(invalid("a drive root cannot be an owned container"));
    }
    if names.len() > 128 {
        return Err(invalid("container ancestor limit exceeded"));
    }
    let root = wide(OsStr::new(&format!("\\\\?\\{}:\\", char::from(drive))));
    let drive_path = wide(OsStr::new(&format!("{}:\\", char::from(drive))));
    if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != DRIVE_FIXED {
        return Err(unsupported("container requires a fixed local drive"));
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
    let fs_len = filesystem
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(filesystem.len());
    if String::from_utf16_lossy(&filesystem[..fs_len]) != "NTFS" {
        return Err(unsupported("container requires NTFS semantics"));
    }
    let mut chain = vec![Arc::new(first)];
    let mut identities = vec![identity(chain[0].as_raw_handle())?];
    let volume = identities[0].volume;
    for name in names {
        let parent = chain.last().expect("root handle retained");
        let handle = relative(
            parent.as_raw_handle(),
            &name,
            true,
            FILE_OPEN,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            null(),
        )?;
        let child_identity = identity(handle.as_raw_handle())?;
        if child_identity.volume != volume || identities.contains(&child_identity) {
            return Err(denied(
                "container path crossed volume or repeated an ancestor",
            ));
        }
        chain.push(Arc::new(handle));
        identities.push(child_identity);
    }
    let container = OwnedContainer {
        chain,
        identities,
        security,
    };
    container.check()?;
    Ok(container)
}

fn validate_container_ace_header(ace_type: u8, ace_flags: u8, ace_size: usize) -> io::Result<()> {
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let supported_flags = OBJECT_INHERIT_ACE as u8
        | CONTAINER_INHERIT_ACE as u8
        | NO_PROPAGATE_INHERIT_ACE as u8
        | INHERIT_ONLY_ACE as u8
        | INHERITED_ACE as u8;
    if !matches!(ace_type, 0 | 1) || ace_flags & !supported_flags != 0 || ace_size < sid_offset + 8
    {
        return Err(denied("unsupported or malformed container ACE"));
    }
    Ok(())
}

fn validate_container_ace_layout(
    ace_type: u8,
    ace_flags: u8,
    ace_size: usize,
    sid_bytes: &[u8],
) -> io::Result<usize> {
    validate_container_ace_header(ace_type, ace_flags, ace_size)?;
    if sid_bytes.len() < 8 {
        return Err(denied("container ACE SID prefix is truncated"));
    }
    let revision = sid_bytes[0];
    let sub_authority_count = sid_bytes[1] as usize;
    let sid_len = 8usize
        .checked_add(
            sub_authority_count
                .checked_mul(4)
                .ok_or_else(|| denied("container SID length overflow"))?,
        )
        .ok_or_else(|| denied("container SID length overflow"))?;
    if revision != 1 || sub_authority_count > 15 || sid_len > sid_bytes.len() || sid_len > 68 {
        return Err(denied("container ACE SID exceeds its bounded record"));
    }
    Ok(sid_len)
}

fn checked_container_access_mask(mask: u32) -> io::Result<u32> {
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut mapped = mask;
    unsafe { MapGenericMask(&mut mapped, &mapping) };
    if mapped & !FILE_ALL_ACCESS != 0 {
        return Err(denied("container ACE contains unsupported access bits"));
    }
    Ok(mapped)
}

fn check_container_access(security: &Security, handle: HANDLE) -> io::Result<()> {
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
    if descriptor.is_null() || owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(denied("container owner descriptor is invalid"));
    }
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    let token_sid = security.sid.as_ptr().cast_mut().cast();
    if owner_len == 0
        || owner_len > 68
        || unsafe { IsValidSid(token_sid) } == 0
        || unsafe { GetLengthSid(token_sid) } as usize != security.sid.len() * size_of::<u32>()
        || unsafe { EqualSid(owner, token_sid) } == 0
    {
        return Err(denied("container owner is not the effective token user"));
    }

    let mut present = 0;
    let mut descriptor_dacl = null_mut();
    let mut defaulted = 0;
    unsafe {
        ok(GetSecurityDescriptorDacl(
            descriptor,
            &mut present,
            &mut descriptor_dacl,
            &mut defaulted,
        ))?
    };
    if present == 0 || descriptor_dacl.is_null() || descriptor_dacl != dacl {
        return Err(denied("container requires a present, non-null DACL"));
    }
    let acl = unsafe { &*descriptor_dacl };
    let acl_size = acl.AclSize as usize;
    if acl_size < size_of::<ACL>()
        || (acl.AclRevision != ACL_REVISION as u8 && acl.AclRevision != ACL_REVISION_DS as u8)
        || unsafe { IsValidAcl(descriptor_dacl) } == 0
    {
        return Err(denied("container ACL header is invalid"));
    }
    let mut size_info = ACL_SIZE_INFORMATION::default();
    unsafe {
        ok(GetAclInformation(
            descriptor_dacl,
            (&mut size_info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ))?
    };
    let bytes_in_use = size_info.AclBytesInUse as usize;
    if bytes_in_use < size_of::<ACL>()
        || bytes_in_use > acl_size
        || size_info.AclBytesFree as usize > acl_size
        || size_info.AceCount > 4096
    {
        return Err(denied("container ACL bounds are invalid"));
    }

    let readable_rights = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

    for index in 0..size_info.AceCount {
        let mut ace_ptr = null_mut();
        unsafe { ok(GetAce(descriptor_dacl, index, &mut ace_ptr))? };
        if ace_ptr.is_null() {
            return Err(denied("container ACL contains a null ACE"));
        }
        let acl_start = descriptor_dacl.cast::<u8>() as usize;
        let ace_start = ace_ptr as usize;
        let acl_end = acl_start
            .checked_add(bytes_in_use)
            .ok_or_else(|| denied("container ACL bounds overflow"))?;
        let header_end = ace_start
            .checked_add(size_of::<ACE_HEADER>())
            .ok_or_else(|| denied("container ACE bounds overflow"))?;
        if ace_start < acl_start || header_end > acl_end {
            return Err(denied("container ACE header exceeds its ACL"));
        }
        let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };
        let ace_size = header.AceSize as usize;
        let ace_end = ace_start
            .checked_add(ace_size)
            .ok_or_else(|| denied("container ACE bounds overflow"))?;
        if ace_end > acl_end {
            return Err(denied("container ACE exceeds its bounded ACL record"));
        }
        validate_container_ace_header(header.AceType, header.AceFlags, ace_size)?;
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let mask = unsafe { *ace_ptr.cast::<u32>().add(1) };
        let sid_bytes_ptr = unsafe { ace_ptr.cast::<u8>().add(sid_offset) };
        let sid_available = ace_size - sid_offset;
        // The ACE end was bounded against AclBytesInUse before forming this slice.
        let sid_bytes = unsafe { std::slice::from_raw_parts(sid_bytes_ptr, sid_available) };
        let sid_len =
            validate_container_ace_layout(header.AceType, header.AceFlags, ace_size, sid_bytes)?;
        let sid = sid_bytes_ptr.cast::<SID>();
        if unsafe { IsValidSid(sid.cast()) } == 0
            || unsafe { GetLengthSid(sid.cast()) } as usize != sid_len
        {
            return Err(denied("container ACE SID is malformed"));
        }

        let mapped = checked_container_access_mask(mask)?;
        if header.AceType == 0 && header.AceFlags & INHERIT_ONLY_ACE as u8 == 0 {
            let trusted = unsafe {
                EqualSid(sid.cast(), token_sid) != 0
                    || IsWellKnownSid(sid.cast(), WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid.cast(), WinBuiltinAdministratorsSid) != 0
            };
            if !trusted && mapped & !readable_rights != 0 {
                return Err(denied(
                    "container grants an untrusted principal mutation rights",
                ));
            }
        }
    }
    Ok(())
}

/// A validation-only capability for an owner-owned readable container.
/// It exposes no private-state mutation operations and never repairs ACLs. Effective grants
/// to the captured TokenUser, LocalSystem, and Administrators SIDs are trusted by policy;
/// other effective grants are limited to file read and execute rights.
pub struct OwnedContainer {
    chain: Vec<Arc<OwnedHandle>>,
    identities: Vec<FileIdentity>,
    security: Security,
}

impl OwnedContainer {
    pub fn open(path: &Path) -> io::Result<Self> {
        open_owner_container(path)
    }

    pub fn identity(&self) -> FileIdentity {
        *self.identities.last().expect("container has a target")
    }

    pub fn check(&self) -> io::Result<()> {
        check_source_anchors(&self.chain, &self.identities)?;
        let handle = self
            .chain
            .last()
            .ok_or_else(|| invalid("empty container chain"))?;
        ensure_kind(handle.as_raw_handle(), true)?;
        check_container_access(&self.security, handle.as_raw_handle())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InspectionLimits {
    pub max_entries: usize,
    /// Total UTF-16 bytes of the returned relative paths, including separators.
    pub max_name_bytes: usize,
    /// Maximum number of components below the inspected root.
    pub max_depth: usize,
}

#[derive(Debug)]
pub struct PrivateTreeInspection {
    pub root_identity: FileIdentity,
    pub entries: Vec<PrivateTreeEntry>,
}

#[derive(Debug)]
pub struct PrivateTreeEntry {
    /// Display/comparison evidence only; this path carries no access authority.
    pub relative_path: std::path::PathBuf,
    pub identity: FileIdentity,
    pub directory: bool,
    /// Observed privacy class only; it is not mutation or transaction authority.
    pub file_access: Option<PrivateFileAccess>,
    pub snapshot: Option<FileSnapshot>,
}

struct InspectionState {
    entries: Vec<PrivateTreeEntry>,
    count: usize,
    name_bytes: usize,
}

fn inspect_directory(
    directory: &Directory,
    prefix: &Path,
    depth: usize,
    limits: InspectionLimits,
    state: &mut InspectionState,
) -> io::Result<()> {
    directory.check()?;
    let raw = {
        let _cursor = directory
            .enumeration
            .lock()
            .map_err(|_| io::Error::other("directory cursor poisoned"))?;
        directory_entries(
            directory.handle(),
            EnumerationLimits {
                // A zero remainder still permits checking an empty directory.
                max_entries: limits.max_entries.saturating_sub(state.count).max(1),
                max_name_bytes: limits
                    .max_name_bytes
                    .saturating_sub(state.name_bytes)
                    .max(2),
            },
        )?
    };
    let mut paths = Vec::with_capacity(raw.len());
    // Account for the complete listing before descending, so pending sibling
    // listings cannot multiply memory beyond the global path/entry budgets.
    for entry in raw {
        if depth + 1 > limits.max_depth || state.count == limits.max_entries {
            return Err(invalid("private inspection entry or depth limit exceeded"));
        }
        let path = prefix.join(&entry.name);
        let bytes = path
            .as_os_str()
            .encode_wide()
            .count()
            .checked_mul(2)
            .ok_or_else(|| invalid("inspection path size overflow"))?;
        state.name_bytes = state
            .name_bytes
            .checked_add(bytes)
            .filter(|total| *total <= limits.max_name_bytes)
            .ok_or_else(|| invalid("private inspection path limit exceeded"))?;
        state.count += 1;
        paths.push((entry, path));
    }
    #[cfg(test)]
    if INSPECTION_REPLACE_AFTER_ENUMERATION.swap(false, Ordering::SeqCst) {
        let Some((entry, _)) = paths.iter().find(|(entry, _)| entry.name == "record") else {
            return Err(invalid("replacement fixture entry was not enumerated"));
        };
        let lock = directory.try_lock(OsStr::new("inspection-hook.lock"), LockMode::Exclusive)?;
        let expected = FileIdentity {
            volume: directory.identity.volume,
            file: entry.identity,
        };
        let held = directory.open_for_rename(&entry.name, expected, &lock)?;
        directory.rename(&held.file, OsStr::new("displaced"))?;
        drop(held);
        let mut replacement = directory.create_file(&entry.name)?;
        replacement.write_all(b"replacement bytes")?;
        replacement.sync_all()?;
    }
    for (entry, path) in paths {
        let access = FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE;
        #[cfg(test)]
        let access = if INSPECTION_DACL_AFTER_SNAPSHOT.load(Ordering::SeqCst) {
            access | WRITE_DAC
        } else {
            access
        };
        let handle = relative(
            directory.handle(),
            &entry.name,
            entry.directory,
            FILE_OPEN,
            access,
            null(),
        )?;
        let expected = FileIdentity {
            volume: directory.identity.volume,
            file: entry.identity,
        };
        if identity(handle.as_raw_handle())? != expected {
            return Err(denied("inspected entry identity changed"));
        }
        if entry.directory {
            directory.security.check(handle.as_raw_handle())?;
            let mut chain = directory.chain.clone();
            chain.push(Arc::new(handle));
            let child = Directory {
                chain,
                identity: expected,
                security: directory.security.clone(),
                enumeration: Mutex::new(()),
            };
            state.entries.push(PrivateTreeEntry {
                relative_path: path.clone(),
                identity: expected,
                directory: true,
                file_access: None,
                snapshot: None,
            });
            inspect_directory(&child, &path, depth + 1, limits, state)?;
            child.check()?;
        } else {
            let access = directory
                .security
                .check_owner_access(handle.as_raw_handle(), true)?;
            let snapshot = file_snapshot(handle.as_raw_handle(), expected)?;
            #[cfg(test)]
            if INSPECTION_DACL_AFTER_SNAPSHOT.swap(false, Ordering::SeqCst) {
                // Test-only adversary: change only the owned fixture leaf through
                // its already-held WRITE_DAC handle after the observed snapshot.
                let mut acl = [0u64; 2];
                unsafe {
                    ok(InitializeAcl(
                        acl.as_mut_ptr().cast(),
                        size_of::<ACL>() as u32,
                        ACL_REVISION,
                    ))?;
                    let code = SetSecurityInfo(
                        handle.as_raw_handle(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        acl.as_mut_ptr().cast(),
                        null_mut(),
                    );
                    if code != ERROR_SUCCESS {
                        return Err(io::Error::from_raw_os_error(code as i32));
                    }
                }
                INSPECTION_DACL_MUTATION_APPLIED.store(true, Ordering::SeqCst);
            }
            let access_after = directory
                .security
                .check_owner_access(handle.as_raw_handle(), true)?;
            if access_after != access {
                return Err(denied(
                    "inspected file owner or DACL changed after snapshot",
                ));
            }
            state.entries.push(PrivateTreeEntry {
                relative_path: path,
                identity: expected,
                directory: false,
                file_access: Some(access),
                snapshot: Some(snapshot),
            });
        }
    }
    directory.check()
}

#[derive(Clone, Copy, Debug)]
pub struct EnumerationLimits {
    pub max_entries: usize,
    pub max_name_bytes: usize,
}
#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: OsString,
    pub identity: FileIdentity,
    pub directory: bool,
}
struct RawEntry {
    name: OsString,
    identity: [u8; 16],
    directory: bool,
}

fn directory_entries(handle: HANDLE, limits: EnumerationLimits) -> io::Result<Vec<RawEntry>> {
    directory_entries_with_policy(handle, limits, true)
}

fn source_directory_entries(
    handle: HANDLE,
    limits: EnumerationLimits,
) -> io::Result<Vec<RawEntry>> {
    directory_entries_with_policy(handle, limits, false)
}

fn directory_entries_with_policy(
    handle: HANDLE,
    limits: EnumerationLimits,
    private_names: bool,
) -> io::Result<Vec<RawEntry>> {
    if limits.max_entries == 0
        || limits.max_entries > 4096
        || limits.max_name_bytes == 0
        || limits.max_name_bytes > 1048576
    {
        return Err(invalid("invalid directory enumeration limits"));
    }
    let mut entries = Vec::new();
    let mut name_bytes = 0usize;
    let mut buffer = vec![0u64; 8192];
    let capacity = buffer.len() * size_of::<u64>();
    let header = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
    let mut class = FileIdExtdDirectoryRestartInfo;
    loop {
        buffer.fill(0);
        let result = unsafe {
            GetFileInformationByHandleEx(handle, class, buffer.as_mut_ptr().cast(), capacity as u32)
        };
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                return Ok(entries);
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        class = FileIdExtdDirectoryInfo;
        let mut offset = 0usize;
        loop {
            if offset % std::mem::align_of::<FILE_ID_EXTD_DIR_INFO>() != 0
                || offset
                    .checked_add(size_of::<FILE_ID_EXTD_DIR_INFO>())
                    .is_none_or(|end| end > capacity)
            {
                return Err(invalid("invalid directory entry layout"));
            }
            // SAFETY: the output buffer is aligned, the fixed record fits, and the
            // variable name length is checked against the same buffer below.
            let entry = unsafe {
                &*buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_EXTD_DIR_INFO>()
            };
            let length = entry.FileNameLength as usize;
            let end = offset
                .checked_add(header)
                .and_then(|value| value.checked_add(length))
                .filter(|value| *value <= capacity)
                .ok_or_else(|| invalid("directory name exceeds its buffer"))?;
            if length == 0 || length % 2 != 0 {
                return Err(invalid("invalid directory name length"));
            }
            // SAFETY: FileNameLength is even and the complete name was bounded above.
            let name = unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), length / 2) };
            if name != [46] && name != [46, 46] {
                name_bytes = name_bytes
                    .checked_add(length)
                    .ok_or_else(|| invalid("directory size overflow"))?;
                if entries.len() >= limits.max_entries || name_bytes > limits.max_name_bytes {
                    return Err(invalid("directory enumeration limit exceeded"));
                }
                if entry.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(denied("reparse entry in source directory"));
                }
                let name = OsString::from_wide(name);
                if private_names {
                    validate_component(&name)?;
                } else {
                    validate_source_component(&name)?;
                }
                entries.push(RawEntry {
                    name,
                    identity: entry.FileId.Identifier,
                    directory: entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                });
            }
            if entry.NextEntryOffset == 0 {
                break;
            }
            let next = offset
                .checked_add(entry.NextEntryOffset as usize)
                .ok_or_else(|| invalid("directory offset overflow"))?;
            if next < end || next >= capacity {
                return Err(invalid("invalid next directory entry"));
            }
            offset = next;
        }
    }
}

// Query the held object's normalized long leaf. Caller spelling alone cannot
// distinguish data from a reserved lock when NTFS 8.3 aliases are enabled.
fn held_leaf(handle: HANDLE) -> io::Result<OsString> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, flags) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    if required > 32768 {
        return Err(invalid("held state name exceeds limit"));
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let length = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(invalid("held state name changed"));
    }
    buffer.truncate(length as usize);
    let start = buffer
        .iter()
        .rposition(|c| *c == 92)
        .map_or(0, |offset| offset + 1);
    let leaf = OsString::from_wide(&buffer[start..]);
    validate_component(&leaf)?;
    Ok(leaf)
}

pub struct MutationFile<'lock> {
    file: PrivateFile,
    lock: &'lock StateLock,
}
impl MutationFile<'_> {
    pub fn identity(&self) -> FileIdentity {
        self.file.identity
    }
    pub fn read_limited(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
        self.file.read_limited(maximum)
    }
}

pub struct UpdateFile<'lock> {
    file: PrivateFile,
    lock: &'lock StateLock,
}
impl UpdateFile<'_> {
    fn check(&self) -> io::Result<()> {
        self.lock.check()?;
        if self.lock.mode != LockMode::Exclusive || self.lock.file.parent != self.file.parent {
            return Err(denied("invalid update guard"));
        }
        self.file.check()
    }
    pub fn identity(&self) -> FileIdentity {
        self.file.identity
    }
    pub fn length(&self) -> io::Result<u64> {
        self.check()?;
        Ok(self.file.file.metadata()?.len())
    }
    pub fn position(&mut self) -> io::Result<u64> {
        self.check()?;
        self.file.file.stream_position()
    }
    pub fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check()?;
        self.file.file.seek(position)
    }
    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        self.file.file.write_all(bytes)
    }
    pub fn append_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        self.file.file.seek(SeekFrom::End(0))?;
        self.file.file.write_all(bytes)
    }
    /// Set length while preserving the explicit cursor, including past EOF.
    pub fn truncate(&mut self, length: u64) -> io::Result<()> {
        self.check()?;
        let cursor = self.file.file.stream_position()?;
        self.file.file.set_len(length)?;
        self.file.file.seek(SeekFrom::Start(cursor))?;
        Ok(())
    }
    pub fn read_limited(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
        self.check()?;
        self.file.read_limited(maximum)
    }
    pub fn sync_all(&self) -> io::Result<()> {
        self.check()?;
        self.file.sync_all()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalState {
    DispositionAcknowledged,
    NamespaceUnknown,
}
#[derive(Debug)]
pub struct Removal {
    pub identity: FileIdentity,
    pub state: RemovalState,
}
#[derive(Debug)]
pub enum RemovalError {
    Unchanged(io::Error),
    Uncertain {
        source: io::Error,
        identity: FileIdentity,
        state: RemovalState,
    },
}
impl From<io::Error> for RemovalError {
    fn from(source: io::Error) -> Self {
        Self::Unchanged(source)
    }
}
impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unchanged(e) => write!(f, "removal not started: {e}"),
            Self::Uncertain { source, .. } => write!(f, "removal requires inspection: {source}"),
        }
    }
}
impl std::error::Error for RemovalError {}
fn remove_handle(handle: HANDLE, expected: FileIdentity) -> Result<Removal, RemovalError> {
    point("before_disposition")?;
    let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status = IO_STATUS_BLOCK::default();
    // The synchronous, checked handle is consumed and only closed afterward.
    let result = unsafe {
        NtSetInformationFile(
            handle,
            &mut status,
            (&information as *const FILE_DISPOSITION_INFORMATION).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    if result < 0 {
        return Err(RemovalError::Uncertain {
            source: io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            identity: expected,
            state: RemovalState::NamespaceUnknown,
        });
    }
    if let Err(source) = point("after_disposition") {
        return Err(RemovalError::Uncertain {
            source,
            identity: expected,
            state: RemovalState::DispositionAcknowledged,
        });
    }
    Ok(Removal {
        identity: expected,
        state: RemovalState::DispositionAcknowledged,
    })
}

pub struct PrivateFile {
    file: File,
    identity: FileIdentity,
    parent: FileIdentity,
    _anchors: Vec<Arc<OwnedHandle>>,
    security: Security,
    writable_candidate: AtomicBool,
    publication: Mutex<()>,
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
    /// By-handle comparison evidence, not a checksum or a transaction lock.
    pub fn snapshot(&self) -> io::Result<FileSnapshot> {
        self.check()?;
        file_snapshot(self.file.as_raw_handle(), self.identity)
    }
    /// Read directly into caller-owned storage, advancing the existing cursor.
    /// The caller retains its domain lock and owns buffer zeroization on errors.
    pub fn read_into(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let count = self.file.read(buffer)?;
        self.check()?;
        Ok(count)
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
        if !self.writable_candidate.load(Ordering::Relaxed) {
            return Err(denied(
                "existing or published state requires an exclusive update guard",
            ));
        }
        self.file.write_all(bytes)
    }
    pub fn sync_all(&self) -> io::Result<()> {
        self.check()?;
        self.file.sync_all()
    }
}

/// Snapshot facts retained by a held source file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    File,
    Directory,
}

/// By-handle metadata observed for one source object; not an atomic tree snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSnapshot {
    pub identity: FileIdentity,
    pub length: u64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
    pub kind: SourceKind,
    pub link_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEntry {
    pub name: OsString,
    pub identity: FileIdentity,
    pub kind: SourceKind,
    pub snapshot: SourceSnapshot,
}

/// A held source-directory capability with no private-state authority.
pub struct SourceDirectory {
    chain: Vec<Arc<OwnedHandle>>,
    identities: Vec<FileIdentity>,
    remaining_depth: usize,
    enumeration: Mutex<()>,
}

impl SourceDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_depth(path, 64)
    }

    /// Open a source root with a fixed maximum number of directory descents.
    /// Child capabilities carry and decrement this budget; it cannot be reset.
    pub fn open_with_depth(path: &Path, max_depth: usize) -> io::Result<Self> {
        if max_depth > 64 {
            return Err(invalid("source depth limit exceeds the hard ceiling"));
        }
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => {
                    return Err(unsupported(
                        "source requires a local drive; UNC/device paths are unsupported",
                    ));
                }
            },
            _ => return Err(invalid("source root must be an absolute drive path")),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(invalid("drive-relative source root"));
        }
        let names: Vec<_> = components
            .map(|component| match component {
                Component::Normal(name) => {
                    validate_source_component(name)?;
                    Ok(name.to_os_string())
                }
                _ => Err(invalid("ambiguous source root path")),
            })
            .collect::<io::Result<_>>()?;
        if names.len() > 128 {
            return Err(invalid("source ancestor limit exceeded"));
        }
        let root = wide(OsStr::new(&format!("\\\\?\\{}:\\", char::from(drive))));
        let drive_path = wide(OsStr::new(&format!("{}:\\", char::from(drive))));
        if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != DRIVE_FIXED {
            return Err(unsupported("source requires a fixed local drive"));
        }
        let root_access = FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE
            | if names.is_empty() {
                FILE_LIST_DIRECTORY
            } else {
                0
            };
        let raw = unsafe {
            CreateFileW(
                root.as_ptr(),
                root_access,
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
        let fs_len = filesystem
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(filesystem.len());
        if String::from_utf16_lossy(&filesystem[..fs_len]) != "NTFS" {
            return Err(unsupported("source requires NTFS semantics"));
        }
        let root_identity = identity(first.as_raw_handle())?;
        let mut chain = vec![Arc::new(first)];
        let mut identities = vec![root_identity];
        for (index, name) in names.iter().enumerate() {
            let is_leaf = index + 1 == names.len();
            let parent = chain.last().expect("root handle retained");
            let access = FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if is_leaf { FILE_LIST_DIRECTORY } else { 0 };
            let handle = relative_source(parent.as_raw_handle(), name, true, FILE_OPEN, access)?;
            let child_identity = identity(handle.as_raw_handle())?;
            if child_identity.volume != root_identity.volume || identities.contains(&child_identity)
            {
                return Err(denied("source path crossed volume or repeated an ancestor"));
            }
            chain.push(Arc::new(handle));
            identities.push(child_identity);
        }
        let source = Self {
            chain,
            identities,
            remaining_depth: max_depth,
            enumeration: Mutex::new(()),
        };
        source.check()?;
        Ok(source)
    }

    pub fn identity(&self) -> FileIdentity {
        *self.identities.last().unwrap()
    }

    /// Enumerate bounded observations and reopen every listed object by its full identity.
    /// A call checks each observed entry; it does not make a whole-tree atomic snapshot.
    pub fn enumerate(&self, limits: EnumerationLimits) -> io::Result<Vec<SourceEntry>> {
        self.check()?;
        let _guard = self
            .enumeration
            .lock()
            .map_err(|_| invalid("source enumeration lock poisoned"))?;
        self.check()?;
        let parent = self
            .chain
            .last()
            .ok_or_else(|| invalid("empty source chain"))?;
        let entries = source_directory_entries(parent.as_raw_handle(), limits)?;
        let volume = self.identity().volume;
        let mut observed = Vec::with_capacity(entries.len());
        for entry in entries {
            let expected = FileIdentity {
                volume,
                file: entry.identity,
            };
            let access = FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if entry.directory {
                    FILE_TRAVERSE | FILE_LIST_DIRECTORY
                } else {
                    FILE_READ_DATA
                };
            let handle = relative_source(
                parent.as_raw_handle(),
                &entry.name,
                entry.directory,
                FILE_OPEN,
                access,
            )?;
            let actual = identity(handle.as_raw_handle())?;
            if actual != expected || actual.volume != volume {
                return Err(denied("source entry identity changed during enumeration"));
            }
            ensure_kind(handle.as_raw_handle(), entry.directory)?;
            let snapshot = source_snapshot(handle.as_raw_handle(), expected, entry.directory)?;
            observed.push(SourceEntry {
                name: entry.name,
                identity: expected,
                kind: snapshot.kind,
                snapshot,
            });
        }
        self.check()?;
        Ok(observed)
    }

    /// Open a directory child only when its full observed identity still matches.
    pub fn child_expected(
        &self,
        name: &OsStr,
        expected: FileIdentity,
    ) -> io::Result<SourceDirectory> {
        self.check()?;
        validate_source_component(name)?;
        if self.remaining_depth == 0 {
            return Err(invalid("source directory depth budget exhausted"));
        }
        if expected.volume != self.identity().volume || self.identities.contains(&expected) {
            return Err(denied("source child crosses volume or repeats an ancestor"));
        }
        let parent = self
            .chain
            .last()
            .ok_or_else(|| invalid("empty source chain"))?;
        let handle = relative_source(
            parent.as_raw_handle(),
            name,
            true,
            FILE_OPEN,
            FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )?;
        let actual = identity(handle.as_raw_handle())?;
        if actual != expected {
            return Err(denied("source directory identity changed before open"));
        }
        ensure_kind(handle.as_raw_handle(), true)?;
        let mut chain = self.chain.clone();
        chain.push(Arc::new(handle));
        let mut identities = self.identities.clone();
        identities.push(expected);
        let child = SourceDirectory {
            chain,
            identities,
            remaining_depth: self.remaining_depth - 1,
            enumeration: Mutex::new(()),
        };
        child.check()?;
        Ok(child)
    }

    pub fn open_file(&self, name: &OsStr) -> io::Result<SourceFile> {
        self.check()?;
        let parent = self.chain.last().unwrap();
        let handle = relative_source(
            parent.as_raw_handle(),
            name,
            false,
            FILE_OPEN,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )?;
        let file_identity = identity(handle.as_raw_handle())?;
        if file_identity.volume != self.identity().volume {
            return Err(denied("source file is on a different volume"));
        }
        let source_file = SourceFile {
            file: File::from(handle),
            identity: file_identity,
            parent_identity: self.identity(),
            leaf_name: name.to_os_string(),
            anchors: self.chain.clone(),
            anchor_identities: self.identities.clone(),
        };
        source_file.check()?;
        Ok(source_file)
    }

    /// Open a child only if its full physical identity still matches an observation.
    pub fn open_file_expected(
        &self,
        name: &OsStr,
        expected: FileIdentity,
    ) -> io::Result<SourceFile> {
        let file = self.open_file(name)?;
        if file.identity != expected {
            return Err(denied("source file identity changed before open"));
        }
        Ok(file)
    }

    fn check(&self) -> io::Result<()> {
        check_source_anchors(&self.chain, &self.identities)
    }
}

/// An immutable execution-permission observation for a held source file.
/// Values are produced only by the fallible source observation API.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionPermission {
    executable: bool,
    identity: FileIdentity,
    security: execution_observation::SecurityFingerprint,
    context: execution_observation::ContextKey,
}

impl std::fmt::Debug for ExecutionPermission {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("ExecutionPermission")
            .field("executable", &self.executable)
            .finish_non_exhaustive()
    }
}

impl ExecutionPermission {
    pub fn executable(&self) -> bool {
        self.executable
    }
}

/// A regular source file held through its directory capability.
pub struct SourceFile {
    file: File,
    identity: FileIdentity,
    parent_identity: FileIdentity,
    leaf_name: OsString,
    anchors: Vec<Arc<OwnedHandle>>,
    anchor_identities: Vec<FileIdentity>,
}

impl SourceFile {
    /// Observe execution permission without executing or mapping the source.
    pub fn execution_permission(&self) -> io::Result<ExecutionPermission> {
        execution_observation::observe(self)
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub fn snapshot(&self) -> io::Result<SourceSnapshot> {
        self.check()?;
        source_snapshot(self.file.as_raw_handle(), self.identity, false)
    }

    /// Read from the held file and reject metadata changes across the read.
    pub fn read_limited(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
        let before = self.snapshot()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(invalid("source file exceeds read limit"));
        }
        let after = self.snapshot()?;
        if before != after {
            return Err(denied("source file changed during checked read"));
        }
        Ok(bytes)
    }

    fn check(&self) -> io::Result<()> {
        check_source_anchors(&self.anchors, &self.anchor_identities)?;
        ensure_kind(self.file.as_raw_handle(), false)?;
        if identity(self.file.as_raw_handle())? != self.identity
            || self.anchor_identities.last().copied() != Some(self.parent_identity)
            || self.parent_identity.volume != self.identity.volume
        {
            return Err(denied("source file or parent identity changed"));
        }
        Ok(())
    }
}

fn check_source_anchors(
    anchors: &[Arc<OwnedHandle>],
    identities: &[FileIdentity],
) -> io::Result<()> {
    if anchors.is_empty() || anchors.len() != identities.len() {
        return Err(invalid("invalid held source ancestor chain"));
    }
    let volume = identities[0].volume;
    for (anchor, expected) in anchors.iter().zip(identities) {
        ensure_kind(anchor.as_raw_handle(), true)?;
        if identity(anchor.as_raw_handle())? != *expected || expected.volume != volume {
            return Err(denied("source ancestor identity changed"));
        }
    }
    Ok(())
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
impl StateLock {
    pub fn identity(&self) -> FileIdentity {
        self.file.identity()
    }
    /// Revalidate the held private object without changing its bytes or length.
    pub fn check(&self) -> io::Result<()> {
        if self.file.snapshot()?.length != 0 {
            return Err(denied("transaction lock must be empty"));
        }
        Ok(())
    }
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
    relative_validated(parent, name, directory, disposition, access, descriptor)
}

fn relative_source(
    parent: HANDLE,
    name: &OsStr,
    directory: bool,
    disposition: u32,
    access: u32,
) -> io::Result<OwnedHandle> {
    validate_source_component(name)?;
    relative_validated(parent, name, directory, disposition, access, null())
}

fn validate_source_component(name: &OsStr) -> io::Result<()> {
    let units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty()
        || units == [u16::from(b'.')]
        || units == [u16::from(b'.'), u16::from(b'.')]
        || units
            .iter()
            .any(|unit| *unit == 0 || matches!(*unit, 0x2f | 0x5c | 0x3a))
    {
        return Err(invalid("ambiguous source path component"));
    }
    Ok(())
}

fn relative_validated(
    parent: HANDLE,
    name: &OsStr,
    directory: bool,
    disposition: u32,
    access: u32,
    descriptor: *const SECURITY_DESCRIPTOR,
) -> io::Result<OwnedHandle> {
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
mod staged_package {
    use super::*;
    use std::os::windows::io::IntoRawHandle;

    const META: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    const ROOT_READ: u32 = META | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
    const READ_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_DELETE;
    const OBSERVER_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const MAX_ENTRIES: usize = 4096;
    const MAX_NAMES: usize = 1048576;
    const MAX_SD: usize = 65536;

    struct UncertainClose {
        raw: usize,
        error: u32,
        identity: Option<FileIdentity>,
        phase: &'static str,
    }
    impl std::fmt::Debug for UncertainClose {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UncertainClose")
                .field("raw", &self.raw)
                .field("error", &self.error)
                .field("identity", &self.identity)
                .field("phase", &self.phase)
                .finish()
        }
    }

    #[derive(Debug, Default)]
    pub(super) struct CloseState {
        active: AtomicU64,
        poisoned: AtomicBool,
        uncertain: Mutex<Vec<UncertainClose>>,
    }
    #[derive(Debug)]
    struct CloseFault {
        message: &'static str,
        state: Arc<CloseState>,
        primary: Option<io::Error>,
    }
    impl std::fmt::Display for CloseFault {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)?;
            let count = self
                .state
                .uncertain
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            write!(f, " ({count} retained uncertain native owners)")?;
            if let Some(error) = &self.primary {
                write!(f, ": {error}")?;
            }
            Ok(())
        }
    }
    impl std::error::Error for CloseFault {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.primary.as_ref().map(|e| e as _)
        }
    }
    impl CloseState {
        pub(super) fn record(
            &self,
            raw: HANDLE,
            error: u32,
            identity: Option<FileIdentity>,
            phase: &'static str,
        ) {
            self.poisoned.store(true, Ordering::Release);
            // A failed close may have consumed/reused the value. This owning
            // uncertainty slot is never blindly re-closed, including in Drop.
            self.uncertain
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(UncertainClose {
                    raw: raw as usize,
                    error,
                    identity,
                    phase,
                });
        }
        pub(super) fn fault(
            self: &Arc<Self>,
            message: &'static str,
            primary: Option<io::Error>,
        ) -> io::Error {
            let kind = primary
                .as_ref()
                .map_or(io::ErrorKind::Other, io::Error::kind);
            io::Error::new(
                kind,
                CloseFault {
                    message,
                    state: Arc::clone(self),
                    primary,
                },
            )
        }
        pub(super) fn check(self: &Arc<Self>) -> io::Result<()> {
            if self.poisoned.load(Ordering::Acquire) {
                Err(self.fault("package native ownership/close uncertainty", None))
            } else {
                Ok(())
            }
        }
        fn acquire(self: &Arc<Self>) -> io::Result<()> {
            self.check()?;
            self.active
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < MAX_ENTRIES as u64).then(|| n + 1)
                })
                .map_err(|_| invalid("package view lease limit exceeded"))?;
            Ok(())
        }
        fn zero(self: &Arc<Self>) -> io::Result<()> {
            self.check()?;
            if self.active.load(Ordering::Acquire) != 0 {
                return Err(denied("package has live read leases"));
            }
            // Observing the releasing Drop's zero count orders its completed
            // close/uncertainty publication before this final poison check.
            self.check()
        }
    }
    fn close_owned(
        handle: OwnedHandle,
        state: &Arc<CloseState>,
        id: Option<FileIdentity>,
        phase: &'static str,
    ) -> io::Result<()> {
        let raw = handle.into_raw_handle();
        if unsafe { CloseHandle(raw) } == 0 {
            let code = unsafe { GetLastError() };
            state.record(raw, code, id, phase);
            Err(state.fault(
                "package CloseHandle failed",
                Some(io::Error::from_raw_os_error(code as i32)),
            ))
        } else {
            Ok(())
        }
    }
    fn finish_owned<T>(
        handle: OwnedHandle,
        state: &Arc<CloseState>,
        id: Option<FileIdentity>,
        phase: &'static str,
        result: io::Result<T>,
    ) -> io::Result<T> {
        match close_owned(handle, state, id, phase) {
            Ok(()) => result,
            Err(_) => Err(state.fault("package checked temporary close failed", result.err())),
        }
    }
    fn close_file_lease(file: File, state: &Arc<CloseState>, id: FileIdentity) -> io::Result<()> {
        let owner = unsafe { OwnedHandle::from_raw_handle(file.into_raw_handle()) };
        let result = close_owned(owner, state, Some(id), "package read lease");
        state.active.fetch_sub(1, Ordering::AcqRel);
        result
    }
    impl CloseState {
        fn healthy_count(self: &Arc<Self>) -> io::Result<u64> {
            self.check()?;
            let count = self.active.load(Ordering::Acquire);
            self.check()?;
            Ok(count)
        }
    }
    impl StageCore {
        fn prove_live_refusal(&self, expected_count: u64) -> io::Result<()> {
            if expected_count == 0
                || self.domain.closes.healthy_count()? != expected_count
                || self.phase != PublicationState::NamespaceUnknown
                || self.final_name.is_some()
                || self.removal.is_some()
                || self.root.is_none()
                || self.root_identity.is_none()
                || self.root_policy.is_none()
                || self.bridge.is_some()
                || self.reader.is_some()
            {
                return Err(denied("live-view refusal has incomplete stage facts"));
            }
            self.check_root()?;
            let creator = self.root.as_ref().unwrap().as_raw_handle();
            let name = PreparedName::new(&self.original_name)?;
            let observer = native_open(
                self.domain.parent(),
                &name,
                true,
                FILE_OPEN,
                ROOT_READ,
                OBSERVER_SHARE,
                null(),
                &self.domain.closes,
                "package-live-original-name",
            )?;
            let mut measured_identity = None;
            let result = (|| {
                let raw = observer.as_raw_handle();
                let actual = identity(raw)?;
                measured_identity = Some(actual);
                if Some(actual) != self.root_identity || identity(creator)? != actual {
                    return Err(denied("live-view original-name identity differs"));
                }
                ensure_kind(raw, true)?;
                if held_leaf(raw)? != self.original_name
                    || held_leaf(creator)? != self.original_name
                    || self.domain.facts(raw, FILE_ALL_ACCESS)?
                        != *self.root_policy.as_ref().unwrap()
                {
                    return Err(denied("live-view original-name policy or leaf changed"));
                }
                self.inventory(raw)?;
                self.check_root()?;
                self.domain.check()
            })();
            finish_owned(
                observer,
                &self.domain.closes,
                measured_identity,
                "package live-view original-name observer",
                result,
            )?;
            self.check_root()?;
            self.domain.check()?;
            if held_leaf(creator)? != self.original_name
                || self.domain.closes.healthy_count()? != expected_count
            {
                return Err(denied("live-view count or original namespace changed"));
            }
            Ok(())
        }
    }

    struct PreparedName {
        wide: Vec<u16>,
    }
    impl PreparedName {
        fn new(name: &OsStr) -> io::Result<Self> {
            let wide = name.encode_wide().collect::<Vec<_>>();
            if wide
                .len()
                .checked_mul(2)
                .is_none_or(|n| n == 0 || n > u16::MAX as usize)
            {
                return Err(invalid("package native component length invalid"));
            }
            Ok(Self { wide })
        }
    }
    #[derive(Debug)]
    pub(super) struct NativeError {
        pub(super) phase: &'static str,
        pub(super) status: i32,
    }
    impl std::fmt::Display for NativeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{} NTSTATUS=0x{:08x}", self.phase, self.status as u32)
        }
    }
    impl std::error::Error for NativeError {}
    fn native_error(phase: &'static str, status: i32) -> io::Error {
        let kind =
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).kind();
        io::Error::new(kind, NativeError { phase, status })
    }
    fn native_open(
        parent: HANDLE,
        name: &PreparedName,
        directory: bool,
        disposition: u32,
        access: u32,
        share: u32,
        descriptor: *const SECURITY_DESCRIPTOR,
        state: &Arc<CloseState>,
        phase: &'static str,
    ) -> io::Result<OwnedHandle> {
        let unicode = UNICODE_STRING {
            Length: (name.wide.len() * 2) as u16,
            MaximumLength: (name.wide.len() * 2) as u16,
            Buffer: name.wide.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: descriptor,
            SecurityQualityOfService: null(),
        };
        let mut raw = null_mut();
        let mut iosb = IO_STATUS_BLOCK::default();
        // IRP_MJ_CREATE is synchronous; NONALERT+SYNCHRONIZE also binds all
        // subsequent operations to synchronous nonalertable file-object I/O.
        // No COMPLETE_IF_OPLOCKED, async mode, backup intent or flag fallback.
        let returned = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut iosb,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                share,
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
        if returned != 0 {
            let error = native_error(phase, returned);
            if !raw.is_null() {
                state.record(raw, 0, None, "unclassified failed native-open output");
                return Err(state.fault(
                    "failed package open returned unclassified output",
                    Some(error),
                ));
            }
            return Err(error);
        }
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(invalid("successful package open returned no valid owner"));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
    pub(super) fn observation_open(
        parent: HANDLE,
        name: &OsStr,
        execute: bool,
        state: &Arc<CloseState>,
    ) -> io::Result<OwnedHandle> {
        validate_source_component(name)?;
        let prepared = PreparedName::new(name)?;
        native_open(
            parent,
            &prepared,
            false,
            FILE_OPEN,
            META | if execute { FILE_EXECUTE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            state,
            if execute {
                "package-execute"
            } else {
                "package-metadata"
            },
        )
    }
    fn sid_copy(sid: PSID, base: *const u8, length: usize) -> io::Result<Vec<u8>> {
        let offset = (sid as usize)
            .checked_sub(base as usize)
            .ok_or_else(|| invalid("package SID outside descriptor"))?;
        if sid.is_null()
            || sid as usize % 4 != 0
            || offset.checked_add(8).is_none_or(|n| n > length)
        {
            return Err(invalid("package SID prefix bounds/alignment invalid"));
        }
        let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
        let size = 8 + count * 4;
        if count > 15 || offset.checked_add(size).is_none_or(|n| n > length) {
            return Err(invalid("package SID tail outside descriptor"));
        }
        ok(unsafe { IsValidSid(sid) })?;
        if unsafe { GetLengthSid(sid) } as usize != size {
            return Err(invalid("package SID length mismatch"));
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), size) }.to_vec())
    }
    fn sid_text(bytes: &[u8]) -> io::Result<String> {
        let mut words = vec![0u32; bytes.len().div_ceil(4)];
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len());
        }
        let mut text = null_mut();
        ok(unsafe { ConvertSidToStringSidW(words.as_mut_ptr().cast(), &mut text) })?;
        let allocation = LocalAllocation(text.cast());
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(invalid("package SID text bound exceeded"));
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| invalid("package SID text invalid"))?;
        drop(allocation);
        Ok(value)
    }
    fn descriptor(user: &[u8], group: &[u8], mask: u32) -> io::Result<Vec<usize>> {
        let user = sid_text(user)?;
        let group = sid_text(group)?;
        let text = wide(OsStr::new(&format!(
            "O:{user}G:{group}D:P(A;;0x{mask:08x};;;{user})"
        )));
        let mut raw = null_mut();
        let mut length = 0;
        ok(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                &mut length,
            )
        })?;
        let allocation = LocalAllocation(raw);
        if length as usize > MAX_SD || (length as usize) < size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
        {
            return Err(invalid("package descriptor size invalid"));
        }
        let mut words = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                raw.cast::<u8>(),
                words.as_mut_ptr().cast(),
                length as usize,
            );
        }
        drop(allocation);
        Ok(words)
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct PolicyFacts {
        owner: Vec<u8>,
        group: Vec<u8>,
        dacl: Vec<u8>,
        control: u16,
    }
    fn policy(
        handle: HANDLE,
        user: &[u8],
        group_expected: &[u8],
        mask: u32,
    ) -> io::Result<PolicyFacts> {
        let mut owner = null_mut();
        let mut group = null_mut();
        let mut dacl = null_mut();
        let mut raw = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                null_mut(),
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let allocation = LocalAllocation(raw.cast());
        ok(unsafe { IsValidSecurityDescriptor(raw) })?;
        let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
        if length > MAX_SD || length < size_of::<SECURITY_DESCRIPTOR_RELATIVE>() {
            return Err(invalid("package policy descriptor bound invalid"));
        }
        let owner = sid_copy(owner, raw.cast(), length)?;
        let group = sid_copy(group, raw.cast(), length)?;
        let mut control = 0;
        let mut revision = 0;
        ok(unsafe { GetSecurityDescriptorControl(raw, &mut control, &mut revision) })?;
        let offset = (dacl as usize)
            .checked_sub(raw as usize)
            .ok_or_else(|| invalid("package DACL outside descriptor"))?;
        if dacl.is_null()
            || dacl as usize % 4 != 0
            || offset
                .checked_add(size_of::<ACL>())
                .is_none_or(|n| n > length)
        {
            return Err(invalid("package ACL header invalid"));
        }
        let size = unsafe { (*dacl).AclSize } as usize;
        if size < size_of::<ACL>() || offset.checked_add(size).is_none_or(|n| n > length) {
            return Err(invalid("package ACL tail invalid"));
        }
        ok(unsafe { IsValidAcl(dacl) })?;
        if control & (SE_DACL_PROTECTED | SE_DACL_PRESENT | SE_SELF_RELATIVE)
            != SE_DACL_PROTECTED | SE_DACL_PRESENT | SE_SELF_RELATIVE
            || owner != user
            || group != group_expected
            || unsafe { (*dacl).AceCount } != 1
        {
            return Err(denied("package owner/group/private DACL changed"));
        }
        let mut ace = null_mut();
        ok(unsafe { GetAce(dacl, 0, &mut ace) })?;
        let ace_offset = (ace as usize)
            .checked_sub(dacl as usize)
            .ok_or_else(|| invalid("package ACE outside ACL"))?;
        if ace as usize % 4 != 0
            || ace_offset
                .checked_add(size_of::<ACE_HEADER>())
                .is_none_or(|n| n > size)
        {
            return Err(invalid("package ACE header invalid"));
        }
        let header = unsafe { ace.cast::<ACE_HEADER>().read() };
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != 0
            || header.AceFlags != 0
            || (header.AceSize as usize) < sid_offset + 8
            || ace_offset
                .checked_add(header.AceSize as usize)
                .is_none_or(|n| n > size)
        {
            return Err(denied(
                "package ACE is not canonical ordinary zero-flag allow",
            ));
        }
        let actual_mask = unsafe { ace.cast::<u8>().add(4).cast::<u32>().read() };
        let sid = sid_copy(
            unsafe { ace.cast::<u8>().add(sid_offset).cast() },
            ace.cast(),
            header.AceSize as usize,
        )?;
        if actual_mask != mask || sid != user {
            return Err(denied("package canonical rights/SID changed"));
        }
        let dacl = unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), size) }.to_vec();
        drop(allocation);
        Ok(PolicyFacts {
            owner,
            group,
            dacl,
            control,
        })
    }

    struct Domain {
        guard: Arc<StateLock>,
        parent_identity: FileIdentity,
        lock_identity: FileIdentity,
        anchors: Vec<Arc<OwnedHandle>>,
        identities: Vec<FileIdentity>,
        security: Security,
        user: Vec<u8>,
        group: Vec<u8>,
        full_sd: Vec<usize>,
        read_sd: Vec<usize>,
        rx_sd: Vec<usize>,
        closes: Arc<CloseState>,
    }
    impl Domain {
        fn capture(directory: &Directory, guard: Arc<StateLock>) -> io::Result<Arc<Self>> {
            directory.require_lock(&guard, true)?;
            let closes = Arc::new(CloseState::default());
            let (user, group) = execution_observation::package_principal(&closes)?;
            let expected = unsafe {
                std::slice::from_raw_parts(
                    directory.security.sid.as_ptr().cast::<u8>(),
                    directory.security.sid.len() * 4,
                )
            };
            if user != expected {
                return Err(denied(
                    "package creation context differs from private parent owner",
                ));
            }
            let identities = directory
                .chain
                .iter()
                .map(|h| identity(h.as_raw_handle()))
                .collect::<io::Result<Vec<_>>>()?;
            let full_sd = descriptor(&user, &group, FILE_ALL_ACCESS)?;
            let read_sd = descriptor(&user, &group, FILE_GENERIC_READ)?;
            let rx_sd = descriptor(&user, &group, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)?;
            let domain = Arc::new(Self {
                lock_identity: guard.identity(),
                guard,
                parent_identity: directory.identity,
                anchors: directory.chain.clone(),
                identities,
                security: directory.security.clone(),
                user,
                group,
                full_sd,
                read_sd,
                rx_sd,
                closes,
            });
            domain.check()?;
            Ok(domain)
        }
        fn parent(&self) -> HANDLE {
            self.anchors.last().unwrap().as_raw_handle()
        }
        fn check(&self) -> io::Result<()> {
            self.closes.check()?;
            check_source_anchors(&self.anchors, &self.identities)?;
            self.security.check(self.parent())?;
            self.guard.check()?;
            if self.identities.last().copied() != Some(self.parent_identity)
                || self.guard.file.parent != self.parent_identity
                || self.guard.identity() != self.lock_identity
                || self.guard.mode != LockMode::Exclusive
            {
                return Err(denied("package parent/lock domain changed"));
            }
            Ok(())
        }
        fn facts(&self, raw: HANDLE, mask: u32) -> io::Result<PolicyFacts> {
            policy(raw, &self.user, &self.group, mask)
        }
    }
    struct StageNode {
        name: OsString,
        identity: Option<FileIdentity>,
        creator: Option<OwnedHandle>,
        snapshot: Option<SourceSnapshot>,
        policy: Option<PolicyFacts>,
        executable: bool,
        attempted: bool,
        flushed: bool,
        sealed: bool,
        poisoned: bool,
    }
    struct StageCore {
        domain: Arc<Domain>,
        original_name: OsString,
        final_name: Option<OsString>,
        root: Option<OwnedHandle>,
        bridge: Option<OwnedHandle>,
        reader: Option<OwnedHandle>,
        bridge_identity: Option<FileIdentity>,
        reader_identity: Option<FileIdentity>,
        root_identity: Option<FileIdentity>,
        root_policy: Option<PolicyFacts>,
        ledger: Vec<StageNode>,
        remaining_entries: usize,
        remaining_name_bytes: usize,
        remaining_depth: usize,
        create_attempted: bool,
        phase: PublicationState,
        removal: Option<DiscardProgress>,
    }
    impl StageCore {
        fn raw(&self) -> io::Result<HANDLE> {
            self.root
                .as_ref()
                .or(self.bridge.as_ref())
                .or(self.reader.as_ref())
                .map(AsRawHandle::as_raw_handle)
                .ok_or_else(|| invalid("package root owner unavailable"))
        }
        fn check_root(&self) -> io::Result<()> {
            self.domain.check()?;
            let raw = self.raw()?;
            ensure_kind(raw, true)?;
            if Some(identity(raw)?) != self.root_identity
                || self
                    .root_identity
                    .is_none_or(|id| id.volume != self.domain.parent_identity.volume)
            {
                return Err(denied("package stage root identity changed"));
            }
            let actual = self.domain.facts(raw, FILE_ALL_ACCESS)?;
            if self
                .root_policy
                .as_ref()
                .is_some_and(|before| *before != actual)
            {
                return Err(denied("package root private policy changed"));
            }
            Ok(())
        }
        fn inventory(&self, root: HANDLE) -> io::Result<()> {
            self.domain.check()?;
            let listed = source_directory_entries(
                root,
                EnumerationLimits {
                    max_entries: MAX_ENTRIES,
                    max_name_bytes: MAX_NAMES,
                },
            )?;
            if listed.len() != self.ledger.len() {
                return Err(denied("package inventory differs from owned ledger"));
            }
            for node in &self.ledger {
                if node.poisoned
                    || !node.attempted
                    || !node.flushed
                    || !node.sealed
                    || node.creator.is_some()
                    || node.identity.is_none()
                    || node.snapshot.is_none()
                    || node.policy.is_none()
                {
                    return Err(denied("package ledger has incomplete/poisoned entry"));
                }
                let id = node.identity.unwrap();
                if !listed.iter().any(|entry| {
                    entry.name == node.name && entry.identity == id.file && !entry.directory
                }) {
                    return Err(denied("package inventory name/identity/kind changed"));
                }
                let prepared = PreparedName::new(&node.name)?;
                let handle = native_open(
                    root,
                    &prepared,
                    false,
                    FILE_OPEN,
                    FILE_GENERIC_READ,
                    READ_SHARE,
                    null(),
                    &self.domain.closes,
                    "package-inventory",
                )?;
                let result = (|| {
                    if source_snapshot(handle.as_raw_handle(), id, false)? != node.snapshot.unwrap()
                        || self
                            .domain
                            .facts(handle.as_raw_handle(), mode(node.executable))?
                            != *node.policy.as_ref().unwrap()
                    {
                        return Err(denied("package sealed entry changed"));
                    }
                    let observed = execution_observation::observe_package(
                        handle.as_raw_handle(),
                        id,
                        root,
                        self.root_identity.unwrap(),
                        &node.name,
                        || {
                            self.domain.check()?;
                            let sampled = source_snapshot(handle.as_raw_handle(), id, false)?;
                            if Some(sampled) != node.snapshot
                                || self
                                    .domain
                                    .facts(handle.as_raw_handle(), mode(node.executable))?
                                    != *node.policy.as_ref().unwrap()
                            {
                                return Err(denied(
                                    "package inventory changed during execution observation",
                                ));
                            }
                            Ok(sampled)
                        },
                        &self.domain.closes,
                    )?;
                    if observed.executable() != node.executable {
                        return Err(denied("package inventory execution mode disagrees"));
                    }
                    Ok(())
                })();
                finish_owned(
                    handle,
                    &self.domain.closes,
                    Some(id),
                    "package inventory reader",
                    result,
                )?;
            }
            Ok(())
        }
        fn make_view<'a>(&'a self, name: &OsStr, executable: bool) -> io::Result<PackageFile<'a>> {
            self.check_root()?;
            let prepared = PreparedName::new(name)?;
            let owner = native_open(
                self.raw()?,
                &prepared,
                false,
                FILE_OPEN,
                FILE_GENERIC_READ,
                READ_SHARE,
                null(),
                &self.domain.closes,
                "package-stage-reader",
            )?;
            let result = (|| {
                let id = identity(owner.as_raw_handle())?;
                let node = self
                    .ledger
                    .iter()
                    .find(|node| node.identity == Some(id))
                    .ok_or_else(|| denied("package reader is not a registered entry"))?;
                if node.poisoned
                    || !node.sealed
                    || !node.flushed
                    || node.creator.is_some()
                    || node.executable != executable
                {
                    return Err(denied("package entry not sealed in requested mode"));
                }
                let sampled = source_snapshot(owner.as_raw_handle(), id, false)?;
                let facts = self.domain.facts(owner.as_raw_handle(), mode(executable))?;
                if Some(sampled) != node.snapshot || Some(&facts) != node.policy.as_ref() {
                    return Err(denied("package reader metadata/policy changed"));
                }
                Ok((id, sampled, facts, node.name.clone()))
            })();
            let (id, snapshot, facts, name) = match result {
                Ok(values) => values,
                Err(error) => {
                    return finish_owned(
                        owner,
                        &self.domain.closes,
                        None,
                        "failed stage reader",
                        Err(error),
                    );
                }
            };
            if let Err(error) = self.domain.closes.acquire() {
                return finish_owned(
                    owner,
                    &self.domain.closes,
                    Some(id),
                    "unleased stage reader",
                    Err(error),
                );
            }
            let view = PackageFile {
                file: Some(File::from(owner)),
                identity: id,
                expected_executable: executable,
                snapshot,
                policy: facts,
                name,
                lease: PackageLease::Stage(self),
                closes: Arc::clone(&self.domain.closes),
            };
            view.execution_permission()?;
            Ok(view)
        }
    }
    #[cfg(test)]
    struct TestTransferError {
        proof: Option<io::Error>,
        anchor: Option<io::Error>,
        file: Option<io::Error>,
        domain: Arc<Domain>,
    }
    #[cfg(test)]
    impl std::fmt::Debug for TestTransferError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestTransferError")
                .field("proof", &self.proof)
                .field("anchor", &self.anchor)
                .field("file", &self.file)
                .field("parent", &self.domain.parent_identity)
                .field("lock", &self.domain.lock_identity)
                .field("closes", &self.domain.closes)
                .finish()
        }
    }
    #[cfg(test)]
    impl std::fmt::Display for TestTransferError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "actual view setup/close failed: {:?}; anchor={:?}; file={:?}; poisoned={}",
                self.proof,
                self.anchor,
                self.file,
                self.domain.closes.poisoned.load(Ordering::Acquire)
            )
        }
    }
    #[cfg(test)]
    impl std::error::Error for TestTransferError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.proof
                .as_ref()
                .or(self.anchor.as_ref())
                .or(self.file.as_ref())
                .map(|e| e as _)
        }
    }
    #[cfg(test)]
    fn test_grant(raw: HANDLE, expected: u32) -> io::Result<()> {
        #[repr(C)]
        #[derive(Default)]
        struct Basic {
            attributes: u32,
            granted: u32,
            handles: u32,
            pointers: u32,
            reserved: [u32; 10],
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(
                raw: HANDLE,
                class: i32,
                value: *mut c_void,
                bytes: u32,
                returned: *mut u32,
            ) -> i32;
        }
        let mut basic = Basic::default();
        let mut returned = 0;
        let status = unsafe {
            NtQueryObject(
                raw,
                0,
                (&mut basic as *mut Basic).cast(),
                size_of::<Basic>() as u32,
                &mut returned,
            )
        };
        if status != 0 {
            return Err(native_error("test genuine-view granted access", status));
        }
        if returned as usize != size_of::<Basic>() || basic.granted != expected {
            return Err(denied("test genuine view actual access differs"));
        }
        println!(
            "live_view_actual_grant expected=0x{expected:08x} actual=0x{:08x} query_status=0",
            basic.granted
        );
        Ok(())
    }
    #[cfg(test)]
    pub(super) struct TestLiveView {
        file: Option<File>,
        root: Option<OwnedHandle>,
        root_id: Option<FileIdentity>,
        expected_root: FileIdentity,
        root_policy: PolicyFacts,
        root_name: OsString,
        domain: Arc<Domain>,
        identity: FileIdentity,
        snapshot: SourceSnapshot,
        policy: PolicyFacts,
        name: OsString,
        executable: bool,
        context: Option<execution_observation::ContextKey>,
    }
    #[cfg(test)]
    fn reject_test_view(
        view: &mut PackageFile<'_>,
        domain: Arc<Domain>,
        proof: io::Error,
    ) -> io::Error {
        let file = view
            .file
            .take()
            .and_then(|file| close_file_lease(file, &view.closes, view.identity).err());
        io::Error::new(
            proof.kind(),
            TestTransferError {
                proof: Some(proof),
                anchor: None,
                file,
                domain,
            },
        )
    }
    #[cfg(test)]
    impl TestLiveView {
        pub(super) fn detach(mut view: PackageFile<'_>) -> io::Result<Self> {
            let domain = match &view.lease {
                PackageLease::Stage(core) => Arc::clone(&core.domain),
                PackageLease::Published(directory) => Arc::clone(&directory.domain),
            };
            let core = match &view.lease {
                PackageLease::Stage(core) => *core,
                PackageLease::Published(_) => {
                    return Err(reject_test_view(
                        &mut view,
                        domain,
                        invalid("test transfer requires a normal stage view"),
                    ));
                }
            };
            let expected_root = match core.root_identity {
                Some(identity) => identity,
                None => {
                    return Err(reject_test_view(
                        &mut view,
                        domain,
                        invalid("test stage root ID unavailable"),
                    ));
                }
            };
            let root_policy = match core.root_policy.clone() {
                Some(policy) => policy,
                None => {
                    return Err(reject_test_view(
                        &mut view,
                        domain,
                        invalid("test stage root policy unavailable"),
                    ));
                }
            };
            let mut holder = Self {
                file: None,
                root: None,
                root_id: None,
                expected_root,
                root_policy,
                root_name: core.original_name.clone(),
                domain,
                identity: view.identity,
                snapshot: view.snapshot,
                policy: view.policy.clone(),
                name: view.name.clone(),
                executable: view.expected_executable,
                context: None,
            };
            let proof = (|| {
                view.check()?;
                if !Arc::ptr_eq(&view.closes, &core.domain.closes) {
                    return Err(denied(
                        "test view is not from the actual stage lease domain",
                    ));
                }
                test_grant(view.raw()?, FILE_GENERIC_READ)?;
                if identity(view.raw()?)? != view.identity {
                    return Err(denied("test original view ID differs"));
                }
                holder.context = Some(execution_observation::test_context(&holder.domain.closes)?);
                let prepared = PreparedName::new(&holder.root_name)?;
                let root = native_open(
                    holder.domain.parent(),
                    &prepared,
                    true,
                    FILE_OPEN,
                    ROOT_READ,
                    OBSERVER_SHARE,
                    null(),
                    &holder.domain.closes,
                    "test genuine-view root anchor",
                )?;
                holder.root = Some(root);
                let raw = holder.root.as_ref().unwrap().as_raw_handle();
                let actual = identity(raw)?;
                holder.root_id = Some(actual);
                if actual != holder.expected_root {
                    return Err(denied("test root anchor actual full ID differs"));
                }
                ensure_kind(raw, true)?;
                test_grant(raw, ROOT_READ)?;
                if held_leaf(raw)? != holder.root_name
                    || holder.domain.facts(raw, FILE_ALL_ACCESS)? != holder.root_policy
                {
                    return Err(denied("test root anchor actual policy/leaf differs"));
                }
                core.check_root()?;
                if execution_observation::test_context(&holder.domain.closes)?
                    != *holder.context.as_ref().unwrap()
                {
                    return Err(denied("test transfer context changed during preparation"));
                }
                Ok(())
            })();
            if let Err(proof) = proof {
                let anchor = holder.close_anchor().err();
                let file = view
                    .file
                    .take()
                    .and_then(|file| close_file_lease(file, &view.closes, view.identity).err());
                return Err(io::Error::new(
                    proof.kind(),
                    TestTransferError {
                        proof: Some(proof),
                        anchor,
                        file,
                        domain: Arc::clone(&holder.domain),
                    },
                ));
            }
            // Everything fallible and every clone precedes this unique real
            // owner transfer. Old PackageFile drops None, without releasing.
            holder.file = view.file.take();
            Ok(holder)
        }
        fn close_anchor(&mut self) -> io::Result<()> {
            if let Some(root) = self.root.take() {
                close_owned(
                    root,
                    &self.domain.closes,
                    self.root_id,
                    "test genuine-view read anchor",
                )?;
            }
            Ok(())
        }
        fn close_parts(&mut self) -> io::Result<()> {
            let anchor = self.close_anchor().err();
            let file = self
                .file
                .take()
                .and_then(|file| close_file_lease(file, &self.domain.closes, self.identity).err());
            if anchor.is_some() || file.is_some() {
                return Err(io::Error::other(TestTransferError {
                    proof: None,
                    anchor,
                    file,
                    domain: Arc::clone(&self.domain),
                }));
            }
            self.domain.closes.check()
        }
        pub(super) fn close(mut self) -> io::Result<()> {
            self.close_parts()?;
            self.domain.closes.zero()
        }
        fn facts(&self) -> io::Result<SourceSnapshot> {
            self.domain.check()?;
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("test view root anchor closed"))?
                .as_raw_handle();
            let file = self
                .file
                .as_ref()
                .ok_or_else(|| invalid("test actual file closed"))?
                .as_raw_handle();
            ensure_kind(root, true)?;
            if identity(root)? != self.expected_root
                || held_leaf(root)? != self.root_name
                || self.domain.facts(root, FILE_ALL_ACCESS)? != self.root_policy
                || self.domain.facts(file, mode(self.executable))? != self.policy
            {
                return Err(denied("test actual view root/file facts changed"));
            }
            let actual = source_snapshot(file, self.identity, false)?;
            if actual != self.snapshot
                || execution_observation::test_context(&self.domain.closes)?
                    != *self.context.as_ref().unwrap()
            {
                return Err(denied("test actual view snapshot/context changed"));
            }
            Ok(actual)
        }
        pub(super) fn read_actual(&mut self, expected: &[u8]) -> io::Result<()> {
            let before = self.facts()?;
            let raw = self.file.as_ref().unwrap().as_raw_handle();
            test_grant(raw, FILE_GENERIC_READ)?;
            let mut bytes = Vec::new();
            {
                let file = self.file.as_mut().unwrap();
                file.seek(SeekFrom::Start(0))?;
                (&mut *file).take(4097).read_to_end(&mut bytes)?;
            }
            if bytes != expected || self.facts()? != before {
                return Err(denied("test transferred actual file bytes changed"));
            }
            let observed = execution_observation::observe_package(
                raw,
                self.identity,
                self.root.as_ref().unwrap().as_raw_handle(),
                self.expected_root,
                &self.name,
                || self.facts(),
                &self.domain.closes,
            )?;
            if observed.executable() != self.executable {
                return Err(denied("test actual view execution mode differs"));
            }
            println!(
                "live_view_actual_read file_id={:?} root_id={:?} snapshot={before:?} bytes_verified=true executable={} same_transferred_file=true",
                self.identity, self.expected_root, self.executable
            );
            Ok(())
        }
    }
    #[cfg(test)]
    impl Drop for TestLiveView {
        fn drop(&mut self) {
            let _ = self.close_parts();
        }
    }
    #[cfg(test)]
    impl StagedDirectory {
        pub(super) fn test_context(&self) -> io::Result<execution_observation::ContextKey> {
            execution_observation::test_context(&self.core.domain.closes)
        }
        pub(super) fn test_zero(&self) -> io::Result<()> {
            self.core.domain.closes.zero()
        }
        pub(super) fn test_managed_policy(&self, raw: HANDLE, mask: u32) -> io::Result<()> {
            let actual = self.core.domain.facts(raw, mask)?;
            println!("live_view_managed_policy mask=0x{mask:08x} actual={actual:?}");
            Ok(())
        }
        pub(super) fn test_finish_native<T>(
            &self,
            owner: OwnedHandle,
            measured: Option<FileIdentity>,
            result: io::Result<T>,
        ) -> io::Result<T> {
            finish_owned(
                owner,
                &self.core.domain.closes,
                measured,
                "live-view independent native observer",
                result,
            )
        }
        pub(super) fn test_unattempted(&self) -> io::Result<()> {
            if self.core.final_name.is_some()
                || self.core.removal.is_some()
                || self.core.phase != PublicationState::NamespaceUnknown
                || self.core.domain.closes.healthy_count()? != 1
            {
                return Err(denied("live-view marker/count facts changed"));
            }
            Ok(())
        }
    }
    #[cfg(test)]
    impl StageRemoval {
        pub(super) fn test_finish_native<T>(
            &self,
            owner: OwnedHandle,
            measured: Option<FileIdentity>,
            result: io::Result<T>,
        ) -> io::Result<T> {
            finish_owned(
                owner,
                &self.domain.closes,
                measured,
                "live-view post-removal independent observer",
                result,
            )
        }
        pub(super) fn test_removed(
            &self,
            root: FileIdentity,
            file: FileIdentity,
        ) -> io::Result<execution_observation::ContextKey> {
            self.domain.check()?;
            self.domain.closes.zero()?;
            if self.root.identity != root
                || self.root.disposition_status != 0
                || !self.root.close_confirmed
                || !self.root.absence_confirmed
                || self.entries.len() != 1
                || self.entries[0].identity != file
                || self.entries[0].disposition_status != 0
                || !self.entries[0].close_confirmed
                || !self.entries[0].absence_confirmed
            {
                return Err(denied("live-view source-guarded removal receipt differs"));
            }
            println!(
                "live_view_actual_removal_receipt root={root:?} file={file:?} native_statuses=0 checked_closes=true measured_original_name_absence=true source_guarded_receipt=true"
            );
            execution_observation::test_context(&self.domain.closes)
        }
    }
    fn mode(executable: bool) -> u32 {
        FILE_GENERIC_READ | if executable { FILE_GENERIC_EXECUTE } else { 0 }
    }

    pub struct StagedDirectory {
        core: StageCore,
        identity: FileIdentity,
    }
    pub struct PackageDirectory {
        domain: Arc<Domain>,
        chain: Vec<(OwnedHandle, FileIdentity)>,
        identity: FileIdentity,
        ledger: Vec<ReadNode>,
        remaining_depth: usize,
        enumeration: Mutex<()>,
    }
    struct ReadNode {
        name: OsString,
        identity: FileIdentity,
        executable: bool,
        snapshot: SourceSnapshot,
        policy: PolicyFacts,
    }
    enum PackageLease<'a> {
        Stage(&'a StageCore),
        Published(&'a PackageDirectory),
    }
    pub struct PackageFile<'a> {
        file: Option<File>,
        identity: FileIdentity,
        expected_executable: bool,
        snapshot: SourceSnapshot,
        policy: PolicyFacts,
        name: OsString,
        lease: PackageLease<'a>,
        closes: Arc<CloseState>,
    }
    pub struct PackagePublication {
        core: StageCore,
        identity: FileIdentity,
        durability: Durability,
    }
    pub struct PackageAcceptance {
        directory: PackageDirectory,
        #[allow(dead_code)]
        identity: FileIdentity,
        #[allow(dead_code)]
        durability: Durability,
    }
    pub struct StageRecovery {
        core: StageCore,
        publication: Option<(FileIdentity, Durability)>,
    }
    // Each receipt fact is constructed only after actual disposition, checked
    // close and exact native name absence have all been confirmed.
    #[allow(dead_code)]
    struct RemovedEntryEvidence {
        identity: FileIdentity,
        disposition_status: i32,
        close_confirmed: bool,
        absence_confirmed: bool,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum DiscardClose {
        Unobserved,
        Confirmed,
        Uncertain,
    }
    struct DiscardStep {
        name: PreparedName,
        identity: FileIdentity,
        owner: Option<OwnedHandle>,
        probe_owner: Option<OwnedHandle>,
        open_attempted: bool,
        open_status: Option<i32>,
        validated: bool,
        disposition_attempted: bool,
        disposition_status: Option<i32>,
        close: DiscardClose,
        absence_attempted: bool,
        absence_status: Option<i32>,
        absence_confirmed: bool,
    }
    impl DiscardStep {
        fn prepare(name: &OsStr, identity: FileIdentity) -> io::Result<Self> {
            Ok(Self {
                name: PreparedName::new(name)?,
                identity,
                owner: None,
                probe_owner: None,
                open_attempted: false,
                open_status: None,
                validated: false,
                disposition_attempted: false,
                disposition_status: None,
                close: DiscardClose::Unobserved,
                absence_attempted: false,
                absence_status: None,
                absence_confirmed: false,
            })
        }
        fn confirm_absence(
            &mut self,
            parent: HANDLE,
            directory: bool,
            closes: &Arc<CloseState>,
            phase: &'static str,
        ) -> io::Result<()> {
            self.absence_attempted = true;
            match native_open(
                parent,
                &self.name,
                directory,
                FILE_OPEN,
                META,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                closes,
                phase,
            ) {
                Ok(owner) => {
                    // A present name is not deletion authority. Retain the
                    // unexpected owner before any further fallible operation.
                    self.probe_owner = Some(owner);
                    self.absence_status = Some(0);
                    Err(denied("discarded package name is still present"))
                }
                Err(error) => {
                    self.absence_status = discard_native_status(&error, phase);
                    if self.absence_status == Some(0xc0000034u32 as i32) {
                        self.absence_confirmed = true;
                        Ok(())
                    } else {
                        Err(error)
                    }
                }
            }
        }
        fn confirmed_evidence(&self) -> io::Result<RemovedEntryEvidence> {
            if !self.validated
                || !self.disposition_attempted
                || self.disposition_status != Some(0)
                || self.close != DiscardClose::Confirmed
                || !self.absence_attempted
                || self.absence_status != Some(0xc0000034u32 as i32)
                || !self.absence_confirmed
                || self.owner.is_some()
                || self.probe_owner.is_some()
            {
                return Err(invalid("package removal evidence is incomplete"));
            }
            Ok(RemovedEntryEvidence {
                identity: self.identity,
                disposition_status: self.disposition_status.unwrap(),
                close_confirmed: self.close == DiscardClose::Confirmed,
                absence_confirmed: self.absence_confirmed,
            })
        }
    }
    struct DiscardProgress {
        // Index order is bound to the immutable construction ledger. Allocate
        // every owner/probe slot and receipt capacity before any disposition.
        entries: Vec<DiscardStep>,
        root: DiscardStep,
        confirmed: Vec<RemovedEntryEvidence>,
    }
    impl DiscardProgress {
        fn prepare(core: &StageCore) -> io::Result<Self> {
            if core.removal.is_some()
                || core.final_name.is_some()
                || core.root.is_none()
                || core.bridge.is_some()
                || core.reader.is_some()
                || core.ledger.len() > MAX_ENTRIES
            {
                return Err(denied("package is not an intact unpublished discard stage"));
            }
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(core.ledger.len())
                .map_err(|e| io::Error::other(e))?;
            let mut confirmed = Vec::new();
            confirmed
                .try_reserve_exact(core.ledger.len())
                .map_err(|e| io::Error::other(e))?;
            for node in &core.ledger {
                entries.push(DiscardStep::prepare(
                    &node.name,
                    node.identity
                        .ok_or_else(|| invalid("package discard entry identity unavailable"))?,
                )?);
            }
            Ok(Self {
                entries,
                root: DiscardStep::prepare(
                    &core.original_name,
                    core.root_identity
                        .ok_or_else(|| invalid("package discard root identity unavailable"))?,
                )?,
                confirmed,
            })
        }
    }
    fn discard_native_status(error: &io::Error, phase: &'static str) -> Option<i32> {
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<NativeError>())
            .filter(|e| e.phase == phase)
            .map(|e| e.status)
    }
    fn discard_mark(raw: HANDLE) -> i32 {
        let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        let mut iosb = IO_STATUS_BLOCK::default();
        // All callers use the actual NONALERT+SYNCHRONIZE file object. Its
        // documented synchronous completion keeps both request buffers live
        // through return; only returned STATUS_SUCCESS acknowledges marking.
        unsafe {
            NtSetInformationFile(
                raw,
                &mut iosb,
                (&information as *const FILE_DISPOSITION_INFORMATION).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        }
    }
    impl StageCore {
        fn discard_entries(&mut self) -> io::Result<()> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("package discard root creator unavailable"))?
                .as_raw_handle();
            for (index, node) in self.ledger.iter().enumerate() {
                self.check_root()?;
                self.domain.closes.zero()?;
                let progress = self.removal.as_mut().unwrap();
                let step = &mut progress.entries[index];
                step.open_attempted = true;
                match native_open(
                    root,
                    &step.name,
                    false,
                    FILE_OPEN,
                    DELETE | META,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    &self.domain.closes,
                    "package-discard-child-open",
                ) {
                    Ok(owner) => {
                        step.owner = Some(owner);
                        step.open_status = Some(0);
                    }
                    Err(error) => {
                        step.open_status =
                            discard_native_status(&error, "package-discard-child-open");
                        return Err(error);
                    }
                }
                let raw = step.owner.as_ref().unwrap().as_raw_handle();
                if Some(source_snapshot(raw, step.identity, false)?) != node.snapshot
                    || self.domain.facts(raw, mode(node.executable))?
                        != *node.policy.as_ref().unwrap()
                {
                    return Err(denied(
                        "package discard entry identity, snapshot or policy changed",
                    ));
                }
                self.domain.check()?;
                self.domain.closes.zero()?;
                step.validated = true;
                step.disposition_attempted = true;
                let returned = discard_mark(raw);
                step.disposition_status = Some(returned);
                if returned != 0 {
                    return Err(native_error("package-discard-child-disposition", returned));
                }
                // The marked file object is only closed from here onward.
                // Its full identity was cached before setting delete-pending.
                let owner = step.owner.take().unwrap();
                match close_owned(
                    owner,
                    &self.domain.closes,
                    Some(step.identity),
                    "package discarded child",
                ) {
                    Ok(()) => step.close = DiscardClose::Confirmed,
                    Err(error) => {
                        step.close = DiscardClose::Uncertain;
                        return Err(error);
                    }
                }
                step.confirm_absence(
                    root,
                    false,
                    &self.domain.closes,
                    "package-discard-child-absence",
                )?;
                self.domain.closes.zero()?;
                progress.confirmed.push(step.confirmed_evidence()?);
            }
            Ok(())
        }
        fn discard_root(&mut self) -> io::Result<()> {
            let progress = self.removal.as_ref().unwrap();
            if progress.entries.len() != self.ledger.len()
                || progress.confirmed.len() != self.ledger.len()
            {
                return Err(invalid("package discard entry progress is incomplete"));
            }
            for step in &progress.entries {
                step.confirmed_evidence()?;
            }
            self.check_root()?;
            self.domain.closes.zero()?;
            let root = self.root.as_ref().unwrap().as_raw_handle();
            let listed = source_directory_entries(
                root,
                EnumerationLimits {
                    max_entries: MAX_ENTRIES,
                    max_name_bytes: MAX_NAMES,
                },
            )?;
            if !listed.is_empty() {
                return Err(denied("package discard root is not empty"));
            }
            self.check_root()?;
            self.domain.closes.zero()?;
            let step = &mut self.removal.as_mut().unwrap().root;
            step.validated = true;
            step.disposition_attempted = true;
            // Use the original FA/DELETE creator. A second DELETE open would
            // conflict with that creator's existing RW/noDELETE sharing.
            let returned = discard_mark(root);
            step.disposition_status = Some(returned);
            if returned != 0 {
                return Err(native_error("package-discard-root-disposition", returned));
            }
            // No root/file queries after marking: close, then observe only
            // through the independently held parent/lock/ancestor domain.
            let owner = self.root.take().unwrap();
            match close_owned(
                owner,
                &self.domain.closes,
                Some(step.identity),
                "package discarded root",
            ) {
                Ok(()) => step.close = DiscardClose::Confirmed,
                Err(error) => {
                    step.close = DiscardClose::Uncertain;
                    return Err(error);
                }
            }
            step.confirm_absence(
                self.domain.parent(),
                true,
                &self.domain.closes,
                "package-discard-root-absence",
            )?;
            self.domain.check()?;
            self.domain.closes.zero()?;
            step.confirmed_evidence()?;
            Ok(())
        }
    }
    #[allow(dead_code)]
    pub struct StageRemoval {
        domain: Arc<Domain>,
        root: RemovedEntryEvidence,
        entries: Vec<RemovedEntryEvidence>,
    }
    pub enum StageRemovalError {
        Unchanged {
            source: io::Error,
            stage: StagedDirectory,
        },
        Uncertain {
            source: io::Error,
            recovery: StageRecovery,
        },
    }
    impl std::fmt::Debug for StageRemovalError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Unchanged { source, stage } => f
                    .debug_struct("Unchanged")
                    .field("source", source)
                    .field("stage", stage)
                    .finish(),
                Self::Uncertain { source, recovery } => f
                    .debug_struct("Uncertain")
                    .field("source", source)
                    .field("recovery", recovery)
                    .finish(),
            }
        }
    }
    pub enum StageCreateError {
        Unchanged(io::Error),
        Uncertain {
            source: io::Error,
            recovery: StageRecovery,
        },
    }
    pub enum StagePublishError {
        Unchanged {
            source: io::Error,
            stage: StagedDirectory,
        },
        Uncertain {
            source: io::Error,
            state: PublicationState,
            recovery: StageRecovery,
        },
    }
    pub struct StageAcceptError {
        pub source: io::Error,
        pub recovery: StageRecovery,
    }

    #[derive(Debug)]
    struct RenameRefusalProofError {
        rename: io::Error,
        proof: io::Error,
    }
    impl std::fmt::Display for RenameRefusalProofError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}; intact-stage proof failed: {}",
                self.rename, self.proof
            )
        }
    }
    impl std::error::Error for RenameRefusalProofError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.proof)
        }
    }
    impl StageCore {
        fn prove_rename_refusal(
            &self,
            attempted: &OsStr,
            prior_final_was_none: bool,
        ) -> io::Result<()> {
            if !prior_final_was_none
                || self.final_name.as_deref() != Some(attempted)
                || self.root.is_none()
                || self.root_identity.is_none()
                || self.root_policy.is_none()
                || self.bridge.is_some()
                || self.reader.is_some()
                || self.removal.is_some()
            {
                return Err(denied("rename refusal has unexpected stage bookkeeping"));
            }
            self.check_root()?;
            self.domain.closes.zero()?;
            let creator = self.root.as_ref().unwrap().as_raw_handle();
            let name = PreparedName::new(&self.original_name)?;
            let observer = native_open(
                self.domain.parent(),
                &name,
                true,
                FILE_OPEN,
                ROOT_READ,
                OBSERVER_SHARE,
                null(),
                &self.domain.closes,
                "package-rename-refusal-original-name",
            )?;
            let mut measured_identity = None;
            let result = (|| {
                let raw = observer.as_raw_handle();
                let actual = identity(raw)?;
                measured_identity = Some(actual);
                if Some(actual) != self.root_identity || identity(creator)? != actual {
                    return Err(denied("rename refusal original-name root identity differs"));
                }
                ensure_kind(raw, true)?;
                if held_leaf(raw)? != self.original_name
                    || held_leaf(creator)? != self.original_name
                    || self.domain.facts(raw, FILE_ALL_ACCESS)?
                        != *self.root_policy.as_ref().unwrap()
                {
                    return Err(denied("rename refusal original-name root facts changed"));
                }
                self.inventory(raw)?;
                self.check_root()?;
                self.domain.closes.zero()
            })();
            // None if querying identity failed; the measured foreign ID is
            // retained if a mismatch was found. Never substitute an expected ID.
            finish_owned(
                observer,
                &self.domain.closes,
                measured_identity,
                "package rename-refusal original-name observer",
                result,
            )?;
            self.check_root()?;
            if held_leaf(creator)? != self.original_name {
                return Err(denied("rename refusal original root leaf changed"));
            }
            self.domain.check()?;
            self.domain.closes.zero()
        }
    }

    impl Directory {
        pub fn open_package(
            &self,
            guard: Arc<StateLock>,
            name: &OsStr,
            expected: FileIdentity,
        ) -> io::Result<PackageDirectory> {
            validate_data_component(name)?;
            self.require_lock(&guard, false)?;
            if expected.volume != self.identity.volume {
                return Err(denied("published package volume differs from held parent"));
            }
            Err(unsupported("published package opening is not implemented"))
        }

        pub fn stage_directory(
            &self,
            guard: Arc<StateLock>,
            name: &OsStr,
        ) -> Result<StagedDirectory, StageCreateError> {
            validate_data_component(name).map_err(StageCreateError::Unchanged)?;
            let prepared = PreparedName::new(name).map_err(StageCreateError::Unchanged)?;
            let domain = Domain::capture(self, guard).map_err(StageCreateError::Unchanged)?;
            let mut core = StageCore {
                domain,
                original_name: name.to_os_string(),
                final_name: None,
                root: None,
                bridge: None,
                reader: None,
                bridge_identity: None,
                reader_identity: None,
                root_identity: None,
                root_policy: None,
                ledger: Vec::new(),
                remaining_entries: MAX_ENTRIES,
                remaining_name_bytes: MAX_NAMES - prepared.wide.len() * 2,
                remaining_depth: 64,
                create_attempted: false,
                phase: PublicationState::NamespaceUnknown,
                removal: None,
            };
            core.ledger.reserve(1);
            core.create_attempted = true;
            let result = (|| {
                let owner = native_open(
                    core.domain.parent(),
                    &prepared,
                    true,
                    FILE_CREATE,
                    FILE_ALL_ACCESS,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    core.domain.full_sd.as_ptr().cast(),
                    &core.domain.closes,
                    "package-stage-create",
                )?;
                core.root = Some(owner);
                core.root_identity = Some(identity(core.raw()?)?);
                ensure_kind(core.raw()?, true)?;
                core.root_policy = Some(core.domain.facts(core.raw()?, FILE_ALL_ACCESS)?);
                if held_leaf(core.raw()?)? != name {
                    return Err(denied("created package stage leaf differs"));
                }
                core.check_root()?;
                Ok(core.root_identity.unwrap())
            })();
            match result {
                Ok(identity) => Ok(StagedDirectory { core, identity }),
                Err(source) => Err(StageCreateError::Uncertain {
                    source,
                    recovery: StageRecovery {
                        core,
                        publication: None,
                    },
                }),
            }
        }
    }
    impl StagedDirectory {
        pub fn identity(&self) -> FileIdentity {
            self.identity
        }
        pub fn write_new<'s>(
            &'s mut self,
            name: &OsStr,
            bytes: &[u8],
            executable: bool,
        ) -> io::Result<PackageFile<'s>> {
            validate_source_component(name)?;
            self.core.check_root()?;
            self.core.domain.closes.zero()?;
            let prepared = PreparedName::new(name)?;
            let name_bytes = prepared.wide.len() * 2;
            if self.core.remaining_entries == 0 || name_bytes > self.core.remaining_name_bytes {
                return Err(invalid("package construction bounds exceeded"));
            }
            self.core.ledger.reserve(1);
            let index = self.core.ledger.len();
            self.core.ledger.push(StageNode {
                name: name.to_os_string(),
                identity: None,
                creator: None,
                snapshot: None,
                policy: None,
                executable,
                attempted: true,
                flushed: false,
                sealed: false,
                poisoned: true,
            });
            self.core.remaining_entries -= 1;
            self.core.remaining_name_bytes -= name_bytes;
            let result = (|| {
                let owner = native_open(
                    self.core.raw()?,
                    &prepared,
                    false,
                    FILE_CREATE,
                    FILE_ALL_ACCESS,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    self.core.domain.full_sd.as_ptr().cast(),
                    &self.core.domain.closes,
                    "package-file-create",
                )?;
                self.core.ledger[index].creator = Some(owner);
                let raw = self.core.ledger[index]
                    .creator
                    .as_ref()
                    .unwrap()
                    .as_raw_handle();
                let id = identity(raw)?;
                self.core.ledger[index].identity = Some(id);
                ensure_kind(raw, false)?;
                if id.volume != self.identity.volume {
                    return Err(denied("package entry volume differs"));
                }
                let actual_name = held_leaf(raw)?;
                validate_source_component(&actual_name)?;
                if actual_name != name {
                    return Err(denied("created package file leaf differs"));
                }
                let mut offset = 0;
                while offset < bytes.len() {
                    let size = (bytes.len() - offset).min(u32::MAX as usize);
                    let mut written = 0;
                    ok(unsafe {
                        WriteFile(
                            raw,
                            bytes[offset..].as_ptr(),
                            size as u32,
                            &mut written,
                            null_mut(),
                        )
                    })?;
                    if written == 0 || written as usize > size {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "package native write made invalid progress",
                        ));
                    }
                    offset += written as usize;
                }
                ok(unsafe { FlushFileBuffers(raw) })?;
                self.core.ledger[index].flushed = true;
                let descriptor = if executable {
                    &self.core.domain.rx_sd
                } else {
                    &self.core.domain.read_sd
                };
                let mut present = 0;
                let mut dacl = null_mut();
                let mut defaulted = 0;
                ok(unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor.as_ptr().cast_mut().cast(),
                        &mut present,
                        &mut dacl,
                        &mut defaulted,
                    )
                })?;
                if present == 0 || dacl.is_null() {
                    return Err(invalid("package sealing DACL absent"));
                }
                let status = unsafe {
                    SetSecurityInfo(
                        raw,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        dacl,
                        null_mut(),
                    )
                };
                if status != ERROR_SUCCESS {
                    return Err(io::Error::from_raw_os_error(status as i32));
                }
                self.core.ledger[index].policy =
                    Some(self.core.domain.facts(raw, mode(executable))?);
                let creator = self.core.ledger[index].creator.take().unwrap();
                close_owned(
                    creator,
                    &self.core.domain.closes,
                    Some(id),
                    "package last writer",
                )?;
                let reader = native_open(
                    self.core.raw()?,
                    &prepared,
                    false,
                    FILE_OPEN,
                    FILE_GENERIC_READ,
                    READ_SHARE,
                    null(),
                    &self.core.domain.closes,
                    "package-postseal-reader",
                )?;
                let mut file = File::from(reader);
                let checked = (|| {
                    let sampled = source_snapshot(file.as_raw_handle(), id, false)?;
                    if sampled.length != bytes.len() as u64
                        || self
                            .core
                            .domain
                            .facts(file.as_raw_handle(), mode(executable))?
                            != *self.core.ledger[index].policy.as_ref().unwrap()
                    {
                        return Err(denied("package post-writer baseline changed"));
                    }
                    let mut offset = 0;
                    let mut buffer = [0u8; 8192];
                    while offset < bytes.len() {
                        let size = buffer.len().min(bytes.len() - offset);
                        let count = file.read(&mut buffer[..size])?;
                        if count == 0 || buffer[..count] != bytes[offset..offset + count] {
                            return Err(denied("package postseal bytes differ"));
                        }
                        offset += count;
                    }
                    if source_snapshot(file.as_raw_handle(), id, false)? != sampled {
                        return Err(denied("package changed across postseal read"));
                    }
                    Ok(sampled)
                })();
                let reader = unsafe { OwnedHandle::from_raw_handle(file.into_raw_handle()) };
                let sampled = finish_owned(
                    reader,
                    &self.core.domain.closes,
                    Some(id),
                    "package postseal verification",
                    checked,
                )?;
                self.core.ledger[index].snapshot = Some(sampled);
                self.core.ledger[index].sealed = true;
                self.core.ledger[index].poisoned = false;
                Ok(())
            })();
            result?;
            self.core.make_view(name, executable)
        }
        pub fn verify_package_mode<'s>(
            &'s self,
            name: &OsStr,
            executable: bool,
        ) -> io::Result<PackageFile<'s>> {
            validate_source_component(name)?;
            self.core.make_view(name, executable)
        }
        pub fn discard(mut self) -> Result<StageRemoval, StageRemovalError> {
            let live = (|| {
                let count = self.core.domain.closes.healthy_count()?;
                if count == 0 {
                    return Ok(false);
                }
                self.core.prove_live_refusal(count)?;
                Ok(true)
            })();
            match live {
                Ok(true) => {
                    return Err(StageRemovalError::Unchanged {
                        source: denied("package has live read leases"),
                        stage: self,
                    });
                }
                Err(source) => {
                    return Err(StageRemovalError::Uncertain {
                        source,
                        recovery: StageRecovery {
                            core: self.core,
                            publication: None,
                        },
                    });
                }
                Ok(false) => {}
            }
            let result = (|| {
                self.core.check_root()?;
                self.core.domain.closes.zero()?;
                self.core.inventory(self.core.raw()?)?;
                self.core.check_root()?;
                self.core.domain.closes.zero()?;
                self.core.removal = Some(DiscardProgress::prepare(&self.core)?);
                self.core.discard_entries()?;
                self.core.discard_root()?;
                self.core
                    .removal
                    .as_ref()
                    .unwrap()
                    .root
                    .confirmed_evidence()
            })();
            let root = match result {
                Ok(root) => root,
                Err(source) => {
                    return Err(StageRemovalError::Uncertain {
                        source,
                        recovery: StageRecovery {
                            core: self.core,
                            publication: None,
                        },
                    });
                }
            };
            let progress = self.core.removal.take().unwrap();
            Ok(StageRemoval {
                domain: self.core.domain,
                root,
                entries: progress.confirmed,
            })
        }

        pub fn publish_directory(
            mut self,
            final_name: &OsStr,
        ) -> Result<PackagePublication, StagePublishError> {
            let live = (|| {
                validate_data_component(final_name)?;
                let count = self.core.domain.closes.healthy_count()?;
                if count == 0 {
                    return Ok(false);
                }
                self.core.prove_live_refusal(count)?;
                Ok(true)
            })();
            match live {
                Ok(true) => {
                    return Err(StagePublishError::Unchanged {
                        source: denied("package has live read leases"),
                        stage: self,
                    });
                }
                Err(source) => {
                    return Err(StagePublishError::Uncertain {
                        source,
                        state: PublicationState::NamespaceUnknown,
                        recovery: StageRecovery {
                            core: self.core,
                            publication: None,
                        },
                    });
                }
                Ok(false) => {}
            }
            let prior_final_was_none = self.core.final_name.is_none();
            let preflight = (|| {
                validate_data_component(final_name)?;
                self.core.check_root()?;
                self.core.domain.closes.zero()?;
                self.core.inventory(self.core.raw()?)?;
                PreparedName::new(final_name)
            })();
            let prepared = match preflight {
                Ok(name) => name,
                Err(source) => {
                    return Err(StagePublishError::Uncertain {
                        source,
                        state: PublicationState::NamespaceUnknown,
                        recovery: StageRecovery {
                            core: self.core,
                            publication: None,
                        },
                    });
                }
            };
            self.core.final_name = Some(final_name.to_os_string());
            let length = offset_of!(FILE_RENAME_INFORMATION, FileName) + prepared.wide.len() * 2;
            let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
            let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            let mut iosb = IO_STATUS_BLOCK::default();
            let returned = unsafe {
                (*information).Anonymous.ReplaceIfExists = false;
                (*information).RootDirectory = self.core.domain.parent();
                (*information).FileNameLength = (prepared.wide.len() * 2) as u32;
                std::ptr::copy_nonoverlapping(
                    prepared.wide.as_ptr(),
                    (*information).FileName.as_mut_ptr(),
                    prepared.wide.len(),
                );
                // Same synchronous NONALERT+SYNCHRONIZE root file object.
                // File object, request and IOSB stay live through final return.
                NtSetInformationFile(
                    self.core.root.as_ref().unwrap().as_raw_handle(),
                    &mut iosb,
                    information.cast(),
                    length as u32,
                    FileRenameInformation,
                )
            };
            if returned != 0 {
                let source = native_error("package-directory-rename", returned);
                if returned == 0xc0000035u32 as i32 {
                    match self
                        .core
                        .prove_rename_refusal(final_name, prior_final_was_none)
                    {
                        Ok(()) => {
                            // Only the proved aborted attempt marker is reset.
                            // All identities, inventory, phase and ownership stay intact.
                            self.core.final_name = None;
                            return Err(StagePublishError::Unchanged {
                                source,
                                stage: self,
                            });
                        }
                        Err(proof) => {
                            let source = io::Error::new(
                                proof.kind(),
                                RenameRefusalProofError {
                                    rename: source,
                                    proof,
                                },
                            );
                            return Err(StagePublishError::Uncertain {
                                source,
                                state: PublicationState::NamespaceUnknown,
                                recovery: StageRecovery {
                                    core: self.core,
                                    publication: None,
                                },
                            });
                        }
                    }
                }
                let state = self.core.phase;
                return Err(StagePublishError::Uncertain {
                    source,
                    state,
                    recovery: StageRecovery {
                        core: self.core,
                        publication: None,
                    },
                });
            }
            let postcheck = (|| {
                self.core.check_root()?;
                let current = PreparedName::new(final_name)?;
                let owner = native_open(
                    self.core.domain.parent(),
                    &current,
                    true,
                    FILE_OPEN,
                    ROOT_READ,
                    OBSERVER_SHARE,
                    null(),
                    &self.core.domain.closes,
                    "package-publication-postcheck",
                )?;
                let result = (|| {
                    if identity(owner.as_raw_handle())? != self.identity {
                        return Err(denied("published package root identity differs"));
                    }
                    self.core
                        .domain
                        .facts(owner.as_raw_handle(), FILE_ALL_ACCESS)?;
                    self.core.inventory(owner.as_raw_handle())
                })();
                finish_owned(
                    owner,
                    &self.core.domain.closes,
                    Some(self.identity),
                    "package published-root observer",
                    result,
                )?;
                let old = PreparedName::new(&self.core.original_name)?;
                match native_open(
                    self.core.domain.parent(),
                    &old,
                    true,
                    FILE_OPEN,
                    META,
                    OBSERVER_SHARE,
                    null(),
                    &self.core.domain.closes,
                    "package-old-name",
                ) {
                    Err(error)
                        if error
                            .get_ref()
                            .and_then(|e| e.downcast_ref::<NativeError>())
                            .is_some_and(|e| e.status == 0xc0000034u32 as i32) =>
                    {
                        Ok(())
                    }
                    Ok(owner) => finish_owned(
                        owner,
                        &self.core.domain.closes,
                        None,
                        "unexpected old package name",
                        Err(denied("old package name remains after publication")),
                    ),
                    Err(error) => Err(error),
                }
            })();
            if let Err(source) = postcheck {
                return Err(StagePublishError::Uncertain {
                    source,
                    state: PublicationState::NamespaceUnknown,
                    recovery: StageRecovery {
                        core: self.core,
                        publication: None,
                    },
                });
            }
            self.core.phase = PublicationState::NamePublished;
            Ok(PackagePublication {
                core: self.core,
                identity: self.identity,
                durability: Durability::FileBuffersFlushed,
            })
        }
    }

    impl PackageFile<'_> {
        fn raw(&self) -> io::Result<HANDLE> {
            self.file
                .as_ref()
                .map(AsRawHandle::as_raw_handle)
                .ok_or_else(|| invalid("package view is closed"))
        }
        fn domain_root(&self) -> io::Result<(&Arc<Domain>, HANDLE, FileIdentity)> {
            match &self.lease {
                PackageLease::Stage(core) => {
                    core.check_root()?;
                    Ok((&core.domain, core.raw()?, core.root_identity.unwrap()))
                }
                PackageLease::Published(directory) => {
                    directory.check()?;
                    Ok((&directory.domain, directory.root(), directory.identity))
                }
            }
        }
        fn check(&self) -> io::Result<()> {
            let (domain, _, parent) = self.domain_root()?;
            if self.identity.volume != parent.volume
                || domain.facts(self.raw()?, mode(self.expected_executable))? != self.policy
                || source_snapshot(self.raw()?, self.identity, false)? != self.snapshot
            {
                return Err(denied("package read view identity/policy/snapshot changed"));
            }
            Ok(())
        }
        pub fn identity(&self) -> FileIdentity {
            self.identity
        }
        pub fn snapshot(&self) -> io::Result<SourceSnapshot> {
            self.check()?;
            source_snapshot(self.raw()?, self.identity, false)
        }
        pub fn read_limited(&mut self, maximum: usize) -> io::Result<Vec<u8>> {
            let before = self.snapshot()?;
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| invalid("closed package view"))?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            (&mut *file)
                .take(maximum.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > maximum {
                return Err(invalid("package file exceeds read limit"));
            }
            if self.snapshot()? != before {
                return Err(denied("package changed during checked read"));
            }
            Ok(bytes)
        }
        pub fn execution_permission(&self) -> io::Result<ExecutionPermission> {
            self.check()?;
            let (_, parent, parent_id) = self.domain_root()?;
            let value = execution_observation::observe_package(
                self.raw()?,
                self.identity,
                parent,
                parent_id,
                &self.name,
                || self.snapshot(),
                &self.closes,
            )?;
            if value.executable() != self.expected_executable {
                return Err(denied(
                    "package execution observation disagrees with declared mode",
                ));
            }
            Ok(value)
        }
    }
    impl Drop for PackageFile<'_> {
        fn drop(&mut self) {
            if let Some(file) = self.file.take() {
                let _ = close_file_lease(file, &self.closes, self.identity);
            }
        }
    }
    impl PackagePublication {
        pub fn identity(&self) -> FileIdentity {
            self.identity
        }
        pub fn durability(&self) -> Durability {
            self.durability
        }
        pub fn accept(mut self) -> Result<PackageAcceptance, StageAcceptError> {
            let result = (|| {
                self.core.check_root()?;
                self.core.domain.closes.zero()?;
                if self.core.phase != PublicationState::NamePublished {
                    return Err(denied("package publication not proven"));
                }
                self.core.inventory(self.core.raw()?)?;
                let name = PreparedName::new(
                    self.core
                        .final_name
                        .as_ref()
                        .ok_or_else(|| invalid("published package name missing"))?,
                )?;
                self.core.bridge = Some(native_open(
                    self.core.domain.parent(),
                    &name,
                    true,
                    FILE_OPEN,
                    ROOT_READ,
                    OBSERVER_SHARE,
                    null(),
                    &self.core.domain.closes,
                    "package-accept-bridge",
                )?);
                self.core.check_root()?;
                let bridge = self.core.bridge.as_ref().unwrap().as_raw_handle();
                self.core.bridge_identity = Some(identity(bridge)?);
                if self.core.bridge_identity != Some(self.identity) {
                    return Err(denied("package acceptance bridge identity differs"));
                }
                self.core.domain.facts(bridge, FILE_ALL_ACCESS)?;
                self.core.inventory(bridge)?;
                let creator = self
                    .core
                    .root
                    .take()
                    .ok_or_else(|| invalid("package DELETE root owner missing"))?;
                close_owned(
                    creator,
                    &self.core.domain.closes,
                    Some(self.identity),
                    "package DELETE root at accept",
                )?;
                self.core.domain.closes.zero()?;
                self.core.reader = Some(native_open(
                    self.core.domain.parent(),
                    &name,
                    true,
                    FILE_OPEN,
                    ROOT_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    &self.core.domain.closes,
                    "package-final-read-root",
                )?);
                let reader = self.core.reader.as_ref().unwrap().as_raw_handle();
                ensure_kind(reader, true)?;
                self.core.reader_identity = Some(identity(reader)?);
                if self.core.reader_identity != Some(self.identity) {
                    return Err(denied(
                        "fresh no-DELETE-sharing package root identity differs",
                    ));
                }
                self.core.domain.facts(reader, FILE_ALL_ACCESS)?;
                self.core.inventory(reader)?;
                self.core.domain.check()?;
                let bridge = self.core.bridge.take().unwrap();
                close_owned(
                    bridge,
                    &self.core.domain.closes,
                    Some(self.identity),
                    "package acceptance bridge",
                )?;
                self.core.domain.closes.zero()?;
                Ok(())
            })();
            if let Err(source) = result {
                return Err(StageAcceptError {
                    source,
                    recovery: StageRecovery {
                        core: self.core,
                        publication: Some((self.identity, self.durability)),
                    },
                });
            }
            let ledger = self
                .core
                .ledger
                .iter()
                .map(|node| ReadNode {
                    name: node.name.clone(),
                    identity: node.identity.unwrap(),
                    executable: node.executable,
                    snapshot: node.snapshot.unwrap(),
                    policy: node.policy.as_ref().unwrap().clone(),
                })
                .collect();
            let reader = self.core.reader.take().unwrap();
            let directory = PackageDirectory {
                domain: self.core.domain,
                chain: vec![(reader, self.identity)],
                identity: self.identity,
                ledger,
                remaining_depth: self.core.remaining_depth,
                enumeration: Mutex::new(()),
            };
            Ok(PackageAcceptance {
                directory,
                identity: self.identity,
                durability: self.durability,
            })
        }
    }
    impl PackageDirectory {
        fn root(&self) -> HANDLE {
            self.chain.last().unwrap().0.as_raw_handle()
        }
        fn check(&self) -> io::Result<()> {
            self.domain.check()?;
            for (owner, expected) in &self.chain {
                ensure_kind(owner.as_raw_handle(), true)?;
                if identity(owner.as_raw_handle())? != *expected {
                    return Err(denied("accepted package chain identity changed"));
                }
                self.domain.facts(owner.as_raw_handle(), FILE_ALL_ACCESS)?;
            }
            if self.chain.last().map(|(_, id)| *id) != Some(self.identity)
                || self.remaining_depth == 0
            {
                return Err(denied("accepted package read domain invalid"));
            }
            Ok(())
        }
        pub fn identity(&self) -> FileIdentity {
            self.identity
        }
        pub fn verify_package_mode<'p>(
            &'p self,
            name: &OsStr,
            expected: FileIdentity,
            executable: bool,
        ) -> io::Result<PackageFile<'p>> {
            let _serial = self
                .enumeration
                .lock()
                .map_err(|_| denied("accepted package read serialization poisoned"))?;
            validate_source_component(name)?;
            self.check()?;
            let node = self
                .ledger
                .iter()
                .find(|node| node.identity == expected)
                .ok_or_else(|| denied("accepted package ID not in ledger"))?;
            if node.executable != executable {
                return Err(denied("accepted package declared mode differs"));
            }
            let prepared = PreparedName::new(name)?;
            let owner = native_open(
                self.root(),
                &prepared,
                false,
                FILE_OPEN,
                FILE_GENERIC_READ,
                READ_SHARE,
                null(),
                &self.domain.closes,
                "accepted-package-reader",
            )?;
            let result = (|| {
                if source_snapshot(owner.as_raw_handle(), expected, false)? != node.snapshot
                    || self.domain.facts(owner.as_raw_handle(), mode(executable))? != node.policy
                {
                    return Err(denied("accepted package entry changed"));
                }
                self.check()?;
                Ok(())
            })();
            if let Err(error) = result {
                return finish_owned(
                    owner,
                    &self.domain.closes,
                    Some(expected),
                    "failed accepted package view",
                    Err(error),
                );
            }
            if let Err(error) = self.domain.closes.acquire() {
                return finish_owned(
                    owner,
                    &self.domain.closes,
                    Some(expected),
                    "unleased accepted view",
                    Err(error),
                );
            }
            let view = PackageFile {
                file: Some(File::from(owner)),
                identity: expected,
                expected_executable: executable,
                snapshot: node.snapshot,
                policy: node.policy.clone(),
                name: node.name.clone(),
                lease: PackageLease::Published(self),
                closes: Arc::clone(&self.domain.closes),
            };
            view.execution_permission()?;
            Ok(view)
        }
    }
    impl PackageAcceptance {
        pub fn directory(&self) -> &PackageDirectory {
            &self.directory
        }
    }

    impl std::fmt::Debug for StageRecovery {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StageRecovery")
                .field("root_identity", &self.core.root_identity)
                .field("phase", &self.core.phase)
                .field("publication", &self.publication)
                .finish_non_exhaustive()
        }
    }
    impl std::fmt::Debug for StagedDirectory {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StagedDirectory")
                .field("identity", &self.identity)
                .finish_non_exhaustive()
        }
    }
    impl std::fmt::Debug for StageCreateError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Unchanged(source) => f.debug_tuple("Unchanged").field(source).finish(),
                Self::Uncertain { source, recovery } => f
                    .debug_struct("Uncertain")
                    .field("source", source)
                    .field("recovery", recovery)
                    .finish(),
            }
        }
    }
    impl std::fmt::Debug for StagePublishError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Unchanged { source, stage } => f
                    .debug_struct("Unchanged")
                    .field("source", source)
                    .field("stage", stage)
                    .finish(),
                Self::Uncertain {
                    source,
                    state,
                    recovery,
                } => f
                    .debug_struct("Uncertain")
                    .field("source", source)
                    .field("state", state)
                    .field("recovery", recovery)
                    .finish(),
            }
        }
    }
    impl std::fmt::Debug for StageAcceptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StageAcceptError")
                .field("source", &self.source)
                .field("recovery", &self.recovery)
                .finish()
        }
    }
}

pub use staged_package::{
    PackageAcceptance, PackageDirectory, PackageFile, PackagePublication, StageAcceptError,
    StageCreateError, StagePublishError, StageRecovery, StageRemoval, StageRemovalError,
    StagedDirectory,
};

#[cfg(test)]
struct SourceSnapshotTestHook {
    expected: FileIdentity,
    source_path: std::path::PathBuf,
    link_path: std::path::PathBuf,
    ran: Arc<AtomicBool>,
}

#[cfg(test)]
static SOURCE_SNAPSHOT_TEST_HOOK: Mutex<Option<SourceSnapshotTestHook>> = Mutex::new(None);

#[cfg(test)]
fn run_source_snapshot_test_hook(expected: FileIdentity) -> io::Result<()> {
    let hook = {
        let mut slot = SOURCE_SNAPSHOT_TEST_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.as_ref().is_some_and(|hook| hook.expected == expected) {
            slot.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        std::fs::hard_link(&hook.source_path, &hook.link_path)?;
        hook.ran.store(true, Ordering::SeqCst);
    }
    Ok(())
}

fn source_snapshot(
    handle: HANDLE,
    expected: FileIdentity,
    directory: bool,
) -> io::Result<SourceSnapshot> {
    ensure_kind(handle, directory)?;
    #[cfg(test)]
    run_source_snapshot_test_hook(expected)?;
    let standard: FILE_STANDARD_INFO = information(handle, FileStandardInfo)?;
    let basic: FILE_BASIC_INFO = information(handle, FileBasicInfo)?;
    if standard.EndOfFile < 0
        || identity(handle)? != expected
        || standard.Directory != directory
        || standard.DeletePending
        || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(denied("source snapshot identity, kind, or length changed"));
    }
    if standard.NumberOfLinks < 1 || (!directory && standard.NumberOfLinks != 1) {
        return Err(denied("source snapshot link count changed"));
    }
    Ok(SourceSnapshot {
        identity: expected,
        length: standard.EndOfFile as u64,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
        attributes: basic.FileAttributes,
        kind: if directory {
            SourceKind::Directory
        } else {
            SourceKind::File
        },
        link_count: standard.NumberOfLinks as u32,
    })
}

fn file_snapshot(handle: HANDLE, expected: FileIdentity) -> io::Result<FileSnapshot> {
    ensure_kind(handle, false)?;
    let standard: FILE_STANDARD_INFO = information(handle, FileStandardInfo)?;
    let basic: FILE_BASIC_INFO = information(handle, FileBasicInfo)?;
    if standard.EndOfFile < 0 || identity(handle)? != expected {
        return Err(denied("file snapshot identity or length changed"));
    }
    Ok(FileSnapshot {
        identity: expected,
        length: standard.EndOfFile as u64,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
        attributes: basic.FileAttributes,
    })
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
    if _name == "before_rename" {
        GAP_CHECK.with(|slot| {
            if let Some(check) = slot.borrow_mut().as_mut() {
                check();
            }
        });
    }
    #[cfg(test)]
    if FAILURE.with(|slot| slot.get() == Some(_name)) {
        return Err(io::Error::other("injected publication failure"));
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
thread_local! { static GAP_CHECK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
static INSPECTION_DACL_AFTER_SNAPSHOT: AtomicBool = AtomicBool::new(false);

mod execution_observation {
    use super::*;
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    const MAX_BYTES: usize = 65536;
    const MAX_ACES: usize = 4096;
    const METADATA_ACCESS: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    const STATUS_ACCESS_DENIED: i32 = 0xc0000022u32 as i32;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct ContextKey {
        thread_token: bool,
        token_type: i32,
        impersonation_level: Option<i32>,
        token_id: (u32, i32),
        authentication_id: (u32, i32),
        modified_id: (u32, i32),
        user: Vec<u8>,
        primary_group: Vec<u8>,
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct NormalizedAce {
        kind: u8,
        flags: u8,
        mask: u32,
        sid: Vec<u8>,
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Dacl {
        Absent,
        Null,
        Entries(Vec<NormalizedAce>),
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct SecurityFingerprint {
        owner: Vec<u8>,
        group: Vec<u8>,
        control: u16,
        dacl: Dacl,
    }
    struct Descriptor {
        words: Vec<usize>,
        fingerprint: SecurityFingerprint,
    }

    #[derive(Default)]
    struct Handles {
        slots: Vec<Option<OwnedHandle>>,
    }
    impl Handles {
        fn own(&mut self, handle: OwnedHandle) -> usize {
            let index = self.slots.len();
            self.slots.push(Some(handle));
            index
        }
        fn raw(&self, index: usize) -> HANDLE {
            self.slots[index].as_ref().unwrap().as_raw_handle()
        }
        fn finish<T>(mut self, result: io::Result<T>) -> io::Result<T> {
            let mut errors = Vec::new();
            for slot in self.slots.iter_mut().rev() {
                if let Some(handle) = slot.take() {
                    let raw = handle.into_raw_handle();
                    if unsafe { CloseHandle(raw) } == 0 {
                        errors.push(io::Error::last_os_error());
                    }
                }
            }
            if errors.is_empty() {
                return result;
            }
            let primary = result.err();
            let kind = primary
                .as_ref()
                .map_or(io::ErrorKind::Other, io::Error::kind);
            Err(io::Error::new(
                kind,
                ObservationCloseError {
                    primary,
                    closes: errors,
                },
            ))
        }
    }
    #[derive(Debug)]
    struct ObservationCloseError {
        primary: Option<io::Error>,
        closes: Vec<io::Error>,
    }
    impl std::fmt::Display for ObservationCloseError {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(output, "execution observation close uncertainty")?;
            if let Some(primary) = &self.primary {
                write!(output, "; original error: {primary}")?;
            }
            for error in &self.closes {
                write!(output, "; CloseHandle: {error}")?;
            }
            Ok(())
        }
    }
    impl std::error::Error for ObservationCloseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.primary
                .as_ref()
                .map(|error| error as _)
                .or_else(|| self.closes.first().map(|error| error as _))
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OpenPhase {
        Metadata,
        Execute,
    }
    #[derive(Debug)]
    struct NativeOpenError {
        phase: OpenPhase,
        status: i32,
    }
    impl std::fmt::Display for NativeOpenError {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                output,
                "execution observation {:?} NtCreateFile NTSTATUS=0x{:08x}",
                self.phase, self.status as u32
            )
        }
    }
    impl std::error::Error for NativeOpenError {}

    fn open(file: &SourceFile, phase: OpenPhase, handles: &mut Handles) -> io::Result<usize> {
        validate_source_component(&file.leaf_name)?;
        let parent = file
            .anchors
            .last()
            .ok_or_else(|| invalid("source observation has no parent anchor"))?;
        if identity(parent.as_raw_handle())? != file.parent_identity {
            return Err(denied("source observation parent changed"));
        }
        let mut name = file.leaf_name.encode_wide().collect::<Vec<_>>();
        let bytes = name
            .len()
            .checked_mul(2)
            .filter(|bytes| *bytes <= u16::MAX as usize)
            .ok_or_else(|| invalid("source observation component too long"))?
            as u16;
        let name = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle(),
            ObjectName: &name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let access = METADATA_ACCESS
            | if phase == OpenPhase::Execute {
                FILE_EXECUTE
            } else {
                0
            };
        let mut raw = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        // IRP_MJ_CREATE (including an existing-file open) is synchronous: the
        // I/O manager waits for a lower driver's pending create to complete.
        // No FILE_COMPLETE_IF_OPLOCKED or asynchronous mode is requested.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks
        // Request/name/output storage stays live through the completed syscall.
        let returned = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        // A nonpending syscall return is authoritative; IOSB need not duplicate
        // it. Only STATUS_SUCCESS proves a successful handle under this contract.
        if returned != 0 {
            let kind =
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(returned) } as i32)
                    .kind();
            return Err(io::Error::new(
                kind,
                NativeOpenError {
                    phase,
                    status: returned,
                },
            ));
        }
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(invalid("source observation open returned no valid handle"));
        }
        let index = handles.own(unsafe { OwnedHandle::from_raw_handle(raw) });
        ensure_kind(handles.raw(index), false)?;
        if identity(handles.raw(index))? != file.identity {
            return Err(denied(
                "source observation reopened a different full identity",
            ));
        }
        Ok(index)
    }

    fn sid_bytes(sid: PSID, base: *const u8, length: usize) -> io::Result<Vec<u8>> {
        if sid.is_null() || sid as usize % 4 != 0 {
            return Err(invalid("source observation SID absent or misaligned"));
        }
        let offset = (sid as usize)
            .checked_sub(base as usize)
            .ok_or_else(|| invalid("source observation SID outside buffer"))?;
        if !offset.checked_add(8).is_some_and(|end| end <= length) {
            return Err(invalid("source observation SID prefix outside buffer"));
        }
        let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
        let bytes = 8 + 4 * count;
        if count > 15
            || !offset.checked_add(bytes).is_some_and(|end| end <= length)
            || unsafe { IsValidSid(sid) } == 0
            || unsafe { GetLengthSid(sid) } as usize != bytes
        {
            return Err(invalid("source observation SID invalid or out of bounds"));
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), bytes) }.to_vec())
    }
    struct TokenBuffer {
        words: Vec<usize>,
        length: usize,
    }
    fn token_buffer(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<TokenBuffer> {
        let mut needed = 0;
        let first = unsafe { GetTokenInformation(handle, class, null_mut(), 0, &mut needed) };
        let error = if first == 0 {
            unsafe { GetLastError() }
        } else {
            ERROR_SUCCESS
        };
        if first != 0 || error != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        if needed == 0 || needed as usize > MAX_BYTES {
            return Err(unsupported(
                "source token information exceeds supported bound",
            ));
        }
        let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = words.len() * size_of::<usize>();
        unsafe {
            ok(GetTokenInformation(
                handle,
                class,
                words.as_mut_ptr().cast(),
                capacity as u32,
                &mut needed,
            ))?;
        }
        if needed == 0 || needed as usize > capacity {
            return Err(invalid("source token information result exceeds buffer"));
        }
        Ok(TokenBuffer {
            words,
            length: needed as usize,
        })
    }
    fn token_value<T: Copy>(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<T> {
        let buffer = token_buffer(handle, class)?;
        if buffer.length < size_of::<T>() {
            return Err(invalid("source token information structure truncated"));
        }
        Ok(unsafe { buffer.words.as_ptr().cast::<T>().read() })
    }
    fn luid(value: LUID) -> (u32, i32) {
        (value.LowPart, value.HighPart)
    }
    fn context(handle: HANDLE, thread_token: bool) -> io::Result<ContextKey> {
        let first: TOKEN_STATISTICS = token_value(handle, TokenStatistics)?;
        let user_buffer = token_buffer(handle, TokenUser)?;
        if user_buffer.length < size_of::<TOKEN_USER>() {
            return Err(invalid("source token user structure truncated"));
        }
        let user = unsafe { &*user_buffer.words.as_ptr().cast::<TOKEN_USER>() };
        let user = sid_bytes(
            user.User.Sid,
            user_buffer.words.as_ptr().cast(),
            user_buffer.length,
        )?;
        let group_buffer = token_buffer(handle, TokenPrimaryGroup)?;
        if group_buffer.length < size_of::<TOKEN_PRIMARY_GROUP>() {
            return Err(invalid("source token primary group truncated"));
        }
        let group = unsafe { &*group_buffer.words.as_ptr().cast::<TOKEN_PRIMARY_GROUP>() };
        let primary_group = sid_bytes(
            group.PrimaryGroup,
            group_buffer.words.as_ptr().cast(),
            group_buffer.length,
        )?;
        let level = if first.TokenType == TokenImpersonation {
            let value: i32 = token_value(handle, TokenImpersonationLevel)?;
            if value != first.ImpersonationLevel {
                return Err(denied("source token impersonation level changed"));
            }
            Some(value)
        } else if first.TokenType == TokenPrimary {
            None
        } else {
            return Err(unsupported("unsupported source token type"));
        };
        let last: TOKEN_STATISTICS = token_value(handle, TokenStatistics)?;
        if luid(first.TokenId) != luid(last.TokenId)
            || luid(first.AuthenticationId) != luid(last.AuthenticationId)
            || luid(first.ModifiedId) != luid(last.ModifiedId)
            || first.TokenType != last.TokenType
            || (level.is_some() && first.ImpersonationLevel != last.ImpersonationLevel)
        {
            return Err(denied("source token changed during observation"));
        }
        Ok(ContextKey {
            thread_token,
            token_type: first.TokenType,
            impersonation_level: level,
            token_id: luid(first.TokenId),
            authentication_id: luid(first.AuthenticationId),
            modified_id: luid(first.ModifiedId),
            user,
            primary_group,
        })
    }
    fn effective(handles: &mut Handles) -> io::Result<(usize, ContextKey)> {
        let mut raw = null_mut();
        let thread = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                1,
                &mut raw,
            )
        } != 0;
        if !thread {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_TOKEN {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            unsafe {
                ok(OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut raw,
                ))?;
            }
        }
        let index = handles.own(unsafe { OwnedHandle::from_raw_handle(raw) });
        let key = context(handles.raw(index), thread)?;
        Ok((index, key))
    }
    fn duplicate(handles: &mut Handles, original: usize, key: &ContextKey) -> io::Result<usize> {
        let mut raw = null_mut();
        let level = key.impersonation_level.unwrap_or(SecurityImpersonation);
        unsafe {
            ok(DuplicateTokenEx(
                handles.raw(original),
                TOKEN_QUERY,
                null(),
                level,
                TokenImpersonation,
                &mut raw,
            ))?;
        }
        let index = handles.own(unsafe { OwnedHandle::from_raw_handle(raw) });
        let stats: TOKEN_STATISTICS = token_value(handles.raw(index), TokenStatistics)?;
        if stats.TokenType != TokenImpersonation || stats.ImpersonationLevel != level {
            return Err(denied(
                "source AccessCheck duplicate has wrong type or level",
            ));
        }
        Ok(index)
    }
    fn mapping() -> GENERIC_MAPPING {
        GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        }
    }
    fn normalized_mask(mask: u32) -> io::Result<u32> {
        let known = FILE_ALL_ACCESS
            | ACCESS_SYSTEM_SECURITY
            | GENERIC_READ
            | GENERIC_WRITE
            | GENERIC_EXECUTE
            | GENERIC_ALL;
        if mask & !known != 0 {
            return Err(unsupported("unsupported source ACE access bits"));
        }
        let mut mapped = mask;
        unsafe {
            MapGenericMask(&mut mapped, &mapping());
        }
        if mapped & !(FILE_ALL_ACCESS | ACCESS_SYSTEM_SECURITY) != 0 {
            return Err(unsupported("unsupported mapped source ACE rights"));
        }
        Ok(mapped)
    }
    fn decode_descriptor(mut words: Vec<usize>, length: usize) -> io::Result<Descriptor> {
        let raw = words.as_mut_ptr().cast();
        unsafe {
            ok(IsValidSecurityDescriptor(raw))?;
        }
        let mut control = 0;
        let mut revision = 0;
        unsafe {
            ok(GetSecurityDescriptorControl(
                raw,
                &mut control,
                &mut revision,
            ))?;
        }
        let supported = SE_OWNER_DEFAULTED
            | SE_GROUP_DEFAULTED
            | SE_DACL_PRESENT
            | SE_DACL_DEFAULTED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_DACL_AUTO_INHERITED
            | SE_DACL_PROTECTED
            | SE_SELF_RELATIVE;
        if control & SE_SELF_RELATIVE == 0 || control & !supported != 0 {
            return Err(unsupported(
                "unsupported source security descriptor controls",
            ));
        }
        let mut owner = null_mut();
        let mut group = null_mut();
        let mut dacl = null_mut();
        let mut defaulted = 0;
        let mut present = 0;
        unsafe {
            ok(GetSecurityDescriptorOwner(raw, &mut owner, &mut defaulted))?;
            ok(GetSecurityDescriptorGroup(raw, &mut group, &mut defaulted))?;
            ok(GetSecurityDescriptorDacl(
                raw,
                &mut present,
                &mut dacl,
                &mut defaulted,
            ))?;
        }
        let owner = sid_bytes(owner, words.as_ptr().cast(), length)?;
        let group = sid_bytes(group, words.as_ptr().cast(), length)?;
        if (control & SE_DACL_PRESENT != 0) != (present != 0) {
            return Err(invalid("source DACL presence disagreement"));
        }
        let normalized = if present == 0 {
            if !dacl.is_null() {
                return Err(invalid("absent source DACL has data"));
            }
            Dacl::Absent
        } else if dacl.is_null() {
            Dacl::Null
        } else {
            if dacl as usize % 4 != 0 {
                return Err(invalid("source DACL is misaligned"));
            }
            let offset = (dacl as usize)
                .checked_sub(words.as_ptr() as usize)
                .ok_or_else(|| invalid("source DACL outside descriptor"))?;
            if !offset
                .checked_add(size_of::<ACL>())
                .is_some_and(|end| end <= length)
            {
                return Err(invalid("source ACL header exceeds descriptor"));
            }
            let acl_length = unsafe { (*dacl).AclSize } as usize;
            if acl_length < size_of::<ACL>()
                || !offset
                    .checked_add(acl_length)
                    .is_some_and(|end| end <= length)
            {
                return Err(invalid("source ACL exceeds descriptor"));
            }
            unsafe {
                ok(IsValidAcl(dacl))?;
            }
            let count = unsafe { (*dacl).AceCount } as usize;
            if count > MAX_ACES {
                return Err(unsupported("source ACL exceeds ACE bound"));
            }
            let mut entries = Vec::with_capacity(count);
            for index in 0..count {
                let mut ace = null_mut();
                unsafe {
                    ok(GetAce(dacl, index as u32, &mut ace))?;
                }
                if ace as usize % 4 != 0 {
                    return Err(invalid("source ACE is misaligned"));
                }
                let offset = (ace as usize)
                    .checked_sub(dacl as usize)
                    .ok_or_else(|| invalid("source ACE outside ACL"))?;
                if !offset
                    .checked_add(size_of::<ACE_HEADER>())
                    .is_some_and(|end| end <= acl_length)
                {
                    return Err(invalid("source ACE header exceeds ACL"));
                }
                let header = unsafe { ace.cast::<ACE_HEADER>().read() };
                let size = header.AceSize as usize;
                let flags = (OBJECT_INHERIT_ACE
                    | CONTAINER_INHERIT_ACE
                    | NO_PROPAGATE_INHERIT_ACE
                    | INHERIT_ONLY_ACE
                    | INHERITED_ACE) as u8;
                if !matches!(header.AceType, 0 | 1) || header.AceFlags & !flags != 0 {
                    return Err(unsupported("unsupported source ACE type or flags"));
                }
                if size < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
                    || !offset
                        .checked_add(size)
                        .is_some_and(|end| end <= acl_length)
                {
                    return Err(invalid("source ACE exceeds ACL"));
                }
                // Ordinary allow/deny ACEs share the mask/SID layout. Object,
                // callback, compound and audit forms are explicitly unsupported.
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid = unsafe { std::ptr::addr_of_mut!((*allowed).SidStart).cast() };
                let sid = sid_bytes(sid, ace.cast(), size)?;
                let mask = normalized_mask(unsafe { std::ptr::addr_of!((*allowed).Mask).read() })?;
                // Normalize only owned storage, without overlapping Rust references.
                unsafe {
                    std::ptr::addr_of_mut!((*allowed).Mask).write(mask);
                }
                entries.push(NormalizedAce {
                    kind: header.AceType,
                    flags: header.AceFlags,
                    mask,
                    sid,
                });
            }
            Dacl::Entries(entries)
        };
        Ok(Descriptor {
            words,
            fingerprint: SecurityFingerprint {
                owner,
                group,
                control,
                dacl: normalized,
            },
        })
    }
    fn security(handle: HANDLE) -> io::Result<Descriptor> {
        let mut owner = null_mut();
        let mut group = null_mut();
        let mut dacl = null_mut();
        let mut raw = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                null_mut(),
                &mut raw,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        // Copy self-relative OS storage into bounded aligned owned memory, then
        // release the OS allocation on both validation success and failure.
        let result = (|| {
            if raw.is_null() {
                return Err(invalid("source security query returned no descriptor"));
            }
            unsafe {
                ok(IsValidSecurityDescriptor(raw))?;
            }
            let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
            if length < size_of::<SECURITY_DESCRIPTOR_RELATIVE>() || length > MAX_BYTES {
                return Err(unsupported(
                    "source security descriptor exceeds supported bound",
                ));
            }
            let mut words = vec![0usize; length.div_ceil(size_of::<usize>())];
            unsafe {
                std::ptr::copy_nonoverlapping(raw.cast::<u8>(), words.as_mut_ptr().cast(), length);
            }
            decode_descriptor(words, length)
        })();
        let free_error = if !raw.is_null() && !unsafe { LocalFree(raw) }.is_null() {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        match (result, free_error) {
            (value, None) => value,
            (Ok(_), Some(error)) => Err(error),
            (Err(primary), Some(error)) => Err(io::Error::new(
                primary.kind(),
                format!("{primary}; security allocation release failed: {error}"),
            )),
        }
    }
    fn access_check(descriptor: &Descriptor, token: HANDLE) -> io::Result<bool> {
        let mut map = mapping();
        let mut privileges = vec![0usize; size_of::<PRIVILEGE_SET>().div_ceil(size_of::<usize>())];
        for attempt in 0..2 {
            let capacity = privileges.len() * size_of::<usize>();
            let mut needed = capacity as u32;
            let mut granted = 0;
            let mut allowed = 0;
            let result = unsafe {
                AccessCheck(
                    descriptor.words.as_ptr().cast_mut().cast(),
                    token,
                    FILE_EXECUTE,
                    &mut map,
                    privileges.as_mut_ptr().cast(),
                    &mut needed,
                    &mut granted,
                    &mut allowed,
                )
            };
            if result == 0 {
                let error = unsafe { GetLastError() };
                if attempt == 0
                    && error == ERROR_INSUFFICIENT_BUFFER
                    && needed as usize > capacity
                    && needed as usize <= MAX_BYTES
                {
                    privileges = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
                    continue;
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            if needed as usize > capacity {
                return Err(invalid(
                    "source AccessCheck privilege output exceeds buffer",
                ));
            }
            let count =
                unsafe { (*privileges.as_ptr().cast::<PRIVILEGE_SET>()).PrivilegeCount } as usize;
            let end = count
                .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
                .and_then(|tail| tail.checked_add(offset_of!(PRIVILEGE_SET, Privilege)))
                .ok_or_else(|| invalid("source AccessCheck privilege count overflow"))?;
            if end > needed as usize || end > capacity {
                return Err(invalid(
                    "source AccessCheck privilege records exceed output",
                ));
            }
            let executable = allowed != 0;
            if granted != if executable { FILE_EXECUTE } else { 0 } {
                return Err(invalid(
                    "source AccessCheck grant disagrees with AccessStatus",
                ));
            }
            return Ok(executable);
        }
        Err(unsupported(
            "source AccessCheck privilege buffer unavailable",
        ))
    }

    impl Handles {
        fn finish_package<T>(
            mut self,
            result: io::Result<T>,
            state: &Arc<staged_package::CloseState>,
        ) -> io::Result<T> {
            for slot in self.slots.iter_mut().rev() {
                if let Some(owner) = slot.take() {
                    let raw = owner.into_raw_handle();
                    if unsafe { CloseHandle(raw) } == 0 {
                        let code = unsafe { GetLastError() };
                        state.record(raw, code, None, "package observation temporary owner");
                    }
                }
            }
            if state.check().is_err() {
                Err(state.fault("package observation ownership uncertainty", result.err()))
            } else {
                result
            }
        }
    }

    #[cfg(test)]
    pub(super) fn test_context(state: &Arc<staged_package::CloseState>) -> io::Result<ContextKey> {
        let mut handles = Handles::default();
        let result = (|| {
            let (original, key) = effective(&mut handles)?;
            if context(handles.raw(original), key.thread_token)? != key {
                return Err(denied("test original effective context changed"));
            }
            let (_, current) = effective(&mut handles)?;
            if current != key {
                return Err(denied("test current effective context changed"));
            }
            Ok(key)
        })();
        handles.finish_package(result, state)
    }

    pub(super) fn package_principal(
        state: &Arc<staged_package::CloseState>,
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut handles = Handles::default();
        let result = (|| {
            let (_, key) = effective(&mut handles)?;
            Ok((key.user, key.primary_group))
        })();
        handles.finish_package(result, state)
    }

    fn package_open(
        parent: HANDLE,
        parent_id: FileIdentity,
        leaf: &OsStr,
        expected: FileIdentity,
        phase: OpenPhase,
        handles: &mut Handles,
        state: &Arc<staged_package::CloseState>,
    ) -> io::Result<usize> {
        ensure_kind(parent, true)?;
        if identity(parent)? != parent_id || parent_id.volume != expected.volume {
            return Err(denied("package observation parent identity changed"));
        }
        let owner =
            staged_package::observation_open(parent, leaf, phase == OpenPhase::Execute, state)?;
        let slot = handles.own(owner);
        ensure_kind(handles.raw(slot), false)?;
        if identity(handles.raw(slot))? != expected {
            return Err(denied(
                "package observation reopened a different full identity",
            ));
        }
        Ok(slot)
    }

    // Borrow the actual stage/accepted parent rather than acquiring a public
    // SourceDirectory whose no-DELETE root sharing conflicts with publication.
    // The existing SourceFile wrapper and its open/share/read behavior stay intact.
    pub(super) fn observe_package<F>(
        file: HANDLE,
        expected: FileIdentity,
        parent: HANDLE,
        parent_id: FileIdentity,
        leaf: &OsStr,
        snapshot: F,
        state: &Arc<staged_package::CloseState>,
    ) -> io::Result<ExecutionPermission>
    where
        F: Fn() -> io::Result<SourceSnapshot>,
    {
        let mut handles = Handles::default();
        let result = (|| {
            state.check()?;
            let before = snapshot()?;
            if source_snapshot(file, expected, false)? != before {
                return Err(denied("package held metadata baseline differs"));
            }
            let (original, key) = effective(&mut handles)?;
            let metadata = package_open(
                parent,
                parent_id,
                leaf,
                expected,
                OpenPhase::Metadata,
                &mut handles,
                state,
            )?;
            if source_snapshot(handles.raw(metadata), expected, false)? != before {
                return Err(denied("package observation metadata changed"));
            }
            let descriptor = security(handles.raw(metadata))?;
            let duplicate = duplicate(&mut handles, original, &key)?;
            let checked = access_check(&descriptor, handles.raw(duplicate))?;
            let native = match package_open(
                parent,
                parent_id,
                leaf,
                expected,
                OpenPhase::Execute,
                &mut handles,
                state,
            ) {
                Ok(probe) => {
                    if source_snapshot(handles.raw(probe), expected, false)? != before
                        || security(handles.raw(probe))?.fingerprint != descriptor.fingerprint
                    {
                        return Err(denied("package execution probe metadata/security changed"));
                    }
                    true
                }
                Err(error)
                    if error
                        .get_ref()
                        .and_then(|e| e.downcast_ref::<staged_package::NativeError>())
                        .is_some_and(|e| {
                            e.phase == "package-execute" && e.status == STATUS_ACCESS_DENIED
                        }) =>
                {
                    state.check()?;
                    false
                }
                Err(error) => return Err(error),
            };
            if checked != native {
                return Err(denied(
                    "package AccessCheck/native execution decisions disagree",
                ));
            }
            if security(handles.raw(metadata))?.fingerprint != descriptor.fingerprint
                || source_snapshot(handles.raw(metadata), expected, false)? != before
                || source_snapshot(file, expected, false)? != before
                || snapshot()? != before
            {
                return Err(denied(
                    "package observation identity/policy/snapshot changed",
                ));
            }
            if context(handles.raw(original), key.thread_token)? != key {
                return Err(denied("original package observation context changed"));
            }
            let (_, current) = effective(&mut handles)?;
            if current != key {
                return Err(denied("current package observation context changed"));
            }
            Ok(ExecutionPermission {
                executable: checked,
                identity: expected,
                security: descriptor.fingerprint,
                context: key,
            })
        })();
        handles.finish_package(result, state)
    }

    pub(super) fn observe(file: &SourceFile) -> io::Result<ExecutionPermission> {
        let mut handles = Handles::default();
        let result = (|| {
            let before = file.snapshot()?;
            let (original, key) = effective(&mut handles)?;
            let metadata = open(file, OpenPhase::Metadata, &mut handles)?;
            if source_snapshot(handles.raw(metadata), file.identity, false)? != before {
                return Err(denied("source metadata baseline changed"));
            }
            let descriptor = security(handles.raw(metadata))?;
            let duplicate = duplicate(&mut handles, original, &key)?;
            let checked = access_check(&descriptor, handles.raw(duplicate))?;
            let native = match open(file, OpenPhase::Execute, &mut handles) {
                Ok(probe) => {
                    if source_snapshot(handles.raw(probe), file.identity, false)? != before
                        || security(handles.raw(probe))?.fingerprint != descriptor.fingerprint
                    {
                        return Err(denied(
                            "source execution probe identity, metadata, or security changed",
                        ));
                    }
                    true
                }
                Err(error)
                    if error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<NativeOpenError>())
                        .is_some_and(|native| {
                            native.phase == OpenPhase::Execute
                                && native.status == STATUS_ACCESS_DENIED
                        }) =>
                {
                    false
                }
                Err(error) => return Err(error),
            };
            if checked != native {
                return Err(denied(
                    "AccessCheck and native source execution probe disagree",
                ));
            }
            if security(handles.raw(metadata))?.fingerprint != descriptor.fingerprint
                || source_snapshot(handles.raw(metadata), file.identity, false)? != before
                || file.snapshot()? != before
            {
                return Err(denied(
                    "source identity, snapshot, or security changed during execution observation",
                ));
            }
            if context(handles.raw(original), key.thread_token)? != key {
                return Err(denied("original source token changed"));
            }
            let (_, current) = effective(&mut handles)?;
            if current != key {
                return Err(denied("current effective source context changed"));
            }
            // All temporary native owners must checked-close before this value
            // can leave the method. It contains facts, never retained authority.
            Ok(ExecutionPermission {
                executable: checked,
                identity: file.identity,
                security: descriptor.fingerprint,
                context: key,
            })
        })();
        handles.finish(result)
    }
}

#[cfg(test)]
static INSPECTION_DACL_MUTATION_APPLIED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static INSPECTION_REPLACE_AFTER_ENUMERATION: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::IntoRawHandle;

    struct RestoreDaclOnDrop {
        handle: OwnedHandle,
        descriptor: Vec<usize>,
    }
    impl RestoreDaclOnDrop {
        fn restore(&self) -> io::Result<()> {
            let mut dacl = null_mut();
            let mut present = 0;
            let mut defaulted = 0;
            unsafe {
                ok(GetSecurityDescriptorDacl(
                    self.descriptor.as_ptr().cast_mut().cast(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                ))?;
                if present == 0 || dacl.is_null() {
                    return Err(invalid("fixture owner DACL unavailable for restoration"));
                }
                let code = SetSecurityInfo(
                    self.handle.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    dacl,
                    null_mut(),
                );
                if code != ERROR_SUCCESS {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
            }
            Ok(())
        }
    }
    impl Drop for RestoreDaclOnDrop {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    struct ResetInspectionHook;
    impl Drop for ResetInspectionHook {
        fn drop(&mut self) {
            INSPECTION_DACL_AFTER_SNAPSHOT.store(false, Ordering::SeqCst);
            INSPECTION_DACL_MUTATION_APPLIED.store(false, Ordering::SeqCst);
            INSPECTION_REPLACE_AFTER_ENUMERATION.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn container_ace_layout_parser_only_rejects_malformed_unknown_and_callback_forms() {
        for (raw, expected) in [
            (GENERIC_READ, FILE_GENERIC_READ),
            (GENERIC_WRITE, FILE_GENERIC_WRITE),
            (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
            (GENERIC_ALL, FILE_ALL_ACCESS),
            (
                GENERIC_READ | GENERIC_EXECUTE,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            ),
        ] {
            assert_eq!(checked_container_access_mask(raw).unwrap(), expected);
        }
        for raw in [
            0x0200_0000,
            0x0100_0000,
            0x0000_0200,
            GENERIC_READ | 0x0200_0000,
            GENERIC_WRITE | 0x0100_0000,
            GENERIC_ALL | 0x0000_0200,
        ] {
            let error = checked_container_access_mask(raw).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                "container ACE contains unsupported access bits"
            );
        }
        let valid_sid = [1, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(
            validate_container_ace_layout(0, 0, 16, &valid_sid).unwrap(),
            8
        );
        assert_eq!(
            validate_container_ace_layout(0, INHERIT_ONLY_ACE as u8, 16, &valid_sid).unwrap(),
            8,
            "well-formed inherit-only ACE layout is parsed"
        );
        assert!(
            validate_container_ace_layout(5, 0, 16, &valid_sid).is_err(),
            "object ACE form is unsupported"
        );
        assert!(
            validate_container_ace_layout(5, INHERIT_ONLY_ACE as u8, 16, &valid_sid).is_err(),
            "object ACE form is rejected even when inherit-only"
        );
        assert!(
            validate_container_ace_layout(9, INHERIT_ONLY_ACE as u8, 16, &valid_sid).is_err(),
            "callback ACE form is rejected even when inherit-only"
        );
        assert!(
            validate_container_ace_layout(0, 0x80, 16, &valid_sid).is_err(),
            "unknown ACE flags are rejected"
        );
        assert!(
            validate_container_ace_layout(0, 0, 15, &valid_sid).is_err(),
            "ACE size shorter than the SID prefix is rejected"
        );
        assert!(
            validate_container_ace_layout(0, 0, 16, &valid_sid[..7]).is_err(),
            "truncated SID prefix is rejected"
        );

        let mut excessive_sid = valid_sid;
        excessive_sid[1] = 16;
        assert!(
            validate_container_ace_layout(0, 0, 16, &excessive_sid).is_err(),
            "SID subauthority count is bounded before IsValidSid/GetLengthSid"
        );
        let mut invalid_revision = valid_sid;
        invalid_revision[0] = 2;
        assert!(
            validate_container_ace_layout(0, 0, 16, &invalid_revision).is_err(),
            "invalid SID revision is rejected"
        );
    }

    struct ResetSourceSnapshotTestHook;
    impl Drop for ResetSourceSnapshotTestHook {
        fn drop(&mut self) {
            SOURCE_SNAPSHOT_TEST_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    fn install_source_snapshot_test_hook(
        hook: SourceSnapshotTestHook,
    ) -> ResetSourceSnapshotTestHook {
        let mut slot = SOURCE_SNAPSHOT_TEST_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(slot.is_none(), "source snapshot hook slot must be empty");
        *slot = Some(hook);
        ResetSourceSnapshotTestHook
    }

    #[test]
    fn source_component_policy_is_separate_from_private_names() {
        for name in ["trailing.", "CON", "name "] {
            let component = OsStr::new(name);
            assert!(
                super::validate_component(component).is_err(),
                "private state must keep rejecting {name:?}"
            );
            assert!(
                validate_source_component(component).is_ok(),
                "public source component should retain {name:?}"
            );
        }
    }

    #[test]
    fn source_snapshot_rejects_link_added_after_initial_kind_check() {
        let home = Home::new();
        let root = home.base.join("race source");
        std::fs::create_dir(&root).unwrap();
        let source_path = root.join("record");
        let link_path = home.base.join("outside hardlink");
        std::fs::write(&source_path, b"hardlink race canary").unwrap();
        let source = SourceDirectory::open(&root).unwrap();
        let initial = source
            .enumerate(EnumerationLimits {
                max_entries: 8,
                max_name_bytes: 1024,
            })
            .unwrap();
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].snapshot.link_count, 1);
        let expected = initial[0].identity;
        let ran = Arc::new(AtomicBool::new(false));
        let _reset_hook = install_source_snapshot_test_hook(SourceSnapshotTestHook {
            expected,
            source_path: source_path.clone(),
            link_path: link_path.clone(),
            ran: Arc::clone(&ran),
        });

        let result = source.enumerate(EnumerationLimits {
            max_entries: 8,
            max_name_bytes: 1024,
        });

        assert!(
            ran.load(Ordering::SeqCst),
            "one-shot hardlink hook did not run"
        );
        assert_eq!(
            std::fs::read(&source_path).unwrap(),
            b"hardlink race canary"
        );
        assert_eq!(std::fs::read(&link_path).unwrap(), b"hardlink race canary");
        let original = File::open(&source_path).unwrap();
        let alias = File::open(&link_path).unwrap();
        let original_standard: FILE_STANDARD_INFO =
            information(original.as_raw_handle(), FileStandardInfo).unwrap();
        let alias_standard: FILE_STANDARD_INFO =
            information(alias.as_raw_handle(), FileStandardInfo).unwrap();
        assert_eq!(original_standard.NumberOfLinks, 2, "real source link count");
        assert_eq!(alias_standard.NumberOfLinks, 2, "real alias link count");
        let original_identity = identity(original.as_raw_handle()).unwrap();
        let alias_identity = identity(alias.as_raw_handle()).unwrap();
        assert_eq!(
            original_identity, expected,
            "original must retain the same full file identity"
        );
        assert_eq!(
            alias_identity, original_identity,
            "alias must name the same full file identity"
        );
        let observed = result.as_ref().ok().and_then(|entries| entries.first());
        assert!(
            matches!(&result, Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && error.to_string() == "source snapshot link count changed"),
            "expected policy rejection after verified real hardlink setup; got {result:?}, observed_link_count={}, full_identity={expected:?} original_identity={original_identity:?} alias_identity={alias_identity:?}",
            observed.map_or(0, |entry| entry.snapshot.link_count)
        );
    }

    #[test]
    fn inspection_rechecks_acl_after_snapshot() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("record")).unwrap();
        file.write_all(b"fixture only").unwrap();
        drop(file);

        let path = home.base.join("state").join("record");
        let path_wide = wide(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let restore = RestoreDaclOnDrop {
            // SAFETY: CreateFileW succeeded and transfers one owned handle.
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
            descriptor: home.dir().security.descriptor.clone(),
        };

        INSPECTION_DACL_MUTATION_APPLIED.store(false, Ordering::SeqCst);
        let _reset_hook = ResetInspectionHook;
        INSPECTION_DACL_AFTER_SNAPSHOT.store(true, Ordering::SeqCst);
        let result = home.dir().inspect_private_tree(InspectionLimits {
            max_entries: 8,
            max_name_bytes: 1024,
            max_depth: 4,
        });
        // The hook must prove the owner DACL changed on this fixture after its
        // file snapshot, before the inspection result is checked.
        assert!(
            INSPECTION_DACL_MUTATION_APPLIED.load(Ordering::SeqCst),
            "the native fixture DACL mutation did not occur"
        );
        restore.restore().unwrap();
        assert!(
            result.is_err(),
            "inspection accepted an owner DACL changed after its file snapshot"
        );
    }

    #[test]
    fn inspection_revalidates_full_identity_after_replacement() {
        let home = Home::new();
        let original = home.original();
        let _reset_hook = ResetInspectionHook;
        INSPECTION_REPLACE_AFTER_ENUMERATION.store(true, Ordering::SeqCst);

        let error = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut displaced = home.dir().open_file(OsStr::new("displaced")).unwrap();
        let mut replacement = home.dir().open_file(OsStr::new("record")).unwrap();
        assert_eq!(displaced.identity(), original);
        assert_ne!(replacement.identity(), original);
        assert_eq!(displaced.read_limited(64).unwrap(), b"original");
        assert_eq!(replacement.read_limited(64).unwrap(), b"replacement bytes");
    }

    #[test]
    fn removal_faults_report_preserved_or_disposition_acknowledged_state() {
        let home = Home::new();
        let expected = home.original();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let file = home
            .dir()
            .open_for_rename(OsStr::new("record"), expected, &lock)
            .unwrap();
        FAILURE.with(|slot| slot.set(Some("before_disposition")));
        assert!(matches!(
            home.dir().remove_file(file),
            Err(RemovalError::Unchanged(_))
        ));
        FAILURE.with(|slot| slot.set(None));
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
        let file = home
            .dir()
            .open_for_rename(OsStr::new("record"), expected, &lock)
            .unwrap();
        FAILURE.with(|slot| slot.set(Some("after_disposition")));
        assert!(
            matches!(home.dir().remove_file(file), Err(RemovalError::Uncertain { identity, state: RemovalState::DispositionAcknowledged, .. }) if identity == expected)
        );
        FAILURE.with(|slot| slot.set(None));
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    fn snapshot_child(path: &Path, expected: &str) {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fs::windows::tests::read_snapshot_child",
                "--nocapture",
            ])
            .env("ORBIT_FS_SNAPSHOT_ROOT", path)
            .env("ORBIT_FS_SNAPSHOT_EXPECT", expected)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned snapshot child exceeded deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .lines()
                .any(|line| line.trim() == "test fs::windows::tests::read_snapshot_child ... ok")
        );
    }

    // Only the mandatory parent counts as native coverage, not this child entry.
    #[test]
    fn read_snapshot_child() {
        let Some(path) = std::env::var_os("ORBIT_FS_SNAPSHOT_ROOT") else {
            return;
        };
        let directory = Directory::open(Path::new(&path)).unwrap();
        let expected = std::env::var("ORBIT_FS_SNAPSHOT_EXPECT").unwrap();
        let guard = directory.try_lock(OsStr::new("transaction.lock"), LockMode::Shared);
        if expected == "blocked" {
            assert_eq!(
                guard.err().unwrap().raw_os_error(),
                Some(ERROR_LOCK_VIOLATION as i32)
            );
        } else {
            let _guard = guard.unwrap();
            assert_eq!(
                directory
                    .open_file(OsStr::new("record"))
                    .unwrap()
                    .read_limited(1024)
                    .unwrap(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn shared_reader_is_excluded_from_actual_two_rename_gap() {
        let home = Home::new();
        let expected = home.original();
        let candidate = home.candidate();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let path = home.base.join("state");
        let gap_path = path.clone();
        GAP_CHECK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let directory = Directory::open(&gap_path).unwrap();
                assert_eq!(
                    directory
                        .open_file(OsStr::new("record"))
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::NotFound
                );
                snapshot_child(&gap_path, "blocked");
            }))
        });
        home.dir()
            .replace(&candidate, OsStr::new("record"), expected, &lock)
            .unwrap();
        GAP_CHECK.with(|slot| *slot.borrow_mut() = None);
        drop(candidate);
        drop(lock);
        snapshot_child(&path, "replacement");
    }

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

    // Test-only native capability evidence. A ProbeHandle remains in the ledger
    // until its single checked CloseHandle succeeds or fails; failure consumes
    // the raw owner and is retained as evidence, never retried.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProbeHandle(usize);

    #[derive(Debug)]
    struct ProbeCreatedName {
        parent: FileIdentity,
        name: OsString,
        directory: bool,
        identity: Option<FileIdentity>,
    }

    struct ProbeLedger {
        handles: Vec<Option<OwnedHandle>>,
        directories: Vec<Option<Directory>>,
        created: Vec<ProbeCreatedName>,
        closed: Vec<String>,
    }
    impl ProbeLedger {
        fn new() -> Self {
            Self {
                handles: Vec::new(),
                directories: Vec::new(),
                created: Vec::new(),
                closed: Vec::new(),
            }
        }
        fn own_directory(&mut self, directory: Directory) -> usize {
            let index = self.directories.len();
            self.directories.push(Some(directory));
            index
        }
        fn directory(&self, index: usize) -> &Directory {
            self.directories[index]
                .as_ref()
                .expect("registered directory owner")
        }
        fn close_directory(&mut self, index: usize) -> io::Result<()> {
            let directory = self.directories[index]
                .take()
                .ok_or_else(|| invalid("directory owner already consumed"))?;
            let errors = probe_close_directory(directory);
            self.closed
                .push(format!("directory#{index} close={errors:?}"));
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "directory#{index} close errors: {errors:?}"
                )))
            }
        }
        fn own(&mut self, handle: OwnedHandle) -> ProbeHandle {
            let id = ProbeHandle(self.handles.len());
            self.handles.push(Some(handle));
            id
        }
        fn raw(&self, id: ProbeHandle) -> HANDLE {
            self.handles[id.0]
                .as_ref()
                .expect("live probe handle")
                .as_raw_handle()
        }
        fn live(&self, id: ProbeHandle) -> bool {
            self.handles.get(id.0).is_some_and(Option::is_some)
        }
        fn note_create(&mut self, parent: FileIdentity, name: &OsStr, directory: bool) -> usize {
            let index = self.created.len();
            self.created.push(ProbeCreatedName {
                parent,
                name: name.to_os_string(),
                directory,
                identity: None,
            });
            let record = &self.created[index];
            println!(
                "probe_creation_reserved parent={:?} name={:?} directory={} identity=UNKNOWN non_authorizing=true",
                record.parent, record.name, record.directory
            );
            index
        }
        fn bind_create(&mut self, index: usize, identity: FileIdentity) -> io::Result<()> {
            let record = self
                .created
                .get_mut(index)
                .ok_or_else(|| invalid("missing probe creation record"))?;
            if record.identity.replace(identity).is_some() {
                return Err(invalid("probe creation identity was already bound"));
            }
            Ok(())
        }
        fn close(&mut self, id: ProbeHandle) -> io::Result<()> {
            let Some(slot) = self.handles.get_mut(id.0) else {
                return Err(invalid("probe handle index is invalid"));
            };
            let Some(handle) = slot.take() else {
                return Err(invalid("probe handle was already consumed"));
            };
            match probe_close_handle(handle) {
                Ok(()) => {
                    self.closed.push(format!("handle#{}=closed", id.0));
                    Ok(())
                }
                Err(error) => {
                    self.closed
                        .push(format!("handle#{}=close-error:{error}", id.0));
                    Err(error)
                }
            }
        }
        fn close_except(&mut self, keep: &[ProbeHandle]) -> Vec<String> {
            let mut errors = Vec::new();
            for index in 0..self.directories.len() {
                if self.directories[index].is_some() {
                    if let Err(error) = self.close_directory(index) {
                        errors.push(error.to_string());
                    }
                }
            }
            for index in 0..self.handles.len() {
                let id = ProbeHandle(index);
                if keep.contains(&id) || !self.live(id) {
                    continue;
                }
                if let Err(error) = self.close(id) {
                    errors.push(format!("handle#{index}: {error}"));
                }
            }
            errors
        }
    }

    #[derive(Clone, Debug)]
    struct ProbeNtResult {
        returned: i32,
        effective: i32,
        iosb_status: Option<i32>,
        iosb_information: Option<usize>,
        iosb_observation: &'static str,
        waited: bool,
    }

    const PROBE_IOSB_SENTINEL: i32 = 0x6f65_7362;
    const PROBE_PENDING: i32 = 0x0000_0103;
    const PROBE_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;
    const PROBE_SHARING_VIOLATION: i32 = 0xC000_0043u32 as i32;
    const PROBE_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;

    type ProbeNtQueryObject =
        unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
    type ProbeGenericProc = unsafe extern "system" fn() -> isize;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(kind: u32) -> HANDLE;
        fn GetModuleHandleW(name: *const u16) -> HANDLE;
        fn GetProcAddress(module: HANDLE, name: *const u8) -> Option<ProbeGenericProc>;
    }

    #[repr(C)]
    struct ProbeObjectBasicInformation {
        attributes: u32,
        granted_access: u32,
        handle_count: u32,
        pointer_count: u32,
        reserved: [u32; 10],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ProbeAclEvidence {
        owner_sid: Vec<u8>,
        dacl: Vec<u8>,
        protected: bool,
        ace_type: u8,
        ace_flags: u8,
        ace_mask: u32,
        ace_sid: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct ProbeStage {
        name: OsString,
        identity: FileIdentity,
        payload: Option<(OsString, FileIdentity)>,
        payload_acl_before: Option<ProbeAclEvidence>,
        payload_acl_after: Option<ProbeAclEvidence>,
    }

    fn probe_ntdll_export(name: &'static [u8]) -> io::Result<ProbeGenericProc> {
        let module_name = wide(OsStr::new("ntdll.dll"));
        let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(io::Error::last_os_error)
    }

    fn probe_granted_access(handle: HANDLE) -> io::Result<u32> {
        let function = probe_ntdll_export(b"NtQueryObject\0")?;
        // SAFETY: GetProcAddress resolved NtQueryObject from the loaded ntdll.
        let query: ProbeNtQueryObject = unsafe { std::mem::transmute(function) };
        let mut information = ProbeObjectBasicInformation {
            attributes: 0,
            granted_access: 0,
            handle_count: 0,
            pointer_count: 0,
            reserved: [0; 10],
        };
        let mut returned = 0u32;
        let status = unsafe {
            query(
                handle,
                0,
                (&mut information as *mut ProbeObjectBasicInformation).cast(),
                size_of::<ProbeObjectBasicInformation>() as u32,
                &mut returned,
            )
        };
        if status != 0 {
            return Err(probe_nt_error("NtQueryObject", status));
        }
        if returned as usize != size_of::<ProbeObjectBasicInformation>() {
            return Err(invalid(
                "NtQueryObject returned an unexpected structure size",
            ));
        }
        Ok(information.granted_access)
    }

    #[derive(Debug)]
    struct ProbeNativeError {
        operation: &'static str,
        status: i32,
    }
    impl std::fmt::Display for ProbeNativeError {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                output,
                "{} NTSTATUS=0x{:08x}",
                self.operation, self.status as u32
            )
        }
    }
    impl std::error::Error for ProbeNativeError {}

    fn probe_nt_error(operation: &'static str, status: i32) -> io::Error {
        let code = unsafe { RtlNtStatusToDosError(status) } as i32;
        io::Error::new(
            io::Error::from_raw_os_error(code).kind(),
            ProbeNativeError { operation, status },
        )
    }

    fn probe_name_missing(error: &io::Error) -> bool {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ProbeNativeError>())
            .is_some_and(|native| native.status == PROBE_NAME_NOT_FOUND)
    }

    fn probe_security_copy(security: &Security) -> Security {
        Security {
            sid: security.sid.clone(),
            descriptor: security.descriptor.clone(),
        }
    }

    // Test-only fail-stop: no unwinding or request-storage reclamation while
    // kernel ownership/completion is uncertain. Windows process teardown waits
    // for outstanding I/O to complete or be cancelled. This is never a result.
    fn probe_uncertain_native_fail_stop() -> ! {
        static MESSAGE: &[u8] = b"ORBIT_PROBE_UNCLASSIFIED_FAIL_STOP: native completion or ownership uncertain; no classification; fixture/close facts UNKNOWN; terminating without unwinding\r\n";
        unsafe {
            let stderr = GetStdHandle((-12i32) as u32);
            if !stderr.is_null() && stderr != INVALID_HANDLE_VALUE {
                let mut written = 0;
                let _ = WriteFile(
                    stderr,
                    MESSAGE.as_ptr(),
                    MESSAGE.len() as u32,
                    &mut written,
                    null_mut(),
                );
            }
            let _ = windows_sys::Win32::System::Threading::TerminateProcess(
                GetCurrentProcess(),
                0xE015_0001,
            );
        }
        std::process::abort()
    }

    fn probe_close_handle(handle: OwnedHandle) -> io::Result<()> {
        let raw = handle.into_raw_handle();
        // Ownership is consumed exactly once even when CloseHandle fails.
        if unsafe { CloseHandle(raw) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn probe_finish_nt_call(
        handle: HANDLE,
        returned: i32,
        status: *mut IO_STATUS_BLOCK,
    ) -> ProbeNtResult {
        let waited = returned == PROBE_PENDING;
        if waited {
            // No IOSB reference or load exists while kernel writes may continue.
            // This synchronous, nonalertable handle has no overlapping request.
            let wait = unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(handle, u32::MAX)
            };
            if wait != WAIT_OBJECT_0 {
                probe_uncertain_native_fail_stop();
            }
        }
        // SAFETY: a nonpending return is final, or the same-handle wait above
        // observed completion. Only then may the kernel output be inspected.
        let iosb_status = unsafe { std::ptr::addr_of!((*status).Anonymous.Status).read() };
        if waited && (iosb_status == PROBE_PENDING || iosb_status == PROBE_IOSB_SENTINEL) {
            probe_uncertain_native_fail_stop();
        }
        let information = unsafe { std::ptr::addr_of!((*status).Information).read() };
        let touched = iosb_status != PROBE_IOSB_SENTINEL || information != usize::MAX;
        ProbeNtResult {
            returned,
            effective: if waited { iosb_status } else { returned },
            iosb_status: touched.then_some(iosb_status),
            iosb_information: touched.then_some(information),
            iosb_observation: if touched {
                "changed-output"
            } else {
                "initialized-by-caller-unchanged-or-ambiguous"
            },
            waited,
        }
    }

    fn probe_log_nt(label: &str, result: &ProbeNtResult) {
        println!(
            "{label} returned=0x{:08x} effective=0x{:08x} pending_wait={} iosb_observation={} iosb_status={:?} iosb_information={:?}",
            result.returned as u32,
            result.effective as u32,
            result.waited,
            result.iosb_observation,
            result
                .iosb_status
                .map(|value| format!("0x{:08x}", value as u32)),
            result.iosb_information,
        );
    }

    fn probe_open(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        directory: bool,
        disposition: u32,
        desired_access: u32,
        share_access: u32,
        descriptor: *const SECURITY_DESCRIPTOR,
    ) -> io::Result<ProbeHandle> {
        validate_data_component(name)?;
        probe_open_validated(
            ledger,
            parent,
            parent_id,
            name,
            directory,
            disposition,
            desired_access,
            share_access,
            descriptor,
        )
    }

    fn probe_open_validated(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        directory: bool,
        disposition: u32,
        desired_access: u32,
        share_access: u32,
        descriptor: *const SECURITY_DESCRIPTOR,
    ) -> io::Result<ProbeHandle> {
        validate_component(name)?;
        let created = disposition == FILE_CREATE;
        let created_index = created.then(|| ledger.note_create(parent_id, name, directory));
        let mut name_wide: Vec<u16> = name.encode_wide().collect();
        if name_wide.len() > u16::MAX as usize / 2 {
            return Err(invalid("probe name exceeds UNICODE_STRING bound"));
        }
        let byte_length = (name_wide.len() * 2) as u16;
        let unicode_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: name_wide.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent,
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: descriptor,
            SecurityQualityOfService: null(),
        };
        let mut raw = null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        status_block.Anonymous.Status = PROBE_IOSB_SENTINEL;
        status_block.Information = usize::MAX;
        let returned = unsafe {
            NtCreateFile(
                &mut raw,
                desired_access,
                &attributes,
                &mut status_block,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
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
        if returned == PROBE_PENDING {
            // NtCreateFile offers no supplied event and an anomalous pending
            // return does not prove that its output handle is usable for a wait.
            // Keep name/OA/IOSB/output/descriptor and fixture owners in scope.
            probe_uncertain_native_fail_stop();
        }
        let result = probe_finish_nt_call(parent, returned, &raw mut status_block);
        probe_log_nt("probe_open", &result);
        if returned != 0 {
            if !raw.is_null() {
                probe_uncertain_native_fail_stop();
            }
            return Err(probe_nt_error("NtCreateFile", returned));
        }
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            probe_uncertain_native_fail_stop();
        }
        let handle = ledger.own(unsafe { OwnedHandle::from_raw_handle(raw) });
        if let Some(index) = created_index {
            let id = identity(ledger.raw(handle))?;
            ledger.bind_create(index, id)?;
        }
        Ok(handle)
    }

    fn probe_rename_directory(
        source: HANDLE,
        target_parent: HANDLE,
        target_name: &OsStr,
    ) -> ProbeNtResult {
        assert!(
            validate_data_component(target_name).is_ok(),
            "rename target is one validated component"
        );
        let name: Vec<u16> = target_name.encode_wide().collect();
        let bytes = offset_of!(FILE_RENAME_INFORMATION, FileName) + name.len() * 2;
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status_block = IO_STATUS_BLOCK::default();
        status_block.Anonymous.Status = PROBE_IOSB_SENTINEL;
        status_block.Information = usize::MAX;
        // SAFETY: aligned variable-tail buffer remains alive through pending
        // completion; relative RootDirectory, one component, ReplaceIfExists=false,
        // and zeroed remaining bytes implement FileRenameInformation flags=0.
        let returned = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = target_parent;
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
            NtSetInformationFile(
                source,
                &mut status_block,
                info.cast(),
                bytes as u32,
                FileRenameInformation,
            )
        };
        probe_finish_nt_call(source, returned, &raw mut status_block)
    }

    fn probe_disposition(handle: HANDLE) -> io::Result<ProbeNtResult> {
        let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        let mut status_block = IO_STATUS_BLOCK::default();
        status_block.Anonymous.Status = PROBE_IOSB_SENTINEL;
        status_block.Information = usize::MAX;
        // SAFETY: input information and IOSB remain live if the synchronous call
        // reports pending; probe_finish_nt_call waits before either can be dropped.
        let returned = unsafe {
            NtSetInformationFile(
                handle,
                &mut status_block,
                (&information as *const FILE_DISPOSITION_INFORMATION).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        };
        let result = probe_finish_nt_call(handle, returned, &raw mut status_block);
        probe_log_nt("probe_disposition", &result);
        if result.effective == 0 {
            Ok(result)
        } else {
            Err(probe_nt_error(
                "FileDispositionInformation",
                result.effective,
            ))
        }
    }

    fn probe_close_directory(directory: Directory) -> Vec<String> {
        let Directory { chain, .. } = directory;
        let mut errors = Vec::new();
        for (index, anchor) in chain.into_iter().enumerate().rev() {
            match Arc::try_unwrap(anchor) {
                Ok(handle) => {
                    if let Err(error) = probe_close_handle(handle) {
                        errors.push(format!("directory-anchor#{index}: {error}"));
                    }
                }
                Err(anchor) => {
                    let count = Arc::strong_count(&anchor);
                    errors.push(format!(
                        "directory-anchor#{index} retained by {count} owner(s)"
                    ));
                    drop(anchor);
                }
            }
        }
        errors
    }

    fn probe_close_lock(lock: StateLock) -> Vec<String> {
        let lock = std::mem::ManuallyDrop::new(lock);
        // SAFETY: StateLock has Drop, so read its PrivateFile once and suppress
        // the automatic unlock; this function performs and checks unlock itself.
        let private = unsafe { std::ptr::read(&lock.file) };
        let mut errors = Vec::new();
        let mut overlap = OVERLAPPED::default();
        if unsafe { UnlockFileEx(private.file.as_raw_handle(), 0, 1, 0, &mut overlap) } == 0 {
            errors.push(format!(
                "exclusive lock unlock: {}",
                io::Error::last_os_error()
            ));
        }
        let PrivateFile { file, _anchors, .. } = private;
        let raw = file.into_raw_handle();
        let owned = unsafe { OwnedHandle::from_raw_handle(raw) };
        if let Err(error) = probe_close_handle(owned) {
            errors.push(format!("exclusive lock handle close: {error}"));
        }
        drop(_anchors);
        errors
    }

    fn probe_read_payload(handle: HANDLE, expected: FileIdentity) -> io::Result<Vec<u8>> {
        if identity(handle)? != expected {
            return Err(denied("probe payload full identity changed"));
        }
        let snapshot = file_snapshot(handle, expected)?;
        if snapshot.length > 4096 {
            return Err(invalid("probe payload exceeds bounded fixture size"));
        }
        let mut bytes = vec![0u8; snapshot.length as usize];
        let mut read = 0;
        if unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(read as usize);
        if bytes.len() as u64 != snapshot.length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short probe payload read",
            ));
        }
        Ok(bytes)
    }

    fn probe_acl_evidence(handle: HANDLE, security: &Security) -> io::Result<ProbeAclEvidence> {
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
        if owner.is_null() || dacl.is_null() {
            return Err(denied("probe owner or DACL is absent"));
        }
        let owner_len = unsafe { GetLengthSid(owner) } as usize;
        if owner_len == 0 || owner_len > 68 {
            return Err(invalid("probe owner SID length is invalid"));
        }
        let owner_sid =
            unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_len) }.to_vec();
        if unsafe { EqualSid(owner, security.sid.as_ptr().cast_mut().cast()) } == 0 {
            return Err(denied("probe object owner is not captured TokenUser"));
        }
        let mut control = 0;
        let mut revision = 0;
        unsafe {
            ok(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?;
        }
        let acl_length = unsafe { (*dacl).AclSize as usize };
        if acl_length < size_of::<ACL>() {
            return Err(invalid("probe DACL size is invalid"));
        }
        let acl_bytes =
            unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), acl_length) }.to_vec();
        if unsafe { (*dacl).AceCount } != 1 {
            return Err(denied("probe DACL must contain exactly one ACE"));
        }
        let mut ace = null_mut();
        unsafe {
            ok(GetAce(dacl, 0, &mut ace))?;
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if (header.AceSize as usize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8 {
            return Err(invalid("probe ACE is shorter than its SID prefix"));
        }
        if header.AceType != 0 {
            return Err(denied("probe DACL ACE is not ordinary allow"));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid_ptr = (&allowed.SidStart as *const u32).cast_mut().cast();
        let ace_sid_len = unsafe { GetLengthSid(ace_sid_ptr) } as usize;
        if ace_sid_len == 0
            || ace_sid_len > header.AceSize as usize - offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        {
            return Err(invalid("probe ACE SID length is invalid"));
        }
        let ace_sid =
            unsafe { std::slice::from_raw_parts(ace_sid_ptr.cast::<u8>(), ace_sid_len) }.to_vec();
        Ok(ProbeAclEvidence {
            owner_sid,
            dacl: acl_bytes,
            protected: control & SE_DACL_PROTECTED != 0,
            ace_type: header.AceType,
            ace_flags: header.AceFlags,
            ace_mask: allowed.Mask,
            ace_sid,
        })
    }

    fn probe_check_r(handle: HANDLE, security: &Security) -> io::Result<ProbeAclEvidence> {
        if security.check_owner_access(handle, true)? != PrivateFileAccess::ReadOnly {
            return Err(denied("probe DACL is not canonical R"));
        }
        let evidence = probe_acl_evidence(handle, security)?;
        if !evidence.protected
            || evidence.ace_flags != 0
            || evidence.ace_mask != FILE_GENERIC_READ
            || evidence.ace_sid
                != security
                    .sid
                    .iter()
                    .flat_map(|word| word.to_ne_bytes())
                    .collect::<Vec<_>>()
        {
            return Err(denied(
                "probe R DACL is not protected owner-only with exact mask and zero ACE flags",
            ));
        }
        Ok(evidence)
    }

    fn probe_check_full(handle: HANDLE, security: &Security) -> io::Result<ProbeAclEvidence> {
        if security.check_owner_access(handle, false)? != PrivateFileAccess::FullControl {
            return Err(denied("probe fixture DACL is not full-control"));
        }
        probe_acl_evidence(handle, security)
    }

    fn probe_open_bound(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        directory: bool,
        desired: u32,
        sharing: u32,
        descriptor: *const SECURITY_DESCRIPTOR,
        expected: Option<FileIdentity>,
        metadata: bool,
    ) -> io::Result<ProbeHandle> {
        if metadata && desired & FILE_READ_ATTRIBUTES == 0 {
            return Err(invalid(
                "FILE_READ_ATTRIBUTES is required for the requested metadata oracle",
            ));
        }
        let handle = probe_open(
            ledger, parent, parent_id, name, directory, FILE_OPEN, desired, sharing, descriptor,
        )?;
        let actual = identity(ledger.raw(handle))?;
        if expected.is_some_and(|wanted| wanted != actual) {
            return Err(denied(
                "probe handle full identity does not match its recorded object",
            ));
        }
        if metadata {
            ensure_kind(ledger.raw(handle), directory)?;
        }
        Ok(handle)
    }

    fn probe_open_lock_bound(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        expected: Option<FileIdentity>,
    ) -> io::Result<ProbeHandle> {
        let name = OsStr::new("transaction.lock");
        validate_lock_component(name)?;
        let handle = probe_open_validated(
            ledger,
            parent,
            parent_id,
            name,
            false,
            FILE_OPEN,
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
        )?;
        let actual = identity(ledger.raw(handle))?;
        if expected.is_some_and(|wanted| actual != wanted) {
            return Err(denied("lock teardown full identity changed"));
        }
        ensure_kind(ledger.raw(handle), false)?;
        Ok(handle)
    }

    fn probe_check_lock_absent(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
    ) -> io::Result<()> {
        match probe_open_lock_bound(ledger, parent, parent_id, None) {
            Ok(handle) => {
                ledger.close(handle)?;
                Err(denied("lock file remains after teardown"))
            }
            Err(error) if probe_name_missing(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn probe_check_absent(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
    ) -> io::Result<()> {
        match probe_open_bound(
            ledger,
            parent,
            parent_id,
            name,
            true,
            FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            None,
            true,
        ) {
            Ok(handle) => {
                ledger.close(handle)?;
                Err(denied(
                    "probe name expected absent but it resolved to a directory",
                ))
            }
            Err(error) if probe_name_missing(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn probe_check_named_directory(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        expected: FileIdentity,
        security: &Security,
    ) -> io::Result<ProbeHandle> {
        let root = probe_open_bound(
            ledger,
            parent,
            parent_id,
            name,
            true,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            Some(expected),
            true,
        )?;
        security.check(ledger.raw(root))?;
        let _ = probe_check_full(ledger.raw(root), security)?;
        Ok(root)
    }

    fn probe_create_payload(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        bytes: &[u8],
        security: &Security,
    ) -> io::Result<(FileIdentity, ProbeAclEvidence)> {
        let writer = probe_open(
            ledger,
            parent,
            parent_id,
            name,
            false,
            FILE_CREATE,
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security.descriptor.as_ptr().cast(),
        )?;
        let file_id = identity(ledger.raw(writer))?;
        let creation_acl = probe_check_full(ledger.raw(writer), security)?;
        let granted = probe_granted_access(ledger.raw(writer))?;
        println!(
            "probe_payload_create file_id={file_id:?} desired=0x{:08x} share=0x{:08x} granted=0x{granted:08x} owner_dacl={creation_acl:?}",
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
        if granted != FILE_ALL_ACCESS {
            return Err(denied(
                "probe file writer grant differs from FILE_ALL_ACCESS creation request",
            ));
        }
        let mut written = 0u32;
        let write_result = if unsafe {
            WriteFile(
                ledger.raw(writer),
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else if written as usize != bytes.len() {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short probe fixture write",
            ))
        } else if unsafe { FlushFileBuffers(ledger.raw(writer)) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        let close_result = ledger.close(writer);
        match (write_result, close_result) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Err(error), Err(close)) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; probe writer close also failed: {close}"),
                ));
            }
        }
        let view = probe_open_bound(
            ledger,
            parent,
            parent_id,
            name,
            false,
            FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            Some(file_id),
            true,
        )?;
        let observed_acl = probe_check_full(ledger.raw(view), security)?;
        if observed_acl != creation_acl {
            return Err(denied(
                "full-control fixture DACL changed between creation and readback",
            ));
        }
        if probe_read_payload(ledger.raw(view), file_id)? != bytes {
            return Err(denied(
                "flushed probe fixture bytes differ on independent readback",
            ));
        }
        ledger.close(view)?;
        Ok((file_id, observed_acl))
    }

    fn probe_set_dacl(handle: HANDLE, security: &Security) -> io::Result<()> {
        let mut present = 0;
        let mut dacl = null_mut();
        let mut defaulted = 0;
        unsafe {
            ok(GetSecurityDescriptorDacl(
                security.descriptor.as_ptr().cast_mut().cast(),
                &mut present,
                &mut dacl,
                &mut defaulted,
            ))?;
        }
        if present == 0 || dacl.is_null() {
            return Err(invalid("probe descriptor has no DACL"));
        }
        let result = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result as i32))
        }
    }

    fn probe_readonly_security(security: &Security) -> io::Result<Security> {
        let mut sid_text = null_mut();
        unsafe {
            ok(ConvertSidToStringSidW(
                security.sid.as_ptr().cast_mut().cast(),
                &mut sid_text,
            ))?;
        }
        let sid_allocation = LocalAllocation(sid_text.cast());
        let mut sid_length = 0usize;
        while unsafe { *sid_text.add(sid_length) } != 0 {
            sid_length += 1;
        }
        let owner = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, sid_length) })
            .map_err(|_| invalid("probe owner SID string encoding"))?;
        drop(sid_allocation);
        let text = wide(OsStr::new(&format!(
            "O:{owner}D:P(A;;0x00120089;;;{owner})"
        )));
        let mut raw = null_mut();
        let mut length = 0u32;
        unsafe {
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                &mut length,
            ))?;
        }
        let allocation = LocalAllocation(raw);
        let actual_length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
        if actual_length == 0 || length < actual_length as u32 {
            return Err(invalid("probe R descriptor length is invalid"));
        }
        let mut descriptor = vec![0usize; actual_length.div_ceil(size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                raw.cast::<u8>(),
                descriptor.as_mut_ptr().cast(),
                actual_length,
            );
        }
        drop(allocation);
        Ok(Security {
            sid: security.sid.clone(),
            descriptor,
        })
    }

    fn probe_open_fixture_directory(
        ledger: &mut ProbeLedger,
        path: &Path,
        security: &Security,
        expected: FileIdentity,
    ) -> io::Result<Directory> {
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(unsupported("probe requires a local drive")),
            },
            _ => return Err(invalid("probe root must be absolute")),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(invalid("probe drive-relative path"));
        }
        let names = components
            .map(|component| match component {
                Component::Normal(name) => {
                    validate_component(name)?;
                    Ok(name.to_os_string())
                }
                _ => Err(invalid("ambiguous probe fixture path")),
            })
            .collect::<io::Result<Vec<_>>>()?;
        if names.is_empty() {
            return Err(invalid("probe fixture cannot be drive root"));
        }
        let drive_path = wide(OsStr::new(&format!("{}:\\", char::from(drive))));
        if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != DRIVE_FIXED {
            return Err(unsupported("probe requires fixed local NTFS"));
        }
        let root_path = wide(OsStr::new(&format!("\\\\?\\{}:\\", char::from(drive))));
        let raw = unsafe {
            CreateFileW(
                root_path.as_ptr(),
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
        let first = ledger.own(unsafe { OwnedHandle::from_raw_handle(raw) });
        ensure_kind(ledger.raw(first), true)?;
        let mut filesystem = [0u16; 32];
        unsafe {
            ok(GetVolumeInformationByHandleW(
                ledger.raw(first),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            ))?;
        }
        let length = filesystem
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(filesystem.len());
        if String::from_utf16_lossy(&filesystem[..length]) != "NTFS" {
            return Err(unsupported("probe requires NTFS semantics"));
        }
        let mut anchors = vec![first];
        let mut parent_id = identity(ledger.raw(first))?;
        for (index, name) in names.iter().enumerate() {
            let desired = if index + 1 == names.len() {
                FILE_ALL_ACCESS & !DELETE
            } else {
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            };
            let parent = ledger.raw(*anchors.last().unwrap());
            let handle = probe_open_validated(
                ledger,
                parent,
                parent_id,
                name,
                true,
                FILE_OPEN,
                desired,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
            )?;
            ensure_kind(ledger.raw(handle), true)?;
            parent_id = identity(ledger.raw(handle))?;
            anchors.push(handle);
        }
        let final_raw = ledger.raw(*anchors.last().unwrap());
        security.check(final_raw)?;
        if parent_id != expected {
            return Err(denied(
                "fixture path differs from recorded creation full identity",
            ));
        }
        // No fallible operation follows transfer: all these owners are already
        // registered, validated and known live. The returned Directory is stored
        // in its fixture/ledger slot before the caller's next fallible operation.
        if anchors.iter().any(|handle| !ledger.live(*handle)) {
            return Err(invalid("missing checked fixture anchor"));
        }
        let chain = anchors
            .into_iter()
            .map(|handle| Arc::new(ledger.handles[handle.0].take().unwrap()))
            .collect();
        Ok(Directory {
            chain,
            identity: parent_id,
            security: probe_security_copy(security),
            enumeration: Mutex::new(()),
        })
    }

    fn probe_create_fixture_lock(
        ledger: &mut ProbeLedger,
        parent: &Directory,
        security: &Security,
    ) -> io::Result<StateLock> {
        let name = OsStr::new("transaction.lock");
        validate_lock_component(name)?;
        let handle = probe_open_validated(
            ledger,
            parent.handle(),
            parent.identity(),
            name,
            false,
            FILE_CREATE,
            FILE_ALL_ACCESS & !DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            security.descriptor.as_ptr().cast(),
        )?;
        let raw = ledger.raw(handle);
        ensure_kind(raw, false)?;
        security.check(raw)?;
        let file_id = identity(raw)?;
        if file_snapshot(raw, file_id)?.length != 0 {
            return Err(denied("new probe lock is not empty"));
        }
        let mut overlap = OVERLAPPED::default();
        if unsafe {
            LockFileEx(
                raw,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlap,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
                probe_uncertain_native_fail_stop();
            }
            return Err(error);
        }
        let owned = ledger.handles[handle.0].take().unwrap();
        Ok(StateLock {
            file: PrivateFile {
                file: File::from(owned),
                identity: file_id,
                parent: parent.identity(),
                _anchors: parent.chain.clone(),
                security: probe_security_copy(security),
                writable_candidate: AtomicBool::new(false),
                publication: Mutex::new(()),
            },
            mode: LockMode::Exclusive,
        })
    }

    fn probe_create_directory(
        ledger: &mut ProbeLedger,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        path: &std::path::Path,
        security: &Security,
        stage_log: Option<&mut Vec<ProbeStage>>,
    ) -> io::Result<(ProbeHandle, FileIdentity)> {
        let creator = probe_open(
            ledger,
            parent,
            parent_id,
            name,
            true,
            FILE_CREATE,
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security.descriptor.as_ptr().cast(),
        )?;
        let created_id = identity(ledger.raw(creator))?;
        let acl = probe_check_full(ledger.raw(creator), security)?;
        if acl.ace_flags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 {
            return Err(denied(
                "new private directory creation ACE flags differ from captured descriptor",
            ));
        }
        if let Some(log) = stage_log {
            log.push(ProbeStage {
                name: name.to_os_string(),
                identity: created_id,
                payload: None,
                payload_acl_before: None,
                payload_acl_after: None,
            });
        }
        ledger.close(creator)?;
        let checked_owner = probe_open_fixture_directory(ledger, path, security, created_id)?;
        let checked_index = ledger.own_directory(checked_owner);
        let checked = ledger.directory(checked_index);
        let checked_id = checked.identity();
        checked.check()?;
        if checked_id != created_id {
            return Err(denied(
                "opened probe directory identity differs from creation identity",
            ));
        }
        let _checked_acl = checked.security.check(checked.handle())?;
        ledger.close_directory(checked_index)?;
        let root = probe_open_bound(
            ledger,
            parent,
            parent_id,
            name,
            true,
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            Some(created_id),
            true,
        )?;
        let granted = probe_granted_access(ledger.raw(root))?;
        if granted != DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE {
            return Err(denied(
                "probe stage root grant differs from DELETE rename authority",
            ));
        }
        println!(
            "probe_root name={name:?} path={path:?} full_id={created_id:?} creation_acl={acl:?} requested=0x{:08x} share=0x{:08x} granted=0x{granted:08x}",
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE
        );
        Ok((root, created_id))
    }

    fn probe_directory_chain(directory: &Directory) -> io::Result<Vec<FileIdentity>> {
        directory
            .chain
            .iter()
            .map(|handle| identity(handle.as_raw_handle()))
            .collect()
    }

    fn probe_recheck_chain(directory: &Directory, expected: &[FileIdentity]) -> io::Result<()> {
        let observed = probe_directory_chain(directory)?;
        if observed != expected {
            return Err(denied("held parent/ancestor full identity chain changed"));
        }
        directory.check()
    }

    fn probe_close_lock_owned(lock: StateLock) -> Vec<String> {
        probe_close_lock(lock)
    }

    struct ProbeFixture {
        ledger: ProbeLedger,
        security: Option<Security>,
        read_only: Option<Security>,
        temp_parent: Option<ProbeHandle>,
        temp_parent_id: Option<FileIdentity>,
        base_name: Option<OsString>,
        base_path: Option<std::path::PathBuf>,
        base_id: Option<FileIdentity>,
        base_dir: Option<Directory>,
        base_chain: Vec<FileIdentity>,
        state_name: OsString,
        state_path: Option<std::path::PathBuf>,
        state_id: Option<FileIdentity>,
        state_dir: Option<Directory>,
        state_chain: Vec<FileIdentity>,
        foreign_name: OsString,
        foreign_path: Option<std::path::PathBuf>,
        foreign_id: Option<FileIdentity>,
        foreign_dir: Option<Directory>,
        foreign_chain: Vec<FileIdentity>,
        lock: Option<StateLock>,
        lock_id: Option<FileIdentity>,
        stages: Vec<ProbeStage>,
        foreign_canary: Option<(FileIdentity, ProbeAclEvidence)>,
        removed: Vec<String>,
        preserve_receipt: String,
    }

    impl ProbeFixture {
        fn empty() -> Self {
            Self {
                ledger: ProbeLedger::new(),
                security: None,
                read_only: None,
                temp_parent: None,
                temp_parent_id: None,
                base_name: None,
                base_path: None,
                base_id: None,
                base_dir: None,
                base_chain: Vec::new(),
                state_name: OsString::from("state"),
                state_path: None,
                state_id: None,
                state_dir: None,
                state_chain: Vec::new(),
                foreign_name: OsString::from("foreign-parent"),
                foreign_path: None,
                foreign_id: None,
                foreign_dir: None,
                foreign_chain: Vec::new(),
                lock: None,
                lock_id: None,
                stages: Vec::new(),
                foreign_canary: None,
                removed: Vec::new(),
                preserve_receipt: String::new(),
            }
        }

        fn initialize(&mut self) -> io::Result<()> {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            self.security = Some(Security::current()?);
            let temp_path = std::env::temp_dir();
            let wide_path = wide(temp_path.as_os_str());
            let raw = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    FILE_LIST_DIRECTORY
                        | FILE_ADD_SUBDIRECTORY
                        | FILE_DELETE_CHILD
                        | FILE_READ_ATTRIBUTES
                        | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let temp_parent = self
                .ledger
                .own(unsafe { OwnedHandle::from_raw_handle(raw) });
            ensure_kind(self.ledger.raw(temp_parent), true)?;
            let temp_id = identity(self.ledger.raw(temp_parent))?;
            let desired = FILE_LIST_DIRECTORY
                | FILE_ADD_SUBDIRECTORY
                | FILE_DELETE_CHILD
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE;
            let granted = probe_granted_access(self.ledger.raw(temp_parent))?;
            if granted & desired != desired {
                return Err(denied(
                    "temporary parent lacks measured relative-create/delete rights",
                ));
            }
            self.temp_parent = Some(temp_parent);
            self.temp_parent_id = Some(temp_id);

            let base = OsString::from(format!(
                "orbit-leaf15-probe-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            validate_data_component(&base)?;
            let base_path = temp_path.join(&base);
            self.base_name = Some(base.clone());
            self.base_path = Some(base_path.clone());
            let temp_raw = self.ledger.raw(temp_parent);
            let (base_handle, base_id) = probe_create_directory(
                &mut self.ledger,
                temp_raw,
                temp_id,
                &base,
                &base_path,
                self.security.as_ref().unwrap(),
                None,
            )?;
            self.base_id = Some(base_id);
            self.ledger.close(base_handle)?;
            self.base_dir = Some(probe_open_fixture_directory(
                &mut self.ledger,
                &base_path,
                self.security.as_ref().unwrap(),
                base_id,
            )?);
            let base_dir = self.base_dir.as_ref().unwrap();
            self.base_chain = probe_directory_chain(base_dir)?;
            if base_dir.identity() != base_id {
                return Err(denied(
                    "private probe base identity differs from created object",
                ));
            }

            let base_dir = self.base_dir.as_ref().unwrap();
            let state_path = base_path.join(&self.state_name);
            self.state_path = Some(state_path.clone());
            let (state_creator, state_id) = probe_create_directory(
                &mut self.ledger,
                base_dir.handle(),
                base_id,
                &self.state_name,
                &state_path,
                self.security.as_ref().unwrap(),
                None,
            )?;
            self.state_id = Some(state_id);
            self.ledger.close(state_creator)?;
            self.state_dir = Some(probe_open_fixture_directory(
                &mut self.ledger,
                &state_path,
                self.security.as_ref().unwrap(),
                state_id,
            )?);
            let state = self.state_dir.as_ref().unwrap();
            self.state_chain = probe_directory_chain(state)?;
            if state.identity() != state_id {
                return Err(denied(
                    "private probe state identity differs from created object",
                ));
            }
            self.lock = Some(probe_create_fixture_lock(
                &mut self.ledger,
                self.state_dir.as_ref().unwrap(),
                self.security.as_ref().unwrap(),
            )?);
            let lock = self.lock.as_ref().unwrap();
            self.lock_id = Some(lock.identity());
            self.state_dir.as_ref().unwrap().require_lock(lock, true)?;

            let foreign_path = base_path.join(&self.foreign_name);
            self.foreign_path = Some(foreign_path.clone());
            let (foreign_creator, foreign_id) = probe_create_directory(
                &mut self.ledger,
                base_dir.handle(),
                base_id,
                &self.foreign_name,
                &foreign_path,
                self.security.as_ref().unwrap(),
                None,
            )?;
            self.foreign_id = Some(foreign_id);
            self.ledger.close(foreign_creator)?;
            self.foreign_dir = Some(probe_open_fixture_directory(
                &mut self.ledger,
                &foreign_path,
                self.security.as_ref().unwrap(),
                foreign_id,
            )?);
            let foreign = self.foreign_dir.as_ref().unwrap();
            self.foreign_chain = probe_directory_chain(foreign)?;
            if foreign.identity() != foreign_id {
                return Err(denied(
                    "foreign parent identity differs from created object",
                ));
            }
            self.read_only = Some(probe_readonly_security(self.security.as_ref().unwrap())?);
            println!(
                "probe_fixture temp_parent={temp_id:?} base={base_id:?} state={state_id:?} foreign={foreign_id:?} lock={:?} lock_mode=Exclusive temp_parent_desired=0x{:08x} temp_parent_granted=0x{granted:08x}",
                self.lock_id, desired,
            );
            Ok(())
        }

        fn base(&self) -> &Directory {
            self.base_dir.as_ref().expect("initialized fixture base")
        }
        fn state(&self) -> &Directory {
            self.state_dir.as_ref().expect("initialized fixture state")
        }
        fn foreign(&self) -> &Directory {
            self.foreign_dir
                .as_ref()
                .expect("initialized fixture foreign")
        }
        fn sec(&self) -> &Security {
            self.security.as_ref().expect("captured probe owner")
        }
        fn rsec(&self) -> &Security {
            self.read_only
                .as_ref()
                .expect("constructed R fixture policy")
        }

        fn bind_stage_payload(
            &mut self,
            root: FileIdentity,
            name: &OsStr,
            file: FileIdentity,
            acl: ProbeAclEvidence,
        ) -> io::Result<()> {
            let stage = self
                .stages
                .iter_mut()
                .find(|stage| stage.identity == root)
                .ok_or_else(|| invalid("created stage is absent from fixture ledger"))?;
            stage.payload = Some((name.to_os_string(), file));
            stage.payload_acl_before = Some(acl.clone());
            stage.payload_acl_after = Some(acl);
            Ok(())
        }

        fn rename_stage(&mut self, root: FileIdentity, new_name: &OsStr) -> io::Result<()> {
            let stage = self
                .stages
                .iter_mut()
                .find(|stage| stage.identity == root)
                .ok_or_else(|| invalid("renamed stage is absent from fixture ledger"))?;
            stage.name = new_name.to_os_string();
            Ok(())
        }

        fn close_parent_owners(&mut self) -> Vec<String> {
            let mut errors = Vec::new();
            if let Some(lock) = self.lock.take() {
                errors.extend(probe_close_lock_owned(lock));
            }
            if let Some(foreign) = self.foreign_dir.take() {
                errors.extend(probe_close_directory(foreign));
            }
            if let Some(state) = self.state_dir.take() {
                errors.extend(probe_close_directory(state));
            }
            if let Some(base) = self.base_dir.take() {
                errors.extend(probe_close_directory(base));
            }
            if let Some(temp) = self.temp_parent.take() {
                if let Err(error) = self.ledger.close(temp) {
                    errors.push(format!("temporary parent close: {error}"));
                }
            }
            errors
        }

        fn preserve_failure(&mut self) -> Vec<String> {
            let keep = self.temp_parent.into_iter().collect::<Vec<_>>();
            let mut errors = self.ledger.close_except(&keep);
            errors.extend(self.close_parent_owners());
            self.preserve_receipt = format!(
                "preserved non-authorizing fixture at {:?}; created={:?}; removed={:?}; consumed_close_facts={:?}; close_errors={errors:?}",
                self.base_path, self.ledger.created, self.removed, self.ledger.closed,
            );
            println!("probe_teardown=preserved receipt={}", self.preserve_receipt);
            errors
        }

        fn cleanup_success(&mut self) -> io::Result<()> {
            self.cleanup_known_entries()?;
            let close_errors = self.close_parent_owners();
            if !close_errors.is_empty() {
                return Err(io::Error::other(format!(
                    "checked fixture owner close errors: {close_errors:?}"
                )));
            }
            if let Some(temp) = self.temp_parent {
                if self.ledger.live(temp) {
                    return Err(invalid("temporary parent still live after fixture cleanup"));
                }
            }
            println!(
                "probe_teardown=all-known-identities-removed removed={:?}",
                self.removed
            );
            Ok(())
        }

        fn finish_success(&mut self) -> io::Result<()> {
            let keep = self.temp_parent.into_iter().collect::<Vec<_>>();
            let close_errors = self.ledger.close_except(&keep);
            if !close_errors.is_empty() {
                return Err(io::Error::other(format!(
                    "pre-cleanup owner close errors: {close_errors:?}"
                )));
            }
            self.cleanup_success()
        }

        fn cleanup_known_entries(&mut self) -> io::Result<()> {
            let state_id = self
                .state_id
                .ok_or_else(|| invalid("state identity missing at teardown"))?;
            let state_handle = self.state().handle();
            let lock_id = self
                .lock_id
                .ok_or_else(|| invalid("lock identity missing at teardown"))?;
            let lock = self
                .lock
                .as_ref()
                .ok_or_else(|| invalid("exclusive lock missing at teardown"))?;
            self.state().require_lock(lock, true)?;
            if identity(state_handle)? != state_id || lock.identity() != lock_id {
                return Err(denied("state/lock full identity changed before teardown"));
            }
            let entries = directory_entries(
                state_handle,
                EnumerationLimits {
                    max_entries: 16,
                    max_name_bytes: 65536,
                },
            )?;
            let expected_names: Vec<OsString> = self
                .stages
                .iter()
                .map(|stage| stage.name.clone())
                .chain([OsString::from("transaction.lock")])
                .collect();
            if entries.len() != expected_names.len()
                || expected_names
                    .iter()
                    .any(|name| !entries.iter().any(|entry| &entry.name == name))
            {
                return Err(denied(
                    "state directory inventory differs from recorded fixture ledger",
                ));
            }
            for stage in self.stages.clone() {
                self.cleanup_stage(&stage)?;
            }
            // Keep the actual exclusive guard through all stage removals; only
            // its own final file removal requires releasing its no-delete hold.
            let lock = self
                .lock
                .take()
                .ok_or_else(|| invalid("exclusive lock missing before teardown"))?;
            let lock_close = probe_close_lock_owned(lock);
            if !lock_close.is_empty() {
                return Err(io::Error::other(format!(
                    "checked exclusive-lock close failed: {lock_close:?}"
                )));
            }
            self.cleanup_lock_file(lock_id)?;
            if !directory_entries(
                state_handle,
                EnumerationLimits {
                    max_entries: 16,
                    max_name_bytes: 65536,
                },
            )?
            .is_empty()
            {
                return Err(denied(
                    "state directory is not empty after known stage/lock cleanup",
                ));
            }
            self.close_state_before_remove(state_id)?;
            let base_id = self
                .base_id
                .ok_or_else(|| invalid("base identity missing at teardown"))?;
            self.remove_named_directory_from_base(&self.state_name.clone(), state_id)?;

            let foreign_id = self
                .foreign_id
                .ok_or_else(|| invalid("foreign parent identity missing at teardown"))?;
            let foreign = self.foreign().handle();
            let canary = self
                .foreign_canary
                .clone()
                .ok_or_else(|| invalid("foreign canary ledger is missing"))?;
            let listed = directory_entries(
                foreign,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?;
            if listed.len() != 1
                || listed[0].name != OsStr::new("canary")
                || listed[0].identity != canary.0.file
            {
                return Err(denied(
                    "foreign parent inventory differs from recorded canary",
                ));
            }
            self.cleanup_foreign_canary(canary.0, &canary.1)?;
            if !directory_entries(
                foreign,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?
            .is_empty()
            {
                return Err(denied("foreign parent not empty after canary cleanup"));
            }
            self.close_foreign_before_remove(foreign_id)?;
            self.remove_named_directory_from_base(&self.foreign_name.clone(), foreign_id)?;

            let base_handle = self.base().handle();
            if identity(base_handle)? != base_id
                || !directory_entries(
                    base_handle,
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 8192,
                    },
                )?
                .is_empty()
            {
                return Err(denied(
                    "base inventory is not empty after state and foreign cleanup",
                ));
            }
            self.close_base_before_remove(base_id)?;
            self.remove_base_from_temp(base_id)?;
            Ok(())
        }

        fn cleanup_stage(&mut self, stage: &ProbeStage) -> io::Result<()> {
            let security = probe_security_copy(self.sec());
            let read_only = probe_security_copy(self.rsec());
            self.state().require_lock(
                self.lock
                    .as_ref()
                    .ok_or_else(|| invalid("cleanup requires live guard"))?,
                true,
            )?;
            let state = self.state();
            let state_id = state.identity();
            let parent = state.handle();
            let root = probe_check_named_directory(
                &mut self.ledger,
                parent,
                state_id,
                &stage.name,
                stage.identity,
                &security,
            )?;
            let root_handle = self.ledger.raw(root);
            let entries = directory_entries(
                root_handle,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?;
            match &stage.payload {
                Some((name, file_id)) => {
                    if entries.len() != 1
                        || entries[0].name != *name
                        || entries[0].identity != file_id.file
                    {
                        return Err(denied(
                            "stage cleanup inventory differs from recorded payload full identity",
                        ));
                    }
                    let writer = probe_open_bound(
                        &mut self.ledger,
                        root_handle,
                        stage.identity,
                        name,
                        false,
                        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        null(),
                        Some(*file_id),
                        true,
                    )?;
                    let writer_raw = self.ledger.raw(writer);
                    let acl_now = match probe_acl_evidence(writer_raw, &security) {
                        Ok(evidence)
                            if evidence.ace_flags == 0
                                && evidence.ace_mask == FILE_GENERIC_READ =>
                        {
                            probe_check_r(writer_raw, &read_only)?
                        }
                        Ok(_) => probe_check_full(writer_raw, &security)?,
                        Err(error) => return Err(error),
                    };
                    if stage
                        .payload_acl_after
                        .as_ref()
                        .is_some_and(|expected| expected != &acl_now)
                    {
                        return Err(denied(
                            "payload ACL differs from the measured final DACL snapshot",
                        ));
                    }
                    probe_set_dacl(writer_raw, &security)?;
                    let restored = probe_check_full(writer_raw, &security)?;
                    println!(
                        "probe_teardown_acl_restore file_id={file_id:?} restored_acl={restored:?} after_measurement=true"
                    );
                    self.ledger.close(writer)?;

                    let delete_file = probe_open_bound(
                        &mut self.ledger,
                        root_handle,
                        stage.identity,
                        name,
                        false,
                        FILE_ALL_ACCESS,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        null(),
                        Some(*file_id),
                        true,
                    )?;
                    let delete_raw = self.ledger.raw(delete_file);
                    let _ = probe_check_full(delete_raw, &security)?;
                    probe_disposition(delete_raw)?;
                    self.ledger.close(delete_file)?;
                    self.removed.push(format!("payload:{:?}:{file_id:?}", name));
                    if !directory_entries(
                        root_handle,
                        EnumerationLimits {
                            max_entries: 4,
                            max_name_bytes: 4096,
                        },
                    )?
                    .is_empty()
                    {
                        return Err(denied(
                            "stage directory has an unrecorded entry after payload disposition",
                        ));
                    }
                }
                None if !entries.is_empty() => {
                    return Err(denied(
                        "empty control stage contains an unrecorded entry at teardown",
                    ));
                }
                None => {}
            }
            self.ledger.close(root)?;
            let remove_root = probe_open_bound(
                &mut self.ledger,
                parent,
                state_id,
                &stage.name,
                true,
                DELETE
                    | FILE_LIST_DIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                Some(stage.identity),
                true,
            )?;
            let remove_raw = self.ledger.raw(remove_root);
            let _ = probe_check_full(remove_raw, &security)?;
            if !directory_entries(
                remove_raw,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?
            .is_empty()
            {
                return Err(denied(
                    "stage directory is not empty before identity-bound teardown",
                ));
            }
            probe_disposition(remove_raw)?;
            self.ledger.close(remove_root)?;
            probe_check_absent(&mut self.ledger, parent, state_id, &stage.name)?;
            self.removed
                .push(format!("stage:{:?}:{:?}", stage.name, stage.identity));
            Ok(())
        }

        fn cleanup_lock_file(&mut self, expected: FileIdentity) -> io::Result<()> {
            let parent = self.state().handle();
            let state_id = self.state().identity();
            let opened = probe_open_lock_bound(&mut self.ledger, parent, state_id, Some(expected))?;
            let raw = self.ledger.raw(opened);
            let _ = probe_check_full(raw, self.sec())?;
            probe_disposition(raw)?;
            self.ledger.close(opened)?;
            probe_check_lock_absent(&mut self.ledger, parent, state_id)?;
            self.removed.push(format!("lock:{expected:?}"));
            Ok(())
        }

        fn cleanup_foreign_canary(
            &mut self,
            expected: FileIdentity,
            expected_acl: &ProbeAclEvidence,
        ) -> io::Result<()> {
            let security = probe_security_copy(self.sec());
            let parent = self.foreign().handle();
            let foreign_id = self.foreign().identity();
            let opened = probe_open_bound(
                &mut self.ledger,
                parent,
                foreign_id,
                OsStr::new("canary"),
                false,
                FILE_ALL_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                Some(expected),
                true,
            )?;
            let raw = self.ledger.raw(opened);
            let actual_acl = probe_check_full(raw, &security)?;
            if &actual_acl != expected_acl
                || probe_read_payload(raw, expected)? != b"untouched foreign canary"
            {
                return Err(denied(
                    "foreign canary ACL, bytes, or full identity changed before teardown",
                ));
            }
            probe_disposition(raw)?;
            self.ledger.close(opened)?;
            probe_check_absent(&mut self.ledger, parent, foreign_id, OsStr::new("canary"))?;
            self.removed.push(format!("foreign-canary:{expected:?}"));
            Ok(())
        }

        fn close_state_before_remove(&mut self, expected: FileIdentity) -> io::Result<()> {
            let state = self
                .state_dir
                .take()
                .ok_or_else(|| invalid("state Directory owner missing"))?;
            let actual = state.identity();
            if actual != expected {
                return Err(denied(
                    "state Directory owner identity changed before close",
                ));
            }
            let errors = probe_close_directory(state);
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "state Directory close errors: {errors:?}"
                )))
            }
        }

        fn close_foreign_before_remove(&mut self, expected: FileIdentity) -> io::Result<()> {
            let foreign = self
                .foreign_dir
                .take()
                .ok_or_else(|| invalid("foreign Directory owner missing"))?;
            let actual = foreign.identity();
            if actual != expected {
                return Err(denied(
                    "foreign Directory owner identity changed before close",
                ));
            }
            let errors = probe_close_directory(foreign);
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "foreign Directory close errors: {errors:?}"
                )))
            }
        }

        fn close_base_before_remove(&mut self, expected: FileIdentity) -> io::Result<()> {
            let base = self
                .base_dir
                .take()
                .ok_or_else(|| invalid("base Directory owner missing"))?;
            let actual = base.identity();
            if actual != expected {
                return Err(denied("base Directory owner identity changed before close"));
            }
            let errors = probe_close_directory(base);
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "base Directory close errors: {errors:?}"
                )))
            }
        }

        fn remove_named_directory_from_base(
            &mut self,
            name: &OsStr,
            expected: FileIdentity,
        ) -> io::Result<()> {
            let security = probe_security_copy(self.sec());
            let parent = self.base().handle();
            let base_id = self.base().identity();
            let remove = probe_open_bound(
                &mut self.ledger,
                parent,
                base_id,
                name,
                true,
                DELETE
                    | FILE_LIST_DIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                Some(expected),
                true,
            )?;
            let raw = self.ledger.raw(remove);
            let _ = probe_check_full(raw, &security)?;
            if !directory_entries(
                raw,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?
            .is_empty()
            {
                return Err(denied("known child directory is not empty at teardown"));
            }
            probe_disposition(raw)?;
            self.ledger.close(remove)?;
            probe_check_absent(&mut self.ledger, parent, base_id, name)?;
            self.removed
                .push(format!("directory:{name:?}:{expected:?}"));
            Ok(())
        }

        fn remove_base_from_temp(&mut self, expected: FileIdentity) -> io::Result<()> {
            let security = probe_security_copy(self.sec());
            let temp = self
                .temp_parent
                .ok_or_else(|| invalid("temporary parent handle missing"))?;
            let parent = self.ledger.raw(temp);
            let parent_id = self
                .temp_parent_id
                .ok_or_else(|| invalid("temporary parent full ID missing"))?;
            if identity(parent)? != parent_id {
                return Err(denied("temporary parent full identity changed"));
            }
            let name = self
                .base_name
                .as_ref()
                .ok_or_else(|| invalid("base name missing"))?
                .clone();
            let remove = probe_open_bound(
                &mut self.ledger,
                parent,
                parent_id,
                &name,
                true,
                DELETE
                    | FILE_LIST_DIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                Some(expected),
                true,
            )?;
            let raw = self.ledger.raw(remove);
            let _ = probe_check_full(raw, &security)?;
            if !directory_entries(
                raw,
                EnumerationLimits {
                    max_entries: 4,
                    max_name_bytes: 4096,
                },
            )?
            .is_empty()
            {
                return Err(denied("fixture base directory is not empty at teardown"));
            }
            probe_disposition(raw)?;
            self.ledger.close(remove)?;
            probe_check_absent(&mut self.ledger, parent, parent_id, &name)?;
            self.removed.push(format!("fixture-base:{expected:?}"));
            Ok(())
        }
    }

    fn probe_verify_payload(
        ledger: &mut ProbeLedger,
        root: HANDLE,
        root_id: FileIdentity,
        file_name: &OsStr,
        expected_id: FileIdentity,
        expected_bytes: &[u8],
        security: &Security,
        expect_r: bool,
        expected_acl: Option<&ProbeAclEvidence>,
    ) -> io::Result<ProbeAclEvidence> {
        let view = probe_open_bound(
            ledger,
            root,
            root_id,
            file_name,
            false,
            FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            Some(expected_id),
            true,
        )?;
        let raw = ledger.raw(view);
        let granted = probe_granted_access(raw)?;
        let desired = FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE;
        println!(
            "probe_read_view file_id={expected_id:?} desired=0x{desired:08x} share=0x{:08x} granted=0x{granted:08x}",
            FILE_SHARE_READ | FILE_SHARE_DELETE
        );
        if granted != desired {
            return Err(denied(
                "probe read-view grant differs from requested R view",
            ));
        }
        let acl = if expect_r {
            probe_check_r(raw, security)?
        } else {
            probe_check_full(raw, security)?
        };
        if expected_acl.is_some_and(|expected| expected != &acl) {
            return Err(denied(
                "payload policy changed across namespace observation",
            ));
        }
        if probe_read_payload(raw, expected_id)? != expected_bytes {
            return Err(denied("payload bytes changed across namespace observation"));
        }
        let standard: FILE_STANDARD_INFO = information(raw, FileStandardInfo)?;
        if standard.NumberOfLinks != 1 || standard.DeletePending {
            return Err(denied("payload link count or delete-pending fact changed"));
        }
        ledger.close(view)?;
        Ok(acl)
    }

    fn probe_positive_control(
        fixture: &mut ProbeFixture,
        old_name: &OsStr,
        target_name: &OsStr,
        payload: Option<&[u8]>,
    ) -> io::Result<(FileIdentity, Option<FileIdentity>)> {
        let security = probe_security_copy(fixture.sec());
        let parent = fixture.state().handle();
        let parent_id = fixture.state().identity();
        probe_check_absent(&mut fixture.ledger, parent, parent_id, target_name)?;
        let stage_path = fixture
            .state_path
            .as_ref()
            .ok_or_else(|| invalid("state path missing"))?
            .join(old_name);
        let (root, root_id) = probe_create_directory(
            &mut fixture.ledger,
            parent,
            parent_id,
            old_name,
            &stage_path,
            &security,
            Some(&mut fixture.stages),
        )?;
        let file_id = if let Some(bytes) = payload {
            let root_raw = fixture.ledger.raw(root);
            let (file_id, acl) = probe_create_payload(
                &mut fixture.ledger,
                root_raw,
                root_id,
                OsStr::new("payload"),
                bytes,
                &security,
            )?;
            fixture.bind_stage_payload(root_id, OsStr::new("payload"), file_id, acl)?;
            Some(file_id)
        } else {
            None
        };

        probe_recheck_chain(fixture.state(), &fixture.state_chain)?;
        fixture.state().require_lock(
            fixture
                .lock
                .as_ref()
                .ok_or_else(|| invalid("exclusive parent lock missing"))?,
            true,
        )?;
        if identity(parent)? != parent_id {
            return Err(denied("positive-control parent identity changed"));
        }
        let result = probe_rename_directory(fixture.ledger.raw(root), parent, target_name);
        probe_log_nt("probe_control_rename", &result);
        if result.effective != 0 {
            return Err(probe_nt_error(
                "positive-control directory rename",
                result.effective,
            ));
        }
        probe_check_absent(&mut fixture.ledger, parent, parent_id, old_name)?;
        let moved_root = probe_check_named_directory(
            &mut fixture.ledger,
            parent,
            parent_id,
            target_name,
            root_id,
            &security,
        )?;
        if let Some(expected_file) = file_id {
            let expected_acl = fixture
                .stages
                .iter()
                .find(|stage| stage.identity == root_id)
                .and_then(|stage| stage.payload_acl_after.as_ref())
                .ok_or_else(|| invalid("positive-control payload ACL receipt missing"))?;
            let moved_raw = fixture.ledger.raw(moved_root);
            probe_verify_payload(
                &mut fixture.ledger,
                moved_raw,
                root_id,
                OsStr::new("payload"),
                expected_file,
                payload.unwrap(),
                &security,
                false,
                Some(expected_acl),
            )?;
        }
        fixture.ledger.close(moved_root)?;
        fixture.rename_stage(root_id, target_name)?;
        fixture.ledger.close(root)?;
        Ok((root_id, file_id))
    }

    fn probe_verify_foreign(
        fixture: &mut ProbeFixture,
        expected_id: FileIdentity,
        expected_acl: &ProbeAclEvidence,
    ) -> io::Result<()> {
        let security = probe_security_copy(fixture.sec());
        let foreign = fixture.foreign();
        foreign.check()?;
        let foreign_raw = foreign.handle();
        let actual_parent = identity(foreign_raw)?;
        if actual_parent
            != fixture
                .foreign_id
                .ok_or_else(|| invalid("foreign parent ID missing"))?
        {
            return Err(denied("foreign parent native full identity changed"));
        }
        let view = probe_open_bound(
            &mut fixture.ledger,
            foreign_raw,
            actual_parent,
            OsStr::new("canary"),
            false,
            FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            Some(expected_id),
            true,
        )?;
        let actual_acl = probe_check_full(fixture.ledger.raw(view), &security)?;
        if &actual_acl != expected_acl
            || probe_read_payload(fixture.ledger.raw(view), expected_id)?
                != b"untouched foreign canary"
        {
            return Err(denied(
                "foreign canary identity, owner/DACL, or bytes changed",
            ));
        }
        fixture.ledger.close(view)?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProbeClassification {
        SupportedMeasuredCohort,
        IncompatibleMeasuredCohort,
    }

    fn probe_execute(fixture: &mut ProbeFixture) -> io::Result<ProbeClassification> {
        let security = probe_security_copy(fixture.sec());
        let read_only = probe_security_copy(fixture.rsec());
        let state_id = fixture
            .state_id
            .ok_or_else(|| invalid("state full ID missing"))?;
        fixture.state().check()?;
        let state_raw = fixture.state().handle();
        let parent_id = identity(state_raw)?;
        if parent_id != state_id {
            return Err(denied("measured parent native full identity changed"));
        }
        let parent_granted = probe_granted_access(state_raw)?;
        let parent_desired = FILE_ALL_ACCESS & !DELETE;
        if parent_granted != parent_desired || parent_granted & FILE_DELETE_CHILD == 0 {
            return Err(denied(
                "parent handle does not have the measured full private-parent/DELETE_CHILD grant",
            ));
        }
        let lock = fixture
            .lock
            .as_ref()
            .ok_or_else(|| invalid("exclusive transaction lock missing"))?;
        fixture.state().require_lock(lock, true)?;
        let lock_id = lock.identity();
        if lock.file.parent != state_id || identity(lock.file.file.as_raw_handle())? != lock_id {
            return Err(denied(
                "exclusive lock does not belong to the actual measured parent",
            ));
        }
        let lock_granted = probe_granted_access(lock.file.file.as_raw_handle())?;
        if lock_granted != FILE_ALL_ACCESS & !DELETE {
            return Err(denied(
                "exclusive lock actual grant differs from requested private lock mask",
            ));
        }
        let ancestor_ids = fixture.state_chain.clone();
        if ancestor_ids.last() != Some(&state_id)
            || ancestor_ids.iter().any(|id| id.volume != state_id.volume)
        {
            return Err(denied("state parent/ancestor full-ID chain is invalid"));
        }
        probe_recheck_chain(fixture.state(), &ancestor_ids)?;
        println!(
            "probe_parent parent={state_id:?} ancestors={ancestor_ids:?} desired=0x{parent_desired:08x} share=0x{:08x} granted=0x{parent_granted:08x} lock={lock_id:?} lock_granted=0x{lock_granted:08x} lock_mode=Exclusive",
            FILE_SHARE_READ | FILE_SHARE_WRITE
        );

        let foreign_id = fixture
            .foreign_id
            .ok_or_else(|| invalid("foreign parent identity missing"))?;
        fixture.foreign().check()?;
        let foreign_raw = fixture.foreign().handle();
        if identity(foreign_raw)? != foreign_id {
            return Err(denied(
                "foreign guard negative-control parent identity changed",
            ));
        }
        let (canary_id, canary_acl) = probe_create_payload(
            &mut fixture.ledger,
            foreign_raw,
            foreign_id,
            OsStr::new("canary"),
            b"untouched foreign canary",
            &security,
        )?;
        fixture.foreign_canary = Some((canary_id, canary_acl.clone()));
        let wrong_guard = fixture.foreign().require_lock(lock, true);
        if !matches!(wrong_guard, Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(denied(
                "foreign parent accepted the measured parent's exclusive lock",
            ));
        }
        if identity(foreign_raw)? != foreign_id {
            return Err(denied("foreign parent changed during wrong-guard refusal"));
        }
        probe_verify_foreign(fixture, canary_id, &canary_acl)?;

        // Independent positive controls use distinct fresh directories and
        // complete before the retained-child measurement begins.
        let (empty_id, _) = probe_positive_control(
            fixture,
            OsStr::new("empty-old"),
            OsStr::new("empty-new"),
            None,
        )?;
        let (closed_id, closed_file) = probe_positive_control(
            fixture,
            OsStr::new("closed-old"),
            OsStr::new("closed-new"),
            Some(b"probe-v1"),
        )?;
        if empty_id == closed_id || closed_file.is_none() {
            return Err(denied(
                "positive controls did not use fresh empty/populated roots",
            ));
        }

        let retained_name = OsStr::new("retained-old");
        let target_name = OsStr::new("retained-new");
        probe_check_absent(&mut fixture.ledger, state_raw, state_id, retained_name)?;
        probe_check_absent(&mut fixture.ledger, state_raw, state_id, target_name)?;
        let stage_path = fixture.state_path.as_ref().unwrap().join(retained_name);
        let (root, root_id) = probe_create_directory(
            &mut fixture.ledger,
            state_raw,
            state_id,
            retained_name,
            &stage_path,
            &security,
            Some(&mut fixture.stages),
        )?;
        let root_raw = fixture.ledger.raw(root);
        let root_granted = probe_granted_access(root_raw)?;
        let root_desired = DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        let root_share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        println!(
            "probe_measured_root parent={state_id:?} root={root_id:?} desired=0x{root_desired:08x} share=0x{root_share:08x} granted=0x{root_granted:08x}"
        );
        if root_granted != root_desired
            || identity(root_raw)? != root_id
            || probe_check_full(root_raw, &security)?.protected == false
        {
            return Err(denied(
                "measured source root identity, exact grant, or secured DACL check failed",
            ));
        }

        // Explicit captured TokenUser owner on creation; read back owner,
        // full identity, initial full-control DACL, and data before sealing.
        let writer = probe_open(
            &mut fixture.ledger,
            root_raw,
            root_id,
            OsStr::new("payload"),
            false,
            FILE_CREATE,
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security.descriptor.as_ptr().cast(),
        )?;
        let payload_id = identity(fixture.ledger.raw(writer))?;
        if security.check(fixture.ledger.raw(writer)).is_err() {
            return Err(denied(
                "new payload owner/DACL did not read back as captured-user full control",
            ));
        }
        let creation_acl = probe_check_full(fixture.ledger.raw(writer), &security)?;
        if probe_granted_access(fixture.ledger.raw(writer))? != FILE_ALL_ACCESS {
            return Err(denied(
                "temporary writer actual grant differs from requested FILE_ALL_ACCESS",
            ));
        }
        let created_data = fixture
            .stages
            .iter_mut()
            .find(|stage| stage.identity == root_id)
            .ok_or_else(|| invalid("measured stage missing from fixture ledger"))?;
        created_data.payload = Some((OsString::from("payload"), payload_id));
        created_data.payload_acl_before = Some(creation_acl);

        // The mutator explicitly requests FILE_READ_ATTRIBUTES because its
        // real type/reparse oracle uses that right; the minimum keeper does not.
        let mutator_desired = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        let mutator = probe_open_bound(
            &mut fixture.ledger,
            root_raw,
            root_id,
            OsStr::new("payload"),
            false,
            mutator_desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            Some(payload_id),
            true,
        )?;
        let mutator_granted = probe_granted_access(fixture.ledger.raw(mutator))?;
        println!(
            "probe_dacl_mutator file_id={payload_id:?} desired=0x{mutator_desired:08x} share=0x{:08x} granted=0x{mutator_granted:08x} metadata_oracle=FILE_READ_ATTRIBUTES",
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
        if mutator_granted != mutator_desired {
            return Err(denied(
                "DACL mutator actual grant differs from explicit metadata-capable request",
            ));
        }
        let keeper_desired = DELETE | SYNCHRONIZE;
        let keeper = probe_open_bound(
            &mut fixture.ledger,
            root_raw,
            root_id,
            OsStr::new("payload"),
            false,
            keeper_desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            Some(payload_id),
            false,
        )?;
        let keeper_granted = probe_granted_access(fixture.ledger.raw(keeper))?;
        println!(
            "probe_minimum_keeper file_id={payload_id:?} desired=0x{keeper_desired:08x} share=0x{:08x} granted=0x{keeper_granted:08x} identity_query=GetFileInformationByHandleEx(FileIdInfo)-on-same-handle",
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
        if keeper_granted != keeper_desired {
            return Err(denied(
                "minimum keeper grant differs from DELETE|SYNCHRONIZE",
            ));
        }

        let mut written = 0u32;
        if unsafe {
            WriteFile(
                fixture.ledger.raw(writer),
                b"probe-v1".as_ptr(),
                8,
                &mut written,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written != 8 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short measured probe payload write",
            ));
        }
        if unsafe { FlushFileBuffers(fixture.ledger.raw(writer)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        probe_set_dacl(fixture.ledger.raw(mutator), &read_only)?;
        let sealed_acl = probe_check_r(fixture.ledger.raw(mutator), &read_only)?;
        fixture
            .stages
            .iter_mut()
            .find(|stage| stage.identity == root_id)
            .unwrap()
            .payload_acl_after = Some(sealed_acl.clone());
        fixture.ledger.close(writer)?;
        fixture.ledger.close(mutator)?;
        if fixture.ledger.live(writer) || fixture.ledger.live(mutator) {
            return Err(invalid(
                "writer or DACL mutator remains live after checked close",
            ));
        }

        // An independent R view validates kind, full ID, link count, bytes and
        // exact zero-flag ACL, then closes before rename. Its share admits DELETE.
        let view = probe_open_bound(
            &mut fixture.ledger,
            root_raw,
            root_id,
            OsStr::new("payload"),
            false,
            FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            Some(payload_id),
            true,
        )?;
        let view_granted = probe_granted_access(fixture.ledger.raw(view))?;
        let view_desired = FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE;
        if view_granted != view_desired {
            return Err(denied("sealed R-view grant differs from requested access"));
        }
        let view_acl = probe_check_r(fixture.ledger.raw(view), &read_only)?;
        if view_acl != sealed_acl
            || probe_read_payload(fixture.ledger.raw(view), payload_id)? != b"probe-v1"
        {
            return Err(denied(
                "independent sealed payload readback differs from written data or DACL",
            ));
        }
        let standard: FILE_STANDARD_INFO = information(fixture.ledger.raw(view), FileStandardInfo)?;
        if standard.NumberOfLinks != 1 || standard.DeletePending {
            return Err(denied("sealed payload is linked or delete-pending"));
        }
        fixture.ledger.close(view)?;
        if fixture.ledger.live(view) {
            return Err(invalid(
                "sealed read view remained live after checked close",
            ));
        }

        let parent = fixture.state().handle();
        probe_recheck_chain(fixture.state(), &ancestor_ids)?;
        fixture
            .state()
            .require_lock(fixture.lock.as_ref().unwrap(), true)?;
        if identity(parent)? != state_id || identity(root_raw)? != root_id {
            return Err(denied(
                "source or target parent identity changed before native rename",
            ));
        }
        probe_check_absent(&mut fixture.ledger, parent, state_id, target_name)?;
        let retained = probe_rename_directory(root_raw, parent, target_name);
        probe_log_nt("probe_retained_child_rename", &retained);
        let completed_success = retained.effective == 0;
        let compatible_status = retained.effective == PROBE_ACCESS_DENIED
            || retained.effective == PROBE_SHARING_VIOLATION;

        let classification = if completed_success {
            probe_check_absent(&mut fixture.ledger, parent, state_id, retained_name)?;
            let observed_root = probe_check_named_directory(
                &mut fixture.ledger,
                parent,
                state_id,
                target_name,
                root_id,
                &security,
            )?;
            let observed_raw = fixture.ledger.raw(observed_root);
            probe_verify_payload(
                &mut fixture.ledger,
                observed_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            fixture.ledger.close(observed_root)?;
            probe_verify_payload(
                &mut fixture.ledger,
                root_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            fixture.rename_stage(root_id, target_name)?;
            ProbeClassification::SupportedMeasuredCohort
        } else {
            // The same original and exact target must remain unchanged/absent;
            // after closing the keeper, retry the same target on this root.
            let old_root = probe_check_named_directory(
                &mut fixture.ledger,
                parent,
                state_id,
                retained_name,
                root_id,
                &security,
            )?;
            let old_raw = fixture.ledger.raw(old_root);
            probe_check_absent(&mut fixture.ledger, parent, state_id, target_name)?;
            probe_verify_payload(
                &mut fixture.ledger,
                old_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            fixture.ledger.close(old_root)?;
            probe_verify_payload(
                &mut fixture.ledger,
                root_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            if fixture.ledger.live(writer)
                || fixture.ledger.live(mutator)
                || fixture.ledger.live(view)
            {
                return Err(invalid(
                    "writer, DACL mutator, or read view remained live at retained-child failure",
                ));
            }
            fixture.ledger.close(keeper)?;
            if fixture.ledger.live(keeper) {
                return Err(invalid("minimum keeper remained live after checked close"));
            }
            probe_check_absent(&mut fixture.ledger, parent, state_id, target_name)?;
            let retry = probe_rename_directory(root_raw, parent, target_name);
            probe_log_nt("probe_same_target_closed_child_retry", &retry);
            if retry.effective != 0 {
                return Err(probe_nt_error(
                    "same-target closed-child retry",
                    retry.effective,
                ));
            }
            probe_check_absent(&mut fixture.ledger, parent, state_id, retained_name)?;
            let moved_root = probe_check_named_directory(
                &mut fixture.ledger,
                parent,
                state_id,
                target_name,
                root_id,
                &security,
            )?;
            let moved_raw = fixture.ledger.raw(moved_root);
            probe_verify_payload(
                &mut fixture.ledger,
                moved_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            fixture.ledger.close(moved_root)?;
            probe_verify_payload(
                &mut fixture.ledger,
                root_raw,
                root_id,
                OsStr::new("payload"),
                payload_id,
                b"probe-v1",
                &read_only,
                true,
                Some(&sealed_acl),
            )?;
            fixture.rename_stage(root_id, target_name)?;
            if compatible_status {
                ProbeClassification::IncompatibleMeasuredCohort
            } else {
                return Err(probe_nt_error(
                    "retained-child rename unclassified despite successful same-target closed-child retry",
                    retained.effective,
                ));
            }
        };

        if fixture.ledger.live(keeper) {
            fixture.ledger.close(keeper)?;
        }
        if fixture.ledger.live(root) {
            fixture.ledger.close(root)?;
        }
        probe_verify_foreign(fixture, canary_id, &canary_acl)?;
        println!(
            "probe_classification={classification:?} measured_parent={state_id:?} ancestors={ancestor_ids:?} root={root_id:?} payload={payload_id:?} target={target_name:?} retained_effective=0x{:08x} same_target_retry={}",
            retained.effective as u32, !completed_success
        );
        Ok(classification)
    }

    #[test]
    fn staged_directory_child_keeper_rename_prerequisite() {
        let mut fixture = ProbeFixture::empty();
        let result = (|| -> io::Result<ProbeClassification> {
            fixture.initialize()?;
            let classification = probe_execute(&mut fixture)?;
            fixture.finish_success()?;
            Ok(classification)
        })();
        match result {
            Ok(classification) => println!("probe_test_result={classification:?}"),
            Err(primary) => {
                let cleanup_errors = fixture.preserve_failure();
                if cleanup_errors.is_empty() {
                    panic!(
                        "native capability measurement/setup failed: {primary}; fixture was preserved"
                    );
                }
                panic!(
                    "native capability measurement/setup failed: {primary}; explicit owner-close errors={cleanup_errors:?}; fixture was preserved"
                );
            }
        }
    }

    const PROBE_DC_DELETE_ACCESS: u32 = DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    const PROBE_DC_NO_CHILD_DELETE: u32 = FILE_ALL_ACCESS & !FILE_DELETE_CHILD;

    // Evidence only: all native owners remain in ProbeLedger. These bounded
    // records never authorize recovery after an uncertain outcome.
    #[derive(Clone, Debug)]
    struct ProbeDcEntry {
        parent: FileIdentity,
        name: OsString,
        attempted_name: Option<OsString>,
        identity: Option<FileIdentity>,
        mask: u32,
        bytes: Vec<u8>,
        creation_acl: Option<ProbeAclEvidence>,
        acl: Option<ProbeAclEvidence>,
        negative_keeper: Option<ProbeHandle>,
        removed: bool,
    }
    #[derive(Debug)]
    struct ProbeDcNegative {
        name: OsString,
        identity: Option<FileIdentity>,
        handle: Option<ProbeHandle>,
        acl: Option<ProbeAclEvidence>,
        removed: bool,
    }
    #[derive(Debug, Default)]
    struct ProbeDcEvidence {
        entries: Vec<ProbeDcEntry>,
        positive_parents: Vec<(FileIdentity, ProbeHandle)>,
        negative: Option<ProbeDcNegative>,
        seal_calls: usize,
        root_rename_calls: usize,
        file_rename_calls: usize,
        disposition_calls: usize,
        native_denials: usize,
        identity_refusals: usize,
        parent_refusals: usize,
    }

    fn probe_dc_security(security: &Security, mask: u32) -> io::Result<Security> {
        if ![
            FILE_GENERIC_READ,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            PROBE_DC_NO_CHILD_DELETE,
        ]
        .contains(&mask)
        {
            return Err(invalid("unsupported delete-child probe policy"));
        }
        let mut text = null_mut();
        unsafe {
            ok(ConvertSidToStringSidW(
                security.sid.as_ptr().cast_mut().cast(),
                &mut text,
            ))?;
        }
        let allocation = LocalAllocation(text.cast());
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let owner = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| invalid("delete-child probe owner encoding"))?;
        drop(allocation);
        let sddl = wide(OsStr::new(&format!(
            "O:{owner}D:P(A;;0x{mask:08x};;;{owner})"
        )));
        let mut raw = null_mut();
        let mut returned = 0;
        unsafe {
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                &mut returned,
            ))?;
        }
        let allocation = LocalAllocation(raw);
        let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
        if length == 0 || returned as usize != length {
            return Err(invalid("delete-child descriptor size mismatch"));
        }
        let mut descriptor = vec![0usize; length.div_ceil(size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(raw.cast::<u8>(), descriptor.as_mut_ptr().cast(), length);
        }
        drop(allocation);
        Ok(Security {
            sid: security.sid.clone(),
            descriptor,
        })
    }

    fn probe_dc_policy(
        handle: HANDLE,
        security: &Security,
        mask: u32,
    ) -> io::Result<ProbeAclEvidence> {
        let acl = probe_acl_evidence(handle, security)?;
        if !acl.protected
            || acl.ace_flags != 0
            || acl.ace_mask != mask
            || acl.ace_sid != acl.owner_sid
        {
            return Err(denied(
                "delete-child probe policy differs from exact protected owner-only mask",
            ));
        }
        Ok(acl)
    }

    fn probe_dc_verify(
        fixture: &mut ProbeFixture,
        parent: HANDLE,
        entry: &ProbeDcEntry,
    ) -> io::Result<()> {
        if identity(parent)? != entry.parent {
            return Err(denied("delete-child observation parent changed"));
        }
        let expected = entry
            .identity
            .ok_or_else(|| invalid("delete-child entry identity unknown"))?;
        let security = probe_security_copy(fixture.sec());
        let view = probe_open_bound(
            &mut fixture.ledger,
            parent,
            entry.parent,
            &entry.name,
            false,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            null(),
            Some(expected),
            true,
        )?;
        let raw = fixture.ledger.raw(view);
        let granted = probe_granted_access(raw)?;
        if granted != FILE_GENERIC_READ {
            return Err(denied("delete-child read-view grant differs"));
        }
        let acl = probe_dc_policy(raw, &security, entry.mask)?;
        if entry.acl.as_ref() != Some(&acl) || probe_read_payload(raw, expected)? != entry.bytes {
            return Err(denied("delete-child entry policy or bytes changed"));
        }
        println!(
            "probe_dc_read parent={:?} name={:?} id={expected:?} mask=0x{:08x} granted=0x{granted:08x} owner_dacl={acl:?} bytes={:?}",
            entry.parent, entry.name, entry.mask, entry.bytes
        );
        fixture.ledger.close(view)
    }

    fn probe_dc_seal(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        mask: u32,
        bytes: &[u8],
        negative_keeper: bool,
    ) -> io::Result<usize> {
        if evidence.entries.len() >= 8 {
            return Err(invalid("delete-child entry bound exceeded"));
        }
        let security = probe_security_copy(fixture.sec());
        let policy = probe_dc_security(&security, mask)?;
        let index = evidence.entries.len();
        evidence.entries.push(ProbeDcEntry {
            parent: parent_id,
            name: name.to_os_string(),
            attempted_name: None,
            identity: None,
            mask,
            bytes: bytes.to_vec(),
            creation_acl: None,
            acl: None,
            negative_keeper: None,
            removed: false,
        });
        let writer = probe_open(
            &mut fixture.ledger,
            parent,
            parent_id,
            name,
            false,
            FILE_CREATE,
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security.descriptor.as_ptr().cast(),
        )?;
        let raw = fixture.ledger.raw(writer);
        let file_id = identity(raw)?;
        evidence.entries[index].identity = Some(file_id);
        ensure_kind(raw, false)?;
        evidence.entries[index].creation_acl = Some(probe_check_full(raw, &security)?);
        if probe_granted_access(raw)? != FILE_ALL_ACCESS {
            return Err(denied("delete-child creation writer grant differs"));
        }
        if negative_keeper {
            let keeper = probe_open_bound(
                &mut fixture.ledger,
                parent,
                parent_id,
                name,
                false,
                DELETE | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                Some(file_id),
                false,
            )?;
            evidence.entries[index].negative_keeper = Some(keeper);
            let granted = probe_granted_access(fixture.ledger.raw(keeper))?;
            if granted != DELETE | SYNCHRONIZE {
                return Err(denied("negative cleanup keeper is not minimal"));
            }
            println!(
                "probe_dc_negative_keeper id={file_id:?} desired=0x{:08x} granted=0x{granted:08x} cleanup_only=true",
                DELETE | SYNCHRONIZE
            );
        }
        let mut written = 0;
        if unsafe {
            WriteFile(
                raw,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short delete-child fixture write",
            ));
        }
        if unsafe { FlushFileBuffers(raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        evidence.seal_calls += 1;
        probe_set_dacl(raw, &policy)?;
        let acl = probe_dc_policy(raw, &security, mask)?;
        evidence.entries[index].acl = Some(acl.clone());
        println!(
            "probe_dc_seal id={file_id:?} mask=0x{mask:08x} owner_dacl={acl:?} native_set_dacl=completed role=initial_seal"
        );
        fixture.ledger.close(writer)?;
        if fixture.ledger.live(writer) {
            return Err(invalid("delete-child writer remained live"));
        }
        probe_dc_verify(fixture, parent, &evidence.entries[index])?;
        Ok(index)
    }

    fn probe_dc_children_closed(
        ledger: &ProbeLedger,
        entries: &[ProbeDcEntry],
        parent: FileIdentity,
    ) -> io::Result<()> {
        for handle in ledger.handles.iter().flatten() {
            let observed = identity(handle.as_raw_handle())?;
            if entries.iter().any(|entry| {
                entry.parent == parent && !entry.removed && entry.identity == Some(observed)
            }) {
                return Err(denied(
                    "a descendant native owner remains before directory publication",
                ));
            }
        }
        println!("probe_dc_descendants parent={parent:?} all_owned_child_handles_closed=true");
        Ok(())
    }

    fn probe_dc_reacquire(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        parent: HANDLE,
        entry: &ProbeDcEntry,
        expected: FileIdentity,
    ) -> io::Result<ProbeHandle> {
        fixture.state().require_lock(
            fixture
                .lock
                .as_ref()
                .ok_or_else(|| invalid("delete-child publication guard missing"))?,
            true,
        )?;
        if identity(parent)? != entry.parent {
            evidence.parent_refusals += 1;
            println!(
                "probe_dc_guard expected_parent={:?} refused=true disposition_executed=false",
                entry.parent
            );
            return Err(denied("delete-child parent full identity differs"));
        }
        let parent_granted = probe_granted_access(parent)?;
        if parent_granted & FILE_DELETE_CHILD == 0 {
            return Err(denied("positive parent lacks actual DELETE_CHILD grant"));
        }
        let handle = probe_open_bound(
            &mut fixture.ledger,
            parent,
            entry.parent,
            &entry.name,
            false,
            PROBE_DC_DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            None,
            true,
        )?;
        let raw = fixture.ledger.raw(handle);
        let actual = identity(raw)?;
        let granted = probe_granted_access(raw)?;
        println!(
            "probe_dc_reacquire parent={:?} parent_granted=0x{parent_granted:08x} name={:?} expected={expected:?} actual={actual:?} desired=0x{PROBE_DC_DELETE_ACCESS:08x} share=0x{:08x} granted=0x{granted:08x} disposition_executed=false",
            entry.parent,
            entry.name,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
        if granted != PROBE_DC_DELETE_ACCESS {
            return Err(denied(
                "fresh delete-child grant differs from exact request",
            ));
        }
        if actual != expected {
            fixture.ledger.close(handle)?;
            evidence.identity_refusals += 1;
            println!(
                "probe_dc_identity_refusal actual={actual:?} expected={expected:?} disposition_executed=false checked_close=true"
            );
            return Err(denied(
                "fresh delete-child handle is a different full identity",
            ));
        }
        let security = probe_security_copy(fixture.sec());
        if entry.acl.as_ref() != Some(&probe_dc_policy(raw, &security, entry.mask)?) {
            return Err(denied("fresh delete-child handle changed policy"));
        }
        probe_dc_verify(fixture, parent, entry)?;
        Ok(handle)
    }

    fn probe_dc_remove(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        parent: HANDLE,
        index: usize,
    ) -> io::Result<()> {
        let entry = evidence.entries[index].clone();
        if entry.removed {
            return Err(invalid("delete-child entry already removed"));
        }
        let expected = entry
            .identity
            .ok_or_else(|| invalid("removal identity unknown"))?;
        let handle = if let Some(keeper) = entry.negative_keeper {
            probe_dc_verify(fixture, parent, &entry)?;
            if identity(fixture.ledger.raw(keeper))? != expected
                || probe_granted_access(fixture.ledger.raw(keeper))? != DELETE | SYNCHRONIZE
            {
                return Err(denied("negative cleanup keeper identity or grant changed"));
            }
            keeper
        } else {
            probe_dc_reacquire(fixture, evidence, parent, &entry, expected)?
        };
        evidence.disposition_calls += 1;
        println!(
            "probe_dc_disposition parent={:?} name={:?} id={expected:?} disposition_executed=true negative_keeper={}",
            entry.parent,
            entry.name,
            entry.negative_keeper.is_some()
        );
        probe_disposition(fixture.ledger.raw(handle))?;
        fixture.ledger.close(handle)?;
        probe_check_absent(&mut fixture.ledger, parent, entry.parent, &entry.name)?;
        evidence.entries[index].removed = true;
        fixture.removed.push(format!(
            "delete-child-payload:{:?}:{expected:?}",
            entry.name
        ));
        println!("probe_dc_removed id={expected:?} absence_verified=true policy_rewritten=false");
        Ok(())
    }

    fn probe_dc_positive(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        old: &OsStr,
        new: &OsStr,
        mask: u32,
    ) -> io::Result<usize> {
        let state = fixture.state().handle();
        let state_id = fixture.state().identity();
        let security = probe_security_copy(fixture.sec());
        let path = fixture
            .state_path
            .as_ref()
            .ok_or_else(|| invalid("positive state path missing"))?
            .join(old);
        probe_check_absent(&mut fixture.ledger, state, state_id, new)?;
        let (rename, root_id) = probe_create_directory(
            &mut fixture.ledger,
            state,
            state_id,
            old,
            &path,
            &security,
            Some(&mut fixture.stages),
        )?;
        let root_acl = probe_check_full(fixture.ledger.raw(rename), &security)?;
        let parent = probe_open_bound(
            &mut fixture.ledger,
            state,
            state_id,
            old,
            true,
            FILE_ALL_ACCESS & !DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            Some(root_id),
            true,
        )?;
        evidence.positive_parents.push((root_id, parent));
        let parent_raw = fixture.ledger.raw(parent);
        let granted = probe_granted_access(parent_raw)?;
        if granted != FILE_ALL_ACCESS & !DELETE || granted & FILE_DELETE_CHILD == 0 {
            return Err(denied("positive root DC grant mismatch"));
        }
        println!(
            "probe_dc_positive_parent id={root_id:?} desired=0x{:08x} share=0x{:08x} granted=0x{granted:08x} acl={root_acl:?}",
            FILE_ALL_ACCESS & !DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        );
        let index = probe_dc_seal(
            fixture,
            evidence,
            parent_raw,
            root_id,
            OsStr::new("payload"),
            mask,
            b"closed-descendant-original",
            false,
        )?;
        let sealed = &evidence.entries[index];
        let stage = fixture
            .stages
            .iter_mut()
            .find(|stage| stage.identity == root_id)
            .ok_or_else(|| invalid("sealed positive stage missing"))?;
        stage.payload = Some((
            sealed.name.clone(),
            sealed
                .identity
                .ok_or_else(|| invalid("sealed positive identity missing"))?,
        ));
        stage.payload_acl_before = sealed.creation_acl.clone();
        stage.payload_acl_after = sealed.acl.clone();
        probe_dc_children_closed(&fixture.ledger, &evidence.entries, root_id)?;
        probe_recheck_chain(fixture.state(), &fixture.state_chain)?;
        fixture
            .state()
            .require_lock(fixture.lock.as_ref().unwrap(), true)?;
        if identity(state)? != state_id || identity(fixture.ledger.raw(rename))? != root_id {
            return Err(denied("positive publication anchors changed"));
        }
        probe_check_absent(&mut fixture.ledger, state, state_id, new)?;
        evidence.root_rename_calls += 1;
        println!(
            "probe_dc_root_rename old={old:?} target={new:?} root={root_id:?} mask=0x{mask:08x} descendants_closed=true"
        );
        let native = probe_rename_directory(fixture.ledger.raw(rename), state, new);
        probe_log_nt("probe_dc_root_rename_result", &native);
        if native.effective != 0 {
            return Err(probe_nt_error(
                "closed-descendant root rename",
                native.effective,
            ));
        }
        probe_check_absent(&mut fixture.ledger, state, state_id, old)?;
        let observed = probe_check_named_directory(
            &mut fixture.ledger,
            state,
            state_id,
            new,
            root_id,
            &security,
        )?;
        if probe_check_full(fixture.ledger.raw(observed), &security)? != root_acl
            || identity(parent_raw)? != root_id
        {
            return Err(denied("published root identity or policy changed"));
        }
        fixture.ledger.close(observed)?;
        fixture.rename_stage(root_id, new)?;
        probe_dc_verify(fixture, parent_raw, &evidence.entries[index])?;
        let entry = evidence.entries[index].clone();
        let acquired = probe_dc_reacquire(
            fixture,
            evidence,
            parent_raw,
            &entry,
            entry.identity.unwrap(),
        )?;
        fixture.ledger.close(acquired)?;
        fixture.ledger.close(rename)?;
        Ok(index)
    }

    fn probe_dc_expect_denial(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        parent: HANDLE,
        parent_id: FileIdentity,
        name: &OsStr,
        directory: bool,
        desired: u32,
        label: &str,
    ) -> io::Result<()> {
        match probe_open(
            &mut fixture.ledger,
            parent,
            parent_id,
            name,
            directory,
            FILE_OPEN,
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
        ) {
            Ok(handle) => {
                let granted = probe_granted_access(fixture.ledger.raw(handle))?;
                fixture.ledger.close(handle)?;
                println!(
                    "probe_dc_denial label={label} unexpected_grant=0x{granted:08x} disposition_executed=false"
                );
                Err(denied("negative control unexpectedly granted access"))
            }
            Err(error) => {
                let native = error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<ProbeNativeError>());
                println!(
                    "probe_dc_denial label={label} desired=0x{desired:08x} native={native:?} disposition_executed=false"
                );
                if native.is_some_and(|status| {
                    status.operation == "NtCreateFile" && status.status == PROBE_ACCESS_DENIED
                }) {
                    evidence.native_denials += 1;
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    fn probe_dc_negative(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
    ) -> io::Result<()> {
        let state = fixture.state().handle();
        let state_id = fixture.state().identity();
        let security = probe_security_copy(fixture.sec());
        let policy = probe_dc_security(&security, PROBE_DC_NO_CHILD_DELETE)?;
        let name = OsStr::new("no-delete-child");
        evidence.negative = Some(ProbeDcNegative {
            name: name.to_os_string(),
            identity: None,
            handle: None,
            acl: None,
            removed: false,
        });
        println!(
            "probe_dc_negative_reserved name={:?} policy=0x{PROBE_DC_NO_CHILD_DELETE:08x} non_authorizing=true",
            evidence.negative.as_ref().unwrap().name
        );
        let creator = probe_open(
            &mut fixture.ledger,
            state,
            state_id,
            name,
            true,
            FILE_CREATE,
            PROBE_DC_NO_CHILD_DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            policy.descriptor.as_ptr().cast(),
        )?;
        evidence.negative.as_mut().unwrap().handle = Some(creator);
        let root_id = identity(fixture.ledger.raw(creator))?;
        evidence.negative.as_mut().unwrap().identity = Some(root_id);
        ensure_kind(fixture.ledger.raw(creator), true)?;
        if probe_granted_access(fixture.ledger.raw(creator))? != PROBE_DC_NO_CHILD_DELETE {
            return Err(denied("negative creator grant differs"));
        }
        let acl = probe_dc_policy(
            fixture.ledger.raw(creator),
            &security,
            PROBE_DC_NO_CHILD_DELETE,
        )?;
        evidence.negative.as_mut().unwrap().acl = Some(acl.clone());
        let r = probe_dc_seal(
            fixture,
            evidence,
            fixture.ledger.raw(creator),
            root_id,
            OsStr::new("read-only"),
            FILE_GENERIC_READ,
            b"negative R",
            true,
        )?;
        let rx = probe_dc_seal(
            fixture,
            evidence,
            fixture.ledger.raw(creator),
            root_id,
            OsStr::new("read-execute"),
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            b"negative RX",
            true,
        )?;
        fixture.ledger.close(creator)?;
        let parent = probe_open_bound(
            &mut fixture.ledger,
            state,
            state_id,
            name,
            true,
            PROBE_DC_NO_CHILD_DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            Some(root_id),
            true,
        )?;
        evidence.negative.as_mut().unwrap().handle = Some(parent);
        let raw = fixture.ledger.raw(parent);
        let granted = probe_granted_access(raw)?;
        if granted != PROBE_DC_NO_CHILD_DELETE
            || granted & FILE_DELETE_CHILD != 0
            || probe_dc_policy(raw, &security, PROBE_DC_NO_CHILD_DELETE)? != acl
        {
            return Err(denied(
                "negative fresh parent policy or actual grant differs",
            ));
        }
        println!(
            "probe_dc_negative_parent id={root_id:?} desired=0x{PROBE_DC_NO_CHILD_DELETE:08x} granted=0x{granted:08x} acl={acl:?} no_broader_parent_handle=true"
        );
        probe_dc_expect_denial(
            fixture,
            evidence,
            state,
            state_id,
            name,
            true,
            FILE_DELETE_CHILD | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            "parent-explicit-DELETE_CHILD",
        )?;
        for index in [r, rx] {
            let entry = evidence.entries[index].clone();
            probe_dc_verify(fixture, raw, &entry)?;
            probe_dc_expect_denial(
                fixture,
                evidence,
                raw,
                root_id,
                &entry.name,
                false,
                PROBE_DC_DELETE_ACCESS,
                "child-fresh-DELETE",
            )?;
            probe_dc_verify(fixture, raw, &entry)?;
        }
        if probe_dc_policy(raw, &security, PROBE_DC_NO_CHILD_DELETE)? != acl {
            return Err(denied(
                "negative parent DACL changed during denial controls",
            ));
        }
        // Only preseal keepers remove negative children; no parent rename or ACL rewrite.
        for index in [r, rx] {
            probe_dc_remove(fixture, evidence, raw, index)?;
        }
        if !directory_entries(
            raw,
            EnumerationLimits {
                max_entries: 8,
                max_name_bytes: 8192,
            },
        )?
        .is_empty()
        {
            return Err(denied("negative parent remains nonempty"));
        }
        ensure_kind(raw, true)?;
        if identity(raw)? != root_id
            || probe_dc_policy(raw, &security, PROBE_DC_NO_CHILD_DELETE)? != acl
        {
            return Err(denied("negative root changed before disposition"));
        }
        evidence.disposition_calls += 1;
        println!(
            "probe_dc_negative_root_disposition id={root_id:?} disposition_executed=true policy_rewritten=false"
        );
        probe_disposition(raw)?;
        fixture.ledger.close(parent)?;
        probe_check_absent(&mut fixture.ledger, state, state_id, name)?;
        evidence.negative.as_mut().unwrap().removed = true;
        fixture
            .removed
            .push(format!("delete-child-negative-root:{root_id:?}"));
        Ok(())
    }

    fn probe_dc_replacement(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
        index: usize,
    ) -> io::Result<()> {
        let original = evidence.entries[index].clone();
        let parent = evidence
            .positive_parents
            .iter()
            .find(|(id, _)| *id == original.parent)
            .ok_or_else(|| invalid("replacement parent missing"))?
            .1;
        let raw = fixture.ledger.raw(parent);
        let saved = OsStr::new("saved-original");
        probe_check_absent(&mut fixture.ledger, raw, original.parent, saved)?;
        let handle = probe_dc_reacquire(
            fixture,
            evidence,
            raw,
            &original,
            original.identity.unwrap(),
        )?;
        evidence.entries[index].attempted_name = Some(saved.to_os_string());
        evidence.file_rename_calls += 1;
        let native = probe_rename_directory(fixture.ledger.raw(handle), raw, saved);
        probe_log_nt("probe_dc_original_to_saved", &native);
        if native.effective != 0 {
            return Err(probe_nt_error(
                "delete-child original saved rename",
                native.effective,
            ));
        }
        fixture.ledger.close(handle)?;
        probe_check_absent(&mut fixture.ledger, raw, original.parent, &original.name)?;
        let mut saved_entry = original.clone();
        saved_entry.name = saved.to_os_string();
        probe_dc_verify(fixture, raw, &saved_entry)?;
        evidence.entries[index].name = saved.to_os_string();
        evidence.entries[index].attempted_name = None;
        fixture
            .stages
            .iter_mut()
            .find(|stage| stage.identity == original.parent)
            .ok_or_else(|| invalid("saved original stage missing"))?
            .payload = Some((saved.to_os_string(), original.identity.unwrap()));
        let replacement = probe_dc_seal(
            fixture,
            evidence,
            raw,
            original.parent,
            &original.name,
            original.mask,
            b"different canonical replacement",
            false,
        )?;
        let fresh = evidence.entries[replacement].clone();
        if fresh.identity == original.identity {
            return Err(denied("replacement did not receive a different full ID"));
        }
        let before = evidence.disposition_calls;
        let refusals = evidence.identity_refusals;
        match probe_dc_reacquire(fixture, evidence, raw, &fresh, original.identity.unwrap()) {
            Ok(handle) => {
                fixture.ledger.close(handle)?;
                return Err(denied("replacement accepted original expected identity"));
            }
            Err(error)
                if evidence.identity_refusals == refusals + 1
                    && evidence.disposition_calls == before =>
            {
                println!(
                    "probe_dc_replacement_refused original={:?} replacement={:?} reason={error} disposition_calls_before={before} disposition_calls_after={}",
                    original.identity, fresh.identity, evidence.disposition_calls
                );
            }
            Err(error) => return Err(error),
        }
        probe_dc_verify(fixture, raw, &evidence.entries[index])?;
        probe_dc_verify(fixture, raw, &fresh)?;
        Ok(())
    }

    fn probe_dc_execute(
        fixture: &mut ProbeFixture,
        evidence: &mut ProbeDcEvidence,
    ) -> io::Result<()> {
        let state_id = fixture.state().identity();
        probe_recheck_chain(fixture.state(), &fixture.state_chain)?;
        fixture
            .state()
            .require_lock(fixture.lock.as_ref().unwrap(), true)?;
        if identity(fixture.state().handle())? != state_id {
            return Err(denied("delete-child actual state ID changed"));
        }
        let security = probe_security_copy(fixture.sec());
        let foreign = fixture.foreign().handle();
        let foreign_id = identity(foreign)?;
        let (canary, acl) = probe_create_payload(
            &mut fixture.ledger,
            foreign,
            foreign_id,
            OsStr::new("canary"),
            b"untouched foreign canary",
            &security,
        )?;
        fixture.foreign_canary = Some((canary, acl.clone()));
        if !matches!(fixture.foreign().require_lock(fixture.lock.as_ref().unwrap(), true), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(denied("foreign parent accepted publication-parent guard"));
        }
        probe_verify_foreign(fixture, canary, &acl)?;
        let r = probe_dc_positive(
            fixture,
            evidence,
            OsStr::new("dc-r-old"),
            OsStr::new("dc-r-published"),
            FILE_GENERIC_READ,
        )?;
        let rx = probe_dc_positive(
            fixture,
            evidence,
            OsStr::new("dc-rx-old"),
            OsStr::new("dc-rx-published"),
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        )?;
        if evidence.entries[r].parent == evidence.entries[rx].parent {
            return Err(denied("R and RX did not use separate roots"));
        }
        let entry = evidence.entries[r].clone();
        let before = evidence.disposition_calls;
        let refusals = evidence.parent_refusals;
        match probe_dc_reacquire(fixture, evidence, foreign, &entry, entry.identity.unwrap()) {
            Ok(handle) => {
                fixture.ledger.close(handle)?;
                return Err(denied("foreign parent admitted a mismatched child domain"));
            }
            Err(error)
                if evidence.parent_refusals == refusals + 1
                    && evidence.disposition_calls == before =>
            {
                println!("probe_dc_foreign_refusal reason={error} disposition_executed=false");
            }
            Err(error) => return Err(error),
        }
        probe_verify_foreign(fixture, canary, &acl)?;
        probe_dc_negative(fixture, evidence)?;
        probe_dc_replacement(fixture, evidence, r)?;
        for index in 0..evidence.entries.len() {
            if evidence.entries[index].removed {
                continue;
            }
            let parent_id = evidence.entries[index].parent;
            let parent = evidence
                .positive_parents
                .iter()
                .find(|(id, _)| *id == parent_id)
                .ok_or_else(|| invalid("cleanup DC parent missing"))?
                .1;
            probe_dc_remove(fixture, evidence, fixture.ledger.raw(parent), index)?;
        }
        for (root_id, parent) in evidence.positive_parents.clone() {
            if !directory_entries(
                fixture.ledger.raw(parent),
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 8192,
                },
            )?
            .is_empty()
                || evidence
                    .entries
                    .iter()
                    .any(|entry| entry.parent == root_id && !entry.removed)
            {
                return Err(denied(
                    "positive root not proved empty before ordinary fixture cleanup",
                ));
            }
            fixture
                .stages
                .iter_mut()
                .find(|stage| stage.identity == root_id)
                .ok_or_else(|| invalid("positive stage missing"))?
                .payload = None;
        }
        if evidence.native_denials != 3
            || evidence.identity_refusals != 1
            || evidence.parent_refusals != 1
            || evidence.root_rename_calls != 2
            || evidence.file_rename_calls != 1
            || evidence.seal_calls != 5
            || evidence.disposition_calls != 6
            || evidence.entries.iter().any(|entry| !entry.removed)
            || !evidence
                .negative
                .as_ref()
                .is_some_and(|negative| negative.removed)
        {
            return Err(invalid(
                "delete-child probe evidence/counter reconciliation failed",
            ));
        }
        probe_verify_foreign(fixture, canary, &acl)?;
        println!(
            "probe_dc_measurements_complete R_RX=true native_denials={} identity_refusals={} parent_refusals={} root_renames={} file_renames={} initial_seals={} experiment_dispositions={} cleanup_acl_rewrites=0 all_payload_absences_verified=true",
            evidence.native_denials,
            evidence.identity_refusals,
            evidence.parent_refusals,
            evidence.root_rename_calls,
            evidence.file_rename_calls,
            evidence.seal_calls,
            evidence.disposition_calls
        );
        Ok(())
    }

    mod live_view_control {
        use super::*;
        const STAGE: &str = "live-view-stage";
        const FINAL: &str = "live-view-final";
        const PAYLOAD: &[u8] = b"live-view-genuine-owned-payload";
        const ROOT_READ: u32 =
            READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
        const RWD: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        #[derive(Clone, Debug, Eq, PartialEq)]
        struct SdImage {
            owner: Vec<u8>,
            group: Vec<u8>,
            control: u16,
            dacl: Vec<u8>,
        }
        fn sid_image(sid: PSID, base: *const u8, bytes: usize) -> io::Result<Vec<u8>> {
            let offset = (sid as usize)
                .checked_sub(base as usize)
                .ok_or_else(|| invalid("live-view SID outside descriptor"))?;
            if sid.is_null()
                || sid as usize % 4 != 0
                || offset.checked_add(8).is_none_or(|end| end > bytes)
            {
                return Err(invalid("live-view SID header bounds invalid"));
            }
            let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
            let length = 8 + count * 4;
            if count > 15
                || offset.checked_add(length).is_none_or(|end| end > bytes)
                || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != length
            {
                return Err(invalid("live-view SID extent invalid"));
            }
            Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
        }
        fn sd_image(raw: HANDLE) -> io::Result<SdImage> {
            let mut owner = null_mut();
            let mut group = null_mut();
            let mut dacl = null_mut();
            let mut sd = null_mut();
            let status = unsafe {
                GetSecurityInfo(
                    raw,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    &mut group,
                    &mut dacl,
                    null_mut(),
                    &mut sd,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let _allocation = LocalAllocation(sd);
            if sd.is_null() || unsafe { IsValidSecurityDescriptor(sd) } == 0 {
                return Err(invalid("live-view descriptor invalid"));
            }
            let bytes = unsafe { GetSecurityDescriptorLength(sd) } as usize;
            if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=65536).contains(&bytes) {
                return Err(invalid("live-view descriptor bounds invalid"));
            }
            let owner = sid_image(owner, sd.cast(), bytes)?;
            let group = sid_image(group, sd.cast(), bytes)?;
            let mut control = 0;
            let mut revision = 0;
            unsafe {
                ok(GetSecurityDescriptorControl(
                    sd,
                    &mut control,
                    &mut revision,
                ))?;
            }
            let offset = (dacl as usize)
                .checked_sub(sd as usize)
                .ok_or_else(|| invalid("live-view ACL outside descriptor"))?;
            if dacl.is_null()
                || dacl as usize % 4 != 0
                || offset
                    .checked_add(size_of::<ACL>())
                    .is_none_or(|end| end > bytes)
                || control & SE_SELF_RELATIVE == 0
            {
                return Err(invalid("live-view ACL header invalid"));
            }
            let length = unsafe { (*dacl).AclSize } as usize;
            if length < size_of::<ACL>()
                || offset.checked_add(length).is_none_or(|end| end > bytes)
                || unsafe { IsValidAcl(dacl) } == 0
            {
                return Err(invalid("live-view ACL extent invalid"));
            }
            Ok(SdImage {
                owner,
                group,
                control,
                dacl: unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), length) }.to_vec(),
            })
        }
        fn chain_images(directory: &Directory) -> io::Result<Vec<SdImage>> {
            directory
                .chain
                .iter()
                .map(|h| sd_image(h.as_raw_handle()))
                .collect()
        }
        enum Error {
            Fixture(io::Error),
            Create(StageCreateError),
            Publish(StagePublishError),
            Removal(StageRemovalError),
            UnexpectedPublication(PackagePublication),
            UnexpectedRemoval(StageRemoval),
        }
        impl From<io::Error> for Error {
            fn from(error: io::Error) -> Self {
                Self::Fixture(error)
            }
        }
        impl std::fmt::Debug for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Fixture(e) => f.debug_tuple("Fixture").field(e).finish(),
                    Self::Create(e) => f.debug_tuple("Create").field(e).finish(),
                    Self::Publish(e) => f.debug_tuple("Publish").field(e).finish(),
                    Self::Removal(e) => f.debug_tuple("Removal").field(e).finish(),
                    Self::UnexpectedPublication(p) => f
                        .debug_tuple("UnexpectedPublicationRetained")
                        .field(&p.identity())
                        .finish(),
                    Self::UnexpectedRemoval(r) => {
                        let _ = r;
                        f.write_str("UnexpectedRemovalReceiptRetained")
                    }
                }
            }
        }
        struct Fixture {
            base: ProbeFixture,
            guard: Option<Arc<StateLock>>,
            stage: Option<StagedDirectory>,
            view: Option<staged_package::TestLiveView>,
            receipt: Option<StageRemoval>,
            root: Option<FileIdentity>,
            file: Option<FileIdentity>,
            snapshot: Option<SourceSnapshot>,
            root_sd: Option<SdImage>,
            file_sd: Option<SdImage>,
            state_sd: Vec<SdImage>,
            foreign_sd: Vec<SdImage>,
            base_sd: Vec<SdImage>,
            lock_sd: Option<SdImage>,
            canary_sd: Option<SdImage>,
            lock_snapshot: Option<FileSnapshot>,
            context: Option<execution_observation::ContextKey>,
            causes: Vec<io::Error>,
            phase: &'static str,
        }
        impl Fixture {
            fn new() -> Self {
                Self {
                    base: ProbeFixture::empty(),
                    guard: None,
                    stage: None,
                    view: None,
                    receipt: None,
                    root: None,
                    file: None,
                    snapshot: None,
                    root_sd: None,
                    file_sd: None,
                    state_sd: Vec::new(),
                    foreign_sd: Vec::new(),
                    base_sd: Vec::new(),
                    lock_sd: None,
                    canary_sd: None,
                    lock_snapshot: None,
                    context: None,
                    causes: Vec::with_capacity(2),
                    phase: "native fixture setup",
                }
            }
            fn setup(&mut self) -> Result<(), Error> {
                self.base.initialize()?;
                let lock = self
                    .base
                    .lock
                    .take()
                    .ok_or_else(|| invalid("live-view actual lock missing"))?;
                self.guard = Some(Arc::new(lock));
                let foreign = self.base.foreign().handle();
                let foreign_id = self.base.foreign_id.unwrap();
                let sec = probe_security_copy(self.base.sec());
                let canary = probe_create_payload(
                    &mut self.base.ledger,
                    foreign,
                    foreign_id,
                    OsStr::new("canary"),
                    b"untouched foreign canary",
                    &sec,
                )?;
                self.base.foreign_canary = Some(canary);
                self.state_sd = chain_images(self.base.state())?;
                self.foreign_sd = chain_images(self.base.foreign())?;
                self.base_sd = chain_images(self.base.base())?;
                let guard = self.guard.as_ref().unwrap();
                self.base.state().require_lock(guard, true)?;
                if Some(guard.identity()) != self.base.lock_id
                    || probe_granted_access(guard.file.file.as_raw_handle())?
                        != FILE_ALL_ACCESS & !DELETE
                {
                    return Err(denied("live-view actual matching lock/grant differs").into());
                }
                self.lock_sd = Some(sd_image(guard.file.file.as_raw_handle())?);
                self.lock_snapshot = Some(guard.file.snapshot()?);
                let stage = self
                    .base
                    .state()
                    .stage_directory(Arc::clone(guard), OsStr::new(STAGE))
                    .map_err(Error::Create)?;
                self.root = Some(stage.identity());
                self.stage = Some(stage);
                {
                    let mut file = self.stage.as_mut().unwrap().write_new(
                        OsStr::new("payload"),
                        PAYLOAD,
                        false,
                    )?;
                    self.file = Some(file.identity());
                    self.snapshot = Some(file.snapshot()?);
                    if file.read_limited(4096)? != PAYLOAD
                        || file.execution_permission()?.executable()
                        || Some(file.snapshot()?) != self.snapshot
                    {
                        return Err(denied("live-view normal written file differs").into());
                    }
                }
                self.context = Some(self.stage.as_ref().unwrap().test_context()?);
                let normal = self
                    .stage
                    .as_ref()
                    .unwrap()
                    .verify_package_mode(OsStr::new("payload"), false)?;
                self.view = Some(staged_package::TestLiveView::detach(normal)?);
                self.view.as_mut().unwrap().read_actual(PAYLOAD)?;
                self.observe_intact("before_publication")
            }
            fn world(&mut self, current: execution_observation::ContextKey) -> io::Result<()> {
                if Some(current) != self.context {
                    return Err(denied("live-view original/current context differs"));
                }
                probe_recheck_chain(self.base.state(), &self.base.state_chain)?;
                probe_recheck_chain(self.base.foreign(), &self.base.foreign_chain)?;
                probe_recheck_chain(self.base.base(), &self.base.base_chain)?;
                if chain_images(self.base.state())? != self.state_sd
                    || chain_images(self.base.foreign())? != self.foreign_sd
                    || chain_images(self.base.base())? != self.base_sd
                {
                    return Err(denied("live-view outer policy image changed"));
                }
                let guard = self
                    .guard
                    .as_ref()
                    .ok_or_else(|| invalid("live-view guard missing"))?;
                self.base.state().require_lock(guard, true)?;
                if Some(guard.identity()) != self.base.lock_id
                    || Some(guard.file.snapshot()?) != self.lock_snapshot
                    || Some(sd_image(guard.file.file.as_raw_handle())?) != self.lock_sd
                {
                    return Err(denied("live-view lock image changed"));
                }
                let (id, acl) = self.base.foreign_canary.clone().unwrap();
                probe_verify_foreign(&mut self.base, id, &acl)?;
                let foreign = self.base.foreign().handle();
                let foreign_id = self.base.foreign_id.unwrap();
                let owner = probe_open_bound(
                    &mut self.base.ledger,
                    foreign,
                    foreign_id,
                    OsStr::new("canary"),
                    false,
                    FILE_GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    null(),
                    None,
                    true,
                )?;
                let raw = self.base.ledger.raw(owner);
                let mut measured = None;
                let result = (|| {
                    let actual = identity(raw)?;
                    measured = Some(actual);
                    if actual != id {
                        return Err(denied("live-view named canary identity changed"));
                    }
                    let image = sd_image(raw)?;
                    if self
                        .canary_sd
                        .as_ref()
                        .is_some_and(|before| *before != image)
                    {
                        return Err(denied("live-view canary OWNER/GROUP/control/DACL changed"));
                    }
                    self.canary_sd = Some(image);
                    Ok(())
                })();
                self.close_observer(owner, measured, result)
            }
            fn close_observer<T>(
                &mut self,
                id: ProbeHandle,
                measured: Option<FileIdentity>,
                result: io::Result<T>,
            ) -> io::Result<T> {
                let owner = self.base.ledger.handles[id.0]
                    .take()
                    .ok_or_else(|| invalid("live-view observer already consumed"))?;
                let result = if let Some(stage) = &self.stage {
                    stage.test_finish_native(owner, measured, result)
                } else {
                    self.receipt
                        .as_ref()
                        .unwrap()
                        .test_finish_native(owner, measured, result)
                };
                self.base.ledger.closed.push(format!(
                    "live-view-observer#{} checked_finish_ok={}",
                    id.0,
                    result.is_ok()
                ));
                result
            }
            fn observe_intact(&mut self, phase: &'static str) -> Result<(), Error> {
                self.world(self.stage.as_ref().unwrap().test_context()?)?;
                self.stage.as_ref().unwrap().test_unattempted()?;
                let parent = self.base.state().handle();
                let parent_id = self.base.state_id.unwrap();
                probe_check_absent(&mut self.base.ledger, parent, parent_id, OsStr::new(FINAL))?;
                let root = probe_open_bound(
                    &mut self.base.ledger,
                    parent,
                    parent_id,
                    OsStr::new(STAGE),
                    true,
                    ROOT_READ,
                    RWD,
                    null(),
                    None,
                    true,
                )?;
                let raw = self.base.ledger.raw(root);
                let mut root_id = None;
                let result = (|| -> io::Result<()> {
                    let actual = identity(raw)?;
                    root_id = Some(actual);
                    if Some(actual) != self.root || held_leaf(raw)? != OsStr::new(STAGE) {
                        return Err(denied("live-view named stage identity differs"));
                    }
                    if probe_granted_access(raw)? != ROOT_READ {
                        return Err(denied("live-view independent root grant differs"));
                    }
                    self.stage
                        .as_ref()
                        .unwrap()
                        .test_managed_policy(raw, FILE_ALL_ACCESS)?;
                    let root_sd = sd_image(raw)?;
                    if self.root_sd.as_ref().is_some_and(|old| *old != root_sd) {
                        return Err(denied("live-view root SD changed"));
                    }
                    self.root_sd = Some(root_sd);
                    let listed = source_directory_entries(
                        raw,
                        EnumerationLimits {
                            max_entries: 4,
                            max_name_bytes: 4096,
                        },
                    )?;
                    if listed.len() != 1
                        || listed[0].name != OsStr::new("payload")
                        || listed[0].directory
                        || listed[0].identity != self.file.unwrap().file
                    {
                        return Err(denied("live-view stage full inventory differs"));
                    }
                    let file = probe_open_bound(
                        &mut self.base.ledger,
                        raw,
                        actual,
                        OsStr::new("payload"),
                        false,
                        FILE_GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        null(),
                        None,
                        true,
                    )?;
                    let file_raw = self.base.ledger.raw(file);
                    let mut measured_file = None;
                    let read = (|| -> io::Result<()> {
                        let actual = identity(file_raw)?;
                        measured_file = Some(actual);
                        if Some(actual) != self.file
                            || Some(source_snapshot(file_raw, actual, false)?) != self.snapshot
                            || probe_granted_access(file_raw)? != FILE_GENERIC_READ
                        {
                            return Err(denied("live-view named file metadata/grant differs"));
                        }
                        let sec = probe_security_copy(self.base.sec());
                        let _ = probe_check_r(file_raw, &sec)?;
                        self.stage
                            .as_ref()
                            .unwrap()
                            .test_managed_policy(file_raw, FILE_GENERIC_READ)?;
                        let image = sd_image(file_raw)?;
                        if self.file_sd.as_ref().is_some_and(|old| *old != image) {
                            return Err(denied("live-view named file SD changed"));
                        }
                        self.file_sd = Some(image);
                        if probe_read_payload(file_raw, actual)? != PAYLOAD {
                            return Err(denied("live-view named file bytes differ"));
                        }
                        Ok(())
                    })();
                    self.close_observer(file, measured_file, read)?;
                    Ok(())
                })();
                self.close_observer(root, root_id, result)?;
                self.view.as_mut().unwrap().read_actual(PAYLOAD)?;
                println!(
                    "live_view_intact phase={phase} root={:?} file={:?} complete_inventory=true managed_FA_R_OWNER_GROUP=true snapshot_bytes_unchanged=true original_context=true parent_lock_anchors_canary=true final_absent=true same_real_view=true pre_attempt_markers_none=true",
                    self.root, self.file
                );
                Ok(())
            }
            fn execute(&mut self) -> Result<(), Error> {
                self.setup()?;
                self.phase = "publication with same genuine live view";
                let stage = self.stage.take().unwrap();
                match stage.publish_directory(OsStr::new(FINAL)) {
                    Err(StagePublishError::Unchanged { source, stage })
                        if source.kind() == io::ErrorKind::PermissionDenied
                            && source.to_string() == "package has live read leases" =>
                    {
                        self.stage = Some(stage);
                        self.causes.push(source);
                    }
                    Err(error) => return Err(Error::Publish(error)),
                    Ok(publication) => return Err(Error::UnexpectedPublication(publication)),
                }
                if Some(self.stage.as_ref().unwrap().identity()) != self.root {
                    return Err(denied("publication returned different stage").into());
                }
                self.observe_intact("after_publication_refusal")?;
                self.phase = "discard with SAME genuine live view";
                let stage = self.stage.take().unwrap();
                match stage.discard() {
                    Err(StageRemovalError::Unchanged { source, stage })
                        if source.kind() == io::ErrorKind::PermissionDenied
                            && source.to_string() == "package has live read leases" =>
                    {
                        self.stage = Some(stage);
                        self.causes.push(source);
                    }
                    Err(error) => return Err(Error::Removal(error)),
                    Ok(receipt) => return Err(Error::UnexpectedRemoval(receipt)),
                }
                if Some(self.stage.as_ref().unwrap().identity()) != self.root {
                    return Err(denied("discard returned different stage").into());
                }
                self.observe_intact("after_discard_refusal")?;
                self.phase = "actual view anchor/file checked close and real release";
                self.view.take().unwrap().close()?;
                self.stage.as_ref().unwrap().test_zero()?;
                self.world(self.stage.as_ref().unwrap().test_context()?)?;
                self.phase = "THAT stage actual discard";
                let stage = self.stage.take().unwrap();
                self.receipt = Some(stage.discard().map_err(Error::Removal)?);
                let key = self
                    .receipt
                    .as_ref()
                    .unwrap()
                    .test_removed(self.root.unwrap(), self.file.unwrap())?;
                self.world(key)?;
                let parent = self.base.state().handle();
                let parent_id = self.base.state_id.unwrap();
                probe_check_absent(&mut self.base.ledger, parent, parent_id, OsStr::new(STAGE))?;
                probe_check_absent(&mut self.base.ledger, parent, parent_id, OsStr::new(FINAL))?;
                let entries = directory_entries(
                    parent,
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 4096,
                    },
                )?;
                if entries.len() != 1
                    || entries[0].name != OsStr::new("transaction.lock")
                    || entries[0].identity != self.base.lock_id.unwrap().file
                    || entries.iter().any(|entry| {
                        entry.identity == self.root.unwrap().file
                            || entry.identity == self.file.unwrap().file
                    })
                {
                    return Err(
                        denied("live-view bounded parent namespace exclusion failed").into(),
                    );
                }
                println!(
                    "live_view_actual_discard_names root={:?} file={:?} original_root_payload_namespace_absent=true final_unused=true bounded_parent_ID_exclusion=true volume_wide_ID_absence_claim=false receipt_held=true",
                    self.root, self.file
                );
                drop(self.receipt.take());
                self.phase = "restore original lock and full known fixture teardown";
                let guard = self.guard.take().unwrap();
                match Arc::try_unwrap(guard) {
                    Ok(lock) => self.base.lock = Some(lock),
                    Err(guard) => {
                        self.guard = Some(guard);
                        return Err(denied("live-view guard alias remains; retained").into());
                    }
                }
                if !self.base.stages.is_empty()
                    || self.causes.len() != 2
                    || self.view.is_some()
                    || self.stage.is_some()
                {
                    return Err(invalid("live-view final product authority remains").into());
                }
                self.base.finish_success()?;
                if self.base.ledger.handles.iter().any(Option::is_some)
                    || self.base.ledger.directories.iter().any(Option::is_some)
                    || self.base.lock.is_some()
                    || self.base.state_dir.is_some()
                    || self.base.foreign_dir.is_some()
                    || self.base.base_dir.is_some()
                {
                    return Err(invalid("live-view fixture owner remains after cleanup").into());
                }
                println!(
                    "live_view_control_complete exact_refusals=2 SAME_actual_view=true actual_file_close_release=true real_discard_receipt=true all_fixture_names_removed=true all_direct_native_owners_checked_closed=true public_Arc_release_not_native_close=true remaining_authority=false"
                );
                Ok(())
            }
        }
        pub(super) struct Failure {
            error: Error,
            retained: Box<Fixture>,
        }
        impl std::fmt::Debug for Failure {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("InvalidGenuineLiveViewControl")
                    .field("phase", &self.retained.phase)
                    .field("error", &self.error)
                    .field("refusal_causes", &self.retained.causes)
                    .field("root", &self.retained.root)
                    .field("file", &self.retained.file)
                    .field("stage_retained", &self.retained.stage.is_some())
                    .field("actual_view_retained", &self.retained.view.is_some())
                    .field("receipt_retained", &self.retained.receipt.is_some())
                    .field("guard_retained", &self.retained.guard.is_some())
                    .field("created_fixture_names", &self.retained.base.ledger.created)
                    .field(
                        "consumed_fixture_close_facts",
                        &self.retained.base.ledger.closed,
                    )
                    .field("owning_typed_carrier", &true)
                    .finish()
            }
        }
        pub(super) fn run() -> Result<(), Failure> {
            let mut fixture = Fixture::new();
            match fixture.execute() {
                Ok(()) => Ok(()),
                Err(error) => Err(Failure {
                    error,
                    retained: Box::new(fixture),
                }),
            }
        }
    }
    #[test]
    fn staged_package_live_views_refuse_publication_and_cleanup()
    -> Result<(), live_view_control::Failure> {
        live_view_control::run()
    }

    #[test]
    fn staged_directory_delete_child_reacquisition_prerequisite() {
        let mut fixture = ProbeFixture::empty();
        let mut evidence = ProbeDcEvidence::default();
        let result = (|| -> io::Result<()> {
            fixture.initialize()?;
            probe_dc_execute(&mut fixture, &mut evidence)?;
            fixture.finish_success()?;
            Ok(())
        })();
        match result {
            Ok(()) => println!(
                "probe_dc_test_result=DeleteChildReacquisitionMeasuredCohort checked_fixture_teardown=complete native_product_support=false"
            ),
            Err(primary) => {
                println!("probe_dc_partial_receipt non_authorizing=true evidence={evidence:?}");
                let errors = fixture.preserve_failure();
                panic!(
                    "delete-child native measurement/setup failed: {primary}; fixture preserved; checked-close errors={errors:?}"
                );
            }
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
