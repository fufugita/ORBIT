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

/// A regular source file held through its directory capability.
pub struct SourceFile {
    file: File,
    identity: FileIdentity,
    parent_identity: FileIdentity,
    anchors: Vec<Arc<OwnedHandle>>,
    anchor_identities: Vec<FileIdentity>,
}

impl SourceFile {
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
