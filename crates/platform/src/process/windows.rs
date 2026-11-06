//! A capability token and a separately owned Job precede every child instruction.

use super::{
    Completion, ConfinementEvidence, ProcessOutput, RUNTIME_CAPABILITY_NAME,
    RUNTIME_CAPABILITY_SID, SpawnSpec, quote_argument, verify_runtime_capability_set,
};
use crate::fs::validate_component;
#[cfg(all(test, feature = "registry-witness"))]
use std::collections::BTreeMap;
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
#[cfg(all(test, feature = "registry-witness"))]
use windows_sys::Wdk::Foundation::ObjectBasicInformation;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
#[cfg(all(test, feature = "registry-witness"))]
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FileDispositionInformation,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
#[cfg(all(test, feature = "registry-witness"))]
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SetSecurityInfo};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::JobObjects::*;
#[cfg(all(test, feature = "registry-witness"))]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Win32::System::Threading::*;
#[cfg(all(test, feature = "registry-witness"))]
use windows_sys::Win32::System::WindowsProgramming::FILE_CREATED;
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

#[derive(Debug)]
struct OperationError {
    operation: &'static str,
    source: io::Error,
}
impl std::fmt::Display for OperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} (OS code {:?})",
            self.operation,
            self.source,
            self.source.raw_os_error()
        )
    }
}
impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
fn operation_error(operation: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), OperationError { operation, source })
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn ok(operation: &'static str, value: i32) -> io::Result<()> {
    if value == 0 {
        Err(operation_error(operation, io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
fn hresult(operation: &'static str, value: i32) -> io::Result<()> {
    if value >= 0 {
        Ok(())
    } else if value as u32 & 0xffff0000 == 0x80070000 {
        Err(operation_error(
            operation,
            io::Error::from_raw_os_error(value & 0xffff),
        ))
    } else {
        Err(operation_error(
            operation,
            io::Error::other(format!("Windows HRESULT {value:#x}")),
        ))
    }
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut encoded: Vec<_> = value.encode_wide().collect();
    if encoded.contains(&0) {
        return Err(invalid("NUL in Windows value"));
    }
    encoded.push(0);
    Ok(encoded)
}
fn own(operation: &'static str, handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(operation_error(operation, io::Error::last_os_error()))
    } else {
        // SAFETY: the caller transfers a successful newly created handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
unsafe fn string_from_pointer(pointer: *const u16) -> io::Result<String> {
    if pointer.is_null() {
        return Err(invalid("missing Windows string"));
    }
    let mut length = 0;
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32768 {
        return Err(invalid("oversized Windows string"));
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(|_| invalid("invalid Windows string"))
}

/// A fresh OS-managed profile is an explicitly capability-accessible resource.
/// It is separate from the owner-only private metadata storage policy.
pub struct SandboxSession {
    name: String,
    sid: Vec<u32>,
    runtime_sid: Vec<u32>,
    #[cfg(all(test, feature = "registry-diagnostic"))]
    registry_probe_sid: Option<Vec<u32>>,
    folder: PathBuf,
    root: Option<OwnedHandle>,
    unsafe_cleanup: AtomicBool,
    #[cfg(all(test, feature = "registry-witness"))]
    registry_witness_child_unobserved: AtomicBool,
    closed: bool,
}

/// Approved script bytes pinned against write/delete access until this guard drops.
/// The session borrow also keeps its held profile anchor alive.
pub struct PreparedScript<'a> {
    _session: &'a SandboxSession,
    _file: File,
    path: PathBuf,
    identity: (u64, [u8; 16]),
}
impl PreparedScript<'_> {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn identity(&self) -> (u64, [u8; 16]) {
        self.identity
    }
}

impl SandboxSession {
    pub fn create() -> io::Result<Self> {
        let mut nonce = [0u8; 16];
        // SAFETY: BCrypt fills the bounded output using the system RNG.
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(operation_error(
                "BCryptGenRandom",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32),
            ));
        }
        let name = format!(
            "orbit.shell.{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let name_wide = wide(OsStr::new(&name))?;
        let runtime_sid = derive_runtime_sid()?;
        let runtime_capability = SID_AND_ATTRIBUTES {
            Sid: runtime_sid.as_ptr().cast_mut().cast(),
            Attributes: SE_GROUP_ENABLED as u32,
        };
        let mut allocated_sid = null_mut();
        // Only the fixed nonnetwork runtime capability is requested.
        hresult("CreateAppContainerProfile", unsafe {
            CreateAppContainerProfile(
                name_wide.as_ptr(),
                name_wide.as_ptr(),
                name_wide.as_ptr(),
                &runtime_capability,
                1,
                &mut allocated_sid,
            )
        })?;
        let result = (|| {
            let length = unsafe { GetLengthSid(allocated_sid) };
            if length == 0 || length > 68 {
                return Err(invalid("invalid profile SID"));
            }
            let mut sid = vec![0u32; (length as usize).div_ceil(4)];
            unsafe {
                ok(
                    "CopySid",
                    CopySid(length, sid.as_mut_ptr().cast(), allocated_sid),
                )?;
            }
            let mut sid_string = null_mut();
            unsafe {
                ok(
                    "ConvertSidToStringSidW",
                    ConvertSidToStringSidW(allocated_sid, &mut sid_string),
                )?;
            }
            let mut folder_pointer = null_mut();
            let folder_result =
                unsafe { GetAppContainerFolderPath(sid_string, &mut folder_pointer) };
            unsafe {
                LocalFree(sid_string.cast());
            }
            hresult("GetAppContainerFolderPath", folder_result)?;
            let folder_result = unsafe { string_from_pointer(folder_pointer) };
            unsafe {
                CoTaskMemFree(folder_pointer.cast());
            }
            let folder = PathBuf::from(folder_result?);
            let path = wide(folder.as_os_str())?;
            let root = own("CreateFileW(profile root)", unsafe {
                CreateFileW(
                    path.as_ptr(),
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            })?;
            check_object(root.as_raw_handle(), true)?;
            Ok(Self {
                name: name.clone(),
                sid,
                runtime_sid,
                #[cfg(all(test, feature = "registry-diagnostic"))]
                registry_probe_sid: None,
                folder,
                root: Some(root),
                unsafe_cleanup: AtomicBool::new(false),
                #[cfg(all(test, feature = "registry-witness"))]
                registry_witness_child_unobserved: AtomicBool::new(false),
                closed: false,
            })
        })();
        unsafe {
            FreeSid(allocated_sid);
        }
        if result.is_err() {
            // Only this successful creation's fresh moniker can be removed.
            unsafe {
                DeleteAppContainerProfile(name_wide.as_ptr());
            }
        }
        result
    }

    pub fn profile_name(&self) -> &str {
        &self.name
    }

    pub fn prepare_file(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("resource input limit"));
        }
        let mut file = File::from(self.open_resource(name, true)?);
        file.write_all(bytes)?;
        file.sync_all()
    }

    pub fn read_file(&self, name: &OsStr, maximum: usize) -> io::Result<Vec<u8>> {
        if maximum > 8 * 1024 * 1024 {
            return Err(invalid("resource read limit"));
        }
        let file = File::from(self.open_resource(name, false)?);
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(invalid("resource exceeds read limit"));
        }
        Ok(bytes)
    }

    pub fn prepare_script(&self, name: &OsStr, source: &str) -> io::Result<PreparedScript<'_>> {
        validate_component(name)?;
        if !name.to_str().is_some_and(|name| name.ends_with(".ps1")) || source.len() > 1024 * 1024 {
            return Err(invalid("expected bounded .ps1 script"));
        }
        let mut writer = File::from(self.open_resource(name, true)?);
        let expected = script_identity(writer.as_raw_handle())?;
        writer.write_all(source.as_bytes())?;
        writer.sync_all()?;
        drop(writer);
        // Reopen relative to the same held root with no write/delete sharing.
        // Check both identity and bytes only after this immutable hold exists;
        // any replacement or modification in the reopen interval fails closed.
        let mut file = File::from(self.open_resource_with_sharing(name, false, FILE_SHARE_READ)?);
        let identity = script_identity(file.as_raw_handle())?;
        if identity != expected {
            return Err(invalid("prepared script identity changed"));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(source.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes != source.as_bytes() {
            return Err(invalid("prepared script bytes changed"));
        }
        Ok(PreparedScript {
            _session: self,
            _file: file,
            path: self.folder.join(name),
            identity,
        })
    }

    fn open_resource(&self, name: &OsStr, create: bool) -> io::Result<OwnedHandle> {
        self.open_resource_with_sharing(name, create, FILE_SHARE_READ | FILE_SHARE_WRITE)
    }

    fn open_resource_with_sharing(
        &self,
        name: &OsStr,
        create: bool,
        sharing: u32,
    ) -> io::Result<OwnedHandle> {
        validate_component(name)?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| invalid("profile closed"))?;
        let mut name: Vec<u16> = name.encode_wide().collect();
        let length = name
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| invalid("resource name too long"))?;
        let mut unicode = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: root.as_raw_handle(),
            ObjectName: &mut unicode,
            Attributes: 0x40,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_GENERIC_READ | if create { FILE_GENERIC_WRITE } else { 0 },
                &attributes,
                &mut status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                sharing,
                if create { FILE_CREATE } else { FILE_OPEN },
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if result < 0 {
            return Err(operation_error(
                "NtCreateFile(resource)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ));
        }
        let handle = own("NtCreateFile(resource handle)", handle)?;
        check_object(handle.as_raw_handle(), false)?;
        Ok(handle)
    }

    pub fn spawn<'a>(&'a self, spec: &SpawnSpec) -> io::Result<OwnedProcess<'a>> {
        OwnedProcess::spawn(self, spec)
    }

    /// Measure the ordinary AppContainer comparison without executing user code.
    /// Uses the production launch setup with only the LPAC opt-out omitted.
    /// No child handle escapes; process and Job termination are observed first.
    pub fn inspect_ordinary_control(&self, spec: &SpawnSpec) -> io::Result<ConfinementEvidence> {
        let (mut child, thread) = OwnedProcess::create_suspended(self, spec, false)?;
        let evidence = child.evidence;
        child.stop()?;
        child.finished = true;
        drop(thread);
        Ok(evidence)
    }

    pub fn close(mut self) -> io::Result<()> {
        self.root.take();
        if self.unsafe_cleanup.load(Ordering::Acquire) {
            return Err(io::Error::other(format!(
                "profile retained after cleanup preservation decision: name={} path={}",
                self.name,
                self.folder.display()
            )));
        }
        hresult("DeleteAppContainerProfile", unsafe {
            DeleteAppContainerProfile(wide(OsStr::new(&self.name))?.as_ptr())
        })?;
        self.closed = true;
        Ok(())
    }
}

#[cfg(all(test, feature = "registry-witness"))]
impl SandboxSession {
    fn retain_profile_for_registry_witness(&self) -> String {
        self.unsafe_cleanup.store(true, Ordering::Release);
        format!(
            "profile_name={} profile_path={}",
            self.name,
            self.folder.display()
        )
    }
}

impl Drop for SandboxSession {
    fn drop(&mut self) {
        self.root.take();
        if !self.closed && !self.unsafe_cleanup.load(Ordering::Acquire) {
            if let Ok(name) = wide(OsStr::new(&self.name)) {
                unsafe {
                    DeleteAppContainerProfile(name.as_ptr());
                }
            }
        }
    }
}

fn script_identity(handle: HANDLE) -> io::Result<(u64, [u8; 16])> {
    let mut information = FILE_ID_INFO::default();
    unsafe {
        ok(
            "GetFileInformationByHandleEx(script identity)",
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut information as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            ),
        )?;
    }
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

fn check_object(handle: HANDLE, directory: bool) -> io::Result<()> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    unsafe {
        ok(
            "GetFileInformationByHandleEx",
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ),
        )?;
        ok(
            "GetFileInformationByHandleEx",
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            ),
        )?;
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || standard.DeletePending
        || standard.Directory != directory
        || (!directory && standard.NumberOfLinks != 1)
    {
        return Err(invalid("resource is linked, replaced or of the wrong kind"));
    }
    Ok(())
}

#[cfg(all(test, feature = "registry-witness"))]
fn verify_file_link_count(handle: HANDLE, expected: u32) -> io::Result<()> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    unsafe {
        ok(
            "GetFileInformationByHandleEx(hardlink attributes)",
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ),
        )?;
        ok(
            "GetFileInformationByHandleEx(hardlink standard info)",
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            ),
        )?;
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || standard.DeletePending
        || standard.Directory
        || standard.NumberOfLinks != expected
    {
        return Err(io::Error::other(format!(
            "hardlink target kind or link count changed: links={}",
            standard.NumberOfLinks
        )));
    }
    Ok(())
}

struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        let sizing = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes) };
        let sizing_error = if sizing == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        if sizing_error.as_ref().and_then(io::Error::raw_os_error)
            != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        {
            return Err(operation_error(
                "InitializeProcThreadAttributeList(size)",
                sizing_error.unwrap_or_else(|| invalid("unexpected successful sizing call")),
            ));
        }
        if bytes == 0 || bytes > 1024 * 1024 {
            return Err(invalid("attribute-list sizing limit"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        unsafe {
            ok(
                "InitializeProcThreadAttributeList",
                InitializeProcThreadAttributeList(
                    storage.as_mut_ptr().cast(),
                    count,
                    0,
                    &mut bytes,
                ),
            )?;
        }
        Ok(Self { storage })
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn set<T>(&mut self, key: u32, value: &T) -> io::Result<()> {
        let operation = match key {
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES => {
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES)"
            }
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY => {
                "UpdateProcThreadAttribute(ALL_APPLICATION_PACKAGES_POLICY)"
            }
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST => "UpdateProcThreadAttribute(HANDLE_LIST)",
            _ => "UpdateProcThreadAttribute",
        };
        unsafe {
            ok(
                operation,
                UpdateProcThreadAttribute(
                    self.pointer(),
                    0,
                    key as usize,
                    (value as *const T).cast(),
                    size_of::<T>(),
                    null_mut(),
                    null(),
                ),
            )
        }
    }

    fn set_handle_list(&mut self, handles: &[HANDLE]) -> io::Result<()> {
        if (handles.len() != 3 && handles.len() != 5)
            || handles.iter().any(|handle| handle.is_null())
        {
            return Err(invalid(
                "process handle-list shape is not an approved stdio/witness set",
            ));
        }
        unsafe {
            ok(
                "UpdateProcThreadAttribute(HANDLE_LIST)",
                UpdateProcThreadAttribute(
                    self.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    std::mem::size_of_val(handles),
                    null_mut(),
                    null(),
                ),
            )
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    unsafe {
        ok(
            "CreatePipe",
            CreatePipe(&mut read, &mut write, &attributes, 4096),
        )?;
    }
    Ok((
        own("CreatePipe(read)", read)?,
        own("CreatePipe(write)", write)?,
    ))
}

fn token_boolean(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<bool> {
    let mut value = 0u32;
    let mut bytes = 0;
    let operation = if class == TokenIsAppContainer {
        "GetTokenInformation(TokenIsAppContainer)"
    } else {
        "GetTokenInformation(boolean)"
    };
    unsafe {
        ok(
            operation,
            GetTokenInformation(token, class, (&mut value as *mut u32).cast(), 4, &mut bytes),
        )?;
    }
    if bytes != 4 {
        return Err(invalid("token boolean shape"));
    }
    Ok(value != 0)
}

/// Two successful access decisions, not a query of an undocumented token payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpacAccessCheck {
    pub all_application_packages_grant: bool,
    pub own_package_grant: bool,
}
impl LpacAccessCheck {
    pub fn is_less_privileged(self) -> bool {
        self.own_package_grant && !self.all_application_packages_grant
    }
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct DerivedSids {
    groups: *mut PSID,
    group_count: u32,
    capabilities: *mut PSID,
    capability_count: u32,
}
impl Drop for DerivedSids {
    fn drop(&mut self) {
        // SAFETY: the successful API owns each SID and each pointer array;
        // initialized null outputs are harmless on an error path.
        unsafe {
            for (array, count) in [
                (self.groups, self.group_count),
                (self.capabilities, self.capability_count),
            ] {
                if !array.is_null() {
                    for index in 0..count {
                        LocalFree((*array.add(index as usize)).cast());
                    }
                    LocalFree(array.cast());
                }
            }
        }
    }
}

fn derive_runtime_sid() -> io::Result<Vec<u32>> {
    let name = wide(OsStr::new(RUNTIME_CAPABILITY_NAME))?;
    let mut allocated = DerivedSids {
        groups: null_mut(),
        group_count: 0,
        capabilities: null_mut(),
        capability_count: 0,
    };
    unsafe {
        ok(
            "DeriveCapabilitySidsFromName(lpacInstrumentation)",
            DeriveCapabilitySidsFromName(
                name.as_ptr(),
                &mut allocated.groups,
                &mut allocated.group_count,
                &mut allocated.capabilities,
                &mut allocated.capability_count,
            ),
        )?;
    }
    if allocated.capability_count != 1 || allocated.capabilities.is_null() {
        return Err(invalid("runtime capability derivation shape"));
    }
    let sid = unsafe { *allocated.capabilities };
    let text = sid_text(sid)?;
    verify_runtime_capability_set(&[(&text, SE_GROUP_ENABLED as u32)])?;
    let bytes = unsafe { GetLengthSid(sid) };
    if bytes == 0 || bytes > 68 {
        return Err(invalid("runtime capability SID length"));
    }
    let mut owned = vec![0u32; (bytes as usize).div_ceil(size_of::<u32>())];
    unsafe {
        ok(
            "CopySid(runtime capability)",
            CopySid(bytes, owned.as_mut_ptr().cast(), sid),
        )?;
    }
    Ok(owned)
}

fn token_buffer(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    operation: &'static str,
) -> io::Result<Vec<usize>> {
    let mut bytes = 0;
    let result = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut bytes) };
    let error = if result == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    if error.as_ref().and_then(io::Error::raw_os_error) != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(operation_error(
            operation,
            error.unwrap_or_else(|| invalid("token sizing succeeded unexpectedly")),
        ));
    }
    let minimum = if class == TokenUser {
        size_of::<TOKEN_USER>()
    } else if class == TokenAppContainerSid {
        size_of::<TOKEN_APPCONTAINER_INFORMATION>()
    } else {
        size_of::<u32>()
    };
    if bytes < minimum as u32 || bytes > 65536 {
        return Err(invalid("token identity buffer size"));
    }
    let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    unsafe {
        ok(
            operation,
            GetTokenInformation(token, class, data.as_mut_ptr().cast(), bytes, &mut bytes),
        )?;
    }
    Ok(data)
}

fn sid_text(sid: PSID) -> io::Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid("invalid access-probe SID"));
    }
    let mut pointer = null_mut();
    unsafe {
        ok(
            "ConvertSidToStringSidW(access probe)",
            ConvertSidToStringSidW(sid, &mut pointer),
        )?;
    }
    let allocation = LocalAllocation(pointer.cast());
    let value = unsafe { string_from_pointer(pointer) };
    drop(allocation);
    value
}

fn descriptor_access(token: HANDLE, owner: &str, package: &str) -> io::Result<bool> {
    // The user pass grants bit1 through Everyone; the package pass must grant it
    // independently through the selected package SID.
    let text = wide(OsStr::new(&format!(
        "O:{owner}G:{owner}D:P(A;;0x1;;;WD)(A;;0x1;;;{package})"
    )))?;
    let mut descriptor = null_mut();
    unsafe {
        ok(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(access probe)",
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            ),
        )?;
    }
    let allocation = LocalAllocation(descriptor);
    let mapping = GENERIC_MAPPING {
        GenericRead: 1,
        GenericWrite: 2,
        GenericExecute: 4,
        GenericAll: 7,
    };
    let mut privileges = vec![0usize; 64];
    for attempt in 0..2 {
        let mut bytes = (privileges.len() * size_of::<usize>()) as u32;
        let (mut granted, mut allowed) = (0, 0);
        let result = unsafe {
            AccessCheck(
                descriptor,
                token,
                1,
                &mapping,
                privileges.as_mut_ptr().cast(),
                &mut bytes,
                &mut granted,
                &mut allowed,
            )
        };
        if result != 0 {
            drop(allocation);
            if (allowed != 0 && granted & 1 == 1) || (allowed == 0 && granted == 0) {
                return Ok(allowed != 0);
            }
            return Err(invalid("inconsistent successful access-probe decision"));
        }
        let error = io::Error::last_os_error();
        if attempt == 0
            && error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
            && bytes > privileges.len() as u32 * size_of::<usize>() as u32
            && bytes <= 65536
        {
            privileges.resize((bytes as usize).div_ceil(size_of::<usize>()), 0);
        } else {
            return Err(operation_error("AccessCheck(LPAC authority probe)", error));
        }
    }
    Err(invalid("access-probe sizing exhausted"))
}

/// Check the LPAC authority property with supported token/ACL APIs. This
/// composition is validated separately against an ordinary AppContainer.
/// API errors never become evidence of a denied grant.
pub fn inspect_lpac_access(token: BorrowedHandle<'_>) -> io::Result<LpacAccessCheck> {
    let token = token.as_raw_handle();
    if !token_boolean(token, TokenIsAppContainer)? {
        return Err(invalid("LPAC access probe requires an AppContainer token"));
    }
    let user = token_buffer(
        token,
        TokenUser,
        "GetTokenInformation(TokenUser for access probe)",
    )?;
    let package = token_buffer(
        token,
        TokenAppContainerSid,
        "GetTokenInformation(TokenAppContainerSid)",
    )?;
    let owner = sid_text(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
    let package = sid_text(unsafe {
        (*package.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer
    })?;
    let mut duplicate = null_mut();
    unsafe {
        ok(
            "DuplicateToken(access probe)",
            DuplicateToken(token, SecurityImpersonation, &mut duplicate),
        )?;
    }
    let duplicate = own("DuplicateToken(access probe handle)", duplicate)?;
    let own_package_grant = descriptor_access(duplicate.as_raw_handle(), &owner, &package)?;
    let all_application_packages_grant =
        descriptor_access(duplicate.as_raw_handle(), &owner, "AC")?;
    if !own_package_grant {
        return Err(io::Error::other(format!(
            "LPAC positive access control failed: own_package={own_package_grant}, all_application_packages={all_application_packages_grant}"
        )));
    }
    Ok(LpacAccessCheck {
        all_application_packages_grant,
        own_package_grant,
    })
}

fn process_completed(process: HANDLE) -> io::Result<bool> {
    let result = unsafe { WaitForSingleObject(process, 0) };
    match result {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(operation_error(
            "WaitForSingleObject(process)",
            io::Error::last_os_error(),
        )),
        _ => Err(invalid("unexpected process wait result")),
    }
}

/// Owned group and pipes; the borrow prevents profile removal during execution.
pub struct OwnedProcess<'a> {
    session: &'a SandboxSession,
    process: OwnedHandle,
    job: OwnedHandle,
    stdout: File,
    stderr: File,
    assigned: bool,
    finished: bool,
    started: Instant,
    timeout: Duration,
    output_limit: usize,
    evidence: ConfinementEvidence,
}

impl<'a> OwnedProcess<'a> {
    fn spawn(session: &'a SandboxSession, spec: &SpawnSpec) -> io::Result<Self> {
        let (child, thread) = Self::create_suspended(session, spec, true)?;
        if !child.evidence.less_privileged {
            return Err(io::Error::other("child failed LPAC admission"));
        }
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(operation_error("ResumeThread", io::Error::last_os_error()));
        }
        Ok(child)
    }

    // Both variants use this exact launch path. Only production can resume;
    // the ordinary control is inspected and terminated inside its safe API.
    fn create_suspended(
        session: &'a SandboxSession,
        spec: &SpawnSpec,
        less_privileged: bool,
    ) -> io::Result<(Self, OwnedHandle)> {
        Self::create_suspended_with_context(session, spec, less_privileged, &[], &[], None)
    }

    #[cfg(all(test, feature = "registry-witness"))]
    fn create_registry_witness_child(
        session: &'a SandboxSession,
        spec: &SpawnSpec,
        role: &str,
        nonce: &str,
        original_user_sid: &str,
        package_sid: &str,
        image_sha256: &str,
        image_identity: (u64, [u8; 16]),
        fixture_digest: &str,
        fixture_identity_sha256: &str,
        private_read_handles: [self::registry_witness_tests::OwnedRegKey; 2],
    ) -> io::Result<(Self, OwnedHandle)> {
        if !matches!(role, "normal" | "cancel")
            || nonce.len() != 32
            || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !original_user_sid.starts_with("S-1-5-")
            || !original_user_sid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || fixture_identity_sha256.len() != 64
            || !fixture_identity_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || private_read_handles.iter().any(|key| key.raw().is_null())
        {
            return Err(invalid("invalid fixed registry witness launch context"));
        }
        let parent_creation =
            self::registry_witness_tests::process_creation_text(unsafe { GetCurrentProcess() })?;
        let environment = [
            ("ORBIT_REGISTRY_WITNESS_ROLE", role),
            ("ORBIT_REGISTRY_WITNESS_NONCE", nonce),
            ("ORBIT_REGISTRY_WITNESS_USER_SID", original_user_sid),
            ("ORBIT_REGISTRY_WITNESS_PACKAGE_SID", package_sid),
            ("ORBIT_REGISTRY_WITNESS_IMAGE_SHA256", image_sha256),
            (
                "ORBIT_REGISTRY_WITNESS_IMAGE_ID",
                &self::registry_witness_tests::identity_text(image_identity),
            ),
            ("ORBIT_REGISTRY_WITNESS_FIXTURE_DIGEST", fixture_digest),
            ("ORBIT_REGISTRY_WITNESS_FIXTURE_ID", fixture_identity_sha256),
            (
                "ORBIT_REGISTRY_WITNESS_PARENT_PID",
                &format!("{}", unsafe { GetCurrentProcessId() }),
            ),
            (
                "ORBIT_REGISTRY_WITNESS_PARENT_CREATION",
                parent_creation.as_str(),
            ),
            (
                "ORBIT_REGISTRY_WITNESS_MACHINE_HANDLE",
                &format!("{}", private_read_handles[0].raw() as usize),
            ),
            (
                "ORBIT_REGISTRY_WITNESS_USER_HANDLE",
                &format!("{}", private_read_handles[1].raw() as usize),
            ),
        ];
        let handles = [
            private_read_handles[0].raw().cast(),
            private_read_handles[1].raw().cast(),
        ];
        let mut private_read_handles = Some(private_read_handles);
        let mut close_inherited = || {
            let mut errors = Vec::new();
            for (index, key) in private_read_handles
                .take()
                .into_iter()
                .flatten()
                .enumerate()
            {
                if let Err(error) = key.close() {
                    errors.push(format!(
                        "private inherited key {index} RegCloseKey failed: {error}"
                    ));
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(errors.join("; ")))
            }
        };
        Self::create_suspended_with_context(
            session,
            spec,
            true,
            &environment,
            &handles,
            Some(&mut close_inherited),
        )
    }

    fn create_suspended_with_context(
        session: &'a SandboxSession,
        spec: &SpawnSpec,
        less_privileged: bool,
        extra_environment: &[(&str, &str)],
        extra_handles: &[HANDLE],
        mut after_create: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> io::Result<(Self, OwnedHandle)> {
        if spec.timeout.is_zero()
            || spec.timeout > Duration::from_secs(3600)
            || spec.output_limit == 0
            || spec.output_limit > 8 * 1024 * 1024
        {
            return Err(invalid("invalid child limits"));
        }
        if !spec.executable.is_absolute() {
            return Err(invalid("child executable must be absolute"));
        }
        let executable = spec.executable.canonicalize()?;
        if !executable.is_absolute() || !executable.is_file() {
            return Err(invalid("child executable must be an absolute file"));
        }
        let executable_text = executable
            .to_str()
            .ok_or_else(|| invalid("executable encoding"))?;
        let mut line = quote_argument(executable_text)?;
        for arg in &spec.arguments {
            line.push(' ');
            line.push_str(&quote_argument(arg)?);
        }
        let mut line = wide(OsStr::new(&line))?;
        if line.len() > 32767 {
            return Err(invalid("child command line limit"));
        }
        let module_root = executable
            .parent()
            .ok_or_else(|| invalid("executable parent"))?
            .to_owned();
        let executable = wide(executable.as_os_str())?;
        let directory = wide(session.folder.as_os_str())?;
        let system_root =
            std::env::var_os("SystemRoot").ok_or_else(|| invalid("SystemRoot missing"))?;
        let paths = format!(
            "{};{}\\System32",
            module_root.display(),
            system_root.to_string_lossy()
        );
        let entries = [
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1".to_owned()),
            (
                "LOCALAPPDATA",
                session.folder.to_string_lossy().into_owned(),
            ),
            ("PATH", paths),
            ("POWERSHELL_TELEMETRY_OPTOUT", "1".to_owned()),
            (
                "PSModulePath",
                module_root.join("Modules").to_string_lossy().into_owned(),
            ),
            ("SystemRoot", system_root.to_string_lossy().into_owned()),
            ("TEMP", session.folder.to_string_lossy().into_owned()),
            ("TMP", session.folder.to_string_lossy().into_owned()),
            ("USERPROFILE", session.folder.to_string_lossy().into_owned()),
        ];
        let mut environment = Vec::new();
        for (key, value) in entries {
            environment.extend(wide(OsStr::new(&format!("{key}={value}")))?);
        }
        for (key, value) in extra_environment {
            if !key.starts_with("ORBIT_REGISTRY_WITNESS_")
                || key.contains('=')
                || value.contains('\0')
            {
                return Err(invalid("unsupported test-only child environment entry"));
            }
            environment.extend(wide(OsStr::new(&format!("{key}={value}")))?);
        }
        environment.push(0);

        let (stdin_read, stdin_write) = pipe()?;
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        unsafe {
            ok(
                "SetHandleInformation",
                SetHandleInformation(stdout_read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0),
            )?;
            ok(
                "SetHandleInformation",
                SetHandleInformation(stderr_read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0),
            )?;
        }
        // EOF is the only supported stdin policy in this first production slice.
        drop(stdin_write);
        let mut runtime_capability = SID_AND_ATTRIBUTES {
            Sid: session.runtime_sid.as_ptr().cast_mut().cast(),
            Attributes: SE_GROUP_ENABLED as u32,
        };
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: session.sid.as_ptr().cast_mut().cast(),
            Capabilities: &mut runtime_capability,
            CapabilityCount: 1,
            Reserved: 0,
        };
        #[cfg(all(test, feature = "registry-diagnostic"))]
        let mut probe_capabilities = self::registry_probe_tests::requested_capabilities(session);
        #[cfg(all(test, feature = "registry-diagnostic"))]
        let capabilities = if probe_capabilities.is_empty() {
            capabilities
        } else {
            SECURITY_CAPABILITIES {
                AppContainerSid: session.sid.as_ptr().cast_mut().cast(),
                Capabilities: probe_capabilities.as_mut_ptr(),
                CapabilityCount: probe_capabilities.len() as u32,
                Reserved: 0,
            }
        };
        let policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let mut handles = vec![
            stdin_read.as_raw_handle(),
            stdout_write.as_raw_handle(),
            stderr_write.as_raw_handle(),
        ];
        handles.extend_from_slice(extra_handles);
        let mut attributes = Attributes::new(if less_privileged { 3 } else { 2 })?;
        attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
        if less_privileged {
            attributes.set(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &policy,
            )?;
        }
        attributes.set_handle_list(&handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin_read.as_raw_handle();
        startup.StartupInfo.hStdOutput = stdout_write.as_raw_handle();
        startup.StartupInfo.hStdError = stderr_write.as_raw_handle();
        startup.lpAttributeList = attributes.pointer();
        let job = own("CreateJobObjectW", unsafe {
            CreateJobObjectW(null(), null())
        })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            ok(
                "SetInformationJobObject",
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ),
            )?;
        }
        let mut info = PROCESS_INFORMATION::default();
        let create_status = unsafe {
            CreateProcessW(
                executable.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        let create_error = if create_status == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let inheritance_cleanup_error = after_create
            .as_deref_mut()
            .and_then(|cleanup| cleanup().err());
        if let Some(error) = create_error {
            let primary = operation_error("CreateProcessW", error);
            return Err(match inheritance_cleanup_error {
                Some(cleanup) => io::Error::other(format!(
                    "{primary}; immediate inherited-handle cleanup also failed: {cleanup}"
                )),
                None => primary,
            });
        }
        // SAFETY: successful CreateProcessW returns two new valid owned handles.
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
        let mut child = Self {
            session,
            process,
            job,
            stdout: File::from(stdout_read),
            stderr: File::from(stderr_read),
            assigned: false,
            finished: false,
            started: Instant::now(),
            timeout: spec.timeout,
            output_limit: spec.output_limit,
            evidence: ConfinementEvidence {
                app_container: false,
                less_privileged: false,
                network_capabilities: 0,
                job_assigned_before_resume: false,
                all_application_packages_grant: false,
                own_package_grant: false,
                total_capabilities: 0,
                runtime_capability_sid: None,
                runtime_capability_attributes: 0,
            },
        };
        unsafe {
            ok(
                "AssignProcessToJobObject",
                AssignProcessToJobObject(child.job.as_raw_handle(), child.process.as_raw_handle()),
            )?;
        }
        child.assigned = true;
        let mut token = null_mut();
        unsafe {
            ok(
                "OpenProcessToken",
                OpenProcessToken(
                    child.process.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token,
                ),
            )?;
        }
        let token = own("OpenProcessToken(handle)", token)?;
        let app_container = token_boolean(token.as_raw_handle(), TokenIsAppContainer)?;
        let access =
            inspect_lpac_access(unsafe { BorrowedHandle::borrow_raw(token.as_raw_handle()) })?;
        let less_privileged = access.is_less_privileged();
        let groups = token_buffer(
            token.as_raw_handle(),
            TokenCapabilities,
            "GetTokenInformation(TokenCapabilities)",
        )?;
        let count = unsafe { *groups.as_ptr().cast::<u32>() };
        let expected_count = 1;
        #[cfg(all(test, feature = "registry-diagnostic"))]
        let expected_count = if session.registry_probe_sid.is_some() {
            2
        } else {
            expected_count
        };
        if count != expected_count
            || groups.len() * size_of::<usize>()
                < std::mem::offset_of!(TOKEN_GROUPS, Groups)
                    + count as usize * size_of::<SID_AND_ATTRIBUTES>()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("actual token capability count/shape rejected: count={count}"),
            ));
        }
        let actual = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0] };
        let actual_sid = sid_text(actual.Sid)?;
        #[cfg(all(test, feature = "registry-diagnostic"))]
        if let Some(registry) = &session.registry_probe_sid {
            registry_probe_tests::verify_capabilities(&groups, registry)?;
        } else {
            verify_runtime_capability_set(&[(&actual_sid, actual.Attributes)])?;
        }
        #[cfg(not(all(test, feature = "registry-diagnostic")))]
        verify_runtime_capability_set(&[(&actual_sid, actual.Attributes)])?;
        let mut in_job = 0;
        unsafe {
            ok(
                "IsProcessInJob",
                IsProcessInJob(
                    child.process.as_raw_handle(),
                    child.job.as_raw_handle(),
                    &mut in_job,
                ),
            )?;
        }
        if !app_container || in_job == 0 {
            return Err(io::Error::other(format!(
                "child capability or Job verification failed: app_container={app_container}, access={access:?}, capabilities={count}, in_job={in_job}"
            )));
        }
        if let Some(error) = inheritance_cleanup_error {
            let cleanup = child.stop();
            if cleanup.is_ok() {
                child.finished = true;
            }
            drop(thread);
            return Err(match cleanup {
                Ok(()) => error,
                Err(stop_error) => io::Error::other(format!(
                    "inherited-handle cleanup failed: {error}; child termination/wait also failed: {stop_error}; Drop will retry and session state records unobserved shutdown"
                )),
            });
        }
        child.evidence = ConfinementEvidence {
            app_container,
            less_privileged,
            network_capabilities: 0,
            job_assigned_before_resume: true,
            all_application_packages_grant: access.all_application_packages_grant,
            own_package_grant: access.own_package_grant,
            total_capabilities: count,
            runtime_capability_sid: Some(RUNTIME_CAPABILITY_SID),
            runtime_capability_attributes: actual.Attributes,
        };
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);
        Ok((child, thread))
    }

    pub fn pid(&self) -> u32 {
        unsafe { GetProcessId(self.process.as_raw_handle()) }
    }
    pub fn evidence(&self) -> ConfinementEvidence {
        self.evidence
    }

    fn active(&self) -> io::Result<u32> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            ok(
                "QueryInformationJobObject",
                QueryInformationJobObject(
                    self.job.as_raw_handle(),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                ),
            )?;
        }
        Ok(info.ActiveProcesses)
    }

    fn stop(&mut self) -> io::Result<()> {
        unsafe {
            if self.assigned {
                ok(
                    "TerminateJobObject",
                    TerminateJobObject(self.job.as_raw_handle(), 1),
                )?;
            } else {
                ok(
                    "TerminateProcess",
                    TerminateProcess(self.process.as_raw_handle(), 1),
                )?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let process_done = process_completed(self.process.as_raw_handle())?;
            if process_done && (!self.assigned || self.active()? == 0) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned child completion not observed",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn wait(mut self, cancellation: &AtomicBool) -> io::Result<ProcessOutput> {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let (mut stdout_closed, mut stderr_closed) = (false, false);
        let mut completion = Completion::Exited;
        let stopped_before_wait = self.finished;
        let mut stopped = stopped_before_wait;
        loop {
            let mut exceeded = false;
            let budget = self
                .output_limit
                .saturating_sub(stdout.len() + stderr.len());
            if !stdout_closed {
                stdout_closed = pump(&mut self.stdout, &mut stdout, budget, &mut exceeded)?;
            }
            let budget = self
                .output_limit
                .saturating_sub(stdout.len() + stderr.len());
            if !stderr_closed {
                stderr_closed = pump(&mut self.stderr, &mut stderr, budget, &mut exceeded)?;
            }
            if !stopped {
                if cancellation.load(Ordering::Acquire) {
                    completion = Completion::Cancelled;
                } else if exceeded {
                    completion = Completion::OutputLimit;
                } else if self.started.elapsed() >= self.timeout {
                    completion = Completion::TimedOut;
                }
                if completion != Completion::Exited {
                    self.stop()?;
                    stopped = true;
                }
            } else if stopped_before_wait && exceeded {
                completion = Completion::OutputLimit;
            }
            let done = process_completed(self.process.as_raw_handle())?;
            if done && !stopped && self.active()? != 0 {
                self.stop()?;
                stopped = true;
            }
            if done && stdout_closed && stderr_closed && self.active()? == 0 {
                break;
            }
            if self.started.elapsed() > self.timeout + Duration::from_secs(6) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned pipe completion not observed",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut code = 0;
        unsafe {
            ok(
                "GetExitCodeProcess",
                GetExitCodeProcess(self.process.as_raw_handle(), &mut code),
            )?;
        }
        self.finished = true;
        Ok(ProcessOutput {
            code,
            stdout,
            stderr,
            completion,
            confinement: self.evidence,
        })
    }
}
impl Drop for OwnedProcess<'_> {
    fn drop(&mut self) {
        if !self.finished && self.stop().is_err() {
            self.session.unsafe_cleanup.store(true, Ordering::Release);
            #[cfg(all(test, feature = "registry-witness"))]
            self.session
                .registry_witness_child_unobserved
                .store(true, Ordering::Release);
        }
    }
}

fn pump(
    file: &mut File,
    output: &mut Vec<u8>,
    budget: usize,
    exceeded: &mut bool,
) -> io::Result<bool> {
    let mut available = 0;
    if unsafe {
        PeekNamedPipe(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &mut available,
            null_mut(),
        )
    } == 0
    {
        let error = unsafe { GetLastError() };
        return if error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA {
            Ok(true)
        } else {
            Err(operation_error(
                "PeekNamedPipe",
                io::Error::from_raw_os_error(error as i32),
            ))
        };
    }
    if available == 0 {
        return Ok(false);
    }
    let mut bytes = [0u8; 4096];
    let amount = (available as usize)
        .min(bytes.len())
        .min(budget.saturating_add(1));
    let read = file.read(&mut bytes[..amount])?;
    let accepted = read.min(budget);
    output.extend_from_slice(&bytes[..accepted]);
    *exceeded |= read > budget;
    Ok(read == 0)
}

#[cfg(all(test, feature = "registry-diagnostic"))]
mod registry_probe_tests {
    use super::*;
    use crate::fs::Directory;
    use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};

    fn evidence(name: &str, bytes: &[u8]) -> io::Result<()> {
        let root = std::env::var_os("ORBIT_NATIVE_EVIDENCE_DIR")
            .ok_or_else(|| invalid("diagnostic evidence directory missing"))?;
        std::fs::write(PathBuf::from(root).join(name), bytes)
    }

    fn fixture() -> io::Result<()> {
        for (name, value) in [
            ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("RUNNER_OS", "Windows"),
            (
                "GITHUB_REF",
                "refs/heads/codex/platform-first-run-windows-proof-20261105",
            ),
            (
                "ORBIT_REGISTRY_DIAGNOSTIC_FIXTURE",
                "github-hosted-fake-data-only-v1",
            ),
        ] {
            if std::env::var(name).as_deref() != Ok(value) {
                return Err(invalid(
                    "registry diagnostic requires its disposable CI fixture",
                ));
            }
        }
        let nonce =
            std::env::var("ORBIT_PROBE_NONCE").map_err(|_| invalid("missing fixture nonce"))?;
        if nonce.len() != 32 || !nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid("invalid fixture nonce"));
        }
        Ok(())
    }

    fn registry_sid() -> io::Result<Vec<u32>> {
        fixture()?;
        let name = wide(OsStr::new("registryRead"))?;
        let mut allocated = DerivedSids {
            groups: null_mut(),
            group_count: 0,
            capabilities: null_mut(),
            capability_count: 0,
        };
        unsafe {
            ok(
                "DeriveCapabilitySidsFromName(registryRead diagnostic)",
                DeriveCapabilitySidsFromName(
                    name.as_ptr(),
                    &mut allocated.groups,
                    &mut allocated.group_count,
                    &mut allocated.capabilities,
                    &mut allocated.capability_count,
                ),
            )?;
        }
        if allocated.capability_count != 1
            || allocated.capabilities.is_null()
            || allocated.group_count > 16
        {
            return Err(invalid("diagnostic capability derivation shape"));
        }
        let sid = unsafe { *allocated.capabilities };
        let text = sid_text(sid)?;
        if text == RUNTIME_CAPABILITY_SID
            || ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"].contains(&text.as_str())
        {
            return Err(invalid(
                "registry derivation returned a disallowed identity",
            ));
        }
        let mut report = format!("fixed_name=registryRead\napplication_sid={text}\n");
        for index in 0..allocated.group_count {
            report.push_str(&format!(
                "group_sid={}\n",
                sid_text(unsafe { *allocated.groups.add(index as usize) })?
            ));
        }
        evidence("registry-derivation.txt", report.as_bytes())?;
        let bytes = unsafe { GetLengthSid(sid) };
        if bytes == 0 || bytes > 68 {
            return Err(invalid("diagnostic SID length"));
        }
        let mut copy = vec![0u32; (bytes as usize).div_ceil(4)];
        unsafe {
            ok(
                "CopySid(registry diagnostic)",
                CopySid(bytes, copy.as_mut_ptr().cast(), sid),
            )?;
        }
        Ok(copy)
    }

    pub(super) fn requested_capabilities(session: &SandboxSession) -> Vec<SID_AND_ATTRIBUTES> {
        session
            .registry_probe_sid
            .as_ref()
            .map_or_else(Vec::new, |sid| {
                vec![
                    SID_AND_ATTRIBUTES {
                        Sid: session.runtime_sid.as_ptr().cast_mut().cast(),
                        Attributes: 4,
                    },
                    SID_AND_ATTRIBUTES {
                        Sid: sid.as_ptr().cast_mut().cast(),
                        Attributes: 4,
                    },
                ]
            })
    }

    pub(super) fn verify_capabilities(groups: &[usize], registry: &[u32]) -> io::Result<()> {
        fixture()?;
        let registry = sid_text(registry.as_ptr().cast_mut().cast())?;
        let entries = unsafe {
            std::slice::from_raw_parts(
                groups
                    .as_ptr()
                    .cast::<u8>()
                    .add(std::mem::offset_of!(TOKEN_GROUPS, Groups))
                    .cast::<SID_AND_ATTRIBUTES>(),
                2,
            )
        };
        let mut actual: Vec<_> = entries
            .iter()
            .map(|entry| Ok((sid_text(entry.Sid)?, entry.Attributes)))
            .collect::<io::Result<_>>()?;
        actual.sort();
        evidence("registry-actual-token.txt", format!(
            "actual_capabilities={actual:?}\ntotal_capabilities=2\nexplicit_network_capabilities=0\nproduction_policy_unchanged=true\n").as_bytes())?;
        let mut expected = vec![(RUNTIME_CAPABILITY_SID.to_owned(), 4), (registry, 4)];
        expected.sort();
        if actual != expected {
            return Err(invalid("diagnostic actual token SID/attribute mismatch"));
        }
        let borrowed: Vec<_> = actual
            .iter()
            .map(|(sid, flags)| (sid.as_str(), *flags))
            .collect();
        if verify_runtime_capability_set(&borrowed).is_ok() {
            return Err(invalid(
                "production singleton unexpectedly accepted diagnostic capabilities",
            ));
        }
        Ok(())
    }

    fn literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn endpoint() -> io::Result<SocketAddr> {
        for address in ("api.github.com", 443)
            .to_socket_addrs()?
            .filter(|a| a.is_ipv4())
            .take(4)
        {
            let std::net::IpAddr::V4(ip) = address.ip() else {
                unreachable!()
            };
            if ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
            {
                continue;
            }
            if let Ok(control) = TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
                if control.peer_addr()? == address && control.local_addr()?.ip() != address.ip() {
                    return Ok(address);
                }
            }
        }
        Err(io::Error::other(
            "nonlocal parent TCP positive control unavailable",
        ))
    }

    // A single explicitly selected real measurement; absent fixture is a failure.
    #[test]
    fn registry_read_fake_data_measurement() {
        let result = measure();
        if let Err(error) = &result {
            let _ = evidence(
                "registry-measurement-error.txt",
                format!("{error:?}\n").as_bytes(),
            );
        }
        result.unwrap();
    }

    fn measure() -> io::Result<()> {
        fixture()?;
        let mut session = SandboxSession::create()?;
        session.registry_probe_sid = Some(registry_sid()?);
        session.prepare_file(OsStr::new("seed.txt"), b"owned seed")?;
        let outside =
            std::env::temp_dir().join(format!("{}-registry-probe", session.profile_name()));
        let directory = Directory::create(&outside)?;
        let mut credential = directory.create_file(OsStr::new("credentials.json"))?;
        credential.write_all(b"synthetic-private-file-credential")?;
        credential.sync_all()?;
        let secret = outside.join("credentials.json");
        let forbidden = outside.join("forbidden.txt");
        let remote = endpoint()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let loopback = listener.local_addr()?;
        drop(TcpStream::connect_timeout(
            &loopback,
            Duration::from_secs(3),
        )?);
        drop(listener.accept()?.0);
        evidence(
            "registry-network-parent.txt",
            format!("nonlocal={remote}\nloopback={loopback}\nTCP_handshake_only=true\n").as_bytes(),
        )?;
        let nonce = std::env::var("ORBIT_PROBE_NONCE").map_err(|_| invalid("nonce"))?;
        let user =
            std::env::var("ORBIT_PROBE_ORIGINAL_SID").map_err(|_| invalid("original SID"))?;
        if !user.starts_with("S-1-5-")
            || !user
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
        {
            return Err(invalid("fixture user SID shape"));
        }
        let machine_hash =
            std::env::var("ORBIT_PROBE_MACHINE_HASH").map_err(|_| invalid("machine hash"))?;
        let user_hash = std::env::var("ORBIT_PROBE_USER_HASH").map_err(|_| invalid("user hash"))?;
        for hash in [&machine_hash, &user_hash] {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("fixture hash shape"));
            }
        }
        let script = REGISTRY_SCRIPT
            .replace("@@NONCE@@", &literal(&nonce))
            .replace("@@USER@@", &literal(&user))
            .replace("@@MACHINE_HASH@@", &literal(&machine_hash))
            .replace("@@USER_HASH@@", &literal(&user_hash))
            .replace("@@SECRET@@", &literal(&secret.to_string_lossy()))
            .replace("@@FORBIDDEN@@", &literal(&forbidden.to_string_lossy()))
            .replace("@@REMOTE@@", &literal(&remote.ip().to_string()))
            .replace("@@REMOTE_PORT@@", &remote.port().to_string())
            .replace("@@LOOPBACK_PORT@@", &loopback.port().to_string());
        let held = session.prepare_script(OsStr::new("registry-measurement.ps1"), &script)?;
        let executable = PathBuf::from(
            std::env::var_os("ORBIT_TEST_POWERSHELL")
                .ok_or_else(|| invalid("PowerShell identity missing"))?,
        );
        let spec = SpawnSpec {
            executable,
            arguments: vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-File".into(),
                held.path()
                    .to_str()
                    .ok_or_else(|| invalid("script encoding"))?
                    .into(),
            ],
            timeout: Duration::from_secs(60),
            output_limit: 131072,
        };
        let (child, thread) = OwnedProcess::create_suspended(&session, &spec, true)?;
        if !child.evidence.app_container
            || !child.evidence.less_privileged
            || !child.evidence.job_assigned_before_resume
        {
            return Err(invalid("diagnostic LPAC/Job admission failed"));
        }
        evidence(
            "registry-admission.txt",
            format!(
                "{:?}\nscript_identity={:?}\n",
                child.evidence,
                held.identity()
            )
            .as_bytes(),
        )?;
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(operation_error(
                "ResumeThread(registry diagnostic)",
                io::Error::last_os_error(),
            ));
        }
        drop(thread);
        let output = child.wait(&AtomicBool::new(false))?;
        evidence("registry-child-stdout.txt", &output.stdout)?;
        evidence("registry-child-stderr.txt", &output.stderr)?;
        evidence(
            "registry-completion.txt",
            format!(
                "code={}\ncompletion={:?}\nobserved_process_and_zero_job_completion=true\n",
                output.code, output.completion
            )
            .as_bytes(),
        )?;
        let payload = session.read_file(OsStr::new("registry-probe.json"), 65536);
        if let Ok(payload) = &payload {
            evidence("registry-probe-payload.json", payload)?;
        }
        let succeeded = output.code == 0
            && output.completion == Completion::Exited
            && String::from_utf8_lossy(&output.stdout).contains("REGISTRY_PROBE_COMPLETE")
            && payload.is_ok()
            && session
                .read_file(OsStr::new("result.txt"), 64)
                .ok()
                .as_deref()
                == Some(b"owned write")
            && !forbidden.exists()
            && std::fs::read(&secret)? == b"synthetic-private-file-credential";
        drop(held);
        session.close()?;
        drop(credential);
        drop(directory);
        std::fs::remove_file(secret)?;
        std::fs::remove_dir(outside)?;
        if !succeeded {
            return Err(io::Error::other(
                "registry measurement incomplete; inspect retained runtime evidence",
            ));
        }
        Ok(())
    }

    const REGISTRY_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$nonce=@@NONCE@@; $originalSid=@@USER@@
$machineName='ORBIT_FAKE_MACHINE_'+$nonce; $userName='ORBIT_FAKE_USER_'+$nonce
$writeName='ORBIT_FAKE_WRITE_'+$nonce; $configName='ORBIT_PUBLIC_CONFIG_'+$nonce
$machineKey='SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$userKey=$originalSid+'\Environment'
$rows=[Collections.Generic.List[object]]::new()
$mustDeny=$true; $complete=$true; $exposed=$false; $stage='initialization'
function Digest([string]$value) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($value))) }
function ExceptionEvidence([Exception]$exception) {
  $chain=[Collections.Generic.List[object]]::new()
  $ambiguous=$false; $depth=0; $leaf=$null
  while($null -ne $exception -and $depth -lt 8) {
    $entry=[ordered]@{type=$exception.GetType().FullName;hresult=$exception.HResult}
    if($exception -is [Net.Sockets.SocketException]) {
      $entry.native_error=$exception.NativeErrorCode
      $entry.socket_error=$exception.SocketErrorCode.ToString()
    }
    if($exception -is [AggregateException] -and $exception.InnerExceptions.Count -ne 1) {
      $ambiguous=$true
    }
    $chain.Add([pscustomobject]$entry)
    $leaf=$exception; $exception=$exception.InnerException; $depth++
  }
  $truncated=$null -ne $exception
  $socketDenied=-not $truncated -and -not $ambiguous -and
    $leaf -is [Net.Sockets.SocketException] -and $leaf.NativeErrorCode -eq 10013 -and
    $leaf.SocketErrorCode -eq [Net.Sockets.SocketError]::AccessDenied
  [pscustomobject]@{chain=@($chain.ToArray());truncated=$truncated;ambiguous_aggregate=$ambiguous;socket_access_denied=$socketDenied}
}


function Observe([string]$id,[scriptblock]$action,[string]$expected,[bool]$protected) {
  $script:stage='registry_'+$id
  $row=[ordered]@{id=$id; stage=$script:stage; status='api_error'; protected_credential=$protected}
  try {
    $value=& $action
    if ($null -eq $value) { $row.status='not_found' }
    else {
      $row.status='readable'; $row.sha256=Digest ([string]$value)
      $row.matches_fixture=$row.sha256 -eq $expected
      if (-not $row.matches_fixture) { $script:complete=$false }
      if ($protected) { $script:exposed=$true }
    }
  } catch {
    $row.exception_evidence=ExceptionEvidence $_.Exception
    $cause=$_.Exception; while ($cause.InnerException) { $cause=$cause.InnerException }
    $row.exception=$cause.GetType().FullName; $row.hresult=$cause.HResult
    if($cause -is [ComponentModel.Win32Exception]){$row.native_error=$cause.NativeErrorCode}
    if ($cause -is [UnauthorizedAccessException] -or $cause -is [Security.SecurityException] -or
        ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 5)) { $row.status='denied' }
    else { $row.status='api_error'; $script:complete=$false }
  }
  $script:rows.Add([pscustomobject]$row)
}
function MustDeny([string]$id,[scriptblock]$action) {
  $script:stage='must_deny_'+$id
  $denied=$false
  $exceptionEvidence=$null
  try { & $action | Out-Null } catch {
    $exceptionEvidence=ExceptionEvidence $_.Exception
    $cause=$_.Exception; while ($cause.InnerException) { $cause=$cause.InnerException }
    $denied=$cause -is [UnauthorizedAccessException] -or $cause -is [Security.SecurityException]
  }
  $script:rows.Add([pscustomobject]@{id=$id; status=$(if($denied){'denied'}else{'must_deny_failed'});exception_evidence=$exceptionEvidence})
  if (-not $denied) { $script:mustDeny=$false }
}
function NetworkDenied([string]$address,[int]$port,[string]$id) {
  if($id -notin @('loopback','nonlocal')){throw 'invalid fixed network stage'}
  $client=$null; $denied=$false; $exceptionEvidence=$null; $disposeEvidence=$null
  $outcome='incomplete'; $connectInvoked=$false
  $script:stage='network_'+$id+'_construct'
  try {
    $client=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
    $script:stage='network_'+$id+'_connect'
    $connectInvoked=$true
    $task=$client.ConnectAsync([Net.IPAddress]::Parse($address),$port)
    $script:stage='network_'+$id+'_wait'
    if(-not $task.Wait(5000)){throw [TimeoutException]::new('bounded network probe timed out')}
    $outcome='connected'
  } catch {
    $exceptionEvidence=ExceptionEvidence $_.Exception
    $denied=$exceptionEvidence.socket_access_denied -eq $true
    $outcome=if($denied){'policy_denied'}else{'incomplete_exception'}
  } finally {
    if($null -ne $client){
      try{$client.Dispose()}catch{$disposeEvidence=ExceptionEvidence $_.Exception;$script:complete=$false}
    }
  }
  $deniedOperation=if(-not $denied){$null}elseif(-not $connectInvoked){'socket_creation'}elseif($script:stage.EndsWith('_wait')){'async_connect_wait'}else{'connect_invocation'}
  $script:rows.Add([pscustomobject]@{id=$id;stage=$script:stage;attempt_outcome=$outcome;
    connect_invoked=$connectInvoked;denied_operation=$deniedOperation;
    status=$(if($denied){'denied_wsaeacces'}else{'inconclusive_or_allowed'});
    exception_evidence=$exceptionEvidence;dispose_exception_evidence=$disposeEvidence})
  if(-not $denied){$script:mustDeny=$false}
}
try {
  $stage='owned_read_write'
  if([IO.File]::ReadAllText('seed.txt') -ne 'owned seed'){throw 'owned read mismatch'}
  [IO.File]::WriteAllText('result.txt','owned write')
  $stage='runtime_identity_module'
  $identity=$PSVersionTable.PSEdition+':'+$PSVersionTable.PSVersion.ToString()
  $runtime=[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
  $module=Get-Date -Format yyyy
  MustDeny 'private_credential_file' { [IO.File]::ReadAllText(@@SECRET@@) }
  MustDeny 'outside_write' { [IO.File]::WriteAllText(@@FORBIDDEN@@,'bad') }
  $stage='process_credential'
  $processAbsent=$null -eq [Environment]::GetEnvironmentVariable('ORBIT_FAKE_SECRET')
  $rows.Add([pscustomobject]@{id='process_credential'; status=$(if($processAbsent){'absent'}else{'must_deny_failed'})})
  if(-not $processAbsent){$mustDeny=$false}
  NetworkDenied '127.0.0.1' @@LOOPBACK_PORT@@ 'loopback'
  NetworkDenied @@REMOTE@@ @@REMOTE_PORT@@ 'nonlocal'
  Observe 'dotnet_machine' { [Environment]::GetEnvironmentVariable($machineName,[EnvironmentVariableTarget]::Machine) } @@MACHINE_HASH@@ $true
  Observe 'dotnet_mapped_user' { [Environment]::GetEnvironmentVariable($userName,[EnvironmentVariableTarget]::User) } @@USER_HASH@@ $true
  Observe 'dotnet_original_user' {
    $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,[Microsoft.Win32.RegistryView]::Registry64)
    try { $key=$root.OpenSubKey($userKey); if($null -eq $key){return $null}; try{$key.GetValue($userName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}finally{$key.Dispose()} }finally{$root.Dispose()}
  } @@USER_HASH@@ $true
  Observe 'provider_machine' { Get-ItemPropertyValue -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\'+$machineKey) -Name $machineName -ErrorAction Stop } @@MACHINE_HASH@@ $true
  Observe 'provider_original_user' { Get-ItemPropertyValue -LiteralPath ('Registry::HKEY_USERS\'+$userKey) -Name $userName -ErrorAction Stop } @@USER_HASH@@ $true
  Observe 'public_configuration' { [Environment]::GetEnvironmentVariable($configName,[EnvironmentVariableTarget]::Machine) } (Digest 'public-fixture-config') $false
  MustDeny 'original_user_registry_write' {
    $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,[Microsoft.Win32.RegistryView]::Registry64)
    try{$key=$root.OpenSubKey($userKey,$true); if($null -eq $key){throw 'missing write fixture'}; try{$key.SetValue($writeName,('child-change:'+$nonce),[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}finally{$root.Dispose()}
  }
  try {
    $stage='win32_declarations'
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class OrbitRegistryProbe {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegOpenKeyExW(IntPtr key,string path,uint options,uint access,out IntPtr result);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegQueryValueExW(IntPtr key,string name,IntPtr reserved,out uint type,byte[] bytes,ref uint size);
 [DllImport("advapi32.dll",ExactSpelling=true)] static extern int RegCloseKey(IntPtr key);
 public static string Read(int root,string path,string name) {
  IntPtr key; int status=RegOpenKeyExW(new IntPtr(root),path,0,0x20119,out key);
  if(status==2)return null; if(status!=0)throw new System.ComponentModel.Win32Exception(status);
  try { uint type,size=0; status=RegQueryValueExW(key,name,IntPtr.Zero,out type,null,ref size);
   if(status==2)return null; if(status!=0 && status!=234)throw new System.ComponentModel.Win32Exception(status);
   if(size==0 || size>8192)throw new InvalidOperationException("fixture size");
   byte[] bytes=new byte[size]; status=RegQueryValueExW(key,name,IntPtr.Zero,out type,bytes,ref size);
   if(status!=0)throw new System.ComponentModel.Win32Exception(status);
   if(type!=1 || size%2!=0)throw new InvalidOperationException("fixture type");
   return Encoding.Unicode.GetString(bytes,0,(int)size).TrimEnd('\0');
  }finally{RegCloseKey(key);}
 }
}
'@
    Observe 'win32_machine' { [OrbitRegistryProbe]::Read(-2147483646,$machineKey,$machineName) } @@MACHINE_HASH@@ $true
    Observe 'win32_mapped_user' { [OrbitRegistryProbe]::Read(-2147483647,'Environment',$userName) } @@USER_HASH@@ $true
    Observe 'win32_original_user' { [OrbitRegistryProbe]::Read(-2147483645,$userKey,$userName) } @@USER_HASH@@ $true
  }catch{$complete=$false; $rows.Add([pscustomobject]@{id='win32_probe';stage=$stage;status='unavailable';exception_evidence=(ExceptionEvidence $_.Exception)})}
}catch{$complete=$false; $rows.Add([pscustomobject]@{id='runtime_or_script';stage=$stage;status='failed';exception_evidence=(ExceptionEvidence $_.Exception)})}
$boundary=if(-not $mustDeny){'failed_must_deny'}elseif($exposed){'unresolved_exposed_persisted_credential'}elseif($complete){'no_exposure_observed'}else{'not_measured'}
$payload=[ordered]@{measurement_status=$(if($complete -and $mustDeny){'complete'}else{'incomplete'});last_stage=$stage;credential_boundary_status=$boundary;production_policy_unchanged=$true;production_support_pass=$false;nonce=$nonce;original_user_sid=$originalSid;registry_view=64;identity=$identity;runtime=$runtime;module=$module;observations=@($rows.ToArray())}
[IO.File]::WriteAllText('registry-probe.json',($payload|ConvertTo-Json -Depth 8))
if($complete -and $mustDeny){[Console]::WriteLine('REGISTRY_PROBE_COMPLETE');exit 0}else{exit 7}
"#;
}

// The strict registry witness is intentionally separate from the broad
// registryRead diagnostic above.  Its private resource owners are cfg-gated
// from all production and ordinary test builds.
#[cfg(all(test, feature = "registry-witness"))]
mod registry_witness_tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::io::{Read, Seek};
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Wdk::Foundation::NtClose;
    use windows_sys::Wdk::System::Registry::{
        KeyValuePartialInformation, NtOpenKey, NtQueryValueKey,
    };
    use windows_sys::Wdk::System::SystemServices::KEY_VALUE_PARTIAL_INFORMATION;
    use windows_sys::Win32::Security::Authorization::{SDDL_REVISION_1, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_OBJECT_LENGTH, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider,
        BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
        BCryptOpenAlgorithmProvider,
    };
    use windows_sys::Win32::System::Registry::*;

    const WITNESS_FRAME_START: &[u8] = b"\x1eORBITW1:";
    const WITNESS_FRAME_END: u8 = 0x1f;

    fn emit_witness_record(payload: &str) -> io::Result<()> {
        if payload.len() > 8192
            || !payload.is_ascii()
            || payload.contains('\u{1e}')
            || payload.contains('\u{1f}')
        {
            return Err(invalid("registry witness record exceeds framing bounds"));
        }
        let mut output = io::stdout().lock();
        write!(output, "\x1eORBITW1:{}:", payload.len())?;
        output.write_all(payload.as_bytes())?;
        output.write_all(&[WITNESS_FRAME_END])?;
        output.flush()
    }

    fn escape_diagnostic(bytes: &[u8]) -> String {
        let bounded = &bytes[..bytes.len().min(1024)];
        let mut escaped = String::with_capacity(bounded.len());
        for byte in bounded {
            if (0x20..=0x7e).contains(byte) && *byte != b'\\' {
                escaped.push(*byte as char);
            } else {
                escaped.push_str(&format!("\\x{byte:02X}"));
            }
        }
        escaped
    }

    /// Registry keys are not kernel HANDLE owners: RegCloseKey is required.
    pub(super) struct OwnedRegKey(HKEY);

    impl OwnedRegKey {
        /// # Safety
        /// `key` must be a successful, uniquely transferred registry handle.
        unsafe fn from_raw(key: HKEY) -> io::Result<Self> {
            if key.is_null() {
                Err(invalid("null registry key"))
            } else {
                Ok(Self(key))
            }
        }

        pub(super) fn raw(&self) -> HKEY {
            self.0
        }

        pub(super) fn close(self) -> io::Result<()> {
            let key = self.0;
            std::mem::forget(self);
            let status = unsafe { RegCloseKey(key) };
            if status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            }
        }
    }

    impl Drop for OwnedRegKey {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { RegCloseKey(self.0) };
            }
        }
    }

    /// Raw NtOpenKey handles have the native NtClose ownership contract.
    struct OwnedNtKey(HANDLE);

    impl OwnedNtKey {
        /// # Safety
        /// `key` must be a successful, uniquely transferred native key handle.
        unsafe fn from_raw(key: HANDLE) -> io::Result<Self> {
            if key.is_null() || key == INVALID_HANDLE_VALUE {
                Err(invalid("invalid native registry key"))
            } else {
                Ok(Self(key))
            }
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn close(self) -> io::Result<()> {
            let key = self.0;
            std::mem::forget(self);
            let status = unsafe { NtClose(key) };
            if status >= 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(status))
            }
        }
    }

    impl Drop for OwnedNtKey {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { NtClose(self.0) };
            }
        }
    }

    fn nt_unicode(value: &str) -> io::Result<(Vec<u16>, UNICODE_STRING)> {
        let mut storage: Vec<u16> = value.encode_utf16().collect();
        let byte_len = storage
            .len()
            .checked_mul(size_of::<u16>())
            .filter(|length| *length <= u16::MAX as usize - size_of::<u16>())
            .ok_or_else(|| invalid("native registry name exceeds UNICODE_STRING limits"))?;
        storage.push(0);
        let value = UNICODE_STRING {
            Length: byte_len as u16,
            MaximumLength: (byte_len + size_of::<u16>()) as u16,
            Buffer: storage.as_mut_ptr(),
        };
        Ok((storage, value))
    }

    fn nt_open_key(path: &str, access: u32) -> Result<OwnedNtKey, i32> {
        let (mut path_storage, mut object_name) =
            nt_unicode(path).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let mut attributes = OBJECT_ATTRIBUTES::default();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = null_mut();
        attributes.ObjectName = &mut object_name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        attributes.SecurityDescriptor = null_mut();
        attributes.SecurityQualityOfService = null_mut();
        let mut handle = null_mut();
        let status = unsafe { NtOpenKey(&mut handle, access, &attributes) };
        // Keep the backing UTF-16 storage alive through the system call.
        std::hint::black_box(&mut path_storage);
        if status < 0 {
            return Err(status);
        }
        // SAFETY: NtOpenKey succeeded and transferred one newly created handle.
        unsafe { OwnedNtKey::from_raw(handle).map_err(|_| STATUS_INVALID_HANDLE) }
    }

    fn nt_query_value(key: &OwnedNtKey, name: &str) -> Result<(u32, Vec<u8>), i32> {
        let (mut name_storage, value_name) =
            nt_unicode(name).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let mut buffer = [0u8; 4096];
        let mut returned = 0u32;
        let status = unsafe {
            NtQueryValueKey(
                key.raw(),
                &value_name,
                KeyValuePartialInformation,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut returned,
            )
        };
        std::hint::black_box(&mut name_storage);
        if status < 0 {
            return Err(status);
        }
        decode_partial_key_value(&buffer, returned as usize)
    }

    fn decode_partial_key_value(buffer: &[u8], returned: usize) -> Result<(u32, Vec<u8>), i32> {
        let type_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Type);
        let length_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, DataLength);
        let data_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Data);
        let field_end = |offset: usize| {
            offset
                .checked_add(size_of::<u32>())
                .ok_or(STATUS_INFO_LENGTH_MISMATCH)
        };
        if returned > buffer.len() || returned < data_offset {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let type_end = field_end(type_offset)?;
        let length_end = field_end(length_offset)?;
        if type_end > returned || length_end > returned {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        // The buffer has byte alignment only. Decode the actual named fields
        // without constructing a potentially unaligned typed reference.
        let value_type = u32::from_le_bytes(
            buffer[type_offset..type_end]
                .try_into()
                .map_err(|_| STATUS_INFO_LENGTH_MISMATCH)?,
        );
        let length = u32::from_le_bytes(
            buffer[length_offset..length_end]
                .try_into()
                .map_err(|_| STATUS_INFO_LENGTH_MISMATCH)?,
        ) as usize;
        let data_end = data_offset
            .checked_add(length)
            .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
        if data_end > returned || data_end > buffer.len() {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        Ok((value_type, buffer[data_offset..data_end].to_vec()))
    }

    fn verify_partial_key_value_header_oracle() -> io::Result<()> {
        let type_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Type);
        let length_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, DataLength);
        let data_offset = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Data);
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // ignored TitleIndex
        bytes[type_offset..type_offset + 4].copy_from_slice(&REG_SZ.to_le_bytes());
        bytes[length_offset..length_offset + 4].copy_from_slice(&2u32.to_le_bytes());
        bytes[data_offset..data_offset + 2].copy_from_slice(&[0x5A, 0xC3]);
        let parsed = decode_partial_key_value(&bytes, data_offset + 2)
            .map_err(io::Error::from_raw_os_error)?;
        if parsed != (REG_SZ, vec![0x5A, 0xC3]) {
            return Err(invalid(
                "synthetic registry result header offset oracle failed",
            ));
        }
        Ok(())
    }

    fn digest(bytes: &[u8]) -> io::Result<String> {
        let mut algorithm = null_mut();
        let mut hash = null_mut();
        let mut object_size = 0u32;
        let mut returned = 0u32;
        let mut object = Vec::<u64>::new();
        let mut output = [0u8; 32];
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, null(), 0)
        };
        if status < 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        let result = (|| {
            let status = unsafe {
                BCryptGetProperty(
                    algorithm,
                    BCRYPT_OBJECT_LENGTH,
                    (&mut object_size as *mut u32).cast(),
                    size_of::<u32>() as u32,
                    &mut returned,
                    0,
                )
            };
            if status < 0
                || returned != size_of::<u32>() as u32
                || object_size == 0
                || object_size > 65536
            {
                return Err(io::Error::other("BCrypt object-size query failed"));
            }
            object.resize((object_size as usize).div_ceil(size_of::<u64>()), 0);
            let status = unsafe {
                BCryptCreateHash(
                    algorithm,
                    &mut hash,
                    object.as_mut_ptr().cast(),
                    object_size,
                    null(),
                    0,
                    0,
                )
            };
            if status < 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            let status = unsafe { BCryptHashData(hash, bytes.as_ptr(), bytes.len() as u32, 0) };
            if status < 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            let status =
                unsafe { BCryptFinishHash(hash, output.as_mut_ptr(), output.len() as u32, 0) };
            if status < 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            Ok(())
        })();
        if !hash.is_null() {
            unsafe { BCryptDestroyHash(hash) };
        }
        unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
        result?;
        Ok(output.iter().map(|byte| format!("{byte:02X}")).collect())
    }

    fn registry_string_digest(bytes: &[u8]) -> io::Result<String> {
        if bytes.len() < 2 || bytes.len() % 2 != 0 {
            return Err(invalid("registry marker is not bounded UTF-16 REG_SZ data"));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("registry marker lacks a UTF-16 terminator"))?;
        if units[end..].iter().any(|unit| *unit != 0) {
            return Err(invalid("registry marker has nonzero trailing data"));
        }
        let value = String::from_utf16(&units[..end])
            .map_err(|_| invalid("registry marker contains invalid UTF-16"))?;
        digest(value.as_bytes())
    }

    fn parent_marker_controls(timing: &str) -> io::Result<()> {
        let machine_name = std::env::var("ORBIT_REGISTRY_WITNESS_MACHINE_MARKER")
            .map_err(|_| invalid("machine marker identity missing"))?;
        let user_name = std::env::var("ORBIT_REGISTRY_WITNESS_USER_MARKER")
            .map_err(|_| invalid("user marker identity missing"))?;
        let expected_machine = std::env::var("ORBIT_REGISTRY_WITNESS_MACHINE_HASH")
            .map_err(|_| invalid("machine marker digest missing"))?;
        let expected_user = std::env::var("ORBIT_REGISTRY_WITNESS_USER_HASH")
            .map_err(|_| invalid("user marker digest missing"))?;
        let user_sid = std::env::var("ORBIT_REGISTRY_WITNESS_USER_SID")
            .map_err(|_| invalid("original user SID missing"))?;
        let machine_path = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        let user_path = format!("{user_sid}\\Environment");
        let machine_nt =
            "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        let user_nt = format!("\\Registry\\User\\{user_sid}\\Environment");
        for (api, root, path, native, name, expected) in [
            (
                "win32",
                HKEY_LOCAL_MACHINE,
                machine_path,
                machine_nt,
                machine_name.as_str(),
                expected_machine.as_str(),
            ),
            (
                "win32",
                HKEY_USERS,
                user_path.as_str(),
                user_nt.as_str(),
                user_name.as_str(),
                expected_user.as_str(),
            ),
        ] {
            let key = win32_open_key(root, path, KEY_QUERY_VALUE)
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let observed = registry_string_digest(
                &win32_query_value(&key, name)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
            )?;
            if !observed.eq_ignore_ascii_case(expected) {
                return Err(io::Error::other("Win32 fake marker digest changed"));
            }
            emit_witness_record(&format!(
                "registry_witness_probe id=parent_present/{timing}/{api}/{} status=0 observed=true sha256={observed}",
                if api == "win32" && root == HKEY_LOCAL_MACHINE {
                    "machine"
                } else {
                    "user"
                }
            ))?;
            let native_key =
                nt_open_key(native, KEY_QUERY_VALUE).map_err(io::Error::from_raw_os_error)?;
            let (kind, value) =
                nt_query_value(&native_key, name).map_err(io::Error::from_raw_os_error)?;
            if kind != REG_SZ || !registry_string_digest(&value)?.eq_ignore_ascii_case(expected) {
                return Err(io::Error::other("native fake marker control changed"));
            }
            let target = if root == HKEY_LOCAL_MACHINE {
                "machine"
            } else {
                "user"
            };
            emit_witness_record(&format!(
                "registry_witness_probe id=parent_present/{timing}/nt/{target} status=0 observed=true sha256={}",
                registry_string_digest(&value)?
            ))?;
        }
        Ok(())
    }

    fn win32_open_key(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> Result<OwnedRegKey, u32> {
        let path = wide(OsStr::new(path)).map_err(|_| ERROR_INVALID_PARAMETER)?;
        let mut key = null_mut();
        let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, access, &mut key) };
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        // SAFETY: RegOpenKeyExW succeeded and returned a uniquely owned key.
        unsafe { OwnedRegKey::from_raw(key).map_err(|_| ERROR_INVALID_HANDLE) }
    }

    fn win32_query_value(key: &OwnedRegKey, name: &str) -> Result<Vec<u8>, u32> {
        win32_query_value_handle(key.raw(), name)
    }

    fn win32_query_value_type(key: HKEY, name: &str) -> Result<u32, u32> {
        let name = wide(OsStr::new(name)).map_err(|_| ERROR_INVALID_PARAMETER)?;
        let mut value_type = 0u32;
        let mut length = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut length,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(value_type)
        } else {
            Err(status)
        }
    }

    fn win32_query_value_handle(key: HKEY, name: &str) -> Result<Vec<u8>, u32> {
        let name = wide(OsStr::new(name)).map_err(|_| ERROR_INVALID_PARAMETER)?;
        let mut value_type = 0u32;
        let mut length = 0u32;
        let first = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut length,
            )
        };
        if first != ERROR_SUCCESS {
            return Err(first);
        }
        if length == 0 || length > 4096 {
            return Err(ERROR_INVALID_DATA);
        }
        let mut bytes = vec![0u8; length as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                null_mut(),
                &mut value_type,
                bytes.as_mut_ptr(),
                &mut length,
            )
        };
        if status != ERROR_SUCCESS || value_type != REG_SZ || length as usize > bytes.len() {
            return Err(if status == ERROR_SUCCESS {
                ERROR_INVALID_DATA
            } else {
                status
            });
        }
        bytes.truncate(length as usize);
        Ok(bytes)
    }

    #[derive(PartialEq, Eq)]
    struct PrivateViewPreimage {
        mutation: Vec<u8>,
        metadata_fixture: Vec<u8>,
        delete_fixture: Vec<u8>,
        root_security: Vec<u8>,
        delete_security: Vec<u8>,
    }

    impl PrivateViewPreimage {
        fn digest(&self) -> io::Result<String> {
            let mut bytes = Vec::new();
            for item in [
                &self.mutation,
                &self.metadata_fixture,
                &self.delete_fixture,
                &self.root_security,
                &self.delete_security,
            ] {
                let length = u32::try_from(item.len())
                    .map_err(|_| invalid("registry preimage field exceeds bound"))?;
                bytes.extend_from_slice(&length.to_le_bytes());
                bytes.extend_from_slice(item);
            }
            digest(&bytes)
        }
    }

    fn registry_key_security(key: HKEY) -> io::Result<Vec<u8>> {
        let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut length = 0u32;
        let first = unsafe { RegGetKeySecurity(key, information, null_mut(), &mut length) };
        if first != ERROR_INSUFFICIENT_BUFFER || length == 0 || length > 65536 {
            return Err(io::Error::other(format!(
                "RegGetKeySecurity(size) returned {first} with length {length}"
            )));
        }
        let words = (length as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        let status = unsafe {
            RegGetKeySecurity(key, information, storage.as_mut_ptr().cast(), &mut length)
        };
        if status != ERROR_SUCCESS
            || length == 0
            || length > (storage.len() * size_of::<usize>()) as u32
        {
            return Err(io::Error::other(format!(
                "RegGetKeySecurity(data) returned {status} with length {length}"
            )));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
        Ok(bytes.to_vec())
    }

    fn private_view_preimage(root: HKEY) -> io::Result<PrivateViewPreimage> {
        let mut metadata = None;
        let mut delete_leaf = None;
        let observed = (|| -> io::Result<PrivateViewPreimage> {
            metadata = Some(
                win32_open_key(root, "Metadata", KEY_READ)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
            );
            delete_leaf = Some(
                win32_open_key(root, "DeleteLeaf", KEY_READ)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
            );
            let metadata = metadata
                .as_ref()
                .ok_or_else(|| invalid("Metadata observer missing"))?;
            let delete_leaf = delete_leaf
                .as_ref()
                .ok_or_else(|| invalid("DeleteLeaf observer missing"))?;
            Ok(PrivateViewPreimage {
                mutation: win32_query_value_handle(root, "Mutation")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                metadata_fixture: win32_query_value(metadata, "Fixture")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                delete_fixture: win32_query_value(delete_leaf, "Fixture")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                root_security: registry_key_security(root)?,
                delete_security: registry_key_security(delete_leaf.raw())?,
            })
        })();
        let mut close_errors = Vec::new();
        if let Some(delete_leaf) = delete_leaf.take() {
            if let Err(error) = delete_leaf.close() {
                close_errors.push(format!("DeleteLeaf observer close: {error}"));
            }
        }
        if let Some(metadata) = metadata.take() {
            if let Err(error) = metadata.close() {
                close_errors.push(format!("Metadata observer close: {error}"));
            }
        }
        match (observed, close_errors.is_empty()) {
            (Ok(preimage), true) => Ok(preimage),
            (Err(primary), true) => Err(primary),
            (Ok(_), false) => Err(io::Error::other(close_errors.join("; "))),
            (Err(primary), false) => Err(io::Error::other(format!(
                "private view preimage failed: {primary}; {}",
                close_errors.join("; ")
            ))),
        }
    }

    fn aligned_security_descriptor(bytes: &[u8]) -> io::Result<Vec<usize>> {
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err(invalid("security descriptor is outside its reviewed bound"));
        }
        let mut storage = vec![0usize; bytes.len().div_ceil(size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                storage.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        Ok(storage)
    }

    fn mutation_probe_subkey_absent(root: HKEY) -> bool {
        win32_open_status(root, "MutationProbe", KEY_READ) == ERROR_FILE_NOT_FOUND
    }

    fn create_mutation_probe_status(root: HKEY) -> u32 {
        let name = match wide(OsStr::new("MutationProbe")) {
            Ok(name) => name,
            Err(_) => return ERROR_INVALID_PARAMETER,
        };
        let mut key = null_mut();
        let mut disposition = 0u32;
        let status = unsafe {
            RegCreateKeyExW(
                root,
                name.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                null(),
                &mut key,
                &mut disposition,
            )
        };
        if status == ERROR_SUCCESS {
            // Never use a key unexpectedly acquired by the restricted child.
            match unsafe { OwnedRegKey::from_raw(key) } {
                Ok(key) => match key.close() {
                    Ok(()) => status,
                    Err(error) => {
                        error.raw_os_error().unwrap_or(ERROR_INVALID_HANDLE as i32) as u32
                    }
                },
                Err(_) => ERROR_INVALID_HANDLE,
            }
        } else {
            status
        }
    }

    fn reopen_and_close_status(root: HKEY, access: u32) -> io::Result<u32> {
        let subkey = wide(OsStr::new(""))?;
        let mut key = null_mut();
        let status = unsafe { RegOpenKeyExW(root, subkey.as_ptr(), 0, access, &mut key) };
        if status != ERROR_SUCCESS {
            return Ok(status);
        }
        // An unexpectedly acquired key is closed immediately without use.
        unsafe { OwnedRegKey::from_raw(key) }?.close()?;
        Ok(ERROR_SUCCESS)
    }

    fn mutation_status(
        root: HKEY,
        operation: &str,
        preimage: &PrivateViewPreimage,
    ) -> io::Result<u32> {
        match operation {
            "set_value" => {
                let name = wide(OsStr::new("Mutation"))?;
                let status = unsafe {
                    RegSetValueExW(
                        root,
                        name.as_ptr(),
                        0,
                        REG_SZ,
                        preimage.mutation.as_ptr(),
                        u32::try_from(preimage.mutation.len())
                            .map_err(|_| invalid("private marker exceeds write bound"))?,
                    )
                };
                Ok(status)
            }
            "delete_value" => {
                let name = wide(OsStr::new("Mutation"))?;
                Ok(unsafe { RegDeleteValueW(root, name.as_ptr()) })
            }
            "create_subkey" => Ok(create_mutation_probe_status(root)),
            "delete_leaf" => {
                let name = wide(OsStr::new("DeleteLeaf"))?;
                Ok(unsafe { RegDeleteKeyW(root, name.as_ptr()) })
            }
            "set_dacl" | "set_owner" => {
                let descriptor = aligned_security_descriptor(&preimage.root_security)?;
                let information = if operation == "set_dacl" {
                    DACL_SECURITY_INFORMATION
                } else {
                    OWNER_SECURITY_INFORMATION
                };
                Ok(unsafe {
                    RegSetKeySecurity(root, information, descriptor.as_ptr().cast_mut().cast())
                })
            }
            "reopen_write" => reopen_and_close_status(root, KEY_WRITE),
            "reopen_delete" => reopen_and_close_status(root, DELETE),
            "reopen_write_dac" => reopen_and_close_status(root, WRITE_DAC),
            "reopen_write_owner" => reopen_and_close_status(root, WRITE_OWNER),
            _ => Err(invalid("unknown fixed registry mutation operation")),
        }
    }

    fn record_mutation_attempt(root: HKEY, operation: &str, view: &str) -> io::Result<()> {
        if !mutation_probe_subkey_absent(root) {
            return Err(invalid("fixed private mutation subkey was not absent"));
        }
        let before = private_view_preimage(root)?;
        let before_digest = before.digest()?;
        let status = mutation_status(root, operation, &before)?;
        let after = private_view_preimage(root);
        let unchanged = after.as_ref().is_ok_and(|after| *after == before);
        let after_digest = after
            .as_ref()
            .ok()
            .and_then(|after| after.digest().ok())
            .unwrap_or_else(|| "unknown".to_owned());
        let subkey_absent = mutation_probe_subkey_absent(root);
        let observed = status == ERROR_ACCESS_DENIED && unchanged && subkey_absent;
        emit_witness_record(&format!(
            "registry_witness_probe id=mutation/{operation}/{view} domain=lstatus status={status:#x} expected=0x5 observed={observed} data_and_descriptor_unchanged={unchanged} mutation_subkey_absent={subkey_absent} before={before_digest} after={after_digest}"
        ))?;
        if !observed {
            return Err(io::Error::other(format!(
                "private mutation control failed: operation={operation} view={view} status={status:#x} unchanged={unchanged} subkey_absent={subkey_absent}"
            )));
        }
        Ok(())
    }

    fn duplicate_read_control(root: HKEY, view: &str) -> io::Result<()> {
        let source_query = query_directory_handle_access(root.cast());
        let Some(source_access) = source_query.granted_access else {
            return Err(io::Error::other(format!(
                "source registry handle access unknown: status={} returned={}",
                query_ntstatus_text(source_query.ntstatus),
                source_query.returned_length
            )));
        };
        if source_access & !KEY_READ != 0 {
            return Err(invalid("inherited registry source exceeds KEY_READ"));
        }
        let mut raw = null_mut();
        let copied = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                root.cast(),
                GetCurrentProcess(),
                &mut raw,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if copied == 0 {
            let status = unsafe { GetLastError() };
            emit_witness_record(&format!(
                "registry_witness_probe id=duplicate_read/{view} domain=win32 status={status:#x} expected=0 observed=false source_access={source_access:#x} actual=unknown"
            ))?;
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let duplicate = unsafe { OwnedRegKey::from_raw(raw.cast()) }?;
        let query = query_directory_handle_access(duplicate.raw().cast());
        let actual = query.granted_access;
        let label_read = private_view_label(duplicate.raw())?;
        let observed = actual == Some(source_access)
            && actual.is_some_and(|mask| mask & !KEY_READ == 0)
            && label_read;
        emit_witness_record(&format!(
            "registry_witness_probe id=duplicate_read/{view} domain=win32 status=0x0 expected=0x0 observed={observed} source_access={source_access:#x} actual={} query_ntstatus={} returned_length={} label_read={label_read}",
            actual.map_or_else(|| "unknown".to_owned(), |mask| format!("{mask:#x}")),
            query_ntstatus_text(query.ntstatus),
            query.returned_length
        ))?;
        duplicate.close()?;
        if !observed {
            return Err(invalid("same-access read duplicate verification failed"));
        }
        Ok(())
    }

    fn duplicate_mutation_control(root: HKEY, view: &str) -> io::Result<()> {
        if !mutation_probe_subkey_absent(root) {
            return Err(invalid("fixed private mutation subkey was not absent"));
        }
        let before = private_view_preimage(root)?;
        let before_digest = before.digest()?;
        let desired = KEY_WRITE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER;
        let mut raw = null_mut();
        let copied = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                root.cast(),
                GetCurrentProcess(),
                &mut raw,
                desired,
                0,
                0,
            )
        };
        if copied == 0 {
            let status = unsafe { GetLastError() };
            let after = private_view_preimage(root);
            let unchanged = after.as_ref().is_ok_and(|after| *after == before);
            let subkey_absent = mutation_probe_subkey_absent(root);
            let after_digest = after
                .as_ref()
                .ok()
                .and_then(|after| after.digest().ok())
                .unwrap_or_else(|| "unknown".to_owned());
            let observed = status == ERROR_ACCESS_DENIED && unchanged && subkey_absent;
            emit_witness_record(&format!(
                "registry_witness_probe id=mutation/duplicate_mutation/{view} domain=win32 status={status:#x} expected=0x5 observed={observed} branch=duplicate_denied desired={desired:#x} actual=unknown data_and_descriptor_unchanged={unchanged} mutation_subkey_absent={subkey_absent} before={before_digest} after={after_digest}"
            ))?;
            return if observed {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            };
        }
        let duplicate = unsafe { OwnedRegKey::from_raw(raw.cast()) }?;
        let query = query_directory_handle_access(duplicate.raw().cast());
        let actual = query.granted_access;
        let Some(actual) = actual else {
            duplicate.close()?;
            return Err(io::Error::other(format!(
                "mutation duplicate granted access unknown: query={} length={}",
                query_ntstatus_text(query.ntstatus),
                query.returned_length
            )));
        };
        if actual & !KEY_READ != 0 {
            duplicate.close()?;
            emit_witness_record(&format!(
                "registry_witness_probe id=mutation/duplicate_mutation/{view} domain=win32 status=0 expected=0x5 observed=false branch=unexpected_granted_access desired={desired:#x} actual={actual:#x}"
            ))?;
            return Err(invalid(
                "mutation duplicate exceeded KEY_READ; closed unused handle",
            ));
        }
        let mut statuses = Vec::new();
        for operation in [
            "set_value",
            "delete_value",
            "create_subkey",
            "delete_leaf",
            "set_dacl",
            "set_owner",
        ] {
            let status = mutation_status(duplicate.raw(), operation, &before)?;
            if status != ERROR_ACCESS_DENIED {
                duplicate.close()?;
                emit_witness_record(&format!(
                    "registry_witness_probe id=mutation/duplicate_mutation/{view} domain=win32 status={status:#x} expected=0x5 observed=false branch=mutation_not_denied desired={desired:#x} actual={actual:#x} operation={operation}"
                ))?;
                return Err(io::Error::other(format!(
                    "mutation through read-limited duplicate was not denied: {operation} status={status:#x}"
                )));
            }
            statuses.push(format!("{operation}=0x{status:x}"));
        }
        let after = private_view_preimage(root);
        let unchanged = after.as_ref().is_ok_and(|after| *after == before);
        let subkey_absent = mutation_probe_subkey_absent(root);
        let after_digest = after
            .as_ref()
            .ok()
            .and_then(|after| after.digest().ok())
            .unwrap_or_else(|| "unknown".to_owned());
        let observed = unchanged && subkey_absent;
        emit_witness_record(&format!(
            "registry_witness_probe id=mutation/duplicate_mutation/{view} domain=win32 status=0x0 expected=0x0 observed={observed} branch=limited desired={desired:#x} actual={actual:#x} query_ntstatus={} returned_length={} data_and_descriptor_unchanged={unchanged} mutation_subkey_absent={subkey_absent} before={before_digest} after={after_digest} attempts={}",
            query_ntstatus_text(query.ntstatus),
            query.returned_length,
            statuses.join(",")
        ))?;
        duplicate.close()?;
        if !observed {
            return Err(invalid("mutation duplicate changed private fixture state"));
        }
        Ok(())
    }

    fn normal_mutation_controls(machine: HKEY, user: HKEY) -> io::Result<()> {
        for (view, root) in [("machine_view", machine), ("user_view", user)] {
            for operation in [
                "set_value",
                "delete_value",
                "create_subkey",
                "delete_leaf",
                "set_dacl",
                "set_owner",
                "reopen_write",
                "reopen_delete",
                "reopen_write_dac",
                "reopen_write_owner",
            ] {
                record_mutation_attempt(root, operation, view)?;
            }
            duplicate_read_control(root, view)?;
            duplicate_mutation_control(root, view)?;
        }
        Ok(())
    }

    fn emit_parent_probe(payload: &str) -> io::Result<()> {
        emit_witness_record(payload)
    }

    fn parent_authority_probes(
        parent_pid: u32,
        parent_creation: &str,
        nonce: &str,
    ) -> io::Result<()> {
        for (name, access) in [
            ("dup_handle", PROCESS_DUP_HANDLE),
            ("vm_write", PROCESS_VM_WRITE),
            ("vm_operation", PROCESS_VM_OPERATION),
            ("create_thread", PROCESS_CREATE_THREAD),
            ("write_dac", WRITE_DAC),
            ("write_owner", WRITE_OWNER),
            ("vm_read", PROCESS_VM_READ),
        ] {
            let handle = unsafe { OpenProcess(access, 0, parent_pid) };
            if !handle.is_null() {
                let owned = own("OpenProcess(parent authority unexpected handle)", handle)?;
                drop(owned);
                emit_parent_probe(&format!(
                    "registry_witness_probe id=parent_authority/{name} domain=win32 status=0 expected=0x5 observed=false requested={access:#x} nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation} unexpected_handle_closed=true"
                ))?;
                return Err(invalid(
                    "unexpected parent process authority handle acquired",
                ));
            }
            let status = unsafe { GetLastError() };
            let observed = status == ERROR_ACCESS_DENIED;
            emit_parent_probe(&format!(
                "registry_witness_probe id=parent_authority/{name} domain=win32 status={status:#x} expected=0x5 observed={observed} requested={access:#x} nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation}"
            ))?;
            if !observed {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(())
    }

    fn parent_token_probes(parent_pid: u32, parent_creation: &str, nonce: &str) -> io::Result<()> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid) };
        if process.is_null() {
            let status = unsafe { GetLastError() };
            let observed = status == ERROR_ACCESS_DENIED;
            emit_parent_probe(&format!(
                "registry_witness_probe id=parent_token/process_query_limited domain=win32 status={status:#x} expected=0x5 observed={observed} branch=blocked_by_process_gate nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation}"
            ))?;
            if !observed {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            for right in [
                "token_duplicate",
                "write_dac",
                "write_owner",
                "token_impersonate",
                "token_assign_primary",
            ] {
                emit_parent_probe(&format!(
                    "registry_witness_probe id=parent_token/{right} domain=gate branch=blocked_by_process_gate executed=false gate_id=parent_token/process_query_limited gate_status=0x5 nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation}"
                ))?;
            }
            return Ok(());
        }
        let process = own("OpenProcess(parent query-limited handle)", process)?;
        let observed_pid = unsafe { GetProcessId(process.as_raw_handle()) };
        let observed_creation = process_creation_text(process.as_raw_handle())?;
        let query = query_directory_handle_access(process.as_raw_handle());
        let actual = query.granted_access;
        let branch_valid = observed_pid == parent_pid
            && observed_creation == parent_creation
            && actual == Some(PROCESS_QUERY_LIMITED_INFORMATION);
        emit_parent_probe(&format!(
            "registry_witness_probe id=parent_token/process_query_limited domain=win32 status=0x0 expected=0x0 observed={branch_valid} branch=query_open actual={} query_ntstatus={} returned_length={} nonce={nonce} parent_pid={observed_pid} parent_creation={observed_creation}",
            actual.map_or_else(|| "unknown".to_owned(), |mask| format!("{mask:#x}")),
            query_ntstatus_text(query.ntstatus),
            query.returned_length
        ))?;
        if !branch_valid {
            return Err(invalid(
                "query-limited parent process handle identity or granted rights mismatch",
            ));
        }
        for (name, access) in [
            ("token_duplicate", TOKEN_DUPLICATE),
            ("write_dac", WRITE_DAC),
            ("write_owner", WRITE_OWNER),
            ("token_impersonate", TOKEN_IMPERSONATE),
            ("token_assign_primary", TOKEN_ASSIGN_PRIMARY),
        ] {
            let mut token = null_mut();
            let opened = unsafe { OpenProcessToken(process.as_raw_handle(), access, &mut token) };
            if opened != 0 {
                let owned = own("OpenProcessToken(unexpected parent token)", token)?;
                drop(owned);
                emit_parent_probe(&format!(
                    "registry_witness_probe id=parent_token/{name} domain=win32 status=0 expected=0x5 observed=false branch=query_open executed=true requested={access:#x} acquired=true nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation} unexpected_token_closed=true"
                ))?;
                return Err(invalid(
                    "unexpected parent token authority acquired and closed",
                ));
            }
            let status = unsafe { GetLastError() };
            let observed = status == ERROR_ACCESS_DENIED;
            emit_parent_probe(&format!(
                "registry_witness_probe id=parent_token/{name} domain=win32 status={status:#x} expected=0x5 observed={observed} branch=query_open executed=true requested={access:#x} acquired=false nonce={nonce} parent_pid={parent_pid} parent_creation={parent_creation}"
            ))?;
            if !observed {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(())
    }

    fn validate_parent_self_binding(pid: u32, creation: &str) -> io::Result<()> {
        if unsafe { GetCurrentProcessId() } != pid
            || process_creation_text(unsafe { GetCurrentProcess() })? != creation
        {
            return Err(invalid(
                "parent process identity changed while collecting helper",
            ));
        }
        Ok(())
    }

    fn private_view_label_digest(root: HKEY) -> io::Result<String> {
        let metadata = win32_open_key(root, "Metadata", KEY_READ)
            .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
        let value = win32_query_value(&metadata, "Fixture")
            .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
        registry_string_digest(&value)
    }

    fn private_view_label(root: HKEY) -> io::Result<bool> {
        let metadata = wide(OsStr::new("Metadata"))?;
        let mut key = null_mut();
        let status = unsafe { RegOpenKeyExW(root, metadata.as_ptr(), 0, KEY_READ, &mut key) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: RegOpenKeyExW returned one owned key.
        let key = unsafe { OwnedRegKey::from_raw(key) }?;
        let bytes = win32_query_value(&key, "Fixture")
            .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
        Ok(decode_reg_sz(&bytes)? == "ORBIT-PRIVATE-METADATA-V1")
    }

    fn decode_reg_sz(bytes: &[u8]) -> io::Result<String> {
        if bytes.is_empty() || bytes.len() > 4096 || bytes.len() % size_of::<u16>() != 0 {
            return Err(invalid("REG_SZ data has invalid UTF-16 byte length"));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| invalid("REG_SZ data is not NUL terminated"))?;
        if units[end..].iter().any(|unit| *unit != 0) {
            return Err(invalid(
                "REG_SZ data has nonzero bytes after its terminator",
            ));
        }
        String::from_utf16(&units[..end]).map_err(|_| invalid("REG_SZ data is invalid UTF-16"))
    }

    fn win32_open_status(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> u32 {
        match win32_open_key(root, path, access) {
            Ok(key) => {
                let _ = key.close();
                ERROR_SUCCESS
            }
            Err(status) => status,
        }
    }

    fn nt_open_status(path: &str, access: u32) -> i32 {
        match nt_open_key(path, access) {
            Ok(key) => {
                let _ = key.close();
                0
            }
            Err(status) => status,
        }
    }

    fn expect_denial(id: &str, domain: &str, actual: i32, expected: i32) {
        emit_witness_record(&format!(
            "registry_witness_probe id={id} domain={domain} status={actual:#x}"
        ))
        .expect("bounded denial record");
        assert_eq!(actual, expected, "required denial probe {id} failed");
    }

    fn record_read(id: &str, observed: bool) {
        emit_witness_record(&format!(
            "registry_witness_probe id={id} observed={observed}"
        ))
        .expect("bounded read record");
        assert!(observed, "required private registry read {id} failed");
    }

    fn create_acl_key(parent: HKEY, name: &str, sddl: &str) -> io::Result<OwnedRegKey> {
        let name = wide(OsStr::new(name))?;
        let sddl = wide(OsStr::new(sddl))?;
        let mut descriptor = null_mut();
        unsafe {
            ok(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(registry witness)",
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                ),
            )?;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut key = null_mut();
        let mut disposition = 0u32;
        let status = unsafe {
            RegCreateKeyExW(
                parent,
                name.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                &attributes,
                &mut key,
                &mut disposition,
            )
        };
        unsafe { LocalFree(descriptor.cast()) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: RegCreateKeyExW returned one owned key handle.
        let key = unsafe { OwnedRegKey::from_raw(key) }?;
        if disposition != REG_CREATED_NEW_KEY {
            let _ = key.close();
            return Err(invalid("registry witness fixture key already existed"));
        }
        Ok(key)
    }

    fn set_string(key: HKEY, name: &str, value: &str) -> io::Result<()> {
        let name = wide(OsStr::new(name))?;
        let mut value: Vec<u16> = value.encode_utf16().collect();
        value.push(0);
        let status = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * size_of::<u16>()) as u32,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    struct PrivateRegistryFixture {
        name: String,
        root: Option<OwnedRegKey>,
        software: Option<OwnedRegKey>,
        created_keys: Vec<String>,
        expected_values: Vec<(String, String, String)>,
        completed_steps: Vec<String>,
    }

    struct HeldHelperImage {
        directory: PathBuf,
        path: PathBuf,
        directory_leaf: String,
        image_leaf: String,
        directory_handle: Option<OwnedHandle>,
        file: Option<File>,
        metadata_anchor: Option<OwnedHandle>,
        control_dacl_handle: Option<OwnedHandle>,
        directory_identity: (u64, [u8; 16]),
        identity: (u64, [u8; 16]),
        expected_length: u64,
        expected_resource_dacl: Vec<u8>,
        expected_directory_dacl: Vec<u8>,
        sha256: String,
    }

    struct JobFence {
        handle: OwnedHandle,
        role: &'static str,
        pid: u32,
        creation: String,
        process_waited: bool,
    }

    const JOB_OBJECT_QUERY_ONLY: u32 = 0x0004;

    struct JobQueryObservation<'a> {
        native_counts: &'a Cell<[Option<u32>; 2]>,
        index: usize,
        injected_error: Option<&'a Cell<Option<&'static str>>>,
    }

    #[derive(Default)]
    struct CleanupJobGate {
        normal: Option<JobFence>,
        cancel: Option<JobFence>,
        unobserved: bool,
        injected_query_error_once: Cell<Option<&'static str>>,
        last_native_active_counts: Cell<[Option<u32>; 2]>,
    }

    impl CleanupJobGate {
        fn require_zero(&self, phase: &str) -> io::Result<()> {
            if self.unobserved {
                return Err(invalid("a registry witness Job shutdown was not observed"));
            }
            self.last_native_active_counts.set([None, None]);
            for (index, fence) in [self.normal.as_ref(), self.cancel.as_ref()]
                .into_iter()
                .enumerate()
            {
                let fence = fence.ok_or_else(|| invalid("both exact Job fences are required"))?;
                fence.require_zero_observed(
                    phase,
                    Some(&JobQueryObservation {
                        native_counts: &self.last_native_active_counts,
                        index,
                        injected_error: (index == 1).then_some(&self.injected_query_error_once),
                    }),
                )?;
            }
            Ok(())
        }

        fn inject_query_error_once(&self, message: &'static str) {
            self.injected_query_error_once.set(Some(message));
        }

        fn clear_query_error_injection(&self) {
            self.injected_query_error_once.set(None);
        }

        fn reset_last_native_active_counts(&self) {
            self.last_native_active_counts.set([None, None]);
        }

        fn last_native_active_counts(&self) -> [Option<u32>; 2] {
            self.last_native_active_counts.get()
        }

        fn close_fences(&mut self) -> Vec<String> {
            let mut errors = Vec::new();
            if let Some(fence) = self.normal.take() {
                if let Err(error) = close_checked(fence.handle, "CloseHandle(normal Job fence)") {
                    errors.push(format!("normal Job fence close: {error}"));
                }
            }
            if let Some(fence) = self.cancel.take() {
                if let Err(error) =
                    close_checked(fence.handle, "CloseHandle(cancellation Job fence)")
                {
                    errors.push(format!("cancellation Job fence close: {error}"));
                }
            }
            errors
        }
    }

    impl JobFence {
        fn require_zero(&self, phase: &str) -> io::Result<u32> {
            self.require_zero_observed(phase, None)
        }

        fn query_accounting(
            &self,
            observation: Option<&JobQueryObservation<'_>>,
        ) -> io::Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION> {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            let native_result = unsafe {
                ok(
                    "QueryInformationJobObject(cleanup fence)",
                    QueryInformationJobObject(
                        self.handle.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    ),
                )
            };
            match native_result {
                Err(error) => Err(error),
                Ok(()) => {
                    if let Some(observation) = observation {
                        let mut counts = observation.native_counts.get();
                        counts[observation.index] = Some(info.ActiveProcesses);
                        observation.native_counts.set(counts);
                        if let Some(message) = observation.injected_error.and_then(Cell::take) {
                            return Err(invalid(message));
                        }
                    }
                    Ok(info)
                }
            }
        }

        fn require_zero_observed(
            &self,
            phase: &str,
            observation: Option<&JobQueryObservation<'_>>,
        ) -> io::Result<u32> {
            let info = self.query_accounting(observation)?;
            if info.ActiveProcesses != 0 {
                return Err(io::Error::other(format!(
                    "{} Job is not empty before {phase}: pid={} creation={} active={}",
                    self.role, self.pid, self.creation, info.ActiveProcesses
                )));
            }
            if !self.process_waited {
                return Err(io::Error::other(format!(
                    "{} exact child process wait not observed before {phase}: pid={} creation={}",
                    self.role, self.pid, self.creation
                )));
            }
            Ok(info.ActiveProcesses)
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ProfileEntryFact {
        identity: (u64, [u8; 16]),
        directory: bool,
        size: i64,
        last_write: i64,
        attributes: u32,
    }

    struct ControlHardlinkExpectation<'a> {
        image_path: &'a str,
        alias_path: &'a str,
        identity: (u64, [u8; 16]),
        length: u64,
        sha256: &'a str,
        dacl: &'a [u8],
    }

    struct ProfileCleanupAnchor {
        packages: Option<OwnedHandle>,
        entry: Option<OwnedHandle>,
        ac: Option<OwnedHandle>,
        entry_leaf: String,
        packages_identity: (u64, [u8; 16]),
        entry_identity: (u64, [u8; 16]),
        ac_identity: (u64, [u8; 16]),
        baseline: BTreeMap<String, ProfileEntryFact>,
    }

    struct RegistryAbsence {
        software: Option<OwnedRegKey>,
        leaf: String,
        absence_proven: bool,
        anchor_closed: bool,
    }

    struct ImageDirectoryAbsence {
        image_disposition_succeeded: bool,
        image_close_succeeded: bool,
        image_absent: bool,
        directory_disposition_succeeded: bool,
        directory_close_succeeded: bool,
        directory_absent: bool,
        errors: Vec<String>,
    }

    struct CleanupReceipt {
        registry: Option<RegistryAbsence>,
        image: Option<ImageDirectoryAbsence>,
        profile_packages: Option<OwnedHandle>,
        profile_packages_identity: Option<(u64, [u8; 16])>,
        profile_entry_leaf: Option<String>,
        profile_sdk_result: Option<i32>,
        profile_packages_close_succeeded: bool,
        profile_absent: bool,
        profile_final_verified: bool,
        normal_job_zero: bool,
        cancel_job_zero: bool,
        errors: Vec<String>,
    }

    impl RegistryAbsence {
        fn verify(&self) -> io::Result<()> {
            let Some(software) = self.software.as_ref() else {
                return if self.absence_proven && self.anchor_closed {
                    Ok(())
                } else {
                    Err(invalid(
                        "Software registry parent anchor missing without verified absence and close",
                    ))
                };
            };
            if win32_open_status(software.raw(), &self.leaf, KEY_READ) != ERROR_FILE_NOT_FOUND {
                return Err(invalid(
                    "nonce registry root is not absent relative to held Software key",
                ));
            }
            Ok(())
        }
    }

    fn close_checked(handle: OwnedHandle, operation: &'static str) -> io::Result<()> {
        let raw = handle.into_raw_handle();
        unsafe { ok(operation, CloseHandle(raw)) }
    }

    fn close_file_checked(file: File, operation: &'static str) -> io::Result<()> {
        let raw = file.into_raw_handle();
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        close_checked(handle, operation)
    }

    fn relative_open(
        parent: HANDLE,
        leaf: &str,
        directory: bool,
        access: u32,
        share: u32,
    ) -> io::Result<OwnedHandle> {
        relative_open_with_status(parent, leaf, directory, access, share, &mut None)
    }

    fn relative_open_with_status(
        parent: HANDLE,
        leaf: &str,
        directory: bool,
        access: u32,
        share: u32,
        native_status: &mut Option<i32>,
    ) -> io::Result<OwnedHandle> {
        validate_component(OsStr::new(leaf))?;
        let (mut storage, mut object_name) = nt_unicode(leaf)?;
        let mut attributes = OBJECT_ATTRIBUTES::default();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = parent;
        attributes.ObjectName = &mut object_name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attributes,
                &mut status,
                null(),
                0,
                share,
                FILE_OPEN,
                (if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                }) | FILE_OPEN_REPARSE_POINT
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        std::hint::black_box(&mut storage);
        if result < 0 {
            *native_status = Some(result);
            return Err(operation_error(
                "NtCreateFile(FILE_OPEN relative cleanup object)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ));
        }
        let owned = own("NtCreateFile(relative cleanup object)", handle)?;
        if let Err(primary) = check_object(owned.as_raw_handle(), directory) {
            return match close_checked(
                owned,
                "CloseHandle(relative object after verification failure)",
            ) {
                Ok(()) => Err(primary),
                Err(close) => Err(io::Error::other(format!(
                    "relative object verification failed: {primary}; handle close failed: {close}"
                ))),
            };
        }
        Ok(owned)
    }

    fn relative_open_hardlink_control(parent: HANDLE, leaf: &str) -> io::Result<OwnedHandle> {
        validate_component(OsStr::new(leaf))?;
        let (mut storage, mut object_name) = nt_unicode(leaf)?;
        let mut attributes = OBJECT_ATTRIBUTES::default();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = parent;
        attributes.ObjectName = &mut object_name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                &attributes,
                &mut status,
                null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        std::hint::black_box(&mut storage);
        if result < 0 {
            return Err(operation_error(
                "NtCreateFile(FILE_OPEN hardlink control observation)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ));
        }
        own("NtCreateFile(hardlink control observation)", handle)
    }

    fn observe_control_hardlink_entry(
        parent: HANDLE,
        leaf: &str,
        expected: &ControlHardlinkExpectation<'_>,
    ) -> io::Result<ProfileEntryFact> {
        let mut file = File::from(relative_open_hardlink_control(parent, leaf)?);
        let observation = (|| -> io::Result<ProfileEntryFact> {
            let handle = file.as_raw_handle();
            verify_file_link_count(handle, 2)?;
            let fact = profile_fact(handle, false)?;
            if fact.identity != expected.identity
                || fact.size < 0
                || fact.size as u64 != expected.length
            {
                return Err(invalid(
                    "hardlink profile name differs from the expected full image identity or size",
                ));
            }
            if resource_dacl_bytes(handle)? != expected.dacl {
                return Err(invalid(
                    "hardlink profile name DACL differs from the held image",
                ));
            }
            let mut bytes = Vec::with_capacity(expected.length as usize);
            (&mut file)
                .take(expected.length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != expected.length || digest(&bytes)? != expected.sha256 {
                return Err(invalid(
                    "hardlink profile name content differs from the held image",
                ));
            }
            Ok(fact)
        })();
        let close = close_checked(
            file.into(),
            "CloseHandle(hardlink profile control observer)",
        );
        match (observation, close) {
            (Ok(fact), Ok(())) => Ok(fact),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(close)) => Err(io::Error::other(format!(
                "hardlink profile observer checked-close failure: {close}"
            ))),
            (Err(primary), Err(close)) => Err(io::Error::other(format!(
                "hardlink profile observer failed: {primary}; checked-close failure: {close}"
            ))),
        }
    }

    fn relative_create_file(
        parent: HANDLE,
        leaf: &str,
        access: u32,
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> io::Result<OwnedHandle> {
        validate_component(OsStr::new(leaf))?;
        let (mut storage, mut object_name) = nt_unicode(leaf)?;
        let mut attributes = OBJECT_ATTRIBUTES::default();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = parent;
        attributes.ObjectName = &mut object_name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
        attributes.SecurityDescriptor = descriptor.cast();
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attributes,
                &mut status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        std::hint::black_box(&mut storage);
        if result < 0 {
            return Err(operation_error(
                "NtCreateFile(FILE_CREATE relative helper image)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ));
        }
        let owned = own("NtCreateFile(relative helper image)", handle)?;
        let verify = (|| -> io::Result<()> {
            if status.Information != FILE_CREATED as usize {
                return Err(operation_error(
                    "NtCreateFile(FILE_CREATE relative helper image result)",
                    invalid("FILE_CREATE did not return FILE_CREATED"),
                ));
            }
            check_object(owned.as_raw_handle(), false)
        })();
        if let Err(primary) = verify {
            return match close_checked(
                owned,
                "CloseHandle(relative image after verification failure)",
            ) {
                Ok(()) => Err(primary),
                Err(close) => Err(io::Error::other(format!(
                    "relative image verification failed: {primary}; handle close failed: {close}"
                ))),
            };
        }
        Ok(owned)
    }

    fn relative_probe_absent(parent: HANDLE, leaf: &str, directory: bool) -> io::Result<bool> {
        validate_component(OsStr::new(leaf))?;
        let (mut storage, mut object_name) = nt_unicode(leaf)?;
        let mut attributes = OBJECT_ATTRIBUTES::default();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = parent;
        attributes.ObjectName = &mut object_name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
        let mut handle = null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &attributes,
                &mut status,
                null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                (if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                }) | FILE_OPEN_REPARSE_POINT
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        std::hint::black_box(&mut storage);
        if result == 0xC000_0034u32 as i32 {
            return Ok(true);
        }
        if result < 0 {
            return Err(operation_error(
                "NtCreateFile(FILE_OPEN relative absence probe)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ));
        }
        let owned = own("NtCreateFile(relative absence probe)", handle)?;
        let identity = script_identity(owned.as_raw_handle());
        let close = close_checked(owned, "CloseHandle(relative absence probe)");
        match (identity, close) {
            (Ok(identity), Ok(())) => Err(io::Error::other(format!(
                "cleanup leaf still exists or was replaced: directory={directory} identity={}",
                identity_text(identity)
            ))),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(close)) => Err(io::Error::other(format!(
                "existing cleanup leaf observation handle close failed: {close}"
            ))),
            (Err(primary), Err(close)) => Err(io::Error::other(format!(
                "cleanup leaf identity probe failed: {primary}; observation close failed: {close}"
            ))),
        }
    }

    fn disposition_once(handle: HANDLE) -> io::Result<()> {
        let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        let mut status = IO_STATUS_BLOCK::default();
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
            Err(operation_error(
                "NtSetInformationFile(FileDispositionInformation)",
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ))
        } else {
            Ok(())
        }
    }

    fn set_relative_name_information(
        handle: HANDLE,
        parent: HANDLE,
        leaf: &str,
        information_class: i32,
        operation: &'static str,
        native_status: &mut Option<i32>,
    ) -> io::Result<()> {
        validate_component(OsStr::new(leaf))?;
        let name: Vec<u16> = OsStr::new(leaf).encode_wide().collect();
        let name_bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| invalid("relative file name length overflow"))?;
        let root_alignment = std::mem::align_of::<HANDLE>();
        let root_offset = (size_of::<u8>() + root_alignment - 1) & !(root_alignment - 1);
        let length_offset = root_offset + size_of::<HANDLE>();
        let name_offset = length_offset + size_of::<u32>();
        let information_length = name_offset
            .checked_add(name_bytes as usize)
            .ok_or_else(|| invalid("relative namespace information size overflow"))?;
        let minimum_header = (name_offset + size_of::<u16>() + std::mem::align_of::<HANDLE>() - 1)
            & !(std::mem::align_of::<HANDLE>() - 1);
        let total = information_length.max(minimum_header);
        let mut storage = vec![0u64; total.div_ceil(size_of::<u64>())];
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), total) };
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<u8>(), 0);
            std::ptr::write_unaligned(bytes.as_mut_ptr().add(root_offset).cast::<HANDLE>(), parent);
            std::ptr::write_unaligned(
                bytes.as_mut_ptr().add(length_offset).cast::<u32>(),
                name_bytes,
            );
        }
        for (index, unit) in name.iter().enumerate() {
            unsafe {
                std::ptr::write_unaligned(
                    bytes
                        .as_mut_ptr()
                        .add(name_offset + index * size_of::<u16>())
                        .cast::<u16>(),
                    *unit,
                );
            }
        }
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            NtSetInformationFile(
                handle,
                &mut status,
                bytes.as_mut_ptr().cast(),
                total as u32,
                information_class,
            )
        };
        if result < 0 {
            *native_status = Some(result);
            Err(operation_error(
                operation,
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32),
            ))
        } else {
            Ok(())
        }
    }

    fn rename_relative(
        handle: HANDLE,
        parent: HANDLE,
        leaf: &str,
        native_status: &mut Option<i32>,
    ) -> io::Result<()> {
        const FILE_RENAME_INFORMATION_CLASS: i32 = 10;
        set_relative_name_information(
            handle,
            parent,
            leaf,
            FILE_RENAME_INFORMATION_CLASS,
            "NtSetInformationFile(FileRenameInformation relative)",
            native_status,
        )
    }

    fn link_relative(
        handle: HANDLE,
        parent: HANDLE,
        leaf: &str,
        native_status: &mut Option<i32>,
    ) -> io::Result<()> {
        const FILE_LINK_INFORMATION_CLASS: i32 = 11;
        set_relative_name_information(
            handle,
            parent,
            leaf,
            FILE_LINK_INFORMATION_CLASS,
            "NtSetInformationFile(FileLinkInformation relative)",
            native_status,
        )
    }

    fn resource_dacl_bytes(handle: HANDLE) -> io::Result<Vec<u8>> {
        let (mut owner, mut group, mut dacl, mut sacl, mut descriptor) =
            (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                &mut sacl,
                &mut descriptor,
            )
        };
        let result = if status == ERROR_SUCCESS {
            descriptor_dacl_bytes(descriptor)
        } else {
            Err(operation_error(
                "GetSecurityInfo(helper resource DACL)",
                io::Error::from_raw_os_error(status as i32),
            ))
        };
        let release = if descriptor.is_null() {
            Ok(())
        } else if unsafe { LocalFree(descriptor.cast()) }.is_null() {
            Ok(())
        } else {
            Err(operation_error(
                "LocalFree(helper resource security descriptor)",
                io::Error::last_os_error(),
            ))
        };
        match (result, release) {
            (Ok(dacl), Ok(())) => Ok(dacl),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(release)) => Err(release),
            (Err(primary), Err(release)) => Err(io::Error::other(format!(
                "helper DACL query failed: {primary}; descriptor release failed: {release}"
            ))),
        }
    }

    fn verify_image_file(
        file: &mut File,
        expected_identity: (u64, [u8; 16]),
        expected_length: u64,
        expected_hash: &str,
        expected_dacl: &[u8],
    ) -> io::Result<()> {
        let handle = file.as_raw_handle();
        if script_identity(handle)? != expected_identity {
            return Err(invalid(
                "helper image identity differs from its captured full ID",
            ));
        }
        check_object(handle, false)?;
        if resource_dacl_bytes(handle)? != expected_dacl {
            return Err(invalid(
                "helper image DACL differs from the captured protected policy",
            ));
        }
        file.seek(std::io::SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(expected_length as usize);
        (&mut *file)
            .take(expected_length.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != expected_length || digest(&bytes)? != expected_hash {
            return Err(invalid(
                "helper image bounded length or SHA-256 differs from the captured image",
            ));
        }
        if script_identity(file.as_raw_handle())? != expected_identity {
            return Err(invalid(
                "helper image identity changed during bounded hash verification",
            ));
        }
        file.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }

    fn profile_children(handle: HANDLE) -> io::Result<Vec<(String, [u8; 16], bool)>> {
        let mut children = Vec::new();
        let mut name_bytes = 0usize;
        let mut buffer = vec![0u64; 8192];
        let capacity = buffer.len() * size_of::<u64>();
        let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let mut class = FileIdExtdDirectoryRestartInfo;
        loop {
            buffer.fill(0);
            let result = unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    class,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                )
            };
            if result == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_MORE_FILES {
                    return Ok(children);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            class = FileIdExtdDirectoryInfo;
            let mut offset = 0usize;
            loop {
                if offset % std::mem::align_of::<FILE_ID_EXTD_DIR_INFO>() != 0
                    || offset + size_of::<FILE_ID_EXTD_DIR_INFO>() > capacity
                {
                    return Err(invalid("invalid profile enumeration record"));
                }
                // The buffer is u64-aligned and the kernel bounded each record by capacity.
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
                    .ok_or_else(|| invalid("profile entry name exceeds enumeration buffer"))?;
                if length == 0 || length % 2 != 0 {
                    return Err(invalid("invalid profile entry name length"));
                }
                let wide_name = unsafe {
                    std::slice::from_raw_parts(entry.FileName.as_ptr(), length / size_of::<u16>())
                };
                if wide_name != [46] && wide_name != [46, 46] {
                    name_bytes = name_bytes
                        .checked_add(length)
                        .ok_or_else(|| invalid("profile enumeration name size overflow"))?;
                    if children.len() >= 512 || name_bytes > 1024 * 1024 {
                        return Err(invalid("fresh profile entry bound exceeded"));
                    }
                    if entry.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(invalid("reparse entry in fresh profile tree"));
                    }
                    let name = String::from_utf16(wide_name)
                        .map_err(|_| invalid("non-Unicode profile entry name"))?;
                    validate_component(OsStr::new(&name))?;
                    children.push((
                        name,
                        entry.FileId.Identifier,
                        entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                    ));
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                let next = offset
                    .checked_add(entry.NextEntryOffset as usize)
                    .ok_or_else(|| invalid("profile enumeration offset overflow"))?;
                if next < end || next >= capacity {
                    return Err(invalid("invalid profile enumeration next offset"));
                }
                offset = next;
            }
        }
    }

    fn collect_profile_baseline(
        handle: HANDLE,
        prefix: &str,
        depth: usize,
        count: &mut usize,
        total_bytes: &mut u64,
        result: &mut BTreeMap<String, ProfileEntryFact>,
    ) -> io::Result<()> {
        collect_profile_baseline_with_hardlink_control(
            handle,
            prefix,
            depth,
            count,
            total_bytes,
            result,
            None,
        )
    }

    fn collect_profile_baseline_with_hardlink_control(
        handle: HANDLE,
        prefix: &str,
        depth: usize,
        count: &mut usize,
        total_bytes: &mut u64,
        result: &mut BTreeMap<String, ProfileEntryFact>,
        hardlink: Option<&ControlHardlinkExpectation<'_>>,
    ) -> io::Result<()> {
        if depth > 16 {
            return Err(invalid("fresh profile nesting bound exceeded"));
        }
        for (name, listed_id, directory) in profile_children(handle)? {
            *count += 1;
            if *count > 512 {
                return Err(invalid("fresh profile entry bound exceeded"));
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}\\{name}")
            };
            let hardlink_entry = hardlink.filter(|expected| {
                relative == expected.image_path || relative == expected.alias_path
            });
            if let Some(expected) = hardlink_entry {
                if directory || listed_id != expected.identity.1 {
                    return Err(invalid(
                        "hardlink profile namespace kind or file ID differs from its exact expectation",
                    ));
                }
                *total_bytes = total_bytes
                    .checked_add(expected.length)
                    .ok_or_else(|| invalid("fresh profile byte count overflow"))?;
                if *total_bytes > 128 * 1024 * 1024 {
                    return Err(invalid("fresh profile byte bound exceeded"));
                }
                let fact = observe_control_hardlink_entry(handle, &name, expected)?;
                if result.insert(relative, fact).is_some() {
                    return Err(invalid(
                        "duplicate hardlink profile name during enumeration",
                    ));
                }
                continue;
            }

            let child = relative_open(
                handle,
                &name,
                directory,
                FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE
                    | if directory {
                        FILE_LIST_DIRECTORY | FILE_TRAVERSE
                    } else {
                        0
                    },
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            )?;
            let observation = (|| -> io::Result<()> {
                let identity = script_identity(child.as_raw_handle())?;
                if identity.1 != listed_id {
                    return Err(invalid("profile entry changed during held enumeration"));
                }
                let mut standard = FILE_STANDARD_INFO::default();
                let mut basic = FILE_BASIC_INFO::default();
                unsafe {
                    ok(
                        "GetFileInformationByHandleEx(profile standard info)",
                        GetFileInformationByHandleEx(
                            child.as_raw_handle(),
                            FileStandardInfo,
                            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                            size_of::<FILE_STANDARD_INFO>() as u32,
                        ),
                    )?;
                    ok(
                        "GetFileInformationByHandleEx(profile basic info)",
                        GetFileInformationByHandleEx(
                            child.as_raw_handle(),
                            FileBasicInfo,
                            (&mut basic as *mut FILE_BASIC_INFO).cast(),
                            size_of::<FILE_BASIC_INFO>() as u32,
                        ),
                    )?;
                }
                if standard.DeletePending
                    || standard.Directory != directory
                    || standard.EndOfFile < 0
                {
                    return Err(invalid("profile entry changed kind or is delete-pending"));
                }
                if !directory {
                    *total_bytes = total_bytes
                        .checked_add(standard.EndOfFile as u64)
                        .ok_or_else(|| invalid("fresh profile byte count overflow"))?;
                    if *total_bytes > 128 * 1024 * 1024 {
                        return Err(invalid("fresh profile byte bound exceeded"));
                    }
                }
                result.insert(
                    relative.clone(),
                    ProfileEntryFact {
                        identity,
                        directory,
                        size: standard.EndOfFile,
                        last_write: basic.LastWriteTime,
                        attributes: basic.FileAttributes,
                    },
                );
                if directory {
                    collect_profile_baseline_with_hardlink_control(
                        child.as_raw_handle(),
                        &relative,
                        depth + 1,
                        count,
                        total_bytes,
                        result,
                        hardlink,
                    )?;
                }
                Ok(())
            })();
            let close = close_checked(child, "CloseHandle(profile baseline entry)");
            match (observation, close) {
                (Ok(()), Ok(())) => {}
                (Err(primary), Ok(())) => return Err(primary),
                (Ok(()), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "profile baseline checked-close failure: {close}"
                    )));
                }
                (Err(primary), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "profile baseline checked-close failure after observation error: {primary}; close: {close}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn profile_baseline(handle: HANDLE) -> io::Result<BTreeMap<String, ProfileEntryFact>> {
        let mut result = BTreeMap::new();
        let mut count = 0;
        let mut total_bytes = 0;
        collect_profile_baseline(handle, "", 0, &mut count, &mut total_bytes, &mut result)?;
        let ac = result
            .get_mut("AC")
            .ok_or_else(|| invalid("fresh profile baseline has no AC directory"))?;
        if !ac.directory {
            return Err(invalid("fresh profile AC entry is not a directory"));
        }
        // Creating and removing the one known helper child legitimately updates
        // this directory timestamp. Exact names, IDs, kinds and child metadata
        // remain compared; only this directly affected parent timestamp is ignored.
        ac.last_write = 0;
        Ok(result)
    }

    fn profile_baseline_with_control_hardlink(
        handle: HANDLE,
        expected: &ControlHardlinkExpectation<'_>,
    ) -> io::Result<BTreeMap<String, ProfileEntryFact>> {
        let mut result = BTreeMap::new();
        let mut count = 0;
        let mut total_bytes = 0;
        collect_profile_baseline_with_hardlink_control(
            handle,
            "",
            0,
            &mut count,
            &mut total_bytes,
            &mut result,
            Some(expected),
        )?;
        for path in [expected.image_path, expected.alias_path] {
            if result
                .get(path)
                .is_none_or(|fact| fact.identity != expected.identity || fact.directory)
            {
                return Err(invalid(
                    "hardlink control did not observe both exact expected image names",
                ));
            }
        }
        let ac = result
            .get_mut("AC")
            .ok_or_else(|| invalid("fresh profile baseline has no AC directory"))?;
        if !ac.directory {
            return Err(invalid("fresh profile AC entry is not a directory"));
        }
        ac.last_write = 0;
        Ok(result)
    }

    fn profile_baseline_direct_children(
        baseline: &BTreeMap<String, ProfileEntryFact>,
        parent: &str,
    ) -> Vec<(String, [u8; 16], bool)> {
        let prefix = format!("{parent}\\");
        baseline
            .iter()
            .filter_map(|(path, fact)| {
                let leaf = path.strip_prefix(&prefix)?;
                (!leaf.contains('\\')).then(|| (leaf.to_owned(), fact.identity.1, fact.directory))
            })
            .collect()
    }

    fn profile_fact(handle: HANDLE, directory: bool) -> io::Result<ProfileEntryFact> {
        let mut standard = FILE_STANDARD_INFO::default();
        let mut basic = FILE_BASIC_INFO::default();
        unsafe {
            ok(
                "GetFileInformationByHandleEx(profile fact standard)",
                GetFileInformationByHandleEx(
                    handle,
                    FileStandardInfo,
                    (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                    size_of::<FILE_STANDARD_INFO>() as u32,
                ),
            )?;
            ok(
                "GetFileInformationByHandleEx(profile fact basic)",
                GetFileInformationByHandleEx(
                    handle,
                    FileBasicInfo,
                    (&mut basic as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                ),
            )?;
        }
        if standard.DeletePending || standard.Directory != directory || standard.EndOfFile < 0 {
            return Err(invalid(
                "profile fact has an unexpected kind or delete-pending state",
            ));
        }
        Ok(ProfileEntryFact {
            identity: script_identity(handle)?,
            directory,
            size: standard.EndOfFile,
            last_write: basic.LastWriteTime,
            attributes: basic.FileAttributes,
        })
    }

    impl ProfileCleanupAnchor {
        fn capture(session: &SandboxSession) -> io::Result<Self> {
            let ac_path = session
                .folder
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("AppContainer storage leaf is not valid Unicode"))?;
            let entry_path = session
                .folder
                .parent()
                .ok_or_else(|| invalid("AppContainer storage parent missing"))?;
            let entry_leaf = entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("AppContainer profile entry is not valid Unicode"))?;
            if ac_path != "AC" || entry_leaf != session.name {
                return Err(invalid("unexpected AppContainer Packages/name/AC layout"));
            }
            let packages_path = entry_path
                .parent()
                .ok_or_else(|| invalid("AppContainer Packages parent missing"))?;
            if packages_path.file_name().and_then(|name| name.to_str()) != Some("Packages") {
                return Err(invalid("AppContainer profile is not beneath Packages"));
            }
            let path = wide(packages_path.as_os_str())?;
            let packages = own("CreateFileW(AppContainer Packages parent)", unsafe {
                CreateFileW(
                    path.as_ptr(),
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            })?;
            check_object(packages.as_raw_handle(), true)?;
            let entry = relative_open(
                packages.as_raw_handle(),
                entry_leaf,
                true,
                DELETE
                    | READ_CONTROL
                    | FILE_LIST_DIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            let ac = relative_open(
                entry.as_raw_handle(),
                "AC",
                true,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            let entry_identity = script_identity(entry.as_raw_handle())?;
            let packages_identity = script_identity(packages.as_raw_handle())?;
            let ac_identity = script_identity(ac.as_raw_handle())?;
            let expected_root = script_identity(
                session
                    .root
                    .as_ref()
                    .ok_or_else(|| invalid("profile root handle missing"))?
                    .as_raw_handle(),
            )?;
            if ac_identity != expected_root {
                return Err(invalid(
                    "recorded AC entry differs from the created profile root",
                ));
            }
            let baseline = profile_baseline(entry.as_raw_handle())?;
            Ok(Self {
                packages: Some(packages),
                entry: Some(entry),
                ac: Some(ac),
                entry_leaf: entry_leaf.to_owned(),
                packages_identity,
                entry_identity,
                ac_identity,
                baseline,
            })
        }

        fn verify_baseline(&self) -> io::Result<()> {
            let entry = self
                .entry
                .as_ref()
                .ok_or_else(|| invalid("profile entry anchor closed"))?;
            if script_identity(entry.as_raw_handle())? != self.entry_identity {
                return Err(invalid("recorded profile entry identity changed"));
            }
            let ac = self
                .ac
                .as_ref()
                .ok_or_else(|| invalid("profile AC anchor closed"))?;
            if script_identity(ac.as_raw_handle())? != self.ac_identity {
                return Err(invalid("recorded profile AC identity changed"));
            }
            if profile_baseline(entry.as_raw_handle())? != self.baseline {
                return Err(invalid(
                    "fresh profile contents changed; unknown entries retained",
                ));
            }
            Ok(())
        }

        fn verify_predelete(
            &self,
            image: &mut HeldHelperImage,
            gate: &CleanupJobGate,
        ) -> io::Result<()> {
            gate.require_zero("owned-resource cleanup preflight")?;
            image.verify_preflight(gate)?;
            self.verify_profile_baseline_with_control_extras(image, &[])
        }

        fn verify_profile_baseline_with_control_extras(
            &self,
            image: &HeldHelperImage,
            extras: &[(String, ProfileEntryFact)],
        ) -> io::Result<()> {
            let entry = self
                .entry
                .as_ref()
                .ok_or_else(|| invalid("profile entry anchor closed"))?;
            if script_identity(entry.as_raw_handle())? != self.entry_identity {
                return Err(invalid(
                    "recorded profile entry identity changed before cleanup",
                ));
            }
            let ac = self
                .ac
                .as_ref()
                .ok_or_else(|| invalid("profile AC anchor closed"))?;
            if script_identity(ac.as_raw_handle())? != self.ac_identity {
                return Err(invalid(
                    "recorded profile AC identity changed before cleanup",
                ));
            }
            let mut expected = self.baseline.clone();
            let directory = image
                .directory_handle
                .as_ref()
                .ok_or_else(|| invalid("owned helper directory keeper missing"))?;
            let file = image
                .file
                .as_ref()
                .ok_or_else(|| invalid("owned helper immutable reader missing"))?;
            let directory_key = format!("AC\\{}", image.directory_leaf);
            let file_key = format!("{directory_key}\\{}", image.image_leaf);
            expected.insert(
                directory_key,
                profile_fact(directory.as_raw_handle(), true)?,
            );
            expected.insert(file_key, profile_fact(file.as_raw_handle(), false)?);
            for (path, fact) in extras {
                if expected.insert(path.clone(), fact.clone()).is_some() {
                    return Err(invalid(
                        "cleanup control profile extra duplicates an owned path",
                    ));
                }
            }
            let observed = profile_baseline(entry.as_raw_handle())?;
            if let Some(observed_directory) = observed.get(&format!("AC\\{}", image.directory_leaf))
            {
                let held_directory = expected
                    .get(&format!("AC\\{}", image.directory_leaf))
                    .expect("held helper directory fact inserted");
                if observed_directory.identity != held_directory.identity
                    || !observed_directory.directory
                {
                    return Err(invalid(
                        "helper directory entry identity differs from its held original",
                    ));
                }
            } else {
                return Err(invalid(
                    "helper directory entry identity differs from its held original",
                ));
            }
            if observed != expected {
                return Err(invalid(
                    "fresh profile contains unknown or changed entries before deletion",
                ));
            }
            Ok(())
        }

        fn verify_profile_baseline_with_control_hardlink(
            &self,
            image: &HeldHelperImage,
            alias_leaf: &str,
        ) -> io::Result<()> {
            validate_component(OsStr::new(alias_leaf))?;
            let entry = self
                .entry
                .as_ref()
                .ok_or_else(|| invalid("profile entry anchor closed"))?;
            if script_identity(entry.as_raw_handle())? != self.entry_identity {
                return Err(invalid(
                    "recorded profile entry identity changed before cleanup",
                ));
            }
            let ac = self
                .ac
                .as_ref()
                .ok_or_else(|| invalid("profile AC anchor closed"))?;
            if script_identity(ac.as_raw_handle())? != self.ac_identity {
                return Err(invalid(
                    "recorded profile AC identity changed before cleanup",
                ));
            }
            let directory = image
                .directory_handle
                .as_ref()
                .ok_or_else(|| invalid("owned helper directory keeper missing"))?;
            let file = image
                .file
                .as_ref()
                .ok_or_else(|| invalid("owned helper immutable reader missing"))?;
            let directory_path = format!("AC\\{}", image.directory_leaf);
            let image_path = format!("{directory_path}\\{}", image.image_leaf);
            let alias_path = format!("AC\\{alias_leaf}");
            let hardlink = ControlHardlinkExpectation {
                image_path: &image_path,
                alias_path: &alias_path,
                identity: image.identity,
                length: image.expected_length,
                sha256: &image.sha256,
                dacl: &image.expected_resource_dacl,
            };
            let observed =
                profile_baseline_with_control_hardlink(entry.as_raw_handle(), &hardlink)?;
            let mut expected = self.baseline.clone();
            expected.insert(
                directory_path.clone(),
                profile_fact(directory.as_raw_handle(), true)?,
            );
            expected.insert(
                image_path.clone(),
                profile_fact(file.as_raw_handle(), false)?,
            );
            let original_fact = observed
                .get(&image_path)
                .ok_or_else(|| invalid("expected original helper image name is absent"))?;
            let alias_fact = observed
                .get(&alias_path)
                .ok_or_else(|| invalid("expected hardlink AC alias is absent"))?
                .clone();
            if &alias_fact != original_fact {
                return Err(invalid(
                    "hardlink original and alias metadata differ after setup",
                ));
            }
            if expected.insert(alias_path, alias_fact).is_some() {
                return Err(invalid(
                    "hardlink control alias duplicates an existing profile path",
                ));
            }
            let observed_directory = observed
                .get(&directory_path)
                .ok_or_else(|| invalid("helper directory profile entry is absent"))?;
            let held_directory = expected
                .get(&directory_path)
                .expect("held helper directory fact inserted");
            if observed_directory.identity != held_directory.identity
                || !observed_directory.directory
            {
                return Err(invalid(
                    "helper directory entry identity differs from its held original",
                ));
            }
            if observed != expected {
                return Err(invalid(
                    "fresh profile contains unknown or changed entries before deletion",
                ));
            }
            Ok(())
        }

        fn verify_profile_inventory_with_control_entries(
            &self,
            entries: &[(String, ProfileEntryFact)],
        ) -> io::Result<()> {
            let entry = self
                .entry
                .as_ref()
                .ok_or_else(|| invalid("profile entry anchor closed"))?;
            let ac = self
                .ac
                .as_ref()
                .ok_or_else(|| invalid("profile AC anchor closed"))?;
            if script_identity(entry.as_raw_handle())? != self.entry_identity
                || script_identity(ac.as_raw_handle())? != self.ac_identity
            {
                return Err(invalid("profile anchor identities changed during control"));
            }
            let mut expected = self.baseline.clone();
            for (path, fact) in entries {
                if expected.insert(path.clone(), fact.clone()).is_some() {
                    return Err(invalid(
                        "control profile inventory duplicated a baseline path",
                    ));
                }
            }
            if profile_baseline(entry.as_raw_handle())? != expected {
                return Err(invalid(
                    "profile control inventory differs from installed namespace state",
                ));
            }
            Ok(())
        }

        fn verify_profile_bindings(&self) -> io::Result<()> {
            let packages = self
                .packages
                .as_ref()
                .ok_or_else(|| invalid("Packages observation anchor closed"))?;
            let entry = self
                .entry
                .as_ref()
                .ok_or_else(|| invalid("profile entry anchor closed"))?;
            let ac = self
                .ac
                .as_ref()
                .ok_or_else(|| invalid("profile AC anchor closed"))?;
            if script_identity(packages.as_raw_handle())? != self.packages_identity
                || script_identity(entry.as_raw_handle())? != self.entry_identity
                || script_identity(ac.as_raw_handle())? != self.ac_identity
            {
                return Err(invalid(
                    "retained profile Packages/entry/AC identity changed",
                ));
            }
            Ok(())
        }

        fn close_internal(&mut self) -> io::Result<()> {
            let mut errors = Vec::new();
            if let Some(ac) = self.ac.take() {
                if let Err(error) = close_checked(ac, "CloseHandle(profile AC anchor)") {
                    errors.push(error.to_string());
                }
            }
            if let Some(entry) = self.entry.take() {
                if let Err(error) = close_checked(entry, "CloseHandle(profile entry anchor)") {
                    errors.push(error.to_string());
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "profile anchor close failures: {}",
                    errors.join("; ")
                )))
            }
        }

        fn require_entry_absent(&self) -> io::Result<()> {
            let packages = self
                .packages
                .as_ref()
                .ok_or_else(|| invalid("Packages parent anchor closed"))?;
            if script_identity(packages.as_raw_handle())? != self.packages_identity {
                return Err(invalid("Packages parent identity changed"));
            }
            relative_probe_absent(packages.as_raw_handle(), &self.entry_leaf, true)?;
            Ok(())
        }
    }

    fn finish_registry_profile(
        mut session: SandboxSession,
        mut anchor: ProfileCleanupAnchor,
        gate: &CleanupJobGate,
        receipt: &mut CleanupReceipt,
    ) -> io::Result<()> {
        receipt.profile_packages_identity = Some(anchor.packages_identity);
        receipt.profile_entry_leaf = Some(anchor.entry_leaf.clone());
        let transition = (|| -> io::Result<()> {
            gate.require_zero("profile cleanup preflight")?;
            if !receipt.normal_job_zero || !receipt.cancel_job_zero {
                return Err(invalid(
                    "both independently observed Job-zero receipts are required",
                ));
            }
            if !receipt.image.as_ref().is_some_and(|image| {
                image.image_disposition_succeeded
                    && image.image_close_succeeded
                    && image.image_absent
                    && image.directory_disposition_succeeded
                    && image.directory_close_succeeded
                    && image.directory_absent
                    && image.errors.is_empty()
            }) {
                return Err(invalid(
                    "image and helper-directory absence receipts are required",
                ));
            }
            receipt
                .registry
                .as_ref()
                .ok_or_else(|| invalid("registry absence receipt missing"))?
                .verify()?;
            anchor.verify_baseline()?;
            gate.require_zero("profile internal-handle close")?;
            anchor.close_internal()?;
            if let Some(root) = session.root.take() {
                close_checked(root, "CloseHandle(profile root before SDK teardown)")?;
            }

            gate.require_zero("DeleteAppContainerProfile")?;
            let name = wide(OsStr::new(&session.name))?;
            let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
            receipt.profile_sdk_result = Some(result);
            if result != 0 {
                return Err(operation_error(
                    "DeleteAppContainerProfile(literal S_OK required)",
                    if result < 0 {
                        io::Error::other(format!("SDK HRESULT {result:#x}"))
                    } else {
                        io::Error::other(format!("SDK returned non-S_OK success {result:#x}"))
                    },
                ));
            }
            anchor.require_entry_absent()?;
            receipt.profile_absent = true;
            let registry = receipt
                .registry
                .as_mut()
                .ok_or_else(|| invalid("registry absence receipt missing after SDK call"))?;
            registry.verify()?;
            registry.absence_proven = true;
            session.closed = true;
            receipt.profile_packages = anchor.packages.take();
            receipt.profile_packages_identity = Some(anchor.packages_identity);
            receipt.profile_entry_leaf = Some(anchor.entry_leaf.clone());
            Ok(())
        })();

        let mut close_errors = Vec::new();
        if transition.is_err() {
            if let Err(error) = anchor.close_internal() {
                close_errors.push(error.to_string());
            }
            if let Some(packages) = anchor.packages.take() {
                match close_checked(
                    packages,
                    "CloseHandle(Packages after profile finalization failure)",
                ) {
                    Ok(()) => receipt.profile_packages_close_succeeded = true,
                    Err(error) => close_errors.push(error.to_string()),
                }
            }
            if let Some(root) = session.root.take() {
                if let Err(error) =
                    close_checked(root, "CloseHandle(profile root after finalization failure)")
                {
                    close_errors.push(error.to_string());
                }
            }
        }

        match (transition, close_errors.is_empty()) {
            (Ok(()), true) => Ok(()),
            (Ok(()), false) => Err(io::Error::other(format!(
                "profile close finalization failed after successful SDK absence proof: {}",
                close_errors.join("; ")
            ))),
            (Err(primary), true) => Err(primary),
            (Err(primary), false) => Err(io::Error::other(format!(
                "profile finalization failed: {primary}; remaining anchor close failures: {}",
                close_errors.join("; ")
            ))),
        }
    }

    fn duplicate_job_fence(child: &OwnedProcess<'_>, role: &'static str) -> io::Result<JobFence> {
        let mut duplicate = null_mut();
        unsafe {
            ok(
                "DuplicateHandle(query-only registry witness Job fence)",
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.job.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut duplicate,
                    JOB_OBJECT_QUERY_ONLY,
                    0,
                    0,
                ),
            )?;
        }
        let handle = own("DuplicateHandle(registry witness Job fence)", duplicate)?;
        let pid = child.pid();
        let creation = process_creation_text(child.process.as_raw_handle())?;
        Ok(JobFence {
            handle,
            role,
            pid,
            creation,
            process_waited: false,
        })
    }

    pub(super) fn identity_text(identity: (u64, [u8; 16])) -> String {
        format!(
            "{:016X}:{}",
            identity.0,
            identity
                .1
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        )
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct HelperPeHeader {
        machine: u16,
        subsystem: u16,
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> io::Result<u16> {
        let end = offset
            .checked_add(size_of::<u16>())
            .ok_or_else(|| invalid("helper PE field offset overflow"))?;
        let field = bytes
            .get(offset..end)
            .ok_or_else(|| invalid("helper PE field is truncated"))?;
        Ok(u16::from_le_bytes([field[0], field[1]]))
    }

    fn read_u32_le(bytes: &[u8], offset: usize) -> io::Result<u32> {
        let end = offset
            .checked_add(size_of::<u32>())
            .ok_or_else(|| invalid("helper PE field offset overflow"))?;
        let field = bytes
            .get(offset..end)
            .ok_or_else(|| invalid("helper PE field is truncated"))?;
        Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
    }

    fn parse_helper_pe_header(bytes: &[u8]) -> io::Result<HelperPeHeader> {
        const DOS_HEADER_BYTES: usize = 64;
        const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
        const COFF_HEADER_BYTES: usize = 20;
        const PE32_PLUS_MAGIC: u16 = 0x020b;
        const PE32_PLUS_FIXED_BYTES: usize = 112;
        const OPTIONAL_SUBSYSTEM_OFFSET: usize = 68;

        if bytes.get(..2) != Some(b"MZ") || bytes.len() < DOS_HEADER_BYTES {
            return Err(invalid(
                "helper image has a truncated or missing DOS header",
            ));
        }
        let pe_offset = usize::try_from(read_u32_le(bytes, 0x3c)?)
            .map_err(|_| invalid("helper PE header offset conversion overflow"))?;
        if pe_offset < DOS_HEADER_BYTES {
            return Err(invalid("helper PE header overlaps the DOS header"));
        }
        let signature_end = pe_offset
            .checked_add(PE_SIGNATURE.len())
            .ok_or_else(|| invalid("helper PE signature offset overflow"))?;
        if bytes.get(pe_offset..signature_end) != Some(PE_SIGNATURE.as_slice()) {
            return Err(invalid("helper PE signature is missing or truncated"));
        }
        let coff_offset = signature_end;
        let coff_end = coff_offset
            .checked_add(COFF_HEADER_BYTES)
            .ok_or_else(|| invalid("helper COFF header offset overflow"))?;
        let coff = bytes
            .get(coff_offset..coff_end)
            .ok_or_else(|| invalid("helper COFF header is truncated"))?;
        let machine = u16::from_le_bytes([coff[0], coff[1]]);
        let optional_bytes = usize::from(u16::from_le_bytes([coff[16], coff[17]]));
        if optional_bytes < PE32_PLUS_FIXED_BYTES {
            return Err(invalid(
                "helper PE optional header is shorter than fixed PE32+ fields",
            ));
        }
        let optional_end = coff_end
            .checked_add(optional_bytes)
            .ok_or_else(|| invalid("helper PE optional header extent overflow"))?;
        let optional = bytes
            .get(coff_end..optional_end)
            .ok_or_else(|| invalid("helper PE optional header extent exceeds the image"))?;
        if read_u16_le(optional, 0)? != PE32_PLUS_MAGIC {
            return Err(invalid("helper image is not PE32+"));
        }
        let subsystem = read_u16_le(optional, OPTIONAL_SUBSYSTEM_OFFSET)?;
        Ok(HelperPeHeader { machine, subsystem })
    }

    fn validate_helper_pe_image(bytes: &[u8]) -> io::Result<HelperPeHeader> {
        let header = parse_helper_pe_header(bytes)?;
        if header.machine != 0x8664 || header.subsystem != 2 {
            return Err(invalid("held helper image must be AMD64 PE32+ GUI"));
        }
        Ok(header)
    }

    fn make_helper_pe_fixture() -> Vec<u8> {
        const PE_OFFSET: usize = 64;
        const COFF_OFFSET: usize = PE_OFFSET + 4;
        const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
        let mut bytes = vec![0u8; OPTIONAL_OFFSET + 112];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        bytes[COFF_OFFSET..COFF_OFFSET + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[COFF_OFFSET + 16..COFF_OFFSET + 18].copy_from_slice(&112u16.to_le_bytes());
        bytes[OPTIONAL_OFFSET..OPTIONAL_OFFSET + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        // Decoys at CheckSum and DllCharacteristics must not be read as Subsystem.
        bytes[OPTIONAL_OFFSET + 64..OPTIONAL_OFFSET + 68].copy_from_slice(&3u32.to_le_bytes());
        bytes[OPTIONAL_OFFSET + 68..OPTIONAL_OFFSET + 70].copy_from_slice(&2u16.to_le_bytes());
        bytes[OPTIONAL_OFFSET + 70..OPTIONAL_OFFSET + 72].copy_from_slice(&3u16.to_le_bytes());
        bytes
    }

    fn verify_helper_pe_parser_oracle() -> io::Result<()> {
        let valid = make_helper_pe_fixture();
        if validate_helper_pe_image(&valid)?
            != (HelperPeHeader {
                machine: 0x8664,
                subsystem: 2,
            })
        {
            return Err(invalid("valid helper PE32+ GUI oracle was rejected"));
        }

        let rejected = |mut bytes: Vec<u8>, offset: usize, value: u32| -> io::Result<()> {
            let field = bytes
                .get_mut(offset..offset + 4)
                .ok_or_else(|| invalid("helper PE oracle field is out of range"))?;
            field.copy_from_slice(&value.to_le_bytes());
            if parse_helper_pe_header(&bytes).is_ok() {
                return Err(invalid("invalid helper PE offset oracle was accepted"));
            }
            Ok(())
        };
        for length in [0, 2, 63, 64 + 2] {
            if parse_helper_pe_header(&valid[..length]).is_ok() {
                return Err(invalid(
                    "truncated helper DOS or PE signature oracle was accepted",
                ));
            }
        }
        if parse_helper_pe_header(&valid[..87]).is_ok() {
            return Err(invalid("truncated helper COFF header oracle was accepted"));
        }

        let pe_offset = 64usize;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        let mut overlapping = valid.clone();
        overlapping[0x3c..0x40].copy_from_slice(&62u32.to_le_bytes());
        if parse_helper_pe_header(&overlapping).is_ok() {
            return Err(invalid("overlapping helper PE header oracle was accepted"));
        }
        rejected(valid.clone(), 0x3c, u32::MAX)?;
        let mut short_optional = valid.clone();
        short_optional[coff_offset + 16..coff_offset + 18].copy_from_slice(&111u16.to_le_bytes());
        if parse_helper_pe_header(&short_optional).is_ok() {
            return Err(invalid(
                "short declared helper optional header oracle was accepted",
            ));
        }
        let mut oversized_optional = valid.clone();
        oversized_optional[coff_offset + 16..coff_offset + 18]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        if parse_helper_pe_header(&oversized_optional).is_ok() {
            return Err(invalid(
                "out-of-image helper optional header oracle was accepted",
            ));
        }
        let mut wrong_machine = valid.clone();
        wrong_machine[coff_offset..coff_offset + 2].copy_from_slice(&0x014cu16.to_le_bytes());
        if validate_helper_pe_image(&wrong_machine).is_ok() {
            return Err(invalid("wrong-machine helper PE oracle was accepted"));
        }
        let mut pe32 = valid.clone();
        pe32[optional_offset..optional_offset + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        if parse_helper_pe_header(&pe32).is_ok() {
            return Err(invalid("PE32 helper image oracle was accepted"));
        }
        for subsystem in [0u16, 3, 4, u16::MAX] {
            let mut wrong_subsystem = valid.clone();
            wrong_subsystem[optional_offset + 68..optional_offset + 70]
                .copy_from_slice(&subsystem.to_le_bytes());
            if validate_helper_pe_image(&wrong_subsystem).is_ok() {
                return Err(invalid("non-GUI helper subsystem oracle was accepted"));
            }
        }
        Ok(())
    }

    pub(super) fn process_creation_text(process: HANDLE) -> io::Result<String> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe {
            ok(
                "GetProcessTimes(registry witness identity)",
                GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user),
            )?;
        }
        let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        Ok(format!("{ticks:016X}"))
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl LocalSecurityDescriptor {
        fn free(&mut self) -> io::Result<()> {
            if self.0.is_null() {
                return Ok(());
            }
            let result = unsafe { LocalFree(self.0.cast()) };
            self.0 = null_mut();
            if result.is_null() {
                Ok(())
            } else {
                Err(operation_error(
                    "LocalFree(helper image security descriptor)",
                    io::Error::last_os_error(),
                ))
            }
        }
    }

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0.cast()) };
            }
        }
    }

    fn helper_directory_security_descriptor(
        user_sid: &str,
        package_sid: &str,
    ) -> io::Result<LocalSecurityDescriptor> {
        let descriptor_sddl = wide(OsStr::new(&format!(
            "O:{user_sid}D:P(A;;FA;;;{user_sid})(A;;FX;;;{package_sid})"
        )))?;
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            let primary = operation_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(helper directory)",
                io::Error::last_os_error(),
            );
            let mut allocation = LocalSecurityDescriptor(descriptor);
            return match allocation.free() {
                Ok(()) => Err(primary),
                Err(finalization) => Err(with_directory_diagnostics(
                    Some(primary),
                    vec![format!("descriptor finalization failed: {finalization}")],
                )),
            };
        }
        if descriptor.is_null() {
            return Err(invalid("helper directory descriptor is null"));
        }
        Ok(LocalSecurityDescriptor(descriptor))
    }

    fn helper_image_security_descriptor(
        user_sid: &str,
        package_sid: &str,
    ) -> io::Result<LocalSecurityDescriptor> {
        let descriptor_sddl = wide(OsStr::new(&format!(
            "O:{user_sid}D:P(A;;FA;;;{user_sid})(A;;FRFX;;;{package_sid})"
        )))?;
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            let primary = operation_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(helper image create)",
                io::Error::last_os_error(),
            );
            let mut allocation = LocalSecurityDescriptor(descriptor);
            return match allocation.free() {
                Ok(()) => Err(primary),
                Err(finalization) => Err(io::Error::other(format!(
                    "helper image descriptor conversion failed: {primary}; allocation release failed: {finalization}"
                ))),
            };
        }
        if descriptor.is_null() {
            return Err(invalid("helper image descriptor is null"));
        }
        Ok(LocalSecurityDescriptor(descriptor))
    }

    fn descriptor_dacl_bytes(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<Vec<u8>> {
        let (mut present, mut dacl, mut defaulted) = (0, null_mut(), 0);
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(operation_error(
                "GetSecurityDescriptorDacl(helper directory)",
                io::Error::last_os_error(),
            ));
        }
        if present == 0 || dacl.is_null() {
            return Err(invalid("helper directory DACL is absent or null"));
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(operation_error(
                "GetAclInformation(helper directory)",
                io::Error::last_os_error(),
            ));
        }
        let length = information.AclBytesInUse as usize;
        if length < size_of::<ACL>() || length > u16::MAX as usize {
            return Err(invalid("helper directory DACL length is outside bounds"));
        }
        // GetAclInformation supplied the bounded byte length for this live ACL.
        Ok(unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), length) }.to_vec())
    }

    fn create_owned_helper_directory(
        session: &SandboxSession,
        leaf: &str,
        user_sid: &str,
        package_sid: &str,
    ) -> io::Result<(OwnedHandle, Vec<u8>)> {
        let root = session
            .root
            .as_ref()
            .ok_or_else(|| invalid("profile closed"))?;
        let mut name: Vec<u16> = leaf.encode_utf16().collect();
        if name.is_empty() || name.contains(&0) {
            return Err(invalid("invalid helper directory component"));
        }
        let byte_length = name
            .len()
            .checked_mul(size_of::<u16>())
            .filter(|length| *length <= u16::MAX as usize - size_of::<u16>())
            .ok_or_else(|| invalid("helper directory name exceeds UNICODE_STRING limits"))?;
        name.push(0);
        let mut object_name = UNICODE_STRING {
            Length: byte_length as u16,
            MaximumLength: (byte_length + size_of::<u16>()) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let mut security = helper_directory_security_descriptor(user_sid, package_sid)?;
        let result = (|| {
            let expected_dacl = descriptor_dacl_bytes(security.0)?;
            let attributes = OBJECT_ATTRIBUTES {
                Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: root.as_raw_handle(),
                ObjectName: &mut object_name,
                Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
                SecurityDescriptor: security.0.cast(),
                SecurityQualityOfService: null_mut(),
            };
            let mut raw_handle = null_mut();
            let mut status = IO_STATUS_BLOCK::default();
            let ntstatus = unsafe {
                NtCreateFile(
                    &mut raw_handle,
                    DELETE
                        | FILE_LIST_DIRECTORY
                        | FILE_TRAVERSE
                        | FILE_READ_ATTRIBUTES
                        | READ_CONTROL
                        | SYNCHRONIZE,
                    &attributes,
                    &mut status,
                    null(),
                    FILE_ATTRIBUTE_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                    null(),
                    0,
                )
            };
            if ntstatus < 0 {
                return Err(operation_error(
                    "NtCreateFile(FILE_CREATE helper directory)",
                    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(ntstatus) } as i32),
                ));
            }
            // Transfer ownership before validation or any subsequent fallible work.
            let handle = own("NtCreateFile(helper directory handle)", raw_handle)?;
            if status.Information != FILE_CREATED as usize {
                return Err(operation_error(
                    "NtCreateFile(FILE_CREATE helper directory disposition)",
                    invalid("successful directory creation did not report FILE_CREATED"),
                ));
            }
            Ok((handle, expected_dacl))
        })();
        let finalization = security.free();
        match (result, finalization) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(finalization)) => Err(with_directory_diagnostics(
                None,
                vec![format!(
                    "helper descriptor finalization failed: {finalization}"
                )],
            )),
            (Err(primary), Err(finalization)) => Err(with_directory_diagnostics(
                Some(primary),
                vec![format!(
                    "helper descriptor finalization failed: {finalization}"
                )],
            )),
        }
    }

    struct DirectoryDescriptorObservation {
        owner_matches_user: Option<bool>,
        dacl_present: Option<bool>,
        dacl_null: Option<bool>,
        dacl_protected: Option<bool>,
        dacl_matches_expected: Option<bool>,
        errors: Vec<String>,
    }

    #[derive(Debug)]
    struct DirectoryDiagnosticContext {
        primary: Option<io::Error>,
        diagnostics: Vec<String>,
    }

    impl std::fmt::Display for DirectoryDiagnosticContext {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if let Some(primary) = &self.primary {
                write!(formatter, "{primary}")?;
            } else {
                formatter.write_str("helper directory diagnostic incomplete")?;
            }
            write!(
                formatter,
                "; diagnostic outcomes: {}",
                self.diagnostics.join("; ")
            )
        }
    }

    impl std::error::Error for DirectoryDiagnosticContext {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.primary
                .as_ref()
                .map(|primary| primary as &(dyn std::error::Error + 'static))
        }
    }

    fn with_directory_diagnostics(
        primary: Option<io::Error>,
        diagnostics: Vec<String>,
    ) -> io::Error {
        if diagnostics.is_empty() {
            return primary.unwrap_or_else(|| invalid("missing directory diagnostic outcome"));
        }
        let kind = primary
            .as_ref()
            .map_or(io::ErrorKind::Other, io::Error::kind);
        io::Error::new(
            kind,
            DirectoryDiagnosticContext {
                primary,
                diagnostics,
            },
        )
    }

    fn observed_bool(value: Option<bool>) -> &'static str {
        match value {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        }
    }

    fn record_helper_diagnostic(payload: &str, errors: &mut Vec<String>) {
        if let Err(error) = emit_witness_record(payload) {
            errors.push(format!("diagnostic record emission failed: {error}"));
        }
    }

    struct DirectoryAccessQuery {
        ntstatus: Option<i32>,
        returned_length: u32,
        granted_access: Option<u32>,
    }

    fn query_ntstatus_text(status: Option<i32>) -> String {
        status.map_or_else(|| "unsupported".to_owned(), |value| format!("{value:#x}"))
    }

    fn query_directory_handle_access(handle: HANDLE) -> DirectoryAccessQuery {
        // PUBLIC_OBJECT_BASIC_INFORMATION contains 14 ULONG/ACCESS_MASK fields.
        // A u32 array provides its required alignment without creating a typed
        // reference into raw bytes. The granted-access field is slot 1.
        let mut information = [0u32; 14];
        let expected_length = (information.len() * size_of::<u32>()) as u32;
        let mut returned_length = 0u32;
        let ntdll_name = match wide(OsStr::new("ntdll.dll")) {
            Ok(name) => name,
            Err(_) => {
                return DirectoryAccessQuery {
                    ntstatus: None,
                    returned_length: 0,
                    granted_access: None,
                };
            }
        };
        let module = unsafe { GetModuleHandleW(ntdll_name.as_ptr()) };
        if module.is_null() {
            return DirectoryAccessQuery {
                ntstatus: None,
                returned_length: 0,
                granted_access: None,
            };
        }
        let Some(export) = (unsafe { GetProcAddress(module, b"NtQueryObject\0".as_ptr()) }) else {
            return DirectoryAccessQuery {
                ntstatus: None,
                returned_length: 0,
                granted_access: None,
            };
        };
        type NtQueryObjectFn = unsafe extern "system" fn(
            HANDLE,
            windows_sys::Wdk::Foundation::OBJECT_INFORMATION_CLASS,
            *mut c_void,
            u32,
            *mut u32,
        ) -> NTSTATUS;
        // SAFETY: resolve the documented NtQueryObject export from the already
        // loaded system ntdll and use its windows-sys 0.61.2 declaration shape.
        let query: NtQueryObjectFn = unsafe { std::mem::transmute(export) };
        let status = unsafe {
            query(
                handle,
                ObjectBasicInformation,
                information.as_mut_ptr().cast(),
                expected_length,
                &mut returned_length,
            )
        };
        let granted_access = if status >= 0 && returned_length == expected_length {
            Some(information[1])
        } else {
            None
        };
        DirectoryAccessQuery {
            ntstatus: Some(status),
            returned_length,
            granted_access,
        }
    }

    fn observe_directory_descriptor(
        path: &Path,
        original_identity: (u64, [u8; 16]),
        user_sid: &str,
        expected_dacl: Option<&[u8]>,
    ) -> DirectoryDescriptorObservation {
        let mut observation = DirectoryDescriptorObservation {
            owner_matches_user: None,
            dacl_present: None,
            dacl_null: None,
            dacl_protected: None,
            dacl_matches_expected: None,
            errors: Vec::new(),
        };
        let path_wide = match wide(path.as_os_str()) {
            Ok(value) => value,
            Err(error) => {
                observation.errors.push(format!(
                    "directory descriptor path encoding failed: {error}"
                ));
                return observation;
            }
        };
        let read_handle = match own(
            "CreateFileW(helper directory READ_CONTROL observation)",
            unsafe {
                CreateFileW(
                    path_wide.as_ptr(),
                    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            },
        ) {
            Ok(handle) => handle,
            Err(error) => {
                observation
                    .errors
                    .push(format!("directory READ_CONTROL open failed: {error}"));
                return observation;
            }
        };
        if let Err(error) = check_object(read_handle.as_raw_handle(), true) {
            observation.errors.push(format!(
                "directory READ_CONTROL object check failed: {error}"
            ));
            return observation;
        }
        let read_identity = match script_identity(read_handle.as_raw_handle()) {
            Ok(identity) => identity,
            Err(error) => {
                observation
                    .errors
                    .push(format!("directory READ_CONTROL identity failed: {error}"));
                return observation;
            }
        };
        if read_identity != original_identity {
            observation
                .errors
                .push("directory READ_CONTROL handle identity mismatch".to_owned());
            return observation;
        }

        let (mut owner, mut descriptor) = (null_mut(), null_mut());
        let status = unsafe {
            GetSecurityInfo(
                read_handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        let mut descriptor = LocalSecurityDescriptor(descriptor);
        let observation_result = (|| {
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if descriptor.0.is_null() {
                return Err(invalid("GetSecurityInfo returned a null descriptor"));
            }
            observation.owner_matches_user = match sid_text(owner) {
                Ok(text) => Some(text == user_sid),
                Err(error) => {
                    observation
                        .errors
                        .push(format!("directory owner SID comparison failed: {error}"));
                    None
                }
            };

            let (mut dacl_present, mut dacl_pointer, mut defaulted) = (0, null_mut(), 0);
            let dacl_ok = unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.0,
                    &mut dacl_present,
                    &mut dacl_pointer,
                    &mut defaulted,
                )
            };
            if dacl_ok == 0 {
                let error = io::Error::last_os_error();
                observation
                    .errors
                    .push(format!("GetSecurityDescriptorDacl failed: {error}"));
            } else {
                observation.dacl_present = Some(dacl_present != 0);
                observation.dacl_null = Some(dacl_pointer.is_null());
                if dacl_present != 0 && !dacl_pointer.is_null() {
                    match descriptor_dacl_bytes(descriptor.0) {
                        Ok(actual) => {
                            observation.dacl_matches_expected =
                                expected_dacl.map(|expected| actual.as_slice() == expected);
                        }
                        Err(error) => observation
                            .errors
                            .push(format!("directory DACL verification failed: {error}")),
                    }
                } else if expected_dacl.is_some() {
                    observation.dacl_matches_expected = Some(false);
                }
            }

            let (mut control, mut revision) = (0, 0);
            let control_ok =
                unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) };
            if control_ok == 0 {
                let error = io::Error::last_os_error();
                observation
                    .errors
                    .push(format!("GetSecurityDescriptorControl failed: {error}"));
            } else {
                observation.dacl_protected = Some(control & SE_DACL_PROTECTED != 0);
            }
            Ok(())
        })();
        if let Err(error) = observation_result {
            observation.errors.push(format!(
                "GetSecurityInfo(helper directory READ_CONTROL) failed: {error}"
            ));
        }
        if let Err(error) = descriptor.free() {
            observation.errors.push(error.to_string());
        }
        observation
    }

    fn hold_helper_image(
        session: &SandboxSession,
        nonce: &str,
        user_sid: &str,
        package_sid: &str,
        control: Option<CleanupControl>,
    ) -> io::Result<HeldHelperImage> {
        let leaf = format!("registry-helper-{nonce}");
        let directory = session.folder.join(&leaf);
        let path = directory.join("orbit-registry-helper.exe");
        let source = std::env::current_exe()?;
        let source_meta = std::fs::metadata(&source)?;
        if !source_meta.is_file() || source_meta.len() == 0 || source_meta.len() > 128 * 1024 * 1024
        {
            return Err(invalid(
                "test helper image size is outside the reviewed bound",
            ));
        }
        let (directory_handle, expected_directory_dacl) =
            create_owned_helper_directory(session, &leaf, user_sid, package_sid)?;
        let mut directory_owner = Some(directory_handle);
        let mut image_writer: Option<File> = None;
        let mut metadata_anchor: Option<OwnedHandle> = None;
        let mut control_dacl_handle: Option<OwnedHandle> = None;
        let mut immutable_reader: Option<File> = None;
        let mut security: Option<LocalSecurityDescriptor> = None;

        let build = (|| -> io::Result<HeldHelperImage> {
            let directory_raw = directory_owner
                .as_ref()
                .ok_or_else(|| invalid("helper directory owner missing during setup"))?
                .as_raw_handle();
            let directory_identity = script_identity(directory_raw)?;
            check_object(directory_raw, true)?;
            let required_directory_access = DELETE
                | FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE;
            let mut diagnostic_errors = Vec::new();
            let query = query_directory_handle_access(directory_raw);
            let granted_access = query.granted_access;
            let access_record = format!(
                "registry_witness_helper_directory_access requested={required_directory_access:#010x} query_ntstatus={} returned_length={} expected_length={} actual={} write_dac={}",
                query_ntstatus_text(query.ntstatus),
                query.returned_length,
                size_of::<[u32; 14]>(),
                granted_access.map_or_else(|| "unknown".to_owned(), |mask| format!("{mask:#010x}")),
                observed_bool(granted_access.map(|mask| mask & WRITE_DAC != 0))
            );
            record_helper_diagnostic(&access_record, &mut diagnostic_errors);
            if granted_access.is_none_or(|actual| {
                actual & required_directory_access != required_directory_access
            }) {
                diagnostic_errors.push(
                    "helper directory keeper lacks its required delete and identity rights"
                        .to_owned(),
                );
            }
            let observation = observe_directory_descriptor(
                &directory,
                directory_identity,
                user_sid,
                Some(&expected_directory_dacl),
            );
            let descriptor_record = format!(
                "registry_witness_helper_directory_descriptor owner_matches_user={} dacl_present={} dacl_null={} dacl_protected={} dacl_matches_expected={}",
                observed_bool(observation.owner_matches_user),
                observed_bool(observation.dacl_present),
                observed_bool(observation.dacl_null),
                observed_bool(observation.dacl_protected),
                observed_bool(observation.dacl_matches_expected)
            );
            record_helper_diagnostic(&descriptor_record, &mut diagnostic_errors);
            diagnostic_errors.extend(observation.errors);
            if observation.owner_matches_user != Some(true)
                || observation.dacl_present != Some(true)
                || observation.dacl_null != Some(false)
                || observation.dacl_protected != Some(true)
                || observation.dacl_matches_expected != Some(true)
                || !diagnostic_errors.is_empty()
            {
                return Err(with_directory_diagnostics(
                    Some(invalid("new helper directory security verification failed")),
                    diagnostic_errors,
                ));
            }

            security = Some(helper_image_security_descriptor(user_sid, package_sid)?);
            let expected_resource_dacl =
                descriptor_dacl_bytes(security.as_ref().expect("descriptor retained").0)?;
            let mut source_file = File::open(&source)
                .map_err(|error| operation_error("File::open(helper image source)", error))?;
            let target_handle = relative_create_file(
                directory_raw,
                "orbit-registry-helper.exe",
                FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                security.as_ref().expect("descriptor retained").0,
            )?;
            image_writer = Some(File::from(target_handle));
            {
                let writer = image_writer.as_mut().expect("writer owner retained");
                io::copy(&mut source_file, writer)
                    .map_err(|error| operation_error("io::copy(relative helper image)", error))?;
                writer
                    .flush()
                    .map_err(|error| operation_error("flush(relative helper image)", error))?;
            }
            let identity = script_identity(
                image_writer
                    .as_ref()
                    .expect("writer owner retained")
                    .as_raw_handle(),
            )?;
            check_object(
                image_writer
                    .as_ref()
                    .expect("writer owner retained")
                    .as_raw_handle(),
                false,
            )?;
            if resource_dacl_bytes(
                image_writer
                    .as_ref()
                    .expect("writer owner retained")
                    .as_raw_handle(),
            )? != expected_resource_dacl
            {
                return Err(invalid(
                    "created helper image DACL differs from its protected policy",
                ));
            }
            metadata_anchor = Some(relative_open(
                directory_raw,
                "orbit-registry-helper.exe",
                false,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            )?);
            if script_identity(
                metadata_anchor
                    .as_ref()
                    .expect("metadata anchor retained")
                    .as_raw_handle(),
            )? != identity
            {
                return Err(invalid("helper image metadata bridge identity changed"));
            }
            let writer = unsafe {
                OwnedHandle::from_raw_handle(
                    image_writer
                        .take()
                        .expect("writer owner retained")
                        .into_raw_handle(),
                )
            };
            close_checked(writer, "CloseHandle(helper image writer)")?;

            if control == Some(CleanupControl::ChangedImageDacl) {
                control_dacl_handle = Some(relative_open(
                    directory_raw,
                    "orbit-registry-helper.exe",
                    false,
                    WRITE_DAC | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                )?);
            }

            immutable_reader = Some(File::from(relative_open(
                directory_raw,
                "orbit-registry-helper.exe",
                false,
                FILE_GENERIC_READ | SYNCHRONIZE,
                FILE_SHARE_READ,
            )?));
            let reader = immutable_reader
                .as_mut()
                .expect("immutable reader retained");
            if script_identity(reader.as_raw_handle())? != identity {
                return Err(invalid(
                    "immutable helper reader identity differs from create handle",
                ));
            }
            check_object(reader.as_raw_handle(), false)?;
            if resource_dacl_bytes(reader.as_raw_handle())? != expected_resource_dacl {
                return Err(invalid("immutable helper image DACL changed"));
            }
            reader.seek(std::io::SeekFrom::Start(0))?;
            let mut image_bytes = Vec::with_capacity(source_meta.len() as usize);
            (&mut *reader)
                .take(source_meta.len() + 1)
                .read_to_end(&mut image_bytes)?;
            if image_bytes.len() as u64 != source_meta.len() {
                return Err(invalid("held helper image length changed during copy"));
            }
            let sha256 = digest(&image_bytes)?;
            if script_identity(reader.as_raw_handle())? != identity {
                return Err(invalid(
                    "immutable helper image identity changed while hashing",
                ));
            }
            let pe_header = validate_helper_pe_image(&image_bytes)?;
            emit_witness_record(&format!(
                "registry_witness_diagnostic stream=helper_image_pe image_id={} image_sha256={} image_bytes={} machine={:#06x} subsystem={:#06x}",
                identity_text(identity),
                sha256,
                image_bytes.len(),
                pe_header.machine,
                pe_header.subsystem
            ))?;
            reader.seek(std::io::SeekFrom::Start(0))?;
            Ok(HeldHelperImage {
                directory,
                path,
                directory_leaf: leaf,
                image_leaf: "orbit-registry-helper.exe".to_owned(),
                directory_handle: directory_owner.take(),
                file: immutable_reader.take(),
                metadata_anchor: metadata_anchor.take(),
                control_dacl_handle: control_dacl_handle.take(),
                directory_identity,
                identity,
                expected_length: source_meta.len(),
                expected_resource_dacl,
                expected_directory_dacl,
                sha256,
            })
        })();

        let descriptor_release = match security.as_mut() {
            Some(descriptor) => descriptor.free(),
            None => Ok(()),
        };
        let descriptor_release_error = descriptor_release.err().map(|error| error.to_string());
        let mut errors = Vec::new();
        if let Err(error) = &build {
            errors.push(error.to_string());
        }
        if let Some(error) = descriptor_release_error {
            errors.push(format!("helper image descriptor release failed: {error}"));
        }
        let mut built_image = match build {
            Ok(image) => Some(image),
            Err(_) => None,
        };
        if let Some(image) = built_image.as_mut() {
            if !errors.is_empty() {
                if let Some(reader) = image.file.take() {
                    if let Err(error) =
                        close_file_checked(reader, "CloseHandle(image after setup failure)")
                    {
                        errors.push(format!("immutable reader close failed: {error}"));
                    }
                }
                if let Some(anchor) = image.metadata_anchor.take() {
                    if let Err(error) =
                        close_checked(anchor, "CloseHandle(image bridge after setup failure)")
                    {
                        errors.push(format!("metadata anchor close failed: {error}"));
                    }
                }
                if let Some(handle) = image.control_dacl_handle.take() {
                    if let Err(error) = close_checked(
                        handle,
                        "CloseHandle(image DACL control after setup failure)",
                    ) {
                        errors.push(format!("image DACL control close failed: {error}"));
                    }
                }
                if let Some(directory) = image.directory_handle.take() {
                    if let Err(error) =
                        close_checked(directory, "CloseHandle(directory after setup failure)")
                    {
                        errors.push(format!("directory keeper close failed: {error}"));
                    }
                }
            }
        }
        if let Some(reader) = immutable_reader.take() {
            if let Err(error) =
                close_file_checked(reader, "CloseHandle(remaining helper image reader)")
            {
                errors.push(format!("remaining image reader close failed: {error}"));
            }
        }
        if let Some(writer) = image_writer.take() {
            if let Err(error) =
                close_file_checked(writer, "CloseHandle(remaining helper image writer)")
            {
                errors.push(format!("remaining image writer close failed: {error}"));
            }
        }
        if let Some(anchor) = metadata_anchor.take() {
            if let Err(error) =
                close_checked(anchor, "CloseHandle(remaining helper metadata anchor)")
            {
                errors.push(format!("remaining metadata anchor close failed: {error}"));
            }
        }
        if let Some(handle) = control_dacl_handle.take() {
            if let Err(error) = close_checked(handle, "CloseHandle(remaining image DACL control)") {
                errors.push(format!(
                    "remaining image DACL control close failed: {error}"
                ));
            }
        }
        if let Some(directory) = directory_owner.take() {
            if let Err(error) =
                close_checked(directory, "CloseHandle(remaining helper directory keeper)")
            {
                errors.push(format!("remaining directory keeper close failed: {error}"));
            }
        }
        if let Some(image) = built_image.take() {
            if errors.is_empty() {
                return Ok(image);
            }
            return Err(io::Error::other(format!(
                "helper image setup failed after image construction: {}",
                errors.join("; ")
            )));
        }
        Err(io::Error::other(format!(
            "helper image setup failed: {}",
            errors.join("; ")
        )))
    }

    impl HeldHelperImage {
        fn verify_preflight(&mut self, gate: &CleanupJobGate) -> io::Result<()> {
            gate.require_zero("helper image and directory preflight")?;
            let directory = self
                .directory_handle
                .as_ref()
                .ok_or_else(|| invalid("held helper directory keeper missing"))?;
            if script_identity(directory.as_raw_handle())? != self.directory_identity {
                return Err(invalid("held helper directory identity changed"));
            }
            check_object(directory.as_raw_handle(), true)?;
            if resource_dacl_bytes(directory.as_raw_handle())? != self.expected_directory_dacl {
                return Err(invalid("held helper directory descriptor changed"));
            }
            let reader = self
                .file
                .as_mut()
                .ok_or_else(|| invalid("immutable image reader missing"))?;
            verify_image_file(
                reader,
                self.identity,
                self.expected_length,
                &self.sha256,
                &self.expected_resource_dacl,
            )?;
            let children = profile_children(directory.as_raw_handle())?;
            if children.iter().any(|(name, identity, is_directory)| {
                name == &self.image_leaf && (*is_directory || *identity != self.identity.1)
            }) {
                return Err(invalid(
                    "helper image directory entry identity differs from its held original",
                ));
            }
            if children.len() != 1 || children[0].0 != self.image_leaf || children[0].2 {
                if children.iter().any(|(name, identity, is_directory)| {
                    name != &self.image_leaf && !*is_directory && *identity == self.identity.1
                }) {
                    return Err(invalid("resource is linked, replaced or of the wrong kind"));
                }
                return Err(invalid(
                    "helper directory contents differ from the exact owned image",
                ));
            }
            let anchor = self
                .metadata_anchor
                .as_ref()
                .ok_or_else(|| invalid("helper image identity bridge missing"))?;
            if script_identity(anchor.as_raw_handle())? != self.identity {
                return Err(invalid("helper image identity bridge changed"));
            }
            Ok(())
        }

        fn cleanup(
            mut self,
            session: &SandboxSession,
            gate: &CleanupJobGate,
        ) -> ImageDirectoryAbsence {
            let mut receipt = ImageDirectoryAbsence {
                image_disposition_succeeded: false,
                image_close_succeeded: false,
                image_absent: false,
                directory_disposition_succeeded: false,
                directory_close_succeeded: false,
                directory_absent: false,
                errors: Vec::new(),
            };
            let mut deletion_file: Option<File> = None;
            let mut deletion_handle: Option<OwnedHandle> = None;
            let outcome = (|| -> io::Result<()> {
                self.verify_preflight(gate)?;
                let directory_raw = self
                    .directory_handle
                    .as_ref()
                    .ok_or_else(|| invalid("held helper directory keeper missing"))?
                    .as_raw_handle();
                if script_identity(directory_raw)? != self.directory_identity {
                    return Err(invalid("held helper directory identity changed"));
                }
                check_object(directory_raw, true)?;
                if resource_dacl_bytes(directory_raw)? != self.expected_directory_dacl {
                    return Err(invalid("held helper directory descriptor changed"));
                }
                gate.require_zero("helper image reader close")?;
                close_file_checked(
                    self.file.take().expect("validated immutable reader"),
                    "CloseHandle(immutable helper image reader)",
                )?;
                gate.require_zero("helper image delete-capability open")?;
                deletion_handle = Some(relative_open(
                    directory_raw,
                    &self.image_leaf,
                    false,
                    FILE_GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ,
                )?);
                let delete_raw = deletion_handle
                    .as_ref()
                    .expect("delete-capability handle retained")
                    .as_raw_handle();
                if script_identity(delete_raw)? != self.identity {
                    return Err(invalid("helper image deletion handle identity changed"));
                }
                deletion_file = Some(File::from(
                    deletion_handle
                        .take()
                        .expect("delete-capability handle retained"),
                ));
                verify_image_file(
                    deletion_file
                        .as_mut()
                        .expect("delete handle retained for hashing"),
                    self.identity,
                    self.expected_length,
                    &self.sha256,
                    &self.expected_resource_dacl,
                )?;
                deletion_handle = Some(unsafe {
                    OwnedHandle::from_raw_handle(
                        deletion_file
                            .take()
                            .expect("delete file retained after hashing")
                            .into_raw_handle(),
                    )
                });
                gate.require_zero("helper image bridge close")?;
                close_checked(
                    self.metadata_anchor
                        .take()
                        .expect("validated identity bridge"),
                    "CloseHandle(helper image identity bridge)",
                )?;
                gate.require_zero("helper image disposition")?;
                disposition_once(
                    deletion_handle
                        .as_ref()
                        .expect("delete-capability owner retained")
                        .as_raw_handle(),
                )?;
                receipt.image_disposition_succeeded = true;
                close_checked(
                    deletion_handle
                        .take()
                        .expect("delete-capability owner retained"),
                    "CloseHandle(helper image deletion capability)",
                )?;
                receipt.image_close_succeeded = true;
                gate.require_zero("helper image absence probe")?;
                receipt.image_absent =
                    relative_probe_absent(directory_raw, &self.image_leaf, false)?;

                gate.require_zero("helper directory pre-disposition")?;
                if script_identity(directory_raw)? != self.directory_identity
                    || !profile_children(directory_raw)?.is_empty()
                {
                    return Err(invalid("helper directory identity or emptiness changed"));
                }
                let root = session.root.as_ref().ok_or_else(|| {
                    invalid("profile root closed before helper directory absence")
                })?;
                gate.require_zero("helper directory disposition")?;
                disposition_once(directory_raw)?;
                receipt.directory_disposition_succeeded = true;
                close_checked(
                    self.directory_handle
                        .take()
                        .expect("validated directory keeper"),
                    "CloseHandle(helper directory deletion capability)",
                )?;
                receipt.directory_close_succeeded = true;
                gate.require_zero("helper directory absence probe")?;
                receipt.directory_absent =
                    relative_probe_absent(root.as_raw_handle(), &self.directory_leaf, true)?;
                if !receipt.image_absent || !receipt.directory_absent {
                    return Err(invalid("helper image/directory absence was not proved"));
                }
                Ok(())
            })();

            if let Some(file) = deletion_file.take() {
                if let Err(error) =
                    close_file_checked(file, "CloseHandle(partial image delete reader)")
                {
                    receipt
                        .errors
                        .push(format!("partial image reader close failed: {error}"));
                }
            }
            if let Some(handle) = deletion_handle.take() {
                if let Err(error) =
                    close_checked(handle, "CloseHandle(partial image delete capability)")
                {
                    receipt.errors.push(format!(
                        "partial image delete-capability close failed: {error}"
                    ));
                }
            }
            if let Some(reader) = self.file.take() {
                if let Err(error) =
                    close_file_checked(reader, "CloseHandle(remaining immutable helper reader)")
                {
                    receipt
                        .errors
                        .push(format!("remaining helper reader close failed: {error}"));
                }
            }
            if let Some(anchor) = self.metadata_anchor.take() {
                if let Err(error) = close_checked(
                    anchor,
                    "CloseHandle(remaining helper image identity bridge)",
                ) {
                    receipt.errors.push(format!(
                        "remaining helper identity bridge close failed: {error}"
                    ));
                }
            }
            if let Some(directory) = self.directory_handle.take() {
                if let Err(error) =
                    close_checked(directory, "CloseHandle(remaining helper directory keeper)")
                {
                    receipt.errors.push(format!(
                        "remaining helper directory keeper close failed: {error}"
                    ));
                }
            }
            if let Err(error) = outcome {
                receipt.errors.push(format!(
                    "helper cleanup failed; image={} directory={} directory_identity={} image_absent={} directory_absent={}: {error}",
                    self.path.display(),
                    self.directory.display(),
                    identity_text(self.directory_identity),
                    receipt.image_absent,
                    receipt.directory_absent
                ));
            }
            receipt
        }
    }

    impl PrivateRegistryFixture {
        fn create(nonce: &str, user_sid: &str, package_sid: &str) -> io::Result<Self> {
            let software = win32_open_key(HKEY_CURRENT_USER, "Software", KEY_ALL_ACCESS)
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let name = format!("ORBIT_WITNESS_{nonce}");
            let policy = format!(
                "O:{user_sid}D:P(D;;0x000D0026;;;{package_sid})(A;;RC;;;OW)(A;;KA;;;{user_sid})(A;;KR;;;{package_sid})"
            );
            let root = create_acl_key(software.raw(), &name, &policy)?;
            let mut created_keys = vec![String::new()];
            let mut expected_values = Vec::new();
            let marker = "ORBIT-PRIVATE-METADATA-V1".to_owned();
            let build: io::Result<()> = (|| {
                for view_name in ["MachineView", "UserView"] {
                    let view = create_acl_key(root.raw(), view_name, &policy)?;
                    created_keys.push(view_name.to_owned());
                    let metadata_path = format!("{view_name}\\Metadata");
                    let metadata = create_acl_key(view.raw(), "Metadata", &policy)?;
                    created_keys.push(metadata_path.clone());
                    expected_values.push((metadata_path, "Fixture".to_owned(), marker.clone()));
                    set_string(metadata.raw(), "Fixture", &marker)?;
                    metadata.close()?;
                    expected_values.push((
                        view_name.to_owned(),
                        "Mutation".to_owned(),
                        "unchanged-v1".to_owned(),
                    ));
                    set_string(view.raw(), "Mutation", "unchanged-v1")?;
                    let leaf_path = format!("{view_name}\\DeleteLeaf");
                    let leaf = create_acl_key(view.raw(), "DeleteLeaf", &policy)?;
                    created_keys.push(leaf_path.clone());
                    expected_values.push((
                        leaf_path,
                        "Fixture".to_owned(),
                        "delete-target-v1".to_owned(),
                    ));
                    set_string(leaf.raw(), "Fixture", "delete-target-v1")?;
                    leaf.close()?;
                    view.close()?;
                }
                Ok(())
            })();
            let mut fixture = Self {
                name,
                root: Some(root),
                software: Some(software),
                created_keys,
                expected_values,
                completed_steps: Vec::new(),
            };
            if let Err(primary) = build {
                return match fixture.cleanup_owned() {
                    Ok(()) => {
                        let detail = format!(
                            "fixture setup failed: {primary}; exact-owned cleanup=absence proven; nonce_root=Software\\{}",
                            fixture.name
                        );
                        let record = emit_witness_record(&format!(
                            "registry_witness_setup_cleanup object=private_fixture nonce_root=Software\\{} outcome=absence_proven",
                            fixture.name
                        ));
                        Err(io::Error::other(match record {
                            Ok(()) => detail,
                            Err(record_error) => {
                                format!("{detail}; status record emission failed: {record_error}")
                            }
                        }))
                    }
                    Err(cleanup) => {
                        let detail = format!(
                            "fixture setup failed: {primary}; exact-owned cleanup/residue: {cleanup}"
                        );
                        let record = emit_witness_record(&format!(
                            "registry_witness_setup_cleanup object=private_fixture outcome=FAILED detail={}",
                            escape_diagnostic(detail.as_bytes())
                        ));
                        Err(io::Error::other(match record {
                            Ok(()) => detail,
                            Err(record_error) => {
                                format!("{detail}; status record emission failed: {record_error}")
                            }
                        }))
                    }
                };
            }
            Ok(fixture)
        }

        fn root_handle(&self, view: &str, access: REG_SAM_FLAGS) -> io::Result<OwnedRegKey> {
            let path = format!("{view}");
            win32_open_key(
                self.root.as_ref().expect("fixture root open").raw(),
                &path,
                access,
            )
            .map_err(|status| io::Error::from_raw_os_error(status as i32))
        }

        fn verify_known_preimages_unchanged(&self) -> io::Result<()> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            for (key_path, value_name, expected) in &self.expected_values {
                let key = if key_path.is_empty() {
                    None
                } else {
                    Some(
                        win32_open_key(root.raw(), key_path, KEY_QUERY_VALUE)
                            .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                    )
                };
                let handle = key.as_ref().map_or(root.raw(), OwnedRegKey::raw);
                let observed = win32_query_value_handle(handle, value_name)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))
                    .and_then(|bytes| decode_reg_sz(&bytes));
                let close = key.map_or(Ok(()), OwnedRegKey::close);
                match (observed, close) {
                    (Ok(value), Ok(())) if value == *expected => {}
                    (Ok(value), Ok(())) => {
                        return Err(io::Error::other(format!(
                            "known private value changed at {key_path}\\{value_name}: {value}"
                        )));
                    }
                    (Err(primary), Ok(())) => return Err(primary),
                    (Ok(_), Err(close)) => {
                        return Err(io::Error::other(format!(
                            "known value observer close failed at {key_path}\\{value_name}: {close}"
                        )));
                    }
                    (Err(primary), Err(close)) => {
                        return Err(io::Error::other(format!(
                            "known value verification failed: {primary}; observer close failed: {close}"
                        )));
                    }
                }
            }
            for view in ["MachineView", "UserView"] {
                let key = self.root_handle(view, KEY_READ)?;
                let label = private_view_label(key.raw());
                let close = key.close();
                match (label, close) {
                    (Ok(true), Ok(())) => {}
                    (Ok(false), Ok(())) => {
                        return Err(io::Error::other(format!(
                            "private view label changed at {view}"
                        )));
                    }
                    (Err(primary), Ok(())) => return Err(primary),
                    (Ok(_), Err(close)) => {
                        return Err(io::Error::other(format!(
                            "private view observer close failed at {view}: {close}"
                        )));
                    }
                    (Err(primary), Err(close)) => {
                        return Err(io::Error::other(format!(
                            "private view verification failed: {primary}; observer close failed: {close}"
                        )));
                    }
                }
            }
            Ok(())
        }

        fn view_preimages(&self) -> io::Result<(PrivateViewPreimage, PrivateViewPreimage)> {
            let machine = self.root_handle("MachineView", KEY_READ)?;
            let machine_preimage = private_view_preimage(machine.raw());
            let machine_close = machine.close();
            let machine_preimage = match (machine_preimage, machine_close) {
                (Ok(preimage), Ok(())) => preimage,
                (Err(primary), Ok(())) => return Err(primary),
                (Ok(_), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "MachineView observer close failed: {close}"
                    )));
                }
                (Err(primary), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "MachineView preimage failed: {primary}; observer close failed: {close}"
                    )));
                }
            };
            let user = self.root_handle("UserView", KEY_READ)?;
            let user_preimage = private_view_preimage(user.raw());
            let user_close = user.close();
            let user_preimage = match (user_preimage, user_close) {
                (Ok(preimage), Ok(())) => preimage,
                (Err(primary), Ok(())) => return Err(primary),
                (Ok(_), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "UserView observer close failed: {close}"
                    )));
                }
                (Err(primary), Err(close)) => {
                    return Err(io::Error::other(format!(
                        "UserView preimage failed: {primary}; observer close failed: {close}"
                    )));
                }
            };
            Ok((machine_preimage, user_preimage))
        }

        fn verify_root_present(&self) -> io::Result<()> {
            let software = self
                .software
                .as_ref()
                .ok_or_else(|| invalid("Software registry anchor missing"))?;
            let held = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let observation = win32_open_key(software.raw(), &self.name, KEY_READ)
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let comparison = match (
                registry_key_security(observation.raw()),
                registry_key_security(held.raw()),
            ) {
                (Ok(observed), Ok(expected)) if observed == expected => Ok(()),
                (Ok(_), Ok(_)) => Err(invalid("private fixture root security descriptor changed")),
                (Err(primary), Ok(_)) | (Ok(_), Err(primary)) => Err(primary),
                (Err(primary), Err(other)) => Err(io::Error::other(format!(
                    "private root security observations failed: {primary}; {other}"
                ))),
            };
            let close = observation.close();
            match (comparison, close) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(()), Err(close)) => Err(io::Error::other(format!(
                    "private root observer close failed: {close}"
                ))),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "private root verification failed: {primary}; observer close failed: {close}"
                ))),
            }
        }

        fn create_unknown_key_canary(
            &self,
            user_sid: &str,
            package_sid: &str,
        ) -> io::Result<PrivateCanaryFacts> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let policy = format!(
                "O:{user_sid}D:P(D;;0x000D0026;;;{package_sid})(A;;RC;;;OW)(A;;KA;;;{user_sid})(A;;KR;;;{package_sid})"
            );
            if win32_open_status(root.raw(), "ForeignCanary", KEY_READ) != ERROR_FILE_NOT_FOUND {
                return Err(invalid(
                    "foreign registry key canary was not absent before setup",
                ));
            }
            let key = create_acl_key(root.raw(), "ForeignCanary", &policy)?;
            let result = (|| {
                set_string(key.raw(), "Marker", "ORBIT-FOREIGN-CANARY-V1")?;
                let value = win32_query_value(&key, "Marker")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
                let descriptor = registry_key_security(key.raw())?;
                Ok(PrivateCanaryFacts {
                    value_sha256: digest(&value)?,
                    descriptor_sha256: digest(&descriptor)?,
                })
            })();
            let close = key.close();
            match (result, close) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(close)) => Err(io::Error::other(format!(
                    "foreign canary key close failed: {close}"
                ))),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "foreign canary setup failed: {primary}; key close failed: {close}"
                ))),
            }
        }

        fn unknown_key_canary_facts(&self) -> io::Result<PrivateCanaryFacts> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let key = win32_open_key(root.raw(), "ForeignCanary", KEY_READ)
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let result = (|| {
                let value = win32_query_value(&key, "Marker")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
                let descriptor = registry_key_security(key.raw())?;
                Ok(PrivateCanaryFacts {
                    value_sha256: digest(&value)?,
                    descriptor_sha256: digest(&descriptor)?,
                })
            })();
            let close = key.close();
            match (result, close) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(close)) => Err(io::Error::other(format!(
                    "foreign canary observer close failed: {close}"
                ))),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "foreign canary verification failed: {primary}; observer close failed: {close}"
                ))),
            }
        }

        fn create_unknown_value_canary(&self) -> io::Result<PrivateCanaryFacts> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let key = win32_open_key(root.raw(), "MachineView\\Metadata", KEY_ALL_ACCESS)
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let result = (|| {
                match win32_query_value(&key, "UnexpectedControlValue") {
                    Err(ERROR_FILE_NOT_FOUND) => {}
                    Ok(_) => {
                        return Err(invalid(
                            "unknown registry value canary existed before setup",
                        ));
                    }
                    Err(status) => return Err(io::Error::from_raw_os_error(status as i32)),
                }
                set_string(
                    key.raw(),
                    "UnexpectedControlValue",
                    "ORBIT-UNKNOWN-VALUE-V1",
                )?;
                let value = win32_query_value(&key, "UnexpectedControlValue")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
                if win32_query_value_type(key.raw(), "UnexpectedControlValue")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?
                    != REG_SZ
                {
                    return Err(invalid("unknown registry value canary is not REG_SZ"));
                }
                let descriptor = registry_key_security(key.raw())?;
                Ok(PrivateCanaryFacts {
                    value_sha256: digest(&value)?,
                    descriptor_sha256: digest(&descriptor)?,
                })
            })();
            let close = key.close();
            match (result, close) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(close)) => Err(io::Error::other(format!(
                    "unexpected registry value setup close failed: {close}"
                ))),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "unexpected registry value setup failed: {primary}; key close failed: {close}"
                ))),
            }
        }

        fn unknown_value_canary_facts(&self) -> io::Result<PrivateCanaryFacts> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let key = win32_open_key(
                root.raw(),
                "MachineView\\Metadata",
                KEY_QUERY_VALUE | READ_CONTROL,
            )
            .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
            let result = (|| {
                let value = win32_query_value(&key, "UnexpectedControlValue")
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
                let descriptor = registry_key_security(key.raw())?;
                Ok(PrivateCanaryFacts {
                    value_sha256: digest(&value)?,
                    descriptor_sha256: digest(&descriptor)?,
                })
            })();
            let close = key.close();
            match (result, close) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(close)) => Err(io::Error::other(format!(
                    "unexpected registry value observation close failed: {close}"
                ))),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "unexpected registry value observation failed: {primary}; key close failed: {close}"
                ))),
            }
        }

        fn verify_unchanged(&self) -> io::Result<()> {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture root owner missing"))?;
            let expected_keys: BTreeSet<String> = self.created_keys.iter().cloned().collect();
            let mut observed_keys = BTreeSet::from([String::new()]);
            let mut pending = vec![String::new()];
            let mut observed_values = BTreeSet::new();
            while let Some(path) = pending.pop() {
                let key = if path.is_empty() {
                    None
                } else {
                    Some(
                        win32_open_key(root.raw(), &path, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS)
                            .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                    )
                };
                let handle = key.as_ref().map_or(root.raw(), OwnedRegKey::raw);

                for index in 0..64u32 {
                    let mut name = [0u16; 512];
                    let mut length = name.len() as u32;
                    let status = unsafe {
                        RegEnumKeyExW(
                            handle,
                            index,
                            name.as_mut_ptr(),
                            &mut length,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    if status == 259 {
                        break;
                    }
                    if status != ERROR_SUCCESS || length as usize > name.len() {
                        return Err(io::Error::other(format!(
                            "bounded private fixture subkey enumeration failed at {path}: {status}"
                        )));
                    }
                    let child = String::from_utf16(&name[..length as usize])
                        .map_err(|_| invalid("private fixture subkey name is not valid UTF-16"))?;
                    let child_path = if path.is_empty() {
                        child
                    } else {
                        format!("{path}\\{child}")
                    };
                    if !observed_keys.insert(child_path.clone()) {
                        return Err(invalid("duplicate private fixture key during inventory"));
                    }
                    if observed_keys.len() > 16 {
                        return Err(invalid("private fixture key inventory exceeded its bound"));
                    }
                    pending.push(child_path);
                }
                if pending.len() + observed_keys.len() > 16 {
                    return Err(invalid("private fixture traversal exceeded its key bound"));
                }

                for index in 0..64u32 {
                    let mut name = [0u16; 512];
                    let mut length = name.len() as u32;
                    let status = unsafe {
                        RegEnumValueW(
                            handle,
                            index,
                            name.as_mut_ptr(),
                            &mut length,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    if status == 259 {
                        break;
                    }
                    if status != ERROR_SUCCESS || length as usize > name.len() {
                        return Err(io::Error::other(format!(
                            "bounded private fixture value enumeration failed at {path}: {status}"
                        )));
                    }
                    let value = String::from_utf16(&name[..length as usize])
                        .map_err(|_| invalid("private fixture value name is not valid UTF-16"))?;
                    observed_values.insert((path.clone(), value));
                }
                if let Some(key) = key {
                    key.close()?;
                }
            }

            let expected_values: BTreeSet<(String, String)> = self
                .expected_values
                .iter()
                .map(|(path, name, _)| (path.clone(), name.clone()))
                .collect();
            if observed_keys != expected_keys || observed_values != expected_values {
                return Err(io::Error::other(format!(
                    "private fixture inventory changed; keys_match={} values_match={}",
                    observed_keys == expected_keys,
                    observed_values == expected_values
                )));
            }

            for view in ["MachineView", "UserView"] {
                let key = self.root_handle(view, KEY_READ)?;
                if !private_view_label(key.raw())?
                    || decode_reg_sz(
                        &win32_query_value(&key, "Mutation")
                            .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                    )? != "unchanged-v1"
                {
                    return Err(io::Error::other("private fixture data changed"));
                }
                let leaf = win32_open_key(key.raw(), "DeleteLeaf", KEY_READ)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?;
                if decode_reg_sz(
                    &win32_query_value(&leaf, "Fixture")
                        .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                )? != "delete-target-v1"
                {
                    return Err(io::Error::other("private delete target changed"));
                }
            }
            Ok(())
        }

        fn cleanup(&mut self, gate: &CleanupJobGate) -> io::Result<RegistryAbsence> {
            gate.require_zero("registry fixture cleanup preflight")?;
            self.verify_unchanged().map_err(|preimage| {
                io::Error::other(format!(
                    "registry preimage changed; no cleanup mutation attempted: {preimage}"
                ))
            })?;
            self.cleanup_owned_steps(Some(gate))?
                .ok_or_else(|| invalid("registry parent receipt missing"))
        }

        fn cleanup_owned(&mut self) -> io::Result<()> {
            let outcome = match self.cleanup_owned_steps(None) {
                Ok(Some(mut receipt)) => match receipt.software.take() {
                    Some(software) => match software.close() {
                        Ok(()) => {
                            receipt.anchor_closed = true;
                            receipt.verify()
                        }
                        Err(error) => Err(io::Error::other(format!(
                            "setup rollback Software anchor close failed after verified absence: {error}"
                        ))),
                    },
                    None => Err(invalid("setup rollback Software anchor missing")),
                },
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            outcome.map_err(|error| {
                let keys = self.created_keys.join(",");
                let values = self
                    .expected_values
                    .iter()
                    .map(|(key, name, _)| format!("{key}\\{name}"))
                    .collect::<Vec<_>>()
                    .join(",");
                io::Error::other(format!(
                    "{error}; nonce_root=Software\\{}; tracked_key_candidates=[{keys}]; tracked_value_candidates=[{values}]; residue_state=unverified",
                    self.name
                ))
            })
        }

        fn cleanup_owned_steps(
            &mut self,
            gate: Option<&CleanupJobGate>,
        ) -> io::Result<Option<RegistryAbsence>> {
            let software_handle = self
                .software
                .as_ref()
                .ok_or_else(|| invalid("Software registry anchor missing"))?;
            let software = software_handle.raw();
            let root_handle = self
                .root
                .as_ref()
                .ok_or_else(|| invalid("private fixture cleanup owner missing"))?
                .raw();
            for (key_path, value_name, expected) in &self.expected_values {
                let key = if key_path.is_empty() {
                    None
                } else {
                    Some(
                        win32_open_key(root_handle, key_path, KEY_QUERY_VALUE | KEY_SET_VALUE)
                            .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                    )
                };
                let handle = key.as_ref().map_or(root_handle, OwnedRegKey::raw);
                let existing = win32_query_value_handle(handle, value_name);
                match existing {
                    Ok(bytes) if decode_reg_sz(&bytes)? == *expected => {
                        if let Some(gate) = gate {
                            gate.require_zero("registry value disposition")?;
                        }
                        let name = wide(OsStr::new(value_name))?;
                        let status = unsafe { RegDeleteValueW(handle, name.as_ptr()) };
                        if status != ERROR_SUCCESS {
                            return Err(io::Error::from_raw_os_error(status as i32));
                        }
                        self.completed_steps
                            .push(format!("value_deleted:{}\\{}", key_path, value_name));
                    }
                    Err(ERROR_FILE_NOT_FOUND) => {}
                    Ok(_) => {
                        return Err(io::Error::other(format!(
                            "unexpected fixture value preserved at {key_path}\\{value_name}"
                        )));
                    }
                    Err(status) => return Err(io::Error::from_raw_os_error(status as i32)),
                }
            }
            for key_path in self.created_keys.iter().rev() {
                let owned_key = if key_path.is_empty() {
                    None
                } else {
                    Some(
                        win32_open_key(root_handle, key_path, KEY_READ)
                            .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                    )
                };
                let handle = owned_key.as_ref().map_or(root_handle, OwnedRegKey::raw);
                require_empty_registry_key(handle, key_path)?;
                if !key_path.is_empty() {
                    if let Some(gate) = gate {
                        gate.require_zero("registry key disposition")?;
                    }
                    owned_key.expect("non-root fixture key").close()?;
                    let path = wide(OsStr::new(key_path))?;
                    let status = unsafe { RegDeleteKeyW(root_handle, path.as_ptr()) };
                    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
                        return Err(io::Error::from_raw_os_error(status as i32));
                    }
                    if win32_open_status(root_handle, key_path, KEY_READ) != ERROR_FILE_NOT_FOUND {
                        return Err(io::Error::other(format!(
                            "owned fixture key absence not proven: {key_path}"
                        )));
                    }
                    self.completed_steps.push(format!("key_absent:{key_path}"));
                }
            }
            self.root.take().expect("fixture root owner").close()?;
            let name = wide(OsStr::new(&self.name))?;
            if let Some(gate) = gate {
                gate.require_zero("registry nonce-root disposition")?;
            }
            let status = unsafe { RegDeleteKeyW(software, name.as_ptr()) };
            if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if win32_open_status(software, &self.name, KEY_READ) != ERROR_FILE_NOT_FOUND {
                return Err(io::Error::other(
                    "private fixture cleanup absence not proven",
                ));
            }
            self.completed_steps.push("nonce_root_absent".to_owned());
            Ok(Some(RegistryAbsence {
                software: self.software.take(),
                leaf: self.name.clone(),
                absence_proven: true,
                anchor_closed: false,
            }))
        }
    }

    fn require_empty_registry_key(key: HKEY, path: &str) -> io::Result<()> {
        let (mut subkeys, mut values) = (0u32, 0u32);
        let status = unsafe {
            RegQueryInfoKeyW(
                key,
                null_mut(),
                null_mut(),
                null(),
                &mut subkeys,
                null_mut(),
                null_mut(),
                &mut values,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::other(format!(
                "RegQueryInfoKeyW({path}) failed: {status}"
            )));
        }
        if subkeys != 0 || values != 0 {
            return Err(io::Error::other(format!(
                "unexpected private key content preserved at {path}: subkeys={subkeys}, values={values}"
            )));
        }
        Ok(())
    }

    /// Closed ID oracle used by the native parent before it accepts evidence.
    /// Constructing this set is not itself a witness result.
    fn required_probe_ids() -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for timing in ["before", "after"] {
            for api in ["win32", "nt"] {
                for target in ["machine", "user"] {
                    ids.insert(format!("parent_present/{timing}/{api}/{target}"));
                }
            }
        }
        for phase in ["baseline", "reset"] {
            for api in ["win32", "nt"] {
                for target in ["machine", "user"] {
                    ids.insert(format!("{phase}/host_denied/{api}/{target}"));
                }
            }
        }
        for phase in ["inherited", "mapped", "remapped"] {
            for view in ["machine_view", "user_view"] {
                ids.insert(format!("{phase}/public_read/{view}"));
            }
        }
        for view in ["machine_view", "user_view"] {
            ids.insert(format!("mapped/private_absent/{view}"));
        }
        for target in ["machine", "user"] {
            ids.insert(format!("mapped/host_denied/nt/{target}"));
        }
        ids.insert("mapped/host_denied/win32/user".to_owned());
        for operation in [
            "set_value",
            "delete_value",
            "create_subkey",
            "delete_leaf",
            "set_dacl",
            "set_owner",
            "reopen_write",
            "reopen_delete",
            "reopen_write_dac",
            "reopen_write_owner",
            "duplicate_mutation",
        ] {
            for view in ["machine_view", "user_view"] {
                ids.insert(format!("mutation/{operation}/{view}"));
            }
        }
        for view in ["machine_view", "user_view"] {
            ids.insert(format!("duplicate_read/{view}"));
        }
        for right in [
            "dup_handle",
            "vm_write",
            "vm_operation",
            "create_thread",
            "write_dac",
            "write_owner",
            "vm_read",
        ] {
            ids.insert(format!("parent_authority/{right}"));
        }
        ids.insert("parent_token/process_query_limited".to_owned());
        for right in [
            "token_duplicate",
            "write_dac",
            "write_owner",
            "token_impersonate",
            "token_assign_primary",
        ] {
            ids.insert(format!("parent_token/{right}"));
        }
        for view in ["machine_view", "user_view"] {
            ids.insert(format!("parent_recovery/{view}"));
        }
        for lifetime in [
            "normal_job_zero",
            "cancel_ready_mapped",
            "cancel_job_zero",
            "cleanup_absent",
        ] {
            ids.insert(format!("lifetime/{lifetime}"));
        }
        ids
    }

    // Keep the binding imports and ownership types tied to this test-only
    // module; the actual fixed helper and native probes are added below.
    #[allow(dead_code)]
    fn binding_smoke_types() {
        let _ = NtOpenKey;
        let _ = NtQueryValueKey;
        let _: Option<KEY_VALUE_PARTIAL_INFORMATION> = None;
        let _ = std::mem::size_of::<OBJECT_ATTRIBUTES>();
    }

    fn reset_predefined_roots() -> io::Result<()> {
        let machine = unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, null_mut()) };
        let user = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, null_mut()) };
        if machine != ERROR_SUCCESS || user != ERROR_SUCCESS {
            return Err(io::Error::other(format!(
                "registry map reset failed: machine={machine}, user={user}"
            )));
        }
        Ok(())
    }

    fn child_admission(package_sid: &str, role: &str, nonce: &str) -> io::Result<()> {
        let mut token = null_mut();
        unsafe {
            ok(
                "OpenProcessToken(registry witness helper)",
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token,
                ),
            )?;
        }
        let token = own("OpenProcessToken(registry witness helper)", token)?;
        if !token_boolean(token.as_raw_handle(), TokenIsAppContainer)? {
            return Err(invalid("registry witness child is not an AppContainer"));
        }
        let access =
            inspect_lpac_access(unsafe { BorrowedHandle::borrow_raw(token.as_raw_handle()) })?;
        if !access.is_less_privileged() {
            return Err(invalid("registry witness child is not LPAC"));
        }
        let groups = token_buffer(
            token.as_raw_handle(),
            TokenCapabilities,
            "GetTokenInformation(registry witness child capabilities)",
        )?;
        let count = unsafe { *groups.as_ptr().cast::<u32>() };
        if count != 1
            || groups.len() * size_of::<usize>()
                < std::mem::offset_of!(TOKEN_GROUPS, Groups) + size_of::<SID_AND_ATTRIBUTES>()
        {
            return Err(invalid(
                "registry witness child capability count differs from singleton",
            ));
        }
        let capability = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).Groups[0] };
        let capability_name = sid_text(capability.Sid)?;
        verify_runtime_capability_set(&[(&capability_name, capability.Attributes)])?;
        let container = token_buffer(
            token.as_raw_handle(),
            TokenAppContainerSid,
            "GetTokenInformation(registry witness package SID)",
        )?;
        let actual_package = sid_text(unsafe {
            (*container.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer
        })?;
        if actual_package != package_sid {
            return Err(invalid("registry witness child package SID mismatch"));
        }
        let mut in_job = 0;
        unsafe {
            ok(
                "IsProcessInJob(registry witness child)",
                IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job),
            )?;
        }
        if in_job == 0 {
            return Err(invalid("registry witness child is not in a Job"));
        }
        let mut thread_token = null_mut();
        let thread_has_token =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) };
        if thread_has_token != 0 {
            let _ = unsafe { CloseHandle(thread_token) };
            return Err(invalid(
                "registry witness child has an unexpected thread token",
            ));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_NO_TOKEN {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let pid = unsafe { GetCurrentProcessId() };
        let creation = process_creation_text(unsafe { GetCurrentProcess() })?;
        emit_witness_record(&format!(
            "registry_witness_child_admission nonce={nonce} role={role} pid={pid} creation={creation} appcontainer=true lpac=true capability_count=1 network_capabilities=0 job=true thread_token=false"
        ))
        .expect("bounded child admission record");
        Ok(())
    }

    fn current_image_observation() -> io::Result<(String, String)> {
        let path = std::env::current_exe()?;
        let path_wide = wide(path.as_os_str())?;
        let handle = own("CreateFileW(current helper image)", unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        check_object(handle.as_raw_handle(), false)?;
        let identity = script_identity(handle.as_raw_handle())?;
        let mut file = File::from(handle);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok((identity_text(identity), digest(&bytes)?))
    }

    fn parent_primary_user_sid() -> io::Result<String> {
        let mut token = null_mut();
        unsafe {
            ok(
                "OpenProcessToken(parent primary identity)",
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
            )?;
        }
        let token = own("OpenProcessToken(parent primary identity)", token)?;
        let user = token_buffer(
            token.as_raw_handle(),
            TokenUser,
            "GetTokenInformation(parent TokenUser)",
        )?;
        let sid = sid_text(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
        let mut thread_token = null_mut();
        let opened =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) };
        if opened != 0 {
            let _ = unsafe { CloseHandle(thread_token) };
            return Err(invalid(
                "parent has a thread token; primary identity is ambiguous",
            ));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_NO_TOKEN {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(sid)
    }

    fn duplicate_inheritable_read_key(key: HKEY) -> io::Result<OwnedRegKey> {
        let mut duplicate = null_mut();
        unsafe {
            ok(
                "DuplicateHandle(private KEY_READ inheritance)",
                DuplicateHandle(
                    GetCurrentProcess(),
                    key.cast(),
                    GetCurrentProcess(),
                    &mut duplicate,
                    KEY_READ,
                    1,
                    0,
                ),
            )?;
        }
        // Establish the registry-specific owner immediately after duplication;
        // every later fallible step must close this handle with RegCloseKey.
        let duplicate = unsafe { OwnedRegKey::from_raw(duplicate.cast()) }?;
        unsafe {
            ok(
                "SetHandleInformation(private registry inheritance)",
                SetHandleInformation(
                    duplicate.raw().cast(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                ),
            )?;
        }
        Ok(duplicate)
    }

    fn registry_record_field<'a>(payload: &'a str, key: &str) -> io::Result<&'a str> {
        let prefix = format!("{key}=");
        let mut values = payload
            .split_ascii_whitespace()
            .filter_map(|field| field.strip_prefix(&prefix));
        let value = values
            .next()
            .ok_or_else(|| invalid("required registry witness record field missing"))?;
        if values.next().is_some() || value.is_empty() {
            return Err(invalid("duplicate or empty registry witness record field"));
        }
        Ok(value)
    }

    fn framed_witness_payloads_with_pending(bytes: &[u8]) -> io::Result<(Vec<&str>, bool)> {
        let mut records = Vec::new();
        let mut cursor = 0usize;
        loop {
            let Some(relative) = bytes[cursor..]
                .windows(WITNESS_FRAME_START.len())
                .position(|part| part == WITNESS_FRAME_START)
            else {
                let tail = &bytes[cursor..];
                let pending_marker = (1..WITNESS_FRAME_START.len())
                    .any(|length| tail.ends_with(&WITNESS_FRAME_START[..length]));
                return Ok((records, pending_marker));
            };
            let start = cursor + relative + WITNESS_FRAME_START.len();
            let Some(colon_offset) = bytes[start..].iter().position(|byte| *byte == b':') else {
                return Ok((records, true));
            };
            let colon = start + colon_offset;
            let length_text = std::str::from_utf8(&bytes[start..colon])
                .map_err(|_| invalid("invalid helper record length"))?;
            if length_text.is_empty()
                || length_text.len() > 4
                || !length_text.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid("invalid helper record length"));
            }
            let length: usize = length_text
                .parse()
                .map_err(|_| invalid("invalid helper record length"))?;
            if length > 8192 {
                return Err(invalid("oversized helper record"));
            }
            let payload_start = colon + 1;
            let payload_end = payload_start
                .checked_add(length)
                .ok_or_else(|| invalid("helper record length overflow"))?;
            if payload_end >= bytes.len() {
                return Ok((records, true));
            }
            if bytes[payload_end] != WITNESS_FRAME_END {
                return Err(invalid("malformed helper record"));
            }
            let payload = std::str::from_utf8(&bytes[payload_start..payload_end])
                .map_err(|_| invalid("helper record is not UTF-8"))?;
            cursor = payload_end + 1;
            records.push(payload);
        }
    }

    fn framed_witness_payloads(bytes: &[u8], allow_partial: bool) -> io::Result<Vec<&str>> {
        let (records, pending) = framed_witness_payloads_with_pending(bytes)?;
        if pending && !allow_partial {
            return Err(invalid("truncated reserved helper frame"));
        }
        Ok(records)
    }

    fn peek_pipe_bytes(file: &File, limit: usize) -> io::Result<Vec<u8>> {
        let mut available = 0u32;
        if unsafe {
            PeekNamedPipe(
                file.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            return Err(operation_error(
                "PeekNamedPipe(registry cancellation readiness)",
                io::Error::from_raw_os_error(error as i32),
            ));
        }
        if available as usize > limit {
            return Err(invalid("cancellation readiness output exceeded its bound"));
        }
        let mut bytes = vec![0u8; available as usize];
        if available != 0 {
            let mut copied = 0u32;
            if unsafe {
                PeekNamedPipe(
                    file.as_raw_handle(),
                    bytes.as_mut_ptr().cast(),
                    available,
                    &mut copied,
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                let error = unsafe { GetLastError() };
                return Err(operation_error(
                    "PeekNamedPipe(registry cancellation snapshot)",
                    io::Error::from_raw_os_error(error as i32),
                ));
            }
            if copied > available {
                return Err(invalid("PeekNamedPipe returned an invalid byte count"));
            }
            bytes.truncate(copied as usize);
        }
        Ok(bytes)
    }

    fn cancel_readiness_complete(
        records: &[&str],
        expected_admission: &str,
        expected_ready: &str,
    ) -> io::Result<bool> {
        match records {
            [] => Ok(false),
            [admission] if *admission == expected_admission => Ok(false),
            [admission, ready] if *admission == expected_admission && *ready == expected_ready => {
                Ok(true)
            }
            _ => Err(invalid(
                "unexpected, duplicate, or replayed cancellation frames",
            )),
        }
    }

    fn cancellation_exit_matches_requested(code: u32, completion: Completion) -> bool {
        code == 1 && completion == Completion::Exited
    }

    fn verify_cancel_readiness_frame_oracle() -> io::Result<()> {
        if !cancellation_exit_matches_requested(1, Completion::Exited)
            || cancellation_exit_matches_requested(101, Completion::Exited)
            || cancellation_exit_matches_requested(1, Completion::TimedOut)
        {
            return Err(invalid(
                "requested cancellation exit-code oracle accepted an unexpected result",
            ));
        }
        let admission = "registry_witness_child_admission nonce=0123456789abcdef0123456789abcdef role=cancel pid=42 creation=0123456789abcdef appcontainer=true lpac=true capability_count=1 network_capabilities=0 job=true thread_token=false";
        let ready = "registry_witness_probe id=lifetime/cancel_ready_mapped role=cancel";
        let mut complete = WITNESS_FRAME_START.to_vec();
        complete.extend_from_slice(admission.len().to_string().as_bytes());
        complete.push(b':');
        complete.extend_from_slice(admission.as_bytes());
        complete.push(WITNESS_FRAME_END);
        complete.extend_from_slice(WITNESS_FRAME_START);
        complete.extend_from_slice(ready.len().to_string().as_bytes());
        complete.push(b':');
        complete.extend_from_slice(ready.as_bytes());
        complete.push(WITNESS_FRAME_END);
        let parsed = framed_witness_payloads(&complete, false)?;
        if !cancel_readiness_complete(&parsed, admission, ready)? {
            return Err(invalid(
                "complete cancellation frame oracle was not accepted",
            ));
        }
        let mut partial = complete.clone();
        partial.pop();
        let partial_records = framed_witness_payloads(&partial, true)?;
        if partial_records.as_slice() != [admission]
            || framed_witness_payloads(&partial, false).is_ok()
        {
            return Err(invalid(
                "partial cancellation frame oracle was not rejected",
            ));
        }
        let mut replay = complete.clone();
        replay.extend_from_slice(WITNESS_FRAME_START);
        replay.extend_from_slice(ready.len().to_string().as_bytes());
        replay.push(b':');
        replay.extend_from_slice(ready.as_bytes());
        replay.push(WITNESS_FRAME_END);
        let replayed = framed_witness_payloads(&replay, false)?;
        if cancel_readiness_complete(&replayed, admission, ready).is_ok() {
            return Err(invalid(
                "replayed cancellation readiness oracle was accepted",
            ));
        }
        let mut malformed = complete.clone();
        let end = malformed.len() - 1;
        malformed[end] = b'!';
        if framed_witness_payloads(&malformed, false).is_ok() {
            return Err(invalid("malformed cancellation frame oracle was accepted"));
        }
        for suffix in [
            WITNESS_FRAME_START[..7].to_vec(),
            [&WITNESS_FRAME_START[..], b"123"].concat(),
            [&WITNESS_FRAME_START[..], b"3:ab"].concat(),
            [&WITNESS_FRAME_START[..], b"3:abc"].concat(),
        ] {
            let mut tailed = complete.clone();
            tailed.extend_from_slice(&suffix);
            let (records, pending) = framed_witness_payloads_with_pending(&tailed)?;
            if !pending
                || (!pending && cancel_readiness_complete(&records, admission, ready)?)
                || framed_witness_payloads(&tailed, false).is_ok()
            {
                return Err(invalid(
                    "complete readiness followed by a reserved-frame tail was accepted",
                ));
            }
            let (stderr_records, stderr_pending) = framed_witness_payloads_with_pending(&suffix)?;
            if !stderr_records.is_empty() || !stderr_pending {
                return Err(invalid("reserved-frame tail on stderr was not detected"));
            }
        }
        Ok(())
    }

    const MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS: usize = 16;

    #[repr(C)]
    struct BoundedJobProcessIdList {
        number_of_assigned_processes: u32,
        number_of_process_ids_in_list: u32,
        process_id_list: [usize; MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS],
    }

    fn checked_job_process_id_count(
        assigned: u32,
        listed: u32,
        returned_bytes: u32,
    ) -> io::Result<usize> {
        let count = usize::try_from(listed)
            .map_err(|_| invalid("Job process ID count conversion overflow"))?;
        let header_bytes = std::mem::offset_of!(BoundedJobProcessIdList, process_id_list);
        let list_bytes = count
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| invalid("Job process ID byte count overflow"))?;
        let required_bytes = header_bytes
            .checked_add(list_bytes)
            .ok_or_else(|| invalid("Job process ID buffer length overflow"))?;
        let returned_bytes = usize::try_from(returned_bytes)
            .map_err(|_| invalid("Job process ID returned length conversion overflow"))?;
        if count > MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS
            || assigned < listed
            || returned_bytes < header_bytes
            || returned_bytes < required_bytes
            || returned_bytes > size_of::<BoundedJobProcessIdList>()
        {
            return Err(invalid("invalid or incomplete Job process ID list shape"));
        }
        Ok(count)
    }

    fn verify_job_process_id_list_oracle() -> io::Result<()> {
        let header_bytes = std::mem::offset_of!(BoundedJobProcessIdList, process_id_list);
        let bytes_for = |count: usize| -> io::Result<u32> {
            let bytes = header_bytes
                .checked_add(
                    count
                        .checked_mul(size_of::<usize>())
                        .ok_or_else(|| invalid("Job process ID oracle overflow"))?,
                )
                .ok_or_else(|| invalid("Job process ID oracle length overflow"))?;
            u32::try_from(bytes).map_err(|_| invalid("Job process ID oracle size overflow"))
        };
        if checked_job_process_id_count(2, 2, bytes_for(2)?)? != 2
            || checked_job_process_id_count(17, 16, bytes_for(16)?)? != 16
            || checked_job_process_id_count(2, 2, bytes_for(2)? - 1).is_ok()
            || checked_job_process_id_count(1, 2, bytes_for(2)?).is_ok()
            || checked_job_process_id_count(
                17,
                (MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS + 1) as u32,
                u32::MAX,
            )
            .is_ok()
            || checked_job_process_id_count(0, 0, u32::MAX).is_ok()
        {
            return Err(invalid("Job process ID list validation oracle failed"));
        }
        Ok(())
    }

    fn emit_cancel_job_member_diagnostics(
        child: &OwnedProcess<'_>,
        child_pid: u32,
        child_creation: &str,
        active_processes: u32,
    ) -> io::Result<()> {
        let mut list = BoundedJobProcessIdList {
            number_of_assigned_processes: 0,
            number_of_process_ids_in_list: 0,
            process_id_list: [0; MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS],
        };
        let mut returned_bytes = 0u32;
        let query_succeeded = unsafe {
            QueryInformationJobObject(
                child.job.as_raw_handle(),
                JobObjectBasicProcessIdList,
                (&mut list as *mut BoundedJobProcessIdList).cast(),
                u32::try_from(size_of::<BoundedJobProcessIdList>())
                    .map_err(|_| invalid("Job process ID diagnostic buffer too large"))?,
                &mut returned_bytes,
            )
        };
        if query_succeeded == 0 {
            let error = io::Error::last_os_error();
            let detail = error.to_string();
            return emit_witness_record(&format!(
                "registry_witness_diagnostic stream=cancel_job_members child_pid={child_pid} creation={child_creation} active_processes={active_processes} query=failed native_error={} error_bytes={} error_truncated={} error_text={}",
                error
                    .raw_os_error()
                    .map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
                detail.len(),
                detail.len() > 1024,
                escape_diagnostic(detail.as_bytes())
            ));
        }

        let assigned = list.number_of_assigned_processes;
        let listed = list.number_of_process_ids_in_list;
        let count = match checked_job_process_id_count(assigned, listed, returned_bytes) {
            Ok(count) => count,
            Err(error) => {
                return emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_members child_pid={child_pid} creation={child_creation} active_processes={active_processes} query=invalid assigned={assigned} listed={listed} returned_bytes={returned_bytes} capacity_bytes={} error={}",
                    size_of::<BoundedJobProcessIdList>(),
                    escape_diagnostic(error.to_string().as_bytes())
                ));
            }
        };
        emit_witness_record(&format!(
            "registry_witness_diagnostic stream=cancel_job_members child_pid={child_pid} creation={child_creation} active_processes={active_processes} query=success assigned={assigned} listed={listed} returned_bytes={returned_bytes} capacity_bytes={} snapshot_complete={} active_count_matches={}",
            size_of::<BoundedJobProcessIdList>(),
            assigned == listed,
            assigned == active_processes
        ))?;

        for (index, raw_pid) in list.process_id_list[..count].iter().copied().enumerate() {
            let pid = match u32::try_from(raw_pid) {
                Ok(pid) if pid != 0 => pid,
                _ => {
                    emit_witness_record(&format!(
                        "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={raw_pid} identity=invalid"
                    ))?;
                    continue;
                }
            };
            let process = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            if process.is_null() {
                let error = io::Error::last_os_error();
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} process_open=failed native_error={}",
                    error
                        .raw_os_error()
                        .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                ))?;
                continue;
            }
            let process = unsafe { OwnedHandle::from_raw_handle(process) };
            let actual_pid = unsafe { GetProcessId(process.as_raw_handle()) };
            if actual_pid == 0 {
                let error = io::Error::last_os_error();
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} identity=unknown native_error={}",
                    error
                        .raw_os_error()
                        .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                ))?;
                continue;
            }
            if actual_pid != pid {
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} identity=pid_mismatch actual_pid={actual_pid}"
                ))?;
                continue;
            }
            let actual_creation = match process_creation_text(process.as_raw_handle()) {
                Ok(creation) => creation,
                Err(error) => {
                    emit_witness_record(&format!(
                        "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} creation=unknown process_times=failed error={}",
                        escape_diagnostic(error.to_string().as_bytes())
                    ))?;
                    continue;
                }
            };
            let own_identity_matches = pid != child_pid || actual_creation == child_creation;
            let child_identity_binding = if pid == child_pid {
                if own_identity_matches {
                    "matches"
                } else {
                    "mismatch"
                }
            } else {
                "not_applicable"
            };
            let mut in_owned_job = 0;
            let membership_succeeded = unsafe {
                IsProcessInJob(
                    process.as_raw_handle(),
                    child.job.as_raw_handle(),
                    &mut in_owned_job,
                )
            };
            if membership_succeeded == 0 {
                let error = io::Error::last_os_error();
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} actual_creation={actual_creation} child_identity_binding={child_identity_binding} membership=unknown native_error={}",
                    error
                        .raw_os_error()
                        .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                ))?;
                continue;
            }
            if in_owned_job == 0 || !own_identity_matches {
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} actual_creation={actual_creation} child_identity_binding={child_identity_binding} membership={} image_query=skipped",
                    in_owned_job != 0
                ))?;
                continue;
            }

            let mut image_path = vec![0u16; 32_768];
            let mut image_path_units = u32::try_from(image_path.len())
                .map_err(|_| invalid("process image path buffer length overflow"))?;
            if unsafe {
                QueryFullProcessImageNameW(
                    process.as_raw_handle(),
                    PROCESS_NAME_WIN32,
                    image_path.as_mut_ptr(),
                    &mut image_path_units,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} actual_creation={actual_creation} child_identity_binding={child_identity_binding} membership=true image_query=unknown native_error={}",
                    error
                        .raw_os_error()
                        .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                ))?;
                continue;
            }
            let path_units = usize::try_from(image_path_units)
                .map_err(|_| invalid("process image path length conversion overflow"))?;
            if path_units == 0 || path_units > image_path.len() {
                emit_witness_record(&format!(
                    "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} actual_creation={actual_creation} membership=true image_query=invalid returned_units={path_units} capacity_units={}",
                    image_path.len()
                ))?;
                continue;
            }
            let shown_units = path_units.min(256);
            let mut escaped_path = String::new();
            for unit in &image_path[..shown_units] {
                match *unit {
                    0x20..=0x7e if *unit != u16::from(b'"') => {
                        escaped_path.push(char::from(*unit as u8));
                    }
                    value if value == u16::from(b'"') => escaped_path.push_str("\\\""),
                    value => escaped_path.push_str(&format!("\\u{value:04X}")),
                }
            }
            emit_witness_record(&format!(
                "registry_witness_diagnostic stream=cancel_job_member child_pid={child_pid} creation={child_creation} index={index} listed_pid={pid} actual_pid={actual_pid} actual_creation={actual_creation} child_identity_binding={child_identity_binding} membership=true image_query=success image_path_units={path_units} image_path_truncated={} image_path=\"{escaped_path}\"",
                path_units > shown_units
            ))?;
        }
        Ok(())
    }

    fn verify_cancel_job_single_member(
        child: &OwnedProcess<'_>,
        child_pid: u32,
        child_creation: &str,
        active_processes: u32,
    ) -> io::Result<()> {
        if active_processes != 1 {
            return Err(invalid(
                "cancel Job active-process sample was not exactly one",
            ));
        }
        let mut list = BoundedJobProcessIdList {
            number_of_assigned_processes: 0,
            number_of_process_ids_in_list: 0,
            process_id_list: [0; MAX_CANCEL_JOB_DIAGNOSTIC_MEMBERS],
        };
        let mut returned_bytes = 0u32;
        let succeeded = unsafe {
            QueryInformationJobObject(
                child.job.as_raw_handle(),
                JobObjectBasicProcessIdList,
                (&mut list as *mut BoundedJobProcessIdList).cast(),
                u32::try_from(size_of::<BoundedJobProcessIdList>())
                    .map_err(|_| invalid("Job process ID proof buffer too large"))?,
                &mut returned_bytes,
            )
        };
        if succeeded == 0 {
            return Err(operation_error(
                "QueryInformationJobObject(cancel live-member proof)",
                io::Error::last_os_error(),
            ));
        }
        let assigned = list.number_of_assigned_processes;
        let listed = list.number_of_process_ids_in_list;
        let count = checked_job_process_id_count(assigned, listed, returned_bytes)?;
        if assigned != 1 || listed != 1 || count != 1 {
            return Err(io::Error::other(format!(
                "cancel Job PID snapshot is not an exact singleton: assigned={assigned} listed={listed} count={count} returned_bytes={returned_bytes}"
            )));
        }
        let listed_pid = u32::try_from(list.process_id_list[0])
            .map_err(|_| invalid("cancel Job PID does not fit a Windows process ID"))?;
        if listed_pid == 0 || listed_pid != child_pid {
            return Err(io::Error::other(format!(
                "cancel Job PID snapshot does not identify the launched helper: listed_pid={listed_pid} child_pid={child_pid}"
            )));
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                listed_pid,
            )
        };
        if process.is_null() {
            return Err(operation_error(
                "OpenProcess(cancel live-member proof)",
                io::Error::last_os_error(),
            ));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        let actual_pid = unsafe { GetProcessId(process.as_raw_handle()) };
        if actual_pid != child_pid {
            return Err(io::Error::other(format!(
                "cancel Job member process handle PID mismatch: actual_pid={actual_pid} child_pid={child_pid}"
            )));
        }
        let actual_creation = process_creation_text(process.as_raw_handle())?;
        if actual_creation != child_creation {
            return Err(io::Error::other(format!(
                "cancel Job member creation time mismatch: actual_creation={actual_creation} child_creation={child_creation}"
            )));
        }
        let mut in_owned_job = 0;
        if unsafe {
            IsProcessInJob(
                process.as_raw_handle(),
                child.job.as_raw_handle(),
                &mut in_owned_job,
            )
        } == 0
        {
            return Err(operation_error(
                "IsProcessInJob(cancel live-member proof)",
                io::Error::last_os_error(),
            ));
        }
        if in_owned_job == 0 {
            return Err(invalid(
                "cancel Job PID-list member is not in the exact owned Job",
            ));
        }
        emit_witness_record(&format!(
            "registry_witness_diagnostic stream=cancel_job_live_member child_pid={child_pid} child_creation={child_creation} assigned={assigned} listed={listed} returned_bytes={returned_bytes} pid={listed_pid} actual_pid={actual_pid} actual_creation={actual_creation} membership=owned_job active_processes={active_processes} observed=true"
        ))
    }

    fn wait_for_cancel_readiness(
        child: &OwnedProcess<'_>,
        child_pid: u32,
        child_creation: &str,
        parent_pid: u32,
        parent_creation: &str,
        expected_admission: &str,
        expected_ready: &str,
    ) -> io::Result<()> {
        loop {
            if child.started.elapsed() >= child.timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cancellation readiness timed out",
                ));
            }
            match process_completed(child.process.as_raw_handle()) {
                Ok(true) => {
                    return match child.active() {
                        Ok(active) => Err(io::Error::other(format!(
                            "cancellation helper exited before readiness: child_pid={child_pid} child_creation={child_creation} process_wait=WAIT_OBJECT_0 QueryInformationJobObject=success active_processes={active}"
                        ))),
                        Err(error) => Err(io::Error::other(format!(
                            "cancellation helper exited before readiness: child_pid={child_pid} child_creation={child_creation} process_wait=WAIT_OBJECT_0 QueryInformationJobObject failed: {error}"
                        ))),
                    };
                }
                Ok(false) => {}
                Err(error) => {
                    let job = child.active();
                    return Err(match job {
                        Ok(active) => io::Error::other(format!(
                            "cancellation readiness wait query failed: child_pid={child_pid} child_creation={child_creation} WaitForSingleObject(process) failed: {error}; QueryInformationJobObject=success active_processes={active}"
                        )),
                        Err(job_error) => io::Error::other(format!(
                            "cancellation readiness wait queries failed: child_pid={child_pid} child_creation={child_creation} WaitForSingleObject(process) failed: {error}; QueryInformationJobObject failed: {job_error}"
                        )),
                    });
                }
            }
            let stdout = peek_pipe_bytes(&child.stdout, child.output_limit)?;
            let stderr = peek_pipe_bytes(
                &child.stderr,
                child.output_limit.saturating_sub(stdout.len()),
            )?;
            if stdout.len() + stderr.len() > child.output_limit {
                return Err(invalid(
                    "cancellation helper exceeded its combined output limit",
                ));
            }
            let (stderr_records, stderr_pending) = framed_witness_payloads_with_pending(&stderr)?;
            if !stderr_records.is_empty() || stderr_pending {
                return Err(invalid("cancellation helper framed evidence on stderr"));
            }
            let (records, pending) = framed_witness_payloads_with_pending(&stdout)?;
            if !pending && cancel_readiness_complete(&records, expected_admission, expected_ready)?
            {
                validate_parent_self_binding(parent_pid, parent_creation)?;
                let process_state = process_completed(child.process.as_raw_handle());
                let job_state = child.active();
                match (process_state, job_state) {
                    (Ok(false), Ok(1)) => {
                        let proof =
                            verify_cancel_job_single_member(child, child_pid, child_creation, 1);
                        let final_process = process_completed(child.process.as_raw_handle());
                        let final_job = child.active();
                        if proof.is_ok()
                            && matches!(final_process.as_ref(), Ok(false))
                            && matches!(final_job.as_ref(), Ok(1))
                        {
                            return Ok(());
                        }
                        let wait_detail = match final_process.as_ref() {
                            Ok(false) => "WAIT_TIMEOUT".to_owned(),
                            Ok(true) => "WAIT_OBJECT_0".to_owned(),
                            Err(error) => format!("failed:{error}"),
                        };
                        let job_detail = match final_job.as_ref() {
                            Ok(active) => format!("active_processes={active}"),
                            Err(error) => format!("failed:{error}"),
                        };
                        let proof_detail = proof
                            .as_ref()
                            .err()
                            .map_or_else(|| "verified".to_owned(), ToString::to_string);
                        let primary = io::Error::other(format!(
                            "cancellation readiness received but exact live-member proof failed: child_pid={child_pid} child_creation={child_creation} first_process_wait=WAIT_TIMEOUT first_active_processes=1 member_proof={proof_detail} final_process_wait={wait_detail} final_job={job_detail}"
                        ));
                        return Err(
                            match emit_cancel_job_member_diagnostics(
                                child,
                                child_pid,
                                child_creation,
                                1,
                            ) {
                                Ok(()) => primary,
                                Err(diagnostic_error) => io::Error::other(format!(
                                    "{primary}; cancel Job member diagnostic emission failed: {diagnostic_error}"
                                )),
                            },
                        );
                    }
                    (Ok(done), Ok(active)) => {
                        let wait_result = if done {
                            "WAIT_OBJECT_0"
                        } else {
                            "WAIT_TIMEOUT"
                        };
                        let primary = format!(
                            "cancellation readiness received but live-member gate failed: child_pid={child_pid} child_creation={child_creation} process_wait={wait_result} QueryInformationJobObject=success active_processes={active}"
                        );
                        return Err(
                            match emit_cancel_job_member_diagnostics(
                                child,
                                child_pid,
                                child_creation,
                                active,
                            ) {
                                Ok(()) => io::Error::other(primary),
                                Err(diagnostic_error) => io::Error::other(format!(
                                    "{primary}; cancel Job member diagnostic emission failed: {diagnostic_error}"
                                )),
                            },
                        );
                    }
                    (Err(wait_error), Ok(active)) => {
                        return Err(io::Error::other(format!(
                            "cancellation readiness gate wait query failed: child_pid={child_pid} child_creation={child_creation} WaitForSingleObject(process) failed: {wait_error}; QueryInformationJobObject=success active_processes={active}"
                        )));
                    }
                    (Ok(done), Err(job_error)) => {
                        let wait_result = if done {
                            "WAIT_OBJECT_0"
                        } else {
                            "WAIT_TIMEOUT"
                        };
                        return Err(io::Error::other(format!(
                            "cancellation readiness gate Job query failed: child_pid={child_pid} child_creation={child_creation} process_wait={wait_result}; QueryInformationJobObject failed: {job_error}"
                        )));
                    }
                    (Err(wait_error), Err(job_error)) => {
                        return Err(io::Error::other(format!(
                            "cancellation readiness gate queries failed: child_pid={child_pid} child_creation={child_creation} WaitForSingleObject(process) failed: {wait_error}; QueryInformationJobObject failed: {job_error}"
                        )));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn forward_child_records(
        bytes: &[u8],
        nonce: &str,
        parent_pid: u32,
        parent_creation: &str,
        skip_probe_id: Option<&str>,
    ) -> io::Result<()> {
        for payload in framed_witness_payloads(bytes, false)? {
            if payload.starts_with("registry_witness_probe id=parent_authority/")
                || payload.starts_with("registry_witness_probe id=parent_token/")
            {
                if registry_record_field(payload, "nonce")? != nonce
                    || registry_record_field(payload, "parent_pid")? != parent_pid.to_string()
                    || registry_record_field(payload, "parent_creation")? != parent_creation
                {
                    return Err(invalid("helper parent-authority record binding mismatch"));
                }
            }
            if skip_probe_id
                .is_some_and(|id| payload.starts_with(&format!("registry_witness_probe id={id} ")))
            {
                continue;
            }
            emit_witness_record(payload)?;
        }
        Ok(())
    }

    fn parent_recovery(fixture: &PrivateRegistryFixture) -> io::Result<()> {
        for view in ["MachineView", "UserView"] {
            let key = fixture.root_handle(view, KEY_ALL_ACCESS)?;
            let id = if view == "MachineView" {
                "machine_view"
            } else {
                "user_view"
            };
            emit_witness_record(&format!(
                "registry_witness_probe id=parent_recovery/{id} observed=true granted_access={KEY_ALL_ACCESS:#x}"
            ))?;
            key.close()?;
        }
        Ok(())
    }

    fn stop_child_after_failure(child: &mut OwnedProcess<'_>, primary: io::Error) -> io::Error {
        match child.stop() {
            Ok(()) => {
                child.finished = true;
                primary
            }
            Err(cleanup) => io::Error::other(format!(
                "{primary}; child termination/wait failed: {cleanup}; OwnedProcess Drop will retry, and the session records any unobserved shutdown"
            )),
        }
    }

    fn emit_cancel_output_diagnostic(
        stream: &str,
        child_pid: u32,
        child_creation: &str,
        output: &ProcessOutput,
        bytes: &[u8],
    ) -> io::Result<()> {
        const CHUNK_SIZE: usize = 1024;
        if bytes.is_empty() {
            return emit_witness_record(&format!(
                "registry_witness_diagnostic stream={stream} child_pid={child_pid} creation={child_creation} exit_code={} completion={:?} total_bytes=0 offset=0 chunk_bytes=0 text=",
                output.code, output.completion
            ));
        }
        for (index, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
            let offset = index * CHUNK_SIZE;
            emit_witness_record(&format!(
                "registry_witness_diagnostic stream={stream} child_pid={child_pid} creation={child_creation} exit_code={} completion={:?} total_bytes={} offset={offset} chunk_bytes={} text={}",
                output.code,
                output.completion,
                bytes.len(),
                chunk.len(),
                escape_diagnostic(chunk)
            ))?;
        }
        Ok(())
    }

    fn cancel_child_after_failure_with_output(
        mut child: OwnedProcess<'_>,
        primary: io::Error,
        child_pid: u32,
        child_creation: &str,
    ) -> io::Error {
        let stop_result = child.stop();
        if stop_result.is_ok() {
            child.finished = true;
        }
        let wait_result = child.wait(&AtomicBool::new(false));
        let mut details = vec![format!(
            "cancellation primary failure for child_pid={child_pid} child_creation={child_creation}: {primary}"
        )];
        if let Err(error) = stop_result {
            details.push(format!("explicit child stop/wait failed: {error}"));
        }
        match wait_result {
            Ok(output) => {
                details.push(format!(
                    "bounded cancellation output drained: exit_code={} completion={:?} stdout_bytes={} stderr_bytes={}",
                    output.code,
                    output.completion,
                    output.stdout.len(),
                    output.stderr.len()
                ));
                if let Err(error) = emit_cancel_output_diagnostic(
                    "cancel_stdout",
                    child_pid,
                    child_creation,
                    &output,
                    &output.stdout,
                ) {
                    details.push(format!("stdout diagnostic emission failed: {error}"));
                }
                if let Err(error) = emit_cancel_output_diagnostic(
                    "cancel_stderr",
                    child_pid,
                    child_creation,
                    &output,
                    &output.stderr,
                ) {
                    details.push(format!("stderr diagnostic emission failed: {error}"));
                }
            }
            Err(error) => details.push(format!("bounded child wait/output drain failed: {error}")),
        }
        io::Error::other(details.join("; "))
    }

    fn run_cancel_witness_child(
        gate: &mut CleanupJobGate,
        session: &SandboxSession,
        fixture: &PrivateRegistryFixture,
        image: &HeldHelperImage,
        nonce: &str,
        user_sid: &str,
        package_sid: &str,
        parent_pid: u32,
        parent_creation: &str,
        fixture_digest: &str,
        fixture_identity_sha256: &str,
        control: Option<CleanupControl>,
        early_control_target: &mut Option<String>,
    ) -> io::Result<()> {
        let machine_root = fixture.root_handle("MachineView", KEY_READ)?;
        let user_root = fixture.root_handle("UserView", KEY_READ)?;
        let machine_descriptor = digest(&registry_key_security(machine_root.raw())?)?;
        let user_descriptor = digest(&registry_key_security(user_root.raw())?)?;
        let machine_label = private_view_label_digest(machine_root.raw())?;
        let user_label = private_view_label_digest(user_root.raw())?;
        let inherited_machine = duplicate_inheritable_read_key(machine_root.raw())?;
        let inherited_user = duplicate_inheritable_read_key(user_root.raw())?;
        machine_root.close()?;
        user_root.close()?;

        let image_id = image.identity;
        let spec = SpawnSpec {
            executable: image.path.clone(),
            arguments: vec![
                "--exact".to_owned(),
                "process::windows::registry_witness_tests::registry_witness_fixed_child_helper"
                    .to_owned(),
                "--nocapture".to_owned(),
            ],
            timeout: Duration::from_secs(30),
            output_limit: 128 * 1024,
        };
        let (mut child, thread) = OwnedProcess::create_registry_witness_child(
            session,
            &spec,
            "cancel",
            nonce,
            user_sid,
            package_sid,
            &image.sha256,
            image_id,
            fixture_digest,
            fixture_identity_sha256,
            [inherited_machine, inherited_user],
        )?;
        gate.cancel = Some(match duplicate_job_fence(&child, "cancel") {
            Ok(fence) => fence,
            Err(primary) => {
                let error = stop_child_after_failure(&mut child, primary);
                drop(thread);
                return Err(error);
            }
        });
        if !child.evidence.app_container
            || !child.evidence.less_privileged
            || !child.evidence.job_assigned_before_resume
            || child.evidence.total_capabilities != 1
            || child.evidence.network_capabilities != 0
            || child.pid() == 0
        {
            let primary = invalid("cancellation helper pre-resume LPAC or Job evidence failed");
            let error = stop_child_after_failure(&mut child, primary);
            drop(thread);
            return Err(error);
        }
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            let error = operation_error(
                "ResumeThread(registry cancellation)",
                io::Error::last_os_error(),
            );
            let error = stop_child_after_failure(&mut child, error);
            drop(thread);
            return Err(error);
        }
        drop(thread);

        let child_pid = child.pid();
        let child_creation = match process_creation_text(child.process.as_raw_handle()) {
            Ok(value) => value,
            Err(error) => return Err(stop_child_after_failure(&mut child, error)),
        };
        let expected_admission = format!(
            "registry_witness_child_admission nonce={nonce} role=cancel pid={child_pid} creation={child_creation} appcontainer=true lpac=true capability_count=1 network_capabilities=0 job=true thread_token=false"
        );
        let expected_child_ready = format!(
            "registry_witness_probe id=lifetime/cancel_ready_mapped nonce={nonce} role=cancel pid={child_pid} creation={child_creation} parent_pid={parent_pid} parent_creation={parent_creation} image_id={} image_sha256={} fixture_id={fixture_identity_sha256} fixture_digest={fixture_digest} machine_descriptor_sha256={machine_descriptor} user_descriptor_sha256={user_descriptor} inherited_machine_label_sha256={machine_label} inherited_user_label_sha256={user_label} mapped_machine_label_sha256={machine_label} mapped_user_label_sha256={user_label} appcontainer=true lpac=true capability_count=1 network_capabilities=0 thread_token=false job=true inherited_reads=2 mapped_machine=true mapped_user=true maps_live=2",
            identity_text(image_id),
            image.sha256
        );
        if let Err(error) = wait_for_cancel_readiness(
            &child,
            child_pid,
            &child_creation,
            parent_pid,
            parent_creation,
            &expected_admission,
            &expected_child_ready,
        ) {
            return Err(cancel_child_after_failure_with_output(
                child,
                error,
                child_pid,
                &child_creation,
            ));
        }
        if let Err(error) = validate_parent_self_binding(parent_pid, parent_creation) {
            return Err(cancel_child_after_failure_with_output(
                child,
                error,
                child_pid,
                &child_creation,
            ));
        }
        let ready_attestation = format!(
            "{expected_child_ready} parent_received_while_alive=true job_active_processes=1"
        );
        if let Err(error) = emit_witness_record(&ready_attestation) {
            return Err(cancel_child_after_failure_with_output(
                child,
                error,
                child_pid,
                &child_creation,
            ));
        }

        if control == Some(CleanupControl::LiveNonzeroJob) {
            match gate.require_zero("live nonzero cleanup") {
                Err(error)
                    if error
                        .to_string()
                        .contains("cancel Job is not empty before live nonzero cleanup")
                        && error.to_string().contains("active=1") =>
                {
                    *early_control_target = Some(error.to_string());
                }
                Err(error) => {
                    return Err(cancel_child_after_failure_with_output(
                        child,
                        error,
                        child_pid,
                        &child_creation,
                    ));
                }
                Ok(()) => {
                    return Err(cancel_child_after_failure_with_output(
                        child,
                        invalid("live nonzero cleanup control did not observe an active member"),
                        child_pid,
                        &child_creation,
                    ));
                }
            }
        }

        if let Err(primary) = child.stop() {
            return Err(stop_child_after_failure(&mut child, primary));
        }
        let active_processes = match child.active() {
            Ok(active) => active,
            Err(primary) => return Err(stop_child_after_failure(&mut child, primary)),
        };
        if active_processes != 0 {
            return Err(invalid(
                "cancellation Job did not reach zero active processes",
            ));
        }
        child.finished = true;
        let output = child.wait(&AtomicBool::new(false))?;
        gate.cancel
            .as_mut()
            .ok_or_else(|| invalid("cancellation Job fence missing after wait"))?
            .process_waited = true;
        if !cancellation_exit_matches_requested(output.code, output.completion) {
            return Err(invalid(
                "cancellation child did not exit with the requested Job termination code",
            ));
        }
        gate.cancel
            .as_ref()
            .ok_or_else(|| invalid("cancellation Job fence missing"))?
            .require_zero("cancellation cleanup handoff")?;
        let stdout_frames = framed_witness_payloads(&output.stdout, false)?;
        if stdout_frames.len() != 2
            || stdout_frames[0] != expected_admission
            || stdout_frames[1] != expected_child_ready
            || !framed_witness_payloads(&output.stderr, false)?.is_empty()
        {
            return Err(invalid(
                "cancellation child final transcript differed from live readiness",
            ));
        }
        validate_parent_self_binding(parent_pid, parent_creation)?;
        forward_child_records(
            &output.stdout,
            nonce,
            parent_pid,
            parent_creation,
            Some("lifetime/cancel_ready_mapped"),
        )?;
        forward_child_records(&output.stderr, nonce, parent_pid, parent_creation, None)?;
        emit_witness_record(&format!(
            "registry_witness_probe id=lifetime/cancel_job_zero nonce={nonce} role=cancel pid={child_pid} creation={child_creation} parent_pid={parent_pid} parent_creation={parent_creation} image_id={} image_sha256={} fixture_id={fixture_identity_sha256} fixture_digest={fixture_digest} terminate_job_object=true process_waited=true active_processes={active_processes} exit_code={} observed=true",
            identity_text(image_id),
            image.sha256,
            output.code
        ))?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CleanupControl {
        WrongImageHash,
        UnknownRegistryKey,
        WrongImageId,
        WrongDirectoryId,
        WrongProfileId,
        ChangedImageDacl,
        UnknownRegistryValue,
        UnknownHelperEntry,
        UnknownProfileEntry,
        ProfileEnumerationLimit,
        ImageLeafSwap,
        DirectorySwap,
        ImageHardlink,
        MissingJobFence,
        LiveNonzeroJob,
        JobQueryError,
    }

    impl CleanupControl {
        fn name(self) -> &'static str {
            match self {
                Self::WrongImageHash => "wrong_image_hash",
                Self::UnknownRegistryKey => "unknown_registry_key",
                Self::WrongImageId => "wrong_image_id",
                Self::WrongDirectoryId => "wrong_directory_id",
                Self::WrongProfileId => "wrong_profile_id",
                Self::ChangedImageDacl => "changed_image_dacl",
                Self::UnknownRegistryValue => "unknown_registry_value",
                Self::UnknownHelperEntry => "unknown_helper_entry",
                Self::UnknownProfileEntry => "unknown_profile_entry",
                Self::ProfileEnumerationLimit => "profile_enumeration_limit",
                Self::ImageLeafSwap => "image_leaf_swap",
                Self::DirectorySwap => "directory_swap",
                Self::ImageHardlink => "image_hardlink",
                Self::MissingJobFence => "missing_job_fence",
                Self::LiveNonzeroJob => "live_nonzero_job",
                Self::JobQueryError => "job_query_error",
            }
        }

        fn target_error(self) -> &'static str {
            match self {
                Self::WrongImageHash => "helper image bounded length or SHA-256 differs",
                Self::UnknownRegistryKey => "private fixture inventory changed",
                Self::WrongImageId => "helper image identity differs from its captured full ID",
                Self::ImageLeafSwap => {
                    "helper image directory entry identity differs from its held original"
                }
                Self::WrongDirectoryId => "held helper directory identity changed",
                Self::WrongProfileId => "recorded profile entry identity changed before cleanup",
                Self::ChangedImageDacl => {
                    "helper image DACL differs from the captured protected policy"
                }
                Self::UnknownRegistryValue => "private fixture inventory changed",
                Self::UnknownHelperEntry => {
                    "helper directory contents differ from the exact owned image"
                }
                Self::UnknownProfileEntry => {
                    "fresh profile contains unknown or changed entries before deletion"
                }
                Self::ProfileEnumerationLimit => "fresh profile entry bound exceeded",
                Self::DirectorySwap => {
                    "helper directory entry identity differs from its held original"
                }
                Self::ImageHardlink => "resource is linked, replaced or of the wrong kind",
                Self::MissingJobFence => "both exact Job fences are required",
                Self::LiveNonzeroJob => "cancel Job is not empty before live nonzero cleanup",
                Self::JobQueryError => "injected Job query error after native zero observation",
            }
        }

        fn rejection(self) -> &'static str {
            match self {
                Self::WrongImageHash => "helper_image_hash_differs",
                Self::UnknownRegistryKey | Self::UnknownRegistryValue => {
                    "private_fixture_inventory_changed"
                }
                Self::WrongImageId => "helper_image_identity_differs",
                Self::WrongDirectoryId => "helper_directory_identity_changed",
                Self::WrongProfileId => "profile_entry_identity_changed",
                Self::ChangedImageDacl => "helper_image_dacl_changed",
                Self::UnknownHelperEntry => "helper_directory_inventory_changed",
                Self::UnknownProfileEntry => "profile_inventory_changed",
                Self::ProfileEnumerationLimit => "profile_entry_bound_exceeded",
                Self::ImageLeafSwap => "helper_image_leaf_swap_refused",
                Self::DirectorySwap => "helper_directory_swap_refused",
                Self::ImageHardlink => "helper_image_hardlink_refused",
                Self::MissingJobFence => "cleanup_job_fence_missing",
                Self::LiveNonzeroJob => "cancel_job_live_nonzero_refused",
                Self::JobQueryError => "cleanup_job_query_error_injected",
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ParentMarkerCanaryFacts {
        machine_value_sha256: String,
        user_value_sha256: String,
        machine_descriptor_sha256: String,
        user_descriptor_sha256: String,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PrivateCanaryFacts {
        value_sha256: String,
        descriptor_sha256: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ControlFileFacts {
        leaf: String,
        identity: (u64, [u8; 16]),
        length: u64,
        content_sha256: String,
        descriptor_sha256: String,
        profile_fact: ProfileEntryFact,
    }

    #[derive(Clone, Debug)]
    struct CleanupControlDetail {
        setup_verified: bool,
        target_reached: bool,
        final_verified: bool,
        state: String,
        native_status: String,
        active_count: String,
        object_name: String,
        object_id: String,
        content_sha256: String,
        descriptor_sha256: String,
        expected_id: String,
        observed_id: String,
        inventory_count: String,
        inventory_sha256: String,
    }

    impl CleanupControlDetail {
        fn empty() -> Self {
            Self {
                setup_verified: false,
                target_reached: false,
                final_verified: false,
                state: "not_applicable".to_owned(),
                native_status: "not_applicable".to_owned(),
                active_count: "not_applicable".to_owned(),
                object_name: "not_applicable".to_owned(),
                object_id: "not_applicable".to_owned(),
                content_sha256: "not_applicable".to_owned(),
                descriptor_sha256: "not_applicable".to_owned(),
                expected_id: "not_applicable".to_owned(),
                observed_id: "not_applicable".to_owned(),
                inventory_count: "not_applicable".to_owned(),
                inventory_sha256: "not_applicable".to_owned(),
            }
        }
    }

    fn create_control_file_canary(
        parent: HANDLE,
        leaf: &str,
        content: &[u8],
        user_sid: &str,
        package_sid: &str,
    ) -> io::Result<ControlFileFacts> {
        if content.len() > 4096 {
            return Err(invalid("cleanup control file canary exceeds its bound"));
        }
        let mut descriptor = helper_image_security_descriptor(user_sid, package_sid)?;
        let created = (|| {
            let handle = relative_create_file(
                parent,
                leaf,
                FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                descriptor.0,
            )?;
            let mut file = File::from(handle);
            let result = (|| {
                file.write_all(content)?;
                file.flush()?;
                let identity = script_identity(file.as_raw_handle())?;
                let descriptor_sha256 = digest(&resource_dacl_bytes(file.as_raw_handle())?)?;
                let profile_fact = profile_fact(file.as_raw_handle(), false)?;
                file.seek(std::io::SeekFrom::Start(0))?;
                let mut observed = Vec::with_capacity(content.len());
                (&mut file)
                    .take(content.len() as u64 + 1)
                    .read_to_end(&mut observed)?;
                if observed != content {
                    return Err(invalid(
                        "cleanup control canary bytes differ after creation",
                    ));
                }
                Ok(ControlFileFacts {
                    leaf: leaf.to_owned(),
                    identity,
                    length: content.len() as u64,
                    content_sha256: digest(content)?,
                    descriptor_sha256,
                    profile_fact,
                })
            })();
            let close = close_file_checked(file, "CloseHandle(cleanup control canary writer)");
            match (result, close) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(close)) => Err(close),
                (Err(primary), Err(close)) => Err(io::Error::other(format!(
                    "cleanup control canary setup failed: {primary}; writer close failed: {close}"
                ))),
            }
        })();
        let release = descriptor.free();
        match (created, release) {
            (Ok(facts), Ok(())) => Ok(facts),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(release)) => Err(release),
            (Err(primary), Err(release)) => Err(io::Error::other(format!(
                "cleanup control canary setup failed: {primary}; descriptor release failed: {release}"
            ))),
        }
    }

    fn verify_control_file_canary(parent: HANDLE, facts: &ControlFileFacts) -> io::Result<()> {
        let opened = relative_open(
            parent,
            &facts.leaf,
            false,
            FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let mut file = File::from(opened);
        let observed = (|| {
            check_object(file.as_raw_handle(), false)?;
            let identity = script_identity(file.as_raw_handle())?;
            let descriptor_sha256 = digest(&resource_dacl_bytes(file.as_raw_handle())?)?;
            file.seek(std::io::SeekFrom::Start(0))?;
            let mut bytes = Vec::with_capacity(facts.length as usize);
            (&mut file)
                .take(facts.length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            let standard = profile_fact(file.as_raw_handle(), false)?;
            if identity != facts.identity
                || standard.size as u64 != facts.length
                || digest(&bytes)? != facts.content_sha256
                || descriptor_sha256 != facts.descriptor_sha256
                || standard != facts.profile_fact
            {
                return Err(invalid(
                    "cleanup control canary identity or preimage changed",
                ));
            }
            Ok(())
        })();
        let close = close_file_checked(file, "CloseHandle(cleanup control canary observer)");
        match (observed, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(close)) => Err(close),
            (Err(primary), Err(close)) => Err(io::Error::other(format!(
                "cleanup control canary observation failed: {primary}; observer close failed: {close}"
            ))),
        }
    }

    fn verify_held_image_base(
        image: &mut HeldHelperImage,
        expected_resource_dacl: &[u8],
    ) -> io::Result<()> {
        let directory = image
            .directory_handle
            .as_ref()
            .ok_or_else(|| invalid("held helper directory keeper missing"))?;
        if script_identity(directory.as_raw_handle())? != image.directory_identity {
            return Err(invalid("held helper directory identity changed"));
        }
        check_object(directory.as_raw_handle(), true)?;
        if resource_dacl_bytes(directory.as_raw_handle())? != image.expected_directory_dacl {
            return Err(invalid("held helper directory descriptor changed"));
        }
        let reader = image
            .file
            .as_mut()
            .ok_or_else(|| invalid("immutable helper image reader missing"))?;
        verify_image_file(
            reader,
            image.identity,
            image.expected_length,
            &image.sha256,
            expected_resource_dacl,
        )?;
        let anchor = image
            .metadata_anchor
            .as_ref()
            .ok_or_else(|| invalid("helper image identity bridge missing"))?;
        if script_identity(anchor.as_raw_handle())? != image.identity {
            return Err(invalid("helper image identity bridge changed"));
        }
        Ok(())
    }

    fn verify_held_directory_identity(image: &HeldHelperImage) -> io::Result<()> {
        let directory = image
            .directory_handle
            .as_ref()
            .ok_or_else(|| invalid("held helper directory keeper missing"))?;
        if script_identity(directory.as_raw_handle())? != image.directory_identity {
            return Err(invalid("held helper directory identity changed"));
        }
        check_object(directory.as_raw_handle(), true)?;
        if resource_dacl_bytes(directory.as_raw_handle())? != image.expected_directory_dacl {
            return Err(invalid("held helper directory descriptor changed"));
        }
        Ok(())
    }

    fn verify_image_content_without_singlelink(image: &mut HeldHelperImage) -> io::Result<()> {
        let reader = image
            .file
            .as_mut()
            .ok_or_else(|| invalid("immutable helper image reader missing"))?;
        if script_identity(reader.as_raw_handle())? != image.identity
            || resource_dacl_bytes(reader.as_raw_handle())? != image.expected_resource_dacl
        {
            return Err(invalid("hardlink target image identity or DACL changed"));
        }
        reader.seek(std::io::SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(image.expected_length as usize);
        (&mut *reader)
            .take(image.expected_length.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != image.expected_length || digest(&bytes)? != image.sha256 {
            return Err(invalid("hardlink target image content changed"));
        }
        if script_identity(reader.as_raw_handle())? != image.identity {
            return Err(invalid(
                "hardlink target image identity changed while hashing",
            ));
        }
        reader.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }

    fn create_control_directory(
        parent: HANDLE,
        leaf: &str,
        user_sid: &str,
        package_sid: &str,
    ) -> io::Result<OwnedHandle> {
        let mut descriptor = helper_directory_security_descriptor(user_sid, package_sid)?;
        let mut handle_owner = None;
        let result = (|| {
            let expected_dacl = descriptor_dacl_bytes(descriptor.0)?;
            let (mut storage, mut object_name) = nt_unicode(leaf)?;
            let mut attributes = OBJECT_ATTRIBUTES::default();
            attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
            attributes.RootDirectory = parent;
            attributes.ObjectName = &mut object_name;
            attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
            attributes.SecurityDescriptor = descriptor.0.cast();
            let mut raw = null_mut();
            let mut status = IO_STATUS_BLOCK::default();
            let ntstatus = unsafe {
                NtCreateFile(
                    &mut raw,
                    DELETE
                        | FILE_LIST_DIRECTORY
                        | FILE_TRAVERSE
                        | FILE_READ_ATTRIBUTES
                        | READ_CONTROL
                        | SYNCHRONIZE,
                    &attributes,
                    &mut status,
                    null(),
                    FILE_ATTRIBUTE_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                    null(),
                    0,
                )
            };
            std::hint::black_box(&mut storage);
            if ntstatus < 0 {
                return Err(operation_error(
                    "NtCreateFile(FILE_CREATE cleanup control directory)",
                    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(ntstatus) } as i32),
                ));
            }
            handle_owner = Some(own("NtCreateFile(cleanup control directory)", raw)?);
            let handle = handle_owner
                .as_ref()
                .expect("cleanup control directory owner retained");
            if status.Information != FILE_CREATED as usize {
                return Err(invalid(
                    "cleanup control directory did not report FILE_CREATED",
                ));
            }
            check_object(handle.as_raw_handle(), true)?;
            if resource_dacl_bytes(handle.as_raw_handle())? != expected_dacl {
                return Err(invalid(
                    "cleanup control directory DACL differs from its private policy",
                ));
            }
            Ok(handle_owner
                .take()
                .expect("verified cleanup control directory owner retained"))
        })();
        let result = match result {
            Ok(handle) => Ok(handle),
            Err(primary) => match handle_owner.take() {
                Some(handle) => match close_checked(
                    handle,
                    "CloseHandle(cleanup control directory after verification failure)",
                ) {
                    Ok(()) => Err(primary),
                    Err(close) => Err(io::Error::other(format!(
                        "cleanup control directory verification failed: {primary}; handle close failed: {close}"
                    ))),
                },
                None => Err(primary),
            },
        };
        let release = descriptor.free();
        match (result, release) {
            (Ok(handle), Ok(())) => Ok(handle),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(handle), Err(release)) => {
                let close =
                    close_checked(handle, "CloseHandle(directory after descriptor failure)");
                match close {
                    Ok(()) => Err(release),
                    Err(close) => Err(io::Error::other(format!(
                        "control directory descriptor release failed: {release}; handle close failed: {close}"
                    ))),
                }
            }
            (Err(primary), Err(release)) => Err(io::Error::other(format!(
                "control directory creation failed: {primary}; descriptor release failed: {release}"
            ))),
        }
    }

    fn remove_package_ace_from_control_image(
        handle: HANDLE,
        user_sid: &str,
    ) -> io::Result<Vec<u8>> {
        let descriptor_text = wide(OsStr::new(&format!("O:{user_sid}D:P(A;;FA;;;{user_sid})")))?;
        let mut descriptor_raw = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor_raw,
                null_mut(),
            )
        };
        if converted == 0 {
            let primary = operation_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW(control DACL)",
                io::Error::last_os_error(),
            );
            let mut descriptor = LocalSecurityDescriptor(descriptor_raw);
            return match descriptor.free() {
                Ok(()) => Err(primary),
                Err(release) => Err(io::Error::other(format!(
                    "control DACL conversion failed: {primary}; descriptor release failed: {release}"
                ))),
            };
        }
        if descriptor_raw.is_null() {
            return Err(invalid("control DACL descriptor is null"));
        }
        let mut descriptor = LocalSecurityDescriptor(descriptor_raw);
        let dacl_result = (|| {
            let mut present = 0;
            let mut dacl = null_mut();
            let mut defaulted = 0;
            if unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
            } == 0
                || present == 0
                || dacl.is_null()
            {
                return Err(operation_error(
                    "GetSecurityDescriptorDacl(control DACL)",
                    io::Error::last_os_error(),
                ));
            }
            let status = unsafe {
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
            if status != ERROR_SUCCESS {
                return Err(operation_error(
                    "SetSecurityInfo(cleanup control image DACL)",
                    io::Error::from_raw_os_error(status as i32),
                ));
            }
            resource_dacl_bytes(handle)
        })();
        let release = descriptor.free();
        match (dacl_result, release) {
            (Ok(actual), Ok(())) => Ok(actual),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(release)) => Err(release),
            (Err(primary), Err(release)) => Err(io::Error::other(format!(
                "control image DACL change failed: {primary}; descriptor release failed: {release}"
            ))),
        }
    }

    fn parent_marker_canary_facts() -> io::Result<ParentMarkerCanaryFacts> {
        let machine_name = std::env::var("ORBIT_REGISTRY_WITNESS_MACHINE_MARKER")
            .map_err(|_| invalid("machine marker identity missing"))?;
        let user_name = std::env::var("ORBIT_REGISTRY_WITNESS_USER_MARKER")
            .map_err(|_| invalid("user marker identity missing"))?;
        let user_sid = std::env::var("ORBIT_REGISTRY_WITNESS_USER_SID")
            .map_err(|_| invalid("original user SID missing"))?;
        let mut machine = None;
        let mut user = None;
        let facts = (|| -> io::Result<ParentMarkerCanaryFacts> {
            machine = Some(
                win32_open_key(
                    HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                    KEY_READ,
                )
                .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
            );
            user = Some(
                win32_open_key(HKEY_USERS, &format!("{user_sid}\\Environment"), KEY_READ)
                    .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
            );
            let machine = machine.as_ref().expect("machine marker observer retained");
            let user = user.as_ref().expect("user marker observer retained");
            Ok(ParentMarkerCanaryFacts {
                machine_value_sha256: registry_string_digest(
                    &win32_query_value(machine, &machine_name)
                        .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                )?,
                user_value_sha256: registry_string_digest(
                    &win32_query_value(user, &user_name)
                        .map_err(|status| io::Error::from_raw_os_error(status as i32))?,
                )?,
                machine_descriptor_sha256: digest(&registry_key_security(machine.raw())?)?,
                user_descriptor_sha256: digest(&registry_key_security(user.raw())?)?,
            })
        })();
        let mut close_errors = Vec::new();
        if let Some(machine) = machine.take() {
            if let Err(error) = machine.close() {
                close_errors.push(format!("machine marker observer close: {error}"));
            }
        }
        if let Some(user) = user.take() {
            if let Err(error) = user.close() {
                close_errors.push(format!("user marker observer close: {error}"));
            }
        }
        match (facts, close_errors.is_empty()) {
            (Ok(facts), true) => Ok(facts),
            (Err(primary), true) => Err(primary),
            (Ok(_), false) => Err(io::Error::other(close_errors.join("; "))),
            (Err(primary), false) => Err(io::Error::other(format!(
                "parent canary observation failed: {primary}; {}",
                close_errors.join("; ")
            ))),
        }
    }

    fn registry_witness_stage_a_run(control: Option<CleanupControl>) -> io::Result<()> {
        verify_cancel_readiness_frame_oracle()?;
        verify_helper_pe_parser_oracle()?;
        verify_job_process_id_list_oracle()?;
        verify_partial_key_value_header_oracle()?;
        let nonce = std::env::var("ORBIT_REGISTRY_WITNESS_NONCE")
            .map_err(|_| invalid("disposable CI fixture nonce missing"))?;
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("invalid disposable CI fixture nonce"));
        }
        let expected_user_sid = std::env::var("ORBIT_REGISTRY_WITNESS_USER_SID")
            .map_err(|_| invalid("disposable CI original user SID missing"))?;
        let user_sid = parent_primary_user_sid()?;
        if user_sid != expected_user_sid {
            return Err(invalid(
                "parent primary process TokenUser differs from fixture identity",
            ));
        }
        let parent_pid = unsafe { GetCurrentProcessId() };
        let parent_creation = process_creation_text(unsafe { GetCurrentProcess() })?;
        let mut session = None;
        let mut profile_anchor = None;
        let mut fixture = None;
        let mut image = None;
        let mut job_gate = CleanupJobGate::default();
        let control_canary_before = if control.is_some() {
            Some(parent_marker_canary_facts()?)
        } else {
            None
        };
        let mut control_target_error: Option<String> = None;
        let mut control_private_canary: Option<PrivateCanaryFacts> = None;
        let mut control_detail = CleanupControlDetail::empty();
        let mut control_file_canary: Option<ControlFileFacts> = None;
        let mut control_original_file_canary: Option<ControlFileFacts> = None;
        let mut control_secondary_name: Option<String> = None;
        let mut control_replacement_directory: Option<OwnedHandle> = None;
        let mut profile_limit_directory: Option<OwnedHandle> = None;
        let mut profile_limit_directory_profile_fact: Option<ProfileEntryFact> = None;
        let mut profile_limit_files: Vec<ControlFileFacts> = Vec::new();
        let mut control_expected_image_identity: Option<(u64, [u8; 16])> = None;
        let mut control_expected_directory_identity: Option<(u64, [u8; 16])> = None;
        let mut control_expected_profile_identity: Option<(u64, [u8; 16])> = None;
        let mut control_expected_image_hash: Option<String> = None;
        let mut control_removed_job_fence: Option<JobFence> = None;
        let mut control_image_dacl_after: Option<Vec<u8>> = None;
        let mut control_namespace_share_refused = false;
        let mut control_check_errors = Vec::new();
        let mut control_preflight_verified = false;
        let mut control_known_preimages_verified = false;
        let mut control_private_canary_unchanged = false;
        let mut control_view_preimages_unchanged = false;
        let mut control_view_preimages_before: Option<(PrivateViewPreimage, PrivateViewPreimage)> =
            None;
        let run_result = (|| {
            parent_marker_controls("before")?;
            session = Some(SandboxSession::create()?);
            let session_ref = session.as_ref().expect("session initialized");
            session_ref.retain_profile_for_registry_witness();
            profile_anchor = Some(ProfileCleanupAnchor::capture(session_ref)?);
            let package_sid = sid_text(session_ref.sid.as_ptr().cast_mut().cast())?;
            fixture = Some(PrivateRegistryFixture::create(
                &nonce,
                &user_sid,
                &package_sid,
            )?);
            let marker_digest = digest(b"ORBIT-PRIVATE-METADATA-V1")?;
            image = Some(hold_helper_image(
                session_ref,
                &nonce,
                &user_sid,
                &package_sid,
                control,
            )?);
            let fixture_ref = fixture.as_ref().expect("fixture initialized");
            let image_ref = image.as_ref().expect("held image initialized");
            let fixture_identity = digest(fixture_ref.name.as_bytes())?;
            let machine_root = fixture_ref.root_handle("MachineView", KEY_READ)?;
            let user_root = fixture_ref.root_handle("UserView", KEY_READ)?;
            let inherited_machine = duplicate_inheritable_read_key(machine_root.raw())?;
            let inherited_user = duplicate_inheritable_read_key(user_root.raw())?;
            machine_root.close()?;
            user_root.close()?;
            let image_id = image_ref.identity;
            let executable = image_ref.path.clone();
            let spec = SpawnSpec {
                executable,
                arguments: vec![
                    "--exact".to_owned(),
                    "process::windows::registry_witness_tests::registry_witness_fixed_child_helper"
                        .to_owned(),
                    "--nocapture".to_owned(),
                ],
                timeout: Duration::from_secs(30),
                output_limit: 128 * 1024,
            };
            let inherited_handles = [inherited_machine, inherited_user];
            let (mut child, thread) = OwnedProcess::create_registry_witness_child(
                session_ref,
                &spec,
                "normal",
                &nonce,
                &user_sid,
                &package_sid,
                &image_ref.sha256,
                image_id,
                &marker_digest,
                &fixture_identity,
                inherited_handles,
            )?;
            job_gate.normal = Some(match duplicate_job_fence(&child, "normal") {
                Ok(fence) => fence,
                Err(primary) => {
                    let error = stop_child_after_failure(&mut child, primary);
                    drop(thread);
                    return Err(error);
                }
            });
            if !child.evidence.app_container
                || !child.evidence.less_privileged
                || !child.evidence.job_assigned_before_resume
                || child.evidence.total_capabilities != 1
                || child.evidence.network_capabilities != 0
                || child.pid() == 0
            {
                let primary = invalid("helper pre-resume LPAC or Job evidence failed");
                let error = stop_child_after_failure(&mut child, primary);
                drop(thread);
                return Err(error);
            }
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                let error =
                    operation_error("ResumeThread(registry witness)", io::Error::last_os_error());
                let error = stop_child_after_failure(&mut child, error);
                drop(thread);
                return Err(error);
            }
            drop(thread);
            let normal_child_pid = child.pid();
            let normal_child_creation = match process_creation_text(child.process.as_raw_handle()) {
                Ok(value) => value,
                Err(error) => return Err(stop_child_after_failure(&mut child, error)),
            };
            let output = child.wait(&AtomicBool::new(false))?;
            job_gate
                .normal
                .as_mut()
                .ok_or_else(|| invalid("normal Job fence missing after wait"))?
                .process_waited = true;
            job_gate
                .normal
                .as_ref()
                .ok_or_else(|| invalid("normal Job fence missing"))?
                .require_zero("normal child wait")?;
            validate_parent_self_binding(parent_pid, &parent_creation)?;
            emit_witness_record(&format!(
                "registry_witness_parent_binding nonce={nonce} pid={parent_pid} creation={parent_creation} live=true"
            ))?;
            emit_witness_record(&format!(
                "registry_witness_child_result role=normal completion={:?} exit={} pid={} creation={} image_id={} image_sha256={} fixture_id={} fixture_digest={}",
                output.completion,
                output.code,
                normal_child_pid,
                normal_child_creation,
                identity_text(image_id),
                image_ref.sha256,
                fixture_identity,
                marker_digest
            ))?;
            emit_witness_record(&format!(
                "registry_witness_diagnostic stream=stdout truncated={} text={}",
                output.stdout.len() > 1024,
                escape_diagnostic(&output.stdout)
            ))?;
            emit_witness_record(&format!(
                "registry_witness_diagnostic stream=stderr truncated={} text={}",
                output.stderr.len() > 1024,
                escape_diagnostic(&output.stderr)
            ))?;
            forward_child_records(&output.stdout, &nonce, parent_pid, &parent_creation, None)?;
            forward_child_records(&output.stderr, &nonce, parent_pid, &parent_creation, None)?;
            if output.code != 0 || output.completion != Completion::Exited {
                return Err(io::Error::other(format!(
                    "normal helper failed: exit={} completion={:?}",
                    output.code, output.completion
                )));
            }
            emit_witness_record(
                "registry_witness_probe id=lifetime/normal_job_zero observed=true active_processes=0",
            )?;
            parent_recovery(fixture_ref)?;
            fixture_ref.verify_unchanged()?;
            run_cancel_witness_child(
                &mut job_gate,
                session_ref,
                fixture_ref,
                image_ref,
                &nonce,
                &user_sid,
                &package_sid,
                parent_pid,
                &parent_creation,
                &marker_digest,
                &fixture_identity,
                control,
                &mut control_target_error,
            )?;
            job_gate.require_zero("registry witness cleanup preflight")?;
            Ok(())
        })();

        let primary_error = run_result.as_ref().err().map(ToString::to_string);
        let mut cleanup_errors = Vec::new();
        let mut receipt = CleanupReceipt {
            registry: None,
            image: None,
            profile_packages: None,
            profile_packages_identity: None,
            profile_entry_leaf: None,
            profile_sdk_result: None,
            profile_packages_close_succeeded: false,
            profile_absent: false,
            profile_final_verified: false,
            normal_job_zero: false,
            cancel_job_zero: false,
            errors: Vec::new(),
        };
        let initial_job_zero = job_gate.require_zero("cleanup transaction preflight");
        let child_shutdown_unobserved = session.as_ref().is_some_and(|session| {
            session
                .registry_witness_child_unobserved
                .load(Ordering::Acquire)
        }) || initial_job_zero.is_err();
        if child_shutdown_unobserved {
            if let Err(error) = initial_job_zero {
                cleanup_errors.push(format!(
                    "exact Job-zero preflight failed; all owned residue retained: {error}"
                ));
            }
            let fixture_residue = fixture.as_ref().map_or_else(
                || "not-owned".to_owned(),
                |fixture| format!("Software\\{}", fixture.name),
            );
            let image_residue = image.as_ref().map_or_else(
                || "not-owned".to_owned(),
                |image| image.path.display().to_string(),
            );
            cleanup_errors.push(format!("child/Job shutdown unobserved; retained registry={fixture_residue}; image={image_residue}; profile={}", session.as_ref().map_or_else(|| "unknown".to_owned(), |session| session.folder.display().to_string())));
            drop(fixture.take());
            drop(image.take());
        } else {
            receipt.normal_job_zero = job_gate.normal.is_some();
            receipt.cancel_job_zero = job_gate.cancel.is_some();
            let preflight = (|| {
                if control.is_some() && primary_error.is_some() {
                    return Err(invalid(
                        "cleanup control injection skipped because the real stage failed",
                    ));
                }
                let fixture = fixture
                    .as_ref()
                    .ok_or_else(|| invalid("private fixture owner missing"))?;
                control_view_preimages_before = if control.is_some() {
                    Some(fixture.view_preimages()?)
                } else {
                    None
                };
                let session_ref = session
                    .as_ref()
                    .ok_or_else(|| invalid("profile owner missing for control"))?;
                let package_sid = sid_text(session_ref.sid.as_ptr().cast_mut().cast())?;
                match control {
                    Some(CleanupControl::UnknownRegistryKey) => {
                        control_private_canary =
                            Some(fixture.create_unknown_key_canary(&user_sid, &package_sid)?);
                        control_detail.state =
                            "absent_before_installed_registry_key_canary".to_owned();
                        control_detail.native_status = "RegCreateKeyExW_SUCCESS".to_owned();
                        control_detail.object_name =
                            "Software\\ORBIT_WITNESS/ForeignCanary".to_owned();
                        control_detail.content_sha256 = control_private_canary
                            .as_ref()
                            .expect("private canary retained")
                            .value_sha256
                            .clone();
                        control_detail.descriptor_sha256 = control_private_canary
                            .as_ref()
                            .expect("private canary retained")
                            .descriptor_sha256
                            .clone();
                    }
                    Some(CleanupControl::UnknownRegistryValue) => {
                        control_private_canary = Some(fixture.create_unknown_value_canary()?);
                        control_detail.state = "absent_before_installed_reg_sz_canary".to_owned();
                        control_detail.native_status = "RegSetValueExW_SUCCESS_REG_SZ".to_owned();
                        control_detail.object_name =
                            "MachineView/Metadata/UnexpectedControlValue".to_owned();
                        control_detail.content_sha256 = control_private_canary
                            .as_ref()
                            .expect("private canary retained")
                            .value_sha256
                            .clone();
                        control_detail.descriptor_sha256 = control_private_canary
                            .as_ref()
                            .expect("private canary retained")
                            .descriptor_sha256
                            .clone();
                    }
                    Some(CleanupControl::WrongImageHash) => {
                        if let Some(held) = image.as_mut() {
                            control_detail.object_name = held.image_leaf.clone();
                            control_detail.object_id = identity_text(held.identity);
                            control_detail.content_sha256 = held.sha256.clone();
                            control_expected_image_hash = Some(held.sha256.clone());
                            held.sha256 = if held.sha256 == "0".repeat(64) {
                                "f".repeat(64)
                            } else {
                                "0".repeat(64)
                            };
                            control_detail.state = "expected_hash_corrupted".to_owned();
                            control_detail.expected_id = control_expected_image_hash
                                .as_ref()
                                .expect("image hash captured")
                                .clone();
                            control_detail.observed_id = held.sha256.clone();
                        }
                    }
                    Some(CleanupControl::WrongImageId) => {
                        let held = image
                            .as_mut()
                            .ok_or_else(|| invalid("held image missing"))?;
                        control_expected_image_identity = Some(held.identity);
                        control_detail.object_name = held.image_leaf.clone();
                        control_detail.object_id = identity_text(held.identity);
                        let mut wrong = held.identity;
                        wrong.1[0] ^= 0x80;
                        held.identity = wrong;
                        control_detail.state = "expected_id_corrupted".to_owned();
                        control_detail.expected_id = identity_text(
                            control_expected_image_identity.expect("image identity captured"),
                        );
                        control_detail.observed_id = identity_text(wrong);
                    }
                    Some(CleanupControl::WrongDirectoryId) => {
                        let held = image
                            .as_mut()
                            .ok_or_else(|| invalid("held image missing"))?;
                        control_expected_directory_identity = Some(held.directory_identity);
                        control_detail.object_name = held.directory_leaf.clone();
                        control_detail.object_id = identity_text(held.directory_identity);
                        let mut wrong = held.directory_identity;
                        wrong.1[0] ^= 0x80;
                        held.directory_identity = wrong;
                        control_detail.state = "expected_id_corrupted".to_owned();
                        control_detail.expected_id = identity_text(
                            control_expected_directory_identity
                                .expect("directory identity captured"),
                        );
                        control_detail.observed_id = identity_text(wrong);
                    }
                    Some(CleanupControl::WrongProfileId) => {
                        let anchor = profile_anchor
                            .as_mut()
                            .ok_or_else(|| invalid("profile anchor missing"))?;
                        control_expected_profile_identity = Some(anchor.entry_identity);
                        control_detail.object_name = anchor.entry_leaf.clone();
                        control_detail.object_id = identity_text(anchor.entry_identity);
                        let mut wrong = anchor.entry_identity;
                        wrong.1[0] ^= 0x80;
                        anchor.entry_identity = wrong;
                        control_detail.state = "expected_id_corrupted".to_owned();
                        control_detail.expected_id = identity_text(
                            control_expected_profile_identity.expect("profile identity captured"),
                        );
                        control_detail.observed_id = identity_text(wrong);
                    }
                    Some(CleanupControl::ChangedImageDacl) => {
                        let held = image
                            .as_mut()
                            .ok_or_else(|| invalid("held image missing"))?;
                        let original = digest(&held.expected_resource_dacl)?;
                        let mutator = held
                            .control_dacl_handle
                            .as_ref()
                            .ok_or_else(|| invalid("test image DACL mutator missing"))?;
                        let changed = remove_package_ace_from_control_image(
                            mutator.as_raw_handle(),
                            &user_sid,
                        )?;
                        let changed_digest = digest(&changed)?;
                        if changed == held.expected_resource_dacl {
                            return Err(invalid(
                                "changed-image-DACL control did not change the DACL",
                            ));
                        }
                        control_image_dacl_after = Some(changed);
                        control_detail.state = "package_ace_removed".to_owned();
                        control_detail.object_name = "helper_image".to_owned();
                        control_detail.object_id = identity_text(held.identity);
                        control_detail.expected_id = original;
                        control_detail.observed_id = changed_digest.clone();
                        control_detail.descriptor_sha256 = changed_digest;
                    }
                    Some(CleanupControl::UnknownHelperEntry) => {
                        let held = image
                            .as_ref()
                            .ok_or_else(|| invalid("held image missing"))?;
                        let directory = held
                            .directory_handle
                            .as_ref()
                            .ok_or_else(|| invalid("held helper directory missing"))?;
                        let leaf = format!("ORBIT-CANARY-{}", &nonce[..8]);
                        let content = format!("ORBIT-UNKNOWN-HELPER-{nonce}").into_bytes();
                        control_file_canary = Some(create_control_file_canary(
                            directory.as_raw_handle(),
                            &leaf,
                            &content,
                            &user_sid,
                            &package_sid,
                        )?);
                        let facts = control_file_canary
                            .as_ref()
                            .expect("helper canary retained");
                        control_detail.state = "absent_before_installed_helper_entry".to_owned();
                        control_detail.object_name = facts.leaf.clone();
                        control_detail.object_id = identity_text(facts.identity);
                        control_detail.content_sha256 = facts.content_sha256.clone();
                        control_detail.descriptor_sha256 = facts.descriptor_sha256.clone();
                    }
                    Some(CleanupControl::UnknownProfileEntry) => {
                        let anchor = profile_anchor
                            .as_ref()
                            .ok_or_else(|| invalid("profile anchor missing"))?;
                        let ac = anchor
                            .ac
                            .as_ref()
                            .ok_or_else(|| invalid("AC anchor missing"))?;
                        let leaf = format!("ORBIT-PROFILE-{}", &nonce[..8]);
                        let content = format!("ORBIT-UNKNOWN-PROFILE-{nonce}").into_bytes();
                        control_file_canary = Some(create_control_file_canary(
                            ac.as_raw_handle(),
                            &leaf,
                            &content,
                            &user_sid,
                            &package_sid,
                        )?);
                        let facts = control_file_canary
                            .as_ref()
                            .expect("profile canary retained");
                        control_detail.state = "absent_before_installed_profile_entry".to_owned();
                        control_detail.object_name = facts.leaf.clone();
                        control_detail.object_id = identity_text(facts.identity);
                        control_detail.content_sha256 = facts.content_sha256.clone();
                        control_detail.descriptor_sha256 = facts.descriptor_sha256.clone();
                    }
                    Some(CleanupControl::ProfileEnumerationLimit) => {
                        let anchor = profile_anchor
                            .as_ref()
                            .ok_or_else(|| invalid("profile anchor missing"))?;
                        let ac = anchor
                            .ac
                            .as_ref()
                            .ok_or_else(|| invalid("AC anchor missing"))?;
                        let directory_leaf = format!("ORBIT-LIMIT-{}", &nonce[..8]);
                        profile_limit_directory = Some(create_control_directory(
                            ac.as_raw_handle(),
                            &directory_leaf,
                            &user_sid,
                            &package_sid,
                        )?);
                        let child = profile_limit_directory
                            .as_ref()
                            .expect("limit directory retained")
                            .as_raw_handle();
                        for index in 0..513usize {
                            let leaf = format!("F{index:03}");
                            profile_limit_files.push(create_control_file_canary(
                                child,
                                &leaf,
                                &[],
                                &user_sid,
                                &package_sid,
                            )?);
                        }
                        profile_limit_directory_profile_fact = Some(profile_fact(child, true)?);
                        let mut inventory = String::new();
                        for facts in &profile_limit_files {
                            use std::fmt::Write as _;
                            write!(
                                inventory,
                                "{}|{}|{}\n",
                                facts.leaf,
                                identity_text(facts.identity),
                                facts.content_sha256
                            )
                            .map_err(|_| invalid("profile-limit inventory formatting failed"))?;
                        }
                        control_detail.state = "installed_513_bounded_empty_files".to_owned();
                        control_detail.object_name = directory_leaf;
                        control_detail.object_id = identity_text(script_identity(child)?);
                        control_detail.descriptor_sha256 = digest(&resource_dacl_bytes(child)?)?;
                        control_detail.inventory_count = "513".to_owned();
                        control_detail.inventory_sha256 = digest(inventory.as_bytes())?;
                    }
                    Some(CleanupControl::MissingJobFence) => {
                        job_gate.require_zero("missing Job fence control pre-arm")?;
                        control_detail.native_status =
                            "STATUS_SUCCESS_both_jobs_zero_before_owner_move".to_owned();
                        control_detail.active_count = "0,0".to_owned();
                        control_removed_job_fence = job_gate.cancel.take();
                        if control_removed_job_fence.is_none() {
                            return Err(invalid("cancellation Job fence missing before control"));
                        }
                        control_detail.state = "one_fence_removed_for_shared_gate".to_owned();
                    }
                    Some(CleanupControl::JobQueryError) => {
                        let control = control.expect("job query error control selected");
                        job_gate.require_zero("Job query error control pre-arm")?;
                        job_gate.reset_last_native_active_counts();
                        job_gate.inject_query_error_once(control.target_error());
                        control_detail.state = "shared_job_query_error_injection_armed".to_owned();
                    }
                    Some(CleanupControl::LiveNonzeroJob) => {
                        if control_target_error.is_none() {
                            return Err(invalid(
                                "live Job control did not record its early refusal",
                            ));
                        }
                        control_detail.state =
                            "actual_cancel_job_singleton_refused_before_stop".to_owned();
                        control_detail.active_count = "1".to_owned();
                    }
                    Some(CleanupControl::ImageLeafSwap) => {
                        let held = image
                            .as_ref()
                            .ok_or_else(|| invalid("held image missing"))?;
                        let directory = held
                            .directory_handle
                            .as_ref()
                            .ok_or_else(|| invalid("held helper directory missing"))?;
                        let reader = held
                            .file
                            .as_ref()
                            .ok_or_else(|| invalid("held image reader missing"))?;
                        let mut original = ControlFileFacts {
                            leaf: held.image_leaf.clone(),
                            identity: held.identity,
                            length: held.expected_length,
                            content_sha256: held.sha256.clone(),
                            descriptor_sha256: digest(&resource_dacl_bytes(
                                reader.as_raw_handle(),
                            )?)?,
                            profile_fact: profile_fact(reader.as_raw_handle(), false)?,
                        };
                        let backup = format!("ORBIT-OLD-IMAGE-{}", &nonce[..8]);
                        let mut rename_native_status = None;
                        let mut rename_handle_close_failed = false;
                        let rename_result = (|| -> io::Result<()> {
                            let rename_handle = relative_open_with_status(
                                directory.as_raw_handle(),
                                &held.image_leaf,
                                false,
                                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                &mut rename_native_status,
                            )?;
                            let renamed = rename_relative(
                                rename_handle.as_raw_handle(),
                                directory.as_raw_handle(),
                                &backup,
                                &mut rename_native_status,
                            );
                            let close =
                                close_checked(rename_handle, "CloseHandle(image rename control)");
                            match (renamed, close) {
                                (Ok(()), Ok(())) => Ok(()),
                                (Err(primary), Ok(())) => Err(primary),
                                (Ok(()), Err(close)) => {
                                    rename_handle_close_failed = true;
                                    Err(close)
                                }
                                (Err(primary), Err(close)) => {
                                    rename_handle_close_failed = true;
                                    Err(io::Error::other(format!(
                                        "image rename failed: {primary}; rename handle close failed: {close}"
                                    )))
                                }
                            }
                        })();
                        if let Err(error) = rename_result {
                            if rename_native_status == Some(0xC000_0043u32 as i32)
                                && !rename_handle_close_failed
                            {
                                control_namespace_share_refused = true;
                                control_detail.state =
                                    "rename_prevented_by_exact_sharing_violation".to_owned();
                                control_detail.native_status = format!(
                                    "NtStatus={:#010x}_Win32=32",
                                    rename_native_status.expect("sharing status captured") as u32
                                );
                                control_detail.object_name = held.image_leaf.clone();
                                control_detail.expected_id = identity_text(held.identity);
                                control_detail.observed_id = identity_text(held.identity);
                            } else {
                                return Err(error);
                            }
                        }
                        if control_namespace_share_refused {
                            control_secondary_name = Some(backup);
                        } else {
                            original.leaf = backup.clone();
                            control_original_file_canary = Some(original);
                            control_secondary_name = Some(backup.clone());
                            let replacement = create_control_file_canary(
                                directory.as_raw_handle(),
                                &held.image_leaf,
                                format!("ORBIT-IMAGE-SWAP-{nonce}").as_bytes(),
                                &user_sid,
                                &package_sid,
                            )?;
                            control_detail.state =
                                "held_image_renamed_and_replacement_installed".to_owned();
                            control_detail.object_name = held.image_leaf.clone();
                            control_detail.object_id = identity_text(replacement.identity);
                            control_detail.expected_id = identity_text(held.identity);
                            control_detail.observed_id = identity_text(replacement.identity);
                            control_detail.content_sha256 = replacement.content_sha256.clone();
                            control_detail.descriptor_sha256 =
                                replacement.descriptor_sha256.clone();
                            control_file_canary = Some(replacement);
                            control_secondary_name = Some(backup);
                        }
                    }
                    Some(CleanupControl::DirectorySwap) => {
                        let held = image
                            .as_ref()
                            .ok_or_else(|| invalid("held image missing"))?;
                        let anchor = profile_anchor
                            .as_ref()
                            .ok_or_else(|| invalid("profile anchor missing"))?;
                        let ac = anchor
                            .ac
                            .as_ref()
                            .ok_or_else(|| invalid("profile AC anchor missing"))?;
                        let original_directory = held
                            .directory_handle
                            .as_ref()
                            .ok_or_else(|| invalid("held helper directory missing"))?;
                        let backup = format!("ORBIT-OLD-DIR-{}", &nonce[..8]);
                        let mut rename_native_status = None;
                        let mut rename_handle_close_failed = false;
                        let rename_result = (|| -> io::Result<()> {
                            let rename_handle = relative_open_with_status(
                                ac.as_raw_handle(),
                                &held.directory_leaf,
                                true,
                                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                &mut rename_native_status,
                            )?;
                            let renamed = rename_relative(
                                rename_handle.as_raw_handle(),
                                ac.as_raw_handle(),
                                &backup,
                                &mut rename_native_status,
                            );
                            let close = close_checked(
                                rename_handle,
                                "CloseHandle(directory rename control)",
                            );
                            match (renamed, close) {
                                (Ok(()), Ok(())) => Ok(()),
                                (Err(primary), Ok(())) => Err(primary),
                                (Ok(()), Err(close)) => {
                                    rename_handle_close_failed = true;
                                    Err(close)
                                }
                                (Err(primary), Err(close)) => {
                                    rename_handle_close_failed = true;
                                    Err(io::Error::other(format!(
                                        "directory rename failed: {primary}; rename handle close failed: {close}"
                                    )))
                                }
                            }
                        })();
                        if let Err(error) = rename_result {
                            if rename_native_status == Some(0xC000_0043u32 as i32)
                                && !rename_handle_close_failed
                            {
                                control_namespace_share_refused = true;
                                control_detail.state =
                                    "rename_prevented_by_exact_sharing_violation".to_owned();
                                control_detail.native_status = format!(
                                    "NtStatus={:#010x}_Win32=32",
                                    rename_native_status.expect("sharing status captured") as u32
                                );
                                control_detail.object_name = held.directory_leaf.clone();
                                control_detail.expected_id = identity_text(held.directory_identity);
                                control_detail.observed_id = identity_text(held.directory_identity);
                            } else {
                                return Err(error);
                            }
                        }
                        if control_namespace_share_refused {
                            control_secondary_name = Some(backup);
                        } else {
                            control_replacement_directory = Some(create_control_directory(
                                ac.as_raw_handle(),
                                &held.directory_leaf,
                                &user_sid,
                                &package_sid,
                            )?);
                            let replacement = control_replacement_directory
                                .as_ref()
                                .ok_or_else(|| invalid("replacement directory owner missing"))?;
                            let replacement_identity =
                                script_identity(replacement.as_raw_handle())?;
                            control_detail.state =
                                "held_directory_renamed_and_replacement_installed".to_owned();
                            control_detail.object_name = held.directory_leaf.clone();
                            control_detail.object_id = identity_text(replacement_identity);
                            control_detail.expected_id = identity_text(held.directory_identity);
                            control_detail.observed_id = identity_text(replacement_identity);
                            control_detail.descriptor_sha256 =
                                digest(&resource_dacl_bytes(replacement.as_raw_handle())?)?;
                            control_secondary_name = Some(backup);
                            // The held old directory remains anchored and must still contain
                            // its exact helper image after its profile name is replaced.
                            if profile_children(original_directory.as_raw_handle())?.len() != 1 {
                                return Err(invalid(
                                    "renamed original helper directory contents changed",
                                ));
                            }
                        }
                    }
                    Some(CleanupControl::ImageHardlink) => {
                        let held = image
                            .as_ref()
                            .ok_or_else(|| invalid("held image missing"))?;
                        let anchor = profile_anchor
                            .as_ref()
                            .ok_or_else(|| invalid("profile anchor missing"))?;
                        let ac = anchor
                            .ac
                            .as_ref()
                            .ok_or_else(|| invalid("profile AC anchor missing"))?;
                        let entry = anchor
                            .entry
                            .as_ref()
                            .ok_or_else(|| invalid("profile entry anchor missing"))?;
                        let leaf = format!("ORBIT-LINK-{}", &nonce[..8]);
                        let source = held
                            .file
                            .as_ref()
                            .ok_or_else(|| invalid("held image reader missing"))?;
                        if !relative_probe_absent(ac.as_raw_handle(), &leaf, false)? {
                            return Err(invalid(
                                "hardlink control target leaf unexpectedly exists",
                            ));
                        }
                        let link_parent = relative_open(
                            entry.as_raw_handle(),
                            "AC",
                            true,
                            FILE_WRITE_DATA
                                | FILE_LIST_DIRECTORY
                                | FILE_TRAVERSE
                                | FILE_READ_ATTRIBUTES
                                | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        )?;
                        let parent_access =
                            query_directory_handle_access(link_parent.as_raw_handle());
                        let source_access = query_directory_handle_access(source.as_raw_handle());
                        let Some(granted_parent) = parent_access.granted_access else {
                            let close = close_checked(
                                link_parent,
                                "CloseHandle(hardlink target parent after access query failure)",
                            );
                            return match close {
                                Ok(()) => Err(invalid(
                                    "hardlink target parent granted-access query unavailable",
                                )),
                                Err(close) => Err(io::Error::other(format!(
                                    "hardlink target parent granted-access query unavailable; close failed: {close}"
                                ))),
                            };
                        };
                        if granted_parent & FILE_WRITE_DATA == 0 {
                            let close = close_checked(
                                link_parent,
                                "CloseHandle(hardlink target parent after access refusal)",
                            );
                            return match close {
                                Ok(()) => Err(invalid(
                                    "hardlink target parent handle lacks file-create access",
                                )),
                                Err(close) => Err(io::Error::other(format!(
                                    "hardlink target parent handle lacks file-create access; close failed: {close}"
                                ))),
                            };
                        }
                        let mut link_native_status = None;
                        let link_result = link_relative(
                            source.as_raw_handle(),
                            link_parent.as_raw_handle(),
                            &leaf,
                            &mut link_native_status,
                        );
                        let link_parent_close =
                            close_checked(link_parent, "CloseHandle(hardlink target parent)");
                        match (link_result, link_parent_close) {
                            (Ok(()), Ok(())) => {}
                            (Err(primary), Ok(())) => return Err(primary),
                            (Ok(()), Err(close)) => return Err(close),
                            (Err(primary), Err(close)) => {
                                return Err(io::Error::other(format!(
                                    "hardlink control failed: {primary}; parent close failed: {close}"
                                )));
                            }
                        }
                        verify_file_link_count(source.as_raw_handle(), 2)?;
                        control_secondary_name = Some(leaf.clone());
                        control_detail.state = "same_volume_hardlink_installed".to_owned();
                        control_detail.native_status = format!(
                            "NtSetInformationFile=STATUS_SUCCESS_source_access={}_parent_access={:#010x}",
                            source_access.granted_access.map_or_else(
                                || "unknown".to_owned(),
                                |value| format!("{value:#010x}")
                            ),
                            granted_parent
                        );
                        control_detail.object_name = leaf;
                        control_detail.object_id = identity_text(held.identity);
                        control_detail.expected_id = identity_text(held.identity);
                        control_detail.observed_id = identity_text(held.identity);
                        control_detail.content_sha256 = held.sha256.clone();
                        control_detail.descriptor_sha256 = digest(&held.expected_resource_dacl)?;
                    }
                    None => {}
                }
                if control.is_some() && control != Some(CleanupControl::JobQueryError) {
                    control_detail.setup_verified = true;
                }
                let inventory = fixture.verify_unchanged();
                let predelete =
                    inventory.and_then(|()| match (profile_anchor.as_ref(), image.as_mut()) {
                        (Some(anchor), Some(image)) => anchor.verify_predelete(image, &job_gate),
                        _ => Err(invalid(
                            "prelaunch profile anchor or held helper image missing",
                        )),
                    });
                if control == Some(CleanupControl::JobQueryError) {
                    let counts = job_gate.last_native_active_counts();
                    let native_zero = counts == [Some(0), Some(0)];
                    let injected_error_reached = predelete.as_ref().err().is_some_and(|error| {
                        error.to_string()
                            == control
                                .expect("query error control selected")
                                .target_error()
                    });
                    control_detail.state = if native_zero && injected_error_reached {
                        "both_native_job_queries_zero_then_shared_gate_error_injected"
                    } else if native_zero {
                        "native_queries_zero_but_shared_gate_injection_not_reached"
                    } else {
                        "job_query_control_did_not_reach_both_native_zero_results"
                    }
                    .to_owned();
                    control_detail.native_status = if native_zero {
                        "native_query_success"
                    } else {
                        "native_query_results_not_both_zero"
                    }
                    .to_owned();
                    control_detail.active_count = format!(
                        "{},{}",
                        counts[0]
                            .map_or_else(|| "unobserved".to_owned(), |count| count.to_string()),
                        counts[1]
                            .map_or_else(|| "unobserved".to_owned(), |count| count.to_string()),
                    );
                    control_detail.setup_verified = native_zero && injected_error_reached;
                    job_gate.clear_query_error_injection();
                }
                if let Some(expected) = control_expected_image_identity.take() {
                    if let Some(held) = image.as_mut() {
                        held.identity = expected;
                    }
                }
                if let Some(expected) = control_expected_directory_identity.take() {
                    if let Some(held) = image.as_mut() {
                        held.directory_identity = expected;
                    }
                }
                if let Some(expected) = control_expected_profile_identity.take() {
                    if let Some(anchor) = profile_anchor.as_mut() {
                        anchor.entry_identity = expected;
                    }
                }
                if let Some(expected) = control_expected_image_hash.take() {
                    if let Some(held) = image.as_mut() {
                        held.sha256 = expected;
                    }
                }
                if let Some(fence) = control_removed_job_fence.take() {
                    job_gate.cancel = Some(fence);
                }
                match predelete {
                    Err(error) => Err(error),
                    Ok(()) if control_namespace_share_refused => {
                        let target = "namespace rename refused with ERROR_SHARING_VIOLATION";
                        control_target_error = Some(target.to_owned());
                        Err(invalid(target))
                    }
                    Ok(()) if control == Some(CleanupControl::LiveNonzeroJob) => Err(invalid(
                        control.expect("live Job control selected").target_error(),
                    )),
                    Ok(()) if control.is_some() => Err(invalid(
                        "cleanup fault did not trigger its expected preflight refusal",
                    )),
                    Ok(()) => Ok(()),
                }
            })();
            let preflight_checked_close_failure = preflight.as_ref().err().is_some_and(|error| {
                error
                    .to_string()
                    .contains("profile baseline checked-close failure")
            });
            if preflight_checked_close_failure {
                control_check_errors.push(format!(
                    "profile baseline traversal close failure: {}",
                    preflight.as_ref().err().expect("close failure detected")
                ));
            }
            match preflight {
                Err(error)
                    if control.is_some()
                        && !preflight_checked_close_failure
                        && error
                            .to_string()
                            .contains(if control_namespace_share_refused {
                                control_target_error
                                    .as_deref()
                                    .unwrap_or_else(|| control.expect("control present").target_error())
                            } else {
                                control.expect("control present").target_error()
                            }) =>
                {
                    control_target_error = Some(error.to_string());
                    control_detail.target_reached = true;
                    if let (Some(fixture), Some(anchor), Some(image)) = (
                        fixture.as_ref(),
                        profile_anchor.as_ref(),
                        image.as_mut(),
                    ) {
                        match fixture.verify_known_preimages_unchanged() {
                            Ok(()) => control_known_preimages_verified = true,
                            Err(error) => control_check_errors.push(format!(
                                "known private view/value recheck: {error}"
                            )),
                        }
                        let root_result = fixture.verify_root_present();
                        let profile_image_result = (|| -> io::Result<()> {
                            match control.expect("control present") {
                            CleanupControl::ChangedImageDacl => verify_held_image_base(
                                image,
                                control_image_dacl_after
                                    .as_deref()
                                    .ok_or_else(|| invalid("changed DACL postimage missing"))?,
                            )
                            .and_then(|()| {
                                anchor.verify_profile_baseline_with_control_extras(image, &[])
                            }),
                            CleanupControl::UnknownHelperEntry => {
                                let facts = control_file_canary.as_ref().ok_or_else(|| {
                                    invalid("helper-entry canary facts missing")
                                })?;
                                let directory = image
                                    .directory_handle
                                    .as_ref()
                                    .ok_or_else(|| invalid("helper directory keeper missing"))?;
                                let mut children = profile_children(directory.as_raw_handle())?;
                                children.sort_by(|left, right| left.0.cmp(&right.0));
                                let mut expected_children = vec![
                                    (image.image_leaf.clone(), image.identity.1, false),
                                    (facts.leaf.clone(), facts.identity.1, false),
                                ];
                                expected_children.sort_by(|left, right| left.0.cmp(&right.0));
                                if children != expected_children {
                                    return Err(invalid(
                                        "helper-entry control inventory changed after refusal",
                                    ));
                                }
                                verify_control_file_canary(directory.as_raw_handle(), facts)?;
                                let profile_extra = vec![(
                                    format!("AC\\{}\\{}", image.directory_leaf, facts.leaf),
                                    facts.profile_fact.clone(),
                                )];
                                let expected_dacl = image.expected_resource_dacl.clone();
                                verify_held_image_base(image, &expected_dacl)
                                    .and_then(|()| {
                                        anchor.verify_profile_baseline_with_control_extras(
                                            image,
                                            &profile_extra,
                                        )
                                    })
                            }
                            CleanupControl::UnknownProfileEntry => {
                                let facts = control_file_canary.as_ref().ok_or_else(|| {
                                    invalid("profile-entry canary facts missing")
                                })?;
                                let ac = anchor
                                    .ac
                                    .as_ref()
                                    .ok_or_else(|| invalid("profile AC anchor missing"))?;
                                verify_control_file_canary(ac.as_raw_handle(), facts)?;
                                let profile_extra = vec![
                                    (format!("AC\\{}", facts.leaf), facts.profile_fact.clone()),
                                ];
                                image.verify_preflight(&job_gate).and_then(|()| {
                                    anchor.verify_profile_baseline_with_control_extras(
                                        image,
                                        &profile_extra,
                                    )
                                })
                            }
                            CleanupControl::ProfileEnumerationLimit => {
                                let entry = anchor
                                    .entry
                                    .as_ref()
                                    .ok_or_else(|| invalid("profile entry anchor missing"))?;
                                let ac = anchor
                                    .ac
                                    .as_ref()
                                    .ok_or_else(|| invalid("profile AC anchor missing"))?;
                                let limit_directory = profile_limit_directory
                                    .as_ref()
                                    .ok_or_else(|| invalid("limit directory owner missing"))?;
                                let expected_limit_directory_fact = profile_limit_directory_profile_fact
                                    .as_ref()
                                    .ok_or_else(|| invalid("limit directory post-setup fact missing"))?;
                                if profile_fact(limit_directory.as_raw_handle(), true)?
                                    != *expected_limit_directory_fact
                                {
                                    return Err(invalid("profile-limit directory post-setup metadata changed"));
                                }
                                let limit_name = control_detail.object_name.as_str();
                                let mut entry_children = profile_children(entry.as_raw_handle())?;
                                entry_children.sort_by(|left, right| left.0.cmp(&right.0));
                                if entry_children.len() != 1
                                    || entry_children[0].0 != "AC"
                                    || !entry_children[0].2
                                {
                                    return Err(invalid("profile entry contents changed around limit canary"));
                                }
                                let mut ac_children = profile_children(ac.as_raw_handle())?;
                                ac_children.sort_by(|left, right| left.0.cmp(&right.0));
                                let mut expected_ac_children = profile_baseline_direct_children(
                                    &anchor.baseline,
                                    "AC",
                                );
                                expected_ac_children.extend(vec![
                                    (
                                        image.directory_leaf.clone(),
                                        image.directory_identity.1,
                                        true,
                                    ),
                                    (
                                        limit_name.to_owned(),
                                        script_identity(limit_directory.as_raw_handle())?.1,
                                        true,
                                    ),
                                ]);
                                expected_ac_children
                                    .sort_by(|left, right| left.0.cmp(&right.0));
                                if ac_children != expected_ac_children {
                                    return Err(invalid("AC contents changed around limit canary"));
                                }
                                if profile_limit_files.len() != 513 {
                                    return Err(invalid("profile-limit control did not retain exactly 513 setup records"));
                                }
                                for facts in &profile_limit_files {
                                    verify_control_file_canary(
                                        limit_directory.as_raw_handle(),
                                        facts,
                                    )?;
                                }
                                anchor
                                    .verify_profile_bindings()
                                    .and_then(|()| image.verify_preflight(&job_gate))
                            }
                            CleanupControl::ImageLeafSwap if control_namespace_share_refused => {
                                let directory = image.directory_handle.as_ref().ok_or_else(|| invalid("held helper directory missing"))?;
                                let backup = control_secondary_name.as_ref().ok_or_else(|| invalid("image backup name missing"))?;
                                if !relative_probe_absent(directory.as_raw_handle(), backup, false)? {
                                    return Err(invalid("sharing-prevented image rename left an alternate name"));
                                }
                                let expected_dacl = image.expected_resource_dacl.clone();
                                verify_held_image_base(image, &expected_dacl)
                                    .and_then(|()| anchor.verify_predelete(image, &job_gate))
                            }
                            CleanupControl::ImageLeafSwap => {
                                let directory = image.directory_handle.as_ref().ok_or_else(|| invalid("held helper directory missing"))?;
                                let original = control_original_file_canary.as_ref().ok_or_else(|| invalid("renamed original image facts missing"))?;
                                let replacement = control_file_canary.as_ref().ok_or_else(|| invalid("replacement image facts missing"))?;
                                let backup = control_secondary_name.as_ref().ok_or_else(|| invalid("image backup name missing"))?;
                                let mut children = profile_children(directory.as_raw_handle())?;
                                children.sort_by(|left, right| left.0.cmp(&right.0));
                                let mut expected_children = vec![
                                    (backup.clone(), original.identity.1, false),
                                    (image.image_leaf.clone(), replacement.identity.1, false),
                                ];
                                expected_children.sort_by(|left, right| left.0.cmp(&right.0));
                                if children != expected_children {
                                    return Err(invalid("image-leaf swap postimage inventory differs"));
                                }
                                verify_control_file_canary(directory.as_raw_handle(), original)?;
                                verify_control_file_canary(directory.as_raw_handle(), replacement)?;
                                let directory_path = format!("AC\\{}", image.directory_leaf);
                                let directory_fact = profile_fact(directory.as_raw_handle(), true)?;
                                let expected_dacl = image.expected_resource_dacl.clone();
                                verify_held_image_base(image, &expected_dacl)?;
                                let entries = vec![
                                    (directory_path, directory_fact),
                                    (format!("AC\\{}\\{}", image.directory_leaf, backup), original.profile_fact.clone()),
                                    (format!("AC\\{}\\{}", image.directory_leaf, image.image_leaf), replacement.profile_fact.clone()),
                                ];
                                anchor.verify_profile_inventory_with_control_entries(&entries)
                            }
                            CleanupControl::DirectorySwap if control_namespace_share_refused => {
                                let ac = anchor.ac.as_ref().ok_or_else(|| invalid("profile AC anchor missing"))?;
                                let backup = control_secondary_name.as_ref().ok_or_else(|| invalid("directory backup name missing"))?;
                                if !relative_probe_absent(ac.as_raw_handle(), backup, true)? {
                                    return Err(invalid("sharing-prevented directory rename left an alternate name"));
                                }
                                let expected_dacl = image.expected_resource_dacl.clone();
                                verify_held_image_base(image, &expected_dacl)
                                    .and_then(|()| anchor.verify_predelete(image, &job_gate))
                            }
                            CleanupControl::DirectorySwap => {
                                let directory = image.directory_handle.as_ref().ok_or_else(|| invalid("held helper directory missing"))?;
                                let replacement = control_replacement_directory.as_ref().ok_or_else(|| invalid("replacement directory owner missing"))?;
                                let backup = control_secondary_name.as_ref().ok_or_else(|| invalid("directory backup name missing"))?;
                                if script_identity(directory.as_raw_handle())? != image.directory_identity
                                    || resource_dacl_bytes(directory.as_raw_handle())? != image.expected_directory_dacl
                                {
                                    return Err(invalid("renamed original directory identity or DACL changed"));
                                }
                                let original_file = image.file.as_ref().ok_or_else(|| invalid("held image reader missing"))?;
                                let original_facts = ControlFileFacts {
                                    leaf: image.image_leaf.clone(),
                                    identity: image.identity,
                                    length: image.expected_length,
                                    content_sha256: image.sha256.clone(),
                                    descriptor_sha256: digest(&resource_dacl_bytes(original_file.as_raw_handle())?)?,
                                    profile_fact: profile_fact(original_file.as_raw_handle(), false)?,
                                };
                                verify_control_file_canary(directory.as_raw_handle(), &original_facts)?;
                                if !profile_children(replacement.as_raw_handle())?.is_empty()
                                    || resource_dacl_bytes(replacement.as_raw_handle())? != image.expected_directory_dacl
                                {
                                    return Err(invalid("replacement helper directory contents or DACL changed"));
                                }
                                let ac = anchor.ac.as_ref().ok_or_else(|| invalid("profile AC anchor missing"))?;
                                let mut ac_children = profile_children(ac.as_raw_handle())?;
                                ac_children.sort_by(|left, right| left.0.cmp(&right.0));
                                let mut expected_ac_children = profile_baseline_direct_children(
                                    &anchor.baseline,
                                    "AC",
                                );
                                expected_ac_children.extend(vec![
                                    (backup.clone(), image.directory_identity.1, true),
                                    (image.directory_leaf.clone(), script_identity(replacement.as_raw_handle())?.1, true),
                                ]);
                                expected_ac_children.sort_by(|left, right| left.0.cmp(&right.0));
                                if ac_children != expected_ac_children {
                                    return Err(invalid("directory-swap postimage inventory differs"));
                                }
                                let entries = vec![
                                    (format!("AC\\{}", backup), profile_fact(directory.as_raw_handle(), true)?),
                                    (format!("AC\\{}\\{}", backup, image.image_leaf), original_facts.profile_fact),
                                    (format!("AC\\{}", image.directory_leaf), profile_fact(replacement.as_raw_handle(), true)?),
                                ];
                                anchor.verify_profile_inventory_with_control_entries(&entries)
                            }
                            CleanupControl::ImageHardlink => {
                                let directory = image.directory_handle.as_ref().ok_or_else(|| invalid("held helper directory missing"))?;
                                let link_name = control_secondary_name.as_ref().ok_or_else(|| invalid("hardlink name missing"))?;
                                let ac = anchor.ac.as_ref().ok_or_else(|| invalid("profile AC anchor missing"))?;
                                let mut children = profile_children(directory.as_raw_handle())?;
                                children.sort_by(|left, right| left.0.cmp(&right.0));
                                if children != vec![(image.image_leaf.clone(), image.identity.1, false)] {
                                    return Err(invalid("hardlink changed the helper directory inventory"));
                                }
                                let image_reader = image.file.as_ref().ok_or_else(|| invalid("held image reader missing"))?;
                                verify_file_link_count(image_reader.as_raw_handle(), 2)?;
                                verify_image_content_without_singlelink(image)?;
                                let ac_children = profile_children(ac.as_raw_handle())?;
                                if !ac_children.iter().any(|(name, id, directory)| name == link_name && id == &image.identity.1 && !directory) {
                                    return Err(invalid("hardlink AC directory entry ID differs from the original image"));
                                }
                                verify_held_directory_identity(image).and_then(|()| {
                                    anchor.verify_profile_baseline_with_control_hardlink(image, link_name)
                                })
                            }
                            _ => anchor.verify_predelete(image, &job_gate),
                            }
                        })();
                        control_preflight_verified =
                            root_result.is_ok() && profile_image_result.is_ok();
                        if let Err(error) = root_result {
                            control_check_errors.push(format!(
                                "nonce-root retained-object recheck: {error}"
                            ));
                        }
                        if let Err(error) = profile_image_result {
                            control_check_errors.push(format!(
                                "profile/image retained-preflight recheck: {error}"
                            ));
                        }
                        match (
                            control_view_preimages_before.as_ref(),
                            fixture.view_preimages(),
                        ) {
                            (Some(before), Ok(after)) if &after == before => {
                                control_view_preimages_unchanged = true;
                            }
                            (Some(_), Ok(_)) => control_check_errors.push(
                                "MachineView/UserView value or security preimage changed".to_owned(),
                            ),
                            (None, Ok(_)) => control_check_errors.push(
                                "MachineView/UserView pre-control snapshot missing".to_owned(),
                            ),
                            (_, Err(error)) => control_check_errors.push(format!(
                                "MachineView/UserView post-rejection snapshot: {error}"
                            )),
                        }
                        if matches!(
                            control,
                            Some(CleanupControl::UnknownRegistryKey)
                                | Some(CleanupControl::UnknownRegistryValue)
                        ) {
                            let canary_observation = if control
                                == Some(CleanupControl::UnknownRegistryValue)
                            {
                                fixture.unknown_value_canary_facts()
                            } else {
                                fixture.unknown_key_canary_facts()
                            };
                            match (
                                control_private_canary.as_ref(),
                                canary_observation,
                            ) {
                                (Some(before), Ok(after)) if &after == before => {
                                    control_private_canary_unchanged = true;
                                }
                                (Some(_), Ok(_)) => control_check_errors.push(
                                    "foreign private key value or descriptor changed".to_owned(),
                                ),
                                (None, Ok(_)) => control_check_errors.push(
                                    "foreign private key baseline missing".to_owned(),
                                ),
                                (_, Err(error)) => control_check_errors.push(format!(
                                    "foreign private key post-rejection observation: {error}"
                                )),
                            }
                        }
                    } else {
                        control_check_errors.push(
                            "retained fixture/profile/image owner missing after target rejection"
                                .to_owned(),
                        );
                    }
                }
                Err(error) => cleanup_errors.push(format!(
                    "cleanup preflight failed; all residue retained: {error}"
                )),
                Ok(()) if control.is_some() => cleanup_errors.push(format!(
                    "cleanup control {} failed to reach its intended preflight rejection; residue retained",
                    control.expect("control present").name()
                )),
                Ok(()) => {
                    if let Some(fixture) = fixture.as_mut() {
                        match fixture.cleanup(&job_gate) {
                            Ok(registry) => receipt.registry = Some(registry),
                            Err(error) => cleanup_errors.push(format!(
                                "private fixture cleanup/residue: {error}; completed_steps=[{}]",
                                fixture.completed_steps.join(",")
                            )),
                        }
                    } else {
                        cleanup_errors
                            .push("private fixture owner missing; cleanup stopped".to_owned());
                    }
                    if cleanup_errors.is_empty() {
                        if let Some(image) = image.take() {
                            let image_receipt = image.cleanup(
                                session.as_ref().expect("profile owner retained"),
                                &job_gate,
                            );
                            cleanup_errors.extend(image_receipt.errors.iter().cloned());
                            receipt.image = Some(image_receipt);
                        } else {
                            cleanup_errors.push(
                                "held helper image owner missing; cleanup stopped".to_owned(),
                            );
                        }
                    }
                    if cleanup_errors.is_empty() {
                        match (session.take(), profile_anchor.take()) {
                            (Some(session), Some(anchor)) => {
                                if let Err(error) = finish_registry_profile(
                                    session,
                                    anchor,
                                    &job_gate,
                                    &mut receipt,
                                ) {
                                    cleanup_errors
                                        .push(format!("profile cleanup/residue: {error}"));
                                }
                            }
                            _ => cleanup_errors.push("profile cleanup anchors missing".to_owned()),
                        }
                    }
                }
            }
        }
        if let Some(fixture) = fixture.as_mut() {
            if let Some(root) = fixture.root.take() {
                if let Err(error) = root.close() {
                    cleanup_errors.push(format!(
                        "retained private fixture root close failed: {error}"
                    ));
                }
            }
            if let Some(software) = fixture.software.take() {
                if let Err(error) = software.close() {
                    cleanup_errors.push(format!(
                        "retained Software registry anchor close failed: {error}"
                    ));
                }
            }
        }
        if let Some(image) = image.as_mut() {
            if let Some(reader) = image.file.take() {
                if let Err(error) =
                    close_file_checked(reader, "CloseHandle(retained helper image reader)")
                {
                    cleanup_errors.push(format!(
                        "retained helper image reader close failed: {error}"
                    ));
                }
            }
            if let Some(anchor) = image.metadata_anchor.take() {
                if let Err(error) =
                    close_checked(anchor, "CloseHandle(retained helper image bridge)")
                {
                    cleanup_errors.push(format!(
                        "retained helper image bridge close failed: {error}"
                    ));
                }
            }
            if let Some(control_dacl) = image.control_dacl_handle.take() {
                if let Err(error) = close_checked(
                    control_dacl,
                    "CloseHandle(retained helper image DACL control)",
                ) {
                    cleanup_errors.push(format!(
                        "retained helper image DACL control close failed: {error}"
                    ));
                }
            }
            if let Some(directory) = image.directory_handle.take() {
                if let Err(error) =
                    close_checked(directory, "CloseHandle(retained helper directory keeper)")
                {
                    cleanup_errors.push(format!(
                        "retained helper directory keeper close failed: {error}"
                    ));
                }
            }
        }
        if let Some(replacement) = control_replacement_directory.take() {
            if let Err(error) = close_checked(
                replacement,
                "CloseHandle(retained replacement helper directory)",
            ) {
                cleanup_errors.push(format!(
                    "retained replacement helper directory close failed: {error}"
                ));
            }
        }
        if let Some(limit_directory) = profile_limit_directory.take() {
            if let Err(error) = close_checked(
                limit_directory,
                "CloseHandle(retained profile-limit directory)",
            ) {
                cleanup_errors.push(format!(
                    "retained profile-limit directory close failed: {error}"
                ));
            }
        }
        if let Some(anchor) = profile_anchor.as_mut() {
            if let Err(error) = anchor.close_internal() {
                cleanup_errors.push(format!(
                    "retained profile entry/AC anchor close failed: {error}"
                ));
            }
            if let Some(packages) = anchor.packages.take() {
                if let Err(error) = close_checked(
                    packages,
                    "CloseHandle(retained Packages observation anchor)",
                ) {
                    cleanup_errors.push(format!("retained Packages anchor close failed: {error}"));
                }
            }
        }
        if let Some(session) = session.as_mut() {
            if let Some(root) = session.root.take() {
                if let Err(error) = close_checked(root, "CloseHandle(retained profile root anchor)")
                {
                    cleanup_errors.push(format!("retained profile root close failed: {error}"));
                }
            }
        }

        let host_marker_result = parent_marker_controls("after");
        if let Err(error) = &host_marker_result {
            cleanup_errors.push(format!("host marker post-control failed: {error}"));
        }
        if let Err(error) = job_gate.require_zero("final cleanup receipt gate") {
            cleanup_errors.push(format!("final exact Job-zero check failed: {error}"));
        }
        if let Some(control) = control {
            let parent_after = parent_marker_canary_facts();
            let parent_canary_unchanged = match (&control_canary_before, &parent_after) {
                (Some(before), Ok(after)) if before == after => true,
                (Some(_), Ok(_)) => {
                    control_check_errors
                        .push("parent marker canary value or descriptor changed".to_owned());
                    false
                }
                (Some(_), Err(error)) => {
                    control_check_errors
                        .push(format!("parent marker canary post-observation: {error}"));
                    false
                }
                (None, _) => {
                    control_check_errors.push("parent marker canary baseline missing".to_owned());
                    false
                }
            };
            let control_job_fences_present = job_gate
                .normal
                .as_ref()
                .is_some_and(|fence| fence.process_waited)
                && job_gate
                    .cancel
                    .as_ref()
                    .is_some_and(|fence| fence.process_waited);
            cleanup_errors.extend(job_gate.close_fences());
            let fixture_id = match fixture.as_ref() {
                Some(fixture) => match digest(fixture.name.as_bytes()) {
                    Ok(identity) => Some(identity),
                    Err(error) => {
                        control_check_errors
                            .push(format!("private fixture identity digest: {error}"));
                        None
                    }
                },
                None => {
                    control_check_errors
                        .push("private fixture owner missing for receipt".to_owned());
                    None
                }
            };
            if image.is_none() {
                control_check_errors.push("held image owner missing for receipt".to_owned());
            }
            let expected_control = primary_error.is_none()
                && control_target_error.is_some()
                && control_preflight_verified
                && control_known_preimages_verified
                && control_view_preimages_unchanged
                && (!matches!(
                    control,
                    CleanupControl::UnknownRegistryKey | CleanupControl::UnknownRegistryValue
                ) || control_private_canary_unchanged)
                && control_job_fences_present
                && host_marker_result.is_ok()
                && parent_canary_unchanged
                && fixture_id.is_some()
                && image.is_some()
                && fixture
                    .as_ref()
                    .is_some_and(|fixture| fixture.completed_steps.is_empty())
                && receipt.profile_sdk_result.is_none()
                && control_check_errors.is_empty()
                && cleanup_errors.is_empty();
            if expected_control {
                control_detail.final_verified = true;
                let image = image.as_ref().expect("validated held image retained");
                let private_value = control_private_canary.as_ref().map_or_else(
                    || "not_applicable".to_owned(),
                    |facts| facts.value_sha256.clone(),
                );
                let private_descriptor = control_private_canary.as_ref().map_or_else(
                    || "not_applicable".to_owned(),
                    |facts| facts.descriptor_sha256.clone(),
                );
                let parent = parent_after.expect("validated parent canary observation");
                let control_record = format!(
                    "registry_witness_control case={} nonce={} parent_pid={} parent_creation={} reached=true rejection={} jobs_zero=true known_views_unchanged=true view_preimages_unchanged=true private_canary_value_sha256={} private_canary_descriptor_sha256={} private_canary_unchanged={} parent_machine_value_sha256={} parent_user_value_sha256={} parent_machine_descriptor_sha256={} parent_user_descriptor_sha256={} parent_canary_unchanged=true registry_root_retained=true image_profile_retained=true image_id={} image_sha256={} fixture_id={} disposition_attempted=false sdk_called=false",
                    control.name(),
                    nonce,
                    parent_pid,
                    parent_creation,
                    if control_namespace_share_refused {
                        "namespace_rename_share_violation"
                    } else {
                        control.rejection()
                    },
                    private_value,
                    private_descriptor,
                    control_private_canary_unchanged,
                    parent.machine_value_sha256,
                    parent.user_value_sha256,
                    parent.machine_descriptor_sha256,
                    parent.user_descriptor_sha256,
                    identity_text(image.identity),
                    image.sha256,
                    fixture_id.expect("validated fixture digest")
                );
                let finalization = format!(
                    "registry_witness_finalization status=retained control={} profile_absent=false sdk_called=false registry_fixture_retained=true image_retained=true helper_directory_retained=true normal_job_zero=true cancel_job_zero=true cleanup_errors=0",
                    control.name()
                );
                let detail_record = format!(
                    "registry_witness_control_detail case={} setup_verified={} target_reached={} final_verified={} state={} native_status={} active_count={} object_name={} object_id={} content_sha256={} descriptor_sha256={} expected_id={} observed_id={} inventory_count={} inventory_sha256={}",
                    control.name(),
                    control_detail.setup_verified,
                    control_detail.target_reached,
                    control_detail.final_verified,
                    control_detail.state,
                    control_detail.native_status,
                    control_detail.active_count,
                    control_detail.object_name,
                    control_detail.object_id,
                    control_detail.content_sha256,
                    control_detail.descriptor_sha256,
                    control_detail.expected_id,
                    control_detail.observed_id,
                    control_detail.inventory_count,
                    control_detail.inventory_sha256
                );
                let mut emission_errors = Vec::new();
                if let Err(error) = emit_witness_record(&control_record) {
                    emission_errors.push(format!("cleanup control receipt emission: {error}"));
                }
                if let Err(error) = emit_witness_record(&detail_record) {
                    emission_errors.push(format!("cleanup control detail emission: {error}"));
                }
                if let Err(error) = emit_witness_record(&finalization) {
                    emission_errors.push(format!("cleanup control finalization emission: {error}"));
                }
                if let Err(error) = emit_witness_record(
                    "registry_witness_status witness_status=INCOMPLETE run_status=control_retained",
                ) {
                    emission_errors.push(format!("cleanup control status emission: {error}"));
                }
                if emission_errors.is_empty() {
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "cleanup control {} evidence emission failed: {}",
                    control.name(),
                    emission_errors.join("; ")
                )));
            }
            let mut failure_details = Vec::new();
            if let Some(primary) = primary_error.as_deref() {
                failure_details.push(format!("real stage prerequisite: {primary}"));
            }
            if let Some(target) = control_target_error.as_deref() {
                failure_details.push(format!("intended preflight rejection observed: {target}"));
            }
            failure_details.extend(control_check_errors.iter().cloned());
            failure_details.extend(cleanup_errors.iter().cloned());
            if failure_details.is_empty() {
                failure_details.push(format!(
                    "cleanup control {} did not prove target rejection and retained residue",
                    control.name()
                ));
            }
            let failure = format!(
                "registry_witness_status witness_status=INCOMPLETE run_status=control_failed primary={}",
                escape_diagnostic(failure_details.join("; ").as_bytes())
            );
            let emission_result = emit_witness_record(&failure);
            if let Err(error) = emission_result {
                failure_details.push(format!("cleanup control failure emission: {error}"));
            }
            return Err(io::Error::other(format!(
                "cleanup control {} failed: {}",
                control.name(),
                failure_details.join("; ")
            )));
        }
        match (
            receipt.profile_packages.as_ref(),
            receipt.profile_packages_identity,
            receipt.profile_entry_leaf.as_deref(),
        ) {
            (Some(packages), Some(expected), Some(leaf)) => {
                match script_identity(packages.as_raw_handle()) {
                    Ok(identity) if identity == expected => {
                        match relative_probe_absent(packages.as_raw_handle(), leaf, true) {
                            Ok(true) => {
                                receipt.profile_absent = true;
                                receipt.profile_final_verified = true;
                            }
                            Ok(false) => {
                                cleanup_errors
                                    .push("final profile entry probe was inconclusive".to_owned());
                                receipt.profile_final_verified = false;
                            }
                            Err(error) => {
                                cleanup_errors.push(format!(
                                    "final AppContainer entry absence check failed: {error}"
                                ));
                                receipt.profile_final_verified = false;
                            }
                        }
                    }
                    Ok(_) => {
                        cleanup_errors
                            .push("Packages parent identity changed at final gate".to_owned());
                        receipt.profile_final_verified = false;
                    }
                    Err(error) => {
                        cleanup_errors
                            .push(format!("Packages parent identity check failed: {error}"));
                        receipt.profile_final_verified = false;
                    }
                }
            }
            _ => {
                cleanup_errors
                    .push("external Packages observation anchor missing at final gate".to_owned());
                receipt.profile_final_verified = false;
            }
        }
        if let Some(registry) = receipt.registry.as_mut() {
            match registry.verify() {
                Ok(()) => registry.absence_proven = true,
                Err(error) => {
                    cleanup_errors.push(format!("final registry absence check failed: {error}"))
                }
            }
        }
        if let Some(packages) = receipt.profile_packages.take() {
            match close_checked(packages, "CloseHandle(Packages final observation parent)") {
                Ok(()) => receipt.profile_packages_close_succeeded = true,
                Err(error) => cleanup_errors.push(format!("Packages parent close failed: {error}")),
            }
        }
        if let Some(registry) = receipt.registry.as_mut() {
            if let Some(software) = registry.software.take() {
                match software.close() {
                    Ok(()) => registry.anchor_closed = true,
                    Err(error) => cleanup_errors
                        .push(format!("Software registry parent close failed: {error}")),
                }
            }
        }
        cleanup_errors.extend(job_gate.close_fences());
        receipt.errors.clone_from(&cleanup_errors);
        let complete = primary_error.is_none()
            && cleanup_errors.is_empty()
            && host_marker_result.is_ok()
            && receipt
                .registry
                .as_ref()
                .is_some_and(|registry| registry.verify().is_ok())
            && receipt.image.as_ref().is_some_and(|image| {
                image.image_disposition_succeeded
                    && image.image_close_succeeded
                    && image.image_absent
                    && image.directory_disposition_succeeded
                    && image.directory_close_succeeded
                    && image.directory_absent
                    && image.errors.is_empty()
            })
            && receipt.profile_sdk_result == Some(0)
            && receipt.profile_absent
            && receipt.profile_final_verified
            && receipt.profile_packages_close_succeeded
            && receipt.normal_job_zero
            && receipt.cancel_job_zero;
        if complete {
            let finalization = emit_witness_record(
                "registry_witness_finalization cleanup_errors=0 registry_absent=true image_absent=true directory_absent=true profile_absent=true normal_job_zero=true cancel_job_zero=true host_marker_postcontrol=observed",
            );
            if let Err(error) = finalization {
                return Err(io::Error::other(format!(
                    "cleanup completed but finalization evidence emission failed: {error}"
                )));
            }
            let cleanup_probe = emit_witness_record(
                "registry_witness_probe id=lifetime/cleanup_absent observed=true normal_job_zero=true cancel_job_zero=true registry_absent=true image_absent=true directory_absent=true profile_absent=true",
            );
            if let Err(error) = cleanup_probe {
                return Err(io::Error::other(format!(
                    "cleanup completed but absence probe emission failed: {error}"
                )));
            }
            if let Err(error) = emit_witness_record(
                "registry_witness_status witness_status=COMPLETE run_status=completed",
            ) {
                return Err(io::Error::other(format!(
                    "cleanup completed but COMPLETE status emission failed: {error}"
                )));
            }
            return Ok(());
        }
        if cleanup_errors.is_empty() {
            cleanup_errors.push("complete cleanup receipt could not be established".to_owned());
        }
        let reported_primary = primary_error
            .clone()
            .unwrap_or_else(|| cleanup_errors[0].clone());
        if let Some(fixture) = fixture.as_ref() {
            if !fixture.completed_steps.is_empty() {
                let partial = format!(
                    "registry_witness_finalization object=private_registry completed_steps={}",
                    fixture.completed_steps.join(",")
                );
                if let Err(error) = emit_witness_record(&partial) {
                    cleanup_errors
                        .push(format!("partial registry receipt emission failed: {error}"));
                }
            }
        }
        {
            let sdk_result = receipt.profile_sdk_result.map_or_else(
                || "not_called".to_owned(),
                |result| format!("0x{:08x}", result as u32),
            );
            let registry_absent = receipt
                .registry
                .as_ref()
                .is_some_and(|registry| registry.absence_proven);
            let software_closed = receipt
                .registry
                .as_ref()
                .is_some_and(|registry| registry.anchor_closed);
            let packages_id = receipt
                .profile_packages_identity
                .map_or_else(|| "unavailable".to_owned(), identity_text);
            let entry_leaf = receipt.profile_entry_leaf.as_deref().map_or_else(
                || "unavailable".to_owned(),
                |leaf| escape_diagnostic(leaf.as_bytes()),
            );
            let partial = format!(
                "registry_witness_finalization object=profile sdk_result={sdk_result} profile_absent={} final_verified={} packages_closed={} packages_id={} entry_leaf={} registry_absent={} software_closed={}",
                receipt.profile_absent,
                receipt.profile_final_verified,
                receipt.profile_packages_close_succeeded,
                packages_id,
                entry_leaf,
                registry_absent,
                software_closed
            );
            if let Err(error) = emit_witness_record(&partial) {
                cleanup_errors.push(format!("partial profile receipt emission failed: {error}"));
            }
        }
        if let Some(image) = receipt.image.as_ref() {
            let partial = format!(
                "registry_witness_finalization object=helper_image image_disposition={} image_closed={} image_absent={} directory_disposition={} directory_closed={} directory_absent={} errors={}",
                image.image_disposition_succeeded,
                image.image_close_succeeded,
                image.image_absent,
                image.directory_disposition_succeeded,
                image.directory_close_succeeded,
                image.directory_absent,
                escape_diagnostic(image.errors.join("; ").as_bytes())
            );
            if let Err(error) = emit_witness_record(&partial) {
                cleanup_errors.push(format!("partial image receipt emission failed: {error}"));
            }
        }
        if let Err(error) = emit_witness_record(&format!(
            "registry_witness_status witness_status=INCOMPLETE run_status=FAILED primary={}",
            escape_diagnostic(reported_primary.as_bytes())
        )) {
            cleanup_errors.push(format!("failure status emission failed: {error}"));
        }
        let errors_to_report = cleanup_errors.clone();
        for error in &errors_to_report {
            if let Err(emission_error) = emit_witness_record(&format!(
                "registry_witness_finalization status=FAILED detail={}",
                escape_diagnostic(error.as_bytes())
            )) {
                cleanup_errors.push(format!("failure detail emission failed: {emission_error}"));
            }
        }
        Err(io::Error::other(format!(
            "registry witness failed: {}; finalization: {}",
            primary_error.unwrap_or_else(|| "cleanup receipt incomplete".to_owned()),
            cleanup_errors.join("; ")
        )))
    }

    #[test]
    fn registry_witness_stage_a() -> io::Result<()> {
        registry_witness_stage_a_run(None)
    }

    #[test]
    fn registry_witness_cleanup_control_wrong_image_hash() -> io::Result<()> {
        registry_witness_stage_a_run(Some(CleanupControl::WrongImageHash))
    }

    #[test]
    fn registry_witness_cleanup_control_unknown_registry_key() -> io::Result<()> {
        registry_witness_stage_a_run(Some(CleanupControl::UnknownRegistryKey))
    }

    macro_rules! registry_witness_cleanup_control_tests {
        ($($test_name:ident => $control:ident),+ $(,)?) => {
            $(
                #[test]
                fn $test_name() -> io::Result<()> {
                    registry_witness_stage_a_run(Some(CleanupControl::$control))
                }
            )+
        };
    }

    registry_witness_cleanup_control_tests! {
        registry_witness_cleanup_control_wrong_image_id => WrongImageId,
        registry_witness_cleanup_control_wrong_directory_id => WrongDirectoryId,
        registry_witness_cleanup_control_wrong_profile_id => WrongProfileId,
        registry_witness_cleanup_control_changed_image_dacl => ChangedImageDacl,
        registry_witness_cleanup_control_unknown_registry_value => UnknownRegistryValue,
        registry_witness_cleanup_control_unknown_helper_entry => UnknownHelperEntry,
        registry_witness_cleanup_control_unknown_profile_entry => UnknownProfileEntry,
        registry_witness_cleanup_control_profile_enumeration_limit => ProfileEnumerationLimit,
        registry_witness_cleanup_control_image_leaf_swap => ImageLeafSwap,
        registry_witness_cleanup_control_directory_swap => DirectorySwap,
        registry_witness_cleanup_control_image_hardlink => ImageHardlink,
        registry_witness_cleanup_control_missing_job_fence => MissingJobFence,
        registry_witness_cleanup_control_live_nonzero_job => LiveNonzeroJob,
        registry_witness_cleanup_control_job_query_error => JobQueryError,
    }

    fn cancellation_child_readiness(
        nonce: &str,
        parent_pid: u32,
        parent_creation: &str,
        image_id: &str,
        image_hash: &str,
        fixture_digest: &str,
        fixture_id: &str,
        machine: &OwnedRegKey,
        user: &OwnedRegKey,
    ) -> io::Result<()> {
        let machine_descriptor = digest(&registry_key_security(machine.raw())?)?;
        let user_descriptor = digest(&registry_key_security(user.raw())?)?;
        let inherited_machine_label = private_view_label_digest(machine.raw())?;
        let inherited_user_label = private_view_label_digest(user.raw())?;
        if !private_view_label(machine.raw())? || !private_view_label(user.raw())? {
            return Err(invalid(
                "cancellation helper did not read both inherited labels",
            ));
        }
        let map_machine = unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, machine.raw()) };
        let map_user = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, user.raw()) };
        if map_machine != ERROR_SUCCESS || map_user != ERROR_SUCCESS {
            let _ = reset_predefined_roots();
            return Err(io::Error::other(format!(
                "cancellation private mapping failed: machine={map_machine} user={map_user}"
            )));
        }
        let mapped_machine = private_view_label(HKEY_LOCAL_MACHINE)?;
        let mapped_user = private_view_label(HKEY_CURRENT_USER)?;
        let mapped_machine_label = private_view_label_digest(HKEY_LOCAL_MACHINE)?;
        let mapped_user_label = private_view_label_digest(HKEY_CURRENT_USER)?;
        if !mapped_machine
            || !mapped_user
            || mapped_machine_label != inherited_machine_label
            || mapped_user_label != inherited_user_label
        {
            return Err(invalid(
                "cancellation mapped labels did not match inherited views",
            ));
        }
        let child_pid = unsafe { GetCurrentProcessId() };
        let child_creation = process_creation_text(unsafe { GetCurrentProcess() })?;
        emit_witness_record(&format!(
            "registry_witness_probe id=lifetime/cancel_ready_mapped nonce={nonce} role=cancel pid={child_pid} creation={child_creation} parent_pid={parent_pid} parent_creation={parent_creation} image_id={image_id} image_sha256={image_hash} fixture_id={fixture_id} fixture_digest={fixture_digest} machine_descriptor_sha256={machine_descriptor} user_descriptor_sha256={user_descriptor} inherited_machine_label_sha256={inherited_machine_label} inherited_user_label_sha256={inherited_user_label} mapped_machine_label_sha256={mapped_machine_label} mapped_user_label_sha256={mapped_user_label} appcontainer=true lpac=true capability_count=1 network_capabilities=0 thread_token=false job=true inherited_reads=2 mapped_machine=true mapped_user=true maps_live=2"
        ))?;
        loop {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn registry_witness_fixed_child_helper() {
        let role = std::env::var("ORBIT_REGISTRY_WITNESS_ROLE")
            .expect("fixed helper test selector must receive a bounded launch role");
        let nonce =
            std::env::var("ORBIT_REGISTRY_WITNESS_NONCE").expect("fixed witness nonce missing");
        let package_sid =
            std::env::var("ORBIT_REGISTRY_WITNESS_PACKAGE_SID").expect("fixed package SID missing");
        let user_sid =
            std::env::var("ORBIT_REGISTRY_WITNESS_USER_SID").expect("original user SID missing");
        assert!(matches!(role.as_str(), "normal" | "cancel"));
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(
            user_sid.starts_with("S-1-5-")
                && user_sid
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
        child_admission(&package_sid, &role, &nonce)
            .expect("actual helper token and Job admission failed");
        let (image_id, image_hash) =
            current_image_observation().expect("held helper image observation failed");
        assert_eq!(
            image_id,
            std::env::var("ORBIT_REGISTRY_WITNESS_IMAGE_ID").expect("held image ID missing")
        );
        assert_eq!(
            image_hash,
            std::env::var("ORBIT_REGISTRY_WITNESS_IMAGE_SHA256")
                .expect("held image digest missing")
        );
        let parent_pid = std::env::var("ORBIT_REGISTRY_WITNESS_PARENT_PID")
            .expect("parent process ID binding missing");
        let parent_pid = parent_pid
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid != 0)
            .expect("invalid parent process ID binding");
        let parent_creation = std::env::var("ORBIT_REGISTRY_WITNESS_PARENT_CREATION")
            .expect("parent creation-time binding missing");
        assert_eq!(parent_creation.len(), 16);
        assert!(parent_creation.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let fixture_digest = std::env::var("ORBIT_REGISTRY_WITNESS_FIXTURE_DIGEST")
            .expect("private fixture digest binding missing");
        assert_eq!(
            fixture_digest,
            digest(b"ORBIT-PRIVATE-METADATA-V1").expect("fixture digest")
        );
        let fixture_id = std::env::var("ORBIT_REGISTRY_WITNESS_FIXTURE_ID")
            .expect("private fixture identity binding missing");
        assert_eq!(fixture_id.len(), 64);
        assert!(fixture_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let machine = std::env::var("ORBIT_REGISTRY_WITNESS_MACHINE_HANDLE")
            .expect("machine read handle missing")
            .parse::<usize>()
            .expect("invalid machine handle encoding") as HKEY;
        let user = std::env::var("ORBIT_REGISTRY_WITNESS_USER_HANDLE")
            .expect("user read handle missing")
            .parse::<usize>()
            .expect("invalid user handle encoding") as HKEY;
        assert!(!machine.is_null() && !user.is_null() && machine != user);
        // SAFETY: these two inherited private-key handles were transferred
        // exclusively to this child and are closed with RegCloseKey.
        let machine = unsafe { OwnedRegKey::from_raw(machine) }.expect("invalid machine key");
        // SAFETY: same transfer contract as the machine handle above.
        let user = unsafe { OwnedRegKey::from_raw(user) }.expect("invalid user key");
        if role == "cancel" {
            return cancellation_child_readiness(
                &nonce,
                parent_pid,
                &parent_creation,
                &image_id,
                &image_hash,
                &fixture_digest,
                &fixture_id,
                &machine,
                &user,
            )
            .expect("cancellation child readiness failed");
        }
        let machine_path = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        let user_path = format!("{user_sid}\\Environment");
        let machine_nt =
            "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        let user_nt = format!("\\Registry\\User\\{user_sid}\\Environment");
        expect_denial(
            "baseline/host_denied/win32/machine",
            "lstatus",
            win32_open_status(HKEY_LOCAL_MACHINE, machine_path, KEY_QUERY_VALUE) as i32,
            ERROR_ACCESS_DENIED as i32,
        );
        expect_denial(
            "baseline/host_denied/win32/user",
            "lstatus",
            win32_open_status(HKEY_USERS, &user_path, KEY_QUERY_VALUE) as i32,
            ERROR_ACCESS_DENIED as i32,
        );
        expect_denial(
            "baseline/host_denied/nt/machine",
            "ntstatus",
            nt_open_status(machine_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        expect_denial(
            "baseline/host_denied/nt/user",
            "ntstatus",
            nt_open_status(&user_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        let inherited_machine = private_view_label(machine.raw()).expect("machine label read");
        let inherited_user = private_view_label(user.raw()).expect("user label read");
        record_read("inherited/public_read/machine_view", inherited_machine);
        record_read("inherited/public_read/user_view", inherited_user);

        let map_machine = unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, machine.raw()) };
        let map_user = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, user.raw()) };
        if map_machine != ERROR_SUCCESS || map_user != ERROR_SUCCESS {
            let _ = reset_predefined_roots();
            panic!("private registry mapping failed: machine={map_machine}, user={map_user}");
        }
        let mapped_machine = private_view_label(HKEY_LOCAL_MACHINE).expect("mapped machine read");
        let mapped_user = private_view_label(HKEY_CURRENT_USER).expect("mapped user read");
        record_read("mapped/public_read/machine_view", mapped_machine);
        record_read("mapped/public_read/user_view", mapped_user);
        expect_denial(
            "mapped/host_denied/nt/machine",
            "ntstatus",
            nt_open_status(machine_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        expect_denial(
            "mapped/host_denied/nt/user",
            "ntstatus",
            nt_open_status(&user_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        expect_denial(
            "mapped/host_denied/win32/user",
            "lstatus",
            win32_open_status(HKEY_USERS, &user_path, KEY_QUERY_VALUE) as i32,
            ERROR_ACCESS_DENIED as i32,
        );
        let machine_absence = win32_open_status(HKEY_LOCAL_MACHINE, "Environment", KEY_QUERY_VALUE);
        emit_witness_record(&format!("registry_witness_probe id=mapped/private_absent/machine_view domain=lstatus status={machine_absence}"))
            .expect("bounded private-absence record");
        assert_eq!(machine_absence, ERROR_FILE_NOT_FOUND);
        let user_absence = win32_open_status(HKEY_CURRENT_USER, "Environment", KEY_QUERY_VALUE);
        emit_witness_record(&format!("registry_witness_probe id=mapped/private_absent/user_view domain=lstatus status={user_absence}"))
            .expect("bounded private-absence record");
        assert_eq!(user_absence, ERROR_FILE_NOT_FOUND);

        if role == "normal" {
            normal_mutation_controls(machine.raw(), user.raw())
                .expect("private registry mutation or duplication control failed");
            parent_authority_probes(parent_pid, &parent_creation, &nonce)
                .expect("separate parent-process authority probes failed");
            parent_token_probes(parent_pid, &parent_creation, &nonce)
                .expect("query-limited parent token gate failed");
        }

        reset_predefined_roots().expect("reset private registry maps");
        expect_denial(
            "reset/host_denied/win32/machine",
            "lstatus",
            win32_open_status(HKEY_LOCAL_MACHINE, machine_path, KEY_QUERY_VALUE) as i32,
            ERROR_ACCESS_DENIED as i32,
        );
        expect_denial(
            "reset/host_denied/win32/user",
            "lstatus",
            win32_open_status(HKEY_USERS, &user_path, KEY_QUERY_VALUE) as i32,
            ERROR_ACCESS_DENIED as i32,
        );
        expect_denial(
            "reset/host_denied/nt/machine",
            "ntstatus",
            nt_open_status(machine_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        expect_denial(
            "reset/host_denied/nt/user",
            "ntstatus",
            nt_open_status(&user_nt, KEY_QUERY_VALUE),
            STATUS_ACCESS_DENIED,
        );
        let remap_machine = unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, machine.raw()) };
        let remap_user = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, user.raw()) };
        assert_eq!(remap_machine, ERROR_SUCCESS);
        assert_eq!(remap_user, ERROR_SUCCESS);
        record_read(
            "remapped/public_read/machine_view",
            private_view_label(HKEY_LOCAL_MACHINE).expect("remapped machine read"),
        );
        record_read(
            "remapped/public_read/user_view",
            private_view_label(HKEY_CURRENT_USER).expect("remapped user read"),
        );
        reset_predefined_roots().expect("final private registry map reset");
        drop(user);
        drop(machine);
        emit_witness_record(&format!(
            "registry_witness_child_complete nonce={nonce} role=normal pid={} image_id={image_id} image_sha256={image_hash} fixture_digest={fixture_digest}",
            unsafe { GetCurrentProcessId() }
        )).expect("bounded child completion record");
    }

    #[test]
    fn registry_witness_closed_manifest_has_seventy_unique_ids() {
        let ids = required_probe_ids();
        assert_eq!(ids.len(), 70);
        assert!(ids.contains("parent_present/before/win32/machine"));
        assert!(ids.contains("parent_present/after/nt/user"));
        assert!(ids.contains("parent_token/token_assign_primary"));
        assert!(ids.contains("lifetime/cancel_ready_mapped"));
    }
}
