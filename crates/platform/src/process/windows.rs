//! A capability token and a separately owned Job precede every child instruction.

use super::{
    Completion, ConfinementEvidence, ProcessOutput, RUNTIME_CAPABILITY_NAME,
    RUNTIME_CAPABILITY_SID, SpawnSpec, quote_argument, verify_runtime_capability_set,
};
use crate::fs::validate_component;
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
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Win32::System::Threading::*;
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
                "profile retained after unobserved child cleanup: {}",
                self.name
            )));
        }
        hresult("DeleteAppContainerProfile", unsafe {
            DeleteAppContainerProfile(wide(OsStr::new(&self.name))?.as_ptr())
        })?;
        self.closed = true;
        Ok(())
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
        let handles = [
            stdin_read.as_raw_handle(),
            stdout_write.as_raw_handle(),
            stderr_write.as_raw_handle(),
        ];
        let mut attributes = Attributes::new(if less_privileged { 3 } else { 2 })?;
        attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
        if less_privileged {
            attributes.set(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &policy,
            )?;
        }
        attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
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
        unsafe {
            ok(
                "CreateProcessW",
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
                ),
            )?;
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
        let mut stopped = false;
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
$mustDeny=$true; $complete=$true; $exposed=$false
function Digest([string]$value) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($value))) }
function Observe([string]$id,[scriptblock]$action,[string]$expected,[bool]$protected) {
  $row=[ordered]@{id=$id; status='api_error'; protected_credential=$protected}
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
  $denied=$false
  try { & $action | Out-Null } catch {
    $cause=$_.Exception; while ($cause.InnerException) { $cause=$cause.InnerException }
    $denied=$cause -is [UnauthorizedAccessException] -or $cause -is [Security.SecurityException]
  }
  $script:rows.Add([pscustomobject]@{id=$id; status=$(if($denied){'denied'}else{'must_deny_failed'})})
  if (-not $denied) { $script:mustDeny=$false }
}
function NetworkDenied([string]$address,[int]$port,[string]$id) {
  $client=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
  $denied=$false
  try {
    try { $task=$client.ConnectAsync([Net.IPAddress]::Parse($address),$port); if (-not $task.Wait(5000)) { throw 'inconclusive timeout' } }
    catch { $cause=$_.Exception; while($cause.InnerException){$cause=$cause.InnerException}
      $denied=$cause -is [Net.Sockets.SocketException] -and $cause.SocketErrorCode -eq [Net.Sockets.SocketError]::AccessDenied }
  } finally { $client.Dispose() }
  $script:rows.Add([pscustomobject]@{id=$id; status=$(if($denied){'denied_wsaeacces'}else{'inconclusive_or_allowed'})})
  if(-not $denied){$script:mustDeny=$false}
}
try {
  if([IO.File]::ReadAllText('seed.txt') -ne 'owned seed'){throw 'owned read mismatch'}
  [IO.File]::WriteAllText('result.txt','owned write')
  $identity=$PSVersionTable.PSEdition+':'+$PSVersionTable.PSVersion.ToString()
  $runtime=[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
  $module=Get-Date -Format yyyy
  MustDeny 'private_credential_file' { [IO.File]::ReadAllText(@@SECRET@@) }
  MustDeny 'outside_write' { [IO.File]::WriteAllText(@@FORBIDDEN@@,'bad') }
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
  }catch{$complete=$false; $rows.Add([pscustomobject]@{id='win32_probe';status='unavailable';exception=$_.Exception.GetType().FullName})}
}catch{$complete=$false; $rows.Add([pscustomobject]@{id='runtime_or_script';status='failed';exception=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult})}
$boundary=if(-not $mustDeny){'failed_must_deny'}elseif($exposed){'unresolved_exposed_persisted_credential'}elseif($complete){'no_exposure_observed'}else{'not_measured'}
$payload=[ordered]@{measurement_status=$(if($complete -and $mustDeny){'complete'}else{'incomplete'});credential_boundary_status=$boundary;production_policy_unchanged=$true;production_support_pass=$false;nonce=$nonce;original_user_sid=$originalSid;registry_view=64;identity=$identity;runtime=$runtime;module=$module;observations=@($rows.ToArray())}
[IO.File]::WriteAllText('registry-probe.json',($payload|ConvertTo-Json -Depth 8))
if($complete -and $mustDeny){[Console]::WriteLine('REGISTRY_PROBE_COMPLETE');exit 0}else{exit 7}
"#;
}
