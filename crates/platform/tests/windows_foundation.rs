use orbit_platform::fs::validate_component;
use std::ffi::OsStr;

#[test]
fn ambiguous_components_are_rejected() {
    for name in [
        "", ".", "..", "a/b", "a\\b", "a:b", "name.", "name ", "CON", "nul.txt",
    ] {
        assert!(
            validate_component(OsStr::new(name)).is_err(),
            "accepted {name:?}"
        );
    }
    validate_component(OsStr::new("session-雪 01.json")).unwrap();
}

#[test]
fn lock_namespace_is_reserved_consistently() {
    use orbit_platform::fs::{validate_data_component, validate_lock_component};
    for name in ["transaction.lock", "OTHER.LOCK", ".lease.lock"] {
        validate_lock_component(OsStr::new(name)).unwrap();
        assert!(validate_data_component(OsStr::new(name)).is_err());
    }
    assert!(validate_lock_component(OsStr::new("ordinary.json")).is_err());
    validate_data_component(OsStr::new("ordinary.json")).unwrap();
}

#[cfg(windows)]
mod windows {
    use orbit_platform::fs::{
        Directory, EnumerationLimits, FileIdentity, InspectionLimits, LockMode, OwnedContainer,
        PrivateFileAccess, RemovalState, SourceDirectory, SourceKind,
    };
    use std::ffi::{OsStr, c_void};
    use std::fs;
    use std::mem::offset_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    struct Home {
        base: PathBuf,
        directory: Option<Directory>,
    }
    impl Home {
        fn new() -> Self {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "orbit-fs-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            let directory = Directory::create(&base.join("private 雪 space")).unwrap();
            Self {
                base,
                directory: Some(directory),
            }
        }
        fn path(&self) -> PathBuf {
            self.base.join("private 雪 space")
        }
        fn dir(&self) -> &Directory {
            self.directory.as_ref().unwrap()
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            drop(self.directory.take());
            fs::remove_dir_all(&self.base).unwrap();
        }
    }
    fn read(directory: &Directory, name: &str) -> Vec<u8> {
        directory
            .open_file(OsStr::new(name))
            .unwrap()
            .read_limited(1024)
            .unwrap()
    }
    fn command(program: &str) -> PathBuf {
        Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join(program)
    }

    fn tree_snapshot(root: &Path) -> Vec<(PathBuf, bool, Vec<u8>)> {
        fn visit(root: &Path, current: &Path, entries: &mut Vec<(PathBuf, bool, Vec<u8>)>) {
            for item in fs::read_dir(current).unwrap() {
                let item = item.unwrap();
                let path = item.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let reparse = metadata.file_attributes() & 0x400 != 0;
                if reparse {
                    entries.push((relative, true, Vec::new()));
                } else if metadata.is_dir() {
                    entries.push((relative, true, Vec::new()));
                    visit(root, &path, entries);
                } else {
                    entries.push((relative, false, fs::read(&path).unwrap()));
                }
            }
        }
        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    fn run_icacls(path: &Path, args: &[&str]) -> String {
        let output = Command::new(command("icacls.exe"))
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "icacls {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn current_sid() -> String {
        let output = Command::new(command("whoami.exe"))
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "whoami failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let row = String::from_utf8_lossy(&output.stdout);
        let sid = row
            .trim()
            .split(',')
            .nth(1)
            .expect("whoami CSV must include a SID")
            .trim_matches('"');
        assert!(sid.starts_with("S-1-"), "invalid current SID: {sid}");
        sid.to_owned()
    }

    #[derive(Debug, Eq, PartialEq)]
    struct FixtureAclFacts {
        owner_matches_current: bool,
        owner_matches_administrators: bool,
        dacl_present: bool,
        dacl_protected: bool,
        ace_count: u16,
        first_ace_type: Option<u8>,
        first_ace_flags: Option<u8>,
        first_ace_sid_matches_current: Option<bool>,
        first_ace_mask: Option<u32>,
        has_current_owner_full_control_ace: bool,
        has_everyone_full_control_ace: bool,
        has_everyone_read_ace: bool,
        everyone_mask: Option<u32>,
        everyone_ace_flags: Option<u8>,
    }

    struct FixtureAclSnapshot {
        facts: FixtureAclFacts,
        normalized_descriptor: Vec<u8>,
    }

    struct LocalSecurityAllocation(*mut c_void);
    impl Drop for LocalSecurityAllocation {
        fn drop(&mut self) {
            let _ = unsafe { LocalFree(self.0) };
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn sid_from_text(value: &str) -> LocalSecurityAllocation {
        let value = wide(OsStr::new(value));
        let mut sid = null_mut();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) },
            0,
            "converting fixture SID failed: {}",
            unsafe { GetLastError() }
        );
        LocalSecurityAllocation(sid.cast())
    }

    fn fixture_handle(path: &Path, access: u32, directory: bool) -> OwnedHandle {
        let path = wide(path.as_os_str());
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "opening an owned fixture for ACL inspection failed: {}",
            unsafe { GetLastError() }
        );
        unsafe { OwnedHandle::from_raw_handle(handle) }
    }

    fn set_fixture_file_mask(path: &Path, sid: &str, mask: u32, ace_flags: u8) {
        let inheritance_flags = match ace_flags {
            0 => "",
            flags if flags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 => "OICI",
            _ => panic!("unsupported fixture ACE inheritance flags: {ace_flags}"),
        };
        let sddl = wide(OsStr::new(&format!(
            "O:{sid}D:P(A;{inheritance_flags};0x{mask:08X};;;{sid})"
        )));
        let mut descriptor = null_mut();
        let mut descriptor_length = 0;
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    &mut descriptor_length,
                )
            },
            0,
            "building fixture ACL descriptor failed: {}",
            unsafe { GetLastError() }
        );
        let descriptor = LocalSecurityAllocation(descriptor.cast());
        let mut present = 0;
        let mut dacl = null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.0.cast(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                )
            },
            0,
            "reading fixture ACL descriptor failed: {}",
            unsafe { GetLastError() }
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());

        let handle = fixture_handle(path, READ_CONTROL | WRITE_DAC, false);
        let result = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        assert_eq!(
            result, ERROR_SUCCESS,
            "setting fixture ACL failed: {result}"
        );
    }

    fn set_container_sddl(path: &Path, sddl: &str) {
        let descriptor_text = wide(OsStr::new(sddl));
        let mut descriptor = null_mut();
        let mut descriptor_length = 0;
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    descriptor_text.as_ptr(),
                    1,
                    &mut descriptor,
                    &mut descriptor_length,
                )
            },
            0,
            "building owned-container ACL fixture failed: {}",
            unsafe { GetLastError() }
        );
        let descriptor = LocalSecurityAllocation(descriptor.cast());
        let mut owner = null_mut();
        let mut owner_defaulted = 0;
        let mut present = 0;
        let mut dacl = null_mut();
        let mut dacl_defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorOwner(descriptor.0.cast(), &mut owner, &mut owner_defaulted)
            },
            0,
            "reading fixture owner failed: {}",
            unsafe { GetLastError() }
        );
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.0.cast(),
                    &mut present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
            },
            0,
            "reading fixture DACL failed: {}",
            unsafe { GetLastError() }
        );
        assert!(!owner.is_null());
        let handle = fixture_handle(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER, true);
        let result = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                null_mut(),
                if present != 0 { dacl } else { null_mut() },
                null_mut(),
            )
        };
        assert_eq!(
            result, ERROR_SUCCESS,
            "installing fixture ACL failed: {result}"
        );
    }

    fn fixture_has_ace(path: &Path, sid_text: &str, mask: u32, flags: u8, ace_type: u8) -> bool {
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut expected_mask = mask;
        unsafe { MapGenericMask(&mut expected_mask, &mapping) };
        let handle = fixture_handle(path, READ_CONTROL, true);
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        let _descriptor = LocalSecurityAllocation(descriptor);
        assert!(!dacl.is_null(), "installed fixture DACL must be non-null");
        let sid = sid_from_text(sid_text);
        let mut info = ACL_SIZE_INFORMATION::default();
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        let mut observed_masks = Vec::new();
        let matched = (0..info.AceCount).any(|index| {
            let mut ace = null_mut();
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != ace_type || header.AceFlags != flags {
                return false;
            }
            let actual_mask = unsafe { *ace.cast::<u32>().add(1) };
            let sid_ptr = unsafe {
                ace.cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .cast()
            };
            if unsafe { EqualSid(sid_ptr, sid.0.cast()) } == 0 {
                return false;
            }
            observed_masks.push(actual_mask);
            actual_mask == expected_mask
        });
        if !matched {
            let observed = observed_masks
                .iter()
                .map(|value| format!("{value:#010x}"))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "fixture ACE mismatch: type={ace_type:#04x}, flags={flags:#04x}, supplied_mask={mask:#010x}, expected_file_mask={expected_mask:#010x}, observed_matching_masks=[{observed}]"
            );
        }
        matched
    }

    fn fixture_container_sddl(owner: &str, grants: &str) -> String {
        format!("O:{owner}D:P(A;;FA;;;{owner}){grants}")
    }

    fn fixture_dacl_is_null(path: &Path) -> bool {
        let handle = fixture_handle(path, READ_CONTROL, true);
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        let _descriptor = LocalSecurityAllocation(descriptor);
        let mut present = 0;
        let mut descriptor_dacl = null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &mut present,
                    &mut descriptor_dacl,
                    &mut defaulted,
                )
            },
            0
        );
        present != 0 && descriptor_dacl.is_null() && dacl.is_null()
    }

    fn delete_capability_open(path: &Path) -> std::io::Result<OwnedHandle> {
        let path = wide(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    fn set_fixture_owner(path: &Path, owner_sid_text: &str, directory: bool) {
        let owner = sid_from_text(owner_sid_text);
        let handle = fixture_handle(path, READ_CONTROL | WRITE_OWNER, directory);
        let result = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner.0.cast(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        assert_eq!(
            result, ERROR_SUCCESS,
            "setting only the fixture owner failed: {result}"
        );
    }

    fn set_public_source_acl(path: &Path, sid: &str, directory: bool) {
        let inheritance = if directory { "OICI" } else { "" };
        let sddl = wide(OsStr::new(&format!(
            "D:P(A;{inheritance};0x001F01FF;;;{sid})(A;{inheritance};0x00120089;;;S-1-1-0)"
        )));
        let mut descriptor = null_mut();
        let mut descriptor_length = 0;
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    &mut descriptor_length,
                )
            },
            0,
            "building public-source fixture ACL failed: {}",
            unsafe { GetLastError() }
        );
        let descriptor = LocalSecurityAllocation(descriptor.cast());
        let mut present = 0;
        let mut dacl = null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.0.cast(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                )
            },
            0,
            "reading public-source fixture ACL failed: {}",
            unsafe { GetLastError() }
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());
        let owner_sid = sid_from_text(sid);
        let handle = fixture_handle(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER, directory);
        let result = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner_sid.0.cast(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        assert_eq!(
            result, ERROR_SUCCESS,
            "installing public-source fixture owner and ACL failed: {result}"
        );
    }

    fn fixture_acl_snapshot(
        path: &Path,
        current_sid_text: &str,
        directory: bool,
    ) -> FixtureAclSnapshot {
        let current_sid = sid_from_text(current_sid_text);
        let administrators_sid = sid_from_text("S-1-5-32-544");
        let everyone_sid = sid_from_text("S-1-1-0");
        let handle = fixture_handle(path, READ_CONTROL, directory);
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(
            result, ERROR_SUCCESS,
            "querying fixture ACL failed: {result}"
        );
        let descriptor = LocalSecurityAllocation(descriptor.cast());

        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorControl(descriptor.0.cast(), &mut control, &mut revision)
            },
            0,
            "reading fixture descriptor control failed: {}",
            unsafe { GetLastError() }
        );
        let mut dacl_present = 0;
        let mut descriptor_dacl = null_mut();
        let mut dacl_defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.0.cast(),
                    &mut dacl_present,
                    &mut descriptor_dacl,
                    &mut dacl_defaulted,
                )
            },
            0,
            "reading fixture DACL presence failed: {}",
            unsafe { GetLastError() }
        );

        let ace_count = if dacl.is_null() {
            0
        } else {
            unsafe { (*dacl).AceCount }
        };
        let mut first_ace_type = None;
        let mut first_ace_flags = None;
        let mut first_ace_sid_matches_current = None;
        let mut first_ace_mask = None;
        let mut has_current_owner_full_control_ace = false;
        let mut has_everyone_full_control_ace = false;
        let mut has_everyone_read_ace = false;
        let mut everyone_mask = None;
        let mut everyone_ace_flags = None;
        if !dacl.is_null() {
            for index in 0..u32::from(ace_count) {
                let mut ace = null_mut();
                assert_ne!(
                    unsafe { GetAce(dacl, index, &mut ace) },
                    0,
                    "reading fixture ACE {index} failed: {}",
                    unsafe { GetLastError() }
                );
                let header = unsafe { &*ace.cast::<ACE_HEADER>() };
                if index == 0 {
                    first_ace_type = Some(header.AceType);
                    first_ace_flags = Some(header.AceFlags);
                }
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || (header.AceSize as usize)
                        < offset_of!(ACCESS_ALLOWED_ACE, SidStart)
                            + offset_of!(windows_sys::Win32::Security::SID, SubAuthority)
                {
                    continue;
                }
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let ace_sid = (&allowed.SidStart as *const u32).cast_mut().cast();
                let sid_length = unsafe { GetLengthSid(ace_sid) } as usize;
                let maximum_sid_length =
                    header.AceSize as usize - offset_of!(ACCESS_ALLOWED_ACE, SidStart);
                if sid_length == 0 || sid_length > maximum_sid_length {
                    continue;
                }
                let sid_matches_current = unsafe { EqualSid(ace_sid, current_sid.0.cast()) } != 0;
                if index == 0 {
                    first_ace_sid_matches_current = Some(sid_matches_current);
                    first_ace_mask = Some(allowed.Mask);
                }
                let effective = header.AceFlags & INHERIT_ONLY_ACE as u8 == 0;
                has_current_owner_full_control_ace |=
                    effective && sid_matches_current && allowed.Mask == FILE_ALL_ACCESS;
                let sid_matches_everyone = unsafe { EqualSid(ace_sid, everyone_sid.0.cast()) != 0 };
                if sid_matches_everyone {
                    everyone_mask = Some(allowed.Mask);
                    everyone_ace_flags = Some(header.AceFlags);
                    has_everyone_read_ace |= effective && allowed.Mask & 0x0012_0089 == 0x0012_0089;
                }
                has_everyone_full_control_ace |=
                    effective && sid_matches_everyone && allowed.Mask == FILE_ALL_ACCESS;
            }
        }

        let mut normalized_descriptor = Vec::new();
        normalized_descriptor.push(u8::from(dacl_present != 0));
        normalized_descriptor.extend_from_slice(&(control & SE_DACL_PROTECTED).to_le_bytes());
        if owner.is_null() {
            normalized_descriptor.extend_from_slice(&0u32.to_le_bytes());
        } else {
            let owner_length = unsafe { GetLengthSid(owner) } as usize;
            normalized_descriptor.extend_from_slice(&(owner_length as u32).to_le_bytes());
            if owner_length != 0 {
                normalized_descriptor.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(owner.cast::<u8>(), owner_length)
                });
            }
        }
        if dacl.is_null() {
            normalized_descriptor.extend_from_slice(&0u32.to_le_bytes());
        } else {
            let acl_length = unsafe { (*dacl).AclSize } as usize;
            normalized_descriptor.extend_from_slice(&(acl_length as u32).to_le_bytes());
            normalized_descriptor.extend_from_slice(unsafe {
                std::slice::from_raw_parts(dacl.cast::<u8>(), acl_length)
            });
        }

        FixtureAclSnapshot {
            facts: FixtureAclFacts {
                owner_matches_current: !owner.is_null()
                    && unsafe { EqualSid(owner, current_sid.0.cast()) } != 0,
                owner_matches_administrators: !owner.is_null()
                    && unsafe { EqualSid(owner, administrators_sid.0.cast()) } != 0,
                dacl_present: dacl_present != 0 && !descriptor_dacl.is_null(),
                dacl_protected: control & SE_DACL_PROTECTED != 0,
                ace_count,
                first_ace_type,
                first_ace_flags,
                first_ace_sid_matches_current,
                first_ace_mask,
                has_current_owner_full_control_ace,
                has_everyone_full_control_ace,
                has_everyone_read_ace,
                everyone_mask,
                everyone_ace_flags,
            },
            normalized_descriptor,
        }
    }

    fn fixture_normalized_dacl(snapshot: &FixtureAclSnapshot) -> &[u8] {
        let normalized = &snapshot.normalized_descriptor;
        assert!(
            normalized.len() >= 7,
            "normalized descriptor must contain the owner length"
        );
        let owner_length = u32::from_le_bytes(normalized[3..7].try_into().unwrap()) as usize;
        let length_offset = 7usize.checked_add(owner_length).unwrap();
        let data_offset = length_offset.checked_add(4).unwrap();
        assert!(
            normalized.len() >= data_offset,
            "normalized descriptor must contain the DACL length"
        );
        let dacl_length =
            u32::from_le_bytes(normalized[length_offset..data_offset].try_into().unwrap()) as usize;
        let dacl_end = data_offset.checked_add(dacl_length).unwrap();
        assert_eq!(
            normalized.len(),
            dacl_end,
            "normalized descriptor must have no trailing bytes"
        );
        &normalized[data_offset..dacl_end]
    }

    fn assert_fixture_acl_unchanged(
        path: &Path,
        current_sid: &str,
        directory: bool,
        before: &FixtureAclSnapshot,
        context: &str,
    ) {
        let after = fixture_acl_snapshot(path, current_sid, directory);
        assert_eq!(
            before.normalized_descriptor, after.normalized_descriptor,
            "{context} must leave the full owner and DACL unchanged"
        );
    }

    fn assert_fixture_acl(
        path: &Path,
        sid: &str,
        directory: bool,
        expected_mask: u32,
        expected_ace_flags: u8,
    ) -> FixtureAclSnapshot {
        let snapshot = fixture_acl_snapshot(path, sid, directory);
        let facts = &snapshot.facts;
        assert!(
            facts.owner_matches_current,
            "fixture owner mismatch: {facts:?}"
        );
        assert!(facts.dacl_present, "fixture DACL missing: {facts:?}");
        assert!(
            facts.dacl_protected,
            "fixture DACL is unprotected: {facts:?}"
        );
        assert_eq!(facts.ace_count, 1, "fixture ACE count mismatch: {facts:?}");
        assert_eq!(
            facts.first_ace_type,
            Some(ACCESS_ALLOWED_ACE_TYPE),
            "fixture ACE type mismatch: {facts:?}"
        );
        assert_eq!(
            facts.first_ace_flags,
            Some(expected_ace_flags),
            "fixture ACE flags mismatch: {facts:?}"
        );
        assert_eq!(
            facts.first_ace_sid_matches_current,
            Some(true),
            "fixture ACE SID mismatch: {facts:?}"
        );
        assert_eq!(
            facts.first_ace_mask,
            Some(expected_mask),
            "fixture ACE mask mismatch: {facts:?}"
        );
        assert!(
            !facts.has_everyone_full_control_ace,
            "fixture is permissive: {facts:?}"
        );
        snapshot
    }

    #[test]
    fn unicode_private_create_reopen_and_read_bounds() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("entry 雪.json")).unwrap();
        file.write_all(b"private state").unwrap();
        file.sync_all().unwrap();
        let identity = file.identity();
        drop(file);
        let directory = Directory::open(&home.path()).unwrap();
        let mut file = directory.open_file(OsStr::new("entry 雪.json")).unwrap();
        assert_eq!(file.identity(), identity);
        assert!(file.read_limited(3).is_err());
        assert_eq!(file.read_limited(1024).unwrap(), b"private state");
    }

    #[test]
    fn source_directory_reads_public_unicode_file_without_private_authority() {
        let home = Home::new();
        let private_name = OsStr::new("private source.txt");
        let private_contents = b"held private baseline";
        let mut private_writer = home.dir().create_file(private_name).unwrap();
        private_writer.write_all(private_contents).unwrap();
        private_writer.sync_all().unwrap();
        drop(private_writer);

        let private_source = SourceDirectory::open(&home.path()).unwrap();
        let mut private_file = private_source.open_file(private_name).unwrap();
        let private_identity = private_file.identity();
        let private_before = private_file.snapshot().unwrap();
        assert_eq!(private_before.identity, private_identity);
        assert_eq!(
            private_file.read_limited(128).unwrap(),
            private_contents,
            "the real SourceFile tracer must read through its held file on a private fixture"
        );
        assert_eq!(private_file.snapshot().unwrap(), private_before);

        let public_root = home.base.join("public source 雪 tree");
        fs::create_dir(&public_root).unwrap();
        let public_name = OsStr::new("source entry 雪.txt");
        let public_path = public_root.join(public_name);
        let public_contents = b"public plugin source bytes";
        fs::write(&public_path, public_contents).unwrap();

        let sid = current_sid();
        set_public_source_acl(&public_root, &sid, true);
        set_public_source_acl(&public_path, &sid, false);

        let root_facts = fixture_acl_snapshot(&public_root, &sid, true).facts;
        assert!(
            root_facts.owner_matches_current,
            "source root owner: {root_facts:?}"
        );
        assert!(root_facts.dacl_present && root_facts.dacl_protected);
        assert_eq!(root_facts.ace_count, 2, "source root ACEs: {root_facts:?}");
        assert!(root_facts.has_current_owner_full_control_ace);
        assert!(root_facts.has_everyone_read_ace);
        assert_eq!(root_facts.everyone_mask, Some(0x0012_0089));
        assert_eq!(
            root_facts.everyone_ace_flags,
            Some((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8),
            "source directory Everyone ACE flags: {root_facts:?}"
        );
        assert!(!root_facts.has_everyone_full_control_ace);

        let file_facts = fixture_acl_snapshot(&public_path, &sid, false).facts;
        assert!(
            file_facts.owner_matches_current,
            "source file owner: {file_facts:?}"
        );
        assert!(file_facts.dacl_present && file_facts.dacl_protected);
        assert_eq!(file_facts.ace_count, 2, "source file ACEs: {file_facts:?}");
        assert!(file_facts.has_current_owner_full_control_ace);
        assert!(file_facts.has_everyone_read_ace);
        assert_eq!(file_facts.everyone_mask, Some(0x0012_0089));
        assert_eq!(
            file_facts.everyone_ace_flags,
            Some(0),
            "source file Everyone ACE flags: {file_facts:?}"
        );
        assert!(!file_facts.has_everyone_full_control_ace);

        let private_policy_error = match Directory::open(&public_root) {
            Ok(_) => panic!("private Directory accepted the public-readable source tree"),
            Err(error) => error,
        };
        assert_eq!(
            private_policy_error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "private Directory must preserve its owner-private DACL requirement"
        );

        let public_source = SourceDirectory::open(&public_root)
            .expect("public source should open through the separate SourceDirectory policy");
        let mut public_file = public_source.open_file(public_name).unwrap();
        let identity = public_file.identity();
        let before = public_file.snapshot().unwrap();
        assert_eq!(before.identity, identity);
        assert_eq!(
            public_file.read_limited(128).unwrap(),
            public_contents,
            "held SourceFile bytes must match the public fixture"
        );
        assert_eq!(public_file.snapshot().unwrap(), before);
    }

    #[test]
    fn source_directory_rejects_replaced_full_identity() {
        let home = Home::new();
        let public_root = home.base.join("public source replacement tree");
        fs::create_dir(&public_root).unwrap();
        let name = OsStr::new("source identity entry 雪.txt");
        let path = public_root.join(name);
        fs::write(&path, b"original public source").unwrap();
        let sid = current_sid();
        set_public_source_acl(&public_root, &sid, true);
        set_public_source_acl(&path, &sid, false);

        let source = SourceDirectory::open(&public_root).unwrap();
        let stale_identity = source.open_file(name).unwrap().identity();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement public source").unwrap();
        set_public_source_acl(&path, &sid, false);

        let replacement = source.open_file(name).unwrap();
        let replacement_identity = replacement.identity();
        assert_ne!(
            replacement_identity, stale_identity,
            "the fixture replacement must have a distinct full physical identity"
        );
        let mut replacement = replacement;
        assert_eq!(
            replacement.read_limited(128).unwrap(),
            b"replacement public source"
        );
        drop(replacement);

        let error = match source.open_file_expected(name, stale_identity) {
            Ok(_) => panic!("SourceDirectory accepted a replaced source identity"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn source_file_rejects_reads_over_the_requested_bound() {
        let home = Home::new();
        let public_root = home.base.join("public source bounded tree");
        fs::create_dir(&public_root).unwrap();
        let name = OsStr::new("bounded source entry 雪.txt");
        let path = public_root.join(name);
        let contents = b"bounded public source bytes";
        fs::write(&path, contents).unwrap();
        let sid = current_sid();
        set_public_source_acl(&public_root, &sid, true);
        set_public_source_acl(&path, &sid, false);

        let source = SourceDirectory::open(&public_root).unwrap();
        let mut file = source.open_file(name).unwrap();
        let before = file.snapshot().unwrap();
        let maximum = contents.len() - 1;
        assert!(
            before.length > maximum as u64,
            "oversize fixture must exceed the requested read bound"
        );
        assert!(
            file.read_limited(maximum).is_err(),
            "SourceFile returned bytes beyond the requested bound"
        );
        assert_eq!(file.snapshot().unwrap(), before);
    }

    #[test]
    fn source_directory_enumerates_nested_unicode_and_preserves_metadata() {
        let home = Home::new();
        let root = home.base.join("public traversal 雪 root");
        fs::create_dir(&root).unwrap();
        let nested = root.join("nested folder");
        fs::create_dir(&nested).unwrap();
        let name = OsStr::new("source entry 雪 file.txt");
        let file_path = nested.join(name);
        fs::write(&file_path, b"nested public bytes").unwrap();
        let sid = current_sid();
        set_public_source_acl(&root, &sid, true);
        set_public_source_acl(&nested, &sid, true);
        set_public_source_acl(&file_path, &sid, false);

        let source = SourceDirectory::open_with_depth(&root, 1).unwrap();
        let limits = EnumerationLimits {
            max_entries: 16,
            max_name_bytes: 4096,
        };
        let root_entries = source.enumerate(limits).unwrap();
        let root_again = source.enumerate(limits).unwrap();
        assert_eq!(
            root_entries, root_again,
            "a repeated bounded enumeration is stable"
        );
        let root_identity = source.identity();
        let repeated_ancestor = FileIdentity {
            volume: root_identity.volume,
            file: root_identity.file,
        };
        assert!(
            source
                .child_expected(OsStr::new("nested folder"), repeated_ancestor)
                .is_err()
        );
        let cross_volume = FileIdentity {
            volume: root_identity.volume ^ 1,
            file: [0xA5; 16],
        };
        assert!(
            source
                .child_expected(OsStr::new("nested folder"), cross_volume)
                .is_err()
        );
        let child = root_entries
            .iter()
            .find(|entry| entry.name == OsStr::new("nested folder"))
            .expect("nested source directory was enumerated");
        assert_eq!(child.kind, SourceKind::Directory);
        assert_eq!(child.snapshot.kind, SourceKind::Directory);
        assert_eq!(child.identity, child.snapshot.identity);
        assert!(child.snapshot.link_count >= 1);

        let nested_source = source
            .child_expected(OsStr::new("nested folder"), child.identity)
            .unwrap();
        let entries = nested_source.enumerate(limits).unwrap();
        let file = entries.iter().find(|entry| entry.name == name).unwrap();
        assert_eq!(file.kind, SourceKind::File);
        assert_eq!(file.snapshot.kind, SourceKind::File);
        assert_eq!(file.snapshot.length, b"nested public bytes".len() as u64);
        assert_eq!(file.snapshot.link_count, 1);
        assert_eq!(file.snapshot.identity, file.identity);
        let mut held = nested_source
            .open_file_expected(name, file.identity)
            .unwrap();
        let before = held.snapshot().unwrap();
        assert_eq!(before.kind, SourceKind::File);
        assert_eq!(before.link_count, 1);
        assert_eq!(held.read_limited(128).unwrap(), b"nested public bytes");
        assert_eq!(held.snapshot().unwrap(), before);
    }

    #[test]
    fn source_directory_carries_depth_budget_and_rejects_stale_child_identity() {
        let home = Home::new();
        let root = home.base.join("public bounded-depth root");
        fs::create_dir(&root).unwrap();
        let child_path = root.join("child");
        fs::create_dir(&child_path).unwrap();
        let grandchild_path = child_path.join("grandchild");
        fs::create_dir(&grandchild_path).unwrap();
        let sid = current_sid();
        set_public_source_acl(&root, &sid, true);
        set_public_source_acl(&child_path, &sid, true);
        set_public_source_acl(&grandchild_path, &sid, true);
        let limits = EnumerationLimits {
            max_entries: 8,
            max_name_bytes: 1024,
        };

        let exhausted = SourceDirectory::open_with_depth(&root, 0).unwrap();
        let initial = exhausted
            .enumerate(limits)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == OsStr::new("child"))
            .unwrap();
        assert!(
            exhausted
                .child_expected(OsStr::new("child"), initial.identity)
                .is_err()
        );

        let source = SourceDirectory::open_with_depth(&root, 1).unwrap();
        let old = source
            .enumerate(limits)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == OsStr::new("child"))
            .unwrap();
        assert_eq!(old.identity, initial.identity);
        fs::remove_dir_all(&child_path).unwrap();
        fs::create_dir(&child_path).unwrap();
        fs::create_dir(&grandchild_path).unwrap();
        set_public_source_acl(&child_path, &sid, true);
        set_public_source_acl(&grandchild_path, &sid, true);
        let replacement = source
            .enumerate(limits)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == OsStr::new("child"))
            .unwrap();
        assert_ne!(
            replacement.identity, old.identity,
            "replacement must have a new full identity"
        );
        let error = match source.child_expected(OsStr::new("child"), old.identity) {
            Ok(_) => panic!("stale directory identity was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let child = source
            .child_expected(OsStr::new("child"), replacement.identity)
            .unwrap();
        let grandchild = child
            .enumerate(limits)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == OsStr::new("grandchild"))
            .unwrap();
        assert!(
            child
                .child_expected(OsStr::new("grandchild"), grandchild.identity)
                .is_err(),
            "the child capability cannot replenish the root's exhausted depth budget"
        );
    }

    #[test]
    fn source_directory_rejects_hardlinks_and_reparse_entries_without_following_them() {
        let home = Home::new();
        let root = home.base.join("public unsafe entries root");
        fs::create_dir(&root).unwrap();
        let sid = current_sid();
        set_public_source_acl(&root, &sid, true);

        let linked = root.join("linked file");
        fs::write(&linked, b"same object").unwrap();
        set_public_source_acl(&linked, &sid, false);
        fs::hard_link(&linked, root.join("hardlink alias")).unwrap();
        let source = SourceDirectory::open(&root).unwrap();
        assert!(
            source
                .enumerate(EnumerationLimits {
                    max_entries: 16,
                    max_name_bytes: 4096
                })
                .is_err(),
            "a regular source file with two links must be rejected"
        );
        fs::remove_file(root.join("hardlink alias")).unwrap();
        fs::remove_file(&linked).unwrap();

        let outside = home.base.join("outside source canary");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary"), b"unchanged").unwrap();
        let junction = root.join("directory junction");
        let output = Command::new(command("cmd.exe"))
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "junction fixture must really be created: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fs::symlink_metadata(&junction).unwrap().file_attributes() & 0x400 != 0);
        assert!(
            source
                .enumerate(EnumerationLimits {
                    max_entries: 16,
                    max_name_bytes: 4096
                })
                .is_err(),
            "a listed reparse source entry must be rejected"
        );
        assert_eq!(fs::read(outside.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn source_directory_enumeration_enforces_entry_and_name_bounds_without_changes() {
        let home = Home::new();
        let root = home.base.join("public source limit root");
        fs::create_dir(&root).unwrap();
        let sid = current_sid();
        set_public_source_acl(&root, &sid, true);
        for name in ["a", "a longer source name"] {
            let path = root.join(name);
            fs::write(&path, b"unchanged").unwrap();
            set_public_source_acl(&path, &sid, false);
        }
        let before = tree_snapshot(&root);
        let source = SourceDirectory::open(&root).unwrap();
        assert!(
            source
                .enumerate(EnumerationLimits {
                    max_entries: 1,
                    max_name_bytes: 4096
                })
                .is_err()
        );
        assert!(
            source
                .enumerate(EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&root), before);
    }

    #[test]
    fn source_directory_holds_root_and_ancestors_while_walking() {
        let home = Home::new();
        let public_ancestor = home.base.join("public ancestor");
        fs::create_dir(&public_ancestor).unwrap();
        let root = public_ancestor.join("source root");
        fs::create_dir(&root).unwrap();
        let child_path = root.join("held child");
        fs::create_dir(&child_path).unwrap();
        let canary_path = child_path.join("canary");
        fs::write(&canary_path, b"held-canary").unwrap();

        let sid = current_sid();
        set_public_source_acl(&public_ancestor, &sid, true);
        set_public_source_acl(&root, &sid, true);
        set_public_source_acl(&child_path, &sid, true);
        set_public_source_acl(&canary_path, &sid, false);

        let ancestor_id = SourceDirectory::open(&public_ancestor).unwrap().identity();
        let root_id = SourceDirectory::open(&root).unwrap().identity();
        let child_id = SourceDirectory::open(&child_path).unwrap().identity();
        let ancestor_acl = fixture_acl_snapshot(&public_ancestor, &sid, true).normalized_descriptor;
        let root_acl = fixture_acl_snapshot(&root, &sid, true).normalized_descriptor;
        let child_acl = fixture_acl_snapshot(&child_path, &sid, true).normalized_descriptor;
        let canary_acl = fixture_acl_snapshot(&canary_path, &sid, false).normalized_descriptor;
        let canary_before = fs::read(&canary_path).unwrap();

        for path in [&public_ancestor, &root] {
            let handle =
                delete_capability_open(path).expect("DELETE control must open before source caps");
            drop(handle);
        }

        let source = SourceDirectory::open(&root).unwrap();
        let entry = source
            .enumerate(EnumerationLimits {
                max_entries: 8,
                max_name_bytes: 1024,
            })
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == OsStr::new("held child"))
            .unwrap();
        let child = source
            .child_expected(OsStr::new("held child"), entry.identity)
            .unwrap();
        assert_eq!(child.identity(), child_id);
        let mut canary = child.open_file(OsStr::new("canary")).unwrap();
        assert_eq!(canary.read_limited(64).unwrap(), canary_before);
        drop(canary);
        drop(source);

        for path in [&public_ancestor, &root] {
            let error = delete_capability_open(path)
                .expect_err("child-held walk must retain ancestor capabilities");
            assert_eq!(
                error.raw_os_error(),
                Some(32),
                "expected exact ERROR_SHARING_VIOLATION from the same DELETE opener"
            );
        }

        let moved_root = public_ancestor.join("source root moved");
        let moved_ancestor = home.base.join("public ancestor moved");
        assert!(!moved_root.exists());
        assert!(!moved_ancestor.exists());
        assert_eq!(fs::read(&canary_path).unwrap(), canary_before);
        assert_eq!(
            fixture_acl_snapshot(&public_ancestor, &sid, true).normalized_descriptor,
            ancestor_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&root, &sid, true).normalized_descriptor,
            root_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&child_path, &sid, true).normalized_descriptor,
            child_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&canary_path, &sid, false).normalized_descriptor,
            canary_acl
        );
        assert_eq!(
            SourceDirectory::open(&public_ancestor).unwrap().identity(),
            ancestor_id
        );
        assert_eq!(SourceDirectory::open(&root).unwrap().identity(), root_id);
        assert_eq!(
            SourceDirectory::open(&child_path).unwrap().identity(),
            child_id
        );

        drop(child);
        for path in [&public_ancestor, &root] {
            let handle = delete_capability_open(path)
                .expect("DELETE opener must succeed after dropping child");
            drop(handle);
        }
        fs::rename(&root, &moved_root).expect("root rename must succeed after dropping child");
        fs::rename(&public_ancestor, &moved_ancestor)
            .expect("ancestor rename must succeed after dropping child");

        let final_root = moved_ancestor.join("source root moved");
        let moved_root_id = SourceDirectory::open(&final_root).unwrap().identity();
        let moved_child = final_root.join("held child");
        assert_eq!(moved_root_id, root_id);
        assert_eq!(
            SourceDirectory::open(&moved_child).unwrap().identity(),
            child_id
        );
        assert_eq!(
            SourceDirectory::open(&moved_ancestor).unwrap().identity(),
            ancestor_id
        );
        let moved_canary = moved_child.join("canary");
        assert_eq!(fs::read(&moved_canary).unwrap(), canary_before);
        assert_eq!(
            fixture_acl_snapshot(&final_root, &sid, true).normalized_descriptor,
            root_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&moved_child, &sid, true).normalized_descriptor,
            child_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&moved_canary, &sid, false).normalized_descriptor,
            canary_acl
        );
        assert_eq!(
            fixture_acl_snapshot(&moved_ancestor, &sid, true).normalized_descriptor,
            ancestor_acl
        );
    }

    #[test]
    fn owned_container_accepts_owner_safe_readable_root() {
        let home = Home::new();
        let sid = current_sid();
        let before_private = fixture_acl_snapshot(&home.path(), &sid, true);
        let private = OwnedContainer::open(&home.path()).unwrap();
        private.check().unwrap();
        assert_eq!(private.identity(), home.dir().identity());
        let after_private = fixture_acl_snapshot(&home.path(), &sid, true);
        assert_eq!(
            before_private.normalized_descriptor,
            after_private.normalized_descriptor
        );

        let public_root = home.base.join("owner safe readable container");
        fs::create_dir(&public_root).unwrap();
        set_public_source_acl(&public_root, &sid, true);
        let before = fixture_acl_snapshot(&public_root, &sid, true);
        let facts = &before.facts;
        assert!(facts.owner_matches_current, "container owner: {facts:?}");
        assert!(
            !facts.owner_matches_administrators,
            "container owner must be the current user: {facts:?}"
        );
        assert!(facts.dacl_present && facts.dacl_protected);
        assert_eq!(facts.ace_count, 2, "container ACEs: {facts:?}");
        assert!(facts.has_current_owner_full_control_ace);
        assert!(facts.has_everyone_read_ace);
        assert_eq!(facts.everyone_mask, Some(0x0012_0089));
        assert_eq!(
            facts.everyone_ace_flags,
            Some((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8),
            "container Everyone ACE flags: {facts:?}"
        );
        assert!(!facts.has_everyone_full_control_ace);

        let private_policy_error = match Directory::open(&public_root) {
            Ok(_) => panic!("private Directory accepted the public-readable container fixture"),
            Err(error) => error,
        };
        assert_eq!(
            private_policy_error.kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let after_private_refusal = fixture_acl_snapshot(&public_root, &sid, true);
        assert_eq!(
            before.normalized_descriptor,
            after_private_refusal.normalized_descriptor
        );

        let container = OwnedContainer::open(&public_root)
            .expect("owner-safe readable container should pass its separate policy");
        container.check().unwrap();
        let after_acceptance = fixture_acl_snapshot(&public_root, &sid, true);
        assert_eq!(
            before.normalized_descriptor,
            after_acceptance.normalized_descriptor
        );
    }

    #[test]
    fn owned_container_accepts_system_admin_and_inherited_effective_read_grants() {
        let home = Home::new();
        let sid = current_sid();
        let system = "S-1-5-18";
        let administrators = "S-1-5-32-544";
        let direct = home.base.join("system and administrators container");
        fs::create_dir(&direct).unwrap();
        let grants = format!("(A;;FA;;;{system})(A;;FA;;;{administrators})(A;;0x00120089;;;WD)");
        set_container_sddl(&direct, &fixture_container_sddl(&sid, &grants));
        assert!(fixture_has_ace(
            &direct,
            system,
            FILE_ALL_ACCESS,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        assert!(fixture_has_ace(
            &direct,
            administrators,
            FILE_ALL_ACCESS,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        assert!(fixture_has_ace(
            &direct,
            "S-1-1-0",
            0x0012_0089,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        let before_direct_open = fixture_acl_snapshot(&direct, &sid, true);
        let direct_container = OwnedContainer::open(&direct).unwrap();
        assert_fixture_acl_unchanged(
            &direct,
            &sid,
            true,
            &before_direct_open,
            "SYSTEM/Admin container open",
        );
        let before_direct_check = fixture_acl_snapshot(&direct, &sid, true);
        direct_container.check().unwrap();
        assert_fixture_acl_unchanged(
            &direct,
            &sid,
            true,
            &before_direct_check,
            "SYSTEM/Admin container check",
        );
        assert!(fixture_has_ace(
            &direct,
            system,
            FILE_ALL_ACCESS,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        assert!(fixture_has_ace(
            &direct,
            administrators,
            FILE_ALL_ACCESS,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));

        let parent = home.base.join("inherited effective container parent");
        fs::create_dir(&parent).unwrap();
        let inherited_grants = format!("(A;CI;FA;;;{sid})(A;CI;0x00120089;;;WD)");
        set_container_sddl(&parent, &fixture_container_sddl(&sid, &inherited_grants));
        let child = parent.join("inherited child");
        fs::create_dir(&child).unwrap();
        let before_owner_change = fixture_acl_snapshot(&child, &sid, true);
        set_fixture_owner(&child, &sid, true);
        let after_owner_change = fixture_acl_snapshot(&child, &sid, true);
        assert!(after_owner_change.facts.owner_matches_current);
        assert!(!after_owner_change.facts.owner_matches_administrators);
        assert!(
            !after_owner_change.facts.dacl_protected,
            "the inherited DACL must remain unprotected"
        );
        assert_eq!(
            before_owner_change.facts.dacl_present,
            after_owner_change.facts.dacl_present
        );
        assert_eq!(
            before_owner_change.facts.dacl_protected,
            after_owner_change.facts.dacl_protected
        );
        assert_eq!(
            fixture_normalized_dacl(&before_owner_change),
            fixture_normalized_dacl(&after_owner_change),
            "owner-only adjustment must preserve the exact inherited DACL bytes and ACE flags"
        );
        let inherited_flags = (INHERITED_ACE | CONTAINER_INHERIT_ACE) as u8;
        assert!(fixture_has_ace(
            &child,
            &sid,
            FILE_ALL_ACCESS,
            inherited_flags,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        assert!(
            fixture_has_ace(
                &child,
                "S-1-1-0",
                0x0012_0089,
                inherited_flags,
                ACCESS_ALLOWED_ACE_TYPE
            ),
            "fixture must install and read back genuine inherited-effective ACEs"
        );
        let before_open = fixture_acl_snapshot(&child, &sid, true);
        let container = OwnedContainer::open(&child)
            .expect("an effective inherited read grant owned by TokenUser is acceptable");
        assert_fixture_acl_unchanged(&child, &sid, true, &before_open, "inherited container open");
        let before_check = fixture_acl_snapshot(&child, &sid, true);
        container.check().unwrap();
        assert_fixture_acl_unchanged(
            &child,
            &sid,
            true,
            &before_check,
            "inherited container check",
        );
    }

    #[test]
    fn owned_container_excludes_valid_inherit_only_grants_from_current_policy() {
        let home = Home::new();
        let sid = current_sid();
        let path = home.base.join("inherit-only container");
        fs::create_dir(&path).unwrap();
        let grants = "(A;IOCI;0x001F01FF;;;WD)";
        set_container_sddl(&path, &fixture_container_sddl(&sid, grants));
        let expected_flags = (INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE) as u8;
        assert!(
            fixture_has_ace(
                &path,
                "S-1-1-0",
                FILE_ALL_ACCESS,
                expected_flags,
                ACCESS_ALLOWED_ACE_TYPE
            ),
            "fixture must install and read back a valid inherit-only full-control ACE"
        );
        let before_open = fixture_acl_snapshot(&path, &sid, true);
        let container = OwnedContainer::open(&path)
            .expect("inherit-only ACE is not an effective grant on the container");
        assert_fixture_acl_unchanged(
            &path,
            &sid,
            true,
            &before_open,
            "inherit-only container open",
        );
        let before_check = fixture_acl_snapshot(&path, &sid, true);
        container.check().unwrap();
        assert_fixture_acl_unchanged(
            &path,
            &sid,
            true,
            &before_check,
            "inherit-only container check",
        );
        assert!(fixture_has_ace(
            &path,
            "S-1-1-0",
            FILE_ALL_ACCESS,
            expected_flags,
            ACCESS_ALLOWED_ACE_TYPE
        ));
    }

    #[test]
    fn owned_container_rejects_dangerous_generic_concrete_and_unknown_rights() {
        let home = Home::new();
        let sid = current_sid();
        // Raw unsupported access flags are covered by the platform's parser-only
        // unit: the native security setter need not retain those requested bits.
        let grants = [
            ("generic-write", 0x4000_0000),
            ("generic-all", 0x1000_0000),
            ("write-data", 0x0000_0002),
            ("append-data", 0x0000_0004),
            ("write-ea", 0x0000_0010),
            ("delete-child", 0x0000_0040),
            ("write-attributes", 0x0000_0100),
            ("delete", 0x0001_0000),
            ("write-dac", 0x0004_0000),
            ("write-owner", 0x0008_0000),
        ];
        for (label, mask) in grants {
            let path = home.base.join(format!("unsafe container {label}"));
            fs::create_dir(&path).unwrap();
            let deny_write_data = if label == "write-data" {
                format!("(D;;0x{mask:08X};;;WD)")
            } else {
                String::new()
            };
            let acl = fixture_container_sddl(
                &sid,
                &format!("(A;;0x00120089;;;WD){deny_write_data}(A;;0x{mask:08X};;;WD)"),
            );
            set_container_sddl(&path, &acl);
            assert!(
                fixture_has_ace(&path, "S-1-1-0", mask, 0, ACCESS_ALLOWED_ACE_TYPE),
                "the Windows fixture must retain {label} mask {mask:#010x}"
            );
            if label == "write-data" {
                assert!(
                    fixture_has_ace(&path, "S-1-1-0", mask, 0, ACCESS_DENIED_ACE_TYPE),
                    "the real deny ACE must precede the unsafe allow fixture"
                );
            }
            let before = fixture_acl_snapshot(&path, &sid, true);
            let error = match OwnedContainer::open(&path) {
                Ok(_) => panic!("OwnedContainer accepted {label} access mask {mask:#010x}"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{label}"
            );
            assert_eq!(
                error.to_string(),
                "container grants an untrusted principal mutation rights",
                "{label}"
            );
            assert_fixture_acl_unchanged(&path, &sid, true, &before, &format!("{label} refusal"));
        }
    }

    #[test]
    fn owned_container_rejects_null_dacl_and_wrong_owner() {
        let home = Home::new();
        let sid = current_sid();
        let null_dacl = home.base.join("null dacl container");
        fs::create_dir(&null_dacl).unwrap();
        set_container_sddl(&null_dacl, &format!("O:{sid}D:NO_ACCESS_CONTROL"));
        assert!(
            fixture_dacl_is_null(&null_dacl),
            "fixture must retain a present null DACL"
        );
        let before_null_refusal = fixture_acl_snapshot(&null_dacl, &sid, true);
        let null_error = match OwnedContainer::open(&null_dacl) {
            Ok(_) => panic!("OwnedContainer accepted a null DACL"),
            Err(error) => error,
        };
        assert_eq!(null_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            null_error.to_string(),
            "container requires a present, non-null DACL"
        );
        assert_fixture_acl_unchanged(
            &null_dacl,
            &sid,
            true,
            &before_null_refusal,
            "null-DACL refusal",
        );
        assert!(
            fixture_dacl_is_null(&null_dacl),
            "refusal must not repair the null DACL"
        );

        let wrong_owner = home.base.join("wrong owner container");
        fs::create_dir(&wrong_owner).unwrap();
        set_container_sddl(
            &wrong_owner,
            &fixture_container_sddl("S-1-5-32-544", "(A;;0x00120089;;;WD)"),
        );
        let wrong_owner_facts = fixture_acl_snapshot(&wrong_owner, &sid, true).facts;
        assert!(
            !wrong_owner_facts.owner_matches_current,
            "fixture owner must differ from TokenUser: {wrong_owner_facts:?}"
        );
        assert!(
            wrong_owner_facts.owner_matches_administrators,
            "fixture owner must be the explicit Administrators SID: {wrong_owner_facts:?}"
        );
        assert!(
            fixture_has_ace(
                &wrong_owner,
                "S-1-1-0",
                0x0012_0089,
                0,
                ACCESS_ALLOWED_ACE_TYPE
            ),
            "wrong-owner fixture must retain the readable access ACE"
        );
        let before_wrong_owner = fixture_acl_snapshot(&wrong_owner, &sid, true);
        let owner_error = match OwnedContainer::open(&wrong_owner) {
            Ok(_) => panic!("OwnedContainer accepted an Administrators-owned container"),
            Err(error) => error,
        };
        assert_eq!(owner_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            owner_error.to_string(),
            "container owner is not the effective token user"
        );
        assert_fixture_acl_unchanged(
            &wrong_owner,
            &sid,
            true,
            &before_wrong_owner,
            "wrong-owner refusal",
        );
    }

    #[test]
    fn owned_container_rechecks_identity_and_dacl_without_repair() {
        let home = Home::new();
        let sid = current_sid();
        let path = home.base.join("container policy recheck");
        fs::create_dir(&path).unwrap();
        set_container_sddl(&path, &fixture_container_sddl(&sid, "(A;;0x00120089;;;WD)"));
        let before_open = fixture_acl_snapshot(&path, &sid, true);
        let container = OwnedContainer::open(&path).unwrap();
        assert_fixture_acl_unchanged(&path, &sid, true, &before_open, "container open");
        let original_identity = container.identity();
        assert!(
            fs::rename(&path, home.base.join("container replacement")).is_err(),
            "the held container handle must block root replacement"
        );
        assert_eq!(container.identity(), original_identity);

        set_container_sddl(
            &path,
            &fixture_container_sddl(&sid, "(A;;0x00120089;;;WD)(A;;0x40000000;;;WD)"),
        );
        assert!(fixture_has_ace(
            &path,
            "S-1-1-0",
            0x4000_0000,
            0,
            ACCESS_ALLOWED_ACE_TYPE
        ));
        let before_mutation_recheck = fixture_acl_snapshot(&path, &sid, true);
        let mutation_error = container.check().unwrap_err();
        assert_eq!(mutation_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            mutation_error.to_string(),
            "container grants an untrusted principal mutation rights"
        );
        assert_fixture_acl_unchanged(
            &path,
            &sid,
            true,
            &before_mutation_recheck,
            "mutating-DACL recheck",
        );
        assert_eq!(container.identity(), original_identity);

        set_container_sddl(&path, &fixture_container_sddl(&sid, "(A;;0x00120089;;;WD)"));
        let before_reopen = fixture_acl_snapshot(&path, &sid, true);
        let reopened = OwnedContainer::open(&path).unwrap();
        assert_fixture_acl_unchanged(&path, &sid, true, &before_reopen, "container reopen");
        set_container_sddl(
            &path,
            &fixture_container_sddl("S-1-5-32-544", "(A;;0x00120089;;;WD)"),
        );
        let before_owner_recheck = fixture_acl_snapshot(&path, &sid, true);
        let owner_error = reopened.check().unwrap_err();
        assert_eq!(owner_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            owner_error.to_string(),
            "container owner is not the effective token user"
        );
        assert_fixture_acl_unchanged(
            &path,
            &sid,
            true,
            &before_owner_recheck,
            "wrong-owner recheck",
        );
    }

    #[test]
    fn absolute_drive_and_verbatim_aliases_keep_identity() {
        let home = Home::new();
        let alias = PathBuf::from(format!("\\\\?\\{}", home.path().display()));
        assert_eq!(
            Directory::open(&alias).unwrap().identity(),
            home.dir().identity()
        );
        for path in [
            "relative\\state",
            "C:state",
            "\\\\server\\share\\state",
            "\\\\?\\UNC\\server\\share\\state",
            "\\\\.\\C:\\state",
        ] {
            assert!(Directory::open(Path::new(path)).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn held_root_and_ancestor_cannot_be_swapped() {
        let home = Home::new();
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        assert!(fs::rename(&home.base, home.base.with_extension("swapped")).is_err());
        home.dir().check().unwrap();
    }

    #[test]
    fn file_keeps_ancestor_handles_after_directory_drop() {
        let mut home = Home::new();
        let file = home.dir().create_file(OsStr::new("held")).unwrap();
        drop(home.directory.take());
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        drop(file);
    }

    #[test]
    fn hardlinks_and_junctions_are_rejected() {
        let home = Home::new();
        drop(home.dir().create_file(OsStr::new("original")).unwrap());
        fs::hard_link(home.path().join("original"), home.path().join("alias")).unwrap();
        assert!(home.dir().open_file(OsStr::new("original")).is_err());
        assert!(home.dir().open_file(OsStr::new("alias")).is_err());
        let outside = home.base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary"), b"unchanged").unwrap();
        let junction = home.path().join("junction");
        let output = Command::new(command("cmd.exe"))
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().child(OsStr::new("junction"), false).is_err());
        assert!(Directory::open(&junction).is_err());
        assert_eq!(fs::read(outside.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn file_symlink_is_not_followed() {
        let home = Home::new();
        let outside = home.base.join("outside-file");
        fs::write(&outside, b"unchanged").unwrap();
        std::os::windows::fs::symlink_file(&outside, home.path().join("link")).unwrap();
        assert!(home.dir().open_file(OsStr::new("link")).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    }

    #[test]
    fn permissive_dacl_is_rejected_by_held_and_reopened_checks() {
        let home = Home::new();
        let output = Command::new(command("icacls.exe"))
            .arg(home.path())
            .args(["/grant", "*S-1-1-0:(F)"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().check().is_err());
        assert!(Directory::open(&home.path()).is_err());
    }

    #[test]
    fn wrong_owner_is_rejected() {
        let home = Home::new();
        let output = Command::new(command("icacls.exe"))
            .arg(home.path())
            .args(["/setowner", "*S-1-5-32-544"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture must actually change owner: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.dir().check().is_err());
        assert!(Directory::open(&home.path()).is_err());
    }

    #[test]
    fn publication_does_not_clobber_and_replace_retains_original() {
        let home = Home::new();
        let mut original = home.dir().create_file(OsStr::new("record")).unwrap();
        original.write_all(b"original").unwrap();
        let expected = original.identity();
        drop(original);
        let mut candidate = home.dir().create_file(OsStr::new("candidate")).unwrap();
        candidate.write_all(b"replacement").unwrap();
        assert!(
            home.dir()
                .publish_new(&candidate, OsStr::new("record"))
                .is_err()
        );
        assert_eq!(read(home.dir(), "record"), b"original");
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let receipt = home
            .dir()
            .replace(&candidate, OsStr::new("record"), expected, &lock)
            .unwrap();
        drop(candidate);
        assert_eq!(read(home.dir(), "record"), b"replacement");
        let backup = receipt.original_backup.unwrap();
        assert_eq!(
            home.dir()
                .open_file(&backup)
                .unwrap()
                .read_limited(1024)
                .unwrap(),
            b"original"
        );
    }

    #[test]
    fn replacement_requires_expected_identity_and_exclusive_lock() {
        let home = Home::new();
        let original = home.dir().create_file(OsStr::new("record")).unwrap();
        let mut wrong = original.identity();
        wrong.file[0] ^= 1;
        drop(original);
        let candidate = home.dir().create_file(OsStr::new("candidate")).unwrap();
        let shared = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), wrong, &shared)
                .is_err()
        );
        drop(shared);
        let exclusive = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .replace(&candidate, OsStr::new("record"), wrong, &exclusive)
                .is_err()
        );
        assert_eq!(read(home.dir(), "record"), b"");
    }

    fn child_lock(path: &Path, mode: &str, expected: bool) {
        child_lock_kind(path, mode, expected, false);
    }
    fn child_lock_kind(path: &Path, mode: &str, expected: bool, existing_only: bool) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::lock_child", "--nocapture"])
            .env("ORBIT_FS_LOCK_ROOT", path)
            .env("ORBIT_FS_LOCK_MODE", mode)
            .env(
                "ORBIT_FS_LOCK_EXISTING_ONLY",
                if existing_only { "yes" } else { "no" },
            )
            .env("ORBIT_FS_LOCK_EXPECT", if expected { "yes" } else { "no" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned lock child exceeded deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == "test windows::lock_child ... ok"),
            "owned child did not execute its named test: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Subprocess entry; the parent tests exercise both successful and denied
    // second-process locks. This helper is not counted as a foundation case.
    #[test]
    fn lock_child() {
        let Some(path) = std::env::var_os("ORBIT_FS_LOCK_ROOT") else {
            return;
        };
        let directory = Directory::open(Path::new(&path)).unwrap();
        let mode = if std::env::var("ORBIT_FS_LOCK_MODE").unwrap() == "shared" {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        };
        let acquired = if std::env::var("ORBIT_FS_LOCK_EXISTING_ONLY").as_deref() == Ok("yes") {
            directory
                .open_lock_existing(OsStr::new("stable.lock"), mode)
                .is_ok()
        } else {
            directory.try_lock(OsStr::new("stable.lock"), mode).is_ok()
        };
        assert_eq!(
            acquired,
            std::env::var("ORBIT_FS_LOCK_EXPECT").unwrap() == "yes"
        );
    }

    #[test]
    fn exclusive_lock_excludes_other_processes_and_releases() {
        let home = Home::new();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        child_lock(&home.path(), "shared", false);
        child_lock(&home.path(), "exclusive", false);
        assert!(
            fs::rename(
                home.path().join("stable.lock"),
                home.path().join("swapped.lock")
            )
            .is_err()
        );
        drop(held);
        child_lock(&home.path(), "exclusive", true);
    }

    #[test]
    fn missing_existing_lock_does_not_create_state() {
        let home = Home::new();
        let inventory = || {
            let mut names: Vec<_> = fs::read_dir(home.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = inventory();
        let error_kind = match home
            .dir()
            .open_lock_existing(OsStr::new("status.lock"), LockMode::Shared)
        {
            Ok(lock) => {
                drop(lock);
                None
            }
            Err(error) => Some(error.kind()),
        };
        assert_eq!(
            inventory(),
            before,
            "an existing-only lock request must not create state"
        );
        assert_eq!(error_kind, Some(std::io::ErrorKind::NotFound));
    }

    #[test]
    fn existing_lock_fixed_buffer_snapshot_and_cursor() {
        let home = Home::new();
        let initial = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let lock_identity = initial.identity();
        let mut seed = home.dir().create_file(OsStr::new("record.json")).unwrap();
        seed.write_all(b"credential-12345").unwrap();
        seed.sync_all().unwrap();
        let identity = seed.identity();
        drop(seed);
        drop(initial);
        let held = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(held.identity(), lock_identity);
        held.check().unwrap();
        let mut file = home.dir().open_file(OsStr::new("record.json")).unwrap();
        let before = file.snapshot().unwrap();
        assert_eq!(before.identity, identity);
        assert_eq!(before.length, 16);
        let mut buffer = [0u8; 8];
        assert_eq!(file.read_into(&mut buffer[..4]).unwrap(), 4);
        assert_eq!(&buffer[..4], b"cred");
        assert_eq!(file.read_into(&mut buffer[4..]).unwrap(), 4);
        assert_eq!(&buffer, b"credenti");
        // One extra caller-owned byte detects overflow of an eight-byte limit.
        let mut extra = [0u8; 1];
        assert_eq!(file.read_into(&mut extra).unwrap(), 1);
        assert_eq!(extra, [b'a']);
        assert_eq!(file.snapshot().unwrap(), before);
        held.check().unwrap();
        buffer.fill(0);
        extra.fill(0);
    }

    #[test]
    fn file_snapshot_detects_content_change() {
        let home = Home::new();
        let mut seed = home.dir().create_file(OsStr::new("record.json")).unwrap();
        seed.write_all(b"before").unwrap();
        seed.sync_all().unwrap();
        let identity = seed.identity();
        drop(seed);
        let file = home.dir().open_file(OsStr::new("record.json")).unwrap();
        let before = file.snapshot().unwrap();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let mut update = home
            .dir()
            .open_for_update(OsStr::new("record.json"), identity, &held)
            .unwrap();
        update.append_all(b" after").unwrap();
        update.sync_all().unwrap();
        drop(update);
        let after = file.snapshot().unwrap();
        assert_eq!(before.identity, after.identity);
        assert_eq!(before.length, 6);
        assert_eq!(after.length, 12);
        assert_ne!(before, after);
        assert!(after.last_write_time > 0 && after.change_time > 0);
    }

    #[test]
    fn existing_lock_rejects_nonempty_and_unsafe_without_repair() {
        let home = Home::new();
        drop(
            home.dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        fs::write(home.path().join("stable.lock"), b"invalid lock").unwrap();
        assert!(
            home.dir()
                .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
                .is_err()
        );
        assert!(
            home.dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .is_err()
        );
        assert_eq!(
            fs::read(home.path().join("stable.lock")).unwrap(),
            b"invalid lock"
        );
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);

        let unsafe_home = Home::new();
        drop(
            unsafe_home
                .dir()
                .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        let path = unsafe_home.path().join("stable.lock");
        assert!(
            Command::new(command("icacls.exe"))
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let before = Command::new(command("icacls.exe"))
            .arg(&path)
            .output()
            .unwrap();
        assert!(before.status.success());
        assert!(
            unsafe_home
                .dir()
                .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
                .is_err()
        );
        let after = Command::new(command("icacls.exe"))
            .arg(&path)
            .output()
            .unwrap();
        assert!(after.status.success());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn existing_only_locks_observe_cross_process_contention() {
        let home = Home::new();
        let initial = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Exclusive)
            .unwrap();
        let identity = initial.identity();
        drop(initial);
        let held = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        child_lock_kind(&home.path(), "shared", true, true);
        child_lock_kind(&home.path(), "exclusive", false, true);
        assert!(
            fs::rename(
                home.path().join("stable.lock"),
                home.path().join("moved.lock")
            )
            .is_err()
        );
        held.check().unwrap();
        drop(held);
        child_lock_kind(&home.path(), "exclusive", true, true);
        let reopened = home
            .dir()
            .open_lock_existing(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(reopened.identity(), identity);
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);
    }

    #[test]
    fn shared_readers_coexist_but_exclude_writer() {
        let home = Home::new();
        let held = home
            .dir()
            .try_lock(OsStr::new("stable.lock"), LockMode::Shared)
            .unwrap();
        child_lock(&home.path(), "shared", true);
        child_lock(&home.path(), "exclusive", false);
        drop(held);
        child_lock(&home.path(), "exclusive", true);
    }

    #[test]
    fn locked_update_has_explicit_cursor_append_length_and_truncate() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("ledger")).unwrap();
        file.write_all(b"abc").unwrap();
        let expected = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let mut update = home
            .dir()
            .open_for_update(OsStr::new("ledger"), expected, &lock)
            .unwrap();
        assert_eq!(update.length().unwrap(), 3);
        assert_eq!(update.seek(std::io::SeekFrom::Start(1)).unwrap(), 1);
        update.write_all(b"Z").unwrap();
        update.append_all(b"de").unwrap();
        assert_eq!(update.position().unwrap(), 5);
        update.truncate(2).unwrap();
        assert_eq!(update.position().unwrap(), 5);
        assert_eq!(update.length().unwrap(), 2);
        update.sync_all().unwrap();
        assert_eq!(update.read_limited(10).unwrap(), b"aZ");
        drop(update);
        let mut ordinary = home.dir().open_file(OsStr::new("ledger")).unwrap();
        assert!(ordinary.write_all(b"unsafe").is_err());
        assert_eq!(ordinary.read_limited(10).unwrap(), b"aZ");
    }

    #[test]
    fn lifecycle_rejects_wrong_identity_shared_and_foreign_guards() {
        let home = Home::new();
        let other = Home::new();
        let file = home.dir().create_file(OsStr::new("record")).unwrap();
        let expected = file.identity();
        drop(file);
        let shared = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), expected, &shared)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), expected, &shared)
                .is_err()
        );
        drop(shared);
        let foreign = other
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), expected, &foreign)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), expected, &foreign)
                .is_err()
        );
        let own = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let mut wrong = expected;
        wrong.file[0] ^= 1;
        assert!(
            home.dir()
                .open_for_update(OsStr::new("record"), wrong, &own)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("record"), wrong, &own)
                .is_err()
        );
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
    }

    #[test]
    fn checked_backup_restore_and_cleanup_preserve_identity() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("retained")).unwrap();
        file.write_all(b"original").unwrap();
        let expected = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = home
            .dir()
            .open_for_rename(OsStr::new("retained"), expected, &lock)
            .unwrap();
        let receipt = home
            .dir()
            .restore_backup(held, OsStr::new("record"))
            .unwrap();
        assert_eq!(receipt.identity, expected);
        assert_eq!(read(home.dir(), "record"), b"original");
        let held = home
            .dir()
            .open_for_rename(OsStr::new("record"), expected, &lock)
            .unwrap();
        let removed = home.dir().remove_file(held).unwrap();
        assert_eq!(removed.identity, expected);
        assert_eq!(removed.state, RemovalState::DispositionAcknowledged);
        assert!(home.dir().open_file(OsStr::new("record")).is_err());
    }

    #[test]
    fn restore_refuses_occupied_target_and_reparse_sources() {
        let home = Home::new();
        let file = home.dir().create_file(OsStr::new("retained")).unwrap();
        let expected = file.identity();
        drop(file);
        drop(home.dir().create_file(OsStr::new("occupied")).unwrap());
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = home
            .dir()
            .open_for_rename(OsStr::new("retained"), expected, &lock)
            .unwrap();
        assert!(
            home.dir()
                .restore_backup(held, OsStr::new("occupied"))
                .is_err()
        );
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("retained"))
                .unwrap()
                .identity(),
            expected
        );
        let outside = home.base.join("outside");
        fs::write(&outside, b"canary").unwrap();
        std::os::windows::fs::symlink_file(&outside, home.path().join("link")).unwrap();
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("link"), expected, &lock)
                .is_err()
        );
        assert_eq!(fs::read(outside).unwrap(), b"canary");
    }

    #[test]
    fn enumeration_is_bounded_and_revalidates_entries() {
        let home = Home::new();
        let a = home.dir().create_file(OsStr::new("entry 雪")).unwrap();
        let expected = a.identity();
        drop(a);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        let entries = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &lock,
            )
            .unwrap();
        assert_eq!(entries.len(), 2); // The stable lock is visible but cannot be mutated as data.
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.name == "entry 雪")
                .unwrap()
                .identity,
            expected
        );
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 1,
                        max_name_bytes: 1024
                    },
                    &lock
                )
                .is_err()
        );
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 1
                    },
                    &lock
                )
                .is_err()
        );
        drop(lock);
        fs::hard_link(home.path().join("entry 雪"), home.path().join("alias")).unwrap();
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Shared)
            .unwrap();
        assert!(
            home.dir()
                .enumerate(
                    EnumerationLimits {
                        max_entries: 8,
                        max_name_bytes: 1024
                    },
                    &lock
                )
                .is_err()
        );
    }

    #[test]
    fn empty_child_cleanup_refuses_live_anchors_nonempty_and_wrong_identity() {
        let home = Home::new();
        let child = home.dir().child(OsStr::new("child"), true).unwrap();
        let expected = child.identity();
        let file = child.create_file(OsStr::new("held")).unwrap();
        let held_id = file.identity();
        drop(file);
        let lock = home
            .dir()
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("child"), expected, &lock)
                .is_err()
        );
        let inner_lock = child
            .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
            .unwrap();
        let held = child
            .open_for_rename(OsStr::new("held"), held_id, &inner_lock)
            .unwrap();
        child.remove_file(held).unwrap();
        drop(inner_lock);
        drop(child);
        // A stable lock intentionally makes this directory nonempty.
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("child"), expected, &lock)
                .is_err()
        );
        let empty = home.dir().child(OsStr::new("empty"), true).unwrap();
        let empty_id = empty.identity();
        drop(empty);
        let mut wrong = empty_id;
        wrong.file[0] ^= 1;
        assert!(
            home.dir()
                .remove_empty_child(OsStr::new("empty"), wrong, &lock)
                .is_err()
        );
        assert_eq!(
            home.dir()
                .remove_empty_child(OsStr::new("empty"), empty_id, &lock)
                .unwrap()
                .identity,
            empty_id
        );
    }

    #[test]
    fn stable_lock_names_cannot_enter_data_mutation_routes() {
        let home = Home::new();
        assert!(
            home.dir()
                .try_lock(OsStr::new("not-reserved"), LockMode::Exclusive)
                .is_err()
        );
        let held = home
            .dir()
            .try_lock(OsStr::new("first.lock"), LockMode::Exclusive)
            .unwrap();
        let other = home
            .dir()
            .try_lock(OsStr::new("OTHER.LOCK"), LockMode::Exclusive)
            .unwrap();
        let snapshot = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &held,
            )
            .unwrap();
        let lock_id = snapshot
            .iter()
            .find(|entry| entry.name == "OTHER.LOCK")
            .unwrap()
            .identity;
        assert!(home.dir().create_file(OsStr::new("OTHER.LOCK")).is_err());
        assert!(
            home.dir()
                .open_for_update(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        let file = home.dir().create_file(OsStr::new("candidate")).unwrap();
        assert!(
            home.dir()
                .publish_new(&file, OsStr::new("OTHER.LOCK"))
                .is_err()
        );
        assert!(
            home.dir()
                .replace(&file, OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
        drop(other);
        assert!(
            home.dir()
                .open_for_rename(OsStr::new("OTHER.LOCK"), lock_id, &held)
                .is_err()
        );
    }

    #[test]
    fn inspection_empty_root_is_no_effect() {
        let home = Home::new();
        let before = tree_snapshot(&home.path());
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert!(inspected.entries.is_empty());
        assert_eq!(tree_snapshot(&home.path()), before);
        assert!(!home.path().join("inspection.lock").exists());
    }

    #[test]
    fn inspection_observes_existing_shared_lock_and_nested_files() {
        let home = Home::new();
        let root_path = home.path();
        let nested_path = root_path.join("nested");
        let nested = home.dir().child(OsStr::new("nested"), true).unwrap();
        let mut full = nested.create_file(OsStr::new("full.json")).unwrap();
        full.write_all(b"full control fixture").unwrap();
        let full_identity = full.identity();
        drop(full);

        let sid = current_sid();
        let mut read_only = home.dir().create_file(OsStr::new("read-only.dat")).unwrap();
        read_only.write_all(b"read-only fixture").unwrap();
        let read_only_identity = read_only.identity();
        drop(read_only);
        let read_only_path = root_path.join("read-only.dat");
        set_fixture_file_mask(&read_only_path, &sid, FILE_GENERIC_READ, 0);

        let mut read_execute = home
            .dir()
            .create_file(OsStr::new("read-execute.dat"))
            .unwrap();
        read_execute.write_all(b"read-execute fixture").unwrap();
        let read_execute_identity = read_execute.identity();
        drop(read_execute);
        let read_execute_path = root_path.join("read-execute.dat");
        set_fixture_file_mask(
            &read_execute_path,
            &sid,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            0,
        );

        let seed = home
            .dir()
            .try_lock(OsStr::new("existing.lock"), LockMode::Exclusive)
            .unwrap();
        let lock_identity = seed.identity();
        drop(seed);
        let shared = home
            .dir()
            .open_lock_existing(OsStr::new("existing.lock"), LockMode::Shared)
            .unwrap();
        assert_eq!(shared.identity(), lock_identity);
        shared.check().unwrap();

        let full_path = nested_path.join("full.json");
        let lock_path = root_path.join("existing.lock");
        let acl_before = [
            (
                root_path.as_path(),
                true,
                assert_fixture_acl(
                    &root_path,
                    &sid,
                    true,
                    FILE_ALL_ACCESS,
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                ),
            ),
            (
                nested_path.as_path(),
                true,
                assert_fixture_acl(
                    &nested_path,
                    &sid,
                    true,
                    FILE_ALL_ACCESS,
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                ),
            ),
            (
                full_path.as_path(),
                false,
                assert_fixture_acl(
                    &full_path,
                    &sid,
                    false,
                    FILE_ALL_ACCESS,
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                ),
            ),
            (
                read_only_path.as_path(),
                false,
                assert_fixture_acl(&read_only_path, &sid, false, FILE_GENERIC_READ, 0),
            ),
            (
                read_execute_path.as_path(),
                false,
                assert_fixture_acl(
                    &read_execute_path,
                    &sid,
                    false,
                    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                    0,
                ),
            ),
            (
                lock_path.as_path(),
                false,
                assert_fixture_acl(
                    &lock_path,
                    &sid,
                    false,
                    FILE_ALL_ACCESS,
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                ),
            ),
        ];
        let before = tree_snapshot(&root_path);
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert_eq!(inspected.entries.len(), 5);
        let get = |name: &str| {
            inspected
                .entries
                .iter()
                .find(|entry| entry.relative_path == Path::new(name))
                .unwrap_or_else(|| panic!("missing inspected entry {name}"))
        };
        assert!(get("nested").directory);
        assert_eq!(get("nested").identity, nested.identity());
        assert_eq!(get("nested").file_access, None);
        assert_eq!(get("nested").snapshot, None);

        let full_entry = get("nested/full.json");
        assert_eq!(full_entry.identity, full_identity);
        assert_eq!(full_entry.file_access, Some(PrivateFileAccess::FullControl));
        assert_eq!(full_entry.snapshot.unwrap().length, 20);

        let read_only_entry = get("read-only.dat");
        assert_eq!(read_only_entry.identity, read_only_identity);
        assert_eq!(
            read_only_entry.file_access,
            Some(PrivateFileAccess::ReadOnly)
        );
        assert_eq!(read_only_entry.snapshot.unwrap().length, 17);

        let read_execute_entry = get("read-execute.dat");
        assert_eq!(read_execute_entry.identity, read_execute_identity);
        assert_eq!(
            read_execute_entry.file_access,
            Some(PrivateFileAccess::ReadExecute)
        );
        assert_eq!(read_execute_entry.snapshot.unwrap().length, 20);

        let lock_entry = get("existing.lock");
        assert_eq!(lock_entry.identity, lock_identity);
        assert_eq!(lock_entry.file_access, Some(PrivateFileAccess::FullControl));
        assert_eq!(lock_entry.snapshot.unwrap().length, 0);
        assert_eq!(tree_snapshot(&root_path), before);
        for (path, directory, before_acl) in &acl_before {
            let after_acl = fixture_acl_snapshot(path, &sid, *directory);
            assert!(
                before_acl.normalized_descriptor == after_acl.normalized_descriptor,
                "inspection changed fixture ACL facts: before={:?}, after={:?}",
                before_acl.facts,
                after_acl.facts
            );
        }
        shared.check().unwrap();
    }

    #[test]
    fn inspection_rejects_permissive_and_wrong_owner_entries_without_repair() {
        let home = Home::new();
        let sid = current_sid();
        let nested = home.dir().child(OsStr::new("nested"), true).unwrap();
        drop(nested.create_file(OsStr::new("private.dat")).unwrap());
        let nested_path = home.path().join("nested");
        let private_acl = assert_fixture_acl(
            &nested_path,
            &sid,
            true,
            FILE_ALL_ACCESS,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        );
        home.dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .expect("valid nested fixture must pass before permissive mutation");

        run_icacls(&nested_path, &["/grant", "*S-1-1-0:(F)"]);
        let permissive_acl_before = fixture_acl_snapshot(&nested_path, &sid, true);
        let permissive_facts = &permissive_acl_before.facts;
        assert!(
            permissive_facts.owner_matches_current,
            "mutator changed fixture owner: {permissive_facts:?}"
        );
        assert!(
            permissive_facts.dacl_present,
            "mutator removed the DACL: {permissive_facts:?}"
        );
        assert!(
            permissive_facts.dacl_protected,
            "mutator unprotected the DACL: {permissive_facts:?}"
        );
        assert_eq!(
            permissive_facts.ace_count, 2,
            "mutator changed more than the intended ACE: {permissive_facts:?}"
        );
        assert!(
            permissive_facts.has_current_owner_full_control_ace,
            "effective current-owner full-control ACE is missing: {permissive_facts:?}"
        );
        assert!(
            permissive_facts.has_everyone_full_control_ace,
            "effective Everyone full-control ACE was not installed: {permissive_facts:?}"
        );
        assert!(private_acl.normalized_descriptor != permissive_acl_before.normalized_descriptor);

        let before = tree_snapshot(&home.path());
        let error = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .expect_err("actual Everyone full-control ACE must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(tree_snapshot(&home.path()), before);
        let permissive_acl_after = fixture_acl_snapshot(&nested_path, &sid, true);
        assert!(
            permissive_acl_before.normalized_descriptor
                == permissive_acl_after.normalized_descriptor,
            "inspection changed permissive fixture ACL facts: before={:?}, after={:?}",
            permissive_acl_before.facts,
            permissive_acl_after.facts
        );
        drop(nested);
        drop(home);

        let home = Home::new();
        let sid = current_sid();
        let mut record = home
            .dir()
            .create_file(OsStr::new("wrong-owner.dat"))
            .unwrap();
        record.write_all(b"owner fixture").unwrap();
        drop(record);
        let record_path = home.path().join("wrong-owner.dat");
        let private_acl = assert_fixture_acl(
            &record_path,
            &sid,
            false,
            FILE_ALL_ACCESS,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        );
        home.dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .expect("valid owner fixture must pass before owner mutation");

        run_icacls(&record_path, &["/setowner", "*S-1-5-32-544"]);
        let wrong_owner_acl_before = fixture_acl_snapshot(&record_path, &sid, false);
        let wrong_owner_facts = &wrong_owner_acl_before.facts;
        assert!(
            !wrong_owner_facts.owner_matches_current,
            "owner mutator did not change owner: {wrong_owner_facts:?}"
        );
        assert!(
            wrong_owner_facts.owner_matches_administrators,
            "fixture owner is not the requested built-in Administrators SID: {wrong_owner_facts:?}"
        );
        assert!(wrong_owner_facts.dacl_present && wrong_owner_facts.dacl_protected);
        assert_eq!(wrong_owner_facts.ace_count, 1);
        assert_eq!(
            wrong_owner_facts.first_ace_type,
            Some(ACCESS_ALLOWED_ACE_TYPE)
        );
        assert_eq!(
            wrong_owner_facts.first_ace_flags,
            Some((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8)
        );
        assert_eq!(wrong_owner_facts.first_ace_sid_matches_current, Some(true));
        assert_eq!(wrong_owner_facts.first_ace_mask, Some(FILE_ALL_ACCESS));
        assert!(wrong_owner_facts.has_current_owner_full_control_ace);
        assert!(!wrong_owner_facts.has_everyone_full_control_ace);
        assert!(private_acl.normalized_descriptor != wrong_owner_acl_before.normalized_descriptor);

        let before = tree_snapshot(&home.path());
        let error = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .expect_err("actual wrong owner must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(tree_snapshot(&home.path()), before);
        let wrong_owner_acl_after = fixture_acl_snapshot(&record_path, &sid, false);
        assert!(
            wrong_owner_acl_before.normalized_descriptor
                == wrong_owner_acl_after.normalized_descriptor,
            "inspection changed wrong-owner fixture ACL facts: before={:?}, after={:?}",
            wrong_owner_acl_before.facts,
            wrong_owner_acl_after.facts
        );
    }

    #[test]
    fn inspection_rejects_reparse_and_hardlink_entries() {
        let home = Home::new();
        let mut original = home.dir().create_file(OsStr::new("original.dat")).unwrap();
        original.write_all(b"hardlink fixture").unwrap();
        drop(original);
        fs::hard_link(
            home.path().join("original.dat"),
            home.path().join("alias.dat"),
        )
        .unwrap();
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);

        let home = Home::new();
        let outside = home.base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary"), b"unchanged").unwrap();
        let junction = home.path().join("junction");
        let output = Command::new(command("cmd.exe"))
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 4,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert_eq!(fs::read(outside.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn inspection_limits_reject_extra_entry_path_and_depth_without_changes() {
        let home = Home::new();
        drop(home.dir().create_file(OsStr::new("a")).unwrap());
        let one_entry = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 1,
                max_name_bytes: 2,
                max_depth: 1,
            })
            .unwrap();
        assert_eq!(one_entry.entries.len(), 1);

        drop(home.dir().create_file(OsStr::new("b")).unwrap());
        let before = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 1,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 3,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before);

        let child = home.dir().child(OsStr::new("nested"), true).unwrap();
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_ok()
        );
        drop(child.create_file(OsStr::new("leaf")).unwrap());
        let before_nested = tree_snapshot(&home.path());
        assert!(
            home.dir()
                .inspect_private_tree(InspectionLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                    max_depth: 1,
                })
                .is_err()
        );
        assert_eq!(tree_snapshot(&home.path()), before_nested);
    }

    #[test]
    fn inspection_holds_root_and_ancestors_while_walking() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("record")).unwrap();
        file.write_all(b"stable").unwrap();
        drop(file);
        let before = tree_snapshot(&home.path());
        let inspected = home
            .dir()
            .inspect_private_tree(InspectionLimits {
                max_entries: 8,
                max_name_bytes: 1024,
                max_depth: 4,
            })
            .unwrap();
        assert_eq!(inspected.root_identity, home.dir().identity());
        assert!(fs::rename(home.path(), home.base.join("replacement")).is_err());
        assert!(fs::rename(&home.base, home.base.with_extension("swapped")).is_err());
        assert_eq!(tree_snapshot(&home.path()), before);
    }

    #[test]
    fn published_candidate_cannot_be_republished_without_a_guard() {
        let home = Home::new();
        let mut file = home.dir().create_file(OsStr::new("candidate")).unwrap();
        file.write_all(b"published").unwrap();
        let expected = file.identity();
        home.dir().publish_new(&file, OsStr::new("record")).unwrap();
        assert!(home.dir().publish_new(&file, OsStr::new("moved")).is_err());
        assert!(file.write_all(b"unlocked").is_err());
        drop(file);
        assert_eq!(
            home.dir()
                .open_file(OsStr::new("record"))
                .unwrap()
                .identity(),
            expected
        );
        assert_eq!(read(home.dir(), "record"), b"published");
        assert!(home.dir().open_file(OsStr::new("moved")).is_err());
    }

    #[test]
    fn simultaneous_publication_preserves_the_only_successful_name() {
        let home = Home::new();
        for round in 0..8 {
            let file = home
                .dir()
                .create_file(OsStr::new(&format!("candidate-{round}")))
                .unwrap();
            let expected = file.identity();
            let left = format!("left-{round}");
            let right = format!("right-{round}");
            let barrier = std::sync::Barrier::new(2);
            let (a, b) = std::thread::scope(|scope| {
                let first = scope.spawn(|| {
                    barrier.wait();
                    home.dir().publish_new(&file, OsStr::new(&left))
                });
                let second = scope.spawn(|| {
                    barrier.wait();
                    home.dir().publish_new(&file, OsStr::new(&right))
                });
                (first.join().unwrap(), second.join().unwrap())
            });
            assert_ne!(
                a.is_ok(),
                b.is_ok(),
                "expected exactly one publication: {a:?}, {b:?}"
            );
            let (winner, loser) = if a.is_ok() {
                (&left, &right)
            } else {
                (&right, &left)
            };
            drop(file);
            assert_eq!(
                home.dir().open_file(OsStr::new(winner)).unwrap().identity(),
                expected
            );
            assert!(home.dir().open_file(OsStr::new(loser)).is_err());
        }
    }

    #[test]
    fn ntfs_short_alias_cannot_bypass_reserved_lock_policy() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let home = Home::new();
        drop(
            home.dir()
                .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
                .unwrap(),
        );
        let guard = home
            .dir()
            .try_lock(OsStr::new("guard.lock"), LockMode::Exclusive)
            .unwrap();
        let entries = home
            .dir()
            .enumerate(
                EnumerationLimits {
                    max_entries: 8,
                    max_name_bytes: 1024,
                },
                &guard,
            )
            .unwrap();
        let expected = entries
            .iter()
            .find(|entry| entry.name == "transaction.lock")
            .unwrap()
            .identity;
        let long: Vec<u16> = home
            .path()
            .join("transaction.lock")
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut short = vec![0u16; 32768];
        let length = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
                long.as_ptr(),
                short.as_mut_ptr(),
                short.len() as u32,
            )
        };
        assert!(
            length > 0 && (length as usize) < short.len(),
            "8.3 fixture lookup failed: {}",
            std::io::Error::last_os_error()
        );
        let short = PathBuf::from(std::ffi::OsString::from_wide(&short[..length as usize]));
        let alias = short.file_name().unwrap();
        assert!(
            orbit_platform::fs::validate_data_component(alias).is_ok(),
            "fixture did not create an actual 8.3 alias: {alias:?}"
        );
        assert!(home.dir().open_file(alias).is_err());
        assert!(home.dir().open_for_update(alias, expected, &guard).is_err());
        assert!(home.dir().open_for_rename(alias, expected, &guard).is_err());
        assert!(home.dir().try_lock(alias, LockMode::Exclusive).is_err());
        drop(guard);
        drop(
            home.dir()
                .try_lock(OsStr::new("transaction.lock"), LockMode::Exclusive)
                .unwrap(),
        );
    }
    mod execution_oracle {
        use super::*;
        use orbit_platform::fs::{SourceFile, SourceSnapshot};
        use std::ffi::OsString;
        use std::io;
        use std::mem::size_of;
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        };
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
            TerminateProcess,
        };

        const META: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        const PENDING: i32 = 0x103;
        const DENIED: i32 = 0xc0000022u32 as i32;
        const ABSENT: i32 = 0xc0000034u32 as i32;
        const PAYLOAD: &[u8] = b"permission-native-fixture-v1";
        const LIMIT: usize = 65536;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(kind: u32) -> HANDLE;
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn RtlNtStatusToDosError(status: i32) -> u32;
        }

        fn bad(message: &'static str) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, message)
        }
        fn yes(value: i32) -> io::Result<()> {
            if value == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        fn require(value: bool, message: &'static str) -> io::Result<()> {
            if value { Ok(()) } else { Err(bad(message)) }
        }
        #[derive(Debug)]
        struct NativeOpenError {
            phase: &'static str,
            status: i32,
            desired: u32,
        }
        impl std::fmt::Display for NativeOpenError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} NTSTATUS=0x{:08x} desired=0x{:08x}",
                    self.phase, self.status as u32, self.desired
                )
            }
        }
        impl std::error::Error for NativeOpenError {}
        fn native_is(error: &io::Error, status: i32) -> bool {
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<NativeOpenError>())
                .is_some_and(|e| e.phase == "NtCreateFile" && e.status == status)
        }
        fn uncertain_request() -> ! {
            static MESSAGE: &[u8] = b"EXEC_ORACLE_UNCLASSIFIED: pending create/ownership unknown; no fixture completion or product RED; terminating without unwinding\r\n";
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
                let _ = TerminateProcess(GetCurrentProcess(), 0xe0150002);
            }
            std::process::abort()
        }
        #[derive(Default)]
        struct Handles {
            slots: Vec<Option<OwnedHandle>>,
            closed: Vec<String>,
        }
        impl Handles {
            fn own(&mut self, raw: HANDLE) -> usize {
                let index = self.slots.len();
                self.slots
                    .push(Some(unsafe { OwnedHandle::from_raw_handle(raw) }));
                index
            }
            fn raw(&self, index: usize) -> HANDLE {
                self.slots[index].as_ref().unwrap().as_raw_handle()
            }
            fn close(&mut self, index: usize) -> io::Result<()> {
                let owned = self.slots[index]
                    .take()
                    .ok_or_else(|| bad("oracle owner already consumed"))?;
                let raw = owned.into_raw_handle();
                if unsafe { CloseHandle(raw) } == 0 {
                    let error = io::Error::last_os_error();
                    self.closed.push(format!("{index}:close-error:{error}"));
                    Err(error)
                } else {
                    self.closed.push(format!("{index}:closed"));
                    Ok(())
                }
            }
            fn close_all(&mut self) -> Vec<String> {
                let mut errors = Vec::new();
                for index in 0..self.slots.len() {
                    if self.slots[index].is_some() {
                        if let Err(error) = self.close(index) {
                            errors.push(error.to_string());
                        }
                    }
                }
                errors
            }
        }
        fn relative(
            handles: &mut Handles,
            parent: HANDLE,
            name: &OsStr,
            directory: bool,
            disposition: u32,
            desired: u32,
            descriptor: *const SECURITY_DESCRIPTOR,
        ) -> io::Result<usize> {
            orbit_platform::fs::validate_component(name)?;
            let mut name_wide = name.encode_wide().collect::<Vec<_>>();
            require(
                name_wide.len() <= u16::MAX as usize / 2,
                "oracle native name too long",
            )?;
            let name = UNICODE_STRING {
                Length: (name_wide.len() * 2) as u16,
                MaximumLength: (name_wide.len() * 2) as u16,
                Buffer: name_wide.as_mut_ptr(),
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
            let mut iosb = IO_STATUS_BLOCK::default();
            iosb.Anonymous.Status = 0x6f736962;
            iosb.Information = usize::MAX;
            let status = unsafe {
                NtCreateFile(
                    &mut raw,
                    desired,
                    &attributes,
                    &mut iosb,
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
            if status == PENDING {
                uncertain_request();
            }
            if status != 0 {
                if !raw.is_null() {
                    uncertain_request();
                }
                println!(
                    "exec_oracle_native_open phase=NtCreateFile returned=0x{:08x} desired=0x{desired:08x} share=READ_WRITE",
                    status as u32
                );
                let kind =
                    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
                        .kind();
                return Err(io::Error::new(
                    kind,
                    NativeOpenError {
                        phase: "NtCreateFile",
                        status,
                        desired,
                    },
                ));
            }
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                uncertain_request();
            }
            let owner = handles.own(raw);
            println!(
                "exec_oracle_native_open phase=NtCreateFile returned=0x{:08x} desired=0x{desired:08x} share=READ_WRITE iosb_status=0x{:08x} information={}",
                status as u32,
                unsafe { iosb.Anonymous.Status } as u32,
                iosb.Information
            );
            Ok(owner)
        }
        fn info<T: Default>(handle: HANDLE, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
            let mut value = T::default();
            yes(unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    class,
                    (&mut value as *mut T).cast(),
                    size_of::<T>() as u32,
                )
            })?;
            Ok(value)
        }
        fn identity(handle: HANDLE) -> io::Result<FileIdentity> {
            let value: FILE_ID_INFO = info(handle, FileIdInfo)?;
            Ok(FileIdentity {
                volume: value.VolumeSerialNumber,
                file: value.FileId.Identifier,
            })
        }
        fn kind(handle: HANDLE, directory: bool) -> io::Result<()> {
            let tag: FILE_ATTRIBUTE_TAG_INFO = info(handle, FileAttributeTagInfo)?;
            let standard: FILE_STANDARD_INFO = info(handle, FileStandardInfo)?;
            require(
                tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    && standard.Directory == directory
                    && !standard.DeletePending
                    && (directory || standard.NumberOfLinks == 1),
                "oracle kind/reparse/link/delete-pending mismatch",
            )
        }
        fn snapshot(handle: HANDLE) -> io::Result<SourceSnapshot> {
            kind(handle, false)?;
            let standard: FILE_STANDARD_INFO = info(handle, FileStandardInfo)?;
            let basic: FILE_BASIC_INFO = info(handle, FileBasicInfo)?;
            require(
                standard.EndOfFile >= 0
                    && basic.FileAttributes
                        & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                        == 0,
                "oracle sampled metadata kind or length mismatch",
            )?;
            Ok(SourceSnapshot {
                identity: identity(handle)?,
                length: standard.EndOfFile as u64,
                last_write_time: basic.LastWriteTime,
                change_time: basic.ChangeTime,
                attributes: basic.FileAttributes,
                kind: SourceKind::File,
                link_count: standard.NumberOfLinks as u32,
            })
        }
        fn sid_bytes(sid: PSID, base: *const u8, length: usize) -> io::Result<Vec<u8>> {
            require(
                !sid.is_null() && sid as usize % 4 == 0,
                "oracle SID absent or misaligned",
            )?;
            let offset = (sid as usize)
                .checked_sub(base as usize)
                .ok_or_else(|| bad("oracle SID outside buffer"))?;
            require(
                offset.checked_add(8).is_some_and(|end| end <= length),
                "oracle SID prefix outside buffer",
            )?;
            let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
            let bytes = 8 + 4 * count;
            require(
                count <= 15 && offset.checked_add(bytes).is_some_and(|end| end <= length),
                "oracle SID tail outside buffer",
            )?;
            yes(unsafe { IsValidSid(sid) })?;
            require(
                unsafe { GetLengthSid(sid) } as usize == bytes,
                "oracle SID length disagreement",
            )?;
            Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), bytes) }.to_vec())
        }
        fn sid_text(bytes: &[u8]) -> io::Result<String> {
            let mut aligned = vec![0u32; bytes.len().div_ceil(4)];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    aligned.as_mut_ptr().cast(),
                    bytes.len(),
                );
            }
            let mut text = null_mut();
            yes(unsafe { ConvertSidToStringSidW(aligned.as_mut_ptr().cast(), &mut text) })?;
            let allocation = LocalSecurityAllocation(text.cast());
            let mut length = 0;
            while unsafe { *text.add(length) } != 0 {
                length += 1;
            }
            let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
                .map_err(|_| bad("oracle SID text encoding"))?;
            drop(allocation);
            Ok(value)
        }
        fn descriptor(key: &TokenKey, mask: u32) -> io::Result<Vec<usize>> {
            let user = sid_text(&key.user)?;
            let group = sid_text(&key.group)?;
            let text = wide(OsStr::new(&format!(
                "O:{user}G:{group}D:P(A;;0x{mask:08x};;;{user})"
            )));
            let mut raw = null_mut();
            let mut returned = 0;
            yes(unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut raw,
                    &mut returned,
                )
            })?;
            let allocation = LocalSecurityAllocation(raw.cast());
            let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
            require(
                length > 0 && length <= LIMIT && length == returned as usize,
                "oracle descriptor length invalid",
            )?;
            let mut bytes = vec![0usize; length.div_ceil(size_of::<usize>())];
            unsafe {
                std::ptr::copy_nonoverlapping(raw.cast::<u8>(), bytes.as_mut_ptr().cast(), length);
            }
            drop(allocation);
            Ok(bytes)
        }
        #[derive(Clone, Debug, Eq, PartialEq)]
        struct TokenKey {
            thread_token: bool,
            token_type: i32,
            impersonation: Option<i32>,
            token_id: (u32, i32),
            authentication_id: (u32, i32),
            modified_id: (u32, i32),
            user: Vec<u8>,
            group: Vec<u8>,
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
            require(
                first == 0
                    && error == ERROR_INSUFFICIENT_BUFFER
                    && needed > 0
                    && needed as usize <= LIMIT,
                "oracle token sizing failed",
            )?;
            let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
            let capacity = words.len() * size_of::<usize>();
            yes(unsafe {
                GetTokenInformation(
                    handle,
                    class,
                    words.as_mut_ptr().cast(),
                    capacity as u32,
                    &mut needed,
                )
            })?;
            require(
                needed > 0 && needed as usize <= capacity,
                "oracle token result exceeds buffer",
            )?;
            Ok(TokenBuffer {
                words,
                length: needed as usize,
            })
        }
        fn token_value<T: Copy>(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<T> {
            let buffer = token_buffer(handle, class)?;
            require(buffer.length >= size_of::<T>(), "short token structure")?;
            Ok(unsafe { buffer.words.as_ptr().cast::<T>().read() })
        }
        fn token_key(handle: HANDLE, thread_token: bool) -> io::Result<TokenKey> {
            let first: TOKEN_STATISTICS = token_value(handle, TokenStatistics)?;
            let user_buffer = token_buffer(handle, TokenUser)?;
            require(
                user_buffer.length >= size_of::<TOKEN_USER>(),
                "short token user",
            )?;
            let user = unsafe { &*user_buffer.words.as_ptr().cast::<TOKEN_USER>() };
            let user = sid_bytes(
                user.User.Sid,
                user_buffer.words.as_ptr().cast(),
                user_buffer.length,
            )?;
            let group_buffer = token_buffer(handle, TokenPrimaryGroup)?;
            require(
                group_buffer.length >= size_of::<TOKEN_PRIMARY_GROUP>(),
                "short token group",
            )?;
            let group = unsafe { &*group_buffer.words.as_ptr().cast::<TOKEN_PRIMARY_GROUP>() };
            let group = sid_bytes(
                group.PrimaryGroup,
                group_buffer.words.as_ptr().cast(),
                group_buffer.length,
            )?;
            let final_stats: TOKEN_STATISTICS = token_value(handle, TokenStatistics)?;
            let luid = |value: LUID| (value.LowPart, value.HighPart);
            require(
                luid(first.TokenId) == luid(final_stats.TokenId)
                    && luid(first.AuthenticationId) == luid(final_stats.AuthenticationId)
                    && luid(first.ModifiedId) == luid(final_stats.ModifiedId)
                    && first.TokenType == final_stats.TokenType,
                "original token changed within capture",
            )?;
            let impersonation = if first.TokenType == TokenImpersonation {
                let level: i32 = token_value(handle, TokenImpersonationLevel)?;
                require(
                    level == first.ImpersonationLevel,
                    "token impersonation level disagreement",
                )?;
                Some(level)
            } else {
                require(first.TokenType == TokenPrimary, "unknown token type")?;
                None
            };
            Ok(TokenKey {
                thread_token,
                token_type: first.TokenType,
                impersonation,
                token_id: luid(first.TokenId),
                authentication_id: luid(first.AuthenticationId),
                modified_id: luid(first.ModifiedId),
                user,
                group,
            })
        }
        fn effective(handles: &mut Handles) -> io::Result<(usize, TokenKey)> {
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
                yes(unsafe {
                    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
                })?;
            }
            let index = handles.own(raw);
            let key = token_key(handles.raw(index), thread)?;
            Ok((index, key))
        }
        fn stable_context(
            handles: &mut Handles,
            original: usize,
            key: &TokenKey,
        ) -> io::Result<()> {
            require(
                token_key(handles.raw(original), key.thread_token)? == *key,
                "retained original token changed",
            )?;
            let (fresh, current) = effective(handles)?;
            let stable = current == *key;
            handles.close(fresh)?;
            require(stable, "effective original token context changed")
        }
        #[derive(Clone, Debug, Eq, PartialEq)]
        struct SecurityFacts {
            owner: Vec<u8>,
            group: Vec<u8>,
            dacl: Vec<u8>,
            control: u16,
        }
        struct ReadDescriptor {
            words: Vec<usize>,
            facts: SecurityFacts,
        }
        fn read_descriptor(
            handle: HANDLE,
            key: &TokenKey,
            mask: u32,
        ) -> io::Result<ReadDescriptor> {
            let mut owner = null_mut();
            let mut group = null_mut();
            let mut dacl = null_mut();
            let mut raw = null_mut();
            let result = unsafe {
                GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    &mut group,
                    &mut dacl,
                    null_mut(),
                    &mut raw,
                )
            };
            if result != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(result as i32));
            }
            let allocation = LocalSecurityAllocation(raw.cast());
            yes(unsafe { IsValidSecurityDescriptor(raw) })?;
            let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
            require(
                length >= size_of::<SECURITY_DESCRIPTOR_RELATIVE>() && length <= LIMIT,
                "oracle descriptor bound exceeded",
            )?;
            let mut words = vec![0usize; length.div_ceil(size_of::<usize>())];
            unsafe {
                std::ptr::copy_nonoverlapping(raw.cast::<u8>(), words.as_mut_ptr().cast(), length);
            }
            drop(allocation);
            let ptr = words.as_mut_ptr().cast();
            yes(unsafe { IsValidSecurityDescriptor(ptr) })?;
            let mut control = 0;
            let mut revision = 0;
            yes(unsafe { GetSecurityDescriptorControl(ptr, &mut control, &mut revision) })?;
            require(
                control & (SE_DACL_PROTECTED | SE_DACL_PRESENT | SE_SELF_RELATIVE)
                    == SE_DACL_PROTECTED | SE_DACL_PRESENT | SE_SELF_RELATIVE,
                "oracle descriptor control invalid",
            )?;
            let mut defaulted = 0;
            let mut present = 0;
            yes(unsafe { GetSecurityDescriptorOwner(ptr, &mut owner, &mut defaulted) })?;
            yes(unsafe { GetSecurityDescriptorGroup(ptr, &mut group, &mut defaulted) })?;
            yes(unsafe {
                GetSecurityDescriptorDacl(ptr, &mut present, &mut dacl, &mut defaulted)
            })?;
            let owner = sid_bytes(owner, words.as_ptr().cast(), length)?;
            let group = sid_bytes(group, words.as_ptr().cast(), length)?;
            require(
                owner == key.user && group == key.group && present != 0 && !dacl.is_null(),
                "oracle owner/group/DACL mismatch",
            )?;
            let offset = (dacl as usize)
                .checked_sub(words.as_ptr() as usize)
                .ok_or_else(|| bad("DACL outside descriptor"))?;
            require(
                offset
                    .checked_add(size_of::<ACL>())
                    .is_some_and(|end| end <= length),
                "short DACL",
            )?;
            let acl_length = unsafe { (*dacl).AclSize } as usize;
            require(
                acl_length >= size_of::<ACL>()
                    && offset
                        .checked_add(acl_length)
                        .is_some_and(|end| end <= length),
                "DACL outside buffer",
            )?;
            yes(unsafe { IsValidAcl(dacl) })?;
            require(
                unsafe { (*dacl).AceCount } == 1,
                "oracle DACL has extra ACEs",
            )?;
            let mut ace = null_mut();
            yes(unsafe { GetAce(dacl, 0, &mut ace) })?;
            let ace_offset = (ace as usize)
                .checked_sub(dacl as usize)
                .ok_or_else(|| bad("ACE outside DACL"))?;
            require(
                ace_offset
                    .checked_add(size_of::<ACE_HEADER>())
                    .is_some_and(|end| end <= acl_length),
                "short ACE",
            )?;
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            require(
                header.AceType == ACCESS_ALLOWED_ACE_TYPE
                    && header.AceFlags == 0
                    && header.AceSize as usize >= offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
                    && ace_offset
                        .checked_add(header.AceSize as usize)
                        .is_some_and(|end| end <= acl_length),
                "noncanonical fixture ACE",
            )?;
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
            require(
                allowed.Mask == mask
                    && sid_bytes(sid, ace.cast(), header.AceSize as usize)? == key.user,
                "oracle ACE mask/SID mismatch",
            )?;
            let dacl_bytes =
                unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), acl_length) }.to_vec();
            Ok(ReadDescriptor {
                words,
                facts: SecurityFacts {
                    owner,
                    group,
                    dacl: dacl_bytes,
                    control,
                },
            })
        }
        fn access_check(descriptor: &ReadDescriptor, duplicate: HANDLE) -> io::Result<bool> {
            let mut mapping = GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            };
            let mut privileges =
                vec![0usize; size_of::<PRIVILEGE_SET>().div_ceil(size_of::<usize>())];
            for attempt in 0..2 {
                let capacity = privileges.len() * size_of::<usize>();
                let mut needed = capacity as u32;
                let mut granted = 0;
                let mut allowed = 0;
                let succeeded = unsafe {
                    AccessCheck(
                        descriptor.words.as_ptr().cast_mut().cast(),
                        duplicate,
                        FILE_EXECUTE,
                        &mut mapping,
                        privileges.as_mut_ptr().cast(),
                        &mut needed,
                        &mut granted,
                        &mut allowed,
                    )
                };
                if succeeded == 0 {
                    let error = unsafe { GetLastError() };
                    if attempt == 0
                        && error == ERROR_INSUFFICIENT_BUFFER
                        && needed as usize > capacity
                        && needed as usize <= LIMIT
                    {
                        privileges = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
                        continue;
                    }
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                require(
                    needed as usize <= capacity,
                    "AccessCheck privilege length exceeds buffer",
                )?;
                let set = privileges.as_ptr().cast::<PRIVILEGE_SET>();
                let count = unsafe { (*set).PrivilegeCount } as usize;
                let end = count
                    .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
                    .and_then(|tail| tail.checked_add(offset_of!(PRIVILEGE_SET, Privilege)))
                    .ok_or_else(|| bad("AccessCheck privilege count overflow"))?;
                require(
                    end <= capacity && end <= needed as usize,
                    "AccessCheck privilege records exceed output",
                )?;
                let executable = allowed != 0;
                require(
                    granted == if executable { FILE_EXECUTE } else { 0 },
                    "AccessCheck granted-mask disagreement",
                )?;
                println!(
                    "exec_oracle_access_check function_bool={succeeded} access_status={allowed} desired=0x{FILE_EXECUTE:08x} granted=0x{granted:08x} privilege_count={count} privilege_bytes={needed}"
                );
                return Ok(executable);
            }
            Err(bad("AccessCheck retry exhausted"))
        }
        #[derive(Debug)]
        struct Entry {
            name: OsString,
            mask: u32,
            id: Option<FileIdentity>,
            facts: Option<SecurityFacts>,
            snapshot: Option<SourceSnapshot>,
            observed: Option<bool>,
            removed: bool,
        }
        struct Fixture {
            handles: Handles,
            key: Option<TokenKey>,
            original: Option<usize>,
            duplicate: Option<usize>,
            temp: Option<usize>,
            temp_id: Option<FileIdentity>,
            root: Option<usize>,
            root_id: Option<FileIdentity>,
            root_name: OsString,
            path: PathBuf,
            entries: Vec<Entry>,
            directory: Option<SourceDirectory>,
            sources: Vec<SourceFile>,
        }
        impl Fixture {
            fn new() -> Self {
                static SERIAL: AtomicU64 = AtomicU64::new(0);
                let name = OsString::from(format!(
                    "orbit-exec-permission-{}-{}",
                    std::process::id(),
                    SERIAL.fetch_add(1, Ordering::Relaxed)
                ));
                Self {
                    handles: Handles::default(),
                    key: None,
                    original: None,
                    duplicate: None,
                    temp: None,
                    temp_id: None,
                    root: None,
                    root_id: None,
                    path: std::env::temp_dir().join(&name),
                    root_name: name,
                    entries: Vec::new(),
                    directory: None,
                    sources: Vec::new(),
                }
            }
            fn create(&mut self) -> io::Result<()> {
                let (original, key) = effective(&mut self.handles)?;
                self.original = Some(original);
                self.key = Some(key.clone());
                println!("exec_oracle_original_context={key:?}");
                let level = key.impersonation.unwrap_or(SecurityImpersonation);
                let mut raw = null_mut();
                yes(unsafe {
                    DuplicateTokenEx(
                        self.handles.raw(original),
                        TOKEN_QUERY,
                        null(),
                        level,
                        TokenImpersonation,
                        &mut raw,
                    )
                })?;
                let duplicate = self.handles.own(raw);
                self.duplicate = Some(duplicate);
                let duplicate_stats: TOKEN_STATISTICS =
                    token_value(self.handles.raw(duplicate), TokenStatistics)?;
                require(
                    duplicate_stats.TokenType == TokenImpersonation
                        && duplicate_stats.ImpersonationLevel == level,
                    "AccessCheck duplicate type/level invalid",
                )?;
                println!(
                    "exec_oracle_accesscheck_duplicate type={} level={} id=({},{}) diagnostic_only=true",
                    duplicate_stats.TokenType,
                    duplicate_stats.ImpersonationLevel,
                    duplicate_stats.TokenId.LowPart,
                    duplicate_stats.TokenId.HighPart
                );
                let temp_path = wide(std::env::temp_dir().as_os_str());
                let raw = unsafe {
                    CreateFileW(
                        temp_path.as_ptr(),
                        FILE_LIST_DIRECTORY
                            | FILE_ADD_SUBDIRECTORY
                            | FILE_DELETE_CHILD
                            | FILE_TRAVERSE
                            | META,
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
                let temp = self.handles.own(raw);
                self.temp = Some(temp);
                kind(raw, true)?;
                self.temp_id = Some(identity(raw)?);
                let security = descriptor(&key, FILE_ALL_ACCESS)?;
                let root = relative(
                    &mut self.handles,
                    raw,
                    &self.root_name,
                    true,
                    FILE_CREATE,
                    FILE_ALL_ACCESS & !DELETE,
                    security.as_ptr().cast(),
                )?;
                self.root = Some(root);
                let root_raw = self.handles.raw(root);
                kind(root_raw, true)?;
                self.root_id = Some(identity(root_raw)?);
                let _ = read_descriptor(root_raw, &key, FILE_ALL_ACCESS)?;
                for (name, mask) in [
                    ("permission-r", FILE_GENERIC_READ),
                    ("permission-rx", FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
                    ("permission-full", FILE_ALL_ACCESS),
                ] {
                    self.entries.push(Entry {
                        name: OsString::from(name),
                        mask,
                        id: None,
                        facts: None,
                        snapshot: None,
                        observed: None,
                        removed: false,
                    });
                    let index = self.entries.len() - 1;
                    let writer = relative(
                        &mut self.handles,
                        root_raw,
                        OsStr::new(name),
                        false,
                        FILE_CREATE,
                        FILE_ALL_ACCESS,
                        security.as_ptr().cast(),
                    )?;
                    let raw = self.handles.raw(writer);
                    kind(raw, false)?;
                    self.entries[index].id = Some(identity(raw)?);
                    let _ = read_descriptor(raw, &key, FILE_ALL_ACCESS)?;
                    let mut written = 0;
                    yes(unsafe {
                        WriteFile(
                            raw,
                            PAYLOAD.as_ptr(),
                            PAYLOAD.len() as u32,
                            &mut written,
                            null_mut(),
                        )
                    })?;
                    require(
                        written as usize == PAYLOAD.len(),
                        "short execution fixture write",
                    )?;
                    yes(unsafe { FlushFileBuffers(raw) })?;
                    let final_sd = descriptor(&key, mask)?;
                    let mut present = 0;
                    let mut dacl = null_mut();
                    let mut defaulted = 0;
                    yes(unsafe {
                        GetSecurityDescriptorDacl(
                            final_sd.as_ptr().cast_mut().cast(),
                            &mut present,
                            &mut dacl,
                            &mut defaulted,
                        )
                    })?;
                    require(
                        present != 0 && !dacl.is_null(),
                        "execution fixture sealing DACL missing",
                    )?;
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
                    let actual = read_descriptor(raw, &key, mask)?;
                    self.entries[index].facts = Some(actual.facts);
                    self.handles.close(writer)?;
                    // Windows can finalize write metadata when the last writer
                    // closes. Freeze only after that checked close, independently.
                    let baseline = relative(
                        &mut self.handles,
                        root_raw,
                        OsStr::new(name),
                        false,
                        FILE_OPEN,
                        META,
                        null(),
                    )?;
                    let baseline_raw = self.handles.raw(baseline);
                    let sampled = snapshot(baseline_raw)?;
                    require(
                        Some(sampled.identity) == self.entries[index].id
                            && read_descriptor(baseline_raw, &key, mask)?.facts
                                == *self.entries[index].facts.as_ref().unwrap(),
                        "fixture identity or policy changed after writer close",
                    )?;
                    self.entries[index].snapshot = Some(sampled);
                    self.handles.close(baseline)?;
                }
                self.directory = Some(SourceDirectory::open(&self.path)?);
                require(
                    self.directory.as_ref().unwrap().identity() == self.root_id.unwrap(),
                    "source root full ID mismatch",
                )?;
                Ok(())
            }
            fn collect(&mut self) -> io::Result<()> {
                let key = self.key.as_ref().unwrap().clone();
                let original = self.original.unwrap();
                let duplicate = self.duplicate.unwrap();
                let root = self.handles.raw(self.root.unwrap());
                for index in 0..3 {
                    stable_context(&mut self.handles, original, &key)?;
                    let source = self
                        .directory
                        .as_ref()
                        .unwrap()
                        .open_file(&self.entries[index].name)?;
                    self.sources.push(source);
                    let before = self.sources[index].snapshot()?;
                    require(
                        Some(before) == self.entries[index].snapshot,
                        "source snapshot differs from independently sealed fixture",
                    )?;
                    require(
                        self.sources[index].read_limited(4096)? == PAYLOAD,
                        "source fixture bytes differ",
                    )?;
                    let meta = relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        META,
                        null(),
                    )?;
                    let meta_raw = self.handles.raw(meta);
                    require(
                        snapshot(meta_raw)? == before,
                        "metadata baseline identity/snapshot differs",
                    )?;
                    let sd = read_descriptor(meta_raw, &key, self.entries[index].mask)?;
                    require(
                        Some(&sd.facts) == self.entries[index].facts.as_ref(),
                        "descriptor changed before AccessCheck",
                    )?;
                    let reader = relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        FILE_GENERIC_READ,
                        null(),
                    )?;
                    let read_raw = self.handles.raw(reader);
                    require(
                        snapshot(read_raw)? == before,
                        "independent data-view snapshot differs",
                    )?;
                    let mut bytes = [0u8; 128];
                    let mut count = 0;
                    yes(unsafe {
                        ReadFile(
                            read_raw,
                            bytes.as_mut_ptr(),
                            bytes.len() as u32,
                            &mut count,
                            null_mut(),
                        )
                    })?;
                    require(
                        &bytes[..count as usize] == PAYLOAD,
                        "independent native bytes differ",
                    )?;
                    self.handles.close(reader)?;
                    let access = access_check(&sd, self.handles.raw(duplicate))?;
                    let native = match relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        META | FILE_EXECUTE,
                        null(),
                    ) {
                        Ok(execute) => {
                            require(
                                snapshot(self.handles.raw(execute))? == before,
                                "native execute-open snapshot differs",
                            )?;
                            require(
                                read_descriptor(
                                    self.handles.raw(execute),
                                    &key,
                                    self.entries[index].mask,
                                )?
                                .facts
                                    == sd.facts,
                                "execute-open descriptor differs",
                            )?;
                            self.handles.close(execute)?;
                            true
                        }
                        Err(error) if native_is(&error, DENIED) => false,
                        Err(error) => return Err(error),
                    };
                    require(
                        access == native && access == [false, true, true][index],
                        "AccessCheck/native execute oracle disagreement",
                    )?;
                    require(
                        read_descriptor(meta_raw, &key, self.entries[index].mask)?.facts
                            == sd.facts
                            && snapshot(meta_raw)? == before
                            && self.sources[index].snapshot()? == before,
                        "fixture descriptor or sampled metadata changed during permission oracles",
                    )?;
                    stable_context(&mut self.handles, original, &key)?;
                    self.handles.close(meta)?;
                    self.entries[index].observed = Some(access);
                    println!(
                        "exec_oracle_case_complete name={:?} mask=0x{:08x} full_id={:?} owner={:?} group={:?} descriptor={:?} snapshot={before:?} AccessCheck={access} native_execute_open={native} expected={} metadata_baseline=success bytes_verified=true original_context_stable=true",
                        self.entries[index].name,
                        self.entries[index].mask,
                        before.identity,
                        sd.facts.owner,
                        sd.facts.group,
                        sd.facts,
                        [false, true, true][index]
                    );
                }
                // Resample all three after collection, before the first product call.
                for index in 0..3 {
                    let meta = relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        META,
                        null(),
                    )?;
                    require(
                        snapshot(self.handles.raw(meta))? == self.entries[index].snapshot.unwrap()
                            && read_descriptor(
                                self.handles.raw(meta),
                                &key,
                                self.entries[index].mask,
                            )?
                            .facts
                                == *self.entries[index].facts.as_ref().unwrap()
                            && self.sources[index].snapshot()?
                                == self.entries[index].snapshot.unwrap(),
                        "all-three final oracle stability check failed",
                    )?;
                    self.handles.close(meta)?;
                }
                stable_context(&mut self.handles, original, &key)?;
                self.handles.close(duplicate)?;
                self.handles.close(original)?;
                require(
                    self.entries.iter().all(|entry| entry.observed.is_some()),
                    "native oracle collection incomplete",
                )?;
                for (index, slot) in self.handles.slots.iter().enumerate() {
                    require(
                        slot.is_none() || Some(index) == self.temp || Some(index) == self.root,
                        "test-owned native oracle handle remained before completion marker",
                    )?;
                }
                println!(
                    "exec_permission_oracles_complete count=3 observations=false,true,true original_context={key:?} all_test_owned_query_handles_checked_closed=true first_product_call_not_yet_made=true"
                );
                Ok(())
            }
            fn product(&self) -> io::Result<()> {
                for index in 0..3 {
                    println!(
                        "exec_permission_product_call index={index} expected={} native_oracles_complete=3",
                        self.entries[index].observed.unwrap()
                    );
                    let observed = self.sources[index].execution_permission()?;
                    require(
                        observed.executable() == self.entries[index].observed.unwrap(),
                        "product execution permission differs from stable native oracles",
                    )?;
                }
                Ok(())
            }
            fn cleanup(&mut self) -> io::Result<()> {
                self.sources.clear();
                let key = self.key.as_ref().unwrap().clone();
                let root = self.handles.raw(self.root.unwrap());
                let root_id = self.root_id.unwrap();
                let listed = self
                    .directory
                    .as_ref()
                    .unwrap()
                    .enumerate(EnumerationLimits {
                        max_entries: 3,
                        max_name_bytes: 1024,
                    })?;
                require(
                    listed.len() == 3
                        && self.entries.iter().all(|entry| {
                            listed.iter().any(|seen| {
                                seen.name == entry.name && Some(seen.identity) == entry.id
                            })
                        }),
                    "fixture cleanup inventory differs",
                )?;
                for index in 0..3 {
                    let delete = relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        DELETE | META,
                        null(),
                    )?;
                    let raw = self.handles.raw(delete);
                    require(
                        Some(snapshot(raw)?) == self.entries[index].snapshot
                            && read_descriptor(raw, &key, self.entries[index].mask)?.facts
                                == *self.entries[index].facts.as_ref().unwrap(),
                        "fixture changed before checked cleanup",
                    )?;
                    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                    yes(unsafe {
                        SetFileInformationByHandle(
                            raw,
                            FileDispositionInfo,
                            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                            size_of::<FILE_DISPOSITION_INFO>() as u32,
                        )
                    })?;
                    self.handles.close(delete)?;
                    match relative(
                        &mut self.handles,
                        root,
                        &self.entries[index].name,
                        false,
                        FILE_OPEN,
                        META,
                        null(),
                    ) {
                        Err(error) if native_is(&error, ABSENT) => {}
                        Ok(found) => {
                            self.handles.close(found)?;
                            return Err(bad("fixture payload remains after deletion"));
                        }
                        Err(error) => return Err(error),
                    }
                    self.entries[index].removed = true;
                }
                require(
                    self.directory
                        .as_ref()
                        .unwrap()
                        .enumerate(EnumerationLimits {
                            max_entries: 3,
                            max_name_bytes: 1024,
                        })?
                        .is_empty(),
                    "fixture root not empty after cleanup",
                )?;
                drop(self.directory.take());
                self.handles.close(self.root.unwrap())?;
                let temp = self.handles.raw(self.temp.unwrap());
                require(
                    Some(identity(temp)?) == self.temp_id,
                    "temporary parent identity changed",
                )?;
                let delete = relative(
                    &mut self.handles,
                    temp,
                    &self.root_name,
                    true,
                    FILE_OPEN,
                    DELETE | META,
                    null(),
                )?;
                let raw = self.handles.raw(delete);
                kind(raw, true)?;
                require(
                    identity(raw)? == root_id,
                    "fixture root changed before deletion",
                )?;
                let _ = read_descriptor(raw, &key, FILE_ALL_ACCESS)?;
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                yes(unsafe {
                    SetFileInformationByHandle(
                        raw,
                        FileDispositionInfo,
                        (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                        size_of::<FILE_DISPOSITION_INFO>() as u32,
                    )
                })?;
                self.handles.close(delete)?;
                match relative(
                    &mut self.handles,
                    temp,
                    &self.root_name,
                    true,
                    FILE_OPEN,
                    META,
                    null(),
                ) {
                    Err(error) if native_is(&error, ABSENT) => {}
                    Ok(found) => {
                        self.handles.close(found)?;
                        return Err(bad("fixture root remains after deletion"));
                    }
                    Err(error) => return Err(error),
                }
                self.handles.close(self.temp.unwrap())?;
                require(
                    self.handles.slots.iter().all(Option::is_none),
                    "native owner remained after fixture teardown",
                )?;
                println!(
                    "exec_permission_fixture_teardown=complete payloads=3 root_absent=true acl_repair=false native_close_facts={:?}",
                    self.handles.closed
                );
                Ok(())
            }
            fn preserve(&mut self) -> Vec<String> {
                self.sources.clear();
                drop(self.directory.take());
                let errors = self.handles.close_all();
                println!(
                    "exec_permission_fixture_preserved non_authorizing=true path={:?} root={:?} entries={:?} close_facts={:?} close_errors={errors:?}",
                    self.path, self.root_id, self.entries, self.handles.closed
                );
                errors
            }
        }
        pub(super) fn run() -> io::Result<()> {
            let mut fixture = Fixture::new();
            if let Err(primary) = fixture.create().and_then(|_| fixture.collect()) {
                let close = fixture.preserve();
                return Err(io::Error::new(
                    primary.kind(),
                    format!(
                        "EXEC_ORACLE_SETUP_FAILURE; not a valid behavioral RED: {primary}; close_errors={close:?}"
                    ),
                ));
            }
            let product = fixture.product();
            if let Err(cleanup) = fixture.cleanup() {
                let close = fixture.preserve();
                return Err(io::Error::other(format!(
                    "EXEC_ORACLE_TEARDOWN_FAILURE; not a valid behavioral RED: {cleanup}; product={product:?}; close_errors={close:?}"
                )));
            }
            product.map_err(|error| io::Error::new(error.kind(), format!("product execution_permission failed after all three native oracles and checked teardown: {error}")))
        }
    }

    #[test]
    fn source_execution_permission_matches_native_r_rx_and_full_control() -> std::io::Result<()> {
        execution_oracle::run()
    }
}
