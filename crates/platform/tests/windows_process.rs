//! Native initial tracer. Profile recovery and streaming input expand this proof.

#[cfg(windows)]
mod windows {
    use orbit_platform::fs::Directory;
    use orbit_platform::process::{Completion, SandboxSession, SpawnSpec, inspect_lpac_access};
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::*;

    struct AttributeList {
        buffer: Vec<usize>,
    }
    impl Drop for AttributeList {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.buffer.as_mut_ptr().cast());
            }
        }
    }
    struct AllocatedSid(PSID);
    impl Drop for AllocatedSid {
        fn drop(&mut self) {
            unsafe {
                FreeSid(self.0);
            }
        }
    }
    struct NeverResumed {
        process: OwnedHandle,
        _thread: OwnedHandle,
        job: OwnedHandle,
        assigned: bool,
    }
    impl Drop for NeverResumed {
        fn drop(&mut self) {
            unsafe {
                if self.assigned {
                    TerminateJobObject(self.job.as_raw_handle(), 1);
                } else {
                    TerminateProcess(self.process.as_raw_handle(), 1);
                }
                WaitForSingleObject(self.process.as_raw_handle(), 5000);
            }
        }
    }

    fn ordinary_appcontainer_token(session: &SandboxSession) -> OwnedHandle {
        let name: Vec<u16> = OsStr::new(session.profile_name())
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut sid = null_mut();
        assert!(unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) } >= 0);
        let sid = AllocatedSid(sid);
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut bytes = 0;
        assert_eq!(
            unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
        assert!(bytes > 0 && bytes <= 65536);
        let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut bytes)
            },
            0
        );
        let mut attributes = AttributeList { buffer };
        assert_ne!(
            unsafe {
                UpdateProcThreadAttribute(
                    attributes.buffer.as_mut_ptr().cast(),
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&capabilities as *const SECURITY_CAPABILITIES).cast(),
                    size_of::<SECURITY_CAPABILITIES>(),
                    null_mut(),
                    null(),
                )
            },
            0
        );
        // No LPAC opt-out attribute is set for this negative control.
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let system = PathBuf::from(&system_root).join("System32");
        let executable: Vec<u16> = system
            .join("cmd.exe")
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let directory: Vec<u16> = system.as_os_str().encode_wide().chain(Some(0)).collect();
        // Windows activation-context setup needs SystemRoot even though this
        // control never resumes. Do not inherit the operator's environment.
        let mut environment: Vec<u16> = OsStr::new("SystemRoot=").encode_wide().collect();
        environment.extend(system_root.encode_wide());
        environment.extend([0, 0]);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.buffer.as_mut_ptr().cast();
        let mut info = PROCESS_INFORMATION::default();
        let job = unsafe { CreateJobObjectW(null(), null()) };
        assert!(!job.is_null());
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                CreateProcessW(
                    executable.as_ptr(),
                    null_mut(),
                    null(),
                    null(),
                    0,
                    CREATE_SUSPENDED
                        | CREATE_NO_WINDOW
                        | CREATE_UNICODE_ENVIRONMENT
                        | EXTENDED_STARTUPINFO_PRESENT,
                    environment.as_ptr().cast(),
                    directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                )
            },
            0,
            "ordinary AppContainer creation: {}",
            std::io::Error::last_os_error()
        );
        let mut control = NeverResumed {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
            _thread: unsafe { OwnedHandle::from_raw_handle(info.hThread) },
            job,
            assigned: false,
        };
        assert_ne!(
            unsafe {
                AssignProcessToJobObject(
                    control.job.as_raw_handle(),
                    control.process.as_raw_handle(),
                )
            },
            0
        );
        control.assigned = true;
        let mut token = null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    control.process.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token,
                )
            },
            0
        );
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        assert_ne!(
            unsafe { TerminateJobObject(control.job.as_raw_handle(), 1) },
            0
        );
        assert_eq!(
            unsafe { WaitForSingleObject(control.process.as_raw_handle(), 5000) },
            WAIT_OBJECT_0
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        control.job.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    )
                },
                0
            );
            if accounting.ActiveProcesses == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "negative-control Job did not empty"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // The primary thread has never been resumed; the returned token remains
        // valid for inspection after observed process/group termination.
        drop(control);
        token
    }

    #[test]
    fn ordinary_appcontainer_does_not_pass_lpac_access_probe() {
        let session = SandboxSession::create().unwrap();
        let token = ordinary_appcontainer_token(&session);
        let access = inspect_lpac_access(token.as_handle()).unwrap();
        assert!(
            access.own_package_grant && access.all_application_packages_grant,
            "{access:?}"
        );
        assert!(!access.is_less_privileged());
        if let Some(evidence) = std::env::var_os("ORBIT_NATIVE_EVIDENCE_DIR") {
            std::fs::write(PathBuf::from(evidence).join("lpac-ordinary-control.txt"),
                format!("{access:?}\nprimary_thread_never_resumed=true\nobserved_job_active_processes=0\n")).unwrap();
        }
        drop(token);
        session.close().unwrap();
    }

    fn executable() -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os("ORBIT_TEST_POWERSHELL")
                .expect("native runner must supply actual PowerShell"),
        );
        assert!(path.is_absolute() && path.is_file());
        path
    }
    fn spec(script: String, timeout: Duration, output_limit: usize) -> SpawnSpec {
        SpawnSpec {
            executable: executable(),
            arguments: vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script,
            ],
            timeout,
            output_limit,
        }
    }
    fn literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn reachable_nonlocal_endpoint() -> SocketAddr {
        let candidates = ("api.github.com", 443)
            .to_socket_addrs()
            .expect("resolve the public TCP control endpoint");
        for endpoint in candidates.filter(|a| a.is_ipv4()).take(4) {
            let std::net::IpAddr::V4(ip) = endpoint.ip() else {
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
            if let Ok(control) =
                std::net::TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))
            {
                assert_eq!(control.peer_addr().unwrap(), endpoint);
                assert_ne!(
                    control.local_addr().unwrap().ip(),
                    endpoint.ip(),
                    "same-host endpoint is not an outbound control"
                );
                // Only the TCP handshake occurs; no application/secret payload is sent.
                drop(control);
                return endpoint;
            }
        }
        panic!("public nonlocal TCP control was unreachable; network proof is inconclusive");
    }

    #[test]
    fn powershell_lpac_reads_owned_resources_and_denies_ambient_authority() {
        let session = SandboxSession::create().expect("create ordinary-user profile");
        session
            .prepare_file(OsStr::new("seed.txt"), b"owned seed")
            .unwrap();
        let outside = std::env::temp_dir().join(format!("{}-outside", session.profile_name()));
        let directory = Directory::create(&outside).unwrap();
        let mut credential = directory
            .create_file(OsStr::new("credentials.json"))
            .unwrap();
        credential
            .write_all(b"fixture-secret-never-in-child")
            .unwrap();
        credential.sync_all().unwrap();
        let secret = outside.join("credentials.json");
        let outside_write = outside.join("forbidden.txt");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let probe = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        drop(listener.accept().unwrap());
        drop(probe);
        let nonlocal = reachable_nonlocal_endpoint();
        if let Some(evidence) = std::env::var_os("ORBIT_NATIVE_EVIDENCE_DIR") {
            std::fs::write(
                PathBuf::from(evidence).join("network-parent-control.txt"),
                format!("api.github.com TCP-only control connected to {nonlocal}\n"),
            )
            .unwrap();
        }
        assert!(
            std::env::var_os("ORBIT_FAKE_SECRET").is_some(),
            "parent canary missing"
        );
        let identity = std::env::var("ORBIT_TEST_POWERSHELL_ID").expect("actual family/version");
        let script = format!(
            r#"
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if ([IO.File]::ReadAllText('seed.txt') -ne 'owned seed') {{ throw 'owned read failed' }}
[IO.File]::WriteAllText('result.txt','owned write')
[Console]::WriteLine('ORBIT_PS:'+$PSVersionTable.PSEdition+':'+$PSVersionTable.PSVersion.ToString())
[Console]::WriteLine('MODULE:'+(Get-Date -Format yyyy))
function Expect-Denied([scriptblock]$Action) {{
  $denied=$false
  try {{ & $Action }} catch {{ $denied=$true }}
  if (-not $denied) {{ throw 'unexpected ambient authority' }}
}}
Expect-Denied {{ [IO.File]::ReadAllText({secret}) | Out-Null }}
Expect-Denied {{ [IO.File]::WriteAllText({outside},'bad') }}
function Expect-SocketPolicyDenied([string]$Address,[int]$Port,[string]$Label) {{
  $client=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,
    [Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
  $denied=$false
  try {{
    try {{
      $task=$client.ConnectAsync([Net.IPAddress]::Parse($Address),$Port)
      if (-not $task.Wait(5000)) {{ throw 'network result inconclusive: timeout' }}
    }} catch {{
      $cause=$_.Exception
      while ($cause.InnerException) {{ $cause=$cause.InnerException }}
      if (($cause -is [Net.Sockets.SocketException]) -and
          ($cause.SocketErrorCode -eq [Net.Sockets.SocketError]::AccessDenied)) {{
        $denied=$true
      }} else {{ throw }}
    }}
  }} finally {{ $client.Dispose() }}
  if (-not $denied) {{ throw ('network authority unexpectedly available: '+$Label) }}
  [Console]::WriteLine('NETWORK_POLICY_DENIED:'+$Label)
}}
Expect-SocketPolicyDenied '127.0.0.1' {port} 'loopback'
Expect-SocketPolicyDenied {nonlocal_ip} {nonlocal_port} 'nonlocal'
if ([Environment]::GetEnvironmentVariable('ORBIT_FAKE_SECRET')) {{ throw 'ambient secret leaked' }}
[Console]::WriteLine('DENIALS_OK')
"#,
            secret = literal(&secret.to_string_lossy()),
            outside = literal(&outside_write.to_string_lossy()),
            nonlocal_ip = literal(&nonlocal.ip().to_string()),
            nonlocal_port = nonlocal.port()
        );
        let child = session
            .spawn(&spec(script, Duration::from_secs(30), 65536))
            .unwrap();
        if let Some(evidence) = std::env::var_os("ORBIT_NATIVE_EVIDENCE_DIR") {
            std::fs::write(
                PathBuf::from(evidence).join("lpac-requested-token.txt"),
                format!("{:?}\n", child.evidence()),
            )
            .unwrap();
        }
        let output = child.wait(&AtomicBool::new(false)).unwrap();
        assert_eq!(output.completion, Completion::Exited);
        assert_eq!(
            output.code,
            0,
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.confinement.app_container
                && output.confinement.less_privileged
                && output.confinement.job_assigned_before_resume
        );
        assert_eq!(output.confinement.network_capabilities, 0);
        assert!(!output.confinement.all_application_packages_grant);
        assert!(output.confinement.own_package_grant);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&format!("ORBIT_PS:{identity}")));
        assert!(stdout.contains("MODULE:") && stdout.contains("DENIALS_OK"));
        assert!(stdout.contains("NETWORK_POLICY_DENIED:loopback"));
        assert!(stdout.contains("NETWORK_POLICY_DENIED:nonlocal"));
        assert!(!stdout.contains("fixture-secret-never-in-child"));
        assert_eq!(
            session.read_file(OsStr::new("result.txt"), 100).unwrap(),
            b"owned write"
        );
        assert!(!outside_write.exists());
        assert_eq!(
            std::fs::read(&secret).unwrap(),
            b"fixture-secret-never-in-child"
        );
        if let Some(evidence) = std::env::var_os("ORBIT_NATIVE_EVIDENCE_DIR") {
            std::fs::write(
                PathBuf::from(evidence).join("powershell-token.txt"),
                format!("{:?}\n{stdout}", output.confinement),
            )
            .unwrap();
        }
        session.close().unwrap();
        drop(credential);
        drop(directory);
        std::fs::remove_file(secret).unwrap();
        std::fs::remove_dir(outside).unwrap();
    }

    #[test]
    fn silent_powershell_deadline_observes_owned_completion() {
        let session = SandboxSession::create().unwrap();
        let started = Instant::now();
        let output = session
            .spawn(&spec(
                "Start-Sleep -Seconds 60".into(),
                Duration::from_secs(2),
                65536,
            ))
            .unwrap()
            .wait(&AtomicBool::new(false))
            .unwrap();
        assert_eq!(output.completion, Completion::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
        session.close().unwrap();
    }

    #[test]
    fn powershell_output_limit_observes_owned_completion() {
        let session = SandboxSession::create().unwrap();
        let output = session
            .spawn(&spec(
                "[Console]::Write('x'*200000)".into(),
                Duration::from_secs(30),
                4096,
            ))
            .unwrap()
            .wait(&AtomicBool::new(false))
            .unwrap();
        assert_eq!(output.completion, Completion::OutputLimit);
        assert!(output.stdout.len() + output.stderr.len() <= 4096);
        session.close().unwrap();
    }
}
