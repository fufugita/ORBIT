//! Native initial tracer. Profile recovery and streaming input expand this proof.

#[cfg(windows)]
mod windows {
    use orbit_platform::fs::Directory;
    use orbit_platform::process::{Completion, SandboxSession, SpawnSpec};
    use std::ffi::OsStr;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

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
        let output = session
            .spawn(&spec(script, Duration::from_secs(30), 65536))
            .unwrap()
            .wait(&AtomicBool::new(false))
            .unwrap();
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
