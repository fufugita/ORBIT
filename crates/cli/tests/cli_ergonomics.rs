//! Shell-facing output is usable directly; JSON stays an explicit interface.

use std::process::{Command, Output};

fn orbit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orbit"))
        .args(args)
        .env_clear()
        .output()
        .expect("CLI starts")
}

#[test]
fn completion_stdout_is_a_shell_script_and_json_remains_available() {
    for shell in ["bash", "zsh", "fish"] {
        let plain = orbit(&["completions", shell]);
        assert!(plain.status.success(), "{shell}: {:?}", plain.stderr);
        let script = String::from_utf8(plain.stdout).unwrap();
        assert!(
            script.starts_with('#'),
            "{shell}: missing shell script header"
        );
        assert!(!script.trim_start().starts_with('{'));
        if shell == "zsh" {
            assert!(script.lines().any(|line| line == "compdef _orbit orbit"));
            assert!(!script.lines().any(|line| line == "_orbit \"$@\""));
        }
        for verb in ["mcp", "compact", "recovery", "serve", "attach", "migrate"] {
            assert!(script.contains(verb), "{shell}: missing {verb}");
        }
        let json = orbit(&["completions", shell, "--json"]);
        assert!(json.status.success());
        let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(value["shell"], shell);
        assert_eq!(value["script"], script);
    }
}

#[test]
fn invalid_completion_arguments_fail_without_emitting_a_script() {
    for args in [
        vec!["completions", "powershell"],
        vec!["completions", "bash", "unexpected"],
        vec!["completions", "bash", "--json", "unexpected"],
    ] {
        let output = orbit(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ORBIT-E1101"));
    }
}

#[test]
fn help_exposes_supported_migration_and_session_controls() {
    let output = orbit(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for option in [
        "migrate --from claude",
        "completions bash|zsh|fish",
        "--bare",
        "--worktree",
        "--permission-mode",
        "--fallback-model",
        "--channels",
        "--channel-permissions",
    ] {
        assert!(help.contains(option), "missing supported control: {option}");
    }
}

#[cfg(unix)]
struct OutputFixture {
    root: std::path::PathBuf,
}

#[cfg(unix)]
impl OutputFixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("orbit-cli-output-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }

    fn run(&self, args: &[&str], stdout: std::process::Stdio) -> Output {
        use std::process::Stdio;

        Command::new(env!("CARGO_BIN_EXE_orbit"))
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", &self.root)
            .env("ORBIT_HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .expect("isolated CLI starts")
    }

    fn assert_no_session_setup(&self) {
        assert!(
            std::fs::read_dir(&self.root).unwrap().next().is_none(),
            "local output commands must not set up a provider or session"
        );
    }
}

#[cfg(unix)]
impl Drop for OutputFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn readerless_stdout() -> std::process::Stdio {
    use std::os::fd::OwnedFd;
    use std::process::Stdio;

    // Wait for the pipe's only reader to exit BEFORE starting ORBIT. Unlike
    // `orbit --help | head`, this cannot pass merely because the entire help
    // fit in the pipe before the consumer stopped reading.
    let mut reader = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let writer = reader.stdin.take().unwrap();
    assert!(reader.wait().unwrap().success());
    let writer: OwnedFd = writer.into();
    Stdio::from(writer)
}

#[cfg(unix)]
#[test]
fn local_cli_output_tolerates_a_consumer_that_already_closed_stdout() {
    let fixture = OutputFixture::new();
    for args in [
        vec!["--help"],
        vec!["provider", "--help"],
        vec!["--version"],
        vec!["help", "--json"],
        vec!["completions", "bash"],
        vec!["version"],
    ] {
        let output = fixture.run(&args, readerless_stdout());
        assert!(output.status.success(), "{args:?}: {:?}", output.stderr);
        assert!(output.stderr.is_empty(), "{args:?}: {:?}", output.stderr);
    }
    fixture.assert_no_session_setup();
}

#[cfg(unix)]
#[test]
fn a_closed_stdout_does_not_hide_failed_command_status() {
    let fixture = OutputFixture::new();
    let args = ["doctor", "--json"];
    let ordinary = fixture.run(&args, std::process::Stdio::piped());
    let report: serde_json::Value = serde_json::from_slice(&ordinary.stdout).unwrap();
    assert_eq!(report["report"]["ready"], false);
    assert_eq!(ordinary.status.code(), Some(1));
    let closed = fixture.run(&args, readerless_stdout());
    assert_eq!(closed.status.code(), ordinary.status.code());
    assert!(closed.stderr.is_empty(), "{:?}", closed.stderr);
    fixture.assert_no_session_setup();
}

#[cfg(target_os = "linux")]
#[test]
fn local_cli_output_reports_real_io_errors_without_a_print_panic() {
    let fixture = OutputFixture::new();
    for args in [vec!["--help"], vec!["completions", "bash"]] {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let output = fixture.run(&args, std::process::Stdio::from(full));
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("cannot write stdout"), "{args:?}: {error}");
        assert!(!error.contains("panicked"), "{args:?}: {error}");
    }
    fixture.assert_no_session_setup();
}

#[cfg(unix)]
struct SetupFixture {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
}

#[cfg(unix)]
impl SetupFixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("orbit-bare-setup-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(
            home.join("settings.toml"),
            "[[hooks]]\nevent = \"Setup\"\nmatcher = \"init\"\ncommand = \"printf setup > setup-hook-ran\"\ntimeout_secs = 1\n",
        )
        .unwrap();
        // An existing, valid settings file whose literal name resembles a flag.
        std::fs::write(root.join("--bare"), "").unwrap();
        Self { root, home }
    }

    fn assert_setup(&self, args: &[&str], hook_runs: bool) {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let settings = std::fs::read(self.home.join("settings.toml")).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_orbit"))
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", &self.root)
            .env("ORBIT_HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("init-only startup did not stop before provider/session setup: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let marker = self.root.join("setup-hook-ran");
        if hook_runs {
            assert_eq!(std::fs::read(&marker).unwrap(), b"setup", "{args:?}");
            std::fs::remove_file(marker).unwrap();
        } else {
            assert!(
                !marker.exists(),
                "bare startup ran the Setup hook: {args:?}"
            );
        }
        assert_eq!(
            std::fs::read(self.home.join("settings.toml")).unwrap(),
            settings
        );
        assert_eq!(std::fs::read_dir(&self.home).unwrap().count(), 1);
    }
}

#[cfg(unix)]
impl Drop for SetupFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
fn bare_flag_suppresses_setup_hooks_before_every_harness_entry() {
    for mode in [None, Some("chat"), Some("serve"), Some("headless")] {
        let fixture = SetupFixture::new();
        let mut args = match mode {
            Some("headless") => vec!["-p", "no provider request is permitted"],
            Some(command) => vec![command],
            None => Vec::new(),
        };
        args.push("--init-only");
        // Prove the configured hook executes before checking suppression.
        fixture.assert_setup(&args, true);
        args.push("--bare");
        fixture.assert_setup(&args, false);
    }
}

#[cfg(unix)]
#[test]
fn bare_words_in_prompt_settings_or_downstream_arguments_do_not_suppress_setup() {
    for args in [
        vec!["--init-only", "-p", "--bare"],
        vec!["--init-only", "--print", "--bare"],
        vec!["--init-only", "--settings", "--bare"],
        vec!["--init-only", "--append-system-prompt", "--bare"],
        vec![
            "mcp",
            "add",
            "fixture",
            "--init-only",
            "--",
            "/bin/echo",
            "--bare",
        ],
    ] {
        let fixture = SetupFixture::new();
        fixture.assert_setup(&args, true);
    }
}
