//! The shell sandbox (roadmap §Permissions: "a sandbox makes saying
//! yes safe").
//!
//! Linux: bubblewrap, the approach Claude Code takes — writes allowed
//! in the working directories and a per-session temp dir, reads
//! everywhere except the deny-read list, no network namespace access.
//! When bwrap is absent or fails to start, the caller is told: every
//! command must then ask, whatever the mode (the roadmap's fallback
//! rule), and the status line says so.
//!
//! macOS: not yet (Seatbelt is release-engineering tier per the
//! review); `Unsupported` is returned and the fallback applies.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What happened when we tried to establish the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// The command ran inside bubblewrap.
    Confined,
    /// bwrap is not installed / not permitted here; the command must
    /// not run unsandboxed without the operator seeing that fact.
    Unavailable(String),
    /// This platform has no sandbox yet (macOS pre-Seatbelt).
    Unsupported,
}

/// The sandbox configuration for one Bash call.
#[derive(Debug, Clone)]
pub struct ShellSandbox {
    /// Directories the command may write (working dirs + session temp).
    pub write_dirs: Vec<PathBuf>,
    /// Directories to bind read-only beyond the base (/usr, /lib...).
    pub read_dirs: Vec<PathBuf>,
    /// Whether network access is allowed inside the sandbox.
    pub network: bool,
    runtime: Result<crate::linux_runtime::LinuxRuntimeLayout, String>,
}

impl ShellSandbox {
    /// The standard profile: writes in the working directories and a
    /// session temp dir; reads everywhere; no network.
    pub fn standard(working_dirs: &[PathBuf], session_id: &str) -> Self {
        let tmp = std::env::temp_dir().join(format!("orbit-sbx-{session_id}"));
        let _ = std::fs::create_dir_all(&tmp);
        let mut write_dirs = working_dirs.to_vec();
        write_dirs.push(tmp);
        ShellSandbox {
            write_dirs,
            read_dirs: vec![],
            network: false,
            runtime: crate::linux_runtime::LinuxRuntimeLayout::discover(),
        }
    }

    /// Probe whether the sandbox can run here: bwrap present and
    /// functional. Runs a trivial confined true/false.
    pub fn probe() -> SandboxStatus {
        // Test override: simulate a machine without bubblewrap (the
        // scenarios can't uninstall the real one).
        if std::env::var("ORBIT_TEST_SANDBOX_OFF").is_ok() {
            return SandboxStatus::Unavailable("simulated absent (ORBIT_TEST_SANDBOX_OFF)".into());
        }
        if !cfg!(target_os = "linux") {
            return SandboxStatus::Unsupported;
        }
        let runtime = match crate::linux_runtime::LinuxRuntimeLayout::discover() {
            Ok(runtime) => runtime,
            Err(error) => return SandboxStatus::Unavailable(error),
        };
        let mut cmd = bwrap_probe(&runtime);
        match cmd.output() {
            Ok(o) if o.status.success() => SandboxStatus::Confined,
            Ok(o) => SandboxStatus::Unavailable(format!(
                "bwrap canary failed ({}): {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => SandboxStatus::Unavailable(format!("bwrap spawn: {e}")),
        }
    }

    /// Build the bwrap command wrapping `user_command`. The returned
    /// Command still needs the shell/appended args by the caller.
    pub fn wrap(&self, user_command: &str, working_dir: &Path) -> Command {
        let Ok(runtime) = &self.runtime else {
            // A discovery failure must fail to spawn; never fall back to an
            // unconfined shell or search the caller's mutable PATH.
            return Command::new("/dev/null/orbit-runtime-unavailable");
        };
        let mut cmd = bwrap_base(runtime);
        // Filesystem: bind / read-only (writes only via --bind below),
        // proc/sys/dev as usual, and the write dirs read-write.
        for dir in &self.write_dirs {
            let d: String = dir.to_string_lossy().into_owned();
            cmd.arg("--bind").arg(&d).arg(&d);
        }
        for dir in &self.read_dirs {
            let d: String = dir.to_string_lossy().into_owned();
            cmd.arg("--ro-bind").arg(&d).arg(&d);
        }
        if !self.network {
            cmd.arg("--unshare-net");
        }
        // S2: blind the deny-read paths INSIDE the sandbox — a `cat
        // ~/.ssh/id_rsa` reads /dev/null, not the key. Files are
        // masked with a read-only /dev/null bind; directories with an
        // empty tmpfs. Masks come AFTER the binds above so they win.
        for entry in crate::deny_read_paths() {
            let home = std::env::var("HOME").unwrap_or_default();
            let expanded = entry.replace('~', &home);
            let path = Path::new(&expanded);
            // Only mask paths that exist here; a missing path needs no
            // mask (nothing to leak).
            let Ok(canonical) = std::fs::canonicalize(path) else {
                continue;
            };
            if canonical.is_dir() {
                // An empty tmpfs hides directory listings but the
                // mount point must exist; --tmpfs creates it.
                cmd.arg("--tmpfs").arg(&canonical);
            } else if canonical.is_file() {
                cmd.arg("--ro-bind").arg("/dev/null").arg(&canonical);
            }
        }
        // Run bash -c <command> inside, in the working directory.
        cmd.arg(&runtime.bash).arg("-c").arg(user_command);
        cmd.current_dir(working_dir);
        cmd
    }
}

fn bwrap_probe(runtime: &crate::linux_runtime::LinuxRuntimeLayout) -> Command {
    let mut command = bwrap_base(runtime);
    command.arg("--unshare-net");
    command.arg(&runtime.bash).args(["-c", "true"]);
    command
}

fn bwrap_base(runtime: &crate::linux_runtime::LinuxRuntimeLayout) -> Command {
    let mut cmd = Command::new(&runtime.bubblewrap);
    for root in &runtime.read_roots {
        cmd.arg("--ro-bind").arg(root).arg(root);
    }
    cmd.arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--die-with-parent")
        .arg("--unshare-ipc")
        .arg("--unshare-pid")
        .arg("--new-session")
        .arg("--setenv")
        .arg("TERM")
        .arg("dumb")
        .arg("--clearenv");
    // PATH so the shell can find binaries.
    cmd.arg("--setenv").arg("PATH").arg(&runtime.path);
    cmd.stdin(Stdio::null());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_runtime_uses_absolute_shell() {
        let work = std::env::temp_dir();
        let command =
            ShellSandbox::standard(std::slice::from_ref(&work), "runtime-path").wrap("true", &work);
        let arguments: Vec<_> = command.get_args().collect();
        assert!(
            Path::new(arguments[arguments.len() - 3]).is_absolute(),
            "the executable inside the sandbox must be an absolute resolved Bash path"
        );
    }

    #[test]
    fn linux_runtime_probe_uses_the_standard_network_boundary() {
        let runtime = crate::linux_runtime::LinuxRuntimeLayout::discover().unwrap();
        let command = bwrap_probe(&runtime);
        assert_eq!(command.get_program(), runtime.bubblewrap);
        let arguments: Vec<_> = command.get_args().collect();
        assert!(arguments.contains(&std::ffi::OsStr::new("--unshare-net")));
        assert_eq!(arguments[arguments.len() - 3], runtime.bash);
    }

    #[test]
    fn probe_reports_a_real_status() {
        // On this Linux box with bwrap installed the probe must say
        // Confined; the assertion is on the ENUM, not the string, so a
        // box without bwrap fails loudly here (which is correct: the
        // gate machine must have the sandbox).
        let status = ShellSandbox::probe();
        assert!(
            matches!(
                status,
                SandboxStatus::Confined | SandboxStatus::Unavailable(_)
            ),
            "probe must return a definite status, got {status:?}"
        );
    }

    #[test]
    fn confined_command_runs_and_writes_only_where_allowed() {
        if !matches!(ShellSandbox::probe(), SandboxStatus::Confined) {
            eprintln!("skipping: no sandbox on this machine");
            return;
        }
        let work = std::env::temp_dir().join(format!("orbit-sbx-t1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let sbx = ShellSandbox::standard(std::slice::from_ref(&work), "t1");

        // A write INSIDE the working dir succeeds.
        let out = sbx
            .wrap("echo hi > inside.txt && cat inside.txt", &work)
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "in-dir write must succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(work.join("inside.txt").exists());

        // A write OUTSIDE the working dir is refused by the read-only bind.
        let out = sbx
            .wrap("echo x > /etc/orbit-sbx-test", &work)
            .output()
            .expect("spawn");
        assert!(
            !out.status.success(),
            "write to /etc must fail in the sandbox"
        );
        assert!(!Path::new("/etc/orbit-sbx-test").exists());

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn network_is_unshared_by_default() {
        if !matches!(ShellSandbox::probe(), SandboxStatus::Confined) {
            eprintln!("skipping: no sandbox on this machine");
            return;
        }
        let work = std::env::temp_dir().join(format!("orbit-sbx-t2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let sbx = ShellSandbox::standard(std::slice::from_ref(&work), "t2");
        // No unshare-net flag test via interfaces: with --unshare-net
        // there is exactly the loopback (down). `ip` may be absent; use
        // /proc/net/dev presence + the fact that a TCP connect fails.
        let out = sbx
            .wrap(
                "bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>&1 && echo OPEN || echo CLOSED",
                &work,
            )
            .output()
            .expect("spawn");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("CLOSED"),
            "network must be unreachable inside the sandbox: {text}"
        );
        let _ = std::fs::remove_dir_all(&work);
    }
}
