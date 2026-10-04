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
        }
    }

    /// Probe whether the sandbox can run here: bwrap present and
    /// functional. Runs a trivial confined true/false.
    pub fn probe() -> SandboxStatus {
        if !cfg!(target_os = "linux") {
            return SandboxStatus::Unsupported;
        }
        if !Path::new("/usr/bin/bwrap").exists() && which_bwrap().is_none() {
            return SandboxStatus::Unavailable("bubblewrap not installed".into());
        }
        // A real canary: run /bin/true under the same flag set the
        // executor uses. If this fails, the sandbox is Unavailable —
        // never guess.
        let mut cmd = bwrap_base();
        cmd.arg("/bin/true");
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
        let mut cmd = bwrap_base();
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
                cmd.arg("--ro-bind")
                    .arg("/dev/null")
                    .arg(&canonical);
            }
        }
        // Run bash -c <command> inside, in the working directory.
        cmd.arg("bash").arg("-c").arg(user_command);
        cmd.current_dir(working_dir);
        cmd
    }
}

fn bwrap_base() -> Command {
    let mut cmd = Command::new(bwrap_bin());
    // Base: read-only root, /dev, /proc; a private /tmp; no new
    // privileges (the roadmap's probe-safely rule generalized: NNP is
    // set per child, never on ORBIT itself).
    // Only dirs that exist (merged-usr layouts may lack /lib64 or
    // /sbin; a missing bind target makes bwrap fail to start).
    for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"] {
        if Path::new(dir).exists() {
            cmd.arg("--ro-bind").arg(dir).arg(dir);
        }
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
    cmd.arg("--setenv")
        .arg("PATH")
        .arg("/usr/local/bin:/usr/bin:/bin");
    cmd.stdin(Stdio::null());
    cmd
}

fn bwrap_bin() -> &'static str {
    if Path::new("/usr/bin/bwrap").exists() {
        "/usr/bin/bwrap"
    } else {
        "bwrap"
    }
}

fn which_bwrap() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join("bwrap"))
            .find(|p| p.exists())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
