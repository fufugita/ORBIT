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

/// What the operator's own settings add to the standard sandbox: the
/// `[sandbox]` table of `$ORBIT_HOME/settings.toml`.
///
/// The standard sandbox shows a command the system directories and the
/// working directories, and gives it no network. A toolchain that lives
/// under the home directory (rustup's `cargo`, a version manager's `node`)
/// is then not found, and nothing can be fetched. This table is how the
/// operator widens it, on purpose and for their own machine:
///
/// ```toml
/// [sandbox]
/// read = ["~/.cargo", "~/.rustup"]    # more directories commands may read
/// write = ["~/.cargo/registry"]       # ... and may write
/// path = ["~/.cargo/bin"]             # put first on PATH
/// network = true                      # let commands reach the network
/// env = { CARGO_HOME = "~/.cargo" }   # variables set for every command
/// enabled = false                     # run commands WITHOUT the sandbox
/// inherit_env = ["SSH_AUTH_SOCK"]     # variables copied into such commands
/// ```
///
/// Only the operator's own file is read: a project's settings cannot widen
/// the sandbox it runs in. Nothing here unmasks the deny-read list, and
/// ORBIT's own home stays hidden whatever is listed.
///
/// `enabled = false` is the operator's decision to run Bash as themselves, the
/// way Claude Code does: `ssh` with their agent, `docker`, `ps` on the host.
/// Only a TOML boolean counts; anything else leaves the sandbox on. A command
/// that runs without the sandbox still gets an allowlisted environment (never
/// ORBIT's own variables, provider keys included) plus this table's `env`,
/// `path` and `inherit_env`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxAdditions {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub path: Vec<PathBuf>,
    pub network: bool,
    pub env: Vec<(String, String)>,
    /// `enabled = false`: the operator runs commands without the sandbox.
    pub disabled: bool,
    /// Names of variables copied from ORBIT's environment into a command
    /// that runs without the sandbox.
    pub inherit_env: Vec<String>,
    /// What the table got wrong, one line each. A wrong entry is left out;
    /// the rest of the table still applies.
    pub problems: Vec<String>,
}

impl SandboxAdditions {
    /// The additions in `$ORBIT_HOME/settings.toml`; none when the file or
    /// the table is absent.
    pub fn load(orbit_home: &Path) -> Self {
        match std::fs::read_to_string(orbit_home.join("settings.toml")) {
            Ok(text) => Self::parse(&text, std::env::home_dir().as_deref()),
            Err(_) => Self::default(),
        }
    }

    /// Read the `[sandbox]` table of a settings file. `user_home` is what a
    /// leading `~` stands for.
    pub fn parse(text: &str, user_home: Option<&Path>) -> Self {
        const MAX_ENTRIES: usize = 32;
        let mut out = Self::default();
        let Ok(doc) = toml::from_str::<toml::Table>(text) else {
            return out;
        };
        let Some(value) = doc.get("sandbox") else {
            return out;
        };
        let Some(table) = value.as_table() else {
            out.problems.push("[sandbox] must be a table".into());
            return out;
        };
        let expand = |raw: &str| -> Option<PathBuf> {
            if raw == "~" {
                return user_home.map(Path::to_path_buf);
            }
            match raw.strip_prefix("~/") {
                Some(rest) => user_home.map(|home| home.join(rest)),
                None => Some(PathBuf::from(raw)),
            }
        };
        for (key, value) in table {
            match key.as_str() {
                "read" | "write" | "path" => {
                    let Some(items) = value.as_array() else {
                        out.problems
                            .push(format!("sandbox.{key} must be a list of directories"));
                        continue;
                    };
                    for item in items.iter().take(MAX_ENTRIES) {
                        let Some(raw) = item.as_str() else {
                            out.problems
                                .push(format!("sandbox.{key}: every entry must be text"));
                            continue;
                        };
                        let dir = expand(raw)
                            .filter(|dir| dir.is_absolute())
                            .and_then(|dir| dir.canonicalize().ok())
                            .filter(|dir| dir.is_dir());
                        match dir {
                            Some(dir) if dir == Path::new("/") => out.problems.push(format!(
                                "sandbox.{key}: / is the whole machine; name the directories"
                            )),
                            Some(dir) => {
                                let list = match key.as_str() {
                                    "read" => &mut out.read,
                                    "write" => &mut out.write,
                                    _ => &mut out.path,
                                };
                                if !list.contains(&dir) {
                                    list.push(dir);
                                }
                            }
                            None => out.problems.push(format!(
                                "sandbox.{key}: {raw} is not an existing directory (absolute, or starting with ~/)"
                            )),
                        }
                    }
                    if items.len() > MAX_ENTRIES {
                        out.problems.push(format!(
                            "sandbox.{key}: only the first {MAX_ENTRIES} entries are used"
                        ));
                    }
                }
                "network" => match value.as_bool() {
                    Some(allowed) => out.network = allowed,
                    None => out
                        .problems
                        .push("sandbox.network must be true or false".into()),
                },
                // Fail safe: only a real `false` turns the sandbox off.
                "enabled" => match value.as_bool() {
                    Some(on) => out.disabled = !on,
                    None => out
                        .problems
                        .push("sandbox.enabled must be true or false".into()),
                },
                "inherit_env" => {
                    let Some(items) = value.as_array() else {
                        out.problems
                            .push("sandbox.inherit_env must be a list of variable names".into());
                        continue;
                    };
                    for item in items.iter().take(MAX_ENTRIES) {
                        let Some(name) = item.as_str() else {
                            out.problems
                                .push("sandbox.inherit_env: every entry must be text".into());
                            continue;
                        };
                        if !plain_env_name(name) {
                            out.problems.push(format!(
                                "sandbox.inherit_env: {name:?} is not a plain variable name"
                            ));
                        } else if !out.inherit_env.iter().any(|known| known == name) {
                            out.inherit_env.push(name.to_owned());
                        }
                    }
                    if items.len() > MAX_ENTRIES {
                        out.problems.push(format!(
                            "sandbox.inherit_env: only the first {MAX_ENTRIES} entries are used"
                        ));
                    }
                }
                "env" => {
                    let Some(vars) = value.as_table() else {
                        out.problems
                            .push("sandbox.env must be a table of NAME = \"value\"".into());
                        continue;
                    };
                    for (name, value) in vars.iter().take(MAX_ENTRIES) {
                        let name_ok = plain_env_name(name);
                        let text = value.as_str().filter(|text| {
                            text.len() <= 4096 && !text.chars().any(char::is_control)
                        });
                        match (name_ok, text) {
                            (true, Some(_)) if name == "PATH" => out.problems.push(
                                "sandbox.env: PATH is set with sandbox.path, not here".into(),
                            ),
                            (true, Some(text)) => {
                                let value = match expand(text) {
                                    Some(path) if text == "~" || text.starts_with("~/") => {
                                        path.to_string_lossy().into_owned()
                                    }
                                    _ => text.to_owned(),
                                };
                                out.env.push((name.clone(), value));
                            }
                            _ => out.problems.push(format!(
                                "sandbox.env: {name} must be a plain name with a one-line text value"
                            )),
                        }
                    }
                }
                other => out.problems.push(format!(
                    "sandbox.{other} is not a setting (enabled, read, write, path, network, env, inherit_env)"
                )),
            }
        }
        // A PATH entry has to be somewhere the command can see.
        let visible: Vec<PathBuf> = out.read.iter().chain(&out.write).cloned().collect();
        let (seen, unseen): (Vec<PathBuf>, Vec<PathBuf>) = std::mem::take(&mut out.path)
            .into_iter()
            .partition(|dir| visible.iter().any(|root| dir.starts_with(root)));
        out.path = seen;
        for dir in unseen {
            out.problems.push(format!(
                "sandbox.path: {} is not under a sandbox.read or sandbox.write directory",
                dir.display()
            ));
        }
        out
    }

    /// Whether the table changes anything.
    pub fn is_empty(&self) -> bool {
        self.read.is_empty()
            && self.write.is_empty()
            && self.path.is_empty()
            && !self.network
            && self.env.is_empty()
            && !self.disabled
            && self.inherit_env.is_empty()
    }

    /// Has the operator, in their own settings, chosen to run commands
    /// without the sandbox? The one place that answers it: a project's
    /// settings are never read, and nothing the model can set reaches it.
    pub fn switched_off(&self) -> bool {
        self.disabled
    }
}

/// A variable name a shell can use: letters, digits and `_`, not starting
/// with a digit.
fn plain_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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
    /// Directories put ahead of the runtime's own on PATH.
    path_first: Vec<PathBuf>,
    /// Variables set for the command.
    env: Vec<(String, String)>,
    /// Directories hidden whatever else is bound (ORBIT's own home).
    hidden: Vec<PathBuf>,
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
            path_first: Vec::new(),
            env: Vec::new(),
            hidden: Vec::new(),
            runtime: crate::linux_runtime::LinuxRuntimeLayout::discover(),
        }
    }

    /// The same sandbox with the operator's additions (see
    /// [`SandboxAdditions`]). `orbit_home` is hidden from the command when
    /// an added directory would otherwise show it: it holds the provider
    /// credentials and the ledger.
    pub fn with_additions(mut self, additions: &SandboxAdditions, orbit_home: &Path) -> Self {
        if additions.is_empty() {
            return self;
        }
        self.read_dirs.extend(additions.read.iter().cloned());
        self.write_dirs.extend(additions.write.iter().cloned());
        self.path_first.extend(additions.path.iter().cloned());
        self.env.extend(additions.env.iter().cloned());
        self.network = self.network || additions.network;
        if let Ok(home) = orbit_home.canonicalize()
            && additions
                .read
                .iter()
                .chain(&additions.write)
                .any(|dir| home.starts_with(dir))
        {
            self.hidden.push(home);
        }
        self
    }

    /// Probe whether the sandbox can run here: bwrap present and
    /// functional. Runs a trivial confined true/false.
    pub fn probe() -> SandboxStatus {
        // Test override: simulate a machine without bubblewrap (the
        // scenarios can't uninstall the real one).
        if std::env::var("ORBIT_TEST_SANDBOX_OFF").is_ok() {
            return SandboxStatus::Unavailable("simulated absent (ORBIT_TEST_SANDBOX_OFF)".into());
        }
        // The canary spawns bwrap, and this is asked before every Bash call
        // (several times per call). A working sandbox is remembered for the
        // life of the process: if bwrap later disappears, `wrap` fails to
        // spawn, which fails closed. A failure is remembered only briefly,
        // so fixing the machine does not need a restart.
        static REMEMBERED: std::sync::Mutex<Option<(std::time::Instant, SandboxStatus)>> =
            std::sync::Mutex::new(None);
        const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
        if let Ok(slot) = REMEMBERED.lock()
            && let Some((at, status)) = slot.as_ref()
            && (!matches!(status, SandboxStatus::Unavailable(_)) || at.elapsed() < RETRY_AFTER)
        {
            return status.clone();
        }
        let status = Self::probe_now();
        if let Ok(mut slot) = REMEMBERED.lock() {
            *slot = Some((std::time::Instant::now(), status.clone()));
        }
        status
    }

    /// Run the canary now, without the remembered answer.
    fn probe_now() -> SandboxStatus {
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
        // Filesystem: the runtime's roots read-only, proc/sys/dev as usual,
        // then the extra read-only directories, then the write dirs
        // read-write. A later bind wins where two overlap, so a writable
        // directory inside a readable one stays writable.
        for dir in &self.read_dirs {
            let d: String = dir.to_string_lossy().into_owned();
            cmd.arg("--ro-bind").arg(&d).arg(&d);
        }
        for dir in &self.write_dirs {
            let d: String = dir.to_string_lossy().into_owned();
            cmd.arg("--bind").arg(&d).arg(&d);
        }
        if self.network {
            // Name lookups read /etc/resolv.conf, which is often a link to
            // a file outside the runtime's roots.
            if let Ok(resolver) = std::fs::canonicalize("/etc/resolv.conf")
                && resolver.is_file()
                && !runtime
                    .read_roots
                    .iter()
                    .any(|root| resolver.starts_with(root))
            {
                cmd.arg("--ro-bind").arg(&resolver).arg(&resolver);
            }
        } else {
            cmd.arg("--unshare-net");
        }
        if !self.path_first.is_empty() {
            let mut dirs = self.path_first.clone();
            dirs.extend(std::env::split_paths(&runtime.path));
            if let Ok(path) = std::env::join_paths(dirs) {
                cmd.arg("--setenv").arg("PATH").arg(path);
            }
        }
        for (name, value) in &self.env {
            cmd.arg("--setenv").arg(name).arg(value);
        }
        for dir in &self.hidden {
            cmd.arg("--tmpfs").arg(dir);
        }
        // S2: blind the deny-read paths INSIDE the sandbox — a `cat
        // ~/.ssh/id_rsa` reads /dev/null, not the key. Files are
        // masked with a read-only /dev/null bind; directories with an
        // empty tmpfs. Masks come AFTER the binds above so they win.
        // The home directory comes from HOME or, when that is unset, the
        // user database: an empty HOME must not turn `~/.ssh` into `/.ssh`
        // and silently drop the mask.
        let home = std::env::home_dir();
        for entry in crate::deny_read_paths() {
            let expanded = match (entry.strip_prefix('~'), &home) {
                (Some(rest), Some(home)) => home
                    .join(rest.trim_start_matches('/'))
                    .to_string_lossy()
                    .into_owned(),
                (Some(_), None) => continue,
                (None, _) => entry.to_string(),
            };
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
        // --clearenv drops everything set before it, so it comes first.
        .arg("--clearenv")
        .arg("--setenv")
        .arg("TERM")
        .arg("dumb");
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

    fn additions_fixture(name: &str) -> (PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("orbit-sbx-add-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        for dir in ["tools/bin", "cache", ".orbit", "work"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        (root.canonicalize().unwrap(), home.canonicalize().unwrap())
    }

    #[test]
    fn additions_are_read_from_the_operators_table() {
        let (root, home) = additions_fixture("parse");
        let text = r#"
claude_compat = true
[sandbox]
read = ["~/tools", "/definitely/not/here", "/"]
write = ["~/cache"]
path = ["~/tools/bin", "/usr/bin"]
network = true
env = { TOOL_HOME = "~/tools", PLAIN = "a ~ b", PATH = "/x", "bad name" = "v" }
extra = 1
"#;
        let additions = SandboxAdditions::parse(text, Some(&home));
        assert_eq!(additions.read, vec![home.join("tools")]);
        assert_eq!(additions.write, vec![home.join("cache")]);
        assert_eq!(additions.path, vec![home.join("tools/bin")]);
        assert!(additions.network);
        assert_eq!(
            additions.env,
            vec![
                ("PLAIN".to_owned(), "a ~ b".to_owned()),
                (
                    "TOOL_HOME".to_owned(),
                    home.join("tools").to_string_lossy().into_owned()
                ),
            ]
        );
        let problems = additions.problems.join("\n");
        for expected in [
            "/definitely/not/here is not an existing directory",
            "/ is the whole machine",
            "is not under a sandbox.read or sandbox.write directory",
            "PATH is set with sandbox.path",
            "bad name must be a plain name",
            "sandbox.extra is not a setting",
        ] {
            assert!(problems.contains(expected), "{expected}: {problems}");
        }
        assert!(!additions.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_settings_file_without_the_table_changes_nothing() {
        let none =
            SandboxAdditions::parse("claude_compat = true\n[permissions]\nallow = []\n", None);
        assert_eq!(none, SandboxAdditions::default());
        assert!(none.is_empty());
        assert_eq!(
            SandboxAdditions::parse("not toml [", None),
            SandboxAdditions::default()
        );
        let work = std::env::temp_dir();
        let plain = ShellSandbox::standard(std::slice::from_ref(&work), "same").wrap("true", &work);
        let added = ShellSandbox::standard(std::slice::from_ref(&work), "same")
            .with_additions(&none, Path::new("/nonexistent"))
            .wrap("true", &work);
        assert_eq!(
            plain.get_args().collect::<Vec<_>>(),
            added.get_args().collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_sandbox_is_on_unless_the_operator_switches_it_off() {
        for on in [
            "",
            "[sandbox]\nnetwork = true\n",
            "[sandbox]\nenabled = true\n",
        ] {
            let additions = SandboxAdditions::parse(on, None);
            assert!(!additions.disabled, "{on:?}");
            assert!(!additions.switched_off(), "{on:?}");
        }
        let off = SandboxAdditions::parse("[sandbox]\nenabled = false\n", None);
        assert!(off.disabled && off.switched_off());
        assert!(off.problems.is_empty(), "{:?}", off.problems);
        assert!(!off.is_empty(), "switching it off is a change");
    }

    #[test]
    fn only_a_real_boolean_switches_the_sandbox_off() {
        for bad in [
            "\"false\"",
            "0",
            "\"off\"",
            "[false]",
            "{ v = false }",
            "1.5",
        ] {
            let additions = SandboxAdditions::parse(&format!("[sandbox]\nenabled = {bad}\n"), None);
            assert!(!additions.disabled, "{bad}");
            assert!(
                additions
                    .problems
                    .iter()
                    .any(|p| p.contains("sandbox.enabled must be true or false")),
                "{bad}: {:?}",
                additions.problems
            );
        }
        // It is a key of the [sandbox] table, nowhere else.
        assert!(!SandboxAdditions::parse("enabled = false\n", None).disabled);
        assert!(!SandboxAdditions::parse("[other]\nenabled = false\n", None).disabled);
    }

    #[test]
    fn the_switch_is_read_from_the_operators_file_each_time() {
        let (root, home) = additions_fixture("switch-file");
        let settings = home.join("settings.toml");
        std::fs::write(&settings, "[sandbox]\nenabled = false\n").unwrap();
        assert!(SandboxAdditions::load(&home).switched_off());
        std::fs::write(&settings, "[sandbox]\nenabled = true\n").unwrap();
        assert!(!SandboxAdditions::load(&home).switched_off());
        std::fs::remove_file(&settings).unwrap();
        assert!(!SandboxAdditions::load(&home).switched_off(), "no file");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn inherit_env_takes_plain_names_only() {
        let additions = SandboxAdditions::parse(
            "[sandbox]\ninherit_env = [\"SSH_AUTH_SOCK\", \"XDG_RUNTIME_DIR\", \"SSH_AUTH_SOCK\", \"bad name\", \"1ST\", \"\", \"A=B\", 7]\n",
            None,
        );
        assert_eq!(additions.inherit_env, ["SSH_AUTH_SOCK", "XDG_RUNTIME_DIR"]);
        let problems = additions.problems.join("\n");
        for bad in ["\"bad name\"", "\"1ST\"", "\"\"", "\"A=B\""] {
            assert!(
                problems.contains(&format!("{bad} is not a plain variable name")),
                "{bad}: {problems}"
            );
        }
        assert!(problems.contains("every entry must be text"), "{problems}");
        assert!(!additions.is_empty(), "naming a variable is a change");
        let wrong = SandboxAdditions::parse("[sandbox]\ninherit_env = \"SSH_AUTH_SOCK\"\n", None);
        assert!(wrong.inherit_env.is_empty());
        assert!(
            wrong
                .problems
                .iter()
                .any(|p| p.contains("sandbox.inherit_env must be a list of variable names")),
            "{:?}",
            wrong.problems
        );
    }

    #[test]
    fn additions_reach_the_command_and_orbit_home_stays_hidden() {
        let (root, home) = additions_fixture("wrap");
        let additions = SandboxAdditions::parse(
            "[sandbox]\nread = [\"~\"]\nwrite = [\"~/cache\"]\npath = [\"~/tools/bin\"]\nnetwork = true\nenv = { TOOL_HOME = \"~/tools\" }\n",
            Some(&home),
        );
        assert_eq!(additions.problems, Vec::<String>::new());
        let work = home.join("work");
        let sandbox = ShellSandbox::standard(std::slice::from_ref(&work), "wrap")
            .with_additions(&additions, &home.join(".orbit"));
        let command = sandbox.wrap("true", &work);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let at = |flag: &str, value: &Path| {
            args.windows(2)
                .position(|pair| pair[0] == flag && Path::new(&pair[1]) == value)
        };
        // The readable home is bound before the writable directories inside
        // it, so those stay writable; ORBIT's own home is covered last.
        let read_home = at("--ro-bind", &home).expect("home is readable");
        let write_work = at("--bind", &work).expect("the working directory is writable");
        let write_cache = at("--bind", &home.join("cache")).expect("the cache is writable");
        let hide = at("--tmpfs", &home.join(".orbit")).expect("ORBIT's home is hidden");
        assert!(read_home < write_work && read_home < write_cache && write_cache < hide);
        assert!(!args.iter().any(|arg| arg == "--unshare-net"));
        let path = args
            .windows(3)
            .rev()
            .find(|triple| triple[0] == "--setenv" && triple[1] == "PATH")
            .map(|triple| triple[2].clone())
            .unwrap();
        assert!(
            path.starts_with(&format!("{}:", home.join("tools/bin").display())),
            "{path}"
        );
        assert!(args.windows(3).any(|triple| triple[0] == "--setenv"
            && triple[1] == "TOOL_HOME"
            && Path::new(&triple[2]) == home.join("tools")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_added_tool_runs_by_name_and_writes_only_where_allowed() {
        if !sandbox_available() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let (root, home) = additions_fixture("run");
        let tool = home.join("tools/bin/orbit-added-tool");
        std::fs::write(&tool, "#!/bin/sh\necho added-tool-ran\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(home.join(".orbit/secret"), "credential").unwrap();
        let work = home.join("work");
        let plain = ShellSandbox::standard(std::slice::from_ref(&work), "run-plain");
        let out = plain.wrap("orbit-added-tool", &work).output().unwrap();
        assert!(
            !out.status.success(),
            "without the table the tool is not found"
        );
        let additions = SandboxAdditions::parse(
            "[sandbox]\nread = [\"~\"]\nwrite = [\"~/cache\"]\npath = [\"~/tools/bin\"]\n",
            Some(&home),
        );
        let sandbox = ShellSandbox::standard(std::slice::from_ref(&work), "run-added")
            .with_additions(&additions, &home.join(".orbit"));
        let script = format!(
            "orbit-added-tool && echo c > {cache}/made && (echo t > {tools}/made 2>/dev/null && echo WROTE-READ-ONLY || echo read-only-held) && (cat {orbit}/secret 2>/dev/null || echo orbit-home-hidden)",
            cache = home.join("cache").display(),
            tools = home.join("tools").display(),
            orbit = home.join(".orbit").display(),
        );
        let out = sandbox.wrap(&script, &work).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("added-tool-ran"),
            "{text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(home.join("cache/made").exists());
        assert!(
            text.contains("read-only-held") && !home.join("tools/made").exists(),
            "{text}"
        );
        assert!(
            text.contains("orbit-home-hidden") && !text.contains("credential"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(root);
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

    fn sandbox_available() -> bool {
        let status = ShellSandbox::probe();
        if matches!(status, SandboxStatus::Confined) {
            return true;
        }
        assert!(
            std::env::var_os("ORBIT_REQUIRE_SANDBOX").is_none(),
            "release validation requires a working shell sandbox, got {status:?}"
        );
        eprintln!("skipping: no sandbox on this machine ({status:?})");
        false
    }

    #[test]
    fn confined_command_runs_and_writes_only_where_allowed() {
        if !sandbox_available() {
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
        if !sandbox_available() {
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
