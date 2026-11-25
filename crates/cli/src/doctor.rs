//! Bounded offline readiness. No check launches a program or contacts a provider.
use crate::customization::{Directory, Error, read_regular};
use crate::setup::{optional_file, validate_provider, verify_bounded_ledger, verify_identity};
use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ProviderAuthIdentity, ProviderCredentialError, ProviderCredentialSource,
    ProviderCredentialStatus, ProviderCredentialStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ready,
    Missing,
    Invalid,
    Configured,
    Unavailable,
    NotTested,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub detail: String,
    pub required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
}
impl DoctorReport {
    fn new() -> Self {
        Self {
            schema_version: 1,
            ready: true,
            checks: Vec::new(),
        }
    }
    fn add(&mut self, id: &str, status: CheckStatus, detail: &str, required: bool) {
        if self.checks.len() >= 127 {
            if self.checks.len() == 127 {
                self.checks.push(DoctorCheck {
                    id: "limits".into(),
                    status: CheckStatus::Invalid,
                    detail: "Readiness checks truncated at 128".into(),
                    required: true,
                });
            }
            self.ready = false;
            return;
        }
        let mut detail =
            orbit_hud::display_safe(detail).unwrap_or_else(|_| "Diagnostic withheld".into());
        let mut end = detail.len().min(256);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
        if required && !matches!(status, CheckStatus::Ready | CheckStatus::Configured) {
            self.ready = false;
        }
        self.checks.push(DoctorCheck {
            id: id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .take(96)
                .collect(),
            status,
            detail,
            required,
        });
    }
}
/// PATH inspection accepts regular executable files only, without spawning them.
pub fn find_executable(command: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if command.is_empty() || command.len() > 256 || command.chars().any(char::is_control) {
        return None;
    }
    let check = |p: PathBuf| {
        let m = std::fs::symlink_metadata(&p).ok()?;
        if m.is_file() && !m.file_type().is_symlink() && m.permissions().mode() & 0o111 != 0 {
            Some(p)
        } else {
            None
        }
    };
    if command.contains('/') {
        return Path::new(command)
            .is_absolute()
            .then(|| PathBuf::from(command))
            .and_then(check);
    }
    std::env::split_paths(path?)
        .take(128)
        .filter(|p| p.is_absolute() && p.as_os_str().len() <= 256)
        .find_map(|p| check(p.join(command)))
}
/// Whether a server's configured command can be run: an executable file,
/// reached directly or through links. A command such as `python3` or `npx`
/// is commonly a link to the real program, so [`find_executable`], which
/// refuses links, would call a working server unavailable.
fn command_can_run(command: &str, path: Option<&std::ffi::OsStr>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if command.is_empty() || command.len() > 256 || command.chars().any(char::is_control) {
        return false;
    }
    let runs = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if command.contains('/') {
        return Path::new(command).is_absolute() && runs(Path::new(command));
    }
    path.is_some_and(|path| {
        std::env::split_paths(path)
            .take(128)
            .filter(|p| p.is_absolute() && p.as_os_str().len() <= 256)
            .any(|p| runs(&p.join(command)))
    })
}
fn inspect_integration(home: &Path, filename: &str, report: &mut DoctorReport) {
    let label = if filename == "mcp.json" { "mcp" } else { "lsp" };
    let bytes = match optional_file(home, filename, 128 * 1024) {
        Ok(Some(b)) => b,
        Ok(None) => {
            report.add(
                label,
                CheckStatus::Missing,
                "Optional configuration is absent",
                false,
            );
            return;
        }
        Err(_) => {
            report.add(
                label,
                CheckStatus::Invalid,
                "Configuration must be a bounded checked regular file",
                false,
            );
            return;
        }
    };
    inspect_integration_bytes(&bytes, label, report);
}
fn inspect_integration_bytes(bytes: &[u8], label: &str, report: &mut DoctorReport) {
    let path_env = std::env::var_os("PATH");
    if label == "mcp" {
        let config: orbit_mcp::McpConfig = match serde_json::from_slice(bytes) {
            Ok(c) => c,
            Err(_) => {
                report.add(label, CheckStatus::Invalid, "MCP JSON is invalid", false);
                return;
            }
        };
        if config.servers.len() > 64 {
            report.add(
                label,
                CheckStatus::Invalid,
                "MCP configuration exceeds 64 servers",
                false,
            );
            return;
        }
        for (index, server) in config.servers.values().enumerate() {
            let id = format!("mcp.{index}");
            if server.validate().is_err() {
                report.add(
                    &id,
                    CheckStatus::Invalid,
                    "MCP server declaration is invalid",
                    false,
                );
            } else if !server.enabled {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Server is disabled; not launched",
                    false,
                );
            } else if server.transport != orbit_mcp::McpTransport::Stdio {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Remote MCP endpoint is configured; connectivity not tested and no request sent",
                    false,
                );
            } else if !command_can_run(&server.command, path_env.as_deref()) {
                report.add(
                    &id,
                    CheckStatus::Unavailable,
                    "Configured executable is absent or cannot be run; not launched",
                    false,
                );
            } else {
                report.add(
                    &id,
                    CheckStatus::NotTested,
                    "Configured executable exists; server handshake has not been tested",
                    false,
                );
            }
        }
        report.add(
            "mcp.configuration",
            CheckStatus::Configured,
            "Configuration inspected without server launch or handshake",
            false,
        );
        report.add(
            "mcp.connectivity",
            CheckStatus::NotTested,
            "No MCP server was contacted; connectivity and handshake were not tested",
            false,
        );
    } else {
        if bytes.len() > 64 * 1024 {
            report.add(
                label,
                CheckStatus::Invalid,
                "LSP configuration exceeds the runtime's 64 KiB limit",
                false,
            );
            return;
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            servers: Vec<Server>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Server {
            name: String,
            command: String,
            #[serde(default)]
            args: Vec<String>,
            language_id: String,
            extensions: Vec<String>,
            workspace_root: PathBuf,
            #[serde(default = "timeout")]
            timeout_ms: u64,
        }
        fn timeout() -> u64 {
            5000
        }
        let config: Config = match std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| toml::from_str(s).ok())
        {
            Some(c) => c,
            None => {
                report.add(label, CheckStatus::Invalid, "LSP TOML is invalid", false);
                return;
            }
        };
        if config.servers.len() > 16 {
            report.add(
                label,
                CheckStatus::Invalid,
                "LSP configuration exceeds the runtime's 16-server limit",
                false,
            );
            return;
        }
        let identifier = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+'))
        };
        let mut names = std::collections::BTreeSet::new();
        for (index, server) in config.servers.iter().enumerate() {
            let id = format!("lsp.{index}");
            let valid = identifier(&server.name)
                && identifier(&server.language_id)
                && names.insert(&server.name)
                && !server.extensions.is_empty()
                && server.extensions.len() <= 32
                && server
                    .extensions
                    .iter()
                    .all(|e| identifier(e) && !e.contains('.'))
                && server.args.len() <= 64
                && server.args.iter().map(String::len).sum::<usize>() <= 16 * 1024
                && server.args.iter().all(|s| !s.contains('\0'))
                && (100..=30000).contains(&server.timeout_ms)
                && server.workspace_root.as_os_str().len() <= 256;
            if !valid {
                report.add(
                    &id,
                    CheckStatus::Invalid,
                    "LSP server declaration is invalid",
                    false,
                );
            } else if !config.enabled {
                report.add(
                    &id,
                    CheckStatus::Configured,
                    "Diagnostics are disabled; not launched",
                    false,
                );
            } else if !command_can_run(&server.command, path_env.as_deref()) {
                report.add(
                    &id,
                    CheckStatus::Unavailable,
                    "Configured executable is absent or cannot be run; not launched",
                    false,
                );
            } else {
                report.add(
                    &id,
                    CheckStatus::NotTested,
                    "Configured executable exists; diagnostics have not been requested",
                    false,
                );
            }
        }
        report.add(
            "lsp.configuration",
            CheckStatus::Configured,
            "Configuration inspected without language-server launch",
            false,
        );
    }
}
/// Hook matchers written as regular expressions: a pattern that does not
/// compile leaves its hook matching only the plain names in it, and nothing else
/// says so before the hook fails to run. Reads settings only; no hook is run,
/// and a hook's command stays out of the report, which people paste.
fn inspect_hook_matchers(home: &Path, workspace: &Path, report: &mut DoctorReport) {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(workspace);
    let hooks = orbit_engine::hooks::Hooks::inspect(home, trusted.then_some(workspace));
    let mut patterns = 0usize;
    let mut broken = Vec::new();
    for hook in &hooks.hooks {
        let Some(matcher) = hook.matcher.as_deref() else {
            continue;
        };
        if !orbit_engine::hooks::is_regex_matcher(matcher) {
            continue;
        }
        patterns += 1;
        if let Some(reason) = orbit_engine::hooks::matcher_problem(matcher) {
            broken.push((hook.event.as_str(), matcher.trim(), reason));
        }
    }
    if patterns == 0 {
        return;
    }
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    if broken.is_empty() {
        report.add(
            "hooks.matchers",
            CheckStatus::Configured,
            &format!(
                "{patterns} regular-expression matcher{} across {} hook{}; all compile; no hook was run",
                plural(patterns),
                hooks.hooks.len(),
                plural(hooks.hooks.len())
            ),
            false,
        );
        return;
    }
    report.add(
        "hooks.matchers",
        CheckStatus::Invalid,
        &format!(
            "{} of the {patterns} regular-expression matcher{} did not compile; those hooks match only the plain names in them",
            broken.len(),
            plural(patterns)
        ),
        false,
    );
    for (index, (event, matcher, reason)) in broken.iter().enumerate().take(8) {
        report.add(
            &format!("hooks.matchers.{index}"),
            CheckStatus::Invalid,
            &format!(
                "{event} hook matcher \"{matcher}\" is not a valid regular expression ({reason})"
            ),
            false,
        );
    }
}

/// The command hooks of the imported plugins the operator named in `plugin_hooks`: which run, which
/// are left out and why, and which named plugin is not there to run at all. Reads the settings and
/// the plugin store; no hook is run, and a hook's command stays out of the report, which people
/// paste. Nothing is said when no plugin is named: they are off by default. Not required either
/// way: whether a plugin's hooks should run is the operator's call, not a reason for ORBIT to call
/// itself not ready.
fn inspect_plugin_hooks(home: &Path, report: &mut DoctorReport) {
    let (_, setting_problems) = orbit_engine::plugin_hooks::allowed(home);
    let resolved = orbit_engine::plugin_hooks::resolve(home);
    if resolved.report.is_empty() && setting_problems.is_empty() {
        return;
    }
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let named = resolved.report.len();
    let running: usize = resolved
        .report
        .iter()
        .map(|plugin| plugin.active.len())
        .sum();
    let left_out: usize = resolved
        .report
        .iter()
        .map(|plugin| plugin.skipped.len())
        .sum();
    let inactive = resolved
        .report
        .iter()
        .filter(|plugin| plugin.inactive.is_some())
        .count();
    let clean = setting_problems.is_empty() && left_out == 0 && inactive == 0;
    let detail = if named == 0 {
        "plugin_hooks could not be read; no plugin's hooks run".to_owned()
    } else {
        let mut detail = format!(
            "{named} plugin{} named in plugin_hooks; {running} command hook{} {}",
            plural(named),
            plural(running),
            if running == 1 { "runs" } else { "run" }
        );
        if left_out > 0 {
            detail.push_str(&format!(", {left_out} left out"));
        }
        if inactive > 0 {
            detail.push_str(&format!(
                ", {inactive} plugin{} {} not run",
                plural(inactive),
                if inactive == 1 { "does" } else { "do" }
            ));
        }
        detail.push_str("; no hook was run");
        detail
    };
    report.add(
        "plugins.hooks",
        if clean {
            CheckStatus::Configured
        } else {
            CheckStatus::Invalid
        },
        &detail,
        false,
    );
    for (index, problem) in setting_problems.iter().enumerate().take(8) {
        report.add(
            &format!("plugins.hooks.setting.{index}"),
            CheckStatus::Invalid,
            problem,
            false,
        );
    }
    // Each detail is cut at 256 bytes and a report holds 128 checks, so a plugin gets one short
    // line (how many hooks run, at which events) and each hook left out gets a line of its own.
    const LISTED: usize = 12;
    const LISTED_LEFT_OUT: usize = 12;
    let (mut lines_shown, mut hooks_shown) = (0usize, 0usize);
    for (index, plugin) in resolved.report.iter().enumerate().take(LISTED) {
        let digest = plugin
            .digest
            .as_deref()
            .map(|digest| format!(" (digest {}…)", &digest[..digest.len().min(8)]))
            .unwrap_or_default();
        let (status, detail) = match &plugin.inactive {
            Some(why) => (
                CheckStatus::Invalid,
                format!("{}{digest}: its hooks do not run: {why}", plugin.name),
            ),
            None => {
                let mut detail = format!(
                    "{}{digest}: {}",
                    plugin.name,
                    if plugin.active.is_empty() {
                        "no command hook runs".to_owned()
                    } else {
                        format!(
                            "{} command hook{}: {}",
                            plugin.active.len(),
                            plural(plugin.active.len()),
                            events_of(&plugin.active)
                        )
                    }
                );
                if !plugin.skipped.is_empty() {
                    detail.push_str(&format!("; {} left out", plugin.skipped.len()));
                }
                (
                    if plugin.skipped.is_empty() {
                        CheckStatus::Configured
                    } else {
                        CheckStatus::Invalid
                    },
                    detail,
                )
            }
        };
        report.add(&format!("plugins.hooks.{index}"), status, &detail, false);
        // Hooks left out for the same reason share a line: a plugin can lose six to one cause.
        let mut by_reason: Vec<(&str, Vec<String>)> = Vec::new();
        for skipped in &plugin.skipped {
            let (event, reason) = skipped.split_once(": ").unwrap_or(("", skipped.as_str()));
            match by_reason.iter_mut().find(|(known, _)| *known == reason) {
                Some((_, events)) => events.push(event.to_owned()),
                None => by_reason.push((reason, vec![event.to_owned()])),
            }
        }
        for (line, (reason, events)) in by_reason.iter().enumerate() {
            if lines_shown == LISTED_LEFT_OUT {
                break;
            }
            lines_shown += 1;
            hooks_shown += events.len();
            report.add(
                &format!("plugins.hooks.{index}.left_out.{line}"),
                CheckStatus::Invalid,
                &format!(
                    "{}: left out {} hook{} ({}): {reason}",
                    plugin.name,
                    events.len(),
                    plural(events.len()),
                    events_of(events)
                ),
                false,
            );
        }
    }
    if left_out > hooks_shown {
        report.add(
            "plugins.hooks.left_out.more",
            CheckStatus::Invalid,
            &format!(
                "{} more hooks left out are not listed here",
                left_out - hooks_shown
            ),
            false,
        );
    }
    if named > LISTED {
        report.add(
            "plugins.hooks.more",
            CheckStatus::Configured,
            &format!("{} more named plugins are not listed here", named - LISTED),
            false,
        );
    }
}

/// The events a plugin's running hooks are at, each once with a count when there is more than one:
/// `PreToolUse, SessionStart ×3`. Matchers are left to `/hooks`, which has the room.
fn events_of(active: &[String]) -> String {
    let mut counted: Vec<(&str, usize)> = Vec::new();
    for hook in active {
        let event = hook.split(" [").next().unwrap_or(hook);
        match counted.iter_mut().find(|(known, _)| *known == event) {
            Some((_, n)) => *n += 1,
            None => counted.push((event, 1)),
        }
    }
    counted
        .iter()
        .map(|(event, n)| {
            if *n == 1 {
                (*event).to_owned()
            } else {
                format!("{event} ×{n}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the instruction files the prompt reads add up to, which of them the 200-line / 25 KB cap
/// cuts, and which are not read at all because a link in them leads where an instruction file may
/// not (to a key, or out of the project): rules that never reach the model are not something to
/// find out from its behaviour. The files are read, no text from them is shown, and nothing here
/// is required: a cut or a refusal is the operator's to weigh, not a reason for ORBIT to call
/// itself not ready.
fn inspect_instructions(home: &Path, workspace: &Path, report: &mut DoctorReport) {
    let files = orbit_engine::context::instruction_report(home, workspace);
    if files.is_empty() {
        return;
    }
    let (refused, read): (Vec<_>, Vec<_>) = files.iter().partition(|file| file.refused.is_some());
    let cut: Vec<_> = read.iter().filter(|file| file.cut.is_some()).collect();
    let bytes: u64 = read.iter().map(|file| file.bytes).sum();
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let mut detail = format!(
        "{} instruction file{} read, {bytes} bytes in all",
        read.len(),
        plural(read.len())
    );
    if cut.is_empty() {
        detail.push_str("; none is cut");
    } else {
        detail.push_str(&format!("; {} cut by the 200-line / 25 KB cap", cut.len()));
    }
    if !refused.is_empty() {
        detail.push_str(&format!("; {} not read", refused.len()));
    }
    report.add(
        "instructions",
        if cut.is_empty() && refused.is_empty() {
            CheckStatus::Configured
        } else {
            CheckStatus::Invalid
        },
        &detail,
        false,
    );
    let problems = cut
        .iter()
        .map(|file| {
            format!(
                "{} is cut: {}",
                file.path.display(),
                file.cut.as_deref().unwrap_or("")
            )
        })
        .chain(refused.iter().map(|file| {
            format!(
                "{} is not read: {}",
                file.path.display(),
                file.refused.as_deref().unwrap_or("")
            )
        }));
    for (index, problem) in problems.enumerate().take(8) {
        report.add(
            &format!("instructions.{index}"),
            CheckStatus::Invalid,
            &problem,
            false,
        );
    }
}

fn inspect_project(home: &Path, workspace: &Path, report: &mut DoctorReport) {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(workspace);
    report.add(
        "project.trust",
        CheckStatus::Configured,
        if trusted {
            "Folder trust already exists; unchanged"
        } else {
            "Folder is untrusted; project integrations are not activated or launched"
        },
        false,
    );
    if !trusted {
        return;
    }
    let root = match Directory::open(workspace, false) {
        Ok(r) => r,
        Err(_) => {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Workspace path is unsafe",
                false,
            );
            return;
        }
    };
    let path = workspace.join(".orbit");
    if !path.exists() {
        return;
    }
    let project = match Directory::open(&path, false) {
        Ok(p) => p,
        Err(_) => {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Project configuration directory is unsafe",
                false,
            );
            return;
        }
    };
    for (file, label) in [("mcp.json", "mcp"), ("lsp.toml", "lsp")] {
        let Ok(base) = project.io() else {
            report.add(
                "project",
                CheckStatus::Invalid,
                "Project configuration identity changed",
                false,
            );
            return;
        };
        let path = base.join(file);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                report.add(
                    &format!("project.{label}"),
                    CheckStatus::Invalid,
                    "Project configuration is unreadable",
                    false,
                );
                continue;
            }
            Ok(_) => {}
        }
        let bytes = match read_regular(&path, 128 * 1024, false) {
            Ok(b) => b,
            Err(_) => {
                report.add(
                    &format!("project.{label}"),
                    CheckStatus::Invalid,
                    "Project configuration is unsafe or exceeds its bound",
                    false,
                );
                continue;
            }
        };
        if label == "lsp" {
            let enabled = optional_file(home, "lsp.toml", 128 * 1024)
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| toml::from_str::<toml::Value>(&s).ok())
                .and_then(|v| v.get("enabled").and_then(toml::Value::as_bool))
                .unwrap_or(false);
            if !enabled {
                report.add("project.lsp",CheckStatus::Configured,"Project diagnostics configuration exists; user-level diagnostics are disabled or absent",false);
                continue;
            }
        }
        let mut temporary = DoctorReport::new();
        inspect_integration_bytes(&bytes, label, &mut temporary);
        for check in temporary.checks {
            report.add(
                &format!("project.{}", check.id),
                check.status,
                &check.detail,
                false,
            );
        }
    }
    if root.check().is_err() || project.check().is_err() {
        report.add(
            "project",
            CheckStatus::Invalid,
            "Project configuration identity changed",
            false,
        );
    }
}
fn inspect_mods(home: &Path, report: &mut DoctorReport) {
    match crate::mods::validation_status(home) {
        Ok(status) => report.add(
            "mods",
            if status.bundles == 0 { CheckStatus::Missing } else { CheckStatus::Configured },
            if status.bundles == 0 { "Optional instruction bundles are absent" } else { "Instruction bundles and enabled metadata are valid local data; no extension code was executed" },
            false,
        ),
        Err(_) => report.add(
            "mods", CheckStatus::Invalid,
            "Instruction bundle or enabled metadata is malformed or unsafe; existing bytes were preserved",
            false,
        ),
    }
}
/// Inspect a managed bundle manifest next to both binaries. No binary is executed.
pub fn browser_check(binary: &Path) -> DoctorCheck {
    let result = (|| -> Result<CheckStatus, Error> {
        let parent = binary
            .parent()
            .ok_or_else(|| Error::UnsafePath("browser parent missing".into()))?;
        let sibling = parent.join("orbit-web");
        if !sibling.exists() {
            return Ok(CheckStatus::Unavailable);
        }
        if find_executable(&sibling.to_string_lossy(), None).is_none() {
            return Ok(CheckStatus::Invalid);
        }
        let manifest = parent.join("manifest.json");
        if !manifest.exists() {
            return Ok(CheckStatus::NotTested);
        }
        let bytes = read_regular(&manifest, 128 * 1024, false)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Invalid("bundle manifest is invalid".into()))?;
        if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1)
            || value.get("version").and_then(|v| v.as_str()) != Some(env!("CARGO_PKG_VERSION"))
            || value.get("target").and_then(|v| v.as_str()) != Some(native_target())
            || value.get("signature").and_then(|v| v.as_str()) != Some("absent")
        {
            return Ok(CheckStatus::Invalid);
        }
        // The distribution lane supplies the canonical components object.
        let Some(components) = value.get("components").and_then(|v| v.as_object()) else {
            return Ok(CheckStatus::NotTested);
        };
        for name in ["orbit", "orbit-web"] {
            let Some(component) = components.get(name) else {
                return Ok(CheckStatus::Invalid);
            };
            let bytes = read_regular(&parent.join(name), 256 * 1024 * 1024, false)?;
            if component.get("size").and_then(|v| v.as_u64()) != Some(bytes.len() as u64)
                || component.get("sha256").and_then(|v| v.as_str())
                    != Some(hex::encode(Sha256::digest(&bytes)).as_str())
            {
                return Ok(CheckStatus::Invalid);
            }
        }
        Ok(CheckStatus::Ready)
    })();
    let status = result.unwrap_or(CheckStatus::Invalid);
    DoctorCheck {
        id: "browser".into(),
        status,
        detail: match status {
            CheckStatus::Ready => "Managed CLI/browser bundle version and component hashes match",
            CheckStatus::Unavailable => "Browser sibling is absent",
            CheckStatus::NotTested => {
                "Browser sibling exists; matching managed bundle metadata is absent"
            }
            _ => "Browser bundle metadata or component identity is invalid",
        }
        .into(),
        required: false,
    }
}
pub fn native_target() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else {
        "unverified-platform"
    }
}
fn provider_credential_status(
    home: &Path,
    provider: &crate::config::ProviderConfig,
) -> (CheckStatus, &'static str) {
    let selected = (|| {
        let endpoint = crate::config::validate_provider_endpoint(&provider.url)
            .map_err(|_| ProviderCredentialError::InvalidIdentity)?;
        let identity = ProviderAuthIdentity::new(
            &provider.name,
            &provider.kind,
            endpoint.as_str(),
            provider.env.as_deref(),
        )?;
        let home =
            std::path::absolute(home).map_err(|_| ProviderCredentialError::UnsafeDirectory)?;
        let store = ProviderCredentialStore::new(&home)?;
        Ok(store.status_read_only_with(&identity, |name| {
            Ok(std::env::var_os(name).map(|value| SecretBytes::new(value.into_encoded_bytes())))
        }))
    })();
    let status = selected.unwrap_or_else(ProviderCredentialStatus::Invalid);
    match status {
        ProviderCredentialStatus::NoAuth => (
            CheckStatus::Configured,
            "Credential source: no authentication; no credential lookup or provider request",
        ),
        ProviderCredentialStatus::Available {
            source: ProviderCredentialSource::Environment,
            ..
        } => (
            CheckStatus::Ready,
            "Credential source: environment override; key format valid, connectivity not tested",
        ),
        ProviderCredentialStatus::Available {
            source: ProviderCredentialSource::Saved,
            ..
        } => (
            CheckStatus::Ready,
            "Credential source: saved private key; exact binding verified, connectivity not tested",
        ),
        ProviderCredentialStatus::Missing => (
            CheckStatus::Missing,
            "Credential source missing; set the declared ENV or save a matching private key",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::InvalidKey) => (
            CheckStatus::Invalid,
            "Credential value is invalid; check the declared ENV or saved key without displaying it",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::EnvironmentUnavailable) => (
            CheckStatus::Invalid,
            "Credential environment is unavailable; no saved fallback or provider request was attempted",
        ),
        ProviderCredentialStatus::Invalid(ProviderCredentialError::Busy) => (
            CheckStatus::Unavailable,
            "Credential storage is busy; retry after the current operation, connectivity not tested",
        ),
        ProviderCredentialStatus::Invalid(_) => (
            CheckStatus::Invalid,
            "Credential storage or binding is invalid or unsafe; no files changed or provider request sent",
        ),
        ProviderCredentialStatus::Available { .. } => (
            CheckStatus::Invalid,
            "Credential source could not be verified; no provider request sent",
        ),
    }
}

pub fn doctor(home: &Path, workspace: &Path) -> DoctorReport {
    let mut report = DoctorReport::new();
    if !home.exists() {
        report.add(
            "home",
            CheckStatus::Missing,
            "Initialize a private ORBIT home with setup",
            true,
        );
        return report;
    }
    if Directory::open(home, true).is_err() {
        report.add(
            "home",
            CheckStatus::Invalid,
            "Home must be an owned private directory without symlinks",
            true,
        );
        return report;
    }
    report.add(
        "home",
        CheckStatus::Ready,
        "Private local home is readable",
        true,
    );
    let adapter_identity = orbit_engine::retry::adapter_identity_digest(
        &orbit_provider_http::openai::openai_identity(),
    );
    report.add(
        "retry.openai_adapter_identity",
        CheckStatus::Configured,
        &format!(
            "Current OpenAI-compatible adapter identity SHA256: {adapter_identity}; offline implementation digest"
        ),
        false,
    );
    // Cache introspection: surface the on-disk caches with
    // their sizes so `orbit doctor` doubles as `cache show`.
    for (label, path) in [
        ("cache.profile_backup", home.join("customization.json.bak")),
        ("cache.context_history", home.join("context-history")),
        (
            "cache.context_history_archives",
            home.join("context-history/owner/archives"),
        ),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                let (files, bytes, partial) = directory_footprint(&path);
                let qualifier = if partial {
                    " (partial; scan limit or unreadable entry)"
                } else {
                    ""
                };
                report.add(
                    label,
                    CheckStatus::Ready,
                    &format!("{files} files, {bytes} bytes{qualifier}"),
                    false,
                );
            }
            Ok(metadata) if metadata.is_file() => {
                report.add(
                    label,
                    CheckStatus::Ready,
                    &format!("{} bytes", metadata.len()),
                    false,
                );
            }
            Ok(_) | Err(_) => {
                report.add(label, CheckStatus::Missing, "No cache content yet", false);
            }
        }
    }
    match verify_identity(home) {
        Ok(_) => report.add(
            "identity",
            CheckStatus::Ready,
            "Signing key, signed trust manifest and PIB identity match",
            true,
        ),
        Err(_) => report.add(
            "identity",
            CheckStatus::Invalid,
            "Identity is missing, partial or cryptographically invalid; use setup repair --dry-run",
            true,
        ),
    }
    match verify_bounded_ledger(home) {
        Ok((n, _)) => report.add(
            "ledger",
            CheckStatus::Ready,
            &format!("Verified {n} bounded hash-chain records"),
            true,
        ),
        Err(_) => report.add(
            "ledger",
            CheckStatus::Invalid,
            "Ledger chain is missing, unsafe, truncated or invalid",
            true,
        ),
    }
    match optional_file(home, "providers.toml", 128 * 1024) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| crate::config::ProvidersConfig::load_from_str(s).ok())
        {
            Some(config) => {
                report.add(
                    "providers",
                    if config.provider.is_empty() {
                        CheckStatus::Missing
                    } else {
                        CheckStatus::Configured
                    },
                    "Offline provider declarations; connectivity is not tested",
                    true,
                );
                let routing_valid = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|raw| crate::phase_routing::parse_settings(raw).ok())
                    .is_some_and(|settings| {
                        crate::phase_routing::validate_settings(&config, &settings).is_ok()
                    });
                let default_spec = if config.roles.main.is_empty() {
                    config.provider.iter().find_map(|provider| {
                        provider
                            .models
                            .first()
                            .map(|model| format!("{}/{}", provider.name, model.id))
                    })
                } else {
                    Some(config.roles.main.clone())
                };
                let default_config = default_spec
                    .as_deref()
                    .and_then(|spec| crate::phase_routing::resolve_model(&config, spec, None).ok())
                    .and_then(|model| model.turn_config(None).ok());
                match default_config {
                    Some(selected) => match crate::provider_policies::load_for_config(home, &selected) {
                        Ok(Some(binding)) => report.add(
                            "retry.policy",
                            CheckStatus::Configured,
                            &format!(
                                "Configured main/default only: total max_attempts={}; requires managed uncapped ordinary admission; smaller caller ceilings apply; final generation-refusal assumption; provider usage/billing unknown; connectivity untested",
                                binding.max_attempts()
                            ),
                            false,
                        ),
                        Ok(None) => report.add(
                            "retry.policy",
                            CheckStatus::NotTested,
                            "No usable optional retry declaration matches the configured main/default model; ordinary retries remain conservative; connectivity not tested",
                            false,
                        ),
                        Err(_) => report.add(
                            "retry.policy",
                            CheckStatus::Invalid,
                            "Provider retry policy is invalid or unsafe; no policy details shown or provider request sent",
                            true,
                        ),
                    },
                    None => report.add(
                        "retry.policy",
                        CheckStatus::Unavailable,
                        "Configured main/default model could not be resolved; optional retry policy was not checked",
                        false,
                    ),
                }
                for (index, provider) in config.provider.iter().enumerate().take(64) {
                    let id = format!("provider.{index}");
                    if validate_provider(provider).is_err() {
                        report.add(
                            &id,
                            CheckStatus::Invalid,
                            "Provider URL/model/ENV declaration is invalid",
                            true,
                        );
                        continue;
                    }
                    report.add(
                        &id,
                        CheckStatus::Configured,
                        "Explicit provider models and adapter are configured; no request sent",
                        true,
                    );
                    let (status, detail) = provider_credential_status(home, provider);
                    report.add(&format!("credential.{index}"), status, detail, true);
                }
                report.add("routing",if routing_valid{CheckStatus::Configured}else{CheckStatus::Invalid},"Exact roles, phase/difficulty targets and keyword bounds checked without dispatch",true);
            }
            None => report.add(
                "providers",
                CheckStatus::Invalid,
                "Provider configuration is malformed",
                true,
            ),
        },
        Ok(None) => report.add(
            "providers",
            CheckStatus::Missing,
            "No providers are configured; setup accepts manual models offline",
            true,
        ),
        Err(_) => report.add(
            "providers",
            CheckStatus::Invalid,
            "Provider configuration is unsafe or exceeds 128 KiB",
            true,
        ),
    }
    match crate::customization::load(home, workspace) {
        Ok(_) => report.add(
            "customization",
            CheckStatus::Ready,
            "Portable profile and legacy configuration validate",
            true,
        ),
        Err(_) => report.add(
            "customization",
            CheckStatus::Invalid,
            "Customization is invalid; no automatic reset or rewrite was performed",
            true,
        ),
    }
    inspect_integration(home, "mcp.json", &mut report);
    inspect_integration(home, "lsp.toml", &mut report);
    inspect_project(home, workspace, &mut report);
    inspect_hook_matchers(home, workspace, &mut report);
    inspect_plugin_hooks(home, &mut report);
    inspect_instructions(home, workspace, &mut report);
    let context =
        orbit_tools::ToolContext::new(home.to_path_buf(), "doctor".into(), workspace.to_path_buf());
    match crate::lsp::availability(home, &context) {
        Ok(Some(_)) => report.add(
            "lsp.activation",
            CheckStatus::Configured,
            "Effective trusted diagnostics configuration validates; no server was launched",
            false,
        ),
        Ok(None) => report.add(
            "lsp.activation",
            CheckStatus::NotTested,
            "Diagnostics are disabled or have no effective trusted server; no launch attempted",
            false,
        ),
        Err(_) => report.add(
            "lsp.activation",
            CheckStatus::Invalid,
            "Effective diagnostics configuration does not pass runtime validation",
            false,
        ),
    }
    inspect_mods(home, &mut report);
    use std::io::IsTerminal;
    report.add(
        "terminal",
        CheckStatus::Configured,
        if std::io::stdout().is_terminal() {
            "Terminal output is attached; fonts are controlled by the terminal host"
        } else {
            "Output is not a terminal; fonts are controlled by the terminal host"
        },
        false,
    );
    report.add(
        "color",
        CheckStatus::Configured,
        if std::env::var_os("NO_COLOR").is_some() {
            "NO_COLOR is present; color output is disabled"
        } else {
            "Terminal color capability is evaluated by the frontend"
        },
        false,
    );
    if let Ok(binary) = std::env::current_exe() {
        let browser = browser_check(&binary);
        report.add(
            &browser.id,
            browser.status,
            &browser.detail,
            browser.required,
        );
    }
    report.add(
        "provider.connectivity",
        CheckStatus::NotTested,
        "No provider request was sent; run the real-provider checklist explicitly",
        false,
    );
    report
}

/// Count a bounded prefix of cache entries without descending through links.
/// The final flag distinguishes complete counts from lower bounds.
fn directory_footprint(dir: &Path) -> (usize, u64, bool) {
    const MAX_ENTRIES: usize = 4096;
    const MAX_DEPTH: usize = 32;
    let (mut examined, mut files, mut bytes) = (0usize, 0usize, 0u64);
    let mut partial = false;
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((current, depth)) = stack.pop() {
        // Validate every ancestor, then enumerate the held directory itself.
        // A symlink in context-history/owner must not redirect cache inspection.
        let Ok(directory) = Directory::open(&current, false) else {
            partial = true;
            continue;
        };
        let Ok(io) = directory.io() else {
            partial = true;
            continue;
        };
        let Ok(entries) = std::fs::read_dir(io) else {
            partial = true;
            continue;
        };
        for entry in entries {
            if examined == MAX_ENTRIES {
                return (files, bytes, true);
            }
            examined += 1;
            let Ok(entry) = entry else {
                partial = true;
                continue;
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {
                    if depth == MAX_DEPTH {
                        partial = true;
                    } else {
                        stack.push((current.join(entry.file_name()), depth + 1));
                    }
                }
                Ok(kind) if kind.is_file() => match entry.metadata() {
                    Ok(metadata) => {
                        files += 1;
                        match bytes.checked_add(metadata.len()) {
                            Some(total) => bytes = total,
                            None => return (files, u64::MAX, true),
                        }
                    }
                    Err(_) => partial = true,
                },
                Ok(_) => partial = true,
                Err(_) => partial = true,
            }
        }
        partial |= directory.check().is_err();
    }
    (files, bytes, partial)
}

#[cfg(test)]
mod footprint_tests {
    use super::directory_footprint;
    use std::path::PathBuf;

    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("orbit-footprint-{}", ulid::Ulid::new()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn empty_directory_fanout_is_bounded_and_reported_as_partial() {
        let tree = Tree::new();
        for index in 0..4097 {
            std::fs::create_dir(tree.0.join(index.to_string())).unwrap();
        }
        assert_eq!(directory_footprint(&tree.0), (0, 0, true));
    }

    #[test]
    fn deep_directory_chains_are_bounded_and_normal_counts_remain_exact() {
        let tree = Tree::new();
        std::fs::write(tree.0.join("sample"), b"four").unwrap();
        assert_eq!(directory_footprint(&tree.0), (1, 4, false));
        let mut path = tree.0.clone();
        for _ in 0..34 {
            path = path.join("nested");
            std::fs::create_dir(&path).unwrap();
        }
        assert_eq!(directory_footprint(&tree.0), (1, 4, true));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_files_and_directories_are_not_counted_or_followed() {
        let tree = Tree::new();
        let outside = Tree::new();
        std::fs::write(outside.0.join("private"), b"not cache content").unwrap();
        std::os::unix::fs::symlink(&outside.0, tree.0.join("directory-link")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("private"), tree.0.join("file-link")).unwrap();
        assert_eq!(directory_footprint(&tree.0), (0, 0, true));
        std::fs::create_dir_all(outside.0.join("owner/archives")).unwrap();
        std::fs::write(
            outside.0.join("owner/archives/private"),
            b"not cache content",
        )
        .unwrap();
        assert_eq!(
            directory_footprint(&tree.0.join("directory-link/owner/archives")),
            (0, 0, true),
            "an intermediate symlink must not redirect inspection"
        );
    }
}
