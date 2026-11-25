//! `orbit plugin import --from-claude`: bring in the plugins Claude Code has installed and enabled.
//!
//! Two records in Claude Code's config folder say what to import: `plugins/installed_plugins.json`
//! (what is installed, and where each copy lives) and the `enabledPlugins` map of `settings.json`
//! (what is switched on). Each enabled, user-scope plugin goes through the ordinary importer, read
//! the way Claude Code reads plugins (`lenient`), at user scope.
//!
//! What this never does: run package code; write anywhere but ORBIT's plugin store; change a
//! plugin ORBIT already holds (a copy that differs is named, with the command that would replace
//! it); or touch anything else in Claude Code's folder, which is where its credentials live. From
//! `settings.json` only `enabledPlugins` is taken, and the rest of the file is neither kept nor shown.

use crate::CliError;
use crate::plugin_commands::{components_phrase, human_lines, open_store, usage};
use orbit_plugin_compat::{
    CompatError, ComponentKind, DiagnosticSeverity, InspectOptions, Inspection, PluginFormat,
    PluginId, PluginStore, StoreScope,
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The registry format this was written against. Another version is refused, not guessed at.
const REGISTRY_VERSION: u64 = 2;
const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_WARNINGS: usize = 12;

struct Request {
    dry_run: bool,
    only: Vec<String>,
}

/// `import --from-claude [--dry-run] [--only NAME]...`, the words after `import`.
pub fn command(home: &Path, project: &Path, words: &[&str]) -> Result<Value, CliError> {
    let request = parse(words)?;
    let claude = orbit_engine::hooks::claude_config_dir().ok_or_else(|| {
        CliError::ConfigInvalid(
            "Claude Code's config folder is not known (no HOME and no CLAUDE_CONFIG_DIR)".into(),
        )
    })?;
    import_from(home, project, &claude, &request)
}

fn parse(words: &[&str]) -> Result<Request, CliError> {
    let (mut from, mut dry_run) = (false, false);
    let mut only: Vec<String> = Vec::new();
    let mut index = 0;
    while index < words.len() {
        match words[index] {
            "--from-claude" => {
                if from {
                    return Err(usage("duplicate --from-claude flag"));
                }
                from = true;
            }
            "--dry-run" => {
                if dry_run {
                    return Err(usage("duplicate --dry-run flag"));
                }
                dry_run = true;
            }
            "--only" => {
                index += 1;
                let name = words
                    .get(index)
                    .filter(|name| !name.starts_with('-'))
                    .ok_or_else(|| usage("--only requires a plugin name"))?;
                if !plain_name(name.split('@').next().unwrap_or_default()) {
                    return Err(usage("--only takes a plugin name or NAME@MARKETPLACE"));
                }
                if !only.iter().any(|known| known == name) {
                    only.push((*name).to_owned());
                }
            }
            flag if flag.starts_with('-') => {
                return Err(usage(&format!(
                    "{flag} does not go with --from-claude, which takes only --dry-run, --only NAME and --json"
                )));
            }
            _ => {
                return Err(usage(
                    "--from-claude imports from Claude Code's own records and takes no package path",
                ));
            }
        }
        index += 1;
    }
    Ok(Request { dry_run, only })
}

/// A name that is safe to print and to put in a command line.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// One plugin Claude Code has enabled.
struct Candidate {
    name: String,
    marketplace: String,
    /// Where Claude Code keeps this install, when it has a user-scope one.
    install: Install,
}

enum Install {
    At(PathBuf),
    /// Enabled, but the registry has no record of it.
    NotInstalled,
    /// Installed only for a project or a local scope, not for the user.
    OtherScope(String),
    /// The key or its value is not something this reads.
    Unreadable(&'static str),
}

fn read_json(path: &Path, limit: u64, what: &str) -> Result<Option<Value>, CliError> {
    let unreadable = |why: &str| CliError::ConfigInvalid(format!("{what} {why}"));
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unreadable("could not be read")),
    };
    if !meta.is_file() || meta.len() > limit {
        return Err(unreadable("is not a regular file of a size this reads"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(limit).read_to_end(&mut bytes))
        .map_err(|_| unreadable("could not be read"))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| unreadable("is not valid JSON"))
}

/// What Claude Code has enabled, in a stable order, and how many installed plugins are not.
fn candidates(claude: &Path) -> Result<(Vec<Candidate>, usize, usize), CliError> {
    let registry = read_json(
        &claude.join("plugins/installed_plugins.json"),
        MAX_REGISTRY_BYTES,
        "plugins/installed_plugins.json",
    )?
    .ok_or_else(|| {
        CliError::ConfigInvalid(format!(
            "plugins/installed_plugins.json was not found under {}; is that Claude Code's config folder?",
            claude.display()
        ))
    })?;
    match registry.get("version").and_then(Value::as_u64) {
        Some(REGISTRY_VERSION) => {}
        other => {
            return Err(CliError::ConfigInvalid(format!(
                "plugins/installed_plugins.json is {}; this reads version {REGISTRY_VERSION} only",
                other.map_or("without a version".to_owned(), |v| format!("version {v}"))
            )));
        }
    }
    let installed = registry
        .get("plugins")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::ConfigInvalid("plugins/installed_plugins.json has no plugins map".into())
        })?;
    // Only `enabledPlugins` is taken from the settings; the rest of the file is dropped unread.
    let settings = read_json(
        &claude.join("settings.json"),
        MAX_SETTINGS_BYTES,
        "settings.json",
    )?;
    let enabled: Map<String, Value> = match settings {
        None => Map::new(),
        Some(Value::Object(mut settings)) => match settings.remove("enabledPlugins") {
            None => Map::new(),
            Some(Value::Object(map)) => map,
            Some(_) => {
                return Err(CliError::ConfigInvalid(
                    "settings.json has an enabledPlugins that is not a map".into(),
                ));
            }
        },
        Some(_) => {
            return Err(CliError::ConfigInvalid(
                "settings.json is not a JSON object".into(),
            ));
        }
    };
    let mut found = Vec::new();
    let mut enabled_and_installed = BTreeSet::new();
    let enabled_count = enabled
        .values()
        .filter(|value| value.as_bool() == Some(true))
        .count();
    for (key, value) in &enabled {
        let (name, marketplace) = key.split_once('@').unwrap_or((key.as_str(), ""));
        if !plain_name(name) || (!marketplace.is_empty() && !plain_name(marketplace)) {
            found.push(Candidate {
                name: "<invalid>".into(),
                marketplace: String::new(),
                install: Install::Unreadable("its name is not a valid plugin name"),
            });
            continue;
        }
        let on = match value {
            Value::Bool(on) => *on,
            _ => {
                found.push(Candidate {
                    name: name.to_owned(),
                    marketplace: marketplace.to_owned(),
                    install: Install::Unreadable(
                        "its enabledPlugins value is neither true nor false",
                    ),
                });
                continue;
            }
        };
        if !on {
            continue;
        }
        let install = match installed.get(key).and_then(Value::as_array) {
            None => Install::NotInstalled,
            Some(installs) => {
                let user = installs
                    .iter()
                    .rev()
                    .find(|install| install.get("scope").and_then(Value::as_str) == Some("user"));
                match user {
                    Some(install) => match install.get("installPath").and_then(Value::as_str) {
                        Some(path) if !path.is_empty() => {
                            enabled_and_installed.insert(key.clone());
                            Install::At(PathBuf::from(path))
                        }
                        _ => Install::Unreadable("its install record has no installPath"),
                    },
                    None => {
                        enabled_and_installed.insert(key.clone());
                        Install::OtherScope(
                            installs
                                .iter()
                                .filter_map(|install| install.get("scope").and_then(Value::as_str))
                                .find(|scope| plain_name(scope))
                                .unwrap_or("another")
                                .to_owned(),
                        )
                    }
                }
            }
        };
        found.push(Candidate {
            name: name.to_owned(),
            marketplace: marketplace.to_owned(),
            install,
        });
    }
    found.sort_by(|a, b| (&a.name, &a.marketplace).cmp(&(&b.name, &b.marketplace)));
    let not_enabled = installed
        .keys()
        .filter(|key| !enabled_and_installed.contains(*key))
        .count();
    Ok((found, enabled_count, not_enabled))
}

/// The installs of one candidate must sit inside Claude Code's own plugin folder: the registry is a
/// file in the operator's home, and a path in it is not a reason to copy some other folder into a
/// store.
fn inside_plugins_folder(claude: &Path, install: &Path) -> bool {
    match (
        claude.join("plugins").canonicalize(),
        install.canonicalize(),
    ) {
        (Ok(root), Ok(path)) => path.starts_with(&root) && path.is_dir(),
        _ => false,
    }
}

fn entry(candidate: &Candidate, status: &str) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("name".into(), json!(candidate.name));
    map.insert("marketplace".into(), json!(candidate.marketplace));
    map.insert("status".into(), json!(status));
    map
}

fn skipped(candidate: &Candidate, reason: &str) -> Value {
    let mut map = entry(candidate, "skipped");
    map.insert("reason".into(), json!(reason));
    Value::Object(map)
}

fn refused(candidate: &Candidate, code: &str, reason: &str) -> Value {
    let mut map = entry(candidate, "refused");
    map.insert("code".into(), json!(code));
    map.insert("reason".into(), json!(reason));
    Value::Object(map)
}

fn count(inspection: &Inspection) -> (Value, u64, u64) {
    let (mut skill, mut agent, mut command, mut hook, mut mcp) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for component in &inspection.components {
        match component.kind {
            ComponentKind::Skill(_) => skill += 1,
            ComponentKind::Agent(_) => agent += 1,
            ComponentKind::Command(_) => command += 1,
            ComponentKind::Hook(_) => hook += 1,
            ComponentKind::Mcp(_) => mcp += 1,
            _ => {}
        }
    }
    (
        json!({"skill": skill, "agent": agent, "command": command, "hook": hook, "mcp": mcp}),
        hook,
        mcp,
    )
}

/// What an inspected plugin holds and what stays off, as the fields of a report entry.
fn describe(map: &mut Map<String, Value>, inspection: &Inspection) {
    let (components, hooks, mcp) = count(inspection);
    let left_out = inspection
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "component_skipped")
        .count();
    let mut warnings: Vec<&str> = inspection
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity != DiagnosticSeverity::Info)
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    warnings.sort_unstable();
    warnings.dedup();
    warnings.truncate(MAX_WARNINGS);
    if let Some(version) = &inspection.manifest.version {
        map.insert("version".into(), json!(version));
    }
    if inspection.manifest.id != map.get("name").and_then(Value::as_str).unwrap_or_default() {
        map.insert("stored_as".into(), json!(inspection.manifest.id));
    }
    map.insert(
        "digest".into(),
        json!(
            inspection
                .source
                .source_digest
                .get(..16)
                .unwrap_or(&inspection.source.source_digest)
        ),
    );
    map.insert("components".into(), components);
    map.insert(
        "withheld".into(),
        json!({"hooks": hooks, "mcp_servers": mcp, "left_out": left_out}),
    );
    map.insert("warnings".into(), json!(warnings));
}

/// A path that can go in a command line the operator might paste.
fn pasteable(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    (!text.chars().any(|c| c.is_control() || c == '\'')).then(|| format!("'{text}'"))
}

fn import_from(
    home: &Path,
    project: &Path,
    claude: &Path,
    request: &Request,
) -> Result<Value, CliError> {
    let (all, enabled, not_enabled) = candidates(claude)?;
    let options = InspectOptions {
        format: Some(PluginFormat::Claude),
        lenient: true,
        ..InspectOptions::default()
    };
    // A dry run only reads; so does the store when there is nothing to import into yet.
    let store: PluginStore = open_store(home, project)?;
    let selected = |candidate: &Candidate| {
        request.only.is_empty()
            || request.only.iter().any(|only| {
                only == &candidate.name
                    || only == &format!("{}@{}", candidate.name, candidate.marketplace)
            })
    };
    let mut entries: Vec<Value> = Vec::new();
    // A plugin's stored name is its manifest's, and ORBIT keeps one plugin per name.
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    for candidate in all.iter().filter(|candidate| selected(candidate)) {
        let path = match &candidate.install {
            Install::At(path) => path,
            Install::NotInstalled => {
                entries.push(skipped(
                    candidate,
                    "enabled in Claude Code but not installed (it has no record in installed_plugins.json)",
                ));
                continue;
            }
            Install::OtherScope(scope) => {
                entries.push(skipped(
                    candidate,
                    &format!(
                        "installed for the {scope} scope only, not for you; ORBIT imports user-scope plugins"
                    ),
                ));
                continue;
            }
            Install::Unreadable(reason) => {
                entries.push(skipped(candidate, reason));
                continue;
            }
        };
        if !inside_plugins_folder(claude, path) {
            entries.push(refused(
                candidate,
                "install_path_outside",
                "its install path is outside Claude Code's plugin folder, or is not a folder; it is not copied",
            ));
            continue;
        }
        let inspection = match orbit_plugin_compat::inspect(path, &options) {
            Ok(inspection) => inspection,
            Err(error) => {
                entries.push(refused(
                    candidate,
                    &code_of(&error),
                    "it could not be read as a plugin",
                ));
                continue;
            }
        };
        let stored_name = inspection.manifest.id.clone();
        if let Some(first) = claimed.get(&stored_name) {
            entries.push(skipped(
                candidate,
                &format!(
                    "another copy named {stored_name} (from {first}) is imported in this run; ORBIT keeps one plugin per name"
                ),
            ));
            continue;
        }
        claimed.insert(stored_name.clone(), candidate.marketplace.clone());
        let id = PluginId {
            name: stored_name,
            scope: StoreScope::User,
        };
        let (status, code, hint, reason) = if request.dry_run {
            match store.status(&id) {
                Ok(None) => ("would_import", None, None, None),
                Ok(Some(held)) if held.digest != inspection.source.source_digest => {
                    ("changed", None, upgrade_hint(&id.name, path), None)
                }
                Ok(Some(held)) if held.options != options || !held.enabled => {
                    ("kept", None, None, Some(KEPT))
                }
                Ok(Some(_)) => ("already", None, None, None),
                Err(error) => ("refused", Some(code_of(&error)), None, None),
            }
        } else {
            match store.import(path, &options, StoreScope::User, true) {
                Ok(receipt) if receipt.reused => ("already", None, None, None),
                Ok(_) => ("imported", None, None, None),
                Err(error) if error.code == "store_upgrade_required" => {
                    ("changed", None, upgrade_hint(&id.name, path), None)
                }
                Err(error) if error.code == "store_state_conflict" => {
                    ("kept", None, None, Some(KEPT))
                }
                Err(error) => ("refused", Some(code_of(&error)), None, None),
            }
        };
        let mut map = entry(candidate, status);
        describe(&mut map, &inspection);
        if let Some(code) = code {
            map.insert("code".into(), json!(code));
            map.insert("reason".into(), json!("the store would not take it"));
        }
        if status == "changed" {
            map.insert(
                "reason".into(),
                json!("Claude Code's copy differs from the one ORBIT holds; ORBIT's is unchanged"),
            );
        }
        if let Some(reason) = reason {
            map.insert("reason".into(), json!(reason));
        }
        if let Some(hint) = hint {
            map.insert("hint".into(), json!(hint));
        }
        entries.push(Value::Object(map));
    }
    for only in &request.only {
        let found = all.iter().any(|candidate| {
            only == &candidate.name
                || only == &format!("{}@{}", candidate.name, candidate.marketplace)
        });
        if !found {
            entries.push(json!({
                "name": only.split('@').next().unwrap_or(only),
                "marketplace": only.split_once('@').map_or("", |(_, market)| market),
                "status": "skipped",
                "reason": "no plugin of that name is enabled in Claude Code",
            }));
        }
    }
    let tally = |status: &str| {
        entries
            .iter()
            .filter(|entry| entry["status"] == status)
            .count()
    };
    let summary = json!({
        "enabled": enabled,
        "imported": tally("imported"),
        "would_import": tally("would_import"),
        "already": tally("already"),
        "changed": tally("changed"),
        "kept": tally("kept"),
        "refused": tally("refused"),
        "skipped": tally("skipped"),
        "not_enabled": not_enabled,
    });
    Ok(json!({
        "schema": "orbit.cli/v1",
        "command": "plugin import",
        "status": "ok",
        "package_code_executed": false,
        "runtime_readiness": "unchecked",
        "bulk": {
            "source": "claude",
            "dry_run": request.dry_run,
            "lenient": true,
            "summary": summary,
            "plugins": entries,
        },
    }))
}

const KEPT: &str = "ORBIT already holds it with other settings (disabled, or imported without --lenient); it is left as it is";

fn upgrade_hint(name: &str, path: &Path) -> Option<String> {
    pasteable(path).map(|path| format!("orbit plugin upgrade {name} {path}"))
}

/// A refusal's code, which names no file and quotes no package text.
fn code_of(error: &CompatError) -> String {
    error
        .code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(96)
        .collect()
}

/// The report for people. One line per plugin, the totals, and what stays off.
pub fn human_report(value: &Value) -> String {
    let bulk = &value["bulk"];
    let dry = bulk["dry_run"].as_bool() == Some(true);
    let text = |v: &Value| v.as_str().unwrap_or("").to_owned();
    let mut lines = vec![
        if dry {
            "Preview of an import from Claude Code (nothing was written):".to_owned()
        } else {
            "Imported from Claude Code:".to_owned()
        },
        "Read the way Claude Code reads plugins (--lenient); user scope; no package code was run."
            .to_owned(),
    ];
    let mut holds_hooks = Vec::new();
    for plugin in bulk["plugins"].as_array().into_iter().flatten().take(512) {
        let name = text(&plugin["name"]);
        let market = text(&plugin["marketplace"]);
        let who = if market.is_empty() {
            name.clone()
        } else {
            format!("{name}@{market}")
        };
        let status = text(&plugin["status"]);
        let mut line = format!("  {status:<12} {who}");
        if let Some(version) = plugin["version"].as_str() {
            line.push_str(&format!(" {version}"));
        }
        if let Some(components) = plugin["components"].as_object() {
            let holds = components_phrase(components);
            if !holds.is_empty() {
                line.push_str(&format!(" — {holds}"));
            }
        }
        let withheld = &plugin["withheld"];
        let hooks = withheld["hooks"].as_u64().unwrap_or(0);
        let mcp = withheld["mcp_servers"].as_u64().unwrap_or(0);
        let left_out = withheld["left_out"].as_u64().unwrap_or(0);
        let mut off: Vec<String> = Vec::new();
        if hooks > 0 {
            off.push("hooks off until plugin_hooks names it".into());
            if matches!(status.as_str(), "imported" | "would_import" | "already") {
                holds_hooks.push(name.clone());
            }
        }
        if mcp > 0 {
            off.push("MCP servers not started".into());
        }
        if left_out > 0 {
            off.push(format!("{left_out} left out"));
        }
        if !off.is_empty() {
            line.push_str(&format!(" [{}]", off.join("; ")));
        }
        if let Some(code) = plugin["code"].as_str() {
            line.push_str(&format!(" ({code})"));
        }
        if let Some(reason) = plugin["reason"].as_str() {
            line.push_str(&format!(": {reason}"));
        }
        lines.push(line);
        if let Some(hint) = plugin["hint"].as_str() {
            lines.push(format!("               to take Claude Code's copy: {hint}"));
        }
    }
    let summary = &bulk["summary"];
    let n = |key: &str| summary[key].as_u64().unwrap_or(0);
    lines.push(format!(
        "{} enabled in Claude Code: {} {}, {} already there, {} changed in Claude Code since, {} kept, {} refused, {} skipped; {} installed but not enabled.",
        n("enabled"),
        n(if dry { "would_import" } else { "imported" }),
        if dry { "would be imported" } else { "imported" },
        n("already"),
        n("changed"),
        n("kept"),
        n("refused"),
        n("skipped"),
        n("not_enabled"),
    ));
    if !holds_hooks.is_empty() {
        holds_hooks.sort();
        holds_hooks.dedup();
        let names: Vec<String> = holds_hooks
            .iter()
            .take(6)
            .map(|name| format!("\"{name}\""))
            .collect();
        lines.push(format!(
            "A plugin's command hooks run only when you name it, in your own settings.toml above the first [table]: plugin_hooks = [{}{}]",
            names.join(", "),
            if holds_hooks.len() > 6 { ", ..." } else { "" }
        ));
    }
    human_lines(lines, false)
}
