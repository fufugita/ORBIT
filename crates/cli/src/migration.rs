//! Offline migration inspection. Source content is summarized, never executed or copied.

use crate::customization::{Directory, read_regular};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_INVENTORY_ENTRIES: usize = 4096;
const MAX_INVENTORY_DEPTH: usize = 8;
const USAGE: &str = "orbit migrate --from claude [--check] [--json]";

#[derive(Default, Serialize)]
struct Source {
    scope: &'static str,
    kind: &'static str,
    status: &'static str,
    detail: &'static str,
    files: usize,
    portable_rules: usize,
    review_rules: usize,
    hook_events: usize,
    status_line: bool,
    skipped_links: usize,
    truncated: bool,
}

impl Source {
    fn new(scope: &'static str, kind: &'static str) -> Self {
        Self {
            scope,
            kind,
            status: "missing",
            detail: "Not present",
            ..Self::default()
        }
    }

    fn blocks(&self) -> bool {
        matches!(
            self.status,
            "invalid" | "unsafe" | "oversized" | "unreadable"
        )
    }
}

/// Check the selected ORBIT home and Claude sources. No writes or requests are made.
pub fn command(home: &Path, workspace: &Path, args: &[String]) -> Result<Value, String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        return Ok(
            json!({"schema":"orbit.cli/v1", "command":"migrate", "status":"ok", "usage":USAGE}),
        );
    }
    let mut from = None;
    let (mut check, mut json_flag) = (false, false);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--from" if from.is_none() => {
                index += 1;
                from = args.get(index).map(String::as_str);
                if from != Some("claude") {
                    return Err(format!("{USAGE}; supported source: claude"));
                }
            }
            "--check" if !check => check = true,
            "--json" if !json_flag => json_flag = true,
            _ => return Err(format!("usage: {USAGE}")),
        }
        index += 1;
    }
    if from != Some("claude") {
        return Err(format!("usage: {USAGE}"));
    }
    let user = orbit_engine::hooks::claude_config_dir();
    let doctor = crate::doctor::doctor(home, workspace);
    let compatible = compatibility(home);
    Ok(inspect(workspace, user.as_deref(), compatible, doctor))
}

fn compatibility(home: &Path) -> Option<bool> {
    match std::env::var("ORBIT_CLAUDE_COMPAT").as_deref() {
        Ok("1" | "true") => return Some(true),
        Ok("0" | "false") => return Some(false),
        _ => {}
    }
    let extra = orbit_tools::executor::extra_settings_file()
        .filter(|path| !orbit_tools::executor::is_json(path));
    compatibility_files(home, extra)
}

fn compatibility_files(home: &Path, extra: Option<PathBuf>) -> Option<bool> {
    let mut enabled = false;
    for path in std::iter::once(home.join("settings.toml")).chain(extra) {
        let Some(bytes) = source_bytes(&path).ok()? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes).ok()?;
        let doc: toml::Table = toml::from_str(text).ok()?;
        if let Some(value) = doc.get("claude_compat") {
            enabled |= value.as_bool()?;
        }
    }
    Some(enabled)
}

fn inspect(
    workspace: &Path,
    user: Option<&Path>,
    compatible: Option<bool>,
    doctor: crate::doctor::DoctorReport,
) -> Value {
    let tools: Vec<String> = crate::tools::tool_definitions()
        .into_iter()
        .map(|tool| tool.name)
        .chain(["Skill", "Task", "Agent"].map(String::from))
        .collect();
    let mut sources = Vec::new();
    for (scope, directory) in user
        .map(|path| ("user", path.to_path_buf()))
        .into_iter()
        .chain(std::iter::once(("project", workspace.join(".claude"))))
    {
        sources.push(settings(&directory.join("settings.json"), scope, &tools));
        if scope == "project" {
            sources.push(settings(
                &directory.join("settings.local.json"),
                scope,
                &tools,
            ));
        }
        for kind in ["commands", "skills"] {
            sources.push(inventory(&directory.join(kind), scope, kind));
        }
    }
    sources.push(json_source(&workspace.join(".mcp.json"), "project", "mcp"));
    for name in ["CLAUDE.md", "AGENTS.md"] {
        sources.push(instruction(&workspace.join(name), name));
    }
    let found = sources.iter().any(|source| source.status != "missing");
    let ready = doctor.ready
        && found
        && compatible.is_some()
        && !sources
            .iter()
            .any(|source| source.blocks() || source.status == "review");
    json!({
        "schema":"orbit.cli/v1", "command":"migrate", "status":if ready {"ok"} else {"attention_required"},
        "source":"claude", "applied":false,
        "report": {
            "ready":ready, "scope":"offline_configuration_only", "source_found":found,
            "claude_compat_enabled":compatible, "sources":sources, "orbit":doctor,
            "limitations":[
                "Claude conversations and durable session history are not imported.",
                "Credentials, project trust and channel approval grants are not copied.",
                "Path-sensitive permission rules and transcript-dependent hooks require review.",
                "Presence of an MCP configuration does not establish authentication or connectivity.",
                "Provider connectivity and full behavioral parity require a live trial."
            ],
            "next_steps":[
                "Resolve invalid or unsafe source files and required orbit doctor checks first.",
                "Preview permission translation with orbit config import-claude; review every omitted rule.",
                "Apply reviewed rules explicitly with orbit config import-claude --apply.",
                "Review hooks, commands and skills before enabling ORBIT_CLAUDE_COMPAT=1 for a trial.",
                "Review orbit folder status and orbit mcp list; trust only the intended project.",
                "Use orbit provider login NAME if the selected provider needs credential setup.",
                "Start a new trial session and check cancellation, resume, compaction and your integrations."
            ]
        }
    })
}

// Inspect every lexical ancestor before a descriptor-backed open. A missing
// ancestor means missing source; an existing symlink is never followed.
pub(crate) fn path_status(path: &Path) -> Result<Option<PathBuf>, &'static str> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "unreadable")?
            .join(path)
    };
    let mut current = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            _ => return Err("unsafe"),
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err("unsafe"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("unreadable"),
        }
    }
    Ok(Some(absolute))
}

pub(crate) fn source_bytes(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    let Some(path) = path_status(path)? else {
        return Ok(None);
    };
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| "unreadable")?;
    if !metadata.is_file() {
        return Err("unsafe");
    }
    if metadata.len() > MAX_SOURCE_BYTES as u64 {
        return Err("oversized");
    }
    let parent = Directory::open(path.parent().ok_or("unsafe")?, false).map_err(|_| "unsafe")?;
    let held = parent
        .io()
        .map_err(|_| "unsafe")?
        .join(path.file_name().ok_or("unsafe")?);
    let bytes = read_regular(&held, MAX_SOURCE_BYTES, false).map_err(|_| "unsafe")?;
    parent.check().map_err(|_| "unsafe")?;
    Ok(Some(bytes))
}

fn failure(source: &mut Source, status: &'static str) {
    source.status = status;
    source.detail = match status {
        "unsafe" => "Symlink, special entry, ownership or identity checks failed",
        "oversized" => "Source exceeds the bounded inspection limit",
        "unreadable" => "Source could not be read",
        _ => "Source configuration is malformed",
    };
}

fn document(path: &Path, source: &mut Source) -> Option<Value> {
    match source_bytes(path) {
        Ok(None) => None,
        Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value.is_object() => {
                source.status = "valid";
                source.detail = "Valid JSON object; nothing executed";
                source.files = 1;
                Some(value)
            }
            _ => {
                failure(source, "invalid");
                None
            }
        },
        Err(status) => {
            failure(source, status);
            None
        }
    }
}

fn json_source(path: &Path, scope: &'static str, kind: &'static str) -> Source {
    let mut source = Source::new(scope, kind);
    let Some(value) = document(path, &mut source) else {
        return source;
    };
    if kind != "mcp" {
        return source;
    }
    let Some(servers) = value.get("mcpServers").and_then(Value::as_object) else {
        failure(&mut source, "invalid");
        return source;
    };
    for server in servers.values() {
        match mcp_server_status(server) {
            Ok(true) => {}
            Ok(false) => {
                source.status = "review";
                source.detail = "Unsupported transport or unresolved target requires review";
            }
            Err(()) => {
                failure(&mut source, "invalid");
                break;
            }
        }
    }
    source
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

fn string_map(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|items| items.values().all(Value::is_string))
}

fn nonempty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

// Use the runtime validator on literal values, without expanding source-owned
// environment references or loading any MCP configuration from disk.
fn mcp_server_status(value: &Value) -> Result<bool, ()> {
    let server = value.as_object().ok_or(())?;
    if !["type", "transport", "command", "url"]
        .iter()
        .all(|key| server.get(*key).is_none_or(Value::is_string))
        || !server.get("args").is_none_or(string_list)
        || !["env", "headers"]
            .iter()
            .all(|key| server.get(*key).is_none_or(string_map))
        || !server.get("disabled").is_none_or(Value::is_boolean)
        || ["command", "url", "type", "transport"]
            .iter()
            .any(|key| server.contains_key(*key) && !nonempty_string(server.get(*key)))
    {
        return Err(());
    }
    let kind = server.get("type").and_then(Value::as_str);
    let transport = match (kind, server.contains_key("url")) {
        (Some("sse"), _) => "sse",
        (Some("http" | "streamable-http"), _) | (None, true) => "streamable-http",
        (Some("stdio") | None, false) => "stdio",
        (Some("stdio"), true) => return Err(()),
        _ => return Ok(false),
    };
    if server.contains_key("transport") {
        // Claude's parser reads `type`; a different spelling must not be
        // silently treated as a supported implicit stdio configuration.
        return Ok(false);
    }
    let mut normalized = server.clone();
    normalized.insert("transport".into(), Value::String(transport.into()));
    let mut config: orbit_mcp::McpServerConfig =
        serde_json::from_value(Value::Object(normalized)).map_err(|_| ())?;
    let unresolved = config.url.as_deref().is_some_and(|url| url.contains("${"));
    if unresolved {
        // Validate the rest of the remote entry while leaving its environment
        // dependent target unresolved and explicitly requiring review.
        config.url = Some("https://unresolved.invalid/mcp".into());
    }
    config.validate().map_err(|_| ())?;
    Ok(!unresolved)
}

fn hook_status(value: &Value) -> Result<bool, ()> {
    let handler = value.as_object().ok_or(())?;
    if ![
        "type", "command", "prompt", "url", "model", "server", "tool", "if",
    ]
    .iter()
    .all(|key| handler.get(*key).is_none_or(Value::is_string))
        || !handler.get("headers").is_none_or(string_map)
        || !handler.get("allowedEnvVars").is_none_or(string_list)
        || !handler.get("async").is_none_or(Value::is_boolean)
        || !handler
            .get("timeout")
            .is_none_or(|value| value.as_u64().is_some_and(|seconds| seconds > 0))
    {
        return Err(());
    }
    match handler.get("type").and_then(Value::as_str) {
        Some("command") => nonempty_string(handler.get("command"))
            .then_some(true)
            .ok_or(()),
        Some("prompt" | "agent") => nonempty_string(handler.get("prompt"))
            .then_some(true)
            .ok_or(()),
        Some("mcp_tool") => (nonempty_string(handler.get("server"))
            && nonempty_string(handler.get("tool"))
            && handler.get("input").is_none_or(Value::is_object))
        .then_some(true)
        .ok_or(()),
        Some("http") => {
            let url = handler.get("url").and_then(Value::as_str).ok_or(())?;
            if url.trim().is_empty() {
                return Err(());
            }
            let headers = handler.get("headers").and_then(Value::as_object);
            if headers.is_some_and(|headers| {
                headers.iter().any(|(name, value)| {
                    name.is_empty()
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                        || value
                            .as_str()
                            .is_none_or(|value| value.contains(['\r', '\n', '\0']))
                })
            }) {
                return Err(());
            }
            if url.contains("${") || headers.is_some_and(|headers| headers.len() > 32) {
                return Ok(false);
            }
            orbit_engine::hooks::http_hook(url, &[], &[]).map_err(|_| ())?;
            Ok(true)
        }
        Some(kind) if !kind.trim().is_empty() => Ok(false),
        _ => Err(()),
    }
}

fn settings(path: &Path, scope: &'static str, tools: &[String]) -> Source {
    let mut source = Source::new(
        scope,
        if path
            .file_name()
            .is_some_and(|name| name == "settings.local.json")
        {
            "settings.local"
        } else {
            "settings"
        },
    );
    let Some(value) = document(path, &mut source) else {
        return source;
    };
    if let Some(permissions) = value.get("permissions") {
        let Some(permissions) = permissions.as_object() else {
            failure(&mut source, "invalid");
            return source;
        };
        for effect in ["deny", "ask", "allow"] {
            let Some(rules) = permissions.get(effect) else {
                continue;
            };
            let Some(rules) = rules.as_array() else {
                failure(&mut source, "invalid");
                return source;
            };
            if rules.len() > 512 {
                failure(&mut source, "oversized");
                return source;
            }
            for rule in rules {
                let Some(rule) = rule.as_str() else {
                    failure(&mut source, "invalid");
                    return source;
                };
                if crate::claude_permissions::translate(rule, tools).is_ok() {
                    source.portable_rules += 1;
                } else {
                    source.review_rules += 1;
                    if effect != "allow" {
                        source.status = "review";
                        source.detail =
                            "Unsupported ask or deny rule requires manual permission migration";
                    }
                }
            }
        }
    }
    if let Some(hooks) = value.get("hooks") {
        let Some(hooks) = hooks.as_object() else {
            failure(&mut source, "invalid");
            return source;
        };
        for event in hooks.values() {
            let Some(entries) = event.as_array() else {
                failure(&mut source, "invalid");
                return source;
            };
            for entry in entries {
                let Some(entry) = entry.as_object() else {
                    failure(&mut source, "invalid");
                    return source;
                };
                if !entry.get("matcher").is_none_or(Value::is_string) {
                    failure(&mut source, "invalid");
                    return source;
                }
                let Some(handlers) = entry.get("hooks").and_then(Value::as_array) else {
                    failure(&mut source, "invalid");
                    return source;
                };
                for handler in handlers {
                    match hook_status(handler) {
                        Ok(true) => {}
                        Ok(false) => {
                            source.status = "review";
                            source.detail = "Unsupported or unresolved hook requires review";
                        }
                        Err(()) => {
                            failure(&mut source, "invalid");
                            return source;
                        }
                    }
                }
            }
        }
        source.hook_events = hooks.len();
    }
    if let Some(line) = value.get("statusLine") {
        source.status_line = true;
        if !line.is_object() || !line.get("command").is_none_or(Value::is_string) {
            failure(&mut source, "invalid");
            return source;
        }
        match line.get("type").and_then(Value::as_str) {
            Some("command") if nonempty_string(line.get("command")) => {}
            Some(kind) if !kind.trim().is_empty() && kind != "command" => {
                source.status = "review";
                source.detail = "Unsupported status line requires review";
            }
            _ => failure(&mut source, "invalid"),
        }
    }
    source
}

fn instruction(path: &Path, kind: &'static str) -> Source {
    let mut source = Source::new("project", kind);
    match source_bytes(path) {
        Ok(Some(_)) => {
            source.status = "valid";
            source.detail = "Instruction file present; contents not displayed";
            source.files = 1;
        }
        Ok(None) => {}
        Err(status) => failure(&mut source, status),
    }
    source
}

fn inventory(path: &Path, scope: &'static str, kind: &'static str) -> Source {
    let mut source = Source::new(scope, kind);
    match path_status(path) {
        Ok(None) => return source,
        Err(status) => {
            failure(&mut source, status);
            return source;
        }
        Ok(Some(_)) => {}
    }
    source.status = "valid";
    source.detail = "Bounded file inventory; no source code executed";
    let mut pending = vec![(path.to_path_buf(), 0)];
    let mut visited = 0;
    while let Some((path, depth)) = pending.pop() {
        let Ok(dir) = Directory::open(&path, false) else {
            failure(&mut source, "unsafe");
            break;
        };
        let Ok(held) = dir.io() else {
            failure(&mut source, "unsafe");
            break;
        };
        let Ok(entries) = std::fs::read_dir(held) else {
            failure(&mut source, "unreadable");
            break;
        };
        for entry in entries {
            visited += 1;
            if visited > MAX_INVENTORY_ENTRIES {
                source.truncated = true;
                break;
            }
            let Ok(entry) = entry else {
                failure(&mut source, "unreadable");
                break;
            };
            let Ok(kind) = entry.file_type() else {
                failure(&mut source, "unreadable");
                break;
            };
            if kind.is_symlink() {
                source.skipped_links += 1;
            } else if kind.is_file() {
                source.files += 1;
            } else if kind.is_dir() {
                if depth < MAX_INVENTORY_DEPTH {
                    pending.push((path.join(entry.file_name()), depth + 1));
                } else {
                    source.truncated = true;
                }
            } else {
                failure(&mut source, "unsafe");
                break;
            }
        }
        if dir.check().is_err() {
            failure(&mut source, "unsafe");
        }
        if source.blocks() || (source.truncated && visited > MAX_INVENTORY_ENTRIES) {
            break;
        }
    }
    if !source.blocks() && (source.truncated || source.skipped_links > 0) {
        source.status = "review";
        source.detail = "Partial inventory; review omitted links or entries manually";
    }
    source
}

/// Human output deliberately excludes source paths, raw rules and executable text.
pub fn human_report(value: &Value) -> String {
    if let Some(usage) = value["usage"].as_str() {
        return format!("{usage}\n");
    }
    let report = &value["report"];
    let mut text = format!(
        "Offline migration check: {}\nNothing was imported or executed. Provider connectivity is untested.\n\n",
        if report["ready"] == true {
            "ready for a trial"
        } else {
            "needs attention"
        }
    );
    for source in report["sources"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "{} {}: {} — {}\n",
            source["scope"].as_str().unwrap_or(""),
            source["kind"].as_str().unwrap_or(""),
            source["status"].as_str().unwrap_or(""),
            source["detail"].as_str().unwrap_or("")
        ));
        if source["files"].as_u64().unwrap_or(0) > 0 {
            text.push_str(&format!(
                "  {} file(s), {} portable rule(s), {} rule(s) to review, {} hook event(s)\n",
                source["files"],
                source["portable_rules"],
                source["review_rules"],
                source["hook_events"]
            ));
        }
    }
    text.push_str(&format!(
        "\nClaude compatibility: {}\n",
        if report["claude_compat_enabled"].is_null() {
            "unknown; repair unsafe or invalid compatibility settings"
        } else if report["claude_compat_enabled"] == true {
            "enabled"
        } else {
            "off; review executable configuration before enabling"
        }
    ));
    for check in report["orbit"]["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|check| {
            check["required"] == true
                && !matches!(check["status"].as_str(), Some("ready" | "configured"))
        })
    {
        text.push_str(&format!(
            "ORBIT {}: {}\n",
            check["id"].as_str().unwrap_or("check"),
            check["detail"].as_str().unwrap_or("Needs attention")
        ));
    }
    text.push_str("\nNext steps:\n");
    for step in report["next_steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        text.push_str(&format!("  {step}\n"));
    }
    text.push_str(
        "\nSessions, credentials, project trust and channel grants are not transferred.\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("orbit-migration-{}", ulid::Ulid::new()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn doctor(ready: bool) -> crate::doctor::DoctorReport {
        crate::doctor::DoctorReport {
            schema_version: 1,
            ready,
            checks: Vec::new(),
        }
    }

    #[test]
    fn migration_is_summary_only_and_keeps_sources_and_destinations_untouched() {
        let tree = Tree::new();
        let source = tree.write("claude/settings.json", r#"{"permissions":{"allow":["Bash","Read","Read(secret/**)"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo DO_NOT_DISPLAY_SECRET"}]}]},"statusLine":{"type":"command","command":"DO_NOT_DISPLAY_SECRET"}}"#);
        tree.write("project/CLAUDE.md", "DO_NOT_DISPLAY_SECRET");
        let before = std::fs::read(&source).unwrap();
        let value = inspect(
            &tree.0.join("project"),
            Some(&tree.0.join("claude")),
            Some(false),
            doctor(true),
        );
        assert_eq!(value["report"]["ready"], true);
        assert_eq!(value["report"]["sources"][0]["portable_rules"], 1);
        assert_eq!(value["report"]["sources"][0]["review_rules"], 2);
        assert_eq!(value["report"]["sources"][0]["hook_events"], 1);
        assert!(!value.to_string().contains("DO_NOT_DISPLAY_SECRET"));
        assert!(!human_report(&value).contains("secret/**"));
        assert_eq!(std::fs::read(source).unwrap(), before);
        assert!(!tree.0.join("project/.orbit").exists());
    }

    #[test]
    fn unsupported_restrictive_rules_require_review_before_a_trial() {
        for effect in ["ask", "deny"] {
            for rule in ["Read", "Edit", "Read(private/**)", "FutureTool"] {
                let tree = Tree::new();
                let mut permissions = json!({});
                permissions[effect] = json!([rule]);
                let source = tree.write(
                    "claude/settings.json",
                    &json!({"permissions": permissions}).to_string(),
                );
                let before = std::fs::read(&source).unwrap();
                let value = inspect(
                    &tree.0.join("project"),
                    Some(&tree.0.join("claude")),
                    Some(false),
                    doctor(true),
                );
                assert_eq!(value["report"]["ready"], false, "{effect}: {rule}");
                assert_eq!(value["report"]["sources"][0]["status"], "review");
                assert_eq!(value["report"]["sources"][0]["review_rules"], 1);
                assert!(!value.to_string().contains("private/**"));
                assert_eq!(std::fs::read(source).unwrap(), before);
                assert!(!tree.0.join("project/.orbit").exists());
            }
        }
    }

    #[test]
    fn malformed_wrong_shape_and_oversized_settings_block_a_trial() {
        let tree = Tree::new();
        for raw in [
            "{",
            "[]",
            r#"{"permissions":{"allow":"Read"}}"#,
            r#"{"permissions":{"allow":[1]}}"#,
            r#"{"hooks":[]}"#,
        ] {
            let path = tree.write("settings.json", raw);
            assert!(settings(&path, "user", &[]).blocks(), "{raw}");
        }
        let path = tree.write("settings.json", &" ".repeat(MAX_SOURCE_BYTES + 1));
        assert_eq!(settings(&path, "user", &[]).status, "oversized");
        tree.write(
            "settings.json",
            &json!({"permissions":{"allow":vec!["Read";513]}}).to_string(),
        );
        assert_eq!(settings(&path, "user", &[]).status, "oversized");
    }

    #[test]
    fn missing_source_and_required_doctor_failure_are_not_ready() {
        let tree = Tree::new();
        let empty = inspect(&tree.0, None, Some(false), doctor(true));
        assert_eq!(empty["report"]["ready"], false);
        tree.write("CLAUDE.md", "instructions");
        assert_eq!(
            inspect(&tree.0, None, Some(false), doctor(false))["report"]["ready"],
            false
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_file_or_parent_is_refused_and_inventory_links_are_not_followed() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let target = tree.write("real/settings.json", "{}");
        symlink(&target, tree.0.join("linked.json")).unwrap();
        assert_eq!(
            settings(&tree.0.join("linked.json"), "user", &[]).status,
            "unsafe"
        );
        symlink(tree.0.join("real"), tree.0.join("linked-dir")).unwrap();
        assert_eq!(
            settings(&tree.0.join("linked-dir/settings.json"), "user", &[]).status,
            "unsafe"
        );
        tree.write("skills/example/SKILL.md", "source");
        symlink(tree.0.join("real"), tree.0.join("skills/linked")).unwrap();
        let source = inventory(&tree.0.join("skills"), "user", "skills");
        assert_eq!(source.files, 1);
        assert_eq!(source.skipped_links, 1);
        assert_eq!(source.status, "review");
    }

    #[test]
    fn deep_inventory_is_explicitly_partial() {
        let tree = Tree::new();
        let deep = format!("skills/{}SKILL.md", "dir/".repeat(MAX_INVENTORY_DEPTH + 2));
        tree.write(&deep, "source");
        let source = inventory(&tree.0.join("skills"), "user", "skills");
        assert_eq!(source.status, "review");
        assert!(source.truncated);
    }

    #[test]
    fn invalid_grammar_is_rejected_before_inspecting_any_source() {
        for args in [
            vec![],
            vec!["--from", "codex"],
            vec!["--apply"],
            vec!["--from", "claude", "--from", "claude"],
            vec!["--from", "claude", "--json", "--json"],
        ] {
            assert!(
                command(
                    Path::new("/does-not-exist"),
                    Path::new("/does-not-exist"),
                    &args.into_iter().map(String::from).collect::<Vec<_>>()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn malformed_hook_and_mcp_shapes_are_blocking() {
        let tree = Tree::new();
        for raw in [
            r#"{"hooks":{"Stop":null}}"#,
            r#"{"hooks":{"Stop":[{"hooks":null}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"command":"do not run"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":" "}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"prompt"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"agent","prompt":42}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"mcp_tool","server":"s"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"http","url":""}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"https://example.com","headers":{"Authorization":1}}]}]}}"#,
            r#"{"statusLine":true}"#,
            r#"{"statusLine":{"type":"command"}}"#,
        ] {
            let file = tree.write("settings.json", raw);
            assert_eq!(settings(&file, "user", &[]).status, "invalid", "{raw}");
        }
        for raw in [
            r#"{}"#,
            r#"{"mcpServers":42}"#,
            r#"{"mcpServers":{"example":null}}"#,
            r#"{"mcpServers":{"example":{"command":"server","args":42}}}"#,
            r#"{"mcpServers":{"example":{"command":""}}}"#,
            r#"{"mcpServers":{"example":{"command":"server","type":42}}}"#,
            r#"{"mcpServers":{"example":{"type":"http"}}}"#,
            r#"{"mcpServers":{"example":{"type":"http","url":""}}}"#,
            r#"{"mcpServers":{"example":{"type":"http","url":"not a url"}}}"#,
            r#"{"mcpServers":{"example":{"type":"http","url":"https://example.com","headers":{"Authorization":1}}}}"#,
            r#"{"mcpServers":{"example":{"type":"http","url":"https://example.com","headers":{"Bad Header":"x"}}}}"#,
            r#"{"mcpServers":{"example":{"type":"http","url":"https://example.com","command":"server"}}}"#,
            r#"{"mcpServers":{"example":{"type":"stdio","url":"https://example.com","command":"server"}}}"#,
        ] {
            let file = tree.write(".mcp.json", raw);
            assert_eq!(
                json_source(&file, "project", "mcp").status,
                "invalid",
                "{raw}"
            );
        }
    }

    #[test]
    fn supported_mcp_transports_and_hook_handlers_remain_valid() {
        for server in [
            json!({"command":"server","args":["--stdio"],"env":{"MODE":"safe"}}),
            json!({"type":"stdio","command":"server"}),
            json!({"type":"http","url":"https://example.com/mcp","headers":{"Authorization":"Bearer literal"}}),
            json!({"type":"streamable-http","url":"https://example.com/mcp"}),
            json!({"type":"sse","url":"http://localhost:8080/events"}),
            json!({"url":"https://example.com/mcp"}),
        ] {
            assert_eq!(mcp_server_status(&server), Ok(true), "{server}");
        }
        for handler in [
            json!({"type":"command","command":"echo safe"}),
            json!({"type":"prompt","prompt":"Check the result","model":"small"}),
            json!({"type":"agent","prompt":"Check the tests"}),
            json!({"type":"mcp_tool","server":"s","tool":"check","input":{}}),
            json!({"type":"http","url":"https://example.com/hook","headers":{"Authorization":"Bearer $TOKEN"},"allowedEnvVars":["TOKEN"]}),
        ] {
            assert_eq!(hook_status(&handler), Ok(true), "{handler}");
        }
    }

    #[test]
    fn unsupported_or_unresolved_executable_settings_require_review() {
        let tree = Tree::new();
        for server in [
            json!({"type":"ws","url":"wss://example.com/mcp"}),
            json!({"transport":"stdio","command":"server"}),
            json!({"type":"http","url":"${MCP_ENDPOINT}"}),
        ] {
            tree.write(".mcp.json", &json!({"mcpServers":{"s":server}}).to_string());
            let report = inspect(&tree.0, None, Some(false), doctor(true));
            assert_eq!(report["report"]["ready"], false);
            assert!(
                report["report"]["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|source| { source["kind"] == "mcp" && source["status"] == "review" })
            );
        }
        std::fs::remove_file(tree.0.join(".mcp.json")).unwrap();
        tree.write(
            ".claude/settings.json",
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"future_handler"}]}]}}"#,
        );
        let report = inspect(&tree.0, None, Some(false), doctor(true));
        assert_eq!(report["report"]["ready"], false);
        assert_eq!(report["report"]["sources"][0]["status"], "review");
    }

    #[cfg(unix)]
    #[test]
    fn compatibility_reads_are_bounded_and_never_follow_links() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let home = tree.0.join("home");
        let file = tree.write("home/settings.toml", "claude_compat = true\n");
        assert_eq!(compatibility_files(&home, None), Some(true));
        std::fs::write(&file, " ".repeat(MAX_SOURCE_BYTES + 1)).unwrap();
        assert_eq!(compatibility_files(&home, None), None);
        std::fs::remove_file(&file).unwrap();
        let target = tree.write("outside.toml", "claude_compat = true\n");
        symlink(target, &file).unwrap();
        assert_eq!(compatibility_files(&home, None), None);
        let report = inspect(&tree.0, None, None, doctor(true));
        assert_eq!(report["report"]["ready"], false);
        assert!(human_report(&report).contains("unknown; repair"));
    }
}
