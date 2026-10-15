//! The Wave 1 executor — the shared tool-execution path every
//! front-end plugs into the engine (roadmap phase 3).
//!
//! Owns: the tool registry, the permission evaluation (mode + rules +
//! deny-read), the approval channel handoff, the secret scanner on
//! every result, and the ledger's intent/verdict/result records.

use crate::permissions::{PermissionMode, RuleSet, Verdict};
use crate::{ToolContext, ToolResult, registry};
use orbit_adapter::types::ToolDefinition;
use std::path::{Path, PathBuf};

/// What an approval channel needs to render a card.
#[derive(Debug, Clone)]
pub struct ApprovalCard {
    pub call_id: String,
    pub tool: String,
    /// Display-safe summary (argument keys, not values).
    pub summary: String,
    /// 1 low, 2 medium, 3 high (computed from the command/paths).
    pub risk: u8,
    /// Real facts for the card (roadmap: no invented facts): the
    /// working directory and the computed risk. Sandbox profile and
    /// network policy appear when phase 3's sandbox lands.
    pub working_dir: String,
}

/// The operator's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAnswer {
    AllowOnce,
    /// Always allow this pattern (saved to the local scope).
    Always,
    /// Allow for this session.
    Session,
    Deny,
}

/// Front-end-supplied approval interaction.
pub trait ApprovalChannel: Send {
    fn ask(&mut self, card: &ApprovalCard) -> ApprovalAnswer;
}

/// A channel that denies everything (headless / dontAsk).
pub struct DenyAll;
impl ApprovalChannel for DenyAll {
    fn ask(&mut self, _card: &ApprovalCard) -> ApprovalAnswer {
        ApprovalAnswer::Deny
    }
}

/// Session-scoped pattern grants (`s` and `a` answers).
#[derive(Default)]
pub struct SessionGrants {
    allowed: std::collections::HashSet<String>,
}

impl SessionGrants {
    pub fn grant(&mut self, key: String) {
        self.allowed.insert(key);
    }
    pub fn is_granted(&self, key: &str) -> bool {
        self.allowed.contains(key)
    }
}

/// The Wave 1 executor. One per session; the engine calls
/// `execute` per round.
pub struct Wave1Executor<'a> {
    pub mode: PermissionMode,
    pub rules: RuleSet,
    pub cx: ToolContext,
    pub approvals: &'a mut dyn ApprovalChannel,
    pub grants: SessionGrants,
    /// Ledger home for intent/verdict/result records (None = no ledger).
    pub ledger_home: Option<PathBuf>,
    pub session_id: String,
}

impl<'a> Wave1Executor<'a> {
    pub fn new(
        mode: PermissionMode,
        rules: RuleSet,
        cx: ToolContext,
        approvals: &'a mut dyn ApprovalChannel,
        ledger_home: Option<PathBuf>,
    ) -> Self {
        let session_id = cx.session_id.clone();
        Wave1Executor {
            mode,
            rules,
            cx,
            approvals,
            grants: SessionGrants::default(),
            ledger_home,
            session_id,
        }
    }

    /// Execute one call. Returns the JSON payload for the model.
    pub fn execute_call(&mut self, call: &CallForExecution) -> String {
        let Some(tool) = registry().into_iter().find(|t| t.name() == call.name) else {
            return ToolResult::err("unknown tool (deny-by-default)").payload;
        };
        let input: serde_json::Value = match serde_json::from_str(&call.arguments) {
            Ok(v) => v,
            Err(e) => return ToolResult::err(&format!("bad arguments: {e}")).payload,
        };
        let key = tool.permission_key(&input);
        let grant_key = format!("{}({})", key.tool, key.pattern);

        // Permission evaluation: mode + rules + read-only classification.
        let is_ro_tool = tool.read_only();
        let is_ro_cmd = call.name == "Bash"
            && crate::bash::is_readonly_command(
                input.get("command").and_then(|v| v.as_str()).unwrap_or(""),
            );
        let (mut verdict, _sandbox_up) = {
            // evaluate_live: mode/rules semantics + the fallback rule
            // (no shell sandbox → every Bash command asks).
            crate::permissions::evaluate_live(
                self.mode,
                &self.rules,
                &key.tool,
                &key.pattern,
                is_ro_tool,
                is_ro_cmd,
            )
        };
        // A remembered grant can cover a default ask, never a deny or a
        // configured confirmation rule. Deliberate bypass remains in evaluate.
        if verdict == Verdict::Ask
            && self.grants.is_granted(&grant_key)
            && self.rules.evaluate(&key.tool, &key.pattern)
                != Some(crate::permissions::RuleEffect::Ask)
        {
            verdict = Verdict::Allow;
        }

        match verdict {
            Verdict::Allow => {}
            Verdict::Deny(reason) => {
                return ToolResult::err(&reason).payload;
            }
            Verdict::Ask => {
                let card = ApprovalCard {
                    call_id: call.id.clone(),
                    tool: call.name.clone(),
                    summary: summarize(&input),
                    risk: risk_for(&call.name, &input),
                    working_dir: self.cx.working_dir.to_string_lossy().into_owned(),
                };
                match self.approvals.ask(&card) {
                    ApprovalAnswer::AllowOnce => {}
                    ApprovalAnswer::Always => {
                        // TODO(phase 3 persistence): write to the local
                        // settings scope. For now: session grant.
                        self.grants.grant(grant_key);
                    }
                    ApprovalAnswer::Session => {
                        self.grants.grant(grant_key);
                    }
                    ApprovalAnswer::Deny => {
                        return ToolResult::denied("denied by you").payload;
                    }
                }
            }
        }

        // Execute + scan + spill.
        let result = tool.run(&input, &self.cx);
        let result = crate::finish(result, &self.cx, &call.id);
        result.payload
    }
}

/// One tool call as the engine hands it over.
pub struct CallForExecution {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Display-safe summary: argument keys only, never values.
fn summarize(input: &serde_json::Value) -> String {
    match input.as_object() {
        Some(obj) => obj.keys().take(4).cloned().collect::<Vec<_>>().join(", "),
        None => String::new(),
    }
}

/// Risk: Bash commands by content; writes medium; reads low.
fn risk_for(tool: &str, input: &serde_json::Value) -> u8 {
    match tool {
        "Bash" => {
            crate::bash::command_risk(input.get("command").and_then(|v| v.as_str()).unwrap_or(""))
        }
        "Write" | "Edit" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod grant_precedence_tests {
    use super::*;
    use crate::permissions::{RuleEffectSerde, parse_rule};

    struct Refuse(usize);
    impl ApprovalChannel for Refuse {
        fn ask(&mut self, _: &ApprovalCard) -> ApprovalAnswer {
            self.0 += 1;
            ApprovalAnswer::Deny
        }
    }

    #[test]
    fn remembered_grants_do_not_skip_deny_or_explicit_confirmation() {
        for effect in [RuleEffectSerde::Deny, RuleEffectSerde::Ask] {
            let path =
                std::env::temp_dir().join(format!("orbit-wave1-policy-{}", ulid::Ulid::new()));
            std::fs::create_dir_all(&path).unwrap();
            let cx = ToolContext::new(path.clone(), "owner".into(), path.clone());
            let mut approval = Refuse(0);
            let rule = parse_rule("Write", effect).unwrap();
            let mut executor = Wave1Executor::new(
                PermissionMode::Default,
                RuleSet { rules: vec![rule] },
                cx,
                &mut approval,
                None,
            );
            executor.grants.grant("Write(out.txt)".into());
            let output = executor.execute_call(&CallForExecution {
                id: "one".into(),
                name: "Write".into(),
                arguments: r#"{"file_path":"out.txt","content":"must not write"}"#.into(),
            });
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap()["ok"],
                false,
                "{output}"
            );
            assert!(!path.join("out.txt").exists());
            drop(executor);
            assert_eq!(approval.0, usize::from(effect == RuleEffectSerde::Ask));
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}

/// The definitions the engine advertises (Wave 1 set).
pub fn wave1_definitions() -> Vec<ToolDefinition> {
    crate::tool_definitions()
}

/// Load the merged rule set from the settings scopes: user, then the
/// project's `.orbit/settings.toml` and `.orbit/settings.local.toml`
/// (both under the current directory), then the old whole-tool
/// `permissions.toml`.
///
/// A folder that is not trusted cannot grant itself anything: its
/// `deny` and `ask` rules still apply (they only make ORBIT stricter),
/// its `allow` rules do not. Without that, cloning a repository and
/// running `orbit` in it would be enough to have `Bash(*)` allowed.
/// `orbit folder trust` is how a person extends trust.
pub fn load_rules(home: &Path) -> RuleSet {
    let project = std::env::current_dir().unwrap_or_default();
    load_rules_in(home, &project)
}

/// [`load_rules`] for an explicit project directory.
pub fn load_rules_in(home: &Path, project: &Path) -> RuleSet {
    match load_sourced_rules_in(home, project) {
        Ok(entries) => RuleSet {
            rules: entries
                .into_iter()
                .filter(|entry| !entry.shadowed)
                .map(|entry| entry.rule)
                .collect(),
        },
        Err(error) => {
            warn_once(home, &error);
            RuleSet::default()
        }
    }
}

/// The source label is a bounded scope name, never an unrelated file's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedPermissionRule {
    pub rule: crate::permissions::PermissionRule,
    pub source: &'static str,
    pub shadowed: bool,
}

/// Strict loader used by execution and the effective policy view.
pub fn load_sourced_rules_in(
    home: &Path,
    project: &Path,
) -> Result<Vec<SourcedPermissionRule>, String> {
    let trusted = crate::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    let mut entries = Vec::new();
    // A file that exists but does not parse is WARNED, never silently
    // skipped (S1: silent skip deleted the user's deny rules).
    for (path, scope, source) in [
        (home.join("settings.toml"), Scope::User, "user"),
        (
            project.join(".orbit/settings.toml"),
            Scope::Project,
            "project",
        ),
        (
            project.join(".orbit/settings.local.toml"),
            Scope::Project,
            "project-local",
        ),
        (home.join("permissions.toml"), Scope::Legacy, "legacy"),
        (
            home.join("permission-overrides.toml"),
            Scope::User,
            "operator-override",
        ),
    ] {
        if source == "operator-override"
            && std::fs::symlink_metadata(&path)
                .is_ok_and(|meta| !meta.file_type().is_file() || meta.len() > 64 * 1024)
        {
            return Err("operator override path must be a bounded regular file".into());
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{source} permission rules cannot be read: {error}")),
        };
        validate_rule_file(&text, matches!(scope, Scope::Legacy))
            .map_err(|error| format!("{source} permission rules: {error}"))?;
        if source == "operator-override" {
            validate_override_file(&text)?;
        }
        let mut rules = RuleSet::default();
        match toml_parse(&text) {
            Ok(v) => match scope {
                Scope::Legacy => merge_legacy(&mut rules, &v),
                Scope::User => {
                    merge_scope(&mut rules, &v, true);
                }
                Scope::Project => {
                    let skipped = merge_scope(&mut rules, &v, trusted);
                    if skipped > 0 {
                        warn_once(
                            &path,
                            &format!(
                                "{skipped} allow rule(s) NOT applied: this folder is not trusted (orbit folder trust)"
                            ),
                        );
                    }
                }
            },
            Err(error) => return Err(format!("{source} permission rules: {error}")),
        }
        entries.extend(rules.rules.into_iter().map(|rule| SourcedPermissionRule {
            rule,
            source,
            shadowed: false,
        }));
    }
    let overrides: std::collections::HashSet<_> = entries
        .iter()
        .filter(|entry| entry.source == "operator-override")
        .map(|entry| entry.rule.tool.clone())
        .collect();
    for entry in &mut entries {
        entry.shadowed = entry.source != "operator-override"
            && entry.rule.effect != crate::permissions::RuleEffectSerde::Deny
            && entry.rule.pattern.is_empty()
            && overrides.contains(&entry.rule.tool);
    }
    Ok(entries)
}

fn validate_rule_file(text: &str, legacy: bool) -> Result<(), String> {
    let doc: toml::Table = toml::from_str(text).map_err(|_| "invalid TOML".to_string())?;
    if legacy {
        for (key, value) in &doc {
            if !matches!(key.as_str(), "allow" | "deny") {
                return Err("legacy permissions support only allow and deny tables".into());
            }
            let table = value
                .as_table()
                .ok_or_else(|| "legacy permission sections must be tables".to_string())?;
            if table.keys().any(|key| key != "tools") {
                return Err("legacy permission tables support only tools".into());
            }
        }
    }
    if !legacy
        && doc
            .get("permissions")
            .is_some_and(|value| !value.is_table())
    {
        return Err("permissions must be a table".into());
    }
    for effect in ["allow", "ask", "deny"] {
        let value = if legacy {
            doc.get(effect).and_then(|table| table.get("tools"))
        } else {
            doc.get("permissions").and_then(|table| table.get(effect))
        };
        if let Some(value) = value {
            let array = value
                .as_array()
                .ok_or_else(|| format!("{effect} must be an array"))?;
            for entry in array {
                let raw = entry
                    .as_str()
                    .ok_or_else(|| format!("{effect} entries must be strings"))?;
                let rule =
                    crate::permissions::parse_rule(raw, crate::permissions::RuleEffectSerde::Ask)
                        .ok_or_else(|| "empty or malformed permission rule".to_string())?;
                if rule.tool.len() > 256 || rule.tool.chars().any(|c| c.is_control()) {
                    return Err(
                        "permission tool names must be bounded and contain no controls".into(),
                    );
                }
                crate::permissions::validate_mcp_selector(&rule.tool)?;
                if rule.tool.starts_with("mcp__")
                    && (!rule.pattern.is_empty() || raw.contains(['(', ')']))
                {
                    return Err("MCP policies use exact tools or mcp__<server>__* without argument patterns".into());
                }
            }
        }
    }
    Ok(())
}

/// The same strict legacy TOML parser used by the merged execution policy.
pub fn load_legacy_permission_rules(home: &Path) -> Result<RuleSet, String> {
    let text = match std::fs::read_to_string(home.join("permissions.toml")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(RuleSet::default()),
        Err(error) => return Err(format!("read legacy permission rules: {error}")),
    };
    validate_rule_file(&text, true)?;
    let parsed = toml_parse(&text)?;
    let mut rules = RuleSet::default();
    merge_legacy(&mut rules, &parsed);
    Ok(rules)
}

fn validate_override_file(text: &str) -> Result<(), String> {
    if text.len() > 64 * 1024 {
        return Err("operator overrides exceed 64 KiB".into());
    }
    let doc: toml::Table =
        toml::from_str(text).map_err(|_| "invalid operator override TOML".to_string())?;
    if doc.keys().any(|key| key != "permissions") {
        return Err("unknown operator override table".into());
    }
    if let Some(value) = doc.get("permissions") {
        let table = value
            .as_table()
            .ok_or_else(|| "override permissions must be a table".to_string())?;
        for (key, value) in table {
            if !matches!(key.as_str(), "allow" | "ask" | "deny") {
                return Err("unknown operator override permission key".into());
            }
            for item in value
                .as_array()
                .ok_or_else(|| "override permissions must be arrays".to_string())?
            {
                let selector = item
                    .as_str()
                    .ok_or_else(|| "override selectors must be strings".to_string())?;
                let rule = crate::permissions::parse_rule(
                    selector,
                    crate::permissions::RuleEffectSerde::Ask,
                )
                .ok_or_else(|| "malformed operator selector".to_string())?;
                if rule.tool != selector
                    || !rule.pattern.is_empty()
                    || selector.contains(['(', ')'])
                    || selector.len() > 256
                    || selector
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
                    || (!selector.starts_with("mcp__") && selector.contains('*'))
                {
                    return Err("operator overrides require exact selectors".into());
                }
                crate::permissions::validate_mcp_selector(selector)?;
            }
        }
    }
    Ok(())
}

/// Replace only a matching operator override; reset reveals independent layers.
/// Publication follows a private, synced temporary file and an atomic rename.
pub fn write_operator_override(
    home: &Path,
    selector: &str,
    effect: Option<crate::permissions::RuleEffectSerde>,
) -> Result<(), String> {
    use std::io::Write;
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let rule = crate::permissions::parse_rule(selector, crate::permissions::RuleEffectSerde::Ask)
        .ok_or_else(|| "a permission selector is required".to_string())?;
    if rule.tool != selector
        || !rule.pattern.is_empty()
        || selector.len() > 256
        || selector
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || (!selector.starts_with("mcp__") && selector.contains('*'))
    {
        return Err("override requires an exact tool or mcp__<server>__* selector".into());
    }
    crate::permissions::validate_mcp_selector(selector)?;
    // The lock is separate from the replaceable file; OS ownership ends on
    // close/crash and concurrent writers cannot silently drop other selectors.
    let lock_path = home.join("permission-overrides.lock");
    if std::fs::symlink_metadata(&lock_path).is_ok_and(|meta| !meta.file_type().is_file()) {
        return Err("operator override lock must be a regular file".into());
    }
    let mut lock_options = std::fs::OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options
        .open(&lock_path)
        .map_err(|error| format!("open operator override lock: {error}"))?;
    lock.try_lock()
        .map_err(|error| format!("operator override writer unavailable: {error}"))?;
    let path = home.join("permission-overrides.toml");
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| !meta.file_type().is_file()) {
        return Err("operator override path must be a regular file".into());
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("read operator overrides: {error}")),
    };
    validate_rule_file(&text, false)?;
    validate_override_file(&text)?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|_| "invalid operator override TOML".to_string())?;
    if doc.get("permissions").is_none() {
        doc["permissions"] = Item::Table(Table::new());
    }
    let perms = doc["permissions"]
        .as_table_mut()
        .ok_or_else(|| "permissions must be a table".to_string())?;
    for (name, selected) in [
        ("allow", crate::permissions::RuleEffectSerde::Allow),
        ("ask", crate::permissions::RuleEffectSerde::Ask),
        ("deny", crate::permissions::RuleEffectSerde::Deny),
    ] {
        let mut entries = Array::new();
        if let Some(existing) = perms.get(name) {
            let array = existing
                .as_array()
                .ok_or_else(|| format!("{name} must be an array"))?;
            for entry in array
                .iter()
                .filter(|entry| entry.as_str() != Some(selector))
            {
                entries.push(entry.clone());
            }
        }
        if effect == Some(selected) {
            entries.push(selector);
        }
        perms[name] = value(entries);
    }
    validate_override_file(&doc.to_string())?;
    let tmp = home.join(format!(".permission-overrides-{}.tmp", ulid::Ulid::new()));
    let backup = tmp.with_extension("previous");
    let save = (|| {
        let directory = std::fs::File::open(home)
            .map_err(|error| format!("open override directory: {error}"))?;
        directory
            .sync_all()
            .map_err(|error| format!("sync override directory: {error}"))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| format!("create operator overrides: {error}"))?;
        file.write_all(doc.to_string().as_bytes())
            .map_err(|error| format!("save operator overrides: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync operator overrides: {error}"))?;
        let previous = path.exists();
        if previous {
            std::fs::hard_link(&path, &backup)
                .map_err(|error| format!("preserve prior overrides: {error}"))?;
        }
        std::fs::rename(&tmp, &path)
            .map_err(|error| format!("publish operator overrides: {error}"))?;
        if let Err(error) = directory.sync_all() {
            let rollback = if previous {
                std::fs::rename(&backup, &path)
            } else {
                std::fs::remove_file(&path)
            };
            rollback.map_err(|rollback| format!("override publication uncertain: sync failed ({error}); rollback failed ({rollback})"))?;
            let _ = directory.sync_all();
            return Err(format!(
                "sync override directory: {error}; prior policy restored"
            ));
        }
        Ok(())
    })();
    if save.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    if save.is_ok() || std::fs::read_to_string(&path).is_ok_and(|current| current == text) {
        let _ = std::fs::remove_file(&backup);
    }
    save
}

/// Remember `rule` as an allow rule in the project's local settings
/// (`.orbit/settings.local.toml`), keeping whatever else the file holds,
/// comments included. A rule already there is left alone. Returns the
/// file written.
///
/// The caller decides whether the folder may be written to at all
/// (it must be trusted: see [`load_rules_in`]); this only edits the file.
/// A `.orbit/.gitignore` naming the file is created when there is none,
/// so a grant meant for one machine is not committed by accident.
pub fn add_local_allow_rule(project: &Path, rule: &str) -> Result<PathBuf, String> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let dir = project.join(".orbit");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join("settings.local.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e} (left untouched)", path.display()))?;
    if doc.get("permissions").is_none() {
        doc["permissions"] = Item::Table(Table::new());
    }
    let perms = doc["permissions"]
        .as_table_mut()
        .ok_or_else(|| format!("{}: `permissions` is not a table", path.display()))?;
    if perms.get("allow").is_none() {
        perms["allow"] = value(Array::new());
    }
    let allow = perms["allow"]
        .as_array_mut()
        .ok_or_else(|| format!("{}: `permissions.allow` is not a list", path.display()))?;
    if allow.iter().any(|v| v.as_str() == Some(rule)) {
        return Ok(path);
    }
    allow.push(rule);
    allow.set_trailing_comma(true);
    // Write whole or not at all: a half-written settings file would drop
    // the person's deny rules the next time it is read.
    let tmp = dir.join(".settings.local.toml.tmp");
    std::fs::write(&tmp, doc.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ignore = dir.join(".gitignore");
    if !ignore.exists() {
        let _ = std::fs::write(&ignore, "settings.local.toml\n");
    }
    Ok(path)
}

/// Where a settings file sits, which decides what it may grant.
enum Scope {
    /// `$ORBIT_HOME/settings.toml`: the person's own.
    User,
    /// The project's files: only as trusted as the folder.
    Project,
    /// The old whole-tool `permissions.toml`.
    Legacy,
}

/// Print a warning about a settings file once per process: the rules are
/// loaded on every tool call, and a warning per call would bury the
/// screen.
fn warn_once(path: &Path, what: &str) {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let key = format!("{}:{what}", path.display());
    let seen = SEEN.get_or_init(Default::default);
    if seen.lock().map(|mut s| s.insert(key)).unwrap_or(true) {
        eprintln!("warning: {}: {what}", path.display());
    }
}

/// Parse a settings file with the real TOML parser (S1): the old
/// hand-written subset dropped multi-line arrays (`deny = [\n  "…",\n]`
/// parsed as empty) and split items containing commas, silently
/// deleting the user's rules. A file that does not parse is an error
/// the caller surfaces — never a silent empty ruleset.
fn toml_parse(text: &str) -> Result<serde_json::Value, String> {
    let parsed: toml::Table =
        toml::from_str(text).map_err(|e| format!("settings parse error: {e}"))?;
    Ok(flatten_toml(&parsed, ""))
}

/// Flatten nested TOML tables into dotted-key JSON (the shape
/// merge_scope/merge_legacy expect: "permissions.deny" → array).
fn flatten_toml(table: &toml::Table, prefix: &str) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in table {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::String(s) => {
                out.insert(key, serde_json::Value::String(s.clone()));
            }
            toml::Value::Integer(i) => {
                out.insert(key, serde_json::Value::Number((*i).into()));
            }
            toml::Value::Float(f) => {
                if let Some(n) = serde_json::Number::from_f64(*f) {
                    out.insert(key, serde_json::Value::Number(n));
                }
            }
            toml::Value::Boolean(b) => {
                out.insert(key, serde_json::Value::Bool(*b));
            }
            toml::Value::Array(a) => {
                out.insert(
                    key,
                    serde_json::Value::Array(
                        a.iter()
                            .filter_map(|x| {
                                x.as_str().map(|s| serde_json::Value::String(s.to_string()))
                            })
                            .collect(),
                    ),
                );
            }
            // Nested tables merge their flattened keys into THIS map
            // (dotted, flat) — not into a nested object.
            toml::Value::Table(t) => {
                if let serde_json::Value::Object(inner) = flatten_toml(t, &key) {
                    out.extend(inner);
                }
            }
            _ => {}
        }
    }
    serde_json::Value::Object(out)
}

/// Merge one scope's `[permissions]` table. `allow_ok` is whether this
/// scope may add allow rules; returns how many it skipped.
fn merge_scope(rules: &mut RuleSet, v: &serde_json::Value, allow_ok: bool) -> usize {
    let mut skipped = 0;
    for (effect, table) in [
        (crate::permissions::RuleEffectSerde::Allow, "allow"),
        (crate::permissions::RuleEffectSerde::Ask, "ask"),
        (crate::permissions::RuleEffectSerde::Deny, "deny"),
    ] {
        let key = format!("permissions.{table}");
        if let Some(arr) = v.get(&key).and_then(|x| x.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str()
                    && let Some(r) = crate::permissions::parse_rule(s, effect)
                {
                    if effect == crate::permissions::RuleEffectSerde::Allow && !allow_ok {
                        skipped += 1;
                    } else {
                        rules.rules.push(r);
                    }
                }
            }
        }
    }
    skipped
}

fn merge_legacy(rules: &mut RuleSet, v: &serde_json::Value) {
    // permissions.toml: allow = ["calculator"], deny = [...]
    for (effect, key) in [
        (crate::permissions::RuleEffectSerde::Allow, "allow.tools"),
        (crate::permissions::RuleEffectSerde::Deny, "deny.tools"),
    ] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str()
                    && let Some(r) = crate::permissions::parse_rule(s, effect)
                {
                    rules.rules.push(r);
                }
            }
        }
    }
}

#[cfg(test)]
mod s1_tests {
    use super::*;

    #[test]
    fn multiline_array_parses() {
        let v = toml_parse("[permissions]\ndeny = [\n  \"Bash(echo *)\",\n]\n").unwrap();
        eprintln!("FLAT: {v}");
        assert!(
            v.get("permissions.deny").is_some(),
            "dotted key present: {v}"
        );
    }
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    use crate::permissions::{FolderTrust, RuleEffect};

    fn dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("orbit-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let project = base.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(project.join(".orbit")).unwrap();
        (home, project)
    }

    const FILE: &str = "[permissions]\nallow = [\"Bash(*)\"]\nask = [\"Bash(git push *)\"]\ndeny = [\"Bash(rm *)\"]\n";

    /// A cloned repository's own settings may make ORBIT stricter, and
    /// may not make it looser.
    #[test]
    fn an_untrusted_folder_adds_no_allow_rules() {
        let (home, project) = dirs("untrusted");
        for f in ["settings.toml", "settings.local.toml"] {
            std::fs::write(project.join(".orbit").join(f), FILE).unwrap();
        }
        let rules = load_rules_in(&home, &project);
        assert_eq!(rules.evaluate("Bash", "anything"), None, "no allow got in");
        assert_eq!(rules.evaluate("Bash", "rm -rf x"), Some(RuleEffect::Deny));
        assert_eq!(
            rules.evaluate("Bash", "git push origin"),
            Some(RuleEffect::Ask)
        );
        let _ = std::fs::remove_dir_all(home.parent().unwrap());
    }

    #[test]
    fn a_trusted_folder_applies_its_allow_rules() {
        let (home, project) = dirs("trusted");
        std::fs::write(project.join(".orbit/settings.local.toml"), FILE).unwrap();
        FolderTrust::new(home.clone()).trust(&project).unwrap();
        let rules = load_rules_in(&home, &project);
        assert_eq!(
            rules.evaluate("Bash", "cargo build"),
            Some(RuleEffect::Allow)
        );
        // Deny still beats allow.
        assert_eq!(rules.evaluate("Bash", "rm -rf x"), Some(RuleEffect::Deny));
        // Trust is per folder.
        let other = project.parent().unwrap().join("other");
        std::fs::create_dir_all(other.join(".orbit")).unwrap();
        std::fs::write(other.join(".orbit/settings.toml"), FILE).unwrap();
        assert_eq!(
            load_rules_in(&home, &other).evaluate("Bash", "cargo build"),
            None
        );
        let _ = std::fs::remove_dir_all(home.parent().unwrap());
    }

    /// The person's own settings are theirs: no trust question.
    #[test]
    fn the_user_scope_needs_no_trust() {
        let (home, project) = dirs("user");
        std::fs::write(home.join("settings.toml"), FILE).unwrap();
        let rules = load_rules_in(&home, &project);
        assert_eq!(
            rules.evaluate("Bash", "cargo build"),
            Some(RuleEffect::Allow)
        );
        let _ = std::fs::remove_dir_all(home.parent().unwrap());
    }
}

#[cfg(test)]
mod local_rule_tests {
    use super::*;

    fn project(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("orbit-localrule-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_rule_lands_in_a_new_local_file_and_is_read_back() {
        let p = project("new");
        let path = add_local_allow_rule(&p, "Bash(cargo test *)").unwrap();
        assert_eq!(path, p.join(".orbit/settings.local.toml"));
        let rules = {
            // Trusted, so the allow rule is read.
            let home = p.join("home");
            crate::permissions::FolderTrust::new(home.clone())
                .trust(&p)
                .unwrap();
            load_rules_in(&home, &p)
        };
        assert_eq!(
            rules.evaluate("Bash", "cargo test --release"),
            Some(crate::permissions::RuleEffect::Allow)
        );
        // The file is kept out of version control by default.
        assert_eq!(
            std::fs::read_to_string(p.join(".orbit/.gitignore")).unwrap(),
            "settings.local.toml\n"
        );
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn what_was_there_stays_there() {
        let p = project("keep");
        std::fs::create_dir_all(p.join(".orbit")).unwrap();
        std::fs::write(
            p.join(".orbit/settings.local.toml"),
            "# mine\n[permissions]\ndeny = [\"Bash(rm *)\"]\nallow = [\"Read\"]\n\n[other]\nkey = 1\n",
        )
        .unwrap();
        add_local_allow_rule(&p, "Bash(git status *)").unwrap();
        // Twice is once.
        add_local_allow_rule(&p, "Bash(git status *)").unwrap();
        let text = std::fs::read_to_string(p.join(".orbit/settings.local.toml")).unwrap();
        assert!(text.contains("# mine"), "{text}");
        assert!(text.contains("deny = [\"Bash(rm *)\"]"), "{text}");
        assert!(text.contains("key = 1"), "{text}");
        assert_eq!(text.matches("Bash(git status *)").count(), 1, "{text}");
        assert!(text.contains("\"Read\""), "{text}");
        let _ = std::fs::remove_dir_all(&p);
    }

    /// A file that does not parse is left exactly as it was: writing over
    /// it would drop the rules in it.
    #[test]
    fn a_broken_file_is_refused_not_overwritten() {
        let p = project("broken");
        std::fs::create_dir_all(p.join(".orbit")).unwrap();
        let broken = "[permissions\ndeny = [";
        std::fs::write(p.join(".orbit/settings.local.toml"), broken).unwrap();
        assert!(add_local_allow_rule(&p, "Bash(ls)").is_err());
        assert_eq!(
            std::fs::read_to_string(p.join(".orbit/settings.local.toml")).unwrap(),
            broken
        );
        let _ = std::fs::remove_dir_all(&p);
    }
}
