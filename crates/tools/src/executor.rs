//! The Wave 1 executor — the shared tool-execution path every
//! front-end plugs into the engine (roadmap phase 3).
//!
//! Owns: the tool registry, the permission evaluation (mode + rules +
//! deny-read), the approval channel handoff, the secret scanner on
//! every result, and the ledger's intent/verdict/result records.

use crate::permissions::{PermissionMode, RuleSet, Verdict};
use crate::{registry, ToolContext, ToolResult};
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
        let (verdict, _sandbox_up) = if self.grants.is_granted(&grant_key) {
            (Verdict::Allow, true)
        } else {
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
    let trusted = crate::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    let mut rules = RuleSet::default();
    // A file that exists but does not parse is WARNED, never silently
    // skipped (S1: silent skip deleted the user's deny rules).
    for (path, scope) in [
        (home.join("settings.toml"), Scope::User),
        (project.join(".orbit/settings.toml"), Scope::Project),
        (project.join(".orbit/settings.local.toml"), Scope::Project),
        (home.join("permissions.toml"), Scope::Legacy),
    ] {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match toml_parse(&text) {
            Ok(v) => match scope {
                Scope::Legacy => merge_legacy(&mut rules, &v),
                Scope::User => {
                    merge_scope(&mut rules, &v, true);
                }
                Scope::Project => {
                    let skipped = merge_scope(&mut rules, &v, trusted);
                    if skipped > 0 {
                        warn_once(&path, &format!(
                            "{skipped} allow rule(s) NOT applied: this folder is not trusted (orbit folder trust)"
                        ));
                    }
                }
            },
            Err(e) => {
                warn_once(
                    &path,
                    &format!("{e} (permission rules in it are NOT applied)"),
                );
            }
        }
    }
    rules
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
                if let Some(s) = item.as_str() {
                    if let Some(r) = crate::permissions::parse_rule(s, effect) {
                        if effect == crate::permissions::RuleEffectSerde::Allow && !allow_ok {
                            skipped += 1;
                        } else {
                            rules.rules.push(r);
                        }
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
                if let Some(s) = item.as_str() {
                    if let Some(r) = crate::permissions::parse_rule(s, effect) {
                        rules.rules.push(r);
                    }
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
