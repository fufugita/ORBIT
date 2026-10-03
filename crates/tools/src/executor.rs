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
                        return ToolResult::err("denied by you").payload;
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

/// Load the merged rule set from the settings scopes (user + project
/// when trusted + local). The old permissions.toml whole-tool rules
/// migrate as bare-tool rules.
pub fn load_rules(home: &Path) -> RuleSet {
    let mut rules = RuleSet::default();
    // User scope: $ORBIT_HOME/settings.toml [permissions] table.
    if let Ok(text) = std::fs::read_to_string(home.join("settings.toml")) {
        if let Ok(v) = toml_parse(&text) {
            merge_scope(&mut rules, &v);
        }
    }
    // Project scope: .orbit/settings.toml (folder trust checked by the
    // caller before loading).
    if let Ok(text) = std::fs::read_to_string(".orbit/settings.toml") {
        if let Ok(v) = toml_parse(&text) {
            merge_scope(&mut rules, &v);
        }
    }
    // Local scope: .orbit/settings.local.toml (gitignored).
    if let Ok(text) = std::fs::read_to_string(".orbit/settings.local.toml") {
        if let Ok(v) = toml_parse(&text) {
            merge_scope(&mut rules, &v);
        }
    }
    // Migration: the old permissions.toml whole-tool rules.
    if let Ok(text) = std::fs::read_to_string(home.join("permissions.toml")) {
        if let Ok(v) = toml_parse(&text) {
            merge_legacy(&mut rules, &v);
        }
    }
    rules
}

/// Minimal TOML subset parser for the permissions tables (arrays of
/// strings under allow/ask/deny). Avoids a toml dependency in this
/// crate; the CLI's config layer can replace it later.
fn toml_parse(text: &str) -> Result<serde_json::Value, String> {
    let mut out = serde_json::Map::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = Some(line[1..line.len() - 1].to_string());
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let value = line[eq + 1..].trim();
            let scope_key = current.clone().unwrap_or_default();
            let full = if scope_key.is_empty() {
                key
            } else {
                format!("{scope_key}.{key}")
            };
            // Parse: string, array of strings, bare word.
            let parsed = if value.starts_with('[') {
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                let items: Vec<String> = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                serde_json::Value::Array(items.into_iter().map(serde_json::Value::String).collect())
            } else {
                serde_json::Value::String(value.trim_matches('"').trim_matches('\'').to_string())
            };
            out.insert(full, parsed);
        }
    }
    Ok(serde_json::Value::Object(out))
}

fn merge_scope(rules: &mut RuleSet, v: &serde_json::Value) {
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
                        rules.rules.push(r);
                    }
                }
            }
        }
    }
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
