//! Persistent permission rules (Claude Code settings parity).
//!
//! Claude Code persists allow/deny rules in settings files so approvals
//! survive restarts. ORBIT's equivalent lives in
//! `$ORBIT_HOME/permissions.toml`:
//!
//! ```toml
//! [allow]
//! tools = ["calculator", "list_models"]
//!
//! [deny]
//! tools = []
//! ```
//!
//! Rules are consulted BEFORE the interactive approval prompt: an allow
//! rule auto-allows (same effect as an R-grant, but durable), a deny rule
//! auto-denies (fail-closed, no prompt). Deny always wins over allow.
//! Unknown tools remain deny-by-default regardless of rules.
//!
//! The file is human-editable; `/permissions` shows the effective set and
//! `/permissions allow <tool>` / `/permissions deny <tool>` mutate it.

use std::collections::BTreeSet;
use std::path::Path;

/// The persisted rule set.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionRules {
    /// Tool names always allowed (durable R-grant).
    #[serde(default)]
    pub allow: RuleSet,
    /// Tool names always denied. Deny wins over allow.
    #[serde(default)]
    pub deny: RuleSet,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    #[serde(default)]
    pub tools: BTreeSet<String>,
}

/// The verdict a rule set yields for a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerdict {
    /// An allow rule matched → auto-allow, no prompt.
    Allow,
    /// A deny rule matched → auto-deny, no prompt.
    Deny,
    /// No rule matched → fall through to the interactive prompt.
    Ask,
}

impl PermissionRules {
    /// Load from `$ORBIT_HOME/permissions.toml`. Missing file → empty
    /// rules (everything asks). Malformed file → empty rules + Err so the
    /// caller can warn (never crash chat over a config typo).
    pub fn load(home: &Path) -> Result<Self, String> {
        let parsed = orbit_tools::executor::load_legacy_permission_rules(home)?;
        let mut rules = Self::default();
        for rule in parsed.rules {
            let selector = if rule.pattern.is_empty() {
                rule.tool
            } else {
                format!("{}({})", rule.tool, rule.pattern)
            };
            match rule.effect {
                orbit_tools::permissions::RuleEffectSerde::Allow => {
                    rules.allow.tools.insert(selector);
                }
                orbit_tools::permissions::RuleEffectSerde::Deny => {
                    rules.deny.tools.insert(selector);
                }
                orbit_tools::permissions::RuleEffectSerde::Ask => {}
            }
        }
        Ok(rules)
    }

    /// Persist to `$ORBIT_HOME/permissions.toml`.
    pub fn save(&self, home: &Path) -> Result<(), String> {
        let mut out = String::new();
        out.push_str("# ORBIT persistent permission rules (Claude Code settings parity).\n");
        out.push_str("# allow = durable auto-allow; deny = durable auto-deny (deny wins).\n\n");
        out.push_str("[allow]\ntools = [");
        out.push_str(
            &self
                .allow
                .tools
                .iter()
                .map(|t| format!("\"{t}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]\n\n[deny]\ntools = [");
        out.push_str(
            &self
                .deny
                .tools
                .iter()
                .map(|t| format!("\"{t}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]\n");
        std::fs::write(home.join("permissions.toml"), out)
            .map_err(|e| format!("write permissions.toml: {e}"))
    }

    /// The effective verdict for a tool. Deny wins; unknown tools are the
    /// caller's concern (execute_call denies them before consulting rules).
    pub fn verdict(&self, tool: &str) -> RuleVerdict {
        self.verdict_with_server(tool, None)
    }

    /// MCP selectors use a configuration-resolved server, never a string prefix.
    pub fn verdict_with_server(&self, tool: &str, server: Option<&str>) -> RuleVerdict {
        let matches = |selector: &String| {
            orbit_tools::permissions::parse_rule(
                selector,
                orbit_tools::permissions::RuleEffectSerde::Ask,
            )
            .is_some_and(|rule| {
                rule.pattern.is_empty()
                    && orbit_tools::permissions::rule_tool_matches(&rule, tool, server)
            })
        };
        if self.deny.tools.iter().any(matches) {
            RuleVerdict::Deny
        } else if self.allow.tools.iter().any(matches) {
            RuleVerdict::Allow
        } else {
            RuleVerdict::Ask
        }
    }

    /// Add an allow rule and persist.
    pub fn allow_tool(&mut self, home: &Path, tool: &str) -> Result<(), String> {
        self.deny.tools.remove(tool);
        self.allow.tools.insert(tool.to_string());
        self.save(home)
    }

    /// Add a deny rule and persist.
    pub fn deny_tool(&mut self, home: &Path, tool: &str) -> Result<(), String> {
        self.allow.tools.remove(tool);
        self.deny.tools.insert(tool.to_string());
        self.save(home)
    }

    /// Remove any rule for a tool and persist.
    pub fn reset_tool(&mut self, home: &Path, tool: &str) -> Result<(), String> {
        self.allow.tools.remove(tool);
        self.deny.tools.remove(tool);
        self.save(home)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-perm-test-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_means_ask() {
        let home = tmp_home("missing");
        let rules = PermissionRules::load(&home).unwrap();
        assert_eq!(rules.verdict("calculator"), RuleVerdict::Ask);
    }

    #[test]
    fn allow_and_deny_roundtrip() {
        let home = tmp_home("roundtrip");
        let mut rules = PermissionRules::default();
        rules.allow_tool(&home, "calculator").unwrap();
        rules.deny_tool(&home, "shell").unwrap();
        // Re-load from disk: both rules persisted.
        let loaded = PermissionRules::load(&home).unwrap();
        assert_eq!(loaded.verdict("calculator"), RuleVerdict::Allow);
        assert_eq!(loaded.verdict("shell"), RuleVerdict::Deny);
        assert_eq!(loaded.verdict("other"), RuleVerdict::Ask);
    }

    #[test]
    fn deny_wins_over_allow() {
        let home = tmp_home("denywins");
        let mut rules = PermissionRules::default();
        rules.allow_tool(&home, "calculator").unwrap();
        rules.deny_tool(&home, "calculator").unwrap();
        assert_eq!(rules.verdict("calculator"), RuleVerdict::Deny);
    }

    #[test]
    fn reset_removes_both() {
        let home = tmp_home("reset");
        let mut rules = PermissionRules::default();
        rules.allow_tool(&home, "calculator").unwrap();
        rules.reset_tool(&home, "calculator").unwrap();
        let loaded = PermissionRules::load(&home).unwrap();
        assert_eq!(loaded.verdict("calculator"), RuleVerdict::Ask);
    }

    #[test]
    fn malformed_file_errors_but_not_crash() {
        let home = tmp_home("malformed");
        std::fs::write(home.join("permissions.toml"), "garbage = no list\n").unwrap();
        assert!(PermissionRules::load(&home).is_err());
    }
}
