//! Permission modes, rules and scopes (roadmap §Permissions).
//!
//! Modes: default, acceptEdits, plan, dontAsk, bypass. Rules name a
//! tool and what it may touch: `Bash(cargo test *)`, `Read(~/.ssh/**)`,
//! `Edit(/src/**)`. Deny → ask → allow; the first match wins; the mode
//! applies only when no rule matches. A deny anywhere beats an allow
//! anywhere. Scopes merge: managed, command line, local (gitignored),
//! project (needs folder trust), user.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// The permission modes (Shift+Tab cycles the first three).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    /// Read-only tools + the read-only shell allowlist run freely;
    /// everything else asks.
    #[default]
    Default,
    /// Also Write/Edit/common file commands inside working directories.
    AcceptEdits,
    /// Read-only tools only; edits wait for ExitPlanMode approval.
    Plan,
    /// Only allow-rule-covered calls run; anything else is denied,
    /// never asked (CI and scripts).
    DontAsk,
    /// Everything runs (containers/VMs only; refused as root).
    Bypass,
}

impl PermissionMode {
    pub fn from_config(s: &str) -> Option<Self> {
        match s {
            "default" => Some(PermissionMode::Default),
            "acceptEdits" | "accept-edits" => Some(PermissionMode::AcceptEdits),
            "plan" => Some(PermissionMode::Plan),
            "dontAsk" | "dont-ask" => Some(PermissionMode::DontAsk),
            "bypass" | "bypassPermissions" => Some(PermissionMode::Bypass),
            _ => None,
        }
    }
}

/// A rule's effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    Allow,
    Ask,
    Deny,
}

/// One pattern rule: `Bash(cargo test *)`, `Edit(/src/**)`,
/// `Read(~/.ssh/**)`, `WebFetch(domain:docs.rs)` — or a bare tool name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRule {
    /// Tool name (Read, Write, Edit, Bash, WebFetch, Agent, mcp__*).
    pub tool: String,
    /// Argument pattern. `*` suffix = prefix match; `**` spans dirs;
    /// empty = the whole tool.
    #[serde(default)]
    pub pattern: String,
    pub effect: RuleEffectSerde,
}

/// serde-friendly effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffectSerde {
    Allow,
    Ask,
    Deny,
}

impl From<RuleEffectSerde> for RuleEffect {
    fn from(e: RuleEffectSerde) -> Self {
        match e {
            RuleEffectSerde::Allow => RuleEffect::Allow,
            RuleEffectSerde::Ask => RuleEffect::Ask,
            RuleEffectSerde::Deny => RuleEffect::Deny,
        }
    }
}

/// The merged rule set across scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(default)]
    pub rules: Vec<PermissionRule>,
}

impl RuleSet {
    /// Evaluate deny → ask → allow across every scope's rules; first
    /// match wins; a deny anywhere beats an allow anywhere.
    pub fn evaluate(&self, tool: &str, argument: &str) -> Option<RuleEffect> {
        // Deny anywhere beats everything.
        if self.rules.iter().any(|r| {
            r.tool == tool && r.effect == RuleEffectSerde::Deny && rule_matches(r, argument)
        }) {
            return Some(RuleEffect::Deny);
        }
        // Then ask.
        if let Some(r) = self.rules.iter().find(|r| {
            r.tool == tool && r.effect == RuleEffectSerde::Ask && rule_matches(r, argument)
        }) {
            let _ = r;
            return Some(RuleEffect::Ask);
        }
        // Then allow.
        if self.rules.iter().any(|r| {
            r.tool == tool && r.effect == RuleEffectSerde::Allow && rule_matches(r, argument)
        }) {
            return Some(RuleEffect::Allow);
        }
        None
    }

    /// Merge two scopes (later scope's rules append; deny still wins by
    /// evaluation order).
    pub fn merged_with(&self, other: &RuleSet) -> RuleSet {
        let mut rules = self.rules.clone();
        rules.extend(other.rules.clone());
        RuleSet { rules }
    }
}

/// Does a rule's pattern match the call's argument?
/// `cargo test *` matches "cargo test --release"; `/src/**` matches
/// paths under /src; empty pattern matches the whole tool.
pub fn rule_matches(rule: &PermissionRule, argument: &str) -> bool {
    if rule.pattern.is_empty() {
        return true;
    }
    let p = &rule.pattern;
    if let Some(prefix) = p.strip_suffix(" *") {
        argument.starts_with(prefix)
    } else if let Some(prefix) = p.strip_suffix("**") {
        let prefix = prefix.trim_end_matches('/');
        argument.starts_with(prefix)
    } else if p.contains('*') {
        crate::glob_match(p, argument)
    } else {
        argument == p
    }
}

/// A settings scope's permission table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopePermissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Parse a rule string like `Bash(cargo test *)` or `Read` into a rule.
pub fn parse_rule(s: &str, effect: RuleEffectSerde) -> Option<PermissionRule> {
    let s = s.trim();
    if let Some(open) = s.find('(') {
        let close = s.rfind(')')?;
        let tool = s[..open].trim().to_string();
        let pattern = s[open + 1..close].trim().to_string();
        if tool.is_empty() {
            return None;
        }
        Some(PermissionRule {
            tool,
            pattern,
            effect,
        })
    } else {
        if s.is_empty() {
            return None;
        }
        Some(PermissionRule {
            tool: s.to_string(),
            pattern: String::new(),
            effect,
        })
    }
}

/// Folder trust: project-scope rules apply only after the operator
/// trusted the folder once. The trust marker lives under ORBIT_HOME.
pub struct FolderTrust {
    home: std::path::PathBuf,
}

impl FolderTrust {
    pub fn new(home: std::path::PathBuf) -> Self {
        FolderTrust { home }
    }

    fn marker_path(&self, dir: &Path) -> std::path::PathBuf {
        // Hash the absolute path to a stable filename.
        use sha2::Digest;
        let digest = hex::encode(sha2::Sha256::digest(dir.to_string_lossy().as_bytes()));
        self.home.join("trust").join("folders").join(digest)
    }

    /// Is this folder trusted (marker file present)?
    pub fn is_trusted(&self, dir: &Path) -> bool {
        self.marker_path(dir).exists()
    }

    /// Trust this folder (idempotent).
    pub fn trust(&self, dir: &Path) -> std::io::Result<()> {
        let marker = self.marker_path(dir);
        if let Some(parent) = marker.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &marker,
            serde_json::json!({ "path": dir.to_string_lossy(), "trusted_at": chrono_now() })
                .to_string(),
        )
    }

    /// Withdraw trust.
    pub fn untrust(&self, dir: &Path) -> std::io::Result<()> {
        let _ = std::fs::remove_file(self.marker_path(dir));
        Ok(())
    }
}

fn chrono_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// The full permission evaluation for one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Runs without asking.
    Allow,
    /// Must ask the operator.
    Ask,
    /// Denied — with a reason for the transcript.
    Deny(String),
}

/// Evaluate one call against mode + rules + tool classification.
/// `is_read_only` comes from the tool registry; `argument` is the
/// permission key's pattern (path or command).
pub fn evaluate(
    mode: PermissionMode,
    rules: &RuleSet,
    tool: &str,
    argument: &str,
    is_read_only_tool: bool,
    is_readonly_command: bool,
) -> Verdict {
    // Bypass: everything runs (refused at startup as root — the CLI
    // checks that separately).
    if mode == PermissionMode::Bypass {
        return Verdict::Allow;
    }

    // Explicit rules first — they override the mode.
    if let Some(effect) = rules.evaluate(tool, argument) {
        return match effect {
            RuleEffect::Allow => Verdict::Allow,
            RuleEffect::Ask => {
                if mode == PermissionMode::DontAsk {
                    Verdict::Deny("no allow rule covers this call (dontAsk)".into())
                } else {
                    Verdict::Ask
                }
            }
            RuleEffect::Deny => Verdict::Deny("denied by rule".into()),
        };
    }

    // No rule: the mode decides.
    match mode {
        PermissionMode::Default | PermissionMode::AcceptEdits => {
            let edit_tools = matches!(tool, "Write" | "Edit" | "NotebookEdit");
            let freely = is_read_only_tool
                || (tool == "Bash" && is_readonly_command)
                || (mode == PermissionMode::AcceptEdits && edit_tools);
            if freely {
                Verdict::Allow
            } else {
                Verdict::Ask
            }
        }
        PermissionMode::Plan => {
            if is_read_only_tool {
                Verdict::Allow
            } else {
                Verdict::Deny("plan mode: read-only until the plan is approved".into())
            }
        }
        PermissionMode::DontAsk => Verdict::Deny("no allow rule covers this call (dontAsk)".into()),
        PermissionMode::Bypass => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(pairs: &[(&str, RuleEffectSerde)]) -> RuleSet {
        RuleSet {
            rules: pairs
                .iter()
                .filter_map(|(s, e)| parse_rule(s, *e))
                .collect(),
        }
    }

    #[test]
    fn deny_beats_allow_across_scopes() {
        let rs = rules(&[
            ("Bash(git push *)", RuleEffectSerde::Allow),
            ("Bash(git push --force *)", RuleEffectSerde::Deny),
        ]);
        assert_eq!(
            rs.evaluate("Bash", "git push origin main"),
            Some(RuleEffect::Allow)
        );
        assert_eq!(
            rs.evaluate("Bash", "git push --force origin main"),
            Some(RuleEffect::Deny)
        );
    }

    #[test]
    fn mode_fills_gaps() {
        // Read-only tools run freely in default mode.
        assert_eq!(
            evaluate(
                PermissionMode::Default,
                &RuleSet::default(),
                "Read",
                "/src/main.rs",
                true,
                false
            ),
            Verdict::Allow
        );
        // Write asks in default mode.
        assert_eq!(
            evaluate(
                PermissionMode::Default,
                &RuleSet::default(),
                "Write",
                "/src/main.rs",
                false,
                false
            ),
            Verdict::Ask
        );
        // Write runs in acceptEdits.
        assert_eq!(
            evaluate(
                PermissionMode::AcceptEdits,
                &RuleSet::default(),
                "Write",
                "/src/main.rs",
                false,
                false
            ),
            Verdict::Allow
        );
        // Bash readonly allowlist runs in default mode.
        assert_eq!(
            evaluate(
                PermissionMode::Default,
                &RuleSet::default(),
                "Bash",
                "git status",
                false,
                true
            ),
            Verdict::Allow
        );
        // Plan mode denies writes, allows reads.
        assert!(matches!(
            evaluate(
                PermissionMode::Plan,
                &RuleSet::default(),
                "Edit",
                "/src/a.rs",
                false,
                false
            ),
            Verdict::Deny(_)
        ));
        // dontAsk denies uncovered calls instead of asking.
        assert!(matches!(
            evaluate(
                PermissionMode::DontAsk,
                &RuleSet::default(),
                "Bash",
                "cargo build",
                false,
                false
            ),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn pattern_shapes() {
        let r = parse_rule("Bash(cargo test *)", RuleEffectSerde::Allow).unwrap();
        assert!(rule_matches(&r, "cargo test --release"));
        assert!(!rule_matches(&r, "cargo build"));
        let r = parse_rule("Edit(/src/**)", RuleEffectSerde::Allow).unwrap();
        assert!(rule_matches(&r, "/src/a/b.rs"));
        assert!(!rule_matches(&r, "/tests/a.rs"));
        let r = parse_rule("Read", RuleEffectSerde::Deny).unwrap();
        assert!(rule_matches(&r, "anything"));
    }
}
