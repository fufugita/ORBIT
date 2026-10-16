//! Automation and proof (roadmap phase 6).
//!
//! - Spoken rules: the authority extractor turns operator speech into
//!   real permission rules ("run the tests but never push" →
//!   Bash(cargo test *) allowed, Bash(git push *) denied).
//! - Test claims: report the current turn's captured Bash completion,
//!   without executing a second command to produce a verdict.
//! - Cost guard: --max-cost stops a session/job at the budget.

use crate::TurnReport;
use std::path::Path;

// ── Spoken rules ───────────────────────────────────────────────────────────

/// A spoken rule extracted from operator speech.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpokenRule {
    /// The permission rule string: `Bash(cargo test *)`.
    pub rule: String,
    pub effect: SpokenEffect,
    /// The phrase that produced it (for the AuthorityGrant record).
    pub source_phrase: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpokenEffect {
    Allow,
    Deny,
}

/// Extract permission rules from natural operator speech. Deliberately
/// conservative: only clear imperative shapes produce rules; anything
/// ambiguous produces nothing (the operator is asked, never guessed).
pub fn extract_spoken_rules(speech: &str) -> Vec<SpokenRule> {
    let mut out = Vec::new();
    for line in speech.lines() {
        let l = line.trim().to_lowercase();
        // "run the tests but never push" / "you may run cargo test but
        // never git push" / "don't push".
        if l.contains("never") || l.contains("don't") || l.contains("do not") {
            // Deny shapes: never <verb-phrase>.
            if let Some(phrase) = deny_phrase(&l)
                && let Some(rule) = phrase_to_rule(&phrase, SpokenEffect::Deny)
            {
                out.push(SpokenRule {
                    rule,
                    effect: SpokenEffect::Deny,
                    source_phrase: line.trim().to_string(),
                });
            }
        }
        // Allow shapes: "run the tests", "you may run cargo test",
        // "feel free to run X". An allow for the same TARGET a deny on
        // this line already covers is dropped (deny wins); different
        // targets on one line both extract ("tests but never push").
        if let Some(phrase) = allow_phrase(&l)
            && let Some(rule) = phrase_to_rule(&phrase, SpokenEffect::Allow)
        {
            let denied_same_target = out.iter().any(|r| {
                r.effect == SpokenEffect::Deny && r.source_phrase == line.trim() && r.rule == rule
            });
            if !denied_same_target {
                out.push(SpokenRule {
                    rule,
                    effect: SpokenEffect::Allow,
                    source_phrase: line.trim().to_string(),
                });
            }
        }
    }
    out
}

fn deny_phrase(l: &str) -> Option<String> {
    for marker in ["never ", "don't ", "do not "] {
        if let Some(pos) = l.find(marker) {
            return Some(l[pos + marker.len()..].trim().to_string());
        }
    }
    None
}

fn allow_phrase(l: &str) -> Option<String> {
    // "run the tests" / "run cargo test" — but NOT when the line is a
    // denial ("never run" would otherwise allow!).
    if l.contains("never") || l.contains("don't") || l.contains("do not") {
        // The line is a denial; only extract an allow from the clause
        // BEFORE the denial marker ("run the tests but never push").
        // " but " is the conjunction between allow and deny clauses —
        // it cuts first; the denial markers cut their own clause.
        let cut = l
            .find(" but ")
            .or_else(|| l.find(" never "))
            .or_else(|| l.find(" don't "))
            .or_else(|| l.find(" do not "))?;
        let head = &l[..cut];
        return command_after_run(head);
    }
    command_after_run(l)
}

fn command_after_run(text: &str) -> Option<String> {
    let t = text
        .trim_start_matches("you may ")
        .trim_start_matches("feel free to ")
        .trim();
    let run = t.find("run ")?;
    let cmd = t[run + 4..].trim();
    // Strip trailing filler.
    let cmd = cmd.trim_end_matches('.');
    if cmd.is_empty() {
        return None;
    }
    Some(cmd.to_string())
}

/// Map a spoken phrase to a permission rule. Conservative: only shapes
/// we can map confidently.
fn phrase_to_rule(phrase: &str, effect: SpokenEffect) -> Option<String> {
    let p = phrase.trim();
    // "push" / "git push" → Bash(git push *)
    if p == "push" || p.starts_with("git push") || p == "force push" {
        return Some(match effect {
            SpokenEffect::Allow => "Bash(git push *)".into(),
            SpokenEffect::Deny => "Bash(git push *)".into(),
        });
    }
    // "the tests" / "tests" / "cargo test" → Bash(cargo test *)
    if p == "the tests" || p == "tests" || p.contains("cargo test") {
        return Some("Bash(cargo test *)".into());
    }
    // A literal command the operator named: "run <cmd>" → Bash(<cmd> *)
    if p.split_whitespace().count() >= 1 && !p.contains(' ') {
        return Some(format!("Bash({p} *)"));
    }
    None
}

// ── Captured test-command evidence ────────────────────────────────────────

/// The structured attestation scan (E10): the last test-like Bash
/// command of a turn, its RECORDED exit status (from the paired tool
/// result — not a re-run, not the model's word), and whether the final
/// text claims a pass. A claim after a failing command is an
/// unverified claim and must be shown as one.
#[derive(Debug, Clone)]
pub struct AttestationScan {
    pub command: String,
    pub exit_code: i64,
    pub claimed_pass: bool,
}

/// Scan a turn's transcript for the attestation facts (E10). Returns
/// None when the current user turn has no recognized test-like Bash
/// call. A recognized call with missing, ambiguous or incomplete evidence
/// returns `exit_code: -1`, retaining the warning contract of existing
/// frontends. A zero means that exact command's captured completion,
/// rather than proof that arbitrary shell text ran a real test suite.
pub fn scan_attestation(
    transcript: &[orbit_adapter::types::ChatMessage],
) -> Option<AttestationScan> {
    use orbit_adapter::types::ChatRole;

    let start = transcript.iter().rposition(|m| m.role == ChatRole::User)? + 1;
    let current = &transcript[start..];
    let final_text = current
        .last()
        .filter(|m| {
            m.role == ChatRole::Assistant && m.tool_calls.as_ref().is_none_or(Vec::is_empty)
        })
        .map(|m| m.content.to_lowercase())
        .unwrap_or_default();

    let (call_index, call, command) = current
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, m)| m.role == ChatRole::Assistant)
        .find_map(|(index, message)| {
            message.tool_calls.as_ref()?.iter().rev().find_map(|call| {
                if call.name != "Bash" {
                    return None;
                }
                let arguments: serde_json::Value = serde_json::from_str(&call.arguments).ok()?;
                let command = arguments.get("command")?.as_str()?;
                test_like_command(command).then(|| (index, call, command.to_owned()))
            })
        })?;

    // Count all occurrences, including other tools and results preceding the
    // call. Choosing only the newest matching ID would hide ambiguity.
    let call_count = current
        .iter()
        .filter_map(|message| message.tool_calls.as_ref())
        .flatten()
        .filter(|candidate| candidate.id == call.id)
        .count();
    let mut results = current.iter().enumerate().filter(|(_, message)| {
        message.role == ChatRole::Tool && message.tool_call_id.as_deref() == Some(call.id.as_str())
    });
    let result = results.next();
    let unique_result = results.next().is_none();
    let exit_code = if !call.id.trim().is_empty() && call_count == 1 && unique_result {
        result
            .filter(|(index, _)| *index > call_index)
            .and_then(|(_, message)| message.tool_result.as_deref())
            .and_then(recorded_exit_code)
            .unwrap_or(-1)
    } else {
        -1
    };
    let claimed_pass = final_text.contains("test") && final_text.contains("pass");
    Some(AttestationScan {
        command,
        exit_code,
        claimed_pass,
    })
}

fn test_like_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    match words.next() {
        Some("cargo" | "npm" | "go") => words.next() == Some("test"),
        Some("pytest") => true,
        Some("python3") => words
            .next()
            .is_some_and(|script| script.starts_with("test")),
        _ => false,
    }
}

fn recorded_exit_code(raw: &str) -> Option<i64> {
    let payload: serde_json::Value = serde_json::from_str(raw).ok()?;
    let payload = payload.as_object()?;
    let ok = payload.get("ok")?.as_bool()?;
    let exit_code = payload.get("exit_code")?.as_i64()?;
    // These fields describe unsupported or unfinished execution states. A
    // malformed state flag is not permission to treat a command as complete.
    for flag in [
        "backgrounded",
        "pending",
        "cancelled",
        "canceled",
        "interrupted",
        "timed_out",
        "denied",
        "is_error",
    ] {
        if payload
            .get(flag)
            .is_some_and(|value| value != &serde_json::Value::Bool(false))
        {
            return None;
        }
    }
    if ["task_id", "status", "state", "error"]
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return None;
    }
    (exit_code != 0 || ok).then_some(exit_code)
}

// ── Cost guard ─────────────────────────────────────────────────────────────

/// A cost budget for a session or job. `--max-cost` (microcents).
#[derive(Debug, Clone, Copy, Default)]
pub struct CostGuard {
    pub max_microcents: Option<u64>,
}

impl CostGuard {
    /// Should the run stop? Returns the reason when over budget.
    pub fn check(&self, spent_microcents: u64) -> Option<String> {
        self.max_microcents
            .map(|max| {
                if spent_microcents >= max {
                    format!("cost guard: spent {spent_microcents}µ¢ of {max}µ¢ budget — stopping")
                } else {
                    String::new()
                }
            })
            .filter(|s| !s.is_empty())
    }
}

// ── Headless completion ────────────────────────────────────────────────────

/// The final summary object for `orbit -p --output-format json` (the
/// CI log can prove what the agent did).
#[derive(Debug, Clone)]
pub struct HeadlessSummary {
    pub ok: bool,
    pub final_text: String,
    pub rounds: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
    /// The ledger head digest at turn end (proof anchor).
    pub ledger_head: Option<String>,
    /// The RTA verdict when the model claimed a test pass (E10):
    /// attested, or an unverified claim against a recorded failure.
    pub rta: Option<serde_json::Value>,
}

impl HeadlessSummary {
    pub fn from_report(report: &TurnReport, ledger_head: Option<String>) -> Self {
        HeadlessSummary {
            ok: report.ok,
            final_text: report.final_text.clone(),
            rounds: report.rounds,
            input_tokens: report.input_tokens,
            output_tokens: report.output_tokens,
            cost_microcents: report.cost_microcents,
            ledger_head,
            rta: None,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "orbit.cli/v1",
            "command": "p",
            "status": if self.ok { "ok" } else { "stopped" },
            "final_text": self.final_text,
            "rounds": self.rounds,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "cost_microcents": self.cost_microcents,
            "ledger_head": self.ledger_head,
            "rta": self.rta,
        })
    }
}

/// Exit codes (roadmap §Headless): 0 done, 1 turn failed, 2 stopped by
/// a permission denial, 3 hit --max-turns, 130 interrupted.
pub fn exit_code(report: &TurnReport, max_rounds: u32, permission_denied: bool) -> i32 {
    // A permission denial is detectable even when the turn afterwards
    // completes (the model saw the refusal and answered around it) —
    // CI must know the run was stopped by policy, so the denial wins
    // over plain success.
    if permission_denied {
        2
    } else if report.ok {
        0
    } else if report.interrupted {
        130
    } else if report.rounds >= max_rounds {
        3
    } else {
        1
    }
}

/// Read the ledger head digest (the proof anchor for the summary).
pub fn ledger_head(home: &Path) -> Option<String> {
    let dir = home.join("ledger");
    let mut newest: Option<(std::path::PathBuf, std::time::SystemTime)> = None;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("jsonl")
            && let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && newest.as_ref().map(|(_, t)| modified > *t).unwrap_or(true)
        {
            newest = Some((p, modified));
        }
    }
    let (path, _) = newest?;
    // The head digest is the last record's digest field.
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().rev().find_map(|l| {
        serde_json::from_str::<serde_json::Value>(l)
            .ok()?
            .get("digest")
            .and_then(|d| d.as_str())
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoken_rules_tests_but_never_push() {
        let rules = extract_spoken_rules("run the tests but never push");
        let deny: Vec<_> = rules
            .iter()
            .filter(|r| r.effect == SpokenEffect::Deny)
            .collect();
        let allow: Vec<_> = rules
            .iter()
            .filter(|r| r.effect == SpokenEffect::Allow)
            .collect();
        assert_eq!(deny.len(), 1, "{rules:?}");
        assert_eq!(deny[0].rule, "Bash(git push *)");
        assert_eq!(allow.len(), 1, "{rules:?}");
        assert_eq!(allow[0].rule, "Bash(cargo test *)");
    }

    #[test]
    fn spoken_dont_push() {
        let rules = extract_spoken_rules("don't push");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule, "Bash(git push *)");
        assert_eq!(rules[0].effect, SpokenEffect::Deny);
    }

    #[test]
    fn ambiguous_speech_produces_nothing() {
        let rules = extract_spoken_rules("maybe we should look at the auth flow later");
        assert!(rules.is_empty(), "ambiguity must not produce rules");
    }

    fn call(id: &str, name: &str, command: &str) -> orbit_adapter::types::ChatMessage {
        let mut message = crate::assistant_message("");
        message.tool_calls = Some(vec![orbit_adapter::types::ToolCallMessage {
            id: id.into(),
            name: name.into(),
            arguments: serde_json::json!({"command": command}).to_string(),
        }]);
        message
    }

    fn result(id: &str, raw: &str) -> orbit_adapter::types::ChatMessage {
        let mut message = crate::assistant_message("");
        message.role = orbit_adapter::types::ChatRole::Tool;
        message.tool_call_id = Some(id.into());
        message.tool_result = Some(raw.into());
        message
    }

    fn proof_turn(raw: &str) -> Vec<orbit_adapter::types::ChatMessage> {
        vec![
            crate::user_message("Run the test command."),
            call("test-call", "Bash", "cargo test --lib"),
            result("test-call", raw),
            crate::assistant_message("The tests pass."),
        ]
    }

    #[test]
    fn captured_test_command_has_exact_zero_exit_and_current_claim() {
        let scan = scan_attestation(&proof_turn(r#"{"ok":true,"exit_code":0}"#)).unwrap();
        assert_eq!(scan.command, "cargo test --lib");
        assert_eq!(scan.exit_code, 0);
        assert!(scan.claimed_pass);
    }

    #[test]
    fn captured_failed_test_remains_unverified_despite_claim() {
        let scan = scan_attestation(&proof_turn(r#"{"ok":false,"exit_code":17}"#)).unwrap();
        assert_eq!(scan.exit_code, 17);
        assert!(scan.claimed_pass);
    }

    #[test]
    fn captured_zero_requires_a_typed_success_flag() {
        for payload in [
            r#"{"ok":false,"exit_code":0}"#,
            r#"{"exit_code":0}"#,
            r#"{"ok":"true","exit_code":0}"#,
            r#"{"ok":null,"exit_code":0}"#,
        ] {
            assert_eq!(
                scan_attestation(&proof_turn(payload)).unwrap().exit_code,
                -1,
                "{payload}"
            );
        }
    }

    #[test]
    fn captured_exit_requires_an_integer_in_the_completed_payload() {
        for payload in [
            r#"{"ok":true}"#,
            r#"{"ok":true,"exit_code":"0"}"#,
            r#"{"ok":true,"exit_code":0.0}"#,
            r#"{"ok":true,"exit_code":null}"#,
            r#"{"ok":true,"exit_code":true}"#,
            r#"{"ok":true,"exit_code":18446744073709551615}"#,
            r#"{"ok":true,"exit_code":0"#,
            r#"[{"ok":true,"exit_code":0}]"#,
        ] {
            assert_eq!(
                scan_attestation(&proof_turn(payload)).unwrap().exit_code,
                -1,
                "{payload}"
            );
        }
    }

    #[test]
    fn captured_pending_background_and_cancelled_results_are_unverified() {
        for flag in [
            "backgrounded",
            "pending",
            "cancelled",
            "canceled",
            "interrupted",
            "timed_out",
            "denied",
            "is_error",
        ] {
            for value in [
                serde_json::json!(true),
                serde_json::json!("false"),
                serde_json::Value::Null,
            ] {
                let mut payload = serde_json::json!({"ok": true, "exit_code": 0});
                payload[flag] = value;
                assert_eq!(
                    scan_attestation(&proof_turn(&payload.to_string()))
                        .unwrap()
                        .exit_code,
                    -1,
                    "{payload}"
                );
            }
        }
        for (key, value) in [
            ("task_id", serde_json::json!("pending-task")),
            ("status", serde_json::json!("running")),
            ("status", serde_json::json!("unknown")),
            ("state", serde_json::json!("cancelled")),
            ("error", serde_json::json!("execution stopped")),
        ] {
            let mut payload = serde_json::json!({"ok": true, "exit_code": 0});
            payload[key] = value;
            assert_eq!(
                scan_attestation(&proof_turn(&payload.to_string()))
                    .unwrap()
                    .exit_code,
                -1,
                "{payload}"
            );
        }
        let pending = proof_turn(r#"{"ok":true,"backgrounded":true,"task_id":"running"}"#);
        assert_eq!(scan_attestation(&pending).unwrap().exit_code, -1);
    }

    #[test]
    fn captured_explicit_false_state_flags_do_not_hide_real_completion() {
        let scan = scan_attestation(&proof_turn(
            r#"{"ok":true,"exit_code":0,"backgrounded":false,"cancelled":false,"sandboxed":true}"#,
        ))
        .unwrap();
        assert_eq!(scan.exit_code, 0);
    }

    #[test]
    fn command_shaped_non_bash_calls_cannot_attest() {
        for name in ["Read", "Task", "plugin:test:Bash", "bash", "Bash "] {
            let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
            turn[1] = call("test-call", name, "cargo test --lib");
            assert!(scan_attestation(&turn).is_none(), "{name}");
        }
    }

    #[test]
    fn bash_calls_must_come_from_assistant_messages() {
        for role in [
            orbit_adapter::types::ChatRole::Tool,
            orbit_adapter::types::ChatRole::System,
        ] {
            let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
            turn[1].role = role;
            assert!(scan_attestation(&turn).is_none());
        }
    }

    #[test]
    fn stale_prior_turn_test_does_not_attest_current_claim() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.push(crate::user_message("Summarize the work."));
        turn.push(crate::assistant_message("The tests pass."));
        assert!(scan_attestation(&turn).is_none());
    }

    #[test]
    fn current_call_cannot_borrow_a_prior_turn_result() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.push(crate::user_message("Run tests again."));
        turn.push(call("test-call", "Bash", "cargo test --lib"));
        turn.push(crate::assistant_message("The tests pass."));
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn current_unique_call_can_reuse_a_prior_turn_id_with_its_own_result() {
        let mut turn = proof_turn(r#"{"ok":false,"exit_code":7}"#);
        turn.extend(proof_turn(r#"{"ok":true,"exit_code":0}"#));
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, 0);
    }

    #[test]
    fn missing_result_keeps_a_recognized_command_unverified() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.remove(2);
        let scan = scan_attestation(&turn).unwrap();
        assert_eq!(scan.command, "cargo test --lib");
        assert_eq!(scan.exit_code, -1);
        assert!(scan.claimed_pass);
    }

    #[test]
    fn mismatched_result_id_cannot_attest() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn[2].tool_call_id = Some("different-call".into());
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn result_must_follow_the_call_in_causal_order() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.swap(1, 2);
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn result_requires_the_tool_role_and_structured_payload() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn[2].role = orbit_adapter::types::ChatRole::Assistant;
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
        turn[2].role = orbit_adapter::types::ChatRole::Tool;
        turn[2].content = turn[2].tool_result.take().unwrap();
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn duplicate_call_ids_are_ambiguous_even_across_tool_names() {
        for name in ["Bash", "Read"] {
            let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
            turn.insert(1, call("test-call", name, "cargo test --lib"));
            assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
        }
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        let duplicate = turn[1].tool_calls.as_ref().unwrap()[0].clone();
        turn[1].tool_calls.as_mut().unwrap().push(duplicate);
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn duplicate_results_are_ambiguous_regardless_of_payload_or_order() {
        for raw in [
            r#"{"ok":true,"exit_code":0}"#,
            r#"{"ok":false,"exit_code":4}"#,
            "malformed",
        ] {
            for index in [1, 3] {
                let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
                turn.insert(index, result("test-call", raw));
                assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
            }
        }
    }

    #[test]
    fn empty_call_id_cannot_attest() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn[1].tool_calls.as_mut().unwrap()[0].id.clear();
        turn[2].tool_call_id = Some(String::new());
        assert_eq!(scan_attestation(&turn).unwrap().exit_code, -1);
    }

    #[test]
    fn latest_recognized_test_call_controls_the_report() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.pop();
        turn.push(call("new-test", "Bash", "npm test"));
        turn.push(result("new-test", r#"{"ok":false,"exit_code":5}"#));
        turn.push(crate::assistant_message("The tests pass."));
        let scan = scan_attestation(&turn).unwrap();
        assert_eq!(scan.command, "npm test");
        assert_eq!(scan.exit_code, 5);
    }

    #[test]
    fn absent_user_boundary_cannot_supply_current_turn_proof() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn.remove(0);
        assert!(scan_attestation(&turn).is_none());
    }

    #[test]
    fn claim_comes_only_from_a_final_plain_assistant_message() {
        let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
        turn[3].content = "The command has finished.".into();
        assert!(!scan_attestation(&turn).unwrap().claimed_pass);
        turn[3].content = "The tests pass.".into();
        turn.push(call("uncompleted", "Read", "other"));
        assert!(!scan_attestation(&turn).unwrap().claimed_pass);
        turn.pop();
        turn.push(result("extra", r#"{"output":"tests pass"}"#));
        assert!(!scan_attestation(&turn).unwrap().claimed_pass);
    }

    #[test]
    fn literal_test_words_inside_other_commands_are_not_test_calls() {
        for command in [
            "echo cargo test",
            "printf pytest",
            "notpytest",
            "cargo testing",
            "python3 inspect.py",
        ] {
            let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
            turn[1] = call("test-call", "Bash", command);
            assert!(scan_attestation(&turn).is_none(), "{command}");
        }
    }

    #[test]
    fn malformed_or_missing_command_arguments_cannot_qualify() {
        for raw in ["not-json", "{}", r#"{"command":null}"#, r#"{"command":42}"#] {
            let mut turn = proof_turn(r#"{"ok":true,"exit_code":0}"#);
            turn[1].tool_calls.as_mut().unwrap()[0].arguments = raw.into();
            assert!(scan_attestation(&turn).is_none());
        }
    }

    #[test]
    fn cost_guard_fires_at_budget() {
        let guard = CostGuard {
            max_microcents: Some(1_000),
        };
        assert!(guard.check(500).is_none());
        assert!(guard.check(1_000).is_some());
        assert!(guard.check(2_000).is_some());
    }

    #[test]
    fn exit_codes() {
        let ok = TurnReport {
            ok: true,
            ..Default::default()
        };
        assert_eq!(exit_code(&ok, 100, false), 0);
        let interrupted = TurnReport {
            interrupted: true,
            ..Default::default()
        };
        assert_eq!(exit_code(&interrupted, 100, false), 130);
        let denied = TurnReport::default();
        assert_eq!(exit_code(&denied, 100, true), 2);
        let capped = TurnReport {
            rounds: 100,
            ..Default::default()
        };
        assert_eq!(exit_code(&capped, 100, false), 3);
        assert_eq!(exit_code(&TurnReport::default(), 100, false), 1);
    }
}
