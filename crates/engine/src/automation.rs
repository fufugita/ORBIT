//! Automation and proof (roadmap phase 6).
//!
//! - Spoken rules: the authority extractor turns operator speech into
//!   real permission rules ("run the tests but never push" →
//!   Bash(cargo test *) allowed, Bash(git push *) denied).
//! - RTA (retest attestation): when the agent claims tests pass, ORBIT
//!   re-runs the recorded command itself; only an attested pass turns
//!   green.
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
            if let Some(phrase) = deny_phrase(&l) {
                if let Some(rule) = phrase_to_rule(&phrase, SpokenEffect::Deny) {
                    out.push(SpokenRule {
                        rule,
                        effect: SpokenEffect::Deny,
                        source_phrase: line.trim().to_string(),
                    });
                }
            }
        }
        // Allow shapes: "run the tests", "you may run cargo test",
        // "feel free to run X". An allow for the same TARGET a deny on
        // this line already covers is dropped (deny wins); different
        // targets on one line both extract ("tests but never push").
        if let Some(phrase) = allow_phrase(&l) {
            if let Some(rule) = phrase_to_rule(&phrase, SpokenEffect::Allow) {
                let denied_same_target = out.iter().any(|r| {
                    r.effect == SpokenEffect::Deny
                        && r.source_phrase == line.trim()
                        && r.rule == rule
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

// ── RTA: retest attestation ────────────────────────────────────────────────

/// An attested test pass: ORBIT re-ran the command itself.
#[derive(Debug, Clone)]
pub struct AttestedPass {
    pub command: String,
    pub exit_code: i32,
    pub attested_at_epoch: u64,
}

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
/// None when no test-like command ran. The exit code comes from the
/// tool result JSON recorded by the Bash tool itself; the claim check
/// covers the common phrasings ("tests pass", "the test passes now",
/// "tests passed", "tests are passing") — the old three-phrase list
/// missed the singular, and a claim is a claim.
pub fn scan_attestation(
    transcript: &[orbit_adapter::types::ChatMessage],
) -> Option<AttestationScan> {
    use orbit_adapter::types::ChatRole;

    // The last test-like Bash tool call, its paired result, and the
    // final assistant text — one reverse pass.
    let mut command: Option<String> = None;
    let mut exit_code: Option<i64> = None;
    let mut final_text = String::new();
    for m in transcript.iter().rev() {
        if m.role == ChatRole::Assistant && final_text.is_empty() && !m.content.is_empty() {
            final_text = m.content.to_lowercase();
        }
        if command.is_none() {
            if let Some(calls) = m.tool_calls.as_ref() {
                for c in calls.iter().rev() {
                    let Ok(a) = serde_json::from_str::<serde_json::Value>(&c.arguments) else {
                        continue;
                    };
                    let Some(cmd) = a.get("command").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let is_test = cmd.contains("cargo test")
                        || cmd.contains("npm test")
                        || cmd.contains("pytest")
                        || cmd.contains("go test")
                        || cmd.contains("python3 test");
                    if is_test {
                        command = Some(cmd.to_string());
                        // The paired result: the Tool message with this
                        // call id carries the recorded exit_code.
                        let id = c.id.clone();
                        if let Some(tm) = transcript.iter().rev().find(|t| {
                            t.role == ChatRole::Tool
                                && t.tool_call_id.as_deref() == Some(id.as_str())
                        }) {
                            if let Some(r) = tm.tool_result.as_deref() {
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(r) {
                                    exit_code = v.get("exit_code").and_then(|x| x.as_i64());
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        if command.is_some() && !final_text.is_empty() {
            break;
        }
    }
    let command = command?;
    let claimed_pass = final_text.contains("test") && (final_text.contains("pass"));
    Some(AttestationScan {
        command,
        exit_code: exit_code.unwrap_or(-1),
        claimed_pass,
    })
}

/// Re-run a command and attest the result. Only a zero exit code
/// attests a pass — the agent's claim is never trusted (roadmap:
/// "when the agent says tests pass, ORBIT re-runs the recorded
/// command itself").
pub fn attest_test_pass(command: &str, working_dir: &Path) -> Result<AttestedPass, String> {
    use std::process::Command;
    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .current_dir(working_dir)
        .output()
        .map_err(|e| format!("retest spawn failed: {e}"))?;
    let code = output.status.code().unwrap_or(-1);
    let attested = AttestedPass {
        command: command.to_string(),
        exit_code: code,
        attested_at_epoch: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    if code == 0 {
        Ok(attested)
    } else {
        Err(format!(
            "retest FAILED (exit {code}): the agent's claim of a passing test is not attested"
        ))
    }
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
        if p.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if newest.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                        newest = Some((p, modified));
                    }
                }
            }
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

    #[test]
    fn rta_attests_only_real_passes() {
        let dir = std::env::temp_dir();
        // A command that genuinely passes.
        let pass = attest_test_pass("true", &dir).unwrap();
        assert_eq!(pass.exit_code, 0);
        // A failing command is refused — the claim is not attested.
        let fail = attest_test_pass("false", &dir);
        assert!(fail.is_err());
        assert!(fail.unwrap_err().contains("not attested"));
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
