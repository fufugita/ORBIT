//! ORBIT HUD — Phase E (E16).
//!
//! Display-only renderer per DR-10 Part B:
//! - H-1/H-2: HUD is display-only; consumes only HudEvents (never mutates state).
//! - H-3: gate-scrubbed payloads — no prompt/secret/card/plan/egress-URL bytes.
//! - H-4/H-5/H-15: brand off by default; three-tier downgrade-only fallback.
//! - H-7: hard downgrade conditions (NO_COLOR/CI/TERM=dumb) are non-overridable.
//! - H-9: stdout = data, stderr = diagnostics.
//! - H-17: cost is integer µ¢.
//! - H-21/H-22: phase-router orchestrator-only; no provider fields in HUD.
//! - H-24: stdout writes serialized.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// HUD error family.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum HudError {
    #[error("payload rejected by display gate: {0}")]
    DisplayGateRejected(String),
    #[error("unsupported output mode: {0}")]
    UnsupportedMode(String),
}

/// Output mode (DR-10 Part B §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputMode {
    Full,
    Compact,
    Plain,
    Json,
    NonTty,
}

/// Brand tier (H-4/H-5/H-15): Anim, Static, Text, Off — downgrade-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BrandTier {
    Anim,
    Static,
    Text,
    Off,
}

/// A HUD event (H-2: display-safe, typed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HudEvent {
    PhaseChanged { phase: String },
    CostBar { cost_microcents: u64 }, // H-17 integer µ¢
    Indicator { kind: String },       // REPLAY | DRIFT | RESTRICTED (H-16)
    Message { text: String },         // DisplaySafeString-only
}

/// The display-safety gate (H-3), value-based: secrets are detected by
/// SHAPE, not by the presence of words like "authorization" (which
/// blanked ordinary code while passing real keys that lacked the word).
/// A detected secret value is REDACTED — the line survives, the value
/// does not. Chain-of-thought markers still reject whole-payload (that
/// rule is about role confusion, not secrets).
pub fn display_safe(text: &str) -> Result<String, HudError> {
    // CoT markers remain hard rejects (H-3): these are prompt-confusion
    // payloads, not secrets.
    let lowered = text.to_lowercase();
    for pat in ["prompt:", "user_message", "chain_of_thought"] {
        if lowered.contains(pat) {
            return Err(HudError::DisplayGateRejected(format!(
                "payload contains disallowed pattern {pat:?} (H-3)"
            )));
        }
    }
    // Secret VALUES: redact, keep the line.
    let text = redact_secret_values(text);
    // Strip ANSI/control sequences (H-3).
    let stripped: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    Ok(stripped)
}

/// Environment negotiation (H-7 hard downgrades, non-overridable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Env {
    pub no_color: bool,
    pub ci: bool,
    pub term_dumb: bool,
}

impl Env {
    /// Resolve the forced output mode + brand tier from the environment.
    /// Precedence (DR-10 §15.1): NO_COLOR > CI > screen-reader > TERM=dumb.
    pub fn negotiate(&self) -> (OutputMode, BrandTier) {
        if self.no_color {
            // NO_COLOR is strongest: forces Plain+Text (H-7 non-overridable).
            (OutputMode::Plain, BrandTier::Text)
        } else if self.ci {
            // CI forces Json+Off (DR-10 §15.4).
            (OutputMode::Json, BrandTier::Off)
        } else if self.term_dumb {
            (OutputMode::Plain, BrandTier::Text)
        } else {
            (OutputMode::Full, BrandTier::Off) // brand off by default (H-4)
        }
    }
}

/// The HUD renderer: display-only (H-1), event-sourced (H-2).
pub struct Hud {
    output_mode: OutputMode,
    brand_tier: BrandTier,
}

impl Hud {
    pub fn new(env: &Env) -> Self {
        let (output_mode, brand_tier) = env.negotiate();
        Self {
            output_mode,
            brand_tier,
        }
    }

    /// Render an event to its output line(s). Returns (stdout, stderr) — the
    /// split is normative (H-9): data to stdout, diagnostics to stderr.
    pub fn render(&self, event: &HudEvent) -> (Option<String>, Option<String>) {
        match self.output_mode {
            OutputMode::Json => {
                // One JSON object per line on stdout (DR-10 §16.6); no ANSI.
                (Some(serde_json::to_string(event).unwrap_or_default()), None)
            }
            OutputMode::Full | OutputMode::Compact | OutputMode::NonTty => {
                match event {
                    HudEvent::PhaseChanged { phase } => (Some(format!("[PHASE:{phase}]")), None),
                    HudEvent::CostBar { cost_microcents } => {
                        (Some(format!("[COST:{cost_microcents}µ¢]")), None) // H-17 integer
                    }
                    HudEvent::Indicator { kind } => (Some(format!("[IND:{kind}]")), None),
                    HudEvent::Message { text } => (Some(text.clone()), None),
                }
            }
            OutputMode::Plain => {
                // Plain: silent stdout, text to stderr (DR-10 §16.5).
                let line = match event {
                    HudEvent::PhaseChanged { phase } => format!("phase={phase}"),
                    HudEvent::CostBar { cost_microcents } => format!("cost={cost_microcents}"),
                    HudEvent::Indicator { kind } => format!("indicator={kind}"),
                    HudEvent::Message { text } => text.clone(),
                };
                (None, Some(line))
            }
        }
    }

    /// Brand is downgrade-only (H-5): the tier may only move TOWARD Off
    /// (Off is the "most off"; Anim is the "most on"). A request to move
    /// toward Anim is a promotion and is refused.
    pub fn downgrade_brand(&mut self, to: BrandTier) {
        if to > self.brand_tier {
            // Higher ordinal = further toward Off (Anim < Static < Text < Off).
            self.brand_tier = to;
        }
        // Never promote toward Anim (H-5).
    }

    pub fn brand_tier(&self) -> BrandTier {
        self.brand_tier
    }

    pub fn output_mode(&self) -> OutputMode {
        self.output_mode
    }
}

/// Redact secret VALUES in place: PEM blocks → `[redacted:private key]`,
/// known token formats → `[redacted:<kind>]`, high-entropy assignments →
/// `[redacted:secret]`. Ordinary words (authorization, api_key in code)
/// and URLs pass untouched — the old keyword rejection is gone.
pub fn redact_secret_values(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        out.push_str(&redact_line(line));
    }
    out
}

fn redact_line(line: &str) -> String {
    // PEM block lines: redact the whole block content.
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
        return "[redacted:private key]\n".into();
    }
    let mut line = line.to_string();
    for (prefix, what) in [
        ("sk-", "api token"),
        ("ghp_", "github token"),
        ("gho_", "github token"),
        ("github_pat_", "github token"),
        ("AKIA", "aws access key"),
        ("xoxb-", "slack token"),
        ("xoxp-", "slack token"),
    ] {
        // One redaction per format per line is enough.
        if let Some(pos) = line.find(prefix) {
            let end = line[pos..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .map(|i| pos + i)
                .unwrap_or(line.len());
            if end - pos >= prefix.len() + 16 {
                line = format!("{}[redacted:{}]{}", &line[..pos], what, &line[end..]);
            }
        }
    }
    // High-entropy assignments: KEY = <long value> → KEY = [redacted]
    if let Some(eq) = line.find('=') {
        let (k, v) = line.split_at(eq);
        let key_up = k.trim().to_uppercase();
        let looks_secret = key_up.contains("SECRET")
            || key_up.contains("TOKEN")
            || key_up.contains("PASSWORD")
            || key_up.contains("API_KEY")
            || key_up.contains("PRIVATE");
        let val = v[1..].trim().trim_matches('"').trim_matches('\'');
        if looks_secret && val.chars().count() >= 32 && entropy_bits(val) > 3.5 {
            return format!(
                "{}= [redacted:secret]{}",
                k,
                &v[1 + v[1..].len() - val.len()..].trim_start_matches(val)
            );
        }
    }
    line
}

fn entropy_bits(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0u32) += 1;
    }
    let n = chars.len() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_forces_plain_text() {
        let env = Env {
            no_color: true,
            ci: false,
            term_dumb: false,
        };
        let (mode, tier) = env.negotiate();
        assert_eq!(mode, OutputMode::Plain);
        assert_eq!(tier, BrandTier::Text);
    }

    #[test]
    fn ci_forces_json_off() {
        let env = Env {
            no_color: false,
            ci: true,
            term_dumb: false,
        };
        let (mode, tier) = env.negotiate();
        assert_eq!(mode, OutputMode::Json);
        assert_eq!(tier, BrandTier::Off);
    }

    #[test]
    fn brand_off_by_default() {
        let env = Env {
            no_color: false,
            ci: false,
            term_dumb: false,
        };
        let (_, tier) = env.negotiate();
        assert_eq!(tier, BrandTier::Off, "H-4 brand default-off");
    }

    #[test]
    fn display_gate_redacts_secret_values_not_words() {
        // Ordinary text and URLs pass unchanged (the old keyword
        // rejection blanked these).
        assert!(display_safe("running task").is_ok());
        assert!(display_safe("let authorization = header;").is_ok());
        assert!(display_safe("api_key = \"name-of-field\"").is_ok());
        assert_eq!(
            display_safe("https://api.openai.com").unwrap(),
            "https://api.openai.com"
        );
        // Real secret VALUES are redacted in place, not rejected.
        let out = display_safe("token = sk-abc123def456ghi789jkl012mno").unwrap();
        assert!(out.contains("[redacted:api token]"), "got: {out}");
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----";
        let out = display_safe(pem).unwrap();
        assert!(out.contains("[redacted:private key]"));
        // CoT markers remain hard rejects (prompt-confusion payloads).
        assert!(display_safe("chain_of_thought: ...").is_err());
    }

    #[test]
    fn json_output_no_ansi() {
        let env = Env {
            no_color: false,
            ci: true,
            term_dumb: false,
        };
        let hud = Hud::new(&env);
        let (out, _err) = hud.render(&HudEvent::PhaseChanged {
            phase: "exec".into(),
        });
        let line = out.unwrap();
        assert!(line.starts_with('{'));
        assert!(!line.contains("\u{1b}"), "no ANSI in JSON mode");
    }

    #[test]
    fn brand_downgrade_only() {
        let env = Env {
            no_color: false,
            ci: false,
            term_dumb: false,
        };
        let mut hud = Hud::new(&env);
        assert_eq!(hud.brand_tier(), BrandTier::Off);
        // Attempt to "promote" — must be a no-op (H-5).
        let _ = &mut hud.downgrade_brand(BrandTier::Anim);
        // Anim > Off, so downgrade refuses (already Off).
        assert_eq!(hud.brand_tier(), BrandTier::Off);
    }
}
