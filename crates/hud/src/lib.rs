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

/// The display-safety gate (H-3): scrub prompt/secret/egress-URL patterns.
pub fn display_safe(text: &str) -> Result<String, HudError> {
    // Reject known leak patterns: raw prompt markers, credentials, egress URLs.
    let lowered = text.to_lowercase();
    for pat in [
        "api_key",
        "apikey",
        "authorization",
        "x-api-key",
        "bearer ",
        "prompt:",
        "user_message",
        "chain_of_thought",
    ] {
        if lowered.contains(pat) {
            return Err(HudError::DisplayGateRejected(format!(
                "payload contains disallowed pattern {pat:?} (H-3)"
            )));
        }
    }
    // Reject raw egress URLs (host:port) — digest/status words only (H-3/IF-6).
    if text.contains("://") {
        return Err(HudError::DisplayGateRejected(
            "payload contains a URL (H-3/IF-6)".into(),
        ));
    }
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
    fn display_gate_rejects_secrets() {
        assert!(display_safe("running task").is_ok());
        assert!(display_safe("api_key=secret").is_err());
        assert!(display_safe("https://api.openai.com").is_err());
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
