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

mod text;

pub use text::{CotStripper, safe_text, strip_cot};

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
    let mut private_blocks = Vec::new();
    for line in text.split_inclusive('\n') {
        let (body, ending) = if let Some(body) = line.strip_suffix("\r\n") {
            (body, "\r\n")
        } else if let Some(body) = line.strip_suffix('\n') {
            (body, "\n")
        } else {
            (line, "")
        };
        if let Some((start, label, end)) = private_key_begin(body) {
            let remainder = &body[end..];
            if remainder.contains("-----BEGIN") || malformed_private_key_start(remainder).is_some()
            {
                if private_blocks.is_empty() {
                    append_private_key_marker(&mut out, &body[..start], ending);
                }
                break;
            }
            if private_blocks.is_empty() {
                let end_marker = format!("-----END {label}-----");
                let close = remainder
                    .match_indices(&end_marker)
                    .find(|(close_start, _)| {
                        let close_end = close_start + end_marker.len();
                        !remainder[..*close_start].ends_with('-')
                            && !remainder[close_end..].starts_with('-')
                    });
                if let Some((close_start, _)) = close {
                    let close_end = end + close_start + end_marker.len();
                    let line = format!(
                        "{}[redacted:private key]{}{}",
                        &body[..start],
                        &body[close_end..],
                        ending
                    );
                    out.push_str(&redact_line(&line));
                    continue;
                }
                append_private_key_marker(&mut out, &body[..start], ending);
            }
            private_blocks.push(label);
            continue;
        }
        if let Some(start) = malformed_private_key_start(body) {
            if private_blocks.is_empty() {
                append_private_key_marker(&mut out, &body[..start], ending);
            }
            break;
        }
        if let Some(label) = private_blocks.last() {
            if private_key_end(body, label) {
                let _ = private_blocks.pop();
            }
            continue;
        }
        out.push_str(&redact_line(line));
    }
    out
}

fn malformed_private_key_start(line: &str) -> Option<usize> {
    let folded = line.to_ascii_lowercase();
    let bytes = folded.as_bytes();

    // The close marker can be separated from `key` by an arbitrarily long
    // ASCII-whitespace suffix. Precompute its next non-whitespace byte once so
    // many key-like words cannot repeatedly scan that same suffix.
    let mut next_non_whitespace = vec![bytes.len(); bytes.len() + 1];
    for index in (0..bytes.len()).rev() {
        next_non_whitespace[index] = if bytes[index].is_ascii_whitespace() {
            next_non_whitespace[index + 1]
        } else {
            index
        };
    }
    let first_non_unicode_whitespace = line
        .char_indices()
        .find_map(|(index, character)| (!character.is_whitespace()).then_some(index));

    let mut hyphen_run_start = 0usize;
    let mut hyphen_run_len = 0usize;
    let mut token_start = None;
    let mut last_token = None;
    let mut earliest_complete_begin = None;
    let mut begin_without_following_delimiter = None;

    for index in 0..bytes.len() {
        let byte = bytes[index];
        let preceding_hyphens = hyphen_run_len;
        let preceding_hyphen_start = hyphen_run_start;

        if byte.is_ascii_alphanumeric() {
            token_start.get_or_insert(index);
        } else {
            if let Some(start) = token_start.take() {
                last_token = Some((start, index));
            }
            if let Some((after_begin, delimiter_start, delimiter_hyphens)) =
                begin_without_following_delimiter
                && index >= after_begin
            {
                if index == after_begin && earliest_complete_begin.is_none() {
                    earliest_complete_begin =
                        Some((after_begin, delimiter_start, delimiter_hyphens));
                }
                // `beginning` is ordinary prose, not a `begin` token. Keep
                // the no-delimiter candidate only for the exact compact
                // form handled by `direct_candidate` below.
                begin_without_following_delimiter = None;
            }
        }

        if bytes[index..].starts_with(b"key")
            && !bytes
                .get(index + b"key".len())
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            let after_key = index + b"key".len();
            let first_boundary_byte = next_non_whitespace[after_key];
            let has_closing_hyphens = first_boundary_byte + 3 <= bytes.len()
                && bytes[first_boundary_byte..first_boundary_byte + 3] == *b"---";

            let previous_token_is_private = |after_begin: usize| {
                let token_before_key = token_start
                    .filter(|start| *start < index)
                    .map(|start| (start, index))
                    .or(last_token);
                token_before_key.is_some_and(|(start, end)| {
                    start >= after_begin && bytes[start..end] == *b"private"
                })
            };

            let complete_candidate = earliest_complete_begin
                .filter(|(after_begin, _, _)| previous_token_is_private(*after_begin));
            let direct_candidate = begin_without_following_delimiter
                .filter(|(after_begin, _, _)| bytes.get(*after_begin..index) == Some(b"private"));

            if let Some((_, delimiter_start, delimiter_hyphens)) =
                complete_candidate.or(direct_candidate)
            {
                let public_prefix_precedes_delimiter = first_non_unicode_whitespace
                    .is_some_and(|first_non_whitespace| first_non_whitespace < delimiter_start);
                let missing_close_is_unambiguous = first_boundary_byte == bytes.len()
                    && (!public_prefix_precedes_delimiter
                        || (public_prefix_precedes_delimiter && delimiter_hyphens == 5));
                if has_closing_hyphens || missing_close_is_unambiguous {
                    return Some(delimiter_start);
                }
            }
        }

        if bytes[index..].starts_with(b"begin") && preceding_hyphens >= 3 {
            let after_begin = index + b"begin".len();
            begin_without_following_delimiter =
                Some((after_begin, preceding_hyphen_start, preceding_hyphens));
        }

        if byte == b'-' {
            if hyphen_run_len == 0 {
                hyphen_run_start = index;
            }
            hyphen_run_len += 1;
        } else {
            hyphen_run_len = 0;
        }
    }

    None
}

fn append_private_key_marker(out: &mut String, prefix: &str, ending: &str) {
    let mut line = String::with_capacity(prefix.len() + 22 + ending.len());
    line.push_str(prefix);
    line.push_str("[redacted:private key]");
    line.push_str(ending);
    out.push_str(&redact_line(&line));
}

fn private_key_begin(line: &str) -> Option<(usize, &str, usize)> {
    const BEGIN: &str = "-----BEGIN ";
    let start = line.find("-----BEGIN")?;
    if (start > 0 && line.as_bytes()[start - 1] == b'-') || !line[start..].starts_with(BEGIN) {
        return None;
    }
    let label_start = start + BEGIN.len();
    let label_end = label_start + line[label_start..].find("-----")?;
    let end = label_end + 5;
    let label = &line[label_start..label_end];
    if line.as_bytes().get(end) == Some(&b'-')
        || !(label == "PRIVATE KEY" || label.ends_with(" PRIVATE KEY"))
    {
        return None;
    }
    let valid = label.split(' ').all(|word| {
        let bytes = word.as_bytes();
        bytes
            .first()
            .is_some_and(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && bytes
                .last()
                .is_some_and(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'-')
    });
    valid.then_some((start, label, end))
}

fn private_key_end(line: &str, label: &str) -> bool {
    let line = line.trim_matches([' ', '\t']);
    let Some(rest) = line.strip_prefix("-----END ") else {
        return false;
    };
    rest.strip_suffix("-----") == Some(label)
}

fn redact_known_format(line: &str, prefix: &str, kind: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut search = 0;
    let mut copied = 0;
    // Search only the immutable input for this pass, never inserted markers.
    while let Some(relative) = line[search..].find(prefix) {
        let start = search + relative;
        let end = line[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .map(|offset| start + offset)
            .unwrap_or(line.len());
        if end - start >= prefix.len() + 16 {
            out.push_str(&line[copied..start]);
            out.push_str("[redacted:");
            out.push_str(kind);
            out.push(']');
            copied = end;
            search = end;
        } else {
            search = start + prefix.len();
        }
    }
    out.push_str(&line[copied..]);
    out
}

fn redact_line(line: &str) -> String {
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
        line = redact_known_format(&line, prefix, what);
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
            let newline = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            return format!("{k}= [redacted:secret]{newline}");
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
    fn unicode_assignment_redaction_preserves_line_boundaries() {
        for (suffix, newline) in [("", ""), ("\n", "\n"), ("\r\n", "\r\n")] {
            let text = format!("secret note = \"éAbCdEfGhIjKlMnOpQrStUvWxYz0123456789\"{suffix}");
            assert_eq!(
                redact_secret_values(&text),
                format!("secret note = [redacted:secret]{newline}")
            );
            assert_eq!(
                display_safe(&text).unwrap(),
                format!(
                    "secret note = [redacted:secret]{}",
                    newline.replace('\r', "")
                )
            );
        }
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

    #[test]
    fn repeated_known_tokens_after_short_decoys_preserve_unicode_public_context() {
        for (prefix, kind) in [
            ("sk-", "api token"),
            ("ghp_", "github token"),
            ("gho_", "github token"),
            ("github_pat_", "github token"),
            ("AKIA", "aws access key"),
            ("xoxb-", "slack token"),
            ("xoxp-", "slack token"),
        ] {
            let first = format!("{prefix}a1B2c3D4e5F6g7H8i9J0");
            let second = format!("{prefix}z9Y8x7W6v5U4t3S2r1Q0");
            for with_decoy in [false, true] {
                let before = if with_decoy {
                    format!("public café {prefix}short 中 ")
                } else {
                    "public café 中 ".to_owned()
                };
                let input = format!("{before}{first} 🦀 {second} public after");
                let expected =
                    format!("{before}[redacted:{kind}] 🦀 [redacted:{kind}] public after");
                let clean = redact_secret_values(&input);
                assert!(!clean.contains(first.as_str()));
                assert!(!clean.contains(second.as_str()));
                assert_eq!(clean, expected);
                assert_eq!(display_safe(&input).unwrap(), expected);
            }
        }
    }

    #[test]
    fn complete_and_unclosed_multiline_private_keys_hide_body_and_keep_line_boundaries() {
        let body_a = "U1lOVEhFVElDX09OTFlfUEVNX0JPRFlfQQ==";
        let body_b = "U1lOVEhFVElDX09OTFlfUEVNX0JPRFlfQg==";
        for newline in ["\n", "\r\n"] {
            for label in [
                "PRIVATE KEY",
                "RSA PRIVATE KEY",
                "DSA PRIVATE KEY",
                "EC PRIVATE KEY",
                "OPENSSH PRIVATE KEY",
                "ENCRYPTED PRIVATE KEY",
            ] {
                let complete = format!(
                    "public before{newline}-----BEGIN {label}-----{newline}{body_a}{newline}{body_b}{newline}-----END {label}-----{newline}public after{newline}"
                );
                let expected = format!(
                    "public before{newline}[redacted:private key]{newline}public after{newline}"
                );
                let clean = redact_secret_values(&complete);
                assert!(!clean.contains(body_a));
                assert!(!clean.contains(body_b));
                assert!(!clean.contains("-----END"));
                assert_eq!(clean, expected);
                assert_eq!(display_safe(&complete).unwrap(), expected.replace('\r', ""));

                let unclosed = format!(
                    "public before{newline}-----BEGIN {label}-----{newline}{body_a}{newline}{body_b}{newline}public-looking tail still inside the private block"
                );
                let expected = format!("public before{newline}[redacted:private key]{newline}");
                let clean = redact_secret_values(&unclosed);
                assert!(!clean.contains(body_a));
                assert!(!clean.contains(body_b));
                assert!(!clean.contains("public-looking tail"));
                assert_eq!(clean, expected);
                assert_eq!(display_safe(&unclosed).unwrap(), expected.replace('\r', ""));
            }

            let mismatched = format!(
                "public before{newline}-----BEGIN RSA PRIVATE KEY-----{newline}{body_a}{newline}-----END PRIVATE KEY-----{newline}{body_b}{newline}-----END RSA PRIVATE KEY-----{newline}public after{newline}"
            );
            let expected = format!(
                "public before{newline}[redacted:private key]{newline}public after{newline}"
            );
            let clean = redact_secret_values(&mismatched);
            assert!(!clean.contains(body_a));
            assert!(!clean.contains(body_b));
            assert!(!clean.contains("-----END"));
            assert_eq!(clean, expected);
            assert_eq!(
                display_safe(&mismatched).unwrap(),
                expected.replace('\r', "")
            );

            let unmatched = format!(
                "public before{newline}-----BEGIN RSA PRIVATE KEY-----{newline}{body_a}{newline}-----END PRIVATE KEY-----{newline}{body_b}{newline}public-looking tail still inside the private block"
            );
            let expected = format!("public before{newline}[redacted:private key]{newline}");
            let clean = redact_secret_values(&unmatched);
            assert!(!clean.contains(body_a));
            assert!(!clean.contains(body_b));
            assert!(!clean.contains("-----END"));
            assert!(!clean.contains("public-looking tail"));
            assert_eq!(clean, expected);
            assert_eq!(
                display_safe(&unmatched).unwrap(),
                expected.replace('\r', "")
            );
        }
    }

    #[test]
    fn inline_private_key_redaction_preserves_text_after_matching_end() {
        let secret = "SYNTHETIC_INLINE_PRIVATE_KEY_SECRET";
        let input =
            format!("before -----BEGIN PRIVATE KEY-----{secret}-----END PRIVATE KEY----- after\n");
        let expected = "before [redacted:private key] after\n";

        let clean = redact_secret_values(&input);
        assert!(!clean.contains(secret));
        assert_eq!(clean, expected);
        assert_eq!(display_safe(&input).unwrap(), expected);
    }

    #[test]
    fn inline_private_key_redaction_fails_closed_on_mixed_case_suffix_header() {
        let input = "before -----BEGIN PRIVATE KEY-----SYNTHETIC_FIRST-----END PRIVATE KEY----- -----begin private key-----SYNTHETIC_SECOND\npublic-looking tail\n";
        let expected = "before [redacted:private key]\n";

        let clean = redact_secret_values(input);
        assert!(!clean.contains("SYNTHETIC_FIRST"));
        assert!(!clean.contains("SYNTHETIC_SECOND"));
        assert!(!clean.contains("public-looking tail"));
        assert_eq!(clean, expected);
        assert_eq!(display_safe(input).unwrap(), expected);

        for opener in ["---", "----", "------"] {
            let prose =
                format!("public prefix {opener}begin private key\nSYNTHETIC_BODY\npublic tail\n");
            assert_eq!(redact_secret_values(&prose), prose);
            assert_eq!(display_safe(&prose).unwrap(), prose);
        }
    }

    #[test]
    fn malformed_inline_private_key_opener_after_public_prefix_fails_closed() {
        let input = "public prefix -----BEGIN PRIVATE KEY\nSYNTHETIC_PRIVATE_BODY\n-----END PRIVATE KEY-----\npublic-looking tail\n";
        let expected = "public prefix [redacted:private key]\n";

        let clean = redact_secret_values(input);
        assert!(!clean.contains("SYNTHETIC_PRIVATE_BODY"));
        assert!(!clean.contains("-----END PRIVATE KEY-----"));
        assert!(!clean.contains("public-looking tail"));
        assert_eq!(clean, expected);
        assert_eq!(display_safe(input).unwrap(), expected);
    }

    #[test]
    fn malformed_mixed_case_private_key_intent_fails_closed() {
        for opener in [
            "-----BEGIN rsa private key-----",
            "-----BEGIN Rsa Private Key-----",
            "-----begin RSA PRIVATE KEY-----",
            "----BEGIN PRIVATE KEY-----",
            "------BEGIN PRIVATE KEY-----",
            "---BEGIN PRIVATE KEY-----",
            "--------BEGIN PRIVATE KEY-----",
        ] {
            let input = format!(
                "public before\n{opener}\nSYNTHETIC_PRIVATE_BODY\npublic-looking tail still private"
            );
            let expected = "public before\n[redacted:private key]\n";
            let clean = redact_secret_values(&input);
            assert!(!clean.contains("SYNTHETIC_PRIVATE_BODY"));
            assert!(!clean.contains("public-looking tail"));
            assert_eq!(clean, expected);
            assert_eq!(display_safe(&input).unwrap(), expected);
        }

        let inline = "public prefix ----BEGIN PRIVATE KEY-----SYNTHETIC_PRIVATE_BODY-----END PRIVATE KEY----- after";
        assert_eq!(
            redact_secret_values(inline),
            "public prefix [redacted:private key]"
        );

        for ordinary in [
            "please begin private key migration after review",
            "Use --begin private key mode for migration",
            "Use -begin private key mode for migration",
            "Use ---begin private key mode for migration",
            "please ---begin private key",
        ] {
            assert_eq!(redact_secret_values(ordinary), ordinary);
        }

        let public = "public before\n-----BEGIN PUBLIC KEY-----\nPUBLIC_KEY_BODY\n-----END PUBLIC KEY-----\npublic after\n";
        assert_eq!(redact_secret_values(public), public);
    }

    #[test]
    fn malformed_private_key_scanner_preserves_ascii_token_and_whitespace_rules() {
        for opener in [
            "---begin privatekey---",
            "---begin private/key---",
            "---begin private-key---",
            "---beginéprivate-key---",
        ] {
            assert_eq!(malformed_private_key_start(opener), Some(0), "{opener:?}");
        }

        for prose in ["---beginning private key---", "---beginner private key---"] {
            assert_eq!(malformed_private_key_start(prose), None, "{prose:?}");
            assert_eq!(redact_secret_values(prose), prose, "{prose:?}");
        }

        assert_eq!(
            malformed_private_key_start("\u{2003}---begin private key"),
            Some(3)
        );
        assert_eq!(
            malformed_private_key_start("---begin private key\u{2003}"),
            None
        );
    }

    #[test]
    fn malformed_private_key_scanner_handles_many_public_key_like_phrases() {
        let line = "---begin public key ---".repeat(1_024);
        assert_eq!(malformed_private_key_start(&line), None);
    }

    #[test]
    fn forged_redaction_markers_do_not_bypass_high_entropy_assignment_redaction() {
        let secret = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9_2-4+6/8=";
        for marker in [
            "[redacted:api token]",
            "[redacted:private key]",
            "[redacted:secret]",
        ] {
            let input = format!("public café {marker} API_KEY = \"{secret}\"\r\npublic after\n");
            let expected =
                format!("public café {marker} API_KEY = [redacted:secret]\r\npublic after\n");
            let clean = redact_secret_values(&input);
            assert!(!clean.contains(secret));
            assert_eq!(clean, expected);
            assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
        }
    }

    #[test]
    fn known_token_suffix_threshold_is_exact_at_unicode_edges() {
        for (prefix, kind) in [
            ("sk-", "api token"),
            ("ghp_", "github token"),
            ("gho_", "github token"),
            ("github_pat_", "github token"),
            ("AKIA", "aws access key"),
            ("xoxb-", "slack token"),
            ("xoxp-", "slack token"),
        ] {
            let short = format!("{prefix}{}", "a".repeat(15));
            let secret = format!("{prefix}{}", "b".repeat(16));
            let input = format!("公開{short}é{secret}🦀public after");
            let expected = format!("公開{short}é[redacted:{kind}]🦀public after");
            let clean = redact_secret_values(&input);
            assert!(clean.contains(short.as_str()));
            assert!(!clean.contains(secret.as_str()));
            assert_eq!(clean, expected);
            assert_eq!(display_safe(&input).unwrap(), expected);
        }
    }

    #[test]
    fn mixed_known_formats_and_repeated_short_decoys_preserve_public_context() {
        let formats = [
            ("sk-", "api token"),
            ("ghp_", "github token"),
            ("gho_", "github token"),
            ("github_pat_", "github token"),
            ("AKIA", "aws access key"),
            ("xoxb-", "slack token"),
            ("xoxp-", "slack token"),
        ];
        for (index, &(prefix, kind)) in formats.iter().enumerate() {
            let (other_prefix, other_kind) = formats[(index + 1) % formats.len()];
            let first = format!("{prefix}a1B2c3D4e5F6g7H8");
            let second = format!("{other_prefix}z9Y8x7W6v5U4t3S2");
            let decoys = format!("{prefix}short/{prefix}tiny");
            for separator in [" 🦀 ", "/", "\r\n"] {
                let input = format!(
                    "café {decoys} 中 {first}{separator}{second}{separator}{first} public after"
                );
                let expected = format!(
                    "café {decoys} 中 [redacted:{kind}]{separator}[redacted:{other_kind}]{separator}[redacted:{kind}] public after"
                );
                let clean = redact_secret_values(&input);
                assert!(!clean.contains(first.as_str()));
                assert!(!clean.contains(second.as_str()));
                assert!(clean.contains(decoys.as_str()));
                assert_eq!(clean, expected);
                assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
            }
        }
    }

    #[test]
    fn private_header_at_eof_keeps_only_its_actual_line_ending() {
        for label in [
            "PRIVATE KEY",
            "EXPERIMENTAL-7 PRIVATE KEY",
            "7-X V2 PRIVATE KEY",
        ] {
            for prefix in ["", "public café "] {
                for ending in ["", "\n", "\r\n"] {
                    for suffix in ["", " INLINE_SYNTHETIC_BODY"] {
                        let input = format!("{prefix}-----BEGIN {label}-----{suffix}{ending}");
                        let expected = format!("{prefix}[redacted:private key]{ending}");
                        let clean = redact_secret_values(&input);
                        assert!(!clean.contains("INLINE_SYNTHETIC_BODY"));
                        assert!(!clean.contains("-----BEGIN"));
                        assert_eq!(clean, expected);
                        assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
                    }
                }
            }
        }
    }

    #[test]
    fn consecutive_private_blocks_preserve_opening_endings_and_future_labels() {
        for (open_a, close_a, open_b, close_b) in [
            ("\n", "\n", "\n", "\n"),
            ("\r\n", "\n", "\n", "\r\n"),
            ("\n", "\r\n", "\r\n", "\n"),
            ("\r\n", "\r\n", "\r\n", "\r\n"),
        ] {
            let input = format!(
                "public before\n-----BEGIN PRIVATE KEY-----{open_a}SYNTHETIC_BODY_A\n-----END PRIVATE KEY-----{close_a}-----BEGIN EXPERIMENTAL-7 PRIVATE KEY-----{open_b}SYNTHETIC_BODY_B\r\n-----END EXPERIMENTAL-7 PRIVATE KEY-----{close_b}public after\n"
            );
            let expected = format!(
                "public before\n[redacted:private key]{open_a}[redacted:private key]{open_b}public after\n"
            );
            let clean = redact_secret_values(&input);
            assert!(!clean.contains("SYNTHETIC_BODY_A"));
            assert!(!clean.contains("SYNTHETIC_BODY_B"));
            assert!(!clean.contains("-----END"));
            assert_eq!(clean, expected);
            assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
        }
    }

    #[test]
    fn nested_private_blocks_require_the_top_label_before_public_output_resumes() {
        for newline in ["\n", "\r\n"] {
            let closed = format!(
                "public before{newline}[redacted:private key]{newline}public after{newline}"
            );
            let unclosed = format!("public before{newline}[redacted:private key]{newline}");
            let cases = [
                (
                    format!(
                        "public before{newline}-----BEGIN PRIVATE KEY-----{newline}SYNTHETIC_OUTER{newline}-----BEGIN PRIVATE KEY-----{newline}SYNTHETIC_INNER{newline}-----END PRIVATE KEY-----{newline}SYNTHETIC_OUTER_TAIL{newline}-----END PRIVATE KEY-----{newline}public after{newline}"
                    ),
                    closed.as_str(),
                ),
                (
                    format!(
                        "public before{newline}-----BEGIN RSA PRIVATE KEY-----{newline}SYNTHETIC_OUTER{newline}-----BEGIN EC PRIVATE KEY-----{newline}SYNTHETIC_INNER{newline}-----END RSA PRIVATE KEY-----{newline}SYNTHETIC_AFTER_EARLY_OUTER_END{newline}-----END EC PRIVATE KEY-----{newline}SYNTHETIC_OUTER_TAIL{newline}-----END RSA PRIVATE KEY-----{newline}public after{newline}"
                    ),
                    closed.as_str(),
                ),
                (
                    format!(
                        "public before{newline}-----BEGIN RSA PRIVATE KEY-----{newline}SYNTHETIC_OUTER{newline}-----BEGIN EC PRIVATE KEY-----{newline}SYNTHETIC_INNER{newline}-----END RSA PRIVATE KEY-----{newline}public-looking tail still private"
                    ),
                    unclosed.as_str(),
                ),
            ];
            for (input, expected) in cases {
                let clean = redact_secret_values(&input);
                assert!(!clean.contains("SYNTHETIC_"));
                assert!(!clean.contains("-----END"));
                assert!(!clean.contains("public-looking tail"));
                assert_eq!(clean, expected);
                assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
            }
        }
    }

    #[test]
    fn malformed_private_openers_poison_outer_closure_until_eof() {
        for opener in [
            "-----BEGIN RSA  PRIVATE KEY-----",
            "-----BEGIN  PRIVATE KEY-----",
            "-----BEGIN RSA_PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY----",
            "-----BEGIN RSA PRIVATE KEY------",
            "------BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY",
            "-----BEGIN RSA PRIVATE KEY---- SYNTHETIC_PREFIX_BODY -----BEGIN PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY----- SYNTHETIC_PREFIX_BODY -----BEGIN PRIVATE KEY-----",
        ] {
            for newline in ["\n", "\r\n"] {
                for inside_outer in [false, true] {
                    let outer = if inside_outer {
                        format!("-----BEGIN PRIVATE KEY-----{newline}SYNTHETIC_OUTER{newline}")
                    } else {
                        String::new()
                    };
                    let input = format!(
                        "public before{newline}{outer}{opener}{newline}SYNTHETIC_PRIVATE_BODY{newline}-----END RSA PRIVATE KEY-----{newline}-----END PRIVATE KEY-----{newline}public-looking tail must stay private"
                    );
                    let expected = format!("public before{newline}[redacted:private key]{newline}");
                    let clean = redact_secret_values(&input);
                    assert!(!clean.contains("SYNTHETIC_"));
                    assert!(!clean.contains("-----END"));
                    assert!(!clean.contains("public-looking tail"));
                    assert_eq!(clean, expected);
                    assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
                }
            }
        }
    }

    #[test]
    fn inline_ends_and_extra_begin_suffixes_cannot_release_private_tail() {
        let cases = [
            (
                "public before\n-----BEGIN PUBLIC KEY-----SOMETHING PRIVATE KEY-----\nSYNTHETIC_BODY\n-----END PUBLIC KEY-----SOMETHING PRIVATE KEY-----\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
            (
                "public before\n-----BEGIN PUBLIC KEY-----BEGIN PRIVATE KEY-----\nSYNTHETIC_BODY\n-----END PUBLIC KEY-----BEGIN PRIVATE KEY-----\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
            (
                "public before\nprefix -----BEGIN PRIVATE KEY----- SYNTHETIC_BODY -----END PRIVATE KEY----- public suffix\npublic-looking tail\n",
                "public before\nprefix [redacted:private key] public suffix\npublic-looking tail\n",
            ),
            (
                "public before\nprefix -----BEGIN PRIVATE KEY----- SYNTHETIC_BODY -----END PRIVATE KEY------SYNTHETIC_PRIVATE_TAIL\npublic-looking tail\n",
                "public before\nprefix [redacted:private key]\n",
            ),
            (
                "public before\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC_BODY -----END PRIVATE KEY----- inline suffix\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
            (
                "public before\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC_BODY -----END PRIVATE KEY----- inline suffix\n \t-----END PRIVATE KEY-----\t \r\npublic after\n",
                "public before\n[redacted:private key]\npublic after\n",
            ),
            (
                "public before\n-----BEGIN PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_BODY\n-----END RSA PRIVATE KEY-----\n-----END PRIVATE KEY-----\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
            (
                "public before\n-----BEGIN PRIVATE KEY----- -----BEGIN PUBLIC KEY-----\nSYNTHETIC_BODY\n-----END PRIVATE KEY-----\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
            (
                "public before\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC_OUTER\n-----BEGIN RSA PRIVATE KEY----- -----BEGIN PUBLIC KEY-----\nSYNTHETIC_BODY\n-----END RSA PRIVATE KEY-----\n-----END PRIVATE KEY-----\npublic-looking tail\n",
                "public before\n[redacted:private key]\n",
            ),
        ];
        for (input, expected) in cases {
            let clean = redact_secret_values(input);
            assert!(!clean.contains("SYNTHETIC_"));
            assert!(!clean.contains("-----END"));
            assert!(!clean.contains("inline suffix"));
            assert_eq!(clean, expected, "input: {input:?}");
            assert_eq!(display_safe(input).unwrap(), expected);
        }
    }

    #[test]
    fn non_private_pem_and_end_markers_outside_a_block_remain_ordinary_text() {
        for newline in ["\n", "\r\n"] {
            for label in ["PUBLIC KEY", "CERTIFICATE", "EXPERIMENTAL DATA"] {
                let input = format!(
                    "public before{newline}-----BEGIN {label}-----{newline}PUBLIC_SYNTHETIC_BODY{newline}-----END {label}-----{newline}-----END PRIVATE KEY-----{newline}public after{newline}"
                );
                assert_eq!(redact_secret_values(&input), input);
                assert_eq!(display_safe(&input).unwrap(), input.replace('\r', ""));
            }
            let token = "sk-a1B2c3D4e5F6g7H8";
            let input = format!(
                "-----BEGIN PUBLIC KEY-----{newline}{token}{newline}-----END PUBLIC KEY-----{newline}"
            );
            let expected = format!(
                "-----BEGIN PUBLIC KEY-----{newline}[redacted:api token]{newline}-----END PUBLIC KEY-----{newline}"
            );
            assert!(!redact_secret_values(&input).contains(token));
            assert_eq!(redact_secret_values(&input), expected);
            assert_eq!(display_safe(&input).unwrap(), expected.replace('\r', ""));
        }
    }
}
