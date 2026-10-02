//! Value-based secret detection (replaces keyword rejection).
//!
//! The old display gate rejected any chunk containing the WORD
//! `authorization` or `api_key` — which blanks ordinary code and every
//! URL while passing a real key that lacks those words. This module
//! detects key SHAPES instead:
//!
//! - PEM private-key blocks (`-----BEGIN ... PRIVATE KEY-----`)
//! - Known token formats: `sk-...` (OpenAI-style), `ghp_`/`gho_`
//!   (GitHub), `AKIA...` (AWS access key id), `xoxb-`/`xoxp-` (Slack)
//! - High-entropy assignments: `secret = <40+ char base62>` style
//!
//! `scan_text` returns a reason when the text carries a secret VALUE.
//! Callers redact or refuse — they keep the line, never the value.

/// True when the text carries a secret value. Returns a short reason.
pub fn scan_text(text: &str) -> Option<String> {
    // 1. PEM private-key blocks — the strongest signal there is.
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        return Some("private key block".into());
    }
    // 2. Known token formats by prefix + plausible length.
    for line in text.lines() {
        let t = line.trim();
        for (prefix, min_len, what) in [
            ("sk-", 20, "api token"),
            ("ghp_", 20, "github token"),
            ("gho_", 20, "github token"),
            ("github_pat_", 30, "github token"),
            ("AKIA", 16, "aws access key"),
            ("xoxb-", 20, "slack token"),
            ("xoxp-", 20, "slack token"),
        ] {
            if let Some(rest) = t.find(prefix).map(|i| &t[i + prefix.len()..]) {
                let body: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .collect();
                if body.chars().count() >= min_len {
                    return Some(format!("{what} ({prefix}…)"));
                }
            }
        }
        // 3. High-entropy assignments: `KEY = <long base62 value>`.
        if let Some((k, v)) = t.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            let k_up = k.trim().to_uppercase();
            let looks_secret = k_up.contains("SECRET")
                || k_up.contains("TOKEN")
                || k_up.contains("PASSWORD")
                || k_up.contains("API_KEY")
                || k_up.contains("PRIVATE");
            if looks_secret && v.chars().count() >= 32 && is_high_entropy(v) {
                return Some("high-entropy secret value".into());
            }
        }
    }
    None
}

/// Shannon entropy over the char histogram; > 3.5 bits/char for a 32+
/// char base62 string is far beyond prose or code identifiers.
fn is_high_entropy(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return false;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0u32) += 1;
    }
    let n = chars.len() as f64;
    let entropy: f64 = counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    entropy > 3.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        assert!(scan_text(pem).is_some());
    }

    #[test]
    fn catches_openai_style_token() {
        assert!(scan_text("token = sk-abc123def456ghi789jkl012").is_some());
    }

    #[test]
    fn catches_aws_key() {
        assert!(scan_text("aws AKIAIOSFODNN7EXAMPLE").is_some());
    }

    #[test]
    fn catches_high_entropy_secret() {
        let v: String = "abcdefghij0123456789ABCDEFGH".repeat(2);
        assert!(scan_text(&format!("MY_SECRET = \"{v}\"")).is_some());
    }

    #[test]
    fn passes_ordinary_code() {
        // The word "authorization" in code is NOT a secret.
        assert!(scan_text("let authorization = req.headers.get(\"auth\");").is_none());
        assert!(scan_text("fn api_key_handler() {}").is_none());
    }

    #[test]
    fn passes_urls() {
        assert!(scan_text("fetch https://example.com/api/v1").is_none());
    }

    #[test]
    fn passes_low_entropy_values() {
        // "password = 12345678" is bad practice but not a leaked secret
        // value; short and low-entropy values don't trip the scanner.
        assert!(scan_text("password = \"12345678\"").is_none());
    }
}
