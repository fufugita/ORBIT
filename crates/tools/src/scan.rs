//! The secret scanner — value detection, not keyword rejection
//! (defect fix #4, applied to every tool result and request).
//!
//! Detects private key blocks, known key formats, and high-entropy
//! tokens. Redacts the VALUE, keeps the line, and reports what was
//! redacted — the old keyword gate rejected whole chunks containing
//! "authorization" while passing a real key that lacked the word.

/// A scan outcome: possibly-redacted text + what was redacted.
#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub text: String,
    pub redactions: Vec<String>,
}

/// Known token formats (prefix → label).
const KEY_FORMATS: &[(&str, &str)] = &[
    ("sk-", "api token"),
    ("sk-ant-", "anthropic token"),
    ("ghp_", "github token"),
    ("gho_", "github token"),
    ("github_pat_", "github token"),
    ("AKIA", "aws access key"),
    ("ASIA", "aws temp key"),
    ("xoxb-", "slack token"),
    ("xoxp-", "slack token"),
    ("AIza", "google api key"),
];

/// Scan and redact. PEM private-key blocks collapse to a marker; known
/// key formats redact the token; high-entropy assignments (>= 32 chars
/// of mixed-case/digits) redact the value.
pub fn scan_result(text: &str) -> ScanOutcome {
    let mut out = ScanOutcome {
        text: String::new(),
        redactions: Vec::new(),
    };
    let mut in_pem = false;
    for line in text.split_inclusive('\n') {
        // PEM block: redact the whole block content.
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
            in_pem = true;
            out.text.push_str("[redacted:private key]\n");
            out.redactions.push("private key block".into());
            continue;
        }
        if in_pem {
            if line.contains("-----END") {
                in_pem = false;
            }
            continue; // drop body lines
        }
        let mut line = line.to_string();
        for (prefix, what) in KEY_FORMATS {
            if let Some(pos) = line.find(prefix) {
                let end = line[pos..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                    .map(|i| pos + i)
                    .unwrap_or(line.len());
                // Real tokens are long; short hits are ordinary words.
                if end - pos >= prefix.len() + 16 {
                    line = format!("{}[redacted:{}]{}", &line[..pos], what, &line[end..]);
                    out.redactions.push((*what).into());
                }
            }
        }
        // High-entropy assignments: KEY = <long value> or KEY: <value>
        if let Some(redacted_line) = scan_assignment(&line) {
            out.redactions.push("secret assignment".into());
            out.text.push_str(&redacted_line);
            continue;
        }
        out.text.push_str(&line);
    }
    out
}

/// KEY = value / KEY: value where the key looks secret and the value
/// is long and high-entropy.
fn scan_assignment(line: &str) -> Option<String> {
    let sep = line.find('=').or_else(|| line.find(':'))?;
    let (k, _) = line.split_at(sep);
    let key_up = k.trim().to_uppercase();
    let looks_secret = key_up.contains("SECRET")
        || key_up.contains("TOKEN")
        || key_up.contains("PASSWORD")
        || key_up.contains("API_KEY")
        || key_up.contains("PRIVATE");
    if !looks_secret {
        return None;
    }
    let value = line[sep + 1..].trim();
    let value = value.trim_matches('"').trim_matches('\'');
    if value.chars().count() < 32 {
        return None;
    }
    if entropy_bits(value) > 3.5 {
        Some(format!("{}= [redacted:secret]\n", k.trim()))
    } else {
        None
    }
}

/// Shannon entropy per character, in bits.
fn entropy_bits(s: &str) -> f64 {
    let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let total = s.chars().count() as f64;
    if total == 0.0 {
        return 0.0;
    }
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_block_redacted() {
        let input = "prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\nsuffix";
        let out = scan_result(input);
        assert!(out.text.contains("[redacted:private key]"));
        assert!(!out.text.contains("MIIEow"));
        assert!(out.text.contains("suffix"));
    }

    #[test]
    fn known_token_redacted_line_kept() {
        let input = "the key is sk-abcdefghijklmnopqrstuvwxyz123456 and more";
        let out = scan_result(input);
        assert!(out.text.contains("[redacted:api token]"));
        assert!(!out.text.contains("abcdefghijklmnopqrstuvwxyz123456"));
        assert!(out.text.contains("the key is"));
        assert!(out.text.contains("and more"));
    }

    #[test]
    fn short_prefix_hit_not_redacted() {
        // "sk-something" under the length threshold stays (ordinary text).
        let input = "the sk-short word stays";
        let out = scan_result(input);
        assert!(out.text.contains("sk-short"));
    }

    #[test]
    fn secret_assignment_redacted() {
        let input = "API_KEY = aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH";
        let out = scan_result(input);
        assert!(out.text.contains("[redacted:secret]"));
        assert!(!out.text.contains("aBcDeFgHiJkLmNoPqRsTuVwXyZ"));
    }

    #[test]
    fn normal_code_untouched() {
        let input = "let x = authorization_header.clone();\nfn main() {}";
        let out = scan_result(input);
        assert_eq!(out.text, input);
        assert!(out.redactions.is_empty());
    }

    #[test]
    fn urls_untouched() {
        let input = "fetch https://example.com/path?query=1";
        let out = scan_result(input);
        assert_eq!(out.text, input);
    }
}
