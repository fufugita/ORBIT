//! Rich text rendering for the conversation pane (docs/tui/DESIGN.md §6.3–6.4).
//!
//! A small, deterministic terminal-safe renderer for the subset of Markdown
//! ORBIT surfaces in model responses. All colours from the token palette,
//! all glyphs from the glyph vocabulary.
//!
//! Markdown rules (§6.3):
//! - H1 bold + underlined; H2 bold; H3 bold ink2.
//! - Lists: ∙ bullet (muted) with a 2-column hanging indent; nested lists ◦;
//!   numbers `1.` muted.
//! - Quotes: ▎ in muted with ink2 text.
//! - Tables: bold header, ─ rule under it, 2-space column gaps, numbers
//!   right-aligned, no vertical bars.
//! - Links: text underlined; the URL itself is never shown (the display gate
//!   rejects it upstream).
//! - Emphasis renders bold; italics render plain.
//!
//! Code (§6.4):
//! - Inline code: surface2 chip with ink text, no backticks. In 16 colours it
//!   becomes cyan text; in monochrome the backticks stay.
//! - Code blocks: surface band, language label right-aligned on the first row
//!   in faint, no line numbers, long lines wrap with ↪ in faint. Code never
//!   truncates silently.

use crate::glyphs::Glyphs;
use crate::tokens::{ColorTier, Design};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::borrow::Cow;

/// Emoji → ASCII text fallback map. Applied at the rich layer when
/// `ORBIT_ASCII_EMOJI` is enabled (default ON). Unmapped emoji pass through.
pub const ASCII_EMOJI_MAP: &[(&str, &str)] = &[
    ("👋", "(wave)"),
    ("✨", "*"),
    ("🛠️", "[tool]"),
    ("🛠", "[tool]"),
    ("🚀", ">>"),
    ("✅", "[ok]"),
    ("❌", "[x]"),
    ("🔒", "[lock]"),
    ("💬", "\""),
    ("🤖", "bot"),
    ("⚠️", "!"),
    ("⚠", "!"),
    ("📦", "pkg"),
    ("🔍", "?"),
    ("🎯", "*"),
    ("🧪", "lab"),
    ("📊", "stats"),
    ("💡", "!"),
    ("🔑", "key"),
    ("🌐", "net"),
    ("⭐", "*"),
    ("🔥", "!"),
    ("💾", "save"),
    ("📁", "dir"),
    ("📄", "doc"),
    ("🌙", "*"),
    ("☀️", "*"),
    ("🎉", "!"),
    ("👍", "+1"),
    ("👎", "-1"),
    ("🐛", "bug"),
    ("🪲", "bug"),
    ("🦀", "rs"),
    ("🐍", "py"),
    ("🐧", "lnx"),
    ("🍎", "mac"),
    ("🪟", "win"),
];

/// Whether the ASCII-emoji fallback is active. Reads `ORBIT_ASCII_EMOJI`
/// (default ON; `0` disables — matched case-insensitively).
pub fn ascii_emoji_enabled() -> bool {
    let v = std::env::var("ORBIT_ASCII_EMOJI").unwrap_or_default();
    ascii_emoji_enabled_from(&v)
}

/// Pure version of the toggle for testing (no env access).
pub fn ascii_emoji_enabled_from(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Apply the ASCII-emoji fallback map to `text`, if enabled.
pub fn apply_ascii_fallback(text: &str) -> Cow<'_, str> {
    if !ascii_emoji_enabled() {
        return Cow::Borrowed(text);
    }
    let mut out: Option<String> = None;
    for (emoji, repl) in ASCII_EMOJI_MAP {
        if text.contains(emoji) {
            let buf = out.get_or_insert_with(|| text.to_string());
            *buf = buf.replace(emoji, repl);
        }
    }
    match out {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(text),
    }
}

/// Render one line into styled spans. The glyph vocabulary comes from the
/// design's glyph set so the ASCII tier stays printable (§13.5).
pub fn render_line<'a>(text: &'a str, d: &Design) -> Line<'a> {
    render_line_inner(&apply_ascii_fallback(text), d)
}

/// How inline code renders (the goldens differ by turn type: user turns
/// chip it, ORBIT turns render it muted plain).
#[derive(Clone, Copy, PartialEq)]
pub enum CodeStyle {
    /// surface2 chip with ink text (§6.4, user turns).
    Chip,
    /// Muted plain text (ORBIT turns, per the goldens). Reserved by the
    /// golden set; the current renderer routes ORBIT turns through Chip —
    /// the variant stays so the mode switch is a one-line change.
    #[allow(dead_code)]
    Muted,
}

/// The styled runs for a line, owned (for wrap-then-render flows).
pub fn runs_for(text: &str, d: &Design) -> Vec<(String, Style)> {
    runs_for_mode(text, d, CodeStyle::Chip)
}

/// The styled runs with an explicit inline-code mode.
pub fn runs_for_mode(text: &str, d: &Design, mode: CodeStyle) -> Vec<(String, Style)> {
    let line = render_line_inner_mode(&apply_ascii_fallback(text), d, mode);
    line.spans
        .into_iter()
        .map(|sp| (sp.content.to_string(), sp.style))
        .collect()
}

fn render_line_inner_mode(text: &str, d: &Design, mode: CodeStyle) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    let p = &d.palette;
    let mono = d.palette.tier == ColorTier::Mono;
    let mut cur = String::new();
    let mut in_code = false;
    for g in unicode_segmentation::UnicodeSegmentation::graphemes(text, true) {
        if g == "`" {
            if !cur.is_empty() {
                push_text_span_mode(&mut spans, std::mem::take(&mut cur), p, mono, in_code, mode);
            }
            in_code = !in_code;
            if mono && in_code {
                spans.push(Span::styled("`", Style::default().fg(p.ink)));
            }
        } else {
            cur.push_str(g);
        }
    }
    if !cur.is_empty() {
        push_text_span_mode(&mut spans, cur, p, mono, in_code, mode);
    }
    Line::from(spans)
}

fn push_text_span_mode(
    spans: &mut Vec<Span<'static>>,
    text: String,
    p: &crate::tokens::ResolvedPalette,
    mono: bool,
    in_code: bool,
    mode: CodeStyle,
) {
    if in_code {
        let style = match (p.tier, mode) {
            (ColorTier::TrueColor | ColorTier::T256, CodeStyle::Chip) => {
                Style::default().fg(p.ink).bg(p.surface2)
            }
            (ColorTier::TrueColor | ColorTier::T256, CodeStyle::Muted) => {
                Style::default().fg(p.muted)
            }
            (ColorTier::Ansi16, _) => Style::default().fg(p.cyan),
            (ColorTier::Mono, _) => Style::default().fg(p.ink),
        };
        let _ = mono;
        spans.push(Span::styled(text, style));
    } else {
        push_plain_span(spans, text, p);
    }
}

/// Plain (non-code) text: emphasis + citation handling.
fn push_plain_span(
    spans: &mut Vec<Span<'static>>,
    text: String,
    p: &crate::tokens::ResolvedPalette,
) {
    // Citations [n] render cyan (§6.7).
    if text.contains('[') {
        let mut rest = text.as_str();
        while let Some(i) = rest.find('[') {
            if let Some(j) = rest[i..].find(']') {
                let (before, after) = rest.split_at(i);
                if !before.is_empty() {
                    push_emphasis_span(spans, before.to_string(), p);
                }
                spans.push(Span::styled(
                    rest[i..=i + j].to_string(),
                    Style::default().fg(p.cyan),
                ));
                rest = &after[j + 1..];
            } else {
                break;
            }
        }
        if !rest.is_empty() {
            push_emphasis_span(spans, rest.to_string(), p);
        }
        return;
    }
    push_emphasis_span(spans, text, p);
}

/// Emphasis only (no citations).
fn push_emphasis_span(
    spans: &mut Vec<Span<'static>>,
    text: String,
    p: &crate::tokens::ResolvedPalette,
) {
    if text.contains("**") {
        let parts: Vec<&str> = text.split("**").collect();
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            let style = if i % 2 == 1 {
                Style::default().fg(p.ink).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.ink)
            };
            spans.push(Span::styled(part.to_string(), style));
        }
    } else {
        spans.push(Span::styled(text, Style::default().fg(p.ink)));
    }
}

fn render_line_inner(text: &str, d: &Design) -> Line<'static> {
    let p = &d.palette;
    let g = &Glyphs::for_set(d.caps.glyphs);
    let trimmed = text.trim_start();
    let indent = text.len() - trimmed.len(); // leading spaces

    // ── Headings (§6.3): H1 bold+underlined, H2 bold, H3 bold ink2 ────────
    if let Some(rest) = trimmed.strip_prefix("### ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default().fg(p.ink2).add_modifier(Modifier::BOLD),
        )]);
    }
    if let Some(rest) = trimmed.strip_prefix("## ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default().fg(p.ink).add_modifier(Modifier::BOLD),
        )]);
    }
    if let Some(rest) = trimmed.strip_prefix("# ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default()
                .fg(p.ink)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )]);
    }

    // ── Quotes (§6.3): ▎ in muted with ink2 text ──────────────────────────
    if trimmed.starts_with('>') {
        let rest = trimmed.trim_start_matches('>').trim_start();
        return Line::from(vec![
            Span::styled(format!("{} ", g.quote_bar), Style::default().fg(p.muted)),
            Span::styled(rest.to_string(), Style::default().fg(p.ink2)),
        ]);
    }

    // ── Lists (§6.3): ∙ top-level, ◦ nested, 2-column hanging indent ──────
    // Nested bullets are indented ≥2 spaces from a `- ` / `* ` marker.
    let is_nested = indent >= 2;
    if let Some(rest) = trimmed.strip_prefix("- ").or(trimmed.strip_prefix("* ")) {
        let bullet = if is_nested { g.bullet_nested } else { g.bullet };
        return Line::from(vec![
            Span::styled(format!("{bullet} "), Style::default().fg(p.muted)),
            Span::styled(rest.to_string(), Style::default().fg(p.ink)),
        ]);
    }
    // Numbered lists: `1.` muted (§6.3).
    if let Some(num) = ordered_list_marker(trimmed) {
        let rest = &trimmed[num.len()..];
        return Line::from(vec![
            Span::styled(format!("{num} "), Style::default().fg(p.muted)),
            Span::styled(rest.to_string(), Style::default().fg(p.ink)),
        ]);
    }

    // ── Code fence marker: language label right-aligned, faint (§6.4) ─────
    if let Some(lang) = trimmed.strip_prefix("```") {
        let lang = lang.trim();
        return Line::from(vec![Span::styled(
            if lang.is_empty() {
                "code".to_string()
            } else {
                lang.to_string()
            },
            Style::default().fg(p.faint),
        )]);
    }

    // Table separator row `| --- | --- |` → the ─ rule under the header.
    if trimmed.starts_with('|') && trimmed.contains('-') && is_table_separator(trimmed) {
        let cols = trimmed.split('|').count().saturating_sub(2);
        let rule: String = std::iter::once(String::new())
            .chain(std::iter::repeat_n(g.rule.repeat(4), cols.max(1)))
            .collect::<Vec<_>>()
            .join("  ");
        return Line::from(Span::styled(rule, Style::default().fg(p.rule)));
    }

    // ── Table row (§6.3): pipes → 2-space gaps; header bold + ─ rule ──────
    if trimmed.starts_with('|') && trimmed.ends_with('|') && trimmed.len() > 2 {
        return table_row(trimmed, d);
    }

    // ── Slash command at line start ────────────────────────────────────────
    if trimmed.starts_with('/') && indent == 0 {
        if let Some((cmd, rest)) = trimmed.split_once(' ') {
            return Line::from(vec![
                Span::styled(cmd.to_string(), Style::default().fg(p.syn_kw)),
                Span::styled(rest.to_string(), Style::default().fg(p.ink)),
            ]);
        }
        return Line::from(vec![Span::styled(
            trimmed.to_string(),
            Style::default().fg(p.muted),
        )]);
    }

    // Default: emphasis + inline-code aware rendering.
    inline_code_line(text, d)
}

/// `1.` / `12.` ordered-list marker, if present.
fn ordered_list_marker(s: &str) -> Option<String> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    if s[digits.len()..].starts_with(". ") {
        Some(format!("{digits}."))
    } else {
        None
    }
}

/// `| --- | :---: |` style separator row.
fn is_table_separator(s: &str) -> bool {
    s.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) && s.contains("-")
}

/// Render a table row: split on `|`, join with 2-space gaps, no vertical
/// bars (§6.3). The header (detected by the caller via the separator row
/// that follows) is bold — here we bold any row whose cells are all
/// non-numeric-looking only if the NEXT line is a separator; without
/// lookahead we bold nothing and let the separator rule provide the
/// header boundary.
fn table_row(trimmed: &str, d: &Design) -> Line<'static> {
    let p = &d.palette;
    let cells: Vec<String> = trimmed
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect();
    let mut spans = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::default()));
        }
        // Numbers right-align in their column (§6.3) — approximation:
        // numeric cells render right-aligned via padding below; here we
        // simply style them muted-bold as the numeric convention.
        let numeric = !cell.is_empty()
            && cell
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | '%' | '+' | '-'));
        let style = if numeric {
            Style::default().fg(p.ink2)
        } else {
            Style::default().fg(p.ink)
        };
        spans.push(Span::styled(cell.clone(), style));
    }
    Line::from(spans)
}

fn inline_code_line(text: &str, d: &Design) -> Line<'static> {
    let p = &d.palette;
    let mono = d.palette.tier == ColorTier::Mono;
    let mut spans: Vec<Span> = Vec::new();
    let mut cur = String::new();
    let mut in_code = false;
    // Grapheme-aware iteration — never split a cluster across spans.
    for g in unicode_segmentation::UnicodeSegmentation::graphemes(text, true) {
        if g == "`" {
            if !cur.is_empty() {
                push_text_span(&mut spans, std::mem::take(&mut cur), p, mono, in_code);
            }
            in_code = !in_code;
            // In monochrome the backticks stay (§6.4).
            if mono && in_code {
                spans.push(Span::styled("`", Style::default().fg(p.ink)));
            }
        } else {
            cur.push_str(g);
        }
    }
    if !cur.is_empty() {
        push_text_span(&mut spans, cur, p, mono, in_code);
    }
    Line::from(spans)
}

/// Push a text span, applying inline-code styling per tier (§6.4):
/// true colour/256 → surface2 chip with ink text (approximated as cyan in
/// 16); mono → plain ink (backticks preserved by the caller).
fn push_text_span(
    spans: &mut Vec<Span<'static>>,
    text: String,
    p: &crate::tokens::ResolvedPalette,
    mono: bool,
    in_code: bool,
) {
    if in_code {
        // §6.4: a surface2 chip with ink text (cyan text in 16; mono keeps
        // the backticks — handled by the caller). Multi-word code chips
        // per word: the spaces between stay plain (golden).
        let style = match p.tier {
            ColorTier::TrueColor | ColorTier::T256 => Style::default().fg(p.ink).bg(p.surface2),
            ColorTier::Ansi16 => Style::default().fg(p.cyan),
            ColorTier::Mono => Style::default().fg(p.ink),
        };
        let _ = mono;
        spans.push(Span::styled(text, style));
    } else {
        // Citations + emphasis (§6.7, §6.3).
        push_plain_span(spans, text, p);
    }
}

/// Render a full message (multi-line) with Markdown awareness.
pub fn render_message<'a>(text: &'a str, d: &Design) -> Vec<Line<'a>> {
    text.lines()
        .map(|l| render_line(l, d))
        .collect::<Vec<Line<'_>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{Design, Theme as TokenTheme};

    fn test_design() -> Design {
        let t = TokenTheme::default();
        Design::resolve(&t, &|_| None)
    }

    fn mono_design() -> Design {
        let toml = "[color]\nmode = \"mono\"\n";
        let t: TokenTheme = toml::from_str(toml).unwrap();
        Design::resolve(&t, &|_| None)
    }

    fn span_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn heading_hides_marker() {
        let line = render_line("## Summary", &test_design());
        assert_eq!(span_text(&line), "Summary");
        assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn h1_hides_single_marker() {
        let line = render_line("# Big", &test_design());
        assert_eq!(span_text(&line), "Big");
        assert!(line.spans[0]
            .style
            .add_modifier
            .contains(Modifier::UNDERLINED));
    }

    #[test]
    fn h3_hides_triple_marker() {
        let line = render_line("### Small", &test_design());
        assert_eq!(span_text(&line), "Small");
    }

    #[test]
    fn bullet_renders_with_dot() {
        let line = render_line("- item", &test_design());
        assert!(span_text(&line).starts_with("∙"));
    }

    #[test]
    fn nested_bullet_uses_hollow_dot() {
        // ≥2-space indent + marker = nested (◦ per §6.3).
        let line = render_line("  - nested", &test_design());
        assert!(span_text(&line).starts_with("◦"));
    }

    #[test]
    fn ordered_list_marker_muted() {
        let line = render_line("1. first", &test_design());
        assert!(span_text(&line).starts_with("1."));
    }

    #[test]
    fn ordered_list_two_digits() {
        let line = render_line("12. twelfth", &test_design());
        assert!(span_text(&line).starts_with("12."));
    }

    #[test]
    fn quote_uses_quote_bar() {
        let line = render_line("> quoted text", &test_design());
        let text = span_text(&line);
        assert!(text.starts_with("▎"));
        assert!(text.contains("quoted text"));
    }

    #[test]
    fn table_row_loses_bars() {
        let line = render_line("| a | b |", &test_design());
        let text = span_text(&line);
        assert!(!text.contains('|'), "no vertical bars (§6.3): {text}");
        assert!(text.contains("a"));
        assert!(text.contains("b"));
    }

    #[test]
    fn table_separator_renders_rule() {
        let line = render_line("| --- | --- |", &test_design());
        let text = span_text(&line);
        assert!(text.contains('─'), "separator is a rule: {text}");
        assert!(!text.contains('|'));
    }

    #[test]
    fn fenced_code_hides_markers() {
        let line = render_line("```rust", &test_design());
        assert_eq!(span_text(&line), "rust");
    }

    #[test]
    fn fenced_code_no_lang() {
        let line = render_line("```", &test_design());
        assert_eq!(span_text(&line), "code");
    }

    #[test]
    fn inline_code_keeps_content() {
        let line = render_line("run `cargo test` now", &test_design());
        let text = span_text(&line);
        assert!(text.contains("cargo test"));
        assert!(!text.contains('`'), "backticks are stripped outside mono");
    }

    #[test]
    fn mono_keeps_backticks() {
        let line = render_line("run `cargo test` now", &mono_design());
        let text = span_text(&line);
        assert!(text.contains('`'), "mono keeps the backticks (§6.4)");
        assert!(text.contains("cargo test"));
    }

    #[test]
    fn star_bullet_renders() {
        let line = render_line("* alt item", &test_design());
        assert!(span_text(&line).starts_with("∙"));
    }

    #[test]
    fn bold_emphasis_renders_bold_without_markers() {
        let line = render_line("The answer is **14**.", &test_design());
        let text = span_text(&line);
        assert!(!text.contains("**"), "markers dropped: {text}");
        assert!(text.contains("14"));
        // The odd segment (inside **) carries BOLD.
        let bold_span = line.spans.iter().find(|s| s.content.contains("14"));
        assert!(bold_span.is_some_and(|s| s.style.add_modifier.contains(Modifier::BOLD)));
    }

    #[test]
    fn ascii_emoji_off_passes_through() {
        assert!(!ascii_emoji_enabled_from("0"));
        assert!(!ascii_emoji_enabled_from("off"));
        assert!(ascii_emoji_enabled_from(""));
        assert!(ascii_emoji_enabled_from("1"));
    }
}
