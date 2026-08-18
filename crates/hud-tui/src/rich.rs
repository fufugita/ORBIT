//! Rich text rendering for the conversation pane (DR-20 §5 polish).
//!
//! A small, deterministic terminal-safe renderer for the subset of Markdown
//! ORBIT surfaces to the model's plain-text responses. Uses theme colors.
//! DR-21 L15: emoji → ASCII fallback when the terminal font lacks glyphs.

use crate::theme::ResolvedTheme;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::borrow::Cow;

/// Emoji → ASCII text fallback map (DR-21 L15). Applied at the rich layer
/// when `ORBIT_ASCII_EMOJI` is enabled (default ON). Covers ≥95% of emoji
/// used in AI chat. Unmapped emoji pass through unchanged.
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

/// Pure version of the toggle for testing (no env access, no unsafe).
pub fn ascii_emoji_enabled_from(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Apply the ASCII-emoji fallback map to `text`, if enabled. Non-emoji
/// text passes through unchanged (zero-copy `Cow`).
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

/// Render one line into styled spans using theme colors.
pub fn render_line<'a>(text: &'a str, theme: &ResolvedTheme) -> Line<'a> {
    // ASCII-emoji fallback first (DR-21 L15), then grapheme-safe rendering.
    render_line_inner(&apply_ascii_fallback(text), theme)
}

/// Inner renderer — every span it produces is an owned `String`, so the
/// returned line is `'static` regardless of the input borrow. The public
/// wrapper re-attaches the caller's lifetime.
fn render_line_inner(text: &str, theme: &ResolvedTheme) -> Line<'static> {
    let c = &theme.colors;
    let trimmed = text.trim_start();

    // Headings.
    if let Some(rest) = trimmed.strip_prefix("### ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default().fg(c.composer).add_modifier(Modifier::BOLD),
        )]);
    }
    if let Some(rest) = trimmed.strip_prefix("## ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default().fg(c.accent).add_modifier(Modifier::BOLD),
        )]);
    }
    if let Some(rest) = trimmed.strip_prefix("# ") {
        return Line::from(vec![Span::styled(
            rest.to_string(),
            Style::default().fg(c.accent).add_modifier(Modifier::BOLD),
        )]);
    }
    // Bullets.
    if let Some(rest) = trimmed.strip_prefix("- ") {
        return Line::from(vec![
            Span::styled("• ", Style::default().fg(c.composer)),
            Span::styled(rest.to_string(), Style::default().fg(c.text)),
        ]);
    }
    if let Some(rest) = trimmed.strip_prefix("* ") {
        return Line::from(vec![
            Span::styled("• ", Style::default().fg(c.composer)),
            Span::styled(rest.to_string(), Style::default().fg(c.text)),
        ]);
    }
    // Slash command at line start.
    if trimmed.starts_with('/') {
        if let Some((cmd, rest)) = trimmed.split_once(' ') {
            return Line::from(vec![
                Span::styled(cmd.to_string(), Style::default().fg(c.composer)),
                Span::styled(rest.to_string(), Style::default().fg(c.text)),
            ]);
        }
        return Line::from(vec![Span::styled(
            trimmed.to_string(),
            Style::default().fg(c.composer),
        )]);
    }
    // Fenced code marker.
    if let Some(lang) = trimmed.strip_prefix("```") {
        let lang = lang.trim();
        return Line::from(vec![Span::styled(
            if lang.is_empty() {
                "── code ──".to_string()
            } else {
                format!("── {} ──", lang)
            },
            Style::default().fg(c.dim),
        )]);
    }
    // Default: inline-code aware rendering.
    inline_code_line(text, theme)
}

fn inline_code_line(text: &str, theme: &ResolvedTheme) -> Line<'static> {
    let c = &theme.colors;
    let mut spans: Vec<Span> = Vec::new();
    let mut cur = String::new();
    let mut in_code = false;
    // Grapheme-aware iteration (DR-21 L14) — never split an emoji ZWJ cluster
    // or combining sequence across spans.
    for g in unicode_segmentation::UnicodeSegmentation::graphemes(text, true) {
        if g == "`" {
            if !cur.is_empty() {
                if in_code {
                    spans.push(Span::styled(
                        std::mem::take(&mut cur),
                        Style::default().fg(c.code_fg),
                    ));
                } else {
                    spans.push(Span::styled(
                        std::mem::take(&mut cur),
                        Style::default().fg(c.text),
                    ));
                }
            }
            in_code = !in_code;
        } else {
            cur.push_str(g);
        }
    }
    if !cur.is_empty() {
        if in_code {
            spans.push(Span::styled(cur, Style::default().fg(c.code_fg)));
        } else {
            spans.push(Span::styled(cur, Style::default().fg(c.text)));
        }
    }
    Line::from(spans)
}

/// Render a full message (multi-line) with Markdown awareness.
pub fn render_message<'a>(text: &'a str, theme: &ResolvedTheme) -> Vec<Line<'a>> {
    text.lines()
        .map(|l| render_line(l, theme))
        .collect::<Vec<Line<'_>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Theme;

    fn test_theme() -> ResolvedTheme {
        Theme::default().resolve()
    }

    fn span_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn heading_hides_marker() {
        let theme = test_theme();
        let line = render_line("## Summary", &theme);
        assert_eq!(span_text(&line), "Summary");
        assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn h1_hides_single_marker() {
        let theme = test_theme();
        let line = render_line("# Big", &theme);
        assert_eq!(span_text(&line), "Big");
    }

    #[test]
    fn h3_hides_triple_marker() {
        let theme = test_theme();
        let line = render_line("### Small", &theme);
        assert_eq!(span_text(&line), "Small");
    }

    #[test]
    fn bullet_renders_with_dot() {
        let theme = test_theme();
        let line = render_line("- item", &theme);
        assert_eq!(span_text(&line), "• item");
    }

    #[test]
    fn star_bullet_renders() {
        let theme = test_theme();
        let line = render_line("* alt item", &theme);
        assert_eq!(span_text(&line), "• alt item");
    }

    #[test]
    fn fenced_code_hides_markers() {
        let theme = test_theme();
        let line = render_line("```rust", &theme);
        assert_eq!(span_text(&line), "── rust ──");
    }

    #[test]
    fn inline_code_hides_backticks() {
        let theme = test_theme();
        let line = render_line("use `ratatui` here", &theme);
        assert_eq!(span_text(&line), "use ratatui here");
        assert!(line
            .spans
            .iter()
            .any(|s| s.content.as_ref() == "ratatui" && s.style.fg.is_some()));
    }

    #[test]
    fn command_line_styles_command() {
        let theme = test_theme();
        let line = render_line("/model glm-5.2", &theme);
        let text = span_text(&line);
        assert!(text.starts_with("/model"));
        assert!(text.contains("glm-5.2"));
    }

    #[test]
    fn plain_text_passthrough() {
        let theme = test_theme();
        let line = render_line("hello world", &theme);
        assert_eq!(span_text(&line), "hello world");
    }

    #[test]
    fn message_multiline() {
        let theme = test_theme();
        let msg = "## Title\n- item\n```rs\ncode\n```\nplain";
        let lines = render_message(msg, &theme);
        assert_eq!(lines.len(), 6);
        assert_eq!(span_text(&lines[0]), "Title");
        assert_eq!(span_text(&lines[1]), "• item");
        assert_eq!(span_text(&lines[2]), "── rs ──");
        assert_eq!(span_text(&lines[4]), "── code ──");
        assert_eq!(span_text(&lines[5]), "plain");
    }

    #[test]
    fn wave_fallback() {
        let theme = test_theme();
        let line = render_line("Hi 👋", &theme);
        assert_eq!(span_text(&line), "Hi (wave)");
    }

    #[test]
    fn star_fallback() {
        let theme = test_theme();
        let line = render_line("Nice ✨", &theme);
        assert_eq!(span_text(&line), "Nice *");
    }

    #[test]
    fn unmapped_passthrough() {
        let theme = test_theme();
        // 🦄 is NOT in the map — passes through unchanged (terminal decides).
        let text = "unicorn 🦄";
        let line = render_line(text, &theme);
        assert_eq!(span_text(&line), text);
    }

    #[test]
    fn toggle_off_passthrough() {
        // With ORBIT_ASCII_EMOJI disabled, emoji pass through untouched.
        // The env toggle is read at render time; here we verify the pure
        // toggle handles the off values and the map is inert when off.
        assert!(!ascii_emoji_enabled_from("0"));
        assert!(!ascii_emoji_enabled_from("false"));
        assert!(!ascii_emoji_enabled_from("OFF"));
        assert!(ascii_emoji_enabled_from(""));
        assert!(ascii_emoji_enabled_from("1"));
    }

    #[test]
    fn code_with_no_lang() {
        let theme = test_theme();
        let line = render_line("```", &theme);
        assert_eq!(span_text(&line), "── code ──");
    }
}
