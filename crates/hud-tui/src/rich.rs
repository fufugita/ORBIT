//! Rich text rendering for the conversation pane (DR-20 §5 polish).
//!
//! A small, deterministic terminal-safe renderer for the subset of Markdown
//! ORBIT surfaces to the model's plain-text responses. Uses theme colors.

use crate::theme::ResolvedTheme;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

/// Render one line into styled spans using theme colors.
pub fn render_line<'a>(text: &'a str, theme: &ResolvedTheme) -> Line<'a> {
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

fn inline_code_line<'a>(text: &'a str, theme: &ResolvedTheme) -> Line<'a> {
    let c = &theme.colors;
    let mut spans: Vec<Span> = Vec::new();
    let mut cur = String::new();
    let mut in_code = false;
    for ch in text.chars() {
        if ch == '`' {
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
            cur.push(ch);
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
    fn code_with_no_lang() {
        let theme = test_theme();
        let line = render_line("```", &theme);
        assert_eq!(span_text(&line), "── code ──");
    }
}
