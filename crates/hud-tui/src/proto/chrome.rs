//! The screen chrome the .md adds beyond panels: the composer hint
//! row with keycap chips and toasts (§9.13), the command palette
//! (§9.19), the help overlay (§9.20), the quit card (§9.21), the
//! size notice (§9.23) and the inline `/` completion list (§9.13).
//!
//! Every overlay is instant (M7): no animation opens or closes one.

use super::comps;
use super::core::Token;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};

/// A keycap chip (§6.15 style): surface2 fill, ink bold letters.
/// Mono tier brackets it — handled by the caller's tier.
fn keycap(key: &str) -> Span<'static> {
    Span::styled(
        format!(" {key} "),
        Style::default()
            .fg(comps::colour(Token::Ink))
            .bg(comps::colour(Token::Panel))
            .add_modifier(Modifier::BOLD),
    )
}

/// One hint: keycap + label.
fn hint(key: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        keycap(key),
        Span::raw(" "),
        Span::styled(
            label.to_string(),
            Style::default().fg(comps::colour(Token::Muted)),
        ),
        Span::raw("   "),
    ]
}

/// The hint row (§9.13): keycaps + one context hint, toast at the
/// right end.
pub fn hint_row(
    turn_live: bool,
    transcript_tall: bool,
    toast: Option<&str>,
    width: u16,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    if turn_live {
        spans.extend(hint("⏎", "queue"));
        spans.extend(hint("⇧⏎", "newline"));
    } else {
        spans.extend(hint("⏎", "send"));
        spans.extend(hint("⇧⏎", "newline"));
        spans.extend(hint("/", "commands"));
    }
    // One context hint, first that applies. (Single-view layouts
    // show `tab views`; we always have multiple panes, so history /
    // scroll.)
    if transcript_tall {
        spans.extend(hint("pgup", "scroll"));
    }
    let mut line = Line::from(spans);
    // The toast rides the right end, ending at the last column.
    if let Some(t) = toast {
        let used: u16 = line.width() as u16;
        let tw = t.chars().count() as u16 + 2;
        if used + tw <= width {
            let mut spans: Vec<Span> = line.spans;
            spans.push(Span::raw(" ".repeat((width - used - tw) as usize)));
            spans.push(Span::styled(
                format!("✓ {t}"),
                Style::default().fg(comps::colour(Token::Green)),
            ));
            line = Line::from(spans);
        }
    }
    line
}

/// The completion list's commands (§9.13), alphabetical.
pub const COMMANDS: [(&str, &str); 7] = [
    (
        "/clear",
        "forget earlier turns (the model stops seeing them)",
    ),
    ("/help", "keys and commands"),
    ("/model", "switch the model for this session"),
    ("/models", "list models from configured providers"),
    ("/resume", "continue a saved session by id"),
    ("/sessions", "browse and resume earlier sessions"),
    ("/usage", "turns, tokens and cost for this session"),
];

/// The inline completion list above the composer (§9.13).
pub fn completion_list(typed: &str, selected: usize) -> (Rect, Vec<Line<'static>>) {
    let prefix = typed.trim_start_matches('/');
    let matches: Vec<&(&str, &str)> = COMMANDS
        .iter()
        .filter(|(c, _)| c.trim_start_matches('/').starts_with(prefix))
        .take(6)
        .collect();
    let lines: Vec<Line> = std::iter::once(Line::from(Span::styled(
        "Commands",
        Style::default().fg(comps::colour(Token::Muted)),
    )))
    .chain(matches.iter().enumerate().map(|(i, (cmd, desc))| {
        let is_sel = i == selected;
        let cmd_span = if is_sel {
            Span::styled(
                cmd.to_string(),
                Style::default()
                    .fg(comps::colour(Token::Ink))
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                cmd.to_string(),
                Style::default().fg(comps::colour(Token::Muted)),
            )
        };
        Line::from(vec![
            if is_sel {
                Span::styled("▌ ", Style::default().fg(comps::colour(Token::Magenta)))
            } else {
                Span::raw("  ")
            },
            cmd_span,
            Span::raw("  "),
            Span::styled(
                desc.to_string(),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ])
    }))
    .collect();
    let h = lines.len() as u16 + 2;
    (
        Rect {
            x: 0,
            y: 0,
            width: 60,
            height: h,
        },
        lines,
    )
}

/// The palette's frame (§9.19).
pub fn palette_area(screen: Rect) -> Rect {
    let w = 78.min(screen.width.saturating_sub(8));
    let h = 17.min(screen.height.saturating_sub(10)).max(8);
    Rect {
        x: screen.x + (screen.width - w) / 2,
        y: screen.y + 5,
        width: w,
        height: h,
    }
}

/// The palette: query row, COMMANDS section, fuzzy-matched rows.
pub fn palette_lines(query: &str, selected: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "› ",
                Style::default()
                    .fg(comps::colour(Token::Magenta))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                query.to_string(),
                Style::default().fg(comps::colour(Token::Ink)),
            ),
        ]),
        Line::from(Span::styled(
            "─".repeat(74),
            Style::default().fg(comps::colour(Token::Rule)),
        )),
        Line::from(Span::styled(
            "COMMANDS",
            Style::default().fg(comps::colour(Token::Muted)),
        )),
    ];
    let matched: Vec<&(&str, &str)> = COMMANDS
        .iter()
        .filter(|(c, _)| subsequence(query, c))
        .collect();
    if matched.is_empty() {
        lines.push(Line::from(Span::styled(
            "no matches",
            Style::default().fg(comps::colour(Token::Muted)),
        )));
    } else {
        for (i, (cmd, desc)) in matched.iter().enumerate() {
            let is_sel = i == selected % matched.len().max(1);
            lines.push(palette_row(cmd, desc, is_sel));
        }
    }
    lines
}

/// Case-insensitive subsequence match (the palette's rule).
pub fn subsequence(query: &str, target: &str) -> bool {
    let mut qi = query.chars().flat_map(|c| c.to_lowercase());
    let mut ti = target.chars().flat_map(|c| c.to_lowercase());
    loop {
        match (qi.next(), ti.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(q), Some(t)) => {
                if q == t {
                    continue;
                }
                // skip target chars until a match
                let mut found = false;
                for t2 in ti.by_ref() {
                    if t2 == q {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return false;
                }
            }
        }
    }
}

fn palette_row(cmd: &str, desc: &str, selected: bool) -> Line<'static> {
    let cmd_style = if selected {
        Style::default()
            .fg(comps::colour(Token::Ink))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(comps::colour(Token::Muted))
    };
    Line::from(vec![
        if selected {
            Span::styled("▌", Style::default().fg(comps::colour(Token::Magenta)))
        } else {
            Span::raw(" ")
        },
        Span::raw("  "),
        Span::styled(cmd.to_string(), cmd_style),
        Span::raw(" ".repeat(22usize.saturating_sub(cmd.chars().count()))),
        Span::styled(
            desc.to_string(),
            Style::default().fg(comps::colour(Token::Muted)),
        ),
    ])
}

/// The help overlay's content (§9.20): two columns of groups.
pub fn help_lines() -> Vec<Line<'static>> {
    // The help overlay (§9.20), per the golden: two columns of
    // groups — ANYWHERE, OUTSIDE THE COMPOSER, APPROVAL left;
    // IN THE COMPOSER right.
    let label = |t: &str| {
        Span::styled(
            t.to_string(),
            Style::default().fg(comps::colour(Token::Muted)),
        )
    };
    let key = |k: &str| {
        Span::styled(
            format!("{k:<11}"),
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(ratatui::style::Modifier::BOLD),
        )
    };
    let key2 = |k: &str| {
        Span::styled(
            format!("{k:<11}"),
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(ratatui::style::Modifier::BOLD),
        )
    };
    let desc = |d: &str| {
        Span::styled(
            d.to_string(),
            Style::default().fg(comps::colour(Token::Muted)),
        )
    };
    let left: Vec<(&str, &str)> = vec![
        ("ANYWHERE", ""),
        ("tab  ⇧tab", "next / previous pane"),
        ("ctrl-c ×2", "quit now"),
        ("", ""),
        ("OUTSIDE THE COMPOSER", ""),
        ("1  2  3", "jump to a pane"),
        ("/", "command palette"),
        ("?", "this help"),
        ("z y", "transcript as plain text"),
        ("z t", "last tool's detail"),
        ("g s  g v", "sessions / activity tab"),
        ("q", "quit"),
        ("", ""),
        ("APPROVAL", ""),
        ("y", "allow once"),
        ("R", "allow tool for session"),
        ("n  esc", "deny"),
    ];
    let right: Vec<(&str, &str)> = vec![
        ("IN THE COMPOSER", ""),
        ("⏎", "send; queues while busy"),
        ("⇧⏎  alt+⏎", "new line"),
        ("↑  ↓", "history"),
        ("pgup  pgdn", "scroll the transcript"),
        ("end", "newest line (if empty)"),
    ];
    let rows = left.len().max(right.len());
    let mut out = Vec::new();
    for r in 0..rows {
        let (lk, ld) = left.get(r).copied().unwrap_or(("", ""));
        let (rk, rd) = right.get(r).copied().unwrap_or(("", ""));
        let mut spans: Vec<Span> = Vec::new();
        if !lk.is_empty() && ld.is_empty() {
            spans.push(label(lk));
        } else if !lk.is_empty() {
            spans.push(key(lk));
            spans.push(desc(ld));
        }
        while spans.iter().map(|s| s.width() as u16).sum::<u16>() < 39 {
            spans.push(Span::raw(" "));
        }
        if !rk.is_empty() && rd.is_empty() {
            spans.push(label(rk));
        } else if !rk.is_empty() {
            spans.push(key2(rk));
            spans.push(desc(rd));
        }
        out.push(Line::from(spans));
    }
    out
}

/// The help overlay's frame.
pub fn help_area(screen: Rect) -> Rect {
    let w = 78.min(screen.width.saturating_sub(8));
    let h = (help_lines().len() as u16 + 2).min(screen.height.saturating_sub(4));
    Rect {
        x: screen.x + (screen.width - w) / 2,
        y: screen.y + 3,
        width: w,
        height: h,
    }
}

/// The quit card (§9.21).
pub fn quit_card(turn_running: bool, screen: Rect) -> (Rect, Vec<Line<'static>>) {
    let lines = if turn_running {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "A turn is running. Quitting stops it.",
                Style::default().fg(comps::colour(Token::Amber)),
            )),
            Line::from(""),
            quit_keys(),
        ]
    } else {
        vec![Line::from(""), quit_keys()]
    };
    let h = lines.len() as u16 + 2;
    let w = 46u16.min(screen.width.saturating_sub(4));
    (
        Rect {
            x: screen.x + (screen.width - w) / 2,
            y: screen.y + 2,
            width: w,
            height: h.min(screen.height.saturating_sub(5)),
        },
        lines,
    )
}

fn quit_keys() -> Line<'static> {
    Line::from(vec![
        keycap("y"),
        Span::raw(" "),
        Span::styled("quit", Style::default().fg(comps::colour(Token::Muted))),
        Span::raw("    "),
        keycap("n"),
        Span::raw(" "),
        Span::styled("stay", Style::default().fg(comps::colour(Token::Muted))),
    ])
}

/// The size notice (§9.23): below 40 × 10 this is the whole screen.
pub fn size_notice_lines(w: u16, h: u16) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "ORBIT needs at least 40 × 10",
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("this terminal is {w} × {h}"),
            Style::default().fg(comps::colour(Token::Muted)),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "enlarge the window or run",
            Style::default().fg(comps::colour(Token::Muted)),
        )),
        Line::from(Span::styled(
            "orbit chat --no-tui",
            Style::default().fg(comps::colour(Token::Ink)),
        )),
    ]
}

/// Render an overlay frame (palette / help / quit) with its title.
pub fn overlay(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    footer: Option<&str>,
) {
    f.render_widget(Clear, area);
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(comps::colour(Token::Rule)))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(Modifier::BOLD),
        ));
    if let Some(ft) = footer {
        block = block.title_bottom(Span::styled(
            format!(" {ft} "),
            Style::default().fg(comps::colour(Token::Muted)),
        ));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsequence_matches_case_insensitive() {
        assert!(subsequence("md", "/model"));
        assert!(subsequence("", "/model"));
        assert!(!subsequence("zzz", "/model"));
    }

    #[test]
    fn hint_row_shows_queue_while_live() {
        let idle = hint_row(false, false, None, 80);
        let live = hint_row(true, false, None, 80);
        let txt = |l: &Line| {
            l.spans
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>()
        };
        assert!(txt(&idle).contains("send"));
        assert!(txt(&live).contains("queue"));
    }

    #[test]
    fn hint_row_toast_rides_right() {
        let l = hint_row(false, false, Some("resent your last prompt"), 100);
        let txt: String = l.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(txt.contains("✓ resent your last prompt"));
    }

    #[test]
    fn palette_fuzzy_matches() {
        let lines = palette_lines("md", 0);
        let txt: String = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect::<String>();
        assert!(txt.contains("/model"));
        assert!(txt.contains("/models"));
        assert!(!txt.contains("/clear"));
    }

    #[test]
    fn quit_card_grows_when_turn_running() {
        let screen = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        let (_, idle) = quit_card(false, screen);
        let (_, live) = quit_card(true, screen);
        assert!(live.len() == idle.len() + 2);
    }
}
