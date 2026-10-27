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
fn keycap_themed(colors: crate::proto::shell::pal::Palette, key: &str) -> Span<'static> {
    Span::styled(
        format!(" {key} "),
        Style::default()
            .fg(comps::colour_themed(colors, Token::Ink))
            .bg(comps::colour_themed(colors, Token::Panel))
            .add_modifier(Modifier::BOLD),
    )
}

/// One hint: keycap + label.
fn hint_themed(
    colors: crate::proto::shell::pal::Palette,
    key: &str,
    label: &str,
) -> Vec<Span<'static>> {
    vec![
        keycap_themed(colors, key),
        Span::raw(" "),
        Span::styled(
            label.to_string(),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        ),
        Span::raw("   "),
    ]
}

/// The hint row (§9.13): keycaps + one context hint, toast at the
/// right end.
pub fn hint_row_themed(
    colors: crate::proto::shell::pal::Palette,
    turn_live: bool,
    transcript_tall: bool,
    toast: Option<&str>,
    width: u16,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    if turn_live {
        spans.extend(hint_themed(colors, "⏎", "queue"));
        spans.extend(hint_themed(colors, "⇧⏎", "newline"));
    } else {
        spans.extend(hint_themed(colors, "⏎", "send"));
        spans.extend(hint_themed(colors, "⇧⏎", "newline"));
        spans.extend(hint_themed(colors, "/", "commands"));
    }
    // One context hint, first that applies. (Single-view layouts
    // show `tab views`; we always have multiple panes, so history /
    // scroll.)
    if transcript_tall {
        spans.extend(hint_themed(colors, "pgup", "scroll"));
    }
    let mut line = Line::from(spans);
    // The toast rides the right end, ending at the last column.
    if let Some(t) = toast {
        let used = line.width();
        let rendered_toast = format!("✓ {t}");
        let tw = super::shell::canvas::text_width(&rendered_toast).max(0) as usize;
        if used.saturating_add(tw) <= width as usize {
            let mut spans: Vec<Span> = line.spans;
            spans.push(Span::raw(" ".repeat(width as usize - used - tw)));
            spans.push(Span::styled(
                rendered_toast,
                Style::default().fg(comps::colour_themed(colors, Token::Green)),
            ));
            line = Line::from(spans);
        }
    }
    line
}

/// The completion list's stable built-in order, extended with customization and routing.
pub const COMMANDS: [(&str, &str); 16] = [
    (
        "/clear",
        "forget earlier turns (the model stops seeing them)",
    ),
    (
        "/compact",
        "summarize the conversation into one summary message",
    ),
    (
        "/effort",
        "show or set configured request effort; default restores the model default",
    ),
    ("/help", "keys and commands"),
    (
        "/mode",
        "set the permission mode (default, acceptEdits, plan, dontAsk, bypass)",
    ),
    ("/model", "switch the model for this session"),
    ("/models", "list models from configured providers"),
    (
        "/permissions",
        "effective rules and sources; allow, ask, deny or reset a tool/server rule",
    ),
    ("/resume", "continue a saved session by id"),
    (
        "/rewind",
        "list checkpoints, or restore files to one: /rewind <id>",
    ),
    ("/sessions", "browse and resume earlier sessions"),
    ("/undo", "drop the last exchange from the context"),
    ("/usage", "turns, tokens and cost for this session"),
    (
        "/customize",
        "show, validate, import, export, set, reset or reload customization",
    ),
    (
        "/route",
        "show routing; auto restores automatic model selection",
    ),
    ("/theme", "show or choose orbit, midnight or paper"),
];

/// The commands the inline list offers for what is typed: every one
/// whose name starts with it (§9.13). The list shows a window of them
/// that follows the selection, so none is out of reach.
pub fn completion_matches(typed: &str) -> Vec<(&'static str, &'static str)> {
    let prefix = typed.trim_start_matches('/');
    COMMANDS
        .iter()
        .filter(|(c, _)| c.trim_start_matches('/').starts_with(prefix))
        .copied()
        .collect()
}

/// Rows the `/` list shows at once.
pub const COMPLETION_ROWS: usize = 6;

/// The `/` list is open while the composer holds one command word —
/// `/`, `/he` — and closes once arguments begin or the text is not a
/// command.
pub fn slash_list(composer: &str) -> Vec<(&'static str, &'static str)> {
    if !composer.starts_with('/') || composer.contains(char::is_whitespace) {
        return Vec::new();
    }
    completion_matches(composer)
}

/// The inline completion list above the composer (§9.13).
pub fn completion_list_themed(
    colors: crate::proto::shell::pal::Palette,
    typed: &str,
    selected: usize,
) -> (Rect, Vec<Line<'static>>) {
    let prefix = typed.trim_start_matches('/');
    let matches: Vec<&(&str, &str)> = COMMANDS
        .iter()
        .filter(|(c, _)| c.trim_start_matches('/').starts_with(prefix))
        .take(6)
        .collect();
    let lines: Vec<Line> = std::iter::once(Line::from(Span::styled(
        "Commands",
        Style::default().fg(comps::colour_themed(colors, Token::Muted)),
    )))
    .chain(matches.iter().enumerate().map(|(i, (cmd, desc))| {
        let is_sel = i == selected;
        let cmd_span = if is_sel {
            Span::styled(
                cmd.to_string(),
                Style::default()
                    .fg(comps::colour_themed(colors, Token::Ink))
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                cmd.to_string(),
                Style::default().fg(comps::colour_themed(colors, Token::Muted)),
            )
        };
        Line::from(vec![
            if is_sel {
                Span::styled(
                    "▌ ",
                    Style::default().fg(comps::colour_themed(colors, Token::Magenta)),
                )
            } else {
                Span::raw("  ")
            },
            cmd_span,
            Span::raw("  "),
            Span::styled(
                desc.to_string(),
                Style::default().fg(comps::colour_themed(colors, Token::Muted)),
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
pub fn palette_lines_themed(
    colors: crate::proto::shell::pal::Palette,
    query: &str,
    selected: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "› ",
                Style::default()
                    .fg(comps::colour_themed(colors, Token::Magenta))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                query.to_string(),
                Style::default().fg(comps::colour_themed(colors, Token::Ink)),
            ),
        ]),
        Line::from(Span::styled(
            "─".repeat(74),
            Style::default().fg(comps::colour_themed(colors, Token::Rule)),
        )),
        Line::from(Span::styled(
            "COMMANDS",
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        )),
    ];
    let matched: Vec<&(&str, &str)> = COMMANDS
        .iter()
        .filter(|(c, _)| subsequence(query, c))
        .collect();
    if matched.is_empty() {
        lines.push(Line::from(Span::styled(
            "no matches",
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        )));
    } else {
        for (i, (cmd, desc)) in matched.iter().enumerate() {
            let is_sel = i == selected % matched.len().max(1);
            lines.push(palette_row_themed(colors, cmd, desc, is_sel));
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

fn palette_row_themed(
    colors: crate::proto::shell::pal::Palette,
    cmd: &str,
    desc: &str,
    selected: bool,
) -> Line<'static> {
    let cmd_style = if selected {
        Style::default()
            .fg(comps::colour_themed(colors, Token::Ink))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(comps::colour_themed(colors, Token::Muted))
    };
    Line::from(vec![
        if selected {
            Span::styled(
                "▌",
                Style::default().fg(comps::colour_themed(colors, Token::Magenta)),
            )
        } else {
            Span::raw(" ")
        },
        Span::raw("  "),
        Span::styled(cmd.to_string(), cmd_style),
        Span::raw(" ".repeat(22usize.saturating_sub(cmd.chars().count()))),
        Span::styled(
            desc.to_string(),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        ),
    ])
}

/// The help overlay's content (§9.20): two columns of groups.
pub fn help_lines_themed(colors: crate::proto::shell::pal::Palette) -> Vec<Line<'static>> {
    // The help overlay (§9.20), per the golden: two columns of
    // groups — ANYWHERE, OUTSIDE THE COMPOSER, APPROVAL left;
    // IN THE COMPOSER right.
    let label = |t: &str| {
        Span::styled(
            t.to_string(),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        )
    };
    let key = |k: &str| {
        Span::styled(
            format!("{k:<11}"),
            Style::default()
                .fg(comps::colour_themed(colors, Token::Ink))
                .add_modifier(ratatui::style::Modifier::BOLD),
        )
    };
    let key2 = |k: &str| {
        Span::styled(
            format!("{k:<11}"),
            Style::default()
                .fg(comps::colour_themed(colors, Token::Ink))
                .add_modifier(ratatui::style::Modifier::BOLD),
        )
    };
    let desc = |d: &str| {
        Span::styled(
            d.to_string(),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
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
        ("ctrl-r", "search history; older match"),
        ("@", "workspace file picker"),
        ("tab", "accept a file suggestion"),
        ("⏎", "accept picker/search draft"),
        ("esc", "close files; restore search"),
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
pub fn help_area_themed(colors: crate::proto::shell::pal::Palette, screen: Rect) -> Rect {
    let w = 78.min(screen.width.saturating_sub(8));
    let h = (help_lines_themed(colors).len() as u16 + 2).min(screen.height.saturating_sub(4));
    Rect {
        x: screen.x + (screen.width - w) / 2,
        y: screen.y + 3,
        width: w,
        height: h,
    }
}

/// The quit card (§9.21).
pub fn quit_card_themed(
    colors: crate::proto::shell::pal::Palette,
    turn_running: bool,
    screen: Rect,
) -> (Rect, Vec<Line<'static>>) {
    let lines = if turn_running {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "A turn is running. Quitting stops it.",
                Style::default().fg(comps::colour_themed(colors, Token::Amber)),
            )),
            Line::from(""),
            quit_keys_themed(colors),
        ]
    } else {
        vec![Line::from(""), quit_keys_themed(colors)]
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

fn quit_keys_themed(colors: crate::proto::shell::pal::Palette) -> Line<'static> {
    Line::from(vec![
        keycap_themed(colors, "y"),
        Span::raw(" "),
        Span::styled(
            "quit",
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        ),
        Span::raw("    "),
        keycap_themed(colors, "n"),
        Span::raw(" "),
        Span::styled(
            "stay",
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        ),
    ])
}

/// The size notice (§9.23): below 40 × 11 this is the whole screen.
pub fn size_notice_lines_themed(
    colors: crate::proto::shell::pal::Palette,
    w: u16,
    h: u16,
) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "ORBIT needs at least 40 × 11",
            Style::default()
                .fg(comps::colour_themed(colors, Token::Ink))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("this terminal is {w} × {h}"),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "enlarge the window or run",
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        )),
        Line::from(Span::styled(
            "orbit chat --no-tui",
            Style::default().fg(comps::colour_themed(colors, Token::Ink)),
        )),
    ]
}

/// Render an overlay frame (palette / help / quit) with its title.
pub fn overlay_themed(
    colors: crate::proto::shell::pal::Palette,
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
        .border_style(Style::default().fg(comps::colour_themed(colors, Token::Rule)))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(comps::colour_themed(colors, Token::Ink))
                .add_modifier(Modifier::BOLD),
        ));
    if let Some(ft) = footer {
        block = block.title_bottom(Span::styled(
            format!(" {ft} "),
            Style::default().fg(comps::colour_themed(colors, Token::Muted)),
        ));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

pub fn hint_row(
    turn_live: bool,
    transcript_tall: bool,
    toast: Option<&str>,
    width: u16,
) -> Line<'static> {
    hint_row_themed(
        crate::proto::shell::pal::Palette::default(),
        turn_live,
        transcript_tall,
        toast,
        width,
    )
}
pub fn completion_list(typed: &str, selected: usize) -> (Rect, Vec<Line<'static>>) {
    completion_list_themed(
        crate::proto::shell::pal::Palette::default(),
        typed,
        selected,
    )
}
pub fn palette_lines(query: &str, selected: usize) -> Vec<Line<'static>> {
    palette_lines_themed(
        crate::proto::shell::pal::Palette::default(),
        query,
        selected,
    )
}
pub fn help_lines() -> Vec<Line<'static>> {
    help_lines_themed(crate::proto::shell::pal::Palette::default())
}
pub fn help_area(screen: Rect) -> Rect {
    help_area_themed(crate::proto::shell::pal::Palette::default(), screen)
}
pub fn quit_card(turn_running: bool, screen: Rect) -> (Rect, Vec<Line<'static>>) {
    quit_card_themed(
        crate::proto::shell::pal::Palette::default(),
        turn_running,
        screen,
    )
}
pub fn size_notice_lines(w: u16, h: u16) -> Vec<Line<'static>> {
    size_notice_lines_themed(crate::proto::shell::pal::Palette::default(), w, h)
}
pub fn overlay(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    footer: Option<&str>,
) {
    overlay_themed(
        crate::proto::shell::pal::Palette::default(),
        f,
        area,
        title,
        lines,
        footer,
    )
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
    fn toast_reservation_uses_the_rendered_cell_width() {
        let colors = crate::proto::shell::pal::Palette::default();
        let base = hint_row_themed(colors, false, false, None, 120);
        let base_width = base.width() as u16;
        let cjk_width = super::super::shell::canvas::text_width("✓ 界") as u16;
        let cjk = hint_row_themed(colors, false, false, Some("界"), base_width + cjk_width);
        let cjk_text = cjk.spans.iter().fold(String::new(), |mut text, span| {
            text.push_str(&span.content);
            text
        });
        assert!(cjk_text.contains("✓ 界"));
        assert_eq!(cjk.width(), (base_width + cjk_width) as usize);

        let too_narrow =
            hint_row_themed(colors, false, false, Some("界"), base_width + cjk_width - 1);
        let narrow_text = too_narrow
            .spans
            .iter()
            .fold(String::new(), |mut text, span| {
                text.push_str(&span.content);
                text
            });
        assert!(!narrow_text.contains("✓ 界"));
        assert!(too_narrow.width() <= (base_width + cjk_width - 1) as usize);

        let combining_width = super::super::shell::canvas::text_width("✓ e\u{301}") as u16;
        let combining = hint_row_themed(
            colors,
            false,
            false,
            Some("e\u{301}"),
            base_width + combining_width,
        );
        assert!(
            combining
                .spans
                .iter()
                .any(|span| span.content.contains("✓ e\u{301}"))
        );
        assert_eq!(combining.width(), (base_width + combining_width) as usize);
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
    fn effort_is_available_in_completion_and_palette() {
        assert_eq!(completion_matches("/eff"), vec![("/effort", COMMANDS[2].1)]);
        let text = palette_lines("effort", 0)
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|s| s.content.into_owned()))
            .collect::<String>();
        assert!(text.contains("/effort"));
        assert!(text.contains("request effort"));
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
