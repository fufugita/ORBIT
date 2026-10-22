//! The conversation transcript's rendering (§9.4–9.12) and the
//! approval card (§9.14) — pure functions of the scenario.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::comps;
use super::core::Token;
use super::scenario::{LineKind, Scenario, ToolState, TranscriptLine};
use super::screen::{Screen, WidthClass};

/// Render every transcript line into styled rows, bottom-anchored by
/// the caller.
pub fn transcript_lines(
    scenario: &Scenario,
    cl: u16,
    cw: u16,
    class: WidthClass,
) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = Vec::new();
    let mut prev_tool = false;
    // A live turn with no model output yet still shows the waiting line
    // (§9.5): the first prompt has only a User line, and a slow provider
    // would otherwise leave the panel looking frozen until the first delta.
    let mut waiting_shown = false;
    for l in &scenario.transcript {
        match l.kind {
            LineKind::User => {
                // §9.4: one blank row follows; a blank row also
                // precedes if the previous block was a tool group.
                if prev_tool {
                    out.push(blank_surface(cl, cw));
                }
                out.extend(user_turn(l, cl, cw, class));
                prev_tool = false;
            }
            LineKind::Model => {
                if prev_tool {
                    out.push(blank_surface(cl, cw));
                }
                if !waiting_shown {
                    // The waiting line (§9.5) opens the turn.
                    out.push(waiting_line(scenario, cl, cw));
                    waiting_shown = true;
                }
                out.extend(model_text(l, scenario, cl, cw));
                prev_tool = false;
            }
            LineKind::Tool => {
                // §9.8: one blank row before and after the group; no
                // blanks inside.
                if !prev_tool && !out.is_empty() {
                    out.push(blank_bg());
                }
                out.extend(tool_line(l, cl, cw, class));
                prev_tool = true;
            }
            LineKind::System => {
                if prev_tool {
                    out.push(blank_bg());
                }
                out.extend(notice(l, cl, cw));
                prev_tool = false;
            }
            LineKind::Queued => {
                out.extend(queued_row(l, cl, cw));
                prev_tool = false;
            }
        }
    }
    // A tool group closes with one blank row.
    if prev_tool {
        out.push(blank_bg());
    }
    // A live turn that produced no Model line yet (the slow first-prompt
    // case) still gets its waiting line, so the panel never looks frozen.
    if !waiting_shown && scenario.is_busy() && !scenario.visible_output {
        out.push(waiting_line(scenario, cl, cw));
    }
    out
}

fn blank_bg() -> Line<'static> {
    Line::from("")
}

fn blank_surface(_cl: u16, cw: u16) -> Line<'static> {
    let width = cw + 3;
    Line::from(Span::styled(
        " ".repeat(width as usize),
        Style::default().bg(comps::colour(Token::Surface)),
    ))
    .style(Style::default().bg(comps::colour(Token::Surface)))
}

/// The user turn (§9.4): a surface band on every row, `›` gutter,
/// ink text, the time right-aligned on the first row.
fn user_turn(l: &TranscriptLine, cl: u16, cw: u16, class: WidthClass) -> Vec<Line<'static>> {
    let band_w = cw + 3;
    let text_w = cw.saturating_sub(2) as usize;
    let rows = wrap(&l.text, text_w);
    let mut out = Vec::new();
    let show_time = class != WidthClass::Compact && class != WidthClass::Tight;
    for (i, row) in rows.iter().enumerate() {
        let mut spans = vec![
            Span::raw("  "),
            if i == 0 {
                Span::styled(
                    "›",
                    Style::default()
                        .fg(comps::colour(Token::Muted))
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw(" ")
            },
            Span::raw(" "),
            Span::styled(row.clone(), Style::default().fg(comps::colour(Token::Ink))),
        ];
        if i == 0
            && let Some(t) = &l.time
            && show_time
        {
            let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
            let pad = band_w.saturating_sub(used + t.width() as u16 + 1);
            spans.push(Span::raw(" ".repeat(pad as usize)));
            spans.push(Span::styled(
                t.clone(),
                Style::default().fg(comps::colour(Token::Muted)),
            ));
        }
        // The band fills to band_w.
        let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
        if used < band_w {
            spans.push(Span::raw(" ".repeat((band_w - used) as usize)));
        }
        out.push(Line::from(spans).style(Style::default().bg(comps::colour(Token::Surface))));
    }
    out.push(blank_surface(cl, cw));
    out
}

/// `waiting for {model}` (§9.5), muted, static.
fn waiting_line(scenario: &Scenario, cl: u16, cw: u16) -> Line<'static> {
    let _ = (cl, cw);
    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            "✦",
            Style::default().fg(comps::colour(if scenario.turn_live {
                Token::Cyan
            } else {
                Token::Magenta
            })),
        ),
        Span::raw(" "),
        Span::styled(
            format!("waiting for {}", scenario.model),
            Style::default().fg(comps::colour(Token::Muted)),
        ),
    ])
}

/// Model prose (§9.5/§9.6): plain ink text, wrapped; the live edge
/// rides the last row while streaming.
fn model_text(l: &TranscriptLine, scenario: &Scenario, cl: u16, cw: u16) -> Vec<Line<'static>> {
    let _ = cl;
    let text_w = cw.saturating_sub(2) as usize;
    let rows = wrap(&l.text, text_w);
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let mut spans = vec![
            Span::raw("  "),
            if i == 0 {
                Span::styled(
                    "✦",
                    Style::default().fg(comps::colour(if scenario.turn_live {
                        Token::Cyan
                    } else {
                        Token::Magenta
                    })),
                )
            } else {
                Span::raw(" ")
            },
            Span::raw(" "),
            Span::styled(row.clone(), Style::default().fg(comps::colour(Token::Ink))),
        ];
        if i + 1 == rows.len() && scenario.turn_live {
            spans.push(Span::styled(
                "▍",
                Style::default().fg(comps::colour(Token::Cyan)),
            ));
        }
        out.push(Line::from(spans));
    }
    if rows.is_empty() {
        out.push(Line::from(""));
    }
    out
}

/// The tool line (§9.8): `{glyph} {name}  {argument}   …   {meta}`.
fn tool_line(l: &TranscriptLine, cl: u16, cw: u16, class: WidthClass) -> Vec<Line<'static>> {
    let _ = cl;
    let (glyph, glyph_colour) = l.tool_state.glyph_parts();
    let name_colour = match l.tool_state {
        ToolState::Running | ToolState::AwaitingYou => Token::Ink,
        _ => Token::Ink2,
    };
    let meta: (String, Token) = match l.tool_state {
        ToolState::Queued => ("queued".into(), Token::Muted),
        ToolState::Running => ("running".into(), Token::Cyan),
        ToolState::AwaitingYou => ("awaiting you".into(), Token::Magenta),
        ToolState::Done => (l.meta.clone(), Token::Muted),
        ToolState::Failed => (
            if l.meta.is_empty() {
                "failed".into()
            } else {
                l.meta.clone()
            },
            Token::Red,
        ),
        ToolState::Denied => ("denied by you".into(), Token::Muted),
        ToolState::Blocked => ("blocked · unknown tool".into(), Token::Amber),
        ToolState::Cancelled => ("cancelled".into(), Token::Muted),
    };
    let compact = matches!(class, WidthClass::Compact | WidthClass::Tight);
    let meta_text = if compact {
        // Compact drops the duration: keep the outcome word only.
        meta.0
            .split(" · ")
            .next()
            .map(str::to_string)
            .unwrap_or_default()
    } else {
        meta.0.clone()
    };
    let mut spans = vec![
        Span::raw("  "),
        Span::styled(glyph, Style::default().fg(comps::colour(glyph_colour))),
        Span::raw(" "),
        Span::styled(
            l.tool_name.clone(),
            Style::default()
                .fg(comps::colour(name_colour))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            l.text.clone(),
            Style::default().fg(comps::colour(Token::Muted)),
        ),
    ];
    if !meta_text.is_empty() {
        let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
        let pad = (cw + 1).saturating_sub(used + meta_text.width() as u16);
        spans.push(Span::raw(" ".repeat(pad as usize)));
        spans.push(Span::styled(
            meta_text,
            Style::default().fg(comps::colour(meta.1)),
        ));
    }
    vec![Line::from(spans)]
}

/// A session notice (§9.11).
fn notice(l: &TranscriptLine, cl: u16, cw: u16) -> Vec<Line<'static>> {
    let _ = (cl, cw);
    vec![Line::from(vec![
        Span::raw("  "),
        Span::styled("∙", Style::default().fg(comps::colour(Token::Muted))),
        Span::raw(" "),
        Span::styled(
            l.text.clone(),
            Style::default().fg(comps::colour(Token::Muted)),
        ),
    ])]
}

/// The queued row (§9.12).
fn queued_row(l: &TranscriptLine, cl: u16, cw: u16) -> Vec<Line<'static>> {
    let _ = cl;
    let mut spans = vec![
        Span::raw("  "),
        Span::styled(
            "›",
            Style::default()
                .fg(comps::colour(Token::Faint))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            l.text.clone(),
            Style::default().fg(comps::colour(Token::Ink2)),
        ),
    ];
    let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
    let pad = cw.saturating_sub(used + 7);
    spans.push(Span::raw(" ".repeat(pad as usize)));
    spans.push(Span::styled(
        "queued",
        Style::default().fg(comps::colour(Token::Muted)),
    ));
    vec![Line::from(spans)]
}

/// Greedy word wrap (§7.4). Hard breaks preserve grapheme boundaries.
/// A grapheme wider than the viewport stays intact on its own row;
/// the renderer clips it without losing text or preventing progress.
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        let mut line_w = 0usize;
        for word in para.split(' ') {
            let ww = word.width();
            if line.is_empty() {
                (line, line_w) = hard_break_word(word, width, &mut out);
            } else if line_w.saturating_add(1).saturating_add(ww) <= width {
                line.push(' ');
                line.push_str(word);
                line_w += 1 + ww;
            } else {
                out.push(std::mem::take(&mut line));
                (line, line_w) = hard_break_word(word, width, &mut out);
            }
        }
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Emit complete rows while scanning a word once, retaining its final row.
fn hard_break_word(word: &str, width: usize, out: &mut Vec<String>) -> (String, usize) {
    let mut start = 0;
    let mut cells = 0usize;
    for (offset, grapheme) in word.grapheme_indices(true) {
        let grapheme_cells = grapheme.width();
        if cells > 0 && grapheme_cells > 0 && cells.saturating_add(grapheme_cells) > width {
            out.push(word[start..offset].to_string());
            start = offset;
            cells = 0;
        }
        cells = cells.saturating_add(grapheme_cells);
    }
    (word[start..].to_string(), cells)
}

// ── The approval card (§9.14) ─────────────────────────────────────

/// Draw the approval card for `tool`, replacing the composer. The
/// card is the only frame on screen: rounded, magenta, surface fill.
pub fn approval_card(f: &mut ratatui::Frame, scr: &Screen, scenario: &Scenario, now_ms: u64) {
    let Some(tool) = scenario.approval_queue.first() else {
        return;
    };
    let (cl, cw) = scr.conv_column();
    let x = cl.saturating_sub(2);
    let w = cw + 3;
    // h = 1 + 1 + A + 1 + K + 1 (no facts today) with A=1, K=1 → 6.
    let h: u16 = 6;
    let height = f.area().height;
    let bottom = height - 2; // row H−2
    let top = bottom.saturating_sub(h - 1);
    let area = Rect {
        x,
        y: top,
        width: w,
        height: h,
    };
    let surface = comps::colour(Token::Surface);
    let magenta = comps::colour(Token::Magenta);
    // Fill.
    f.render_widget(
        ratatui::widgets::Block::default().style(Style::default().bg(surface)),
        area,
    );
    // Top border: ╭─ ◇ Allow {tool}? ─…─ (risk) ─╮
    let _title = format!(" ◇ Allow {tool}? ");
    let mut top_spans: Vec<Span> = Vec::new();
    top_spans.push(Span::styled("╭".to_string(), Style::default().fg(magenta)));
    top_spans.push(Span::styled("─ ".to_string(), Style::default().fg(magenta)));
    top_spans.push(Span::styled(
        "◇",
        Style::default().fg(magenta).add_modifier(Modifier::BOLD),
    ));
    top_spans.push(Span::styled(
        format!(" Allow {tool}? "),
        Style::default()
            .fg(comps::colour(Token::Ink))
            .add_modifier(Modifier::BOLD),
    ));
    let used: u16 = top_spans.iter().map(|s| s.width() as u16).sum();
    // The right edge ╮ with 1 cell of ─ before it.
    let fill = w.saturating_sub(used + 2);
    top_spans.push(Span::styled(
        "─".repeat(fill as usize),
        Style::default().fg(magenta),
    ));
    top_spans.push(Span::styled("─╮", Style::default().fg(magenta)));
    f.render_widget(
        Paragraph::new(Line::from(top_spans)).style(Style::default().bg(surface)),
        Rect {
            x,
            y: top,
            width: w,
            height: 1,
        },
    );
    // Action row (T+2): the summary, ink bold, from x+3.
    let action = scenario
        .approval_summary
        .clone()
        .unwrap_or_else(|| format!("{tool}()"));
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("  {action}"),
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(surface)),
        Rect {
            x,
            y: top + 2,
            width: w,
            height: 1,
        },
    );
    // Keys row (T+4): y / R / n+esc.
    let keys_row = keys_line(scenario, now_ms);
    f.render_widget(
        Paragraph::new(keys_row).style(Style::default().bg(surface)),
        Rect {
            x,
            y: top + 4,
            width: w,
            height: 1,
        },
    );
    // Bottom border ╰…╯ (+ paused/queue notes at x+2).
    let mut bot_spans = vec![Span::styled("╰", Style::default().fg(magenta))];
    let last_typing = scenario
        .last_key_ms
        .max(scenario.approval_shown_ms.min(scenario.last_key_ms));
    let note: Option<String> = if now_ms.saturating_sub(last_typing) < 1000 {
        Some(" paused while you type ".into())
    } else if scenario.approval_queue.len() > 1 {
        Some(format!(" {} of {} ", 1, scenario.approval_queue.len()))
    } else {
        None
    };
    let mut used: u16 = 1;
    if let Some(n) = &note {
        let ns = Span::styled(n.clone(), Style::default().fg(comps::colour(Token::Muted)));
        used += ns.width() as u16;
        bot_spans.push(Span::styled("─".repeat(2), Style::default().fg(magenta)));
        used += 2;
        bot_spans.push(ns);
    }
    let fill = w.saturating_sub(used + 2);
    bot_spans.push(Span::styled(
        "─".repeat(fill as usize),
        Style::default().fg(magenta),
    ));
    bot_spans.push(Span::styled("╯", Style::default().fg(magenta)));
    f.render_widget(
        Paragraph::new(Line::from(bot_spans)).style(Style::default().bg(surface)),
        Rect {
            x,
            y: bottom,
            width: w,
            height: 1,
        },
    );
}

fn keys_line(scenario: &Scenario, now_ms: u64) -> Line<'static> {
    // Arming (§9.14): disabled when a key was pressed < 1000 ms
    // before the card appeared, or within its lifetime since.
    // Arming (§9.14): any keypress less than 1000 ms before the card
    // appeared, or since, keeps the keys disabled until 1000 ms pass
    // without a key.
    let last_typing = scenario
        .last_key_ms
        .max(scenario.approval_shown_ms.min(scenario.last_key_ms));
    let disabled = now_ms.saturating_sub(last_typing) < 1000;
    let cap_colour = |t: Token| {
        if disabled {
            comps::colour(Token::Faint)
        } else {
            comps::colour(t)
        }
    };
    let _ = cap_colour;
    let cap = |k: &str| {
        Span::styled(
            format!(" {k} "),
            if disabled {
                Style::default().fg(comps::colour(Token::Faint))
            } else {
                Style::default()
                    .fg(comps::colour(Token::Ink))
                    .add_modifier(Modifier::BOLD)
            },
        )
    };
    let label = |l: &str| {
        Span::styled(
            l.to_string(),
            if disabled {
                Style::default().fg(comps::colour(Token::Faint))
            } else {
                Style::default().fg(comps::colour(Token::Ink2))
            },
        )
    };
    Line::from(vec![
        Span::raw("  "),
        cap("y"),
        Span::raw(" "),
        label("allow once"),
        Span::raw("    "),
        cap("R"),
        Span::raw(" "),
        label(&format!(
            "allow {} for this session",
            scenario
                .approval_queue
                .first()
                .map(String::as_str)
                .unwrap_or("tool")
        )),
        Span::raw("    "),
        cap("n"),
        Span::raw(" "),
        cap("esc"),
        Span::raw(" "),
        label("deny"),
    ])
}

#[cfg(test)]
mod wrap_tests {
    use super::*;

    #[test]
    fn greedy_wrap_preserves_ascii_spacing_paragraphs_and_empty_input() {
        assert_eq!(wrap("alpha beta", 7), ["alpha", "beta"]);
        assert_eq!(wrap("abcdefghijk", 3), ["abc", "def", "ghi", "jk"]);
        assert_eq!(wrap("one  two", 8), ["one  two"]);
        assert_eq!(wrap("a\n\nb\n", 4), ["a", "", "b", ""]);
        assert_eq!(wrap("", 4), [""]);
        assert_eq!(wrap("retained source", 0), [""]);
    }

    #[test]
    fn narrow_wrap_preserves_unicode_graphemes_and_always_consumes_input() {
        for text in [
            "界界界界界界",
            "🙂🙂🙂🙂🙂",
            "e\u{301}e\u{301}e\u{301}",
            "👩‍💻👩‍💻👩‍💻",
        ] {
            for width in [1, 3, 4, 10] {
                let rows = wrap(text, width);
                assert!(
                    rows.iter().all(|row| !row.is_empty()),
                    "{text:?} at {width}"
                );
                assert_eq!(rows.concat(), text, "{text:?} at {width}");
                let actual: Vec<_> = rows.iter().flat_map(|row| row.graphemes(true)).collect();
                assert_eq!(actual, text.graphemes(true).collect::<Vec<_>>());
                assert!(
                    rows.iter()
                        .all(|row| row.width() <= width || row.graphemes(true).count() == 1)
                );
            }
        }
        assert_eq!(wrap("界界界", 3), ["界", "界", "界"]);
        assert_eq!(wrap("界界界", 4), ["界界", "界"]);
        assert_eq!(wrap("a 界界界 z", 4), ["a", "界界", "界 z"]);
        assert_eq!(wrap("e\u{301}e\u{301}", 1), ["e\u{301}", "e\u{301}"]);
        assert_eq!(wrap("👩‍💻👩‍💻", 1), ["👩‍💻", "👩‍💻"]);
    }

    #[test]
    fn long_joined_emoji_word_advances_without_splitting_or_empty_rows() {
        let text = "👩‍💻".repeat(4096);
        let rows = wrap(&text, 1);
        assert_eq!(rows.len(), 4096);
        assert_eq!(rows.concat(), text);
        assert!(rows.iter().all(|row| row == "👩‍💻"));
    }
}
