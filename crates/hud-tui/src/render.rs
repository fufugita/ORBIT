//! Ratatui rendering — the ORBIT visual system (docs/tui/DESIGN.md).
//!
//! Ink, not boxes: structure comes from gutters, alignment, spacing and
//! hairlines. No pane has a border. At most one rounded frame is on screen
//! at a time, and a frame always means "this needs you" — an approval, the
//! palette, a confirmation. All colours come from the token palette
//! (tokens.rs); all glyphs from glyphs.rs. No literals in render code.

use crate::glyphs::Glyphs;
use crate::rich::render_message;
use crate::state::{
    App, ConnectionState, Focus, LeftTab, LogoPhase, TaskState, ToolState, TranscriptLine,
    VerificationResult,
};
use crate::tokens::Design;
use crate::unicode::truncate_graphemes;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};

// ── Pane headers (§6.1) ──────────────────────────────────────────────────────

/// One-row pane header: title, then a hairline rule filling the rest of the
/// row. The focused pane gets a heavy rule (`━`, rule_hi) and a magenta
/// title; unfocused panes get a light rule (`─`, rule) and an ink2 title.
/// This replaces the old boxed pane_block — no Borders::ALL anywhere.
fn pane_header_line(
    title: &str,
    focused: bool,
    area_width: u16,
    d: &Design,
    g: &Glyphs,
) -> Line<'static> {
    let (title_color, rule_glyph, rule_color, bold) = if focused {
        (d.palette.magenta, g.rule_focus, d.palette.rule_hi, true)
    } else {
        (d.palette.ink2, g.rule, d.palette.rule, false)
    };
    let mut style = Style::default().fg(title_color);
    if bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    let title_span = Span::styled(format!(" {title} "), style);
    // Fill the remainder of the row with the rule glyph. Width math is
    // approximate for wide titles; the rule just fills whatever remains.
    let title_w = display_width_of(title) as u16 + 2;
    let fill = area_width.saturating_sub(title_w) as usize;
    let rule = rule_glyph.repeat(fill);
    Line::from(vec![
        title_span,
        Span::styled(rule, Style::default().fg(rule_color)),
    ])
}

/// Display width helper (single source: unicode.rs).
fn display_width_of(s: &str) -> usize {
    crate::unicode::display_width(s)
}

/// Render the one-row header for a pane, then return the body area below it.
fn render_pane_header(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
    g: &Glyphs,
) -> Rect {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);
    frame.render_widget(
        Paragraph::new(pane_header_line(title, focused, area.width, d, g)),
        rows[0],
    );
    rows[1]
}

// ── Main render ──────────────────────────────────────────────────────────────

/// Render the current app state into the frame.
///
/// Layout (§5.3 row priorities): 1 header-less main row | 1 status line.
/// The chrome budget is 2 rows total (the old build spent 11).
pub fn render(frame: &mut ratatui::Frame, app: &App, composer_text: &str, d: &Design) {
    let area = frame.area();
    let g = &Glyphs::for_set(d.caps.glyphs);

    // Vertical: main (fill) | status (1).
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    // Three columns: left rail | divider | conversation | divider | right
    // rail. Rails are column counts (tokens::LayoutConfig); the dividers are
    // full-height hairlines that double as scroll tracks (§6.14).
    let l = &d.layout_rails;
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(l.0),
            Constraint::Length(1), // divider track
            Constraint::Min(10),   // conversation
            Constraint::Length(1), // divider track
            Constraint::Length(l.1),
        ])
        .split(outer[0]);

    render_left_pane(frame, main[0], app, d, g);
    render_divider(frame, main[1], app, d, g, false);
    render_center_pane(frame, main[2], app, composer_text, d, g);
    render_divider(frame, main[3], app, d, g, true);
    render_right_pane(frame, main[4], app, d, g);
    // Command palette (§6.13): an overlay above the panes, under the
    // status line.
    if app.palette.open {
        render_palette(frame, outer[0], app, d, g);
    }

    render_status_bar(frame, outer[1], app, d, g);

    // Overlays — the only frames on screen (one at a time, §1).
    if app.quit_confirmation {
        render_quit_modal(frame, area, app, d, g);
    }
    if !app.pending_approvals.is_empty() {
        render_approval_modal(frame, area, app, d, g);
    }
}

// ── Divider / scrollbar (§6.14) ──────────────────────────────────────────────

/// Full-height divider `│`; when the transcript overflows, the center
/// divider becomes a scroll track with a `┃` thumb at the transcript's
/// position.
fn render_divider(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
    is_center: bool,
) {
    if area.height == 0 {
        return;
    }
    let track = Span::styled(g.divider, Style::default().fg(d.palette.rule));
    let mut lines: Vec<Line> = vec![Line::from(track.clone()); area.height as usize];

    // Scroll thumb on the center divider when there is more content than
    // fits. (Approximate: app.scroll_hint carries 0=at-bottom, 1=scrolled.)
    if is_center && app.viewport_manual {
        // Position the thumb by scroll fraction; without exact totals here,
        // place it in the upper third while scrolled (the pill in §6.14's
        // "↓ n new" is a later step — the track alone is honest).
        let idx = (area.height as usize / 3).min(area.height as usize - 1);
        lines[idx] = Line::from(Span::styled(g.thumb, Style::default().fg(d.palette.muted)));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

// ── Left rail (§6.9) ─────────────────────────────────────────────────────────

fn render_left_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Activity",
    };
    let body = render_pane_header(frame, area, title, app.focus == Focus::Left, d, g);

    let items: Vec<ListItem> = match app.left_tab {
        LeftTab::Sessions => vec![ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!("{} ", g.conn_online), Style::default().fg(p.green)),
                Span::styled(&app.session_id_prefix, Style::default().fg(p.ink)),
            ]),
            Line::from(vec![
                Span::styled("model ", Style::default().fg(p.muted)),
                Span::styled(&app.model, Style::default().fg(p.ink2)),
            ]),
        ])],
        LeftTab::Verbose => {
            if app.in_flight.is_empty() {
                vec![ListItem::new(Line::from(vec![Span::styled(
                    "(no active stream)",
                    Style::default().fg(p.faint),
                )]))]
            } else {
                vec![ListItem::new(vec![
                    Line::from(vec![Span::styled("streaming", Style::default().fg(p.cyan))]),
                    Line::from(vec![Span::styled(
                        &app.in_flight,
                        Style::default().fg(p.muted),
                    )]),
                ])]
            }
        }
    };
    frame.render_widget(List::new(items), body);
}

// ── Center pane: transcript + composer (§6.2–6.8, §5.5) ──────────────────────

fn render_center_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    composer_text: &str,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;

    // No pane header on the conversation — it IS the centre of gravity
    // (§1). Split: transcript (fill) | queue | composer band.
    //
    // Composer auto-height (§5.5): one row when empty, one row per line of
    // content, capped at half the pane so the transcript always keeps ≥3
    // rows. Lines beyond the cap show the last ones (the newest line stays
    // visible).
    let queue_h = app.queued.len() as u16;
    let text_lines = composer_text.lines().count().max(1) as u16;
    let composer_cap = (area.height / 2).max(1);
    let composer_h = text_lines.min(composer_cap);
    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(queue_h),
            Constraint::Length(composer_h),
        ])
        .split(area);

    // ── Transcript ─────────────────────────────────────────────────────────
    // The welcome screen (§8.1): an empty session shows the expanded mark,
    // centered in the conversation. The first turn replaces it.
    let mut lines: Vec<Line> = Vec::new();
    if app.transcript.is_empty() && app.in_flight.is_empty() {
        let mark = welcome_mark(d, g);
        let mark_w = 36u16; // widest mark row
        let mark_h = mark.len() as u16;
        if center[0].width > mark_w + 4 && center[0].height > mark_h + 4 {
            let pad_y = (center[0].height.saturating_sub(mark_h)) / 3;
            for _ in 0..pad_y {
                lines.push(Line::from(""));
            }
            let pad_x = (center[0].width.saturating_sub(mark_w)) / 2;
            let pad = " ".repeat(pad_x as usize);
            for l in mark {
                let mut padded = vec![Span::raw(pad.clone())];
                padded.extend(l.spans);
                lines.push(Line::from(padded));
            }
        }
    }
    // Gutter 3 (§6.5): the you-glyph at col 0, text from col 2.
    let user_gutter = || Span::styled(format!("{}  ", g.you), Style::default().fg(p.muted));
    let orbit_gutter = |live: bool| {
        Span::styled(
            format!("{}  ", g.orbit),
            Style::default().fg(if live { p.cyan } else { p.magenta }),
        )
    };

    for entry in &app.transcript {
        match entry {
            TranscriptLine::User(text) => {
                lines.push(Line::from(user_gutter()));
                for line in text.lines() {
                    lines.push(Line::from(vec![
                        Span::raw("   "),
                        Span::styled(line, Style::default().fg(p.ink)),
                    ]));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Assistant(text) => {
                lines.push(Line::from(orbit_gutter(false)));
                for rich_line in render_message(text, d) {
                    let mut spans = vec![Span::raw("   ")];
                    spans.extend(rich_line.spans);
                    lines.push(Line::from(spans));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Stripped { tool_name } => {
                // The tool line alone — stripping stays in the bridge,
                // silently (§12: no "(reasoning stripped)" advertisement).
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("{} {tool_name}", g.running),
                        Style::default().fg(p.ink2),
                    ),
                ]));
                lines.push(Line::from(""));
            }
            TranscriptLine::System(text) => {
                lines.push(Line::from(vec![
                    Span::styled(format!("{} ", g.notice), Style::default().fg(p.muted)),
                    Span::styled(text, Style::default().fg(p.muted)),
                ]));
                lines.push(Line::from(""));
            }
        }
    }

    // In-flight stream — live star in the gutter, cyan while working.
    let streaming = !app.in_flight.is_empty();
    if streaming {
        lines.push(Line::from(orbit_gutter(true)));
        for rich_line in render_message(&app.in_flight, d) {
            let mut spans = vec![Span::raw("   ")];
            spans.extend(rich_line.spans);
            lines.push(Line::from(spans));
        }
    }
    // NOTE: while Streaming with an empty in_flight, no transcript line is
    // added — the working star in the status line (§6.11) is the sole
    // indicator. This keeps streamed text contiguous in the render buffer
    // (§7: text appears without token-by-token animation) and avoids the
    // old "thinking phrases" theatre.

    // Errors — red glyph + word (colour is the third signal).
    if let Some(err) = &app.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", g.failed), Style::default().fg(p.red)),
            Span::styled(err, Style::default().fg(p.red)),
        ]));
    }

    // Viewport: auto-scroll to bottom unless the operator scrolled up.
    let visible_height = center[0].height as usize;
    let total_lines = lines.len();
    let scroll = if app.viewport_manual {
        app.viewport_scroll as usize
    } else {
        total_lines.saturating_sub(visible_height)
    };

    let transcript = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll as u16, 0));
    frame.render_widget(transcript, center[0]);

    // ── Queue: pending prompts above the composer ──────────────────────────
    let mut queue_rows = Vec::new();
    for q in &app.queued {
        queue_rows.push(Line::from(vec![
            Span::styled(format!("{} ", g.pending), Style::default().fg(p.faint)),
            Span::styled(truncate_graphemes(q, 40), Style::default().fg(p.muted)),
        ]));
    }
    if !queue_rows.is_empty() {
        frame.render_widget(Paragraph::new(queue_rows), center[1]);
    }

    // ── Composer: a band, not a box (§5.5) ─────────────────────────────────
    // The › prompt in magenta (your input is one of the six magenta things),
    // text in ink, no border. While streaming the band shows Stop.
    let composer_focused = app.focus == Focus::Center;
    let prompt_color = if composer_focused { p.magenta } else { p.faint };
    let turn_live = app.turn_in_flight
        || app.tool_state == ToolState::Streaming
        || matches!(app.tool_state, ToolState::Running(_));
    let cursor_on = !turn_live && (app.tick_count / 16).is_multiple_of(2);
    let cursor = if cursor_on { "▏" } else { " " };
    let first_text_line = composer_text.lines().next().unwrap_or("");
    let prompt_line = if composer_text.is_empty() {
        Line::from(vec![
            Span::styled(format!("{} ", g.you), Style::default().fg(prompt_color)),
            Span::styled("ask orbit", Style::default().fg(p.faint)),
            Span::styled(cursor, Style::default().fg(p.magenta)),
        ])
    } else {
        Line::from(vec![
            Span::styled(format!("{} ", g.you), Style::default().fg(prompt_color)),
            Span::styled(first_text_line, Style::default().fg(p.ink)),
        ])
    };
    // All content lines, capped: when the text exceeds the cap, show the
    // LAST lines (the newest input stays visible; older lines scroll out).
    let all_lines: Vec<&str> = composer_text.lines().collect();
    let visible: Vec<Line> = if all_lines.is_empty() {
        vec![prompt_line]
    } else {
        let take = (all_lines.len() as u16).min(composer_h) as usize;
        let start = all_lines.len() - take;
        all_lines[start..]
            .iter()
            .enumerate()
            .map(|(i, line)| {
                if start + i == 0 {
                    prompt_line.clone()
                } else {
                    Line::from(vec![
                        Span::raw("  "),
                        Span::styled(*line, Style::default().fg(p.ink)),
                    ])
                }
            })
            .collect()
    };
    frame.render_widget(Paragraph::new(visible), center[2]);
}

// ── Right rail (§6.10) ───────────────────────────────────────────────────────

/// A workspace section label: muted label + faint count (§6.10).
fn section_line(label: &str, count: usize, p: &crate::tokens::ResolvedPalette) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_string(), Style::default().fg(p.muted)),
        Span::styled(format!("  {count}"), Style::default().fg(p.faint)),
    ])
}

fn render_right_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let body = render_pane_header(frame, area, "Workspace", app.focus == Focus::Right, d, g);
    let mut lines: Vec<Line> = vec![Line::from("")];

    let w = &app.workspace;
    if w.plan.is_empty() && w.findings.is_empty() && w.verification.is_empty() {
        // Backend hasn't filled it yet (PR-F).
        lines.push(Line::from(vec![Span::styled(
            "(workspace empty — PR-F wires the bridge)",
            Style::default().fg(p.faint),
        )]));
    } else {
        // ── Phase stepper (§6.10) ──────────────────────────────────────────
        // ✓━━✓━━◉──◌──◌  execute  3/5
        let current = w.phase_index.min(4);
        let mut stepper: Vec<Span> = Vec::new();
        for i in 0..5 {
            let color = if i < current {
                p.muted
            } else if i == current {
                p.cyan
            } else {
                p.faint
            };
            let ch = if i < current {
                g.done.to_string()
            } else {
                ["◉", "◌", "◌"][(i - current).min(2)].to_string()
            };
            let weight = if i == current {
                Style::default().fg(p.cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };
            stepper.push(Span::styled(ch, weight));
            if i < 4 {
                let connector = if i < current { "━━" } else { "──" };
                let c_color = if i < current { p.muted } else { p.faint };
                stepper.push(Span::styled(connector, Style::default().fg(c_color)));
            }
        }
        let phase_names = ["orient", "reason", "act", "verify", "respond"];
        let mut header = stepper;
        header.push(Span::raw(" "));
        header.push(Span::styled(
            phase_names[current],
            Style::default().fg(p.cyan).add_modifier(Modifier::BOLD),
        ));
        header.push(Span::styled(
            format!("  {}/5", current + 1),
            Style::default().fg(p.faint),
        ));
        lines.push(Line::from(header));
        lines.push(Line::from(""));

        // ── Section helper ────────────────────────────────────────────────

        // PLAN
        if !w.plan.is_empty() {
            lines.push(section_line("PLAN", w.plan.len(), p));
            for task in &w.plan {
                let (glyph, color, bold) = match task.state {
                    TaskState::Active => ("●", p.cyan, true),
                    TaskState::Blocked => (g.blocked, p.amber, false),
                    TaskState::Failed => (g.failed, p.red, false),
                    TaskState::Retest => (g.retest, p.amber, false),
                    TaskState::AwaitingApproval => ("◇", p.magenta, false),
                    TaskState::Done => (g.done, p.muted, false),
                };
                let mut title_style = Style::default().fg(p.ink);
                if bold {
                    title_style = title_style.add_modifier(Modifier::BOLD);
                }
                let evidence = if task.evidence > 0 {
                    format!(
                        "  {} proof{}",
                        task.evidence,
                        if task.evidence == 1 { "" } else { "s" }
                    )
                } else {
                    "  claimed".to_string()
                };
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(format!("{glyph} "), Style::default().fg(color)),
                    Span::styled(task.title.clone(), title_style),
                    Span::styled(
                        evidence,
                        Style::default().fg(if task.evidence > 0 { p.green } else { p.faint }),
                    ),
                ]));
                if let Some(sub) = &task.sub {
                    let sub_color = match task.state {
                        TaskState::Active => p.cyan,
                        TaskState::Failed => p.red,
                        TaskState::Blocked | TaskState::Retest => p.amber,
                        TaskState::AwaitingApproval => p.muted,
                        TaskState::Done => p.faint,
                    };
                    lines.push(Line::from(vec![
                        Span::styled("      ", Style::default()),
                        Span::styled(sub.clone(), Style::default().fg(sub_color)),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }

        // FINDINGS
        if !w.findings.is_empty() {
            lines.push(section_line("FINDINGS", w.findings.len(), p));
            for f in &w.findings {
                let source = f
                    .source
                    .as_deref()
                    .map(|s| format!(" {s}"))
                    .unwrap_or_default();
                lines.push(Line::from(vec![
                    Span::styled("  ∙ ", Style::default().fg(p.faint)),
                    Span::styled(f.title.clone(), Style::default().fg(p.ink2)),
                    Span::styled(source, Style::default().fg(p.faint)),
                ]));
            }
            lines.push(Line::from(""));
        }

        // VERIFICATION
        if !w.verification.is_empty() {
            lines.push(section_line("VERIFICATION", w.verification.len(), p));
            for v in &w.verification {
                let (glyph, color) = match v.result {
                    VerificationResult::Passed => (g.done, p.green),
                    VerificationResult::Failed => (g.failed, p.red),
                    VerificationResult::Pending => ("◌", p.faint),
                };
                let proof = if v.proof_count > 0 {
                    format!(
                        "  {} proof{}",
                        v.proof_count,
                        if v.proof_count == 1 { "" } else { "s" }
                    )
                } else {
                    "  claimed".to_string()
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {glyph} "), Style::default().fg(color)),
                    Span::styled(v.name.clone(), Style::default().fg(p.ink2)),
                    Span::styled(proof, Style::default().fg(p.faint)),
                ]));
            }
        }
    }

    frame.render_widget(Paragraph::new(lines), body);
}

/// The command palette overlay (§6.13): 78 columns (or W−8), top edge on
/// row 5, rule_hi rounded frame, surface2 fill, query row with a magenta ›,
/// sections, fuzzy-matched chars in magenta bold, the selected row in wash
/// with a ▌. No backdrop dimming; open and close are instant.
fn render_palette(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let w = 78u16.min(area.width.saturating_sub(8));
    let h = 16u16.min(area.height.saturating_sub(8));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = 5u16.min(area.height.saturating_sub(h));
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };

    // Clear the underlying cells first — the overlay must fully cover
    // whatever is beneath it (§6.13: no bleed-through).
    frame.render_widget(ratatui::widgets::Clear, rect);
    // Frame: rounded, rule_hi, surface2 fill.
    let block = Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(p.rule_hi))
        .style(Style::default().bg(p.surface2));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let mut lines: Vec<Line> = Vec::new();

    // Query row: magenta › + the query + esc close on the right.
    let esc_note = "esc close";
    // › + space + query + padding + esc note must fit inner.width.
    let used = 2 + app.palette.query.chars().count();
    let query_space = (inner.width as usize).saturating_sub(used + esc_note.len());
    lines.push(Line::from(vec![
        Span::styled(format!("{} ", g.you), Style::default().fg(p.magenta)),
        Span::styled(
            format!("{}{}", app.palette.query, " ".repeat(query_space)),
            Style::default().fg(p.ink),
        ),
        Span::styled(esc_note.to_string(), Style::default().fg(p.faint)),
    ]));
    // Hairline.
    lines.push(Line::from(Span::styled(
        "─".repeat(inner.width as usize),
        Style::default().fg(p.rule),
    )));

    // COMMANDS section.
    let commands = crate::state::filtered_commands(&app.palette.query);
    lines.push(Line::from(vec![
        Span::styled("COMMANDS", Style::default().fg(p.muted)),
        Span::styled(
            format!("  {}", commands.len()),
            Style::default().fg(p.faint),
        ),
    ]));

    // Rows: label with fuzzy-matched chars in magenta bold, description in
    // muted at column 22, hint on the right. Selected row: wash + ▌.
    for (i, cmd) in commands.iter().enumerate() {
        let selected = i == app.palette.selected;
        // Fuzzy match positions in the label.
        let matched = fuzzy_positions(&cmd.label, &app.palette.query);
        let mut label_spans: Vec<Span> = Vec::new();
        for (ci, ch) in cmd.label.chars().enumerate() {
            let is_match = matched.contains(&ci);
            let mut style = if is_match {
                Style::default().fg(p.magenta).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.ink2)
            };
            if selected {
                style = style.bg(p.wash);
            }
            label_spans.push(Span::styled(ch.to_string(), style));
        }
        let desc_pad = 22usize.saturating_sub(cmd.label.chars().count() + 2);
        let mut row: Vec<Span> = vec![Span::styled(
            if selected { "▌ " } else { "  " },
            Style::default().fg(if selected { p.magenta } else { p.faint }),
        )];
        row.extend(label_spans);
        row.push(Span::styled(
            format!("{}{}", " ".repeat(desc_pad), cmd.description),
            Style::default()
                .fg(p.muted)
                .bg(if selected { p.wash } else { p.surface2 }),
        ));
        lines.push(Line::from(row));
    }

    // Footer of keys.
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "↑↓ select · enter run · esc close",
        Style::default().fg(p.faint),
    )]));

    frame.render_widget(
        Paragraph::new(lines).style(Style::default().bg(p.surface2)),
        inner,
    );
}

/// Positions in `text` matched by the fuzzy `query` (subsequence).
fn fuzzy_positions(text: &str, query: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let hay: Vec<char> = text.to_lowercase().chars().collect();
    let mut qi = 0;
    for (i, c) in hay.iter().enumerate() {
        if qi < query.len()
            && *c
                == query
                    .chars()
                    .nth(qi)
                    .unwrap()
                    .to_lowercase()
                    .next()
                    .unwrap()
        {
            positions.push(i);
            qi += 1;
        }
    }
    positions
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    // Left side: the compact mark (the working star while ORBIT works — the
    // only moving cell), then the dynamic state.
    let mark =
        if matches!(app.logo_phase, LogoPhase::Working) || app.tool_state == ToolState::Streaming {
            g.working()[app.spinner_frame as usize % 4]
        } else {
            g.orbit
        };
    let tool_state = match &app.tool_state {
        ToolState::Idle => Span::styled("idle", Style::default().fg(p.muted)),
        ToolState::Streaming => Span::styled("streaming", Style::default().fg(p.cyan)),
        ToolState::AwaitingApproval => Span::styled(
            format!("{} approval", g.decision),
            Style::default().fg(p.magenta),
        ),
        ToolState::Running(name) => Span::styled(
            format!("{} {name}", g.running,),
            Style::default().fg(p.cyan),
        ),
        ToolState::AutoGranted(name) => Span::styled(
            format!("{} auto({name})", g.allowed_session),
            Style::default().fg(p.muted),
        ),
    };
    let conn = match app.connection {
        ConnectionState::Online => Span::styled(
            format!("{} online", g.conn_online),
            Style::default().fg(p.green),
        ),
        ConnectionState::Reconnecting => Span::styled(
            format!("{} reconnect", g.conn_retrying),
            Style::default().fg(p.amber),
        ),
        ConnectionState::Offline => Span::styled(
            format!("{} offline", g.conn_offline),
            Style::default().fg(p.red),
        ),
    };

    let tokens = format!(
        "{}{} {}{}",
        g.tokens_down,
        format_count(app.total_input_tokens),
        g.tokens_up,
        format_count(app.total_output_tokens)
    );

    let cost = app.total_cost_microcents;
    let cost_str = format!("${}.{:06}", cost / 1_000_000, cost % 1_000_000);

    let sep = Span::styled(" ", Style::default());
    let mut spans = vec![
        Span::styled(mark, Style::default().fg(p.magenta)),
        sep.clone(),
        Span::styled(&app.model, Style::default().fg(p.ink2)),
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        Span::styled(&app.provider, Style::default().fg(p.muted)),
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        Span::styled(&app.session_id_prefix, Style::default().fg(p.faint)),
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        tool_state,
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        conn,
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        Span::styled(tokens, Style::default().fg(p.muted)),
        Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint)),
        Span::styled(cost_str, Style::default().fg(p.ink2)),
    ];
    if !app.last_status.is_empty() {
        spans.push(Span::styled(
            format!(" {} ", g.sep),
            Style::default().fg(p.faint),
        ));
        spans.push(Span::styled(&app.last_status, Style::default().fg(p.muted)));
    }
    frame.render_widget(Line::from(spans), area);
}

/// Format a count with k/M/B suffixes: 1_234 → "1.2k".
pub fn format_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

// ── Overlays — the only frames (§1, §6.16) ───────────────────────────────────

/// A one-colour rounded frame for overlays (§4.2): magenta for approvals
/// (ORBIT asking for your authority), rule_hi for confirmations. Built from
/// glyph constants — never the ┌┐ set, never double-line.
fn overlay_block<'a>(title: &'a str, color: Color, g: &Glyphs) -> Block<'a> {
    use ratatui::symbols::border;
    let set = border::Set {
        top_left: g.frame_top_left,
        top_right: g.frame_top_right,
        bottom_left: g.frame_bottom_left,
        bottom_right: g.frame_bottom_right,
        vertical_left: g.frame_left,
        vertical_right: g.frame_right,
        horizontal_top: g.frame_top,
        horizontal_bottom: g.frame_bottom,
    };
    Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_set(set)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

/// Quit confirmation — a small solid card, NO backdrop dimming (§12).
fn render_quit_modal(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let is_running =
        app.tool_state == ToolState::Streaming || matches!(app.tool_state, ToolState::Running(_));
    let title = if is_running {
        "Still running — quit?"
    } else {
        "Quit ORBIT?"
    };
    let message = if is_running {
        "A response is still running. Quit anyway?"
    } else {
        "Are you sure you want to quit?"
    };

    let modal = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(6),
            Constraint::Min(1),
        ])
        .split(area);
    let modal_h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(10),
            Constraint::Percentage(50),
            Constraint::Min(10),
        ])
        .split(modal[1]);

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![Span::styled(message, Style::default().fg(p.ink))]),
        Line::from(""),
        Line::from(vec![
            Span::styled("y", Style::default().fg(p.magenta)),
            Span::styled(" quit   ", Style::default().fg(p.muted)),
            Span::styled("n", Style::default().fg(p.magenta)),
            Span::styled(" stay", Style::default().fg(p.muted)),
        ]),
    ])
    .block(overlay_block(title, d.palette.rule_hi, g));
    frame.render_widget(content, modal_h[1]);
}

/// The approval card (§6.15): docked at the bottom of the conversation,
/// full conversation width, the ONLY magenta frame on screen. The request
/// is ORBIT asking for your authority — it wears the brand colour, not a
/// warning colour, and never looks like an OS error dialog.
///
/// Facts arrive only from structured backend data; today the request
/// carries tool name + summary, so the card renders those and the keys row.
/// The risk badge, facts grid, and scroll-to-review land with the backend
/// `risk` field (the one field this design can't draw without).
fn render_approval_modal(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    let first = &app.pending_approvals[0];

    // Docked at the bottom of the conversation area: full width minus
    // 1-column margins, height by content.
    let queue_note = if app.pending_approvals.len() > 1 {
        format!("{} of {}", 1, app.pending_approvals.len())
    } else {
        String::new()
    };
    let height = 8u16;
    let dock = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(height)])
        .split(area);
    let dock_h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(dock[1]);

    let badge = g.risk_meter(first.risk);
    let title = if queue_note.is_empty() {
        format!("Allow {}? {badge}", first.tool_name)
    } else {
        format!("Allow {}? {badge} · {queue_note}", first.tool_name)
    };

    let summary = if app.pending_approvals.len() > 1 {
        format!(
            "{} (+{} more)",
            first.summary,
            app.pending_approvals.len() - 1
        )
    } else {
        first.summary.clone()
    };

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                &first.tool_name,
                Style::default().fg(p.ink).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(&summary, Style::default().fg(p.ink2)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  y", Style::default().fg(p.magenta)),
            Span::styled(" allow once   ", Style::default().fg(p.muted)),
            Span::styled("R", Style::default().fg(p.magenta)),
            Span::styled(
                format!(" allow {} this session   ", first.tool_name),
                Style::default().fg(p.muted),
            ),
            Span::styled("n/esc", Style::default().fg(p.magenta)),
            Span::styled(" deny", Style::default().fg(p.muted)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            // [GPT-AMEND 4] the post-decision honesty line.
            Span::styled(
                "Action not executed · no option is preselected",
                Style::default().fg(p.faint),
            ),
        ]),
    ])
    .block(overlay_block(&title, p.magenta, g));
    frame.render_widget(content, dock_h[1]);
}

// ── Startup / empty-state mark (§8) ──────────────────────────────────────────

/// The expanded mark (§8.1): half-block letterforms, a braille ring tilted
/// behind the strokes, the star at the ring's upper right, the tagline
/// beneath. Static — motion lives in the status line's working star alone.
///
/// Letters are ink, the ring magenta_dim, the star magenta, the tagline
/// muted. It appears only on the welcome screen of an empty session; the
/// first turn replaces it.
pub fn welcome_mark(d: &Design, _g: &Glyphs) -> Vec<Line<'static>> {
    let p = &d.palette;
    // 3 rows × 31 columns (§8.1). The ring is braille dots; where it crosses
    // a letterform stroke it hides (the letterform wins).
    let row0 = "    ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀";
    let row1 = " ⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █";
    let row2 = " ⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █";
    let tagline = "    the harness that orbits around you";
    let mark_line = |row: &str| -> Line<'static> {
        // Split each row into ring cells (braille) vs letter cells (blocks):
        // braille → magenta_dim, blocks → ink, the star → magenta.
        let spans: Vec<Span> = row
            .chars()
            .map(|c| {
                let color = if c == '✦' {
                    p.magenta
                } else if c.is_ascii_alphanumeric() || "▄▀█".contains(c) {
                    p.ink
                } else {
                    p.magenta_dim // braille ring + spaces ride the dim colour
                };
                Span::styled(c.to_string(), Style::default().fg(color))
            })
            .collect();
        Line::from(spans)
    };
    vec![
        mark_line(row0),
        mark_line(row1),
        mark_line(row2),
        Line::from(Span::styled(
            tagline.to_string(),
            Style::default().fg(p.muted),
        )),
    ]
}
