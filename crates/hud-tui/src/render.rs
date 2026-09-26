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
use ratatui::widgets::{Block, Paragraph, Wrap};

// ── Pane headers (§6.1) ──────────────────────────────────────────────────────

/// One-row pane header: title, then a hairline rule filling the rest of the
/// row. The focused pane gets a heavy rule (`━`, rule_hi) and a magenta
/// title; unfocused panes get a light rule (`─`, rule) and an ink2 title.


/// Render a bordered pane (herdr-style): a full Block border with the title
/// riding the top edge. The focused pane's border is the accent; unfocused
/// panes get the muted rule colour. Returns the inner content rect.
fn render_pane_frame(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
    g: &Glyphs,
) -> Rect {
    let p = &d.palette;
    // Focus is the tmux active-tab convention: the focused pane's title is
    // a FILLED chip (magenta bg, canvas-ink text, bold) riding the top
    // border — unmistakable at any size, and still "a word" of magenta
    // (§1). The borders stay quiet (rule / rule_hi); the chip carries the
    // focus. In mono the chip falls back to reversed video (the third
    // signal, §1) because a Reset bg fill would be invisible.
    let (border_color, title_style) = if focused {
        let mut chip = Style::default().fg(p.bg).bg(p.magenta);
        if d.caps.color == crate::tokens::ColorTier::Mono {
            // Mono: magenta resolves to Reset, so the bg fill vanishes.
            // Reversed video gives the same solid-block read.
            chip = Style::default().fg(p.magenta).add_modifier(Modifier::REVERSED);
        }
        (p.rule_hi, chip.add_modifier(Modifier::BOLD))
    } else {
        (p.rule, Style::default().fg(p.ink2))
    };
    // The ASCII tier keeps every chrome cell printable ASCII (§13.5):
    // ratatui's Plain border set is unicode, so the ASCII tier draws its
    // own + - | frame.
    if g.set() == crate::tokens::GlyphSet::Ascii {
        // ratatui Plain borders are unicode; the ASCII tier draws its own
        // + - | frame (invariant_ascii_tier_is_ascii, §13.5).
        let inner = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };
        draw_ascii_pane_border(frame, area, &title, border_color, title_style, g);
        return inner;
    }
    let block = Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(format!(" {title} "), title_style));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

/// ASCII-tier pane border: + corners, - horizontal, | vertical.
fn draw_ascii_pane_border(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    color: ratatui::style::Color,
    title_style: Style,
    g: &Glyphs,
) {
    if area.width < 2 || area.height < 2 {
        return;
    }
    let buf = frame.buffer_mut();
    let style = Style::default().fg(color);
    // The ASCII-tier border uses the rounded-corner glyphs (╭ ╯) when
    // the terminal renders unicode; if it doesn't, those cells fall back
    // to + / - / | by the user's terminal. The intent is to look modern
    // even in the safe tier.
    let tl = g.corner_tl();
    let tr = g.corner_tr();
    let bl = g.corner_bl();
    let br = g.corner_br();
    let h = g.border_h();
    let v = g.border_v();
    let title_text = format!(" {title} ");
    let title_w = title_text.chars().count() as u16;
    let mut top = String::new();
    top.push_str(tl);
    let title_start = 1;
    let title_end = (title_start + title_w).min(area.width - 1);
    for x in 1..(area.width - 1) {
        if x >= title_start && x < title_end {
            let idx = (x - title_start) as usize;
            if idx < title_text.chars().count() {
                top.push(title_text.chars().nth(idx).unwrap());
            } else {
                top.push_str(h);
            }
        } else {
            top.push_str(h);
        }
    }
    top.push_str(tr);
    buf.set_stringn(area.x, area.y, &top, area.width as usize, style);
    // Title styling: overwrite the title chars with the title style
    buf.set_stringn(
        area.x + 1,
        area.y,
        &title_text,
        title_w as usize,
        title_style,
    );
    // Bottom — rounded corners to match the top.
    let bottom = format!("{bl}{}{br}", h.repeat((area.width - 2) as usize));
    buf.set_stringn(
        area.x,
        area.y + area.height - 1,
        &bottom,
        area.width as usize,
        style,
    );
    // Sides
    for y in 1..(area.height - 1) {
        buf.set_stringn(area.x, area.y + y, v, 1, style);
        buf.set_stringn(area.x + area.width - 1, area.y + y, v, 1, style);
    }
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
    // herdr-style: three bordered panes, no divider columns — the pane
    // borders ARE the separation. A 1-col gap between panes keeps the
    // borders from doubling up. Rails collapse responsively on narrow
    // terminals (the conversation always keeps ≥40 cols): full rails ≥120,
    // right rail drops 100-119, left drops 80-99, single pane <80.
    let total = area.width;
    let (left_w, right_w) = if total >= 120 {
        (d.layout_rails.0, d.layout_rails.1)
    } else if total >= 100 {
        // Right rail shrinks to fit; the conversation keeps ≥40.
        (d.layout_rails.0, (total - d.layout_rails.0 - 44).max(0))
    } else if total >= 80 {
        // Both rails compact: 18/22 keeps the center ≥36 at 80 cols.
        (18, 22)
    } else {
        (0, 0)
    };
    let mut constraints = Vec::new();
    if left_w > 0 {
        constraints.push(Constraint::Length(left_w));
        constraints.push(Constraint::Length(1)); // gap
    }
    constraints.push(Constraint::Min(10)); // conversation
    if right_w > 0 {
        constraints.push(Constraint::Length(1)); // gap
        constraints.push(Constraint::Length(right_w));
    }
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(outer[0]);

    // Pane slots depend on which rails are present.
    // Record the pane rects for the mouse hit-test (interior mutability —
    // the renderer sees &App).
    app.pane_rects.left.set(if left_w > 0 { Some(main[0]) } else { None });
    app.pane_rects.center.set(Some(main[if left_w > 0 { 2 } else { 0 }]));
    app.pane_rects
        .right
        .set(if right_w > 0 { Some(main[main.len() - 1]) } else { None });

    // Zoom (herdr-style): the zoomed pane fills the whole surface.
    if let Some(zoomed) = app.zoomed_pane {
        match zoomed {
            Focus::Left => render_left_pane(frame, outer[0], app, d, g),
            Focus::Center => render_center_pane(frame, outer[0], app, composer_text, d, g),
            Focus::Right => render_right_pane(frame, outer[0], app, d, g),
            _ => {}
        }
        render_status_bar(frame, outer[1], app, d, g);
        return;
    }
    let mut idx = 0;
    if left_w > 0 {
        render_left_pane(frame, main[idx], app, d, g);
        idx += 2; // rail + gap
    }
    render_center_pane(frame, main[idx], app, composer_text, d, g);
    if right_w > 0 {
        render_right_pane(frame, main[idx + 2], app, d, g); // gap + rail
    }

    // Per-pane selection highlight (herdr-style): paint the selected cells
    // INSIDE the owning pane only — the pane boundary is the isolation
    // boundary.
    if let Some(sel) = &app.selection {
        if sel.is_visible() {
            let rect = match sel.pane {
                Focus::Left => app.pane_rects.left.get(),
                Focus::Center => app.pane_rects.center.get(),
                Focus::Right => app.pane_rects.right.get(),
                _ => None,
            };
            if let Some(rect) = rect {
                let inner = ratatui::layout::Rect {
                    x: rect.x + 1,
                    y: rect.y + 1,
                    width: rect.width.saturating_sub(2),
                    height: rect.height.saturating_sub(2),
                };
                let buf = frame.buffer_mut();
                for row in 0..inner.height {
                    for col in 0..inner.width {
                        if sel.contains(row, col) {
                            let cell = &mut buf[(inner.x + col, inner.y + row)];
                            let fg = cell.style().fg.unwrap_or(d.palette.ink);
                            cell.set_style(
                                Style::default()
                                    .fg(fg)
                                    .bg(d.palette.magenta_dim),
                            );
                        }
                    }
                }
            }
        }
    }
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
    if app.help_open {
        render_help_overlay(frame, area, app, d, g);
    }
    if !app.pending_approvals.is_empty() {
        // Docked inside the pane area (outer[0]) — never collides with the
        // status line.
        render_approval_modal(frame, outer[0], app, d, g);
    }
}

// ── Divider / scrollbar (§6.14) ──────────────────────────────────────────────

/// Full-height divider `│`; when the transcript overflows, the center
/// divider becomes a scroll track with a `┃` thumb at the transcript's

// ── Left rail (§6.9) ─────────────────────────────────────────────────────────

fn render_left_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Activity",
    };
    let body = render_pane_frame(frame, area, title, app.focus == Focus::Left, d, g);

    // One blank row of breathing room below the top border (matches the
    // transcript's padding).
    let mut lines: Vec<Line> = vec![Line::from("")];

    match app.left_tab {
        LeftTab::Sessions => {
            // ── Session block ──
            let conn_glyph = match app.connection {
                ConnectionState::Online => (g.conn_online, p.green),
                ConnectionState::Reconnecting => (g.conn_retrying, p.amber),
                ConnectionState::Offline => (g.conn_offline, p.red),
            };
            lines.push(Line::from(vec![
                Span::styled(conn_glyph.0, Style::default().fg(conn_glyph.1)),
                Span::raw(" "),
                Span::styled(&app.session_id_prefix, Style::default().fg(p.ink)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("model ", Style::default().fg(p.muted)),
                Span::styled(&app.model, Style::default().fg(p.ink2)),
            ]));
            lines.push(Line::from(""));

            // ── Usage block (herdr shows tokens per agent) ──
            lines.push(section_label("USAGE", p));
            lines.push(Line::from(vec![
                Span::styled("turns ", Style::default().fg(p.muted)),
                Span::styled(
                    app.total_turns.to_string(),
                    Style::default().fg(p.ink2),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("in    ", Style::default().fg(p.muted)),
                Span::styled(
                    format_tokens(app.total_input_tokens),
                    Style::default().fg(p.ink2),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("out   ", Style::default().fg(p.muted)),
                Span::styled(
                    format_tokens(app.total_output_tokens),
                    Style::default().fg(p.ink2),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("cost  ", Style::default().fg(p.muted)),
                Span::styled(
                    format!("${:.4}", app.total_cost_microcents as f64 / 1_000_000.0),
                    Style::default().fg(p.ink2),
                ),
            ]));
            lines.push(Line::from(""));

            // ── Queue block ──
            if !app.queued.is_empty() {
                lines.push(section_label("QUEUED", p));
                for (i, q) in app.queued.iter().enumerate() {
                    let shown: String = q.chars().take(body.width as usize - 4).collect();
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("{} ", i + 1),
                            Style::default().fg(p.faint),
                        ),
                        Span::styled(shown, Style::default().fg(p.ink2)),
                    ]));
                }
                lines.push(Line::from(""));
            }

            // ── Keys hint: the three essentials; ? shows the full map ──
            lines.push(section_label("KEYS", p));
            for (k, v) in [
                ("Tab", "cycle panes"),
                ("Z", "zoom pane"),
                ("?", "all keys"),
            ] {
                lines.push(Line::from(vec![
                    Span::styled(format!("{k:<8}"), Style::default().fg(p.ink2)),
                    Span::styled(v, Style::default().fg(p.muted)),
                ]));
            }
        }
        LeftTab::Verbose => {
            if app.in_flight.is_empty() {
                lines.push(Line::from(Span::styled(
                    "(no active stream)",
                    Style::default().fg(p.faint),
                )));
            } else {
                // The live stream, wrapped to the rail width.
                let width = body.width as usize;
                let mut row = String::new();
                for ch in app.in_flight.chars() {
                    if row.chars().count() >= width {
                        lines.push(Line::from(Span::styled(
                            row.clone(),
                            Style::default().fg(p.ink2),
                        )));
                        row.clear();
                    }
                    row.push(ch);
                }
                if !row.is_empty() {
                    lines.push(Line::from(Span::styled(
                        row,
                        Style::default().fg(p.ink2),
                    )));
                }
            }
        }
    }

    // Per-pane scroll (functional isolation).
    let para = Paragraph::new(lines).scroll((app.pane_scroll[0], 0));
    frame.render_widget(para, body);
}

/// A small caps section label with a rule — the visual rhythm anchor.
fn section_label(text: &str, p: &crate::tokens::ResolvedPalette) -> Line<'static> {
    Line::from(vec![
        Span::styled(text.to_string(), Style::default().fg(p.faint)),
        Span::styled(" ─", Style::default().fg(p.surface2)),
    ])
}

/// Compact token counts: 1234 → 1.2k.
fn format_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}m", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
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

    // The conversation gets the same bordered frame as the rails — the
    // three panes read as equal, isolated surfaces (herdr-style). The
    // title carries the session identity.
    // The center title is the conversation itself — session metadata
    // lives in the status line and the left rail (no duplication).
    let title = "Conversation".to_string();
    let area = render_pane_frame(frame, area, &title, app.focus == Focus::Center, d, g);

    // Split: transcript (fill) | queue | composer band.
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
    // One blank row of breathing room below the top border.
    let mut lines: Vec<Line> = vec![Line::from("")];
    if app.transcript.is_empty() && app.in_flight.is_empty() {
        let mark = welcome_mark_frame(d, app.startup_frame);
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
                // The gutter rides the FIRST line (herdr-style) — no orphan
                // glyph row. Continuation lines align under the text.
                let mut first = true;
                for line in text.lines() {
                    if first {
                        lines.push(Line::from(vec![
                            user_gutter(),
                            Span::styled(line, Style::default().fg(p.ink)),
                        ]));
                        first = false;
                    } else {
                        lines.push(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(line, Style::default().fg(p.ink)),
                        ]));
                    }
                }
                if first {
                    // Empty user message: still show the gutter.
                    lines.push(Line::from(user_gutter()));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Assistant(text) => {
                // Same: the ✦ rides the first rendered line.
                let mut first = true;
                for rich_line in render_message(text, d) {
                    let mut spans = Vec::new();
                    if first {
                        spans.push(orbit_gutter(false));
                        first = false;
                    } else {
                        spans.push(Span::raw("   "));
                    }
                    spans.extend(rich_line.spans);
                    lines.push(Line::from(spans));
                }
                if first {
                    lines.push(Line::from(orbit_gutter(false)));
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
        // The gutter rides the first line (no orphan ✦ row).
        let mut first = true;
        for rich_line in render_message(&app.in_flight, d) {
            let mut spans = Vec::new();
            if first {
                spans.push(orbit_gutter(true));
                first = false;
            } else {
                spans.push(Span::raw("   "));
            }
            spans.extend(rich_line.spans);
            lines.push(Line::from(spans));
        }
        if first {
            lines.push(Line::from(orbit_gutter(true)));
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
        app.pane_scroll[1] as usize
    } else {
        total_lines.saturating_sub(visible_height)
    };

    let transcript = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll as u16, 0));
    frame.render_widget(transcript, center[0]);

    // ── Queue + toast: pending prompts left, the §6.12 toast right ────────
    let mut queue_rows = Vec::new();
    for q in &app.queued {
        queue_rows.push(Line::from(vec![
            Span::styled(format!("{} ", g.pending), Style::default().fg(p.faint)),
            Span::styled(truncate_graphemes(q, 40), Style::default().fg(p.muted)),
        ]));
    }
    if let Some(toast) = &app.toast {
        // The toast rides the queue row, right-aligned: ✓ text (green) /
        // plain text (muted) / ✕ text (red). Never floats over content.
        let (glyph, color) = match toast.kind {
            crate::state::ToastKind::Success => (g.done, p.green),
            crate::state::ToastKind::Neutral => ("", p.muted),
            crate::state::ToastKind::Error => (g.failed, p.red),
        };
        let text = if glyph.is_empty() {
            toast.text.clone()
        } else {
            format!("{glyph} {}", toast.text)
        };
        let text_w = crate::unicode::display_width(&text);
        let row = center[1].width as usize;
        let pad = row.saturating_sub(text_w + 2);
        let mut line = queue_rows.pop().unwrap_or_default();
        line.spans.push(Span::raw(" ".repeat(pad)));
        line.spans.push(Span::styled(text, Style::default().fg(color)));
        queue_rows.push(line);
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
    // Standard terminal blink cadence (~530 ms on, ~530 ms off).
    let cursor_on = !turn_live && (app.tick_count / 33).is_multiple_of(2);
    let cursor = if cursor_on { "▍" } else { " " };
    let first_text_line = composer_text.lines().next().unwrap_or("");
    let prompt_line = if composer_text.is_empty() {
        Line::from(vec![
            Span::styled(format!("{} ", g.you), Style::default().fg(prompt_color)),
            Span::styled("ask orbit", Style::default().fg(p.faint)),
            Span::styled(cursor, Style::default().fg(p.magenta)),
        ])
    } else {
        // The cursor rides the text end (a real terminal cursor) —
        // blinking only when the composer is focused and no turn is live.
        let mut spans = vec![
            Span::styled(format!("{} ", g.you), Style::default().fg(prompt_color)),
            Span::styled(first_text_line, Style::default().fg(p.ink)),
        ];
        if composer_focused && !turn_live {
            spans.push(Span::styled(cursor, Style::default().fg(p.magenta)));
        }
        Line::from(spans)
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
    let body = render_pane_frame(frame, area, "Workspace", app.focus == Focus::Right, d, g);
    // Two blank rows: border + breathing room.
    let mut lines: Vec<Line> = vec![Line::from(""), Line::from("")];

    let w = &app.workspace;
    if w.plan.is_empty() && w.findings.is_empty() && w.verification.is_empty() {
        // A useful empty state: what WILL appear here + how to drive it.
        for text in [
            "The turn's plan, findings, and",
            "verification land here as the",
            "model works.",
            "",
            "Phases: orient → reason → act →",
            "verify → respond",
        ] {
            lines.push(Line::from(Span::styled(
                text,
                Style::default().fg(p.faint),
            )));
        }
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
                    // Tail-truncate: paths and status strings matter at the
                    // END, so keep the tail and drop the head.
                    let budget = body.width.saturating_sub(2) as usize;
                    let shown = if sub.chars().count() > budget {
                        let skip = sub.chars().count() - budget;
                        format!("…{}", sub.chars().skip(skip).collect::<String>())
                    } else {
                        sub.clone()
                    };
                    lines.push(Line::from(vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(shown, Style::default().fg(sub_color)),
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

    // Per-pane scroll (functional isolation): the workspace rail scrolls
    // independently.
    let para = Paragraph::new(lines).scroll((app.pane_scroll[2], 0));
    frame.render_widget(para, body);
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
    // The status line rides a surface2 bar — the bottom zone anchor.
    frame.render_widget(
        ratatui::widgets::Block::default().style(Style::default().bg(p.surface2)),
        area,
    );
    // Left side: the compact mark (the working star while ORBIT works — the
    // only moving cell), then the dynamic state.
    let mark =
        if matches!(app.logo_phase, LogoPhase::Working) || app.tool_state == ToolState::Streaming {
            g.working()[app.spinner_frame as usize % 4]
        } else {
            g.orbit
        };
    // Mode chip (the multiplexer pattern): INSERT is silent (the default —
    // type to talk); the other modes show a chip so the operator knows
    // which input model is live (herdr shows PREFIX/COPY the same way).
    // Zoom chip: when a pane is zoomed, say so (herdr shows zoom in the
    // tab bar; ORBIT's status line is the equivalent).
    let zoom_chip = if app.zoomed_pane.is_some() {
        Span::styled(" ZOOM ", Style::default().fg(p.bg).bg(p.green))
    } else {
        Span::raw("")
    };
    let mode_chip = match app.input_mode {
        crate::state::InputMode::Insert => Span::raw(""),
        crate::state::InputMode::Normal => {
            Span::styled(" NORMAL ", Style::default().fg(p.bg).bg(p.amber))
        }
        crate::state::InputMode::Prefix => {
            Span::styled(" PREFIX ", Style::default().fg(p.bg).bg(p.magenta))
        }
        crate::state::InputMode::Copy => {
            Span::styled(" COPY ", Style::default().fg(p.bg).bg(p.cyan))
        }
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

    // Two-zone status (herdr-style hierarchy): identity on the left,
    // live metrics on the right. The zones breathe — no wall of text.
    let sep = Span::styled(format!(" {} ", g.sep), Style::default().fg(p.faint));
    let mut left_spans = vec![
        Span::styled(mark, Style::default().fg(p.magenta)),
        Span::raw(" "),
        mode_chip,
        zoom_chip,
        Span::raw(" "),
        Span::styled(&app.model, Style::default().fg(p.ink2)),
        sep.clone(),
        Span::styled(&app.session_id_prefix, Style::default().fg(p.faint)),
    ];
    if !app.last_status.is_empty() {
        left_spans.push(sep.clone());
        left_spans.push(Span::styled(
            app.last_status.clone(),
            Style::default().fg(p.muted),
        ));
    }
    // §6.11 M5: the turn report rides the left side for 2 s.
    if let Some(r) = &app.turn_report {
        let secs = r.duration_ms as f64 / 1000.0;
        let cost = format!("+${:.4}", r.cost_microcents as f64 / 1_000_000.0);
        let tools = if r.tool_count == 1 {
            "1 tool".to_string()
        } else {
            format!("{} tools", r.tool_count)
        };
        left_spans.push(sep.clone());
        left_spans.push(Span::styled(
            format!("✓ done · {secs:.0}s · {tools} · {cost}"),
            Style::default().fg(p.green),
        ));
    }
    let right_spans = vec![
        tool_state,
        sep.clone(),
        conn,
        sep.clone(),
        Span::styled(tokens, Style::default().fg(p.muted)),
        sep.clone(),
        Span::styled(cost_str, Style::default().fg(p.ink2)),
    ];
    // Measure and pad so the right zone hugs the right edge.
    let left_w: usize = left_spans
        .iter()
        .map(|sp| crate::unicode::display_width(&sp.to_string()))
        .sum();
    let right_w: usize = right_spans
        .iter()
        .map(|sp| crate::unicode::display_width(&sp.to_string()))
        .sum();
    let total_w = area.width as usize;
    let gap = total_w.saturating_sub(left_w + right_w);
    let mut spans = left_spans;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right_spans);
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(p.surface2)),
        area,
    );
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
    frame.render_widget(ratatui::widgets::Clear, modal_h[1]);
    frame.render_widget(content, modal_h[1]);
}

/// §6.16 help overlay: the same frame as quit, two columns of keys
/// grouped by pane. Any key closes it.
fn render_help_overlay(frame: &mut ratatui::Frame, area: Rect, _app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let w = 64u16.min(area.width.saturating_sub(8));
    let h = 20u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let block = overlay_block("Keys", p.rule_hi, g);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let key = |k: &str, v: &str| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("{k:<14}"), Style::default().fg(p.magenta)),
            Span::styled(v.to_string(), Style::default().fg(p.ink2)),
        ])
    };
    let label = |t: &str| -> Line<'static> {
        Line::from(Span::styled(t.to_string(), Style::default().fg(p.faint)))
    };

    let left = vec![
        label("CONVERSATION"),
        key("enter", "send the prompt"),
        key("esc", "normal mode"),
        key("i", "insert mode"),
        key("ctrl+b", "prefix mode"),
        key("ctrl+k", "clear composer"),
        key("ctrl+c", "quit (twice)"),
        Line::from(""),
        label("PANES"),
        key("tab", "cycle focus"),
        key("1 2 3", "jump to pane"),
        key("Z", "zoom the pane"),
        key("g g / G", "top / bottom"),
        key("j k / ↑↓", "scroll the pane"),
    ];
    let right = vec![
        label("MODES"),
        key("y", "yank (copy mode)"),
        key("?", "this help"),
        key("/", "command palette"),
        Line::from(""),
        label("RAILS"),
        key("g s", "sessions rail"),
        key("g v", "activity rail"),
        key("g w", "workspace rail"),
        Line::from(""),
        label("MOUSE"),
        key("drag", "select in a pane"),
        key("shift+click", "native selection"),
        key("wheel", "scroll the pane"),
    ];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);
    frame.render_widget(Paragraph::new(left), cols[0]);
    frame.render_widget(Paragraph::new(right), cols[1]);
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
    // Dock 1 row above the pane's bottom border so the modal's frame
    // never doubles with the pane's corners.
    let dock = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(height + 1)])
        .split(area);
    let dock_area = Rect {
        x: dock[1].x,
        y: dock[1].y,
        width: dock[1].width,
        height,
    };
    let dock_h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(dock_area);

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
    // Clear the underlying pane borders so the modal reads as a solid
    // surface, not a frame over frames.
    frame.render_widget(ratatui::widgets::Clear, dock_h[1]);
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
    welcome_mark_frame(d, u8::MAX)
}

/// The welcome mark at a startup frame (§8.3): 0 = O alone, 1 = ⅓ ring,
/// 2 = ⅔ ring, 3 = ring + star, 4 = RBIT fills, 5+ = tagline. u8::MAX =
/// the complete mark (the steady state).
pub fn welcome_mark_frame(d: &Design, frame: u8) -> Vec<Line<'static>> {
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
    // §8.3 frame masking: the reveal sweeps left-to-right across the mark
    // (the ring forming around the O), then the tagline. frame 0 shows
    // only the O (the first letterform); each frame reveals ~1/5 more.
    let reveal: usize = match frame {
        0 => 8,   // the O alone
        1 => 16,  // a third of the ring
        2 => 24,  // two thirds
        3 => 30,  // ring complete + star
        4 => 36,  // RBIT filled
        _ => usize::MAX, // tagline + hold
    };
    let mask = |row: &str| -> String {
        if reveal == usize::MAX {
            return row.to_string();
        }
        // Keep leading spaces so alignment never shifts; reveal N cells.
        let mut out = String::new();
        let mut shown = 0;
        for c in row.chars() {
            if c == ' ' {
                out.push(' ');
            } else if shown < reveal {
                out.push(c);
                shown += 1;
            } else {
                out.push(' ');
            }
        }
        out
    };
    let show_tagline = frame >= 5 || frame == u8::MAX;
    let mut out = vec![
        mark_line(&mask(row0)),
        mark_line(&mask(row1)),
        mark_line(&mask(row2)),
    ];
    if show_tagline {
        out.push(Line::from(Span::styled(
            tagline.to_string(),
            Style::default().fg(p.muted),
        )));
    }
    out
}
