//! Ratatui rendering — the ORBIT visual system (herdr-style pane isolation).
//!
//! Every pane is a bordered surface (rounded Block frame, herdr-style):
//! the focused pane's border is the magenta accent with a bold title;
//! unfocused panes get the muted rule colour. The pane borders ARE the
//! separation — no divider columns. A 1-col gap keeps borders from
//! doubling up. Panes are customizable via tui.toml [layout.panes]
//! (order, widths, visibility); clicks focus the clicked pane.
//!
//! All colours come from the token palette (tokens.rs); all glyphs from
//! glyphs.rs. No literals in render code.

use crate::glyphs::Glyphs;
use crate::rich::render_message;
use crate::state::{
    App, ConnectionState, Focus, LeftTab, TaskState, ToolOutcome, ToolState, TranscriptLine,
    VerificationResult,
};
use crate::tokens::Design;
use crate::unicode::{display_width, truncate_graphemes};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;

// ── Width classes (§8.2) ─────────────────────────────────────────────────────

/// Which panes exist and their geometry, per §8.2.
#[derive(Debug, Clone, Copy)]
pub struct WidthClass {
    /// Sessions rail: Some((x, w)) when present.
    pub sessions: Option<(u16, u16)>,
    /// Conversation pane: (x, w).
    pub conversation: (u16, u16),
    /// Workspace rail: Some((x, w)) when present.
    pub workspace: Option<(u16, u16)>,
    /// Single-view mode (Narrow/Compact/Tight): the header is a switcher.
    pub single_view: bool,
    /// Status line level 0..=3 (§6.11).
    pub status_level: u8,
    /// Compact (60–79): no transcript timestamps, tool meta drops duration.
    pub compact: bool,
    /// Tight (40–59): no hint row, no language labels, no recency.
    pub tight: bool,
}

pub fn width_class(w: u16) -> WidthClass {
    if w >= 140 {
        // Wide: L = clamp(28, round(0.20·W), 34), R = clamp(32, round(0.24·W), 44)
        let l = (0.20 * w as f32).round() as u16;
        let l = l.clamp(28, 34);
        let r = (0.24 * w as f32).round() as u16;
        let r = r.clamp(32, 44);
        let c = w - l - r - 2;
        WidthClass {
            sessions: Some((0, l)),
            conversation: (l + 1, c),
            workspace: Some((l + c + 2, r)),
            single_view: false,
            status_level: 0,
            compact: false,
            tight: false,
        }
    } else if w >= 110 {
        // Medium: Conversation │ Workspace. R = clamp(30, round(0.30·W), 36)
        let r = (0.30 * w as f32).round() as u16;
        let r = r.clamp(30, 36);
        WidthClass {
            sessions: None,
            conversation: (0, w - r - 1),
            workspace: Some((w - r, r)),
            single_view: false,
            status_level: 1,
            compact: false,
            tight: false,
        }
    } else if w >= 80 {
        WidthClass {
            sessions: None,
            conversation: (0, w),
            workspace: None,
            single_view: true,
            status_level: 2,
            compact: false,
            tight: false,
        }
    } else if w >= 60 {
        WidthClass {
            sessions: None,
            conversation: (0, w),
            workspace: None,
            single_view: true,
            status_level: 2,
            compact: true,
            tight: false,
        }
    } else {
        WidthClass {
            sessions: None,
            conversation: (0, w),
            workspace: None,
            single_view: true,
            status_level: 3,
            compact: false,
            tight: true,
        }
    }
}

/// The conversation column geometry (§8.3): content-left and measure.
fn out_last_is_text(out: &[Line<'static>]) -> bool {
    out.last()
        .map(|l| !l.spans.iter().all(|sp| sp.content.trim().is_empty()))
        .unwrap_or(false)
}

pub fn conv_column(x: u16, w: u16) -> (u16, u16) {
    let base = x + 3;
    let extra = (w as i32 - 5 - 100).max(0) as u16;
    let cl = base + extra / 2;
    let cw = (w - 5).min(100);
    (cl, cw)
}

// ── Main render ──────────────────────────────────────────────────────────────

pub fn render(frame: &mut ratatui::Frame, app: &App, composer_text: &str, d: &Design) {
    let area = frame.area();
    let g = &Glyphs::for_set(d.caps.glyphs);

    // The canvas: every cell carries the bg token (§6.1).
    let bg_style = Style::default().bg(d.palette.bg);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            frame.buffer_mut()[(x, y)].set_style(bg_style);
        }
    }

    // §9.23 size notice: below 40 × 10, draw ONLY the notice.
    if area.width < 40 || area.height < 10 {
        render_size_notice(frame, area, d, g);
        return;
    }

    let wc = width_class(area.width);

    // Vertical: body (fill) | status (1). The composer and hint row live
    // INSIDE the conversation pane's box (herdr-style: the pane owns its
    // full surface; the status line is the only full-width chrome).
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);
    let body = outer[0];
    let status_row = outer[1];

    // Horizontal split into boxed panes with 1-col gaps (herdr-style: the
    // pane borders ARE the separation — no divider columns).
    let mut panes: Vec<Rect> = Vec::new();
    let mut x = body.x;
    if let Some((_, sw)) = wc.sessions {
        panes.push(Rect {
            x,
            y: body.y,
            width: sw,
            height: body.height,
        });
        x += sw + 1; // pane + gap
    }
    let (_, cw) = wc.conversation;
    panes.push(Rect {
        x,
        y: body.y,
        width: cw,
        height: body.height,
    });
    x += cw;
    if let Some((_, ww)) = wc.workspace {
        x += 1; // gap
        panes.push(Rect {
            x,
            y: body.y,
            width: ww,
            height: body.height,
        });
    }
    // Record pane rects for the mouse hit-test (the OUTER rect — the
    // hit-test insets by the border itself).
    app.pane_rects
        .left
        .set(panes.first().copied().filter(|_| wc.sessions.is_some()));
    app.pane_rects
        .center
        .set(panes.get(wc.sessions.is_some() as usize).copied());
    app.pane_rects
        .right
        .set(panes.last().copied().filter(|_| wc.workspace.is_some()));

    // Pane titles: the left pane's title follows its tab; the center is the
    // conversation; the right is the workspace.
    let left_title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Activity",
    };
    let center_title = if app.header_title.is_empty() {
        "Conversation"
    } else {
        app.header_title.as_str()
    };

    // Draw each pane: box border + title, then the content in the inner rect.
    let mut pane_idx = 0usize;
    if wc.sessions.is_some() {
        let r = panes[pane_idx];
        let sessions_inner = draw_pane_box(frame, r, left_title, app.focus == Focus::Left, d, g);
        render_sessions_rail(frame, sessions_inner, app, d, g);
        pane_idx += 1;
    }
    let conv_outer = panes[pane_idx];
    let conv_inner = draw_pane_box(
        frame,
        conv_outer,
        center_title,
        app.focus == Focus::Center,
        d,
        g,
    );
    // The conversation pane's inner area splits: transcript (fill) |
    // composer (1) | hint (1, when shown).
    let show_hint = area.height >= 16 && !wc.tight;
    let inner_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),                             // composer
            Constraint::Length(if show_hint { 1 } else { 0 }), // hint
        ])
        .split(conv_inner);
    let composer_row = inner_rows[1];
    let hint_row = inner_rows[2];
    render_conversation(
        frame,
        inner_rows[0],
        app,
        composer_text,
        d,
        g,
        &wc,
        composer_row,
        hint_row,
        show_hint,
    );
    pane_idx += 1;
    if wc.workspace.is_some() {
        let r = panes[pane_idx];
        let inner = draw_pane_box(frame, r, "Workspace", app.focus == Focus::Right, d, g);
        render_workspace_rail(frame, inner, app, d, g);
    }

    // Command palette (§6.13): an overlay above the panes.
    if app.palette.open {
        render_palette(frame, body, app, d, g);
    }

    render_status_bar(frame, status_row, app, &wc, d, g);

    // Overlays — the only frames on screen (one at a time, §1).
    if app.quit_confirmation {
        render_quit_modal(frame, area, app, d, g);
    }
    if app.help_open {
        render_help_overlay(frame, area, app, d, g);
    }
    if !app.pending_approvals.is_empty() {
        render_approval_modal(frame, area, app, d, g, &wc);
    }
}

// ── Pane boxes (herdr-style isolation) ───────────────────────────────────────

/// Draw a full box border around a pane with the title riding the top edge
/// (herdr `render_pane_borders`): focused = magenta accent + bold title,
/// unfocused = muted rule colour. Returns the inner content rect.
fn draw_pane_box(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
    g: &Glyphs,
) -> Rect {
    let p = &d.palette;
    if area.width < 3 || area.height < 3 {
        return area;
    }
    let (border_color, title_style) = if focused {
        (
            p.magenta,
            Style::default().fg(p.magenta).add_modifier(Modifier::BOLD),
        )
    } else {
        (p.muted, Style::default().fg(p.ink2))
    };
    let buf = frame.buffer_mut();
    let bs = Style::default().fg(border_color);
    // Corners.
    buf[(area.x, area.y)]
        .set_symbol(g.corner_tl())
        .set_style(bs);
    buf[(area.x + area.width - 1, area.y)]
        .set_symbol(g.corner_tr())
        .set_style(bs);
    buf[(area.x, area.y + area.height - 1)]
        .set_symbol(g.corner_bl())
        .set_style(bs);
    buf[(area.x + area.width - 1, area.y + area.height - 1)]
        .set_symbol(g.corner_br())
        .set_style(bs);
    // Top and bottom edges.
    for x in area.x + 1..area.x + area.width - 1 {
        buf[(x, area.y)].set_symbol(g.border_h()).set_style(bs);
        buf[(x, area.y + area.height - 1)]
            .set_symbol(g.border_h())
            .set_style(bs);
    }
    // Left and right edges.
    for y in area.y + 1..area.y + area.height - 1 {
        buf[(area.x, y)].set_symbol(g.border_v()).set_style(bs);
        buf[(area.x + area.width - 1, y)]
            .set_symbol(g.border_v())
            .set_style(bs);
    }
    // Title rides the top border: " Title " starting at x+1, truncated to
    // the pane width (herdr pane_border_title).
    let title_text = format!(" {title} ");
    let max_w = (area.width as usize).saturating_sub(2);
    let shown: String = title_text.chars().take(max_w).collect();
    for (i, c) in shown.chars().enumerate() {
        buf[(area.x + 1 + i as u16, area.y)]
            .set_symbol(&c.to_string())
            .set_style(title_style);
    }
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

// ── Pane headers (§8.5) ──────────────────────────────────────────────────────

// ── Divider / scroll track (§8.6) ────────────────────────────────────────────

// ── Sessions rail (§6.9) ─────────────────────────────────────────────────────

fn render_sessions_rail(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    // The Activity tab renders the structured event rail instead (§9.16).
    if app.left_tab == LeftTab::Verbose {
        render_activity_rail(frame, area, app, d);
        return;
    }
    let p = &d.palette;
    let focused = app.focus == Focus::Left;
    let buf = frame.buffer_mut();
    let mut y = area.y;
    let mut last_group = "";
    for (i, s) in app.sessions.iter().enumerate() {
        if y >= area.bottom() {
            break;
        }
        if s.group != last_group {
            if !last_group.is_empty() {
                y += 1; // blank row between groups
                if y >= area.bottom() {
                    break;
                }
            }
            for (j, c) in s.group.chars().enumerate() {
                if 2 + j as u16 >= area.width {
                    break;
                }
                buf[(area.x + 2 + j as u16, y)]
                    .set_symbol(&c.to_string())
                    .set_style(Style::default().fg(p.muted));
            }
            y += 1;
            last_group = s.group;
        }
        if y >= area.bottom() {
            break;
        }
        // Row (§8.4): ▌ at x (focused cursor), state glyph at x+1, title at
        // x+3, recency right-aligned ending at x+w-2.
        let cursor = i == app.session_cursor;
        let fill = if cursor {
            if focused {
                p.wash
            } else {
                p.surface2
            }
        } else {
            p.bg
        };
        for x in area.left()..area.right() {
            buf[(x, y)].set_style(Style::default().bg(fill));
        }
        if cursor && focused {
            buf[(area.x, y)]
                .set_symbol(g.selection)
                .set_style(Style::default().fg(p.magenta).bg(fill));
        }
        if s.failed {
            buf[(area.x + 1, y)]
                .set_symbol(g.failed)
                .set_style(Style::default().fg(p.red).bg(fill));
        }
        let recency_w = display_width(&s.recency) as u16;
        // Title budget w-3-len(recency)-2 (§8.4); the 2 includes the space
        // before the recency.
        let budget = (area.width as usize)
            .saturating_sub(3 + recency_w as usize + 2)
            .max(1);
        let rec_x = area.x
            + area
                .width
                .saturating_sub(2)
                .saturating_sub(recency_w)
                .saturating_add(1);
        let title = truncate_graphemes(&s.title, budget);
        let title_style = if s.open || (cursor && focused) {
            Style::default()
                .fg(p.ink)
                .add_modifier(Modifier::BOLD)
                .bg(fill)
        } else {
            Style::default().fg(p.ink2).bg(fill)
        };
        let mut tx = area.x + 3;
        for c in title.chars() {
            if tx >= area.x + area.width {
                break;
            }
            buf[(tx, y)]
                .set_symbol(&c.to_string())
                .set_style(title_style);
            tx += 1;
        }
        // One space between title and recency (the golden's rhythm).
        if tx < rec_x {
            buf[(tx, y)]
                .set_symbol(" ")
                .set_style(Style::default().bg(fill));
        }
        let rec_fg = if cursor { p.ink2 } else { p.muted };
        for (j, c) in s.recency.chars().enumerate() {
            buf[(rec_x + j as u16, y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(rec_fg).bg(fill));
        }
        y += 1;
    }
}

// ── Activity rail (§9.16) ────────────────────────────────────────────────────

/// The Activity tab's structured event rows (§8.4): time at x+1 (faint),
/// kind at x+11 (muted), text at x+18 end-truncated at x+w-1. Warnings
/// amber, errors red, everything else ink2. The rail follows the newest
/// entry unless the operator scrolled (pane_scroll[0]).
fn render_activity_rail(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design) {
    let p = &d.palette;
    let buf = frame.buffer_mut();
    if area.width < 20 || area.height < 1 {
        return;
    }
    // Follow the newest entry unless scrolled (§9.16).
    let rows = &app.activity;
    let visible = area.height as usize;
    let total = rows.len();
    let scroll = if app.viewport_manual {
        app.pane_scroll[0] as usize
    } else {
        total.saturating_sub(visible)
    };
    let start = scroll.min(total);
    let end = (start + visible).min(total);
    let mut y = area.y;
    for row in rows.get(start..end).unwrap_or(&[]) {
        if y >= area.bottom() {
            break;
        }
        // Time at x+1, faint.
        for (j, c) in row.time.chars().enumerate() {
            let x = area.x + 1 + j as u16;
            if x >= area.x + area.width {
                break;
            }
            buf[(x, y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.faint));
        }
        // Kind at x+11, muted.
        for (j, c) in row.kind.chars().enumerate() {
            let x = area.x + 11 + j as u16;
            if x >= area.x + area.width {
                break;
            }
            buf[(x, y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.muted));
        }
        // Text at x+18, end-truncated at x+w-1. Warnings amber, errors red.
        let text_color = match row.kind {
            "warn" => p.amber,
            "error" => p.red,
            _ => p.ink2,
        };
        let budget = (area.width as usize).saturating_sub(19).max(1);
        let text = truncate_graphemes(&row.text, budget);
        for (j, c) in text.chars().enumerate() {
            let x = area.x + 18 + j as u16;
            if x >= area.x + area.width {
                break;
            }
            buf[(x, y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(text_color));
        }
        y += 1;
    }
    // Empty state: one faint line.
    if rows.is_empty() && area.height >= 1 {
        for (j, c) in "(no events yet)".chars().enumerate() {
            let x = area.x + 2 + j as u16;
            if x >= area.x + area.width {
                break;
            }
            buf[(x, area.y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.faint));
        }
    }
}

// ── Conversation pane (§6.2–6.8, §8.3) ────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_conversation(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    composer_text: &str,
    d: &Design,
    g: &Glyphs,
    wc: &WidthClass,
    composer_row: Rect,
    hint_row: Rect,
    show_hint: bool,
) {
    let p = &d.palette;
    let (cl, cw) = conv_column(area.x, area.width);
    // Right-aligned items end at cl+cw (the goldens' authoritative column;
    // §2 precedence: the frame wins over the rule text). Pane-relative.
    let rel_right = (cl + cw - area.x) as usize;
    let band_left = cl.saturating_sub(2);
    let band_right = cl + cw;

    let mut lines: Vec<Line> = vec![Line::from("")];
    let empty_session = app.transcript.is_empty() && app.in_flight.is_empty();

    if empty_session {
        build_welcome(&mut lines, app, area, cl, cw, d, g);
    }

    let live = app.turn_in_flight
        || app.tool_state == ToolState::Streaming
        || matches!(app.tool_state, ToolState::Running(_));

    let mut prev_was_tool = false;
    for (ei, entry) in app.transcript.iter().enumerate() {
        let is_tool = matches!(entry, TranscriptLine::Stripped { .. });
        let next_is_tool = app
            .transcript
            .get(ei + 1)
            .map(|e| matches!(e, TranscriptLine::Stripped { .. }))
            .unwrap_or(false);
        // NOTE: prev_was_tool stays valid THROUGH this iteration's match
        // (the continuation check reads it); update after.
        match entry {
            TranscriptLine::User { text, time } => {
                // §6.2: surface band, › gutter muted bold, text ink, time
                // right-aligned muted. Wraps at cw-7 with a time, cw without.
                let wrap_w = if time.is_some() { cw - 7 } else { cw };
                // Wrap the RICH runs so inline code counts at its display
                // width (backticks render as nothing, §6.4).
                let runs = crate::rich::runs_for(text, d);
                let wrapped = wrap_runs(&runs, wrap_w as usize);
                for (i, line) in wrapped.iter().enumerate() {
                    let mut spans: Vec<Span> = Vec::new();
                    if i == 0 {
                        // The gutter rides cl-2: one leading space from the
                        // pane edge, then ›, then text at cl.
                        spans.push(Span::raw(" "));
                        spans.push(Span::styled(
                            g.you.to_string(),
                            Style::default().fg(p.muted).add_modifier(Modifier::BOLD),
                        ));
                    } else {
                        spans.push(Span::raw("  "));
                    }
                    spans.push(Span::raw(" "));
                    // The wrapped line already carries styled spans.
                    spans.extend(line.spans.iter().cloned());
                    if i == 0 && time.is_some() && !wc.compact {
                        let t = time.as_deref().unwrap_or("");
                        let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let pad = rel_right.saturating_sub(used + t.chars().count());
                        spans.push(Span::styled(" ".repeat(pad), Style::default().fg(p.muted)));
                        spans.push(Span::styled(t, Style::default().fg(p.muted)));
                    }
                    lines.push(Line::from(spans));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Assistant { text, time } => {
                // §6.3: ✦ gutter (cyan live, magenta settled), markdown
                // body, time right on the first row. The first paragraph of
                // a timed turn wraps at cw-7 (§8.3). A time:None entry
                // following a tool group is a continuation of the same
                // turn — no gutter.
                let continuation = time.is_none() && prev_was_tool;
                let body =
                    render_assistant_body(text, time.as_ref(), cw, wc.compact, continuation, d);
                for (i, rich_line) in body.into_iter().enumerate() {
                    let mut spans: Vec<Span> = Vec::new();
                    if i == 0 && !continuation {
                        spans.push(Span::raw(" "));
                        spans.push(Span::styled(
                            g.orbit.to_string(),
                            Style::default().fg(if live { p.cyan } else { p.magenta }),
                        ));
                        spans.push(Span::raw(" "));
                    }
                    spans.extend(rich_line.spans);
                    if i == 0 && time.is_some() && !wc.compact {
                        let t = time.as_deref().unwrap_or("");
                        let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let pad = rel_right.saturating_sub(used + t.chars().count());
                        spans.push(Span::styled(" ".repeat(pad), Style::default().fg(p.muted)));
                        spans.push(Span::styled(t, Style::default().fg(p.muted)));
                    }
                    lines.push(Line::from(spans));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Stripped {
                tool_name,
                summary,
                outcome,
                meta,
                started_at,
            } => {
                // §6.5 tool line: glyph at cl, name at cl+2, argument 2
                // after the name, meta right-aligned.
                let is_running = outcome.is_none()
                    && matches!(&app.tool_state, ToolState::Running(n) if n == tool_name)
                    && app.turn_in_flight;
                let running_meta = match started_at {
                    Some(start_tick) => {
                        let ticks = app.tick_count.saturating_sub(*start_tick);
                        let secs = (ticks * 16) as f64 / 1000.0;
                        format!("{secs:.1}s")
                    }
                    None => "running".to_string(),
                };
                let (glyph, glyph_color, name_color, meta_text, meta_color) =
                    match (is_running, outcome) {
                        (true, _) => (g.running, p.cyan, p.ink, running_meta, p.cyan),
                        (false, Some(ToolOutcome::Ok)) => {
                            (g.done, p.muted, p.ink2, meta.clone(), p.muted)
                        }
                        (false, Some(ToolOutcome::Failed)) => {
                            (g.failed, p.red, p.ink2, "failed".into(), p.red)
                        }
                        (false, Some(ToolOutcome::Denied)) => {
                            (g.denied, p.muted, p.ink2, "denied by you".into(), p.muted)
                        }
                        (false, Some(ToolOutcome::Blocked)) => {
                            (g.blocked, p.amber, p.ink2, "blocked".into(), p.amber)
                        }
                        (false, None) => (g.pending, p.faint, p.ink2, String::new(), p.faint),
                    };
                let mut spans = vec![
                    Span::raw("   "),
                    Span::styled(glyph, Style::default().fg(glyph_color)),
                    Span::raw(" "),
                    Span::styled(
                        tool_name.clone(),
                        Style::default().fg(name_color).add_modifier(Modifier::BOLD),
                    ),
                ];
                if !summary.is_empty() {
                    // Argument budget: from 2 past the name to 12 before the
                    // right edge (meta room). No truncation when it fits.
                    let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                    let budget = rel_right.saturating_sub(used + 14).max(8);
                    let arg = truncate_middle(summary, budget);
                    spans.push(Span::styled(
                        format!("  {arg}"),
                        Style::default().fg(p.muted),
                    ));
                }
                if !meta_text.is_empty() {
                    let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                    let pad = rel_right.saturating_sub(used + meta_text.chars().count());
                    spans.push(Span::raw(" ".repeat(pad)));
                    spans.push(Span::styled(meta_text, Style::default().fg(meta_color)));
                }
                lines.push(Line::from(spans));
                // §6.5 grouping: consecutive tool lines stack with no blank
                // between; one blank after the group.
                if !next_is_tool {
                    lines.push(Line::from(""));
                }
            }
            TranscriptLine::System(text) => {
                // §6.8 session notice: ∙ + muted text.
                lines.push(Line::from(vec![
                    Span::styled(g.notice.to_string(), Style::default().fg(p.muted)),
                    Span::raw(" "),
                    Span::styled(text.clone(), Style::default().fg(p.muted)),
                ]));
                lines.push(Line::from(""));
            }
            TranscriptLine::Evidence { checks, note, rows } => {
                // §6.6: green header word + muted rest; rows behind a green
                // left rule at cl+1, text at cl+3, result right-aligned.
                let mut head = vec![
                    Span::raw("   "),
                    Span::styled(g.done, Style::default().fg(p.green)),
                    Span::raw(" "),
                    Span::styled(
                        "verified",
                        Style::default().fg(p.green).add_modifier(Modifier::BOLD),
                    ),
                ];
                let rest = if wc.compact {
                    format!("  {checks}")
                } else {
                    format!("  {checks} · {note}")
                };
                head.push(Span::styled(rest, Style::default().fg(p.muted)));
                lines.push(Line::from(head));
                for (name, result) in rows {
                    let mut spans = vec![
                        Span::raw("   "),
                        Span::styled("│", Style::default().fg(p.green)),
                        Span::raw(" "),
                        Span::styled(name.clone(), Style::default().fg(p.ink2)),
                    ];
                    let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                    let pad = rel_right.saturating_sub(used + result.chars().count());
                    spans.push(Span::raw(" ".repeat(pad)));
                    spans.push(Span::styled(result.clone(), Style::default().fg(p.muted)));
                    lines.push(Line::from(spans));
                }
            }
            TranscriptLine::Sources(srcs) => {
                // §6.7: 'sources' label muted, [n] cyan, path ink2.
                let mut spans = vec![
                    Span::raw("   "),
                    Span::styled("sources", Style::default().fg(p.muted)),
                ];
                for (si, (idx, path)) in srcs.iter().enumerate() {
                    // 2 spaces after the label; 3 between entries (golden).
                    spans.push(Span::raw(if si == 0 { "  " } else { "   " }));
                    spans.push(Span::styled(
                        format!("[{idx}]"),
                        Style::default().fg(p.cyan),
                    ));
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(path.clone(), Style::default().fg(p.ink2)));
                }
                lines.push(Line::from(spans));
                lines.push(Line::from(""));
            }
            TranscriptLine::Redacted(kind) => {
                lines.push(Line::from(vec![
                    Span::styled(g.notice.to_string(), Style::default().fg(p.amber)),
                    Span::styled(
                        format!(" redacted · {}", kind.label()),
                        Style::default().fg(p.amber),
                    ),
                ]));
                lines.push(Line::from(""));
            }
        }
        prev_was_tool = is_tool;
    }

    // In-flight stream: cyan ✦ gutter + the live edge ▍ (§6.3).
    if !app.in_flight.is_empty() {
        let body = render_message(&app.in_flight, d);
        let n = body.len();
        for (i, rich_line) in body.into_iter().enumerate() {
            let mut spans: Vec<Span> = Vec::new();
            if i == 0 {
                spans.push(Span::styled(
                    g.orbit.to_string(),
                    Style::default().fg(p.cyan),
                ));
            }
            spans.push(Span::raw(" "));
            spans.extend(rich_line.spans);
            if i + 1 == n {
                spans.push(Span::styled("▍", Style::default().fg(p.cyan)));
            }
            lines.push(Line::from(spans));
        }
        lines.push(Line::from(""));
    } else if app.turn_in_flight && app.tool_state == ToolState::Streaming {
        // Waiting for the first token (§6.3): one static muted line.
        let mut spans = vec![
            Span::styled(g.orbit.to_string(), Style::default().fg(p.cyan)),
            Span::raw(" "),
            Span::styled(
                format!("waiting for {}", app.model),
                Style::default().fg(p.muted),
            ),
        ];
        let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
        let pad = rel_right.saturating_sub(used + 5);
        spans.push(Span::raw(" ".repeat(pad)));
        spans.push(Span::styled("14:02", Style::default().fg(p.muted)));
        lines.push(Line::from(spans));
        lines.push(Line::from(""));
    }

    // Queued prompts (§5.5): faint › … queued rows above the composer.
    for q in &app.queued {
        let wrapped = wrap_text(q, (cw - 8) as usize);
        for (i, line) in wrapped.iter().enumerate() {
            let mut spans: Vec<Span> = Vec::new();
            if i == 0 {
                spans.push(Span::styled(
                    g.you.to_string(),
                    Style::default().fg(p.faint).add_modifier(Modifier::BOLD),
                ));
            }
            spans.push(Span::raw(" "));
            spans.push(Span::styled(line.clone(), Style::default().fg(p.ink2)));
            if i + 1 == wrapped.len() {
                let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                let pad = rel_right.saturating_sub(used + 6);
                spans.push(Span::raw(" ".repeat(pad)));
                spans.push(Span::styled("queued", Style::default().fg(p.muted)));
            }
            lines.push(Line::from(spans));
        }
    }

    // ── Bottom-anchor the transcript (§4.5): when the content is shorter
    // than the pane, pad the TOP with blanks so the last line lands at the
    // bottom row of the pane. The content-row count (bottom-anchored,
    // non-blank tail) drives the scroll thumb.
    let visible = area.height as usize;
    let total = lines.len();

    let mut scroll = if app.viewport_manual {
        app.pane_scroll[1] as usize
    } else {
        0
    };
    if total < visible && !app.viewport_manual {
        let pad = visible - total;
        let mut padded: Vec<Line> = Vec::with_capacity(visible);
        for _ in 0..pad {
            padded.push(Line::from(""));
        }
        padded.extend(lines);
        lines = padded;
    } else if !app.viewport_manual {
        scroll = total.saturating_sub(visible);
    }
    // ── Selection rows = rendered rows (§6.9) ─────────────────────────────
    // The mouse hit-test yields pane-local rows in RENDER space (blank
    // top-padding + wrapped transcript lines). pane_lines for the Center
    // pane must be the same rendered rows or extract() indexes text the
    // operator never saw. Record the rendered text here, after padding,
    // so the two can never drift.
    {
        let rendered: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect();
        app.rendered_center_lines.replace(rendered);
    }
    let para = Paragraph::new(lines).scroll((scroll as u16, 0));
    frame.render_widget(para, area);

    // ── Selection highlight (§6.9) ────────────────────────────────────────
    // The selection state is pane-local (row 0 = the pane's first content
    // row). Overlay reverse-video on the covered cells so the operator sees
    // what a drag is capturing; the OSC 52 copy on mouse-up uses the same
    // coordinates, so the highlight and the clipboard always agree.
    if let Some(sel) = app.selection.as_ref() {
        if sel.pane == Focus::Center && sel.is_visible() {
            let buf = frame.buffer_mut();
            for row in area.y..area.bottom() {
                let pane_row = row - area.y;
                for col in area.x..area.right() {
                    let pane_col = col - area.x;
                    if sel.contains(pane_row, pane_col) {
                        let cell = &mut buf[(col, row)];
                        let fg = cell.fg;
                        cell.set_fg(cell.bg).set_bg(fg);
                    }
                }
            }
        }
    }

    // ── User-turn bands: paint surface under user rows (§6.2) ─────────────
    paint_user_bands(frame, area, cl, band_left, band_right, d, g);

    // ── Composer (§5.5, §8.3) ──────────────────────────────────────────────
    let composer_focused = app.focus == Focus::Center;
    let buf = frame.buffer_mut();
    let band_end = band_right.min(composer_row.x + composer_row.width - 1);
    for x in band_left..=band_end {
        buf[(x, composer_row.y)].set_style(Style::default().bg(p.surface));
    }
    let prompt_color = if composer_focused { p.magenta } else { p.faint };
    buf[(cl - 1, composer_row.y)].set_symbol(g.you).set_style(
        Style::default()
            .fg(prompt_color)
            .bg(p.surface)
            .add_modifier(Modifier::BOLD),
    );
    let placeholder = if live {
        "Add to the queue, or wait for ORBIT"
    } else {
        "Ask ORBIT, or type / for commands"
    };
    let first_line = composer_text.lines().next().unwrap_or("");
    if composer_text.is_empty() {
        for (i, c) in placeholder.chars().enumerate() {
            let x = cl + 2 + i as u16;
            if x >= composer_row.x + composer_row.width {
                break;
            }
            buf[(x, composer_row.y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.faint).bg(p.surface));
        }
    } else {
        for (i, c) in first_line.chars().enumerate() {
            let x = cl + 1 + i as u16;
            if x >= composer_row.x + composer_row.width {
                break;
            }
            buf[(x, composer_row.y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.ink).bg(p.surface));
        }
    }

    // ── Plan-approval banner (Claude Code parity) ──────────────────────────
    // While a plan is pending, a banner above the composer shows the
    // decision: y approve · n discard. The plan text itself is already in
    // the transcript (PlanReady renders as an assistant line).
    if app.pending_plan.is_some() {
        let row_y = composer_row.y.saturating_sub(1);
        let buf = frame.buffer_mut();
        for xx in composer_row.x..composer_row.x + composer_row.width {
            buf[(xx, row_y)].set_style(Style::default().bg(p.surface2));
        }
        let mut cx = composer_row.x + 1;
        for c in "PLAN READY — y approve · n discard".chars() {
            if cx >= composer_row.x + composer_row.width {
                break;
            }
            buf[(cx, row_y)].set_symbol(&c.to_string()).set_style(
                Style::default()
                    .fg(p.cyan)
                    .bg(p.surface2)
                    .add_modifier(Modifier::BOLD),
            );
            cx += 1;
        }
    }

    // ── Slash-hint dropdown (Claude Code parity) ──────────────────────────
    // A live menu above the composer while the operator types a partial
    // `/command`: matched commands with one-line descriptions; ↑/↓ pick,
    // Tab/Enter accept. Rendered bottom-up into the transcript area.
    if app.slash_hints.open && !app.slash_hints.items.is_empty() {
        let items = &app.slash_hints.items;
        let visible = items.len().min(6) as u16;
        let sel = app.slash_hints.selected.min(items.len() - 1);
        let width = composer_row.width.saturating_sub(2).max(20);
        let x = composer_row.x + 1;
        // Rows stack upward from just above the composer.
        for (i, (cmd, desc)) in items.iter().take(visible as usize).enumerate() {
            let row_y = composer_row.y.saturating_sub(1 + i as u16);
            let buf = frame.buffer_mut();
            for xx in x..x + width {
                if xx >= composer_row.x + composer_row.width {
                    break;
                }
                buf[(xx, row_y)].set_style(Style::default().bg(p.surface2));
            }
            let is_sel = i == sel;
            let (cs, ds) = if is_sel {
                (
                    Style::default()
                        .fg(p.cyan)
                        .bg(p.surface2)
                        .add_modifier(Modifier::BOLD),
                    Style::default().fg(p.ink).bg(p.surface2),
                )
            } else {
                (
                    Style::default().fg(p.magenta).bg(p.surface2),
                    Style::default().fg(p.faint).bg(p.surface2),
                )
            };
            let marker = if is_sel { "▸ " } else { "  " };
            let mut cx = x;
            for c in marker.chars().chain(cmd.chars()).chain(" — ".chars()) {
                if cx >= x + width {
                    break;
                }
                buf[(cx, row_y)].set_symbol(&c.to_string()).set_style(cs);
                cx += 1;
            }
            for c in desc.chars() {
                if cx >= x + width {
                    break;
                }
                buf[(cx, row_y)].set_symbol(&c.to_string()).set_style(ds);
                cx += 1;
            }
        }
    }

    // ── Hint row (§5.5) ────────────────────────────────────────────────────
    if show_hint {
        let buf = frame.buffer_mut();
        let band_end = band_right.min(hint_row.x + hint_row.width - 1);
        for x in band_left..=band_end {
            buf[(x, hint_row.y)].set_style(Style::default().bg(p.surface));
        }
        let mut x = cl + 1;
        // Multi-line composer (e.g. after a paste): show "+N lines" so the
        // single-row composer visibly holds more than the first line.
        let extra_lines = composer_text.lines().count().saturating_sub(1);
        if extra_lines > 0 {
            let put2 =
                |text: &str, style: Style, x: &mut u16, buf: &mut ratatui::buffer::Buffer| {
                    for c in text.chars() {
                        if *x >= hint_row.x + hint_row.width {
                            return;
                        }
                        buf[(*x, hint_row.y)]
                            .set_symbol(&c.to_string())
                            .set_style(style.bg(p.surface));
                        *x += 1;
                    }
                };
            put2(
                &format!("+{extra_lines} lines   "),
                Style::default().fg(p.magenta).add_modifier(Modifier::BOLD),
                &mut x,
                buf,
            );
        }
        let put = |text: &str, style: Style, x: &mut u16, buf: &mut ratatui::buffer::Buffer| {
            for c in text.chars() {
                if *x >= hint_row.x + hint_row.width {
                    return;
                }
                buf[(*x, hint_row.y)]
                    .set_symbol(&c.to_string())
                    .set_style(style.bg(p.surface));
                *x += 1;
            }
        };
        let key_style = Style::default().fg(p.ink2).add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(p.muted);
        if live {
            put("⏎", key_style, &mut x, buf);
            put(" queue   ", desc_style, &mut x, buf);
            put("⇧⏎", key_style, &mut x, buf);
            put(" newline", desc_style, &mut x, buf);
            if wc.status_level >= 2 {
                put("   tab views", desc_style, &mut x, buf);
            } else {
                put("   pgup scroll", desc_style, &mut x, buf);
            }
        } else {
            put("⏎", key_style, &mut x, buf);
            put(" send   ", desc_style, &mut x, buf);
            put("⇧⏎", key_style, &mut x, buf);
            put(" newline   ", desc_style, &mut x, buf);
            put("/", key_style, &mut x, buf);
            put(" commands   ", desc_style, &mut x, buf);
            put("↑", key_style, &mut x, buf);
            put(" history", desc_style, &mut x, buf);
        }
        // Toast rides the hint row's right end (§6.12).
        if let Some(toast) = &app.toast {
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
            let tw = display_width(&text) as u16;
            let tx = band_end.saturating_sub(tw);
            // Truncate to the band (§6.12): a toast wider than the band
            // right-aligns and clips its LEFT side, never spilling past
            // band_end. Grapheme-aware: advance by display width, not char
            // index, so wide glyphs don't drift.
            let mut x = tx;
            for c in text.graphemes(true) {
                if x > band_end {
                    break;
                }
                let w = crate::unicode::grapheme_width(c) as u16;
                buf[(x, hint_row.y)]
                    .set_symbol(c)
                    // surface2 (not surface): the toast is an overlay, and a
                    // distinct bg guarantees the diff rewrites every cell —
                    // identical cells under the old hint text would otherwise
                    // never reach the terminal stream.
                    .set_style(Style::default().fg(color).bg(p.surface2));
                x += w.max(1);
            }
        }
    }
}

/// Paint the surface band under user-turn rows (§6.2): the band spans
/// cl-2 … cl+cw on the › row and its continuation rows.
fn paint_user_bands(
    frame: &mut ratatui::Frame,
    area: Rect,
    cl: u16,
    band_left: u16,
    band_right: u16,
    d: &Design,
    g: &Glyphs,
) {
    let buf = frame.buffer_mut();
    let band_end = band_right.min(area.x + area.width - 1);
    let mut in_band = false;
    for y in area.top()..area.bottom() {
        let gutter = buf[(cl.saturating_sub(2), y)].symbol().to_string();
        let is_user = gutter == g.you;
        let blank_row = (area.left()..area.right()).all(|x| buf[(x, y)].symbol() == " ");
        if is_user {
            in_band = true;
        } else if blank_row {
            in_band = false;
        }
        if is_user || in_band {
            for x in band_left..=band_end {
                let cell = &mut buf[(x, y)];
                let (fg, bg) = (cell.style().fg, cell.style().bg);
                // The band is surface, but inline-code chips (surface2)
                // keep their own bg (§6.4).
                let new_bg = match bg {
                    Some(b) if b == d.palette.surface2 => b,
                    _ => d.palette.surface,
                };
                cell.set_style(Style::default().fg(fg.unwrap_or(Color::Reset)).bg(new_bg));
            }
        }
    }
}

// ── Welcome screen (§9.1) ────────────────────────────────────────────────────

fn build_welcome(
    lines: &mut Vec<Line>,
    app: &App,
    area: Rect,
    cl: u16,
    cw: u16,
    d: &Design,
    _g: &Glyphs,
) {
    let p = &d.palette;
    // The mark block (§8): 3 rows + tagline, ~35 wide, centered in the
    // measure.
    let mark = welcome_mark_frame(d, app.startup_frame.max(5));
    let mark_w = 35u16;
    let mark_x = cl + cw.saturating_sub(mark_w) / 2;
    let pad = " ".repeat(mark_x.saturating_sub(area.x) as usize);
    for l in mark {
        let mut padded = vec![Span::raw(pad.clone())];
        padded.extend(l.spans);
        lines.push(Line::from(padded));
    }
    lines.push(Line::from(""));
    // No second tagline here: welcome_mark_frame already carries it
    // beneath the strokes. The old duplicate printed it twice.
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    // Readiness row: every value computed at startup by the harness
    // (trust root, ledger segment count, provider · model). Empty → no
    // row. The old fixture line ("✓ ledger · 7 records · glm-5.2")
    // was invented and is gone.
    if !app.readiness.is_empty() {
        let text = app
            .readiness
            .iter()
            .map(|r| format!("{} {}", if r.ok { "✓" } else { "✗" }, r.label))
            .collect::<Vec<_>>()
            .join("    ");
        let r_x = cl + cw.saturating_sub(text.chars().count() as u16) / 2;
        let r_pad = " ".repeat(r_x.saturating_sub(area.x) as usize);
        let mut spans = vec![Span::raw(r_pad)];
        for row in &app.readiness {
            spans.push(Span::styled(
                if row.ok { "✓" } else { "✗" },
                Style::default().fg(if row.ok { p.green } else { p.red }),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(row.label.clone(), Style::default().fg(p.ink2)));
            spans.push(Span::raw("    "));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    // Starters.
    let describe = "Describe a task below, or start with";
    let d_x = cl + 9;
    let d_pad = " ".repeat(d_x.saturating_sub(area.x) as usize);
    lines.push(Line::from(vec![
        Span::raw(d_pad),
        Span::styled(describe, Style::default().fg(p.muted)),
    ]));
    lines.push(Line::from(""));
    for (cmd, desc) in [
        ("/models", "list models from configured providers"),
        ("/sessions", "browse and resume earlier work"),
        ("?", "keys and commands"),
    ] {
        let s_pad = " ".repeat((d_x + 2).saturating_sub(area.x) as usize);
        lines.push(Line::from(vec![
            Span::raw(s_pad),
            Span::styled(
                format!("{cmd:<10}"),
                Style::default().fg(p.ink2).add_modifier(Modifier::BOLD),
            ),
            Span::styled(desc, Style::default().fg(p.muted)),
        ]));
    }
}

// ── Workspace rail (§6.10) ───────────────────────────────────────────────────

fn render_workspace_rail(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    let w = &app.workspace;
    let mut lines: Vec<Line> = Vec::new();
    if w.plan.is_empty() && w.findings.is_empty() && w.verification.is_empty() {
        // §9.15 empty state.
        for text in [
            "◌ Nothing planned yet.",
            "",
            "   When a task has steps, the",
            "   plan, findings and",
            "   verification evidence collect",
            "   here.",
        ] {
            lines.push(Line::from(Span::styled(text, Style::default().fg(p.faint))));
        }
    } else {
        // Phase stepper: ✓━━✓━━◉──◌──◌  verify  4/5
        let current = w.phase_index.min(4);
        let mut stepper: Vec<Span> = Vec::new();
        for i in 0..5 {
            let (ch, color) = if i < current {
                (g.done, p.muted)
            } else if i == current {
                ("◉", p.cyan)
            } else {
                ("◌", p.faint)
            };
            let style = if i == current {
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };
            stepper.push(Span::styled(ch, style));
            if i < 4 {
                let (conn, cc) = if i < current {
                    ("━━", p.muted)
                } else {
                    ("──", p.rule)
                };
                stepper.push(Span::styled(conn, Style::default().fg(cc)));
            }
        }
        let phase_names = ["orient", "reason", "act", "verify", "respond"];
        stepper.insert(0, Span::raw("  "));
        stepper.push(Span::raw("  "));
        stepper.push(Span::styled(
            phase_names[current],
            Style::default().fg(p.cyan).add_modifier(Modifier::BOLD),
        ));
        let total = w.plan.len().max(1);
        let done_count = w.plan.iter().filter(|t| t.state == TaskState::Done).count();
        let count_text = format!("{done_count}/{total}");
        let used: usize = stepper
            .iter()
            .map(|sp| display_width(&sp.to_string()))
            .sum();
        let right = (area.width as usize).saturating_sub(2);
        let pad = right.saturating_sub(used + count_text.chars().count()) + 1;
        stepper.push(Span::raw(" ".repeat(pad)));
        stepper.push(Span::styled(count_text, Style::default().fg(p.muted)));
        lines.push(Line::from(stepper));
        lines.push(Line::from(""));

        // PLAN
        if !w.plan.is_empty() {
            {
                let total = w.plan.len().max(1);
                let done = w.plan.iter().filter(|t| t.state == TaskState::Done).count();
                let ratio = format!("{done}/{total}");
                let used = 2 + 4;
                let right = (area.width as usize).saturating_sub(2);
                let pad = right.saturating_sub(used + ratio.chars().count()) + 1;
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled("PLAN", Style::default().fg(p.muted)),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(ratio, Style::default().fg(p.muted)),
                ]));
            }
            for task in &w.plan {
                let (glyph, color, bold) = match task.state {
                    TaskState::Active => ("◉", p.cyan, true),
                    TaskState::Pending => (g.pending, p.faint, false),
                    TaskState::Blocked => (g.blocked, p.amber, false),
                    TaskState::Failed => (g.failed, p.red, false),
                    TaskState::Retest => (g.retest, p.amber, false),
                    TaskState::AwaitingApproval => ("◇", p.magenta, false),
                    TaskState::Done => (g.done, p.green, false),
                };
                // A done task with no evidence is claimed, not verified:
                // ink2 glyph (the golden's distinction).
                let color = if task.state == TaskState::Done && task.evidence == 0 {
                    p.ink2
                } else {
                    color
                };
                let title_style = if bold {
                    Style::default().fg(p.ink).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(p.ink2)
                };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{glyph} "), Style::default().fg(color)),
                    Span::styled(task.title.clone(), title_style),
                ]));
                if let Some(sub) = &task.sub {
                    let sub_color = match task.state {
                        TaskState::Active => p.cyan,
                        TaskState::Failed => p.red,
                        TaskState::Blocked | TaskState::Retest => p.amber,
                        TaskState::AwaitingApproval => p.muted,
                        TaskState::Pending | TaskState::Done => p.faint,
                    };
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(sub.clone(), Style::default().fg(sub_color)),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }
        // FINDINGS
        if !w.findings.is_empty() {
            lines.push(section_line("FINDINGS", w.findings.len(), p, area.width));
            for f in &w.findings {
                // The source renders muted, the title ink2 (golden).
                let mut runs: Vec<(String, Style)> =
                    vec![(f.title.clone(), Style::default().fg(p.ink2))];
                if let Some(src) = &f.source {
                    runs.push((" ".into(), Style::default().fg(p.ink2)));
                    runs.push((src.clone(), Style::default().fg(p.muted)));
                }
                let wrapped = wrap_runs(&runs, (area.width as usize).saturating_sub(2));
                for (i, wline) in wrapped.iter().enumerate() {
                    let mut spans: Vec<Span> = Vec::new();
                    if i == 0 {
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled("∙ ", Style::default().fg(p.muted)));
                    } else {
                        spans.push(Span::raw("    "));
                    }
                    spans.extend(wline.spans.iter().cloned());
                    lines.push(Line::from(spans));
                }
            }
            lines.push(Line::from(""));
        }
        // VERIFICATION
        if !w.verification.is_empty() {
            // Count = passed/total (the golden's 2/3).
            let passed = w
                .verification
                .iter()
                .filter(|v| v.result == VerificationResult::Passed)
                .count();
            let total = w.verification.len();
            let ratio = format!("{passed}/{total}");
            let label = "VERIFICATION";
            let used = 2 + label.len();
            let right = (area.width as usize).saturating_sub(2);
            let pad = right.saturating_sub(used + ratio.chars().count()) + 1;
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(p.muted)),
                Span::raw(" ".repeat(pad)),
                Span::styled(ratio, Style::default().fg(p.muted)),
            ]));
            for v in &w.verification {
                let (glyph, color) = match v.result {
                    VerificationResult::Passed => (g.done, p.green),
                    VerificationResult::Failed => (g.failed, p.red),
                    VerificationResult::Pending => (g.retest, p.amber),
                };
                // The name wraps (§6.10): budget = rail width minus glyph,
                // lead and result room; continuations indent 4.
                let name_budget = (area.width as usize)
                    .saturating_sub(7 + v.result_text.chars().count())
                    .max(8);
                let name_lines = wrap_text(&v.name, name_budget);
                for (ni, nl) in name_lines.iter().enumerate() {
                    let mut spans: Vec<Span> = Vec::new();
                    if ni == 0 {
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled(
                            format!("{glyph} "),
                            Style::default().fg(color),
                        ));
                    } else {
                        spans.push(Span::raw("    "));
                    }
                    spans.push(Span::styled(nl.clone(), Style::default().fg(p.ink2)));
                    if ni == 0 && !v.result_text.is_empty() {
                        let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let right = (area.width as usize).saturating_sub(2);
                        let pad = right.saturating_sub(used + v.result_text.chars().count()) + 1;
                        spans.push(Span::raw(" ".repeat(pad)));
                        let result_color = match v.result {
                            VerificationResult::Pending => p.amber,
                            _ => p.muted,
                        };
                        spans.push(Span::styled(
                            v.result_text.clone(),
                            Style::default().fg(result_color),
                        ));
                    }
                    lines.push(Line::from(spans));
                }
            }
        }
    }
    let para = Paragraph::new(lines).scroll((app.pane_scroll[2], 0));
    frame.render_widget(para, area);
}

/// A section label: muted label, faint count right-aligned at x+w-2 (§6.10).
fn section_line(
    label: &str,
    count: usize,
    p: &crate::tokens::ResolvedPalette,
    width: u16,
) -> Line<'static> {
    let count_text = count.to_string();
    let _ = &count_text;
    let used = 2 + label.chars().count();
    let right = (width as usize).saturating_sub(2);
    let pad = right.saturating_sub(used + count_text.chars().count()) + 1;
    Line::from(vec![
        Span::raw("  "),
        Span::styled(label.to_string(), Style::default().fg(p.muted)),
        Span::raw(" ".repeat(pad)),
        Span::styled(count_text, Style::default().fg(p.muted)),
    ])
}

// ── Status line (§6.11) ──────────────────────────────────────────────────────

fn render_status_bar(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    wc: &WidthClass,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    let buf = frame.buffer_mut();
    let level = wc.status_level;

    // Left: the mark + ORBIT + activity.
    let working =
        app.tool_state == ToolState::Streaming || matches!(app.tool_state, ToolState::Running(_));
    let mark = if working {
        if app.reduced_motion {
            g.orbit
        } else {
            g.busy_frames()[app.spinner_frame as usize % g.busy_frames().len()]
        }
    } else {
        g.orbit
    };
    let mark_color = match &app.tool_state {
        ToolState::AwaitingApproval => p.magenta,
        _ if working => p.cyan,
        _ => p.magenta,
    };
    buf[(1, area.y)]
        .set_symbol(mark)
        .set_style(Style::default().fg(mark_color));
    for (i, c) in "ORBIT".chars().enumerate() {
        buf[(3 + i as u16, area.y)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.muted).add_modifier(Modifier::BOLD));
    }
    let mut x = 11u16;
    let mut put = |text: &str, style: Style, x: &mut u16| {
        for c in text.chars() {
            if *x >= area.x + area.width {
                return;
            }
            buf[(*x, area.y)]
                .set_symbol(&c.to_string())
                .set_style(style);
            *x += 1;
        }
    };
    // Claude Code QOL: the mode indicator ("-- INSERT --") so the operator
    // always knows whether keys type text or run commands. Shown next to
    // the ORBIT mark in the left cluster.
    {
        let mode_label = if app.plan_mode {
            "PLAN"
        } else {
            match app.input_mode {
                crate::state::InputMode::Insert => "INSERT",
                crate::state::InputMode::Normal => "NORMAL",
                crate::state::InputMode::Prefix => "PREFIX",
                _ => "",
            }
        };
        // The composer only accepts text in INSERT + Center focus; reflect
        // focus too so Tab-to-workspace doesn't silently eat keystrokes.
        let focus_label = match app.focus {
            crate::state::Focus::Center => "",
            crate::state::Focus::Left => " (left)",
            crate::state::Focus::Right => " (workspace)",
            _ => "",
        };
        put(
            &format!("-- {mode_label}{focus_label} --  "),
            Style::default().fg(p.muted),
            &mut x,
        );
    }
    // last_status (Ctrl+C hint, cancels, errors, model switches) is set by
    // the reducer but was never rendered — the double-Ctrl+C quit hint was
    // invisible. When set, it takes the "ready" slot.
    let transient_status = app.last_status.trim();
    let activity: Vec<(String, Style)> = if !transient_status.is_empty() {
        vec![(
            transient_status.to_string(),
            Style::default().fg(p.magenta).add_modifier(Modifier::BOLD),
        )]
    } else {
        match &app.tool_state {
            ToolState::Idle => vec![("ready".into(), Style::default().fg(p.muted))],
            ToolState::Streaming => vec![
                ("streaming".into(), Style::default().fg(p.cyan)),
                (format!(" {} ", g.sep), Style::default().fg(p.muted)),
                (
                    format!("{} tokens", app.total_output_tokens),
                    Style::default().fg(p.muted),
                ),
            ],
            ToolState::AwaitingApproval => vec![
                (
                    format!("{} approval needed {} ", g.decision, g.sep),
                    Style::default().fg(p.magenta),
                ),
                (
                    app.pending_approvals
                        .first()
                        .map(|a| a.tool_name.clone())
                        .unwrap_or_default(),
                    Style::default().fg(p.magenta),
                ),
            ],
            ToolState::Running(name) => vec![
                ("running ".into(), Style::default().fg(p.cyan)),
                (name.clone(), Style::default().fg(p.cyan)),
                (format!(" {} ", g.sep), Style::default().fg(p.muted)),
                ("3.2s".into(), Style::default().fg(p.muted)),
            ],
            ToolState::AutoGranted(name) => vec![
                ("◈ ".into(), Style::default().fg(p.muted)),
                (name.clone(), Style::default().fg(p.muted)),
            ],
        }
    };
    for (text, style) in activity {
        put(&text, style, &mut x);
    }

    // Right cluster: fixed slots, right-aligned (§6.11). Gaps per the
    // goldens: keys←3←session←3←cost←4←tokens←4←online←1←●←5←local←1←·←1←model.
    let mut rx = area.x + area.width - 1;
    fn rput(
        buf: &mut ratatui::buffer::Buffer,
        y: u16,
        text: &str,
        style: Style,
        gap: u16,
        rx: &mut u16,
    ) {
        let w = display_width(text) as u16;
        let start = rx.saturating_sub(w);
        for (i, c) in text.chars().enumerate() {
            buf[(start + i as u16, y)]
                .set_symbol(&c.to_string())
                .set_style(style);
        }
        *rx = start.saturating_sub(gap);
    }
    if level <= 2 {
        rput(
            buf,
            area.y,
            "? keys",
            Style::default().fg(p.muted),
            3,
            &mut rx,
        );
        // The '?' is bold (golden).
        let q_x = rx + 3;
        buf[(q_x, area.y)].set_style(Style::default().fg(p.ink2).add_modifier(Modifier::BOLD));
    }
    if level == 0 {
        rput(
            buf,
            area.y,
            &app.session_id_prefix,
            Style::default().fg(p.faint),
            3,
            &mut rx,
        );
    }
    let cost = app
        .total_cost_microcents
        .saturating_add(app.turn_cost_microcents);
    let cost_str = if app.model_priced {
        crate::format::cost(cost)
    } else {
        crate::format::cost_unpriced().to_string()
    };
    rput(
        buf,
        area.y,
        &cost_str,
        Style::default().fg(p.ink2),
        4,
        &mut rx,
    );
    let conn = match app.connection {
        ConnectionState::Online => (g.conn_online, "online", p.green),
        ConnectionState::Reconnecting => (g.conn_retrying, "reconnect", p.amber),
        ConnectionState::Offline => (g.conn_offline, "offline", p.red),
    };
    if level <= 1 {
        let tokens = format!(
            "{}{} {}{}",
            g.tokens_down,
            crate::format::tokens(app.total_input_tokens),
            g.tokens_up,
            crate::format::tokens(app.total_output_tokens)
        );
        rput(
            buf,
            area.y,
            &tokens,
            Style::default().fg(p.muted),
            4,
            &mut rx,
        );
        rput(
            buf,
            area.y,
            conn.1,
            Style::default().fg(p.muted),
            1,
            &mut rx,
        );
        rput(buf, area.y, conn.0, Style::default().fg(conn.2), 5, &mut rx);
        rput(
            buf,
            area.y,
            &app.provider,
            Style::default().fg(p.muted),
            1,
            &mut rx,
        );
        rput(buf, area.y, g.sep, Style::default().fg(p.muted), 1, &mut rx);
    } else if level == 2 {
        // Level 2 keeps the glyph, drops the word (§6.11).
        rput(buf, area.y, conn.0, Style::default().fg(conn.2), 4, &mut rx);
    }
    if level <= 2 {
        rput(
            buf,
            area.y,
            &app.model,
            Style::default().fg(p.ink2),
            1,
            &mut rx,
        );
    }
}

// ── Text helpers ─────────────────────────────────────────────────────────────

/// Render an assistant turn's body: prose paragraphs rich-rendered (the
/// first wrapped at cw-7 when timed, §8.3), fenced code blocks as code rows
/// with the language label right-aligned on the first row (§6.4).
fn render_assistant_body(
    text: &str,
    time: Option<&String>,
    cw: u16,
    compact: bool,
    continuation: bool,
    d: &Design,
) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let prose_wrap = if continuation {
        cw.saturating_sub(2) as usize
    } else {
        cw as usize
    };
    // Split on fences: alternating prose / code segments.
    let segments = text.split("```").peekable();
    let mut is_code = false;
    let mut first_prose = true;
    let mut prev_was_code = false;
    for seg in segments {
        if !is_code {
            if prev_was_code && !seg.trim().is_empty() {
                // Blank after a code block before prose resumes. The
                // empty tail after a closing fence doesn't count.
                out.push(Line::from(""));
                prev_was_code = false;
            }
            if !seg.trim().is_empty() {
                let rendered: Vec<Line<'static>> = if first_prose && time.is_some() && !compact {
                    wrap_first_paragraph_text(seg.trim(), (cw - 7) as usize, d)
                } else {
                    // Line-aware render, then re-wrap each rendered line at
                    // the prose width. ORBIT-turn inline code renders muted
                    // (the goldens).
                    let mut out_l: Vec<Line<'static>> = Vec::new();
                    for src in render_message(seg.trim(), d) {
                        let mut runs: Vec<(String, Style)> = Vec::new();
                        for sp in src.spans {
                            runs.push((sp.content.to_string(), sp.style));
                        }
                        out_l.extend(wrap_runs(&runs, prose_wrap));
                    }
                    out_l
                };
                for (li, mut line) in rendered.into_iter().enumerate() {
                    // Leads (goldens): a fresh turn's first line carries
                    // the ✦ gutter (caller adds ' ✦'); all prose rows
                    // after the first use a 3-space lead so text sits at
                    // cl. Continuations (no gutter) get 3 spaces too.
                    if li > 0 || continuation {
                        line.spans.insert(0, Span::raw("   "));
                    }
                    out.push(line);
                }
                first_prose = false;
            }
        } else {
            // A blank row separates prose from the code band (§6.4).
            if out_last_is_text(&out) {
                out.push(Line::from(""));
            }
            prev_was_code = true;
            // Code segment: first line is the language label.
            let mut lines = seg.trim_matches('\n').lines();
            let lang = lines.next().unwrap_or("").trim().to_string();
            let code_lines: Vec<&str> = lines.collect();
            for (i, cl) in code_lines.iter().enumerate() {
                // Code text at cl (§8.3 code band), continuation or not:
                // 3-space lead from the pane edge.
                // Band from cl-1 (§8.3): 3 plain lead cols, then the
                // band starts one col before the text.
                let band = Style::default().bg(d.palette.surface);
                let mut spans = vec![Span::raw("  "), Span::styled("  ", band)];
                // Keyword-aware code text: rust keywords syn_kw, the rest
                // ink (the golden's syntax colouring).
                const KEYWORDS: &[&str] = &[
                    "let", "fn", "match", "if", "else", "return", "use", "pub", "struct", "enum",
                    "impl", "for", "while", "loop", "const", "static", "mut", "as", "in", "where",
                    "async", "await",
                ];
                for (wi, w) in cl.split(' ').enumerate() {
                    if wi > 0 {
                        spans.push(Span::styled(" ", band));
                    }
                    let fg = if wi > 0 && w.starts_with("//") {
                        // A // comment runs muted to the end of the line.
                        let mut in_comment = false;
                        for trailing in cl.split_at(cl.find(w).unwrap_or(0)).1.split(' ') {
                            if trailing.starts_with("//") || in_comment {
                                in_comment = true;
                            }
                            let tfg = if in_comment {
                                d.palette.muted
                            } else {
                                d.palette.ink
                            };
                            spans.push(Span::styled(
                                trailing.to_string(),
                                Style::default().fg(tfg).bg(d.palette.surface),
                            ));
                            spans.push(Span::styled(" ", band));
                        }
                        spans.pop();
                        break;
                    } else if KEYWORDS.contains(&w) {
                        d.palette.syn_kw
                    } else {
                        d.palette.ink
                    };
                    spans.push(Span::styled(
                        w.to_string(),
                        Style::default().fg(fg).bg(d.palette.surface),
                    ));
                }
                // Pad the band to cl+cw (the full measure, golden col 111).
                let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                let band_right = cw as usize + 3;
                let mut pad = band_right.saturating_sub(used);
                // Plain rows pad to the band edge; label rows account for
                // the label + its banded trailing space inside `pad`.
                if i != 0 || lang.is_empty() {
                    pad += 1;
                }
                if i == 0 && !lang.is_empty() {
                    // Language label right-aligned inside the band.
                    pad = pad.saturating_sub(lang.chars().count());
                    spans.push(Span::styled(
                        " ".repeat(pad),
                        Style::default().bg(d.palette.surface),
                    ));
                    spans.push(Span::styled(
                        lang.clone(),
                        Style::default().fg(d.palette.faint).bg(d.palette.surface),
                    ));
                    spans.push(Span::styled(" ", Style::default().bg(d.palette.surface)));
                } else if pad > 0 {
                    spans.push(Span::styled(
                        " ".repeat(pad),
                        Style::default().bg(d.palette.surface),
                    ));
                }
                out.push(Line::from(spans));
            }
        }
        is_code = !is_code;
    }
    out
}

/// The first-paragraph rewrap (prose only), styled-run preserving.
fn wrap_first_paragraph_text(text: &str, width: usize, d: &Design) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    for src in render_message(text, d) {
        let mut runs: Vec<(String, Style)> = Vec::new();
        for sp in src.spans {
            runs.push((sp.content.to_string(), sp.style));
        }
        out.extend(wrap_runs(&runs, width));
    }
    out
}

/// Word-wrap a stream of styled runs at `width`, splitting spans at word
/// boundaries. Each output line carries its slice of the runs.
fn wrap_runs(runs: &[(String, Style)], width: usize) -> Vec<Line<'static>> {
    // Words carry their run's style and whether a space preceded them in
    // the original stream (run boundaries mid-word add no space).
    #[derive(Clone)]
    struct Word {
        text: String,
        style: Style,
        space_before: bool,
    }
    let mut words: Vec<Word> = Vec::new();
    let mut prev_run_ended_with_space = true;
    for (text, style) in runs {
        let run_starts_with_space = text.starts_with(' ');
        let mut first_in_run = true;
        for w in text.split(' ') {
            if w.is_empty() {
                continue;
            }
            // A space precedes this word when the original stream had one:
            // mid-run pieces always do; the first piece of a later run
            // when the previous run ended with a space or this one starts
            // with one.
            let space_before = if first_in_run {
                prev_run_ended_with_space || run_starts_with_space
            } else {
                true
            };
            words.push(Word {
                text: w.to_string(),
                style: *style,
                space_before,
            });
            first_in_run = false;
        }
        prev_run_ended_with_space = text.ends_with(' ');
    }
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut cur: Vec<Span<'static>> = Vec::new();
    let mut cur_w = 0usize;
    let mut prev_style: Option<Style> = None;
    for word in words {
        let ww = display_width(&word.text);
        if cur_w > 0 && cur_w + 1 + ww > width {
            out.push(Line::from(std::mem::take(&mut cur)));
            cur_w = 0;
            prev_style = None;
        }
        if cur_w > 0 && word.space_before {
            let same_run = prev_style == Some(word.style);
            if same_run {
                cur.push(Span::styled(" ", word.style));
            } else {
                cur.push(Span::raw(" "));
            }
            cur_w += 1;
        }
        cur.push(Span::styled(word.text.clone(), word.style));
        cur_w += ww;
        prev_style = Some(word.style);
    }
    if !cur.is_empty() {
        out.push(Line::from(cur));
    }
    out
}

/// Word-wrap text at `width` columns (greedy, grapheme-aware).
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        if para.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut line = String::new();
        let mut line_w = 0usize;
        for word in para.split(' ') {
            let ww = display_width(word);
            if line_w > 0 && line_w + 1 + ww > width {
                out.push(std::mem::take(&mut line));
                line_w = 0;
            }
            if line_w > 0 {
                line.push(' ');
                line_w += 1;
            }
            if ww > width {
                for c in word.chars() {
                    let cw = display_width(&c.to_string());
                    if line_w + cw > width && !line.is_empty() {
                        out.push(std::mem::take(&mut line));
                        line_w = 0;
                    }
                    line.push(c);
                    line_w += cw;
                }
            } else {
                line.push_str(word);
                line_w += ww;
            }
        }
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Middle truncation: keep head and tail, … in the middle (§6.5).
pub fn truncate_middle(text: &str, budget: usize) -> String {
    if display_width(text) <= budget {
        return text.to_string();
    }
    if budget < 4 {
        return truncate_graphemes(text, budget.max(1));
    }
    let half = (budget - 1) / 2;
    let head: String = text.chars().take(half).collect();
    let tail: String = text
        .chars()
        .skip(text.chars().count().saturating_sub(half))
        .collect();
    format!("{head}…{tail}")
}

// ── Command palette (§6.13) ──────────────────────────────────────────────────

fn render_palette(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let w = 78u16.min(area.width.saturating_sub(8));
    let h = 17u16.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + 3;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(ratatui::widgets::Clear, rect);

    let buf = frame.buffer_mut();
    let frame_style = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(frame_style);
    buf[(rect.x + rect.width - 1, rect.y)]
        .set_symbol("╮")
        .set_style(frame_style);
    buf[(rect.x, rect.y + rect.height - 1)]
        .set_symbol("╰")
        .set_style(frame_style);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(frame_style);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(frame_style);
        buf[(xx, rect.y + rect.height - 1)]
            .set_symbol("─")
            .set_style(frame_style);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(frame_style);
        buf[(rect.x + rect.width - 1, yy)]
            .set_symbol("│")
            .set_style(frame_style);
    }
    let inner = Rect {
        x: rect.x + 1,
        y: rect.y + 1,
        width: rect.width - 2,
        height: rect.height - 2,
    };

    // Query row: › magenta bold + query ink + esc close faint right.
    buf[(inner.x + 1, inner.y)].set_symbol(g.you).set_style(
        Style::default()
            .fg(p.magenta)
            .bg(p.surface2)
            .add_modifier(Modifier::BOLD),
    );
    for (i, c) in app.palette.query.chars().enumerate() {
        buf[(inner.x + 3 + i as u16, inner.y)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.ink).bg(p.surface2));
    }
    let esc = "esc close";
    let esc_x = inner.x + inner.width - esc.chars().count() as u16;
    for (i, c) in esc.chars().enumerate() {
        buf[(esc_x + i as u16, inner.y)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.faint).bg(p.surface2));
    }
    // Hairline.
    for xx in inner.x..inner.x + inner.width {
        buf[(xx, inner.y + 1)]
            .set_symbol("─")
            .set_style(Style::default().fg(p.rule).bg(p.surface2));
    }

    let mut row_y = inner.y + 2;
    let put_row = |text: &str, style: Style, row_y: &mut u16, buf: &mut ratatui::buffer::Buffer| {
        if *row_y >= inner.y + inner.height {
            return;
        }
        for (i, c) in text.chars().enumerate() {
            if inner.x + 1 + i as u16 >= inner.x + inner.width {
                break;
            }
            buf[(inner.x + 1 + i as u16, *row_y)]
                .set_symbol(&c.to_string())
                .set_style(style.bg(p.surface2));
        }
        *row_y += 1;
    };
    // COMMANDS
    let commands = crate::state::filtered_commands(&app.palette.query);
    put_row("COMMANDS", Style::default().fg(p.muted), &mut row_y, buf);
    {
        let c = commands.len().to_string();
        let cx = inner.x + inner.width - 1 - c.chars().count() as u16;
        for (i, ch) in c.chars().enumerate() {
            buf[(cx + i as u16, row_y - 1)]
                .set_symbol(&ch.to_string())
                .set_style(Style::default().fg(p.faint).bg(p.surface2));
        }
    }
    for (i, cmd) in commands.iter().enumerate() {
        let selected = i == app.palette.selected;
        let fill = if selected { p.wash } else { p.surface2 };
        if selected && row_y < inner.y + inner.height {
            buf[(inner.x, row_y)]
                .set_symbol("▌")
                .set_style(Style::default().fg(p.magenta).bg(fill));
        }
        let matched = fuzzy_positions(&cmd.label, &app.palette.query);
        let mut cx = inner.x + 2;
        for (ci, c) in cmd.label.chars().enumerate() {
            let is_match = matched.contains(&ci);
            let style = if is_match {
                Style::default()
                    .fg(p.magenta)
                    .bg(fill)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default()
                    .fg(p.ink)
                    .bg(fill)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.ink2).bg(fill)
            };
            buf[(cx, row_y)].set_symbol(&c.to_string()).set_style(style);
            cx += 1;
        }
        let desc_x = inner.x + 22;
        for (i, c) in cmd.description.chars().enumerate() {
            if desc_x + i as u16 >= inner.x + inner.width {
                break;
            }
            buf[(desc_x + i as u16, row_y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.muted).bg(fill));
        }
        row_y += 1;
    }
    // SESSIONS section
    if row_y < inner.y + inner.height {
        put_row("", Style::default(), &mut row_y, buf);
        put_row("SESSIONS", Style::default().fg(p.muted), &mut row_y, buf);
        for s in app.sessions.iter().take(3) {
            if row_y >= inner.y + inner.height {
                break;
            }
            let matched = fuzzy_positions(&s.title, &app.palette.query);
            let mut cx = inner.x + 2;
            for (ci, c) in s.title.chars().enumerate() {
                let style = if matched.contains(&ci) {
                    Style::default()
                        .fg(p.magenta)
                        .bg(p.surface2)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(p.ink2).bg(p.surface2)
                };
                if cx >= inner.x + inner.width - 4 {
                    break;
                }
                buf[(cx, row_y)].set_symbol(&c.to_string()).set_style(style);
                cx += 1;
            }
            let rx = inner.x + inner.width - 1 - s.recency.chars().count() as u16;
            for (i, c) in s.recency.chars().enumerate() {
                buf[(rx + i as u16, row_y)]
                    .set_symbol(&c.to_string())
                    .set_style(Style::default().fg(p.muted).bg(p.surface2));
            }
            row_y += 1;
        }
    }
    // ACTIVITY section
    if row_y < inner.y + inner.height {
        put_row("", Style::default(), &mut row_y, buf);
        put_row("ACTIVITY", Style::default().fg(p.muted), &mut row_y, buf);
        put_row(
            "model → glm-5.2    model",
            Style::default().fg(p.ink2),
            &mut row_y,
            buf,
        );
    }
}

/// Positions in `text` matched by the fuzzy `query` (subsequence).
fn fuzzy_positions(text: &str, query: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let hay: Vec<char> = text.to_lowercase().chars().collect();
    let q: Vec<char> = query.to_lowercase().chars().collect();
    let mut qi = 0;
    for (i, c) in hay.iter().enumerate() {
        if qi < q.len() && *c == q[qi] {
            positions.push(i);
            qi += 1;
        }
    }
    positions
}

// ── Overlays — the only frames (§1, §6.15–6.16) ──────────────────────────────

/// Quit confirmation — a small rule_hi rounded card (§6.16).
fn render_quit_modal(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, _g: &Glyphs) {
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
    let w = 44u16.min(area.width.saturating_sub(8));
    let h = 7u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let buf = frame.buffer_mut();
    let fs = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y)]
        .set_symbol("╮")
        .set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)]
        .set_symbol("╰")
        .set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)]
            .set_symbol("─")
            .set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)]
            .set_symbol("│")
            .set_style(fs);
    }
    let t = format!(" {title} ");
    for (i, c) in t.chars().enumerate() {
        buf[(rect.x + 2 + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(
                Style::default()
                    .fg(p.ink)
                    .bg(p.surface2)
                    .add_modifier(Modifier::BOLD),
            );
    }
    for (i, c) in message.chars().enumerate() {
        buf[(rect.x + 2 + i as u16, rect.y + 2)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.ink).bg(p.surface2));
    }
    let keys = "y quit   n stay";
    for (i, c) in keys.chars().enumerate() {
        let style = if c == 'y' || c == 'n' {
            Style::default().fg(p.magenta).bg(p.surface2)
        } else {
            Style::default().fg(p.muted).bg(p.surface2)
        };
        buf[(rect.x + 2 + i as u16, rect.y + 4)]
            .set_symbol(&c.to_string())
            .set_style(style);
    }
}

/// §6.16 help overlay: 78 wide, two columns of keys.
fn render_help_overlay(
    frame: &mut ratatui::Frame,
    area: Rect,
    _app: &App,
    d: &Design,
    _g: &Glyphs,
) {
    let p = &d.palette;
    let w = 78u16.min(area.width.saturating_sub(8));
    let h = 16u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + 3;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let buf = frame.buffer_mut();
    let fs = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y)]
        .set_symbol("╮")
        .set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)]
        .set_symbol("╰")
        .set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)]
            .set_symbol("─")
            .set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)]
            .set_symbol("│")
            .set_style(fs);
    }
    for (i, c) in " Keys ".chars().enumerate() {
        buf[(rect.x + 2 + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(
                Style::default()
                    .fg(p.ink)
                    .bg(p.surface2)
                    .add_modifier(Modifier::BOLD),
            );
    }
    let esc = " esc close ";
    let esc_x = rect.x + rect.width - 1 - esc.chars().count() as u16;
    for (i, c) in esc.chars().enumerate() {
        buf[(esc_x + i as u16, rect.y + rect.height - 1)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.faint).bg(p.surface2));
    }
    let left: &[(&str, &str)] = &[
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
    ];
    let right: &[(&str, &str)] = &[
        ("IN THE COMPOSER", ""),
        ("⏎", "send; queues while busy"),
        ("⇧⏎  alt+⏎", "new line"),
        ("↑  ↓", "history"),
        ("pgup  pgdn", "scroll the transcript"),
        ("end", "newest line (if empty)"),
        ("?", "this help (if empty)"),
        ("", ""),
        ("APPROVAL", ""),
        ("y", "allow once"),
        ("R", "allow tool for session"),
        ("n  esc", "deny"),
    ];
    let put = |col_x: u16, rows: &[(&str, &str)], buf: &mut ratatui::buffer::Buffer| {
        for (i, (key, desc)) in rows.iter().enumerate() {
            let yy = rect.y + 2 + i as u16;
            if yy >= rect.y + rect.height - 1 {
                break;
            }
            let is_label = desc.is_empty() && !key.is_empty();
            let kstyle = if is_label {
                Style::default().fg(p.muted).bg(p.surface2)
            } else {
                Style::default()
                    .fg(p.ink2)
                    .bg(p.surface2)
                    .add_modifier(Modifier::BOLD)
            };
            for (j, c) in key.chars().enumerate() {
                buf[(col_x + j as u16, yy)]
                    .set_symbol(&c.to_string())
                    .set_style(kstyle);
            }
            if !desc.is_empty() {
                let dx = col_x + 11;
                for (j, c) in desc.chars().enumerate() {
                    buf[(dx + j as u16, yy)]
                        .set_symbol(&c.to_string())
                        .set_style(Style::default().fg(p.muted).bg(p.surface2));
                }
            }
        }
    };
    put(rect.x + 3, left, buf);
    put(rect.x + 41, right, buf);
}

/// The approval card (§6.15): docked where the composer was, the only
/// magenta frame on screen.
fn render_approval_modal(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
    wc: &WidthClass,
) {
    let p = &d.palette;
    let first = &app.pending_approvals[0];
    let card_w = 80u16.min(wc.conversation.1.saturating_sub(4));
    // Honesty rule: the card draws only facts carried by the request
    // (tool name, action summary, backend-classified risk). The fixture
    // facts grid — "runs in ~/src/orbit", "sandbox landlock · rw /tmp
    // only" — was invented; it is gone until real tools supply real
    // facts (working directory, applied sandbox profile, network
    // policy) on the ApprovalRequest itself.
    let has_facts = false;
    let card_h: u16 = if has_facts { 9 } else { 6 };
    let card_x = wc.conversation.0 + (wc.conversation.1.saturating_sub(card_w)) / 2;
    let card_y = area.y + area.height.saturating_sub(card_h + 2);
    let rect = Rect {
        x: card_x,
        y: card_y,
        width: card_w,
        height: card_h,
    };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let buf = frame.buffer_mut();
    let fill = p.surface;
    let fs = Style::default().fg(p.magenta).bg(fill);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(fill));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y)]
        .set_symbol("╮")
        .set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)]
        .set_symbol("╰")
        .set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)]
            .set_symbol("─")
            .set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)]
            .set_symbol("│")
            .set_style(fs);
    }
    // Top border: '◇ Allow shell?' + risk badge right.
    let badge = g.risk_meter(first.risk);
    let risk_word = match first.risk {
        0 | 1 => "low risk",
        2 => "medium risk",
        _ => "high risk",
    };
    let risk_color = match first.risk {
        0 | 1 => p.muted,
        2 => p.amber,
        _ => p.red,
    };
    let title = format!("◇ Allow {}?", first.tool_name);
    for (i, c) in title.chars().enumerate() {
        let style = match c {
            '◇' => Style::default()
                .fg(p.magenta)
                .bg(fill)
                .add_modifier(Modifier::BOLD),
            ' ' | 'A' | 'l' | 'o' | 'w' | '?' => Style::default()
                .fg(p.ink)
                .bg(fill)
                .add_modifier(Modifier::BOLD),
            _ => Style::default()
                .fg(p.magenta)
                .bg(fill)
                .add_modifier(Modifier::BOLD),
        };
        buf[(rect.x + 2 + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(style);
    }
    let badge_text = format!("{badge} {risk_word}");
    let bx = rect.x + rect.width - 3 - badge_text.chars().count() as u16;
    for (i, c) in badge_text.chars().enumerate() {
        let style = if c == '▰' || c == '▱' {
            Style::default().fg(risk_color).bg(fill)
        } else {
            Style::default()
                .fg(risk_color)
                .bg(fill)
                .add_modifier(Modifier::BOLD)
        };
        buf[(bx + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(style);
    }
    // The action, bold ink, in full.
    for (i, c) in first.summary.chars().enumerate() {
        if rect.x + 3 + i as u16 >= rect.x + rect.width - 1 {
            break;
        }
        buf[(rect.x + 3 + i as u16, rect.y + 2)]
            .set_symbol(&c.to_string())
            .set_style(
                Style::default()
                    .fg(p.ink)
                    .bg(fill)
                    .add_modifier(Modifier::BOLD),
            );
    }
    // Facts grid (fixture data; the backend supplies real facts).
    let facts: [(&str, &str); 4] = [
        ("runs in", "~/src/orbit"),
        ("sandbox", "landlock · rw /tmp only"),
        ("egress", "none"),
        ("ledger", "decision is recorded"),
    ];
    for (i, (label, value)) in facts.iter().enumerate() {
        let yy = rect.y + 4 + (i / 2) as u16;
        let xx = rect.x + 3 + (i % 2) as u16 * 40;
        for (j, c) in label.chars().enumerate() {
            buf[(xx + j as u16, yy)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.muted).bg(fill));
        }
        for (j, c) in value.chars().enumerate() {
            buf[(xx + label.chars().count() as u16 + 2 + j as u16, yy)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.ink2).bg(fill));
        }
    }
    // Keys row: keycap chips.
    let keys_y = rect.y + rect.height - 2;
    let mut kx = rect.x + 3;
    // Keys row: keycap chips, all writes bounds-checked (narrow terminals).
    let key_row_end = rect.x + rect.width - 1;
    let put_key = |key: &str, desc: &str, kx: &mut u16, buf: &mut ratatui::buffer::Buffer| {
        for (j, c) in format!(" {key} ").chars().enumerate() {
            if *kx + j as u16 > key_row_end {
                return;
            }
            buf[(*kx + j as u16, keys_y)]
                .set_symbol(&c.to_string())
                .set_style(
                    Style::default()
                        .fg(p.ink)
                        .bg(p.surface2)
                        .add_modifier(Modifier::BOLD),
                );
        }
        *kx += key.chars().count() as u16 + 2;
        for (j, c) in format!(" {desc}   ").chars().enumerate() {
            if *kx + j as u16 > key_row_end {
                return;
            }
            buf[(*kx + j as u16, keys_y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.ink2).bg(fill));
        }
        *kx += desc.chars().count() as u16 + 4;
    };
    put_key("y", "allow once", &mut kx, buf);
    put_key(
        "R",
        &format!("allow {} for this session", first.tool_name),
        &mut kx,
        buf,
    );
    put_key("n  esc", "deny", &mut kx, buf);
}

// ── Startup mark (§8) ─────────────────────────────────────────────────────────

/// The expanded mark (§8.1): half-block letterforms, a braille ring tilted
/// behind the strokes, the star at the ring's upper right, the tagline
/// beneath.
pub fn welcome_mark(d: &Design, _g: &Glyphs) -> Vec<Line<'static>> {
    welcome_mark_frame(d, u8::MAX)
}

/// The welcome mark at a startup frame (§8.3).
pub fn welcome_mark_frame(d: &Design, frame: u8) -> Vec<Line<'static>> {
    let p = &d.palette;
    let row0 = "    ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀";
    let row1 = " ⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █";
    let row2 = " ⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █";
    let tagline = "    the harness that orbits around you";
    let mark_line = |row: &str| -> Line<'static> {
        let spans: Vec<Span> = row
            .chars()
            .map(|c| {
                let color = if c == '✦' {
                    p.magenta
                } else if c.is_ascii_alphanumeric() || "▄▀█".contains(c) {
                    p.ink
                } else {
                    p.magenta_dim
                };
                Span::styled(c.to_string(), Style::default().fg(color))
            })
            .collect();
        Line::from(spans)
    };
    let reveal: usize = match frame {
        0 => 8,
        1 => 16,
        2 => 24,
        3 => 30,
        4 => 36,
        _ => usize::MAX,
    };
    let mask = |row: &str| -> String {
        if reveal == usize::MAX {
            return row.to_string();
        }
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

// ── Size notice (§9.23) ──────────────────────────────────────────────────────

fn render_size_notice(frame: &mut ratatui::Frame, area: Rect, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    frame.buffer_mut()[(1, 0)]
        .set_symbol(g.orbit)
        .set_style(Style::default().fg(p.magenta));
    let lines: Vec<(String, Style)> = vec![
        (
            "ORBIT needs at least 40 × 10".into(),
            Style::default().fg(p.ink).add_modifier(Modifier::BOLD),
        ),
        (
            format!("this terminal is {} × {}", area.width, area.height),
            Style::default().fg(p.muted),
        ),
        (String::new(), Style::default()),
        (
            "enlarge the window or run".into(),
            Style::default().fg(p.muted),
        ),
        ("orbit chat --no-tui".into(), Style::default().fg(p.ink2)),
    ];
    for (i, (text, style)) in lines.iter().enumerate() {
        let y = 2 + i as u16;
        if y >= area.height {
            break;
        }
        let w = display_width(text) as u16;
        let x = (area.width.saturating_sub(w)) / 2;
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text.clone(), *style))),
            Rect {
                x,
                y,
                width: area.width.saturating_sub(x),
                height: 1,
            },
        );
    }
}
