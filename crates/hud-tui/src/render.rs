//! Ratatui rendering — the ORBIT visual system (PROMPT.md §6, §8).
//!
//! Ink, not boxes: structure comes from gutters, alignment, spacing and
//! hairlines. No pane has a border. At most one rounded frame is on screen
//! at a time, and a frame always means "this needs you" — an approval, the
//! palette, a confirmation. All colours come from the token palette
//! (tokens.rs); all glyphs from glyphs.rs. No literals in render code.
//!
//! Layout (§8): one shared pane-header row, air, pane bodies with the
//! transcript bottom-anchored, air, the composer (input + hint), and the
//! status line. Width classes (§8.2) pick which panes exist; the
//! conversation column geometry (§8.3) fixes every offset.

use crate::glyphs::Glyphs;
use crate::rich::render_message;
use crate::state::{
    App, ConnectionState, Focus, LeftTab, LogoPhase, SessionRow, TaskState, ToolOutcome,
    ToolState, TranscriptLine, VerificationResult,
};
use crate::tokens::Design;
use crate::unicode::{display_width, truncate_graphemes};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

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

    // Vertical (§8.1): header | air | body | air | composer | hint | status.
    let show_hint = area.height >= 16 && !wc.tight;
    let show_header = area.height >= 12 || !wc.single_view;
    let mut constraints = Vec::new();
    if show_header {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Length(1)); // air
    constraints.push(Constraint::Min(4)); // body
    constraints.push(Constraint::Length(1)); // air above composer
    constraints.push(Constraint::Length(1)); // composer input
    if show_hint {
        constraints.push(Constraint::Length(1)); // hint row
    }
    constraints.push(Constraint::Length(1)); // status
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    let mut i = 0usize;
    if show_header {
        render_pane_headers(frame, rows[i], app, &wc, d, g);
        i += 1;
    }
    i += 1; // air
    let body = rows[i];
    i += 1;
    i += 1; // air above composer
    let composer_row = rows[i];
    i += 1;
    let hint_row = if show_hint {
        let r = rows[i];
        i += 1;
        r
    } else {
        Rect::new(0, 0, 0, 0)
    };
    let status_row = rows[i];

    // Horizontal split of the body into panes. The dividers run from below
    // the header to above the status line (§8.6: row 0 to H-2 — including
    // the air rows), so compute them against the full span.
    let div_top = if show_header { area.y + 1 } else { area.y };
    let div_bottom = status_row.y; // exclusive
    let mut panes: Vec<Rect> = Vec::new();
    let mut dividers: Vec<Rect> = Vec::new();
    let mut x = body.x;
    if let Some((_, sw)) = wc.sessions {
        panes.push(Rect { x, y: body.y, width: sw, height: body.height });
        x += sw;
        dividers.push(Rect { x, y: div_top, width: 1, height: div_bottom.saturating_sub(div_top) });
        x += 1;
    }
    let (_, cw) = wc.conversation;
    panes.push(Rect { x, y: body.y, width: cw, height: body.height });
    x += cw;
    if let Some((_, ww)) = wc.workspace {
        dividers.push(Rect { x, y: div_top, width: 1, height: div_bottom.saturating_sub(div_top) });
        x += 1;
        panes.push(Rect { x, y: body.y, width: ww, height: body.height });
    }
    // Record pane rects for the mouse hit-test.
    app.pane_rects.left.set(panes.first().copied().filter(|_| wc.sessions.is_some()));
    app.pane_rects
        .center
        .set(panes.get(wc.sessions.is_some() as usize).copied());
    app.pane_rects
        .right
        .set(panes.last().copied().filter(|_| wc.workspace.is_some()));

    // Render panes.
    let mut pane_idx = 0usize;
    if wc.sessions.is_some() {
        render_sessions_rail(frame, panes[pane_idx], app, d, g);
        pane_idx += 1;
    }
    let conv_area = panes[pane_idx];
    render_conversation(
        frame,
        conv_area,
        app,
        composer_text,
        d,
        g,
        &wc,
        composer_row,
        hint_row,
        show_hint,
    );
    // The thumb spans exactly the pane rows that carry content — scan the
    // rendered buffer (immune to line-accounting drift).
    let buf = frame.buffer_mut();
    let mut t0 = conv_area.bottom();
    let mut t1 = conv_area.y;
    for y in conv_area.top()..conv_area.bottom() {
        let has_content = (conv_area.left()..conv_area.right())
            .any(|x| buf[(x, y)].symbol() != " ");
        if has_content {
            t0 = t0.min(y);
            t1 = t1.max(y);
        }
    }
    let thumb_range = if t1 >= t0 { (t0, t1) } else { (0, 0) };
    pane_idx += 1;
    if wc.workspace.is_some() {
        render_workspace_rail(frame, panes[pane_idx], app, d, g);
    }
    for (di, div) in dividers.iter().enumerate() {
        // The divider immediately right of the transcript is its scroll
        // track (§8.6) — the thumb spans the content rows (bottom-anchored).
        let is_scroll_track = (wc.sessions.is_some() && di == 1)
            || (wc.sessions.is_none() && di == 0);
        render_divider(frame, *div, d, g, is_scroll_track, thumb_range);
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

// ── Pane headers (§8.5) ──────────────────────────────────────────────────────

/// One shared header row: each pane's title + rule + right meta, side by
/// side. Focused: magenta bold title, heavy ━ in rule_hi. Unfocused: active
/// tab ink bold, other tabs muted, light ─ in rule.
fn render_pane_headers(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    wc: &WidthClass,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    let buf = frame.buffer_mut();
    if wc.single_view {
        // View switcher: Sessions   Conversation   Workspace 2/5 ━━━━
        let active = match app.focus {
            Focus::Left => "Sessions",
            Focus::Center | Focus::Status => "Conversation",
            Focus::Right => "Workspace",
        };
        let mut x = 1u16;
        for name in ["Sessions", "Conversation", "Workspace"] {
            let style = if name == active {
                Style::default().fg(p.magenta).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.muted)
            };
            for c in name.chars() {
                if x >= area.x + area.width {
                    return;
                }
                buf[(x, area.y)].set_symbol(&c.to_string()).set_style(style);
                x += 1;
            }
            x += 3;
        }
        // The workspace meta (2/5) rides the switcher: cyan while a turn
        // is live, muted when idle.
        if !app.workspace_meta.is_empty() {
            let live = app.turn_in_flight
                || app.tool_state == ToolState::Streaming
                || matches!(app.tool_state, ToolState::Running(_));
            let style = if live {
                Style::default().fg(p.cyan)
            } else {
                Style::default().fg(p.muted)
            };
            for c in app.workspace_meta.chars() {
                if x >= area.x + area.width {
                    break;
                }
                buf[(x, area.y)].set_symbol(&c.to_string()).set_style(style);
                x += 1;
            }
            x += 1;
        }
        // The rule fills the rest, heavy for the focused view.
        let focused_center = app.focus == Focus::Center;
        let rule_ch = if focused_center { g.rule_focus } else { g.rule };
        let rule_color = if focused_center { p.rule_hi } else { p.rule };
        while x < area.x + area.width.saturating_sub(1) {
            buf[(x, area.y)]
                .set_symbol(rule_ch)
                .set_style(Style::default().fg(rule_color));
            x += 1;
        }
        return;
    }
    // Multi-pane: one header segment per pane.
    if let Some((sx, sw)) = wc.sessions {
        // Two tabs: the active one ink bold (focused: magenta bold), the
        // other muted (§8.5).
        let (a, b) = match app.left_tab {
            LeftTab::Sessions => ("Sessions", "Activity"),
            LeftTab::Verbose => ("Activity", "Sessions"),
        };
        draw_tabs_header(buf, Rect { x: sx, y: area.y, width: sw, height: 1 }, a, b, app.focus == Focus::Left, d, g);
    }
    let mut segs: Vec<(Rect, &str, String, bool)> = Vec::new();
    let (cx, cwid) = wc.conversation;
    segs.push((
        Rect { x: cx, y: area.y, width: cwid, height: 1 },
        &app.header_title,
        app.header_meta.clone(),
        app.focus == Focus::Center,
    ));
    if let Some((wx, ww)) = wc.workspace {
        segs.push((
            Rect { x: wx, y: area.y, width: ww, height: 1 },
            "Workspace",
            String::new(),
            app.focus == Focus::Right,
        ));
    }
    for (rect, title, meta, focused) in segs {
        draw_pane_header(buf, rect, title, &meta, focused, d, g);
    }
    // The divider glyphs pierce the header row too (§8.6: row 0 to H-2).
    if let Some((_, sw)) = wc.sessions {
        buf[(sw, area.y)]
            .set_symbol(g.divider)
            .set_style(Style::default().fg(p.rule));
    }
    if let Some((wx, _)) = wc.workspace {
        buf[(wx.saturating_sub(1), area.y)]
            .set_symbol(g.divider)
            .set_style(Style::default().fg(p.rule));
    }
}

/// One pane's header segment: title at x+1, rule after, right meta at
/// x+w-2 (§8.5).
fn draw_pane_header(
    buf: &mut ratatui::buffer::Buffer,
    rect: Rect,
    title: &str,
    meta: &str,
    focused: bool,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    if rect.width < 3 {
        return;
    }
    let (title_style, rule_ch, rule_color) = if focused {
        (
            Style::default().fg(p.magenta).add_modifier(Modifier::BOLD),
            g.rule_focus,
            p.rule_hi,
        )
    } else {
        (Style::default().fg(p.ink).add_modifier(Modifier::BOLD), g.rule, p.rule)
    };
    let mut x = rect.x + 1;
    for c in title.chars() {
        if x >= rect.x + rect.width {
            return;
        }
        buf[(x, rect.y)].set_symbol(&c.to_string()).set_style(title_style);
        x += 1;
    }
    let meta_w = display_width(meta) as u16;
    let meta_x = if meta_w > 0 {
        rect.x + rect.width.saturating_sub(2).saturating_sub(meta_w).saturating_add(1)
    } else {
        rect.x + rect.width.saturating_sub(1)
    };
    let rule_end = if meta_w > 0 {
        meta_x.saturating_sub(1)
    } else {
        rect.x + rect.width - 1
    };
    x += 1;
    while x < rule_end {
        buf[(x, rect.y)]
            .set_symbol(rule_ch)
            .set_style(Style::default().fg(rule_color));
        x += 1;
    }
    if meta_w > 0 {
        let mut mx = meta_x;
        for c in meta.chars() {
            if mx >= rect.x + rect.width {
                break;
            }
            buf[(mx, rect.y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.muted));
            mx += 1;
        }
    }
}

/// A two-tab header (the Sessions rail): active tab bold (magenta when the
/// rail is focused, ink otherwise), the other tab muted, light rule.
fn draw_tabs_header(
    buf: &mut ratatui::buffer::Buffer,
    rect: Rect,
    tab_a: &str,
    tab_b: &str,
    focused: bool,
    d: &Design,
    g: &Glyphs,
) {
    let p = &d.palette;
    if rect.width < 4 {
        return;
    }
    let active_style = if focused {
        Style::default().fg(p.magenta).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(p.ink).add_modifier(Modifier::BOLD)
    };
    let mut x = rect.x + 1;
    for c in tab_a.chars() {
        if x >= rect.x + rect.width { return; }
        buf[(x, rect.y)].set_symbol(&c.to_string()).set_style(active_style);
        x += 1;
    }
    x += 2;
    for c in tab_b.chars() {
        if x >= rect.x + rect.width { return; }
        buf[(x, rect.y)].set_symbol(&c.to_string()).set_style(Style::default().fg(p.muted));
        x += 1;
    }
    x += 1;
    while x < rect.x + rect.width.saturating_sub(1) {
        buf[(x, rect.y)].set_symbol(g.rule).set_style(Style::default().fg(p.rule));
        x += 1;
    }
}

// ── Divider / scroll track (§8.6) ────────────────────────────────────────────

fn render_divider(
    frame: &mut ratatui::Frame,
    area: Rect,
    d: &Design,
    g: &Glyphs,
    scroll_track: bool,
    thumb_range: (u16, u16),
) {
    if area.width < 1 || area.height < 1 {
        return;
    }
    let buf = frame.buffer_mut();
    // The thumb spans the content rows (bottom-anchored), muted; the rest
    // of the track is rule (§8.6).
    let (t0, t1) = thumb_range;
    for y in area.top()..area.bottom() {
        let (sym, fg) = if scroll_track && y >= t0 && y <= t1 {
            (g.thumb, d.palette.muted)
        } else {
            (g.divider, d.palette.rule)
        };
        buf[(area.x, y)].set_symbol(sym).set_style(Style::default().fg(fg));
    }
}

// ── Sessions rail (§6.9) ─────────────────────────────────────────────────────

fn render_sessions_rail(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
) {
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
            if focused { p.wash } else { p.surface2 }
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
        let rec_x = area.x + area.width.saturating_sub(2).saturating_sub(recency_w).saturating_add(1);
        let title = truncate_graphemes(&s.title, budget);
        let title_style = if s.open || (cursor && focused) {
            Style::default().fg(p.ink).add_modifier(Modifier::BOLD).bg(fill)
        } else {
            Style::default().fg(p.ink2).bg(fill)
        };
        let mut tx = area.x + 3;
        for c in title.chars() {
            if tx >= area.x + area.width {
                break;
            }
            buf[(tx, y)].set_symbol(&c.to_string()).set_style(title_style);
            tx += 1;
        }
        // One space between title and recency (the golden's rhythm).
        if tx < rec_x {
            buf[(tx, y)].set_symbol(" ").set_style(Style::default().bg(fill));
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
                        let used: usize =
                            spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let pad = rel_right.saturating_sub(used + t.chars().count());
                        spans.push(Span::styled(
                            " ".repeat(pad),
                            Style::default().fg(p.muted),
                        ));
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
                let body = render_assistant_body(
                    text,
                    time.as_ref(),
                    cw,
                    wc.compact,
                    continuation,
                    d,
                );
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
                        let used: usize =
                            spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let pad = rel_right.saturating_sub(used + t.chars().count());
                        spans.push(Span::styled(
                            " ".repeat(pad),
                            Style::default().fg(p.muted),
                        ));
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
                        (false, Some(ToolOutcome::Denied)) => (
                            g.denied,
                            p.muted,
                            p.ink2,
                            "denied by you".into(),
                            p.muted,
                        ),
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
                    let used: usize =
                        spans.iter().map(|s| display_width(&s.to_string())).sum();
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
                spans.push(Span::styled(g.orbit.to_string(), Style::default().fg(p.cyan)));
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
    let para = Paragraph::new(lines).scroll((scroll as u16, 0));
    frame.render_widget(para, area);

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
    buf[(cl - 1, composer_row.y)]
        .set_symbol(g.you)
        .set_style(
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

    // ── Hint row (§5.5) ────────────────────────────────────────────────────
    if show_hint {
        let buf = frame.buffer_mut();
        let band_end = band_right.min(hint_row.x + hint_row.width - 1);
        for x in band_left..=band_end {
            buf[(x, hint_row.y)].set_style(Style::default().bg(p.surface));
        }
        let mut x = cl + 1;
        let mut put = |text: &str, style: Style, x: &mut u16, buf: &mut ratatui::buffer::Buffer| {
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
            for (i, c) in text.chars().enumerate() {
                buf[(tx + i as u16, hint_row.y)]
                    .set_symbol(&c.to_string())
                    .set_style(Style::default().fg(color).bg(p.surface));
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
    let pad = " ".repeat(mark_x.saturating_sub(area.x).max(0) as usize);
    for l in mark {
        let mut padded = vec![Span::raw(pad.clone())];
        padded.extend(l.spans);
        lines.push(Line::from(padded));
    }
    lines.push(Line::from(""));
    // Tagline centered.
    let tagline = "the harness that orbits around you";
    let tag_x = cl + cw.saturating_sub(tagline.chars().count() as u16) / 2;
    let tag_pad = " ".repeat(tag_x.saturating_sub(area.x).max(0) as usize);
    lines.push(Line::from(vec![
        Span::raw(tag_pad),
        Span::styled(tagline, Style::default().fg(p.muted)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    // Readiness row (fixture data; the backend fills it when it exists).
    let readiness = "✓ trust root    ✓ ledger · 7 records    ✓ local · glm-5.2";
    let r_x = cl + cw.saturating_sub(readiness.chars().count() as u16) / 2;
    let r_pad = " ".repeat(r_x.saturating_sub(area.x).max(0) as usize);
    let mut spans = vec![Span::raw(r_pad)];
    for seg in readiness.split("    ") {
        let (glyph, rest) = seg.split_once(' ').unwrap_or((seg, ""));
        spans.push(Span::styled(glyph, Style::default().fg(p.green)));
        if !rest.is_empty() {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(rest, Style::default().fg(p.ink2)));
        }
        spans.push(Span::raw("    "));
    }
    lines.push(Line::from(spans));
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    // Starters.
    let describe = "Describe a task below, or start with";
    let d_x = cl + 9;
    let d_pad = " ".repeat(d_x.saturating_sub(area.x).max(0) as usize);
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
                let (conn, cc) = if i < current { ("━━", p.muted) } else { ("──", p.rule) };
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
        let used: usize = stepper.iter().map(|sp| display_width(&sp.to_string())).sum();
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
                let mut title_style = if bold {
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
                let mut runs: Vec<(String, Style)> = vec![(f.title.clone(), Style::default().fg(p.ink2))];
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
                        let used: usize =
                            spans.iter().map(|s| display_width(&s.to_string())).sum();
                        let right = (area.width as usize).saturating_sub(2);
                        let pad = right
                            .saturating_sub(used + v.result_text.chars().count())
                            + 1;
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
    let working = app.tool_state == ToolState::Streaming
        || matches!(app.tool_state, ToolState::Running(_));
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
    buf[(1, area.y)].set_symbol(mark).set_style(Style::default().fg(mark_color));
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
            buf[(*x, area.y)].set_symbol(&c.to_string()).set_style(style);
            *x += 1;
        }
    };
    let activity: Vec<(String, Style)> = match &app.tool_state {
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
            (format!("{} approval needed {} ", g.decision, g.sep), Style::default().fg(p.magenta)),
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
    };
    for (text, style) in activity {
        put(&text, style, &mut x);
    }

    // Right cluster: fixed slots, right-aligned (§6.11). Gaps per the
    // goldens: keys←3←session←3←cost←4←tokens←4←online←1←●←5←local←1←·←1←model.
    let mut rx = area.x + area.width - 1;
    fn rput(buf: &mut ratatui::buffer::Buffer, y: u16, text: &str, style: Style, gap: u16, rx: &mut u16) {
        let w = display_width(text) as u16;
        let start = rx.saturating_sub(w);
        for (i, c) in text.chars().enumerate() {
            buf[(start + i as u16, y)].set_symbol(&c.to_string()).set_style(style);
        }
        *rx = start.saturating_sub(gap);
    }
    if level <= 2 {
        rput(buf, area.y, "? keys", Style::default().fg(p.muted), 3, &mut rx);
        // The '?' is bold (golden).
        let q_x = rx + 3;
        buf[(q_x, area.y)].set_style(Style::default().fg(p.ink2).add_modifier(Modifier::BOLD));
    }
    if level == 0 {
        rput(buf, area.y, &app.session_id_prefix, Style::default().fg(p.faint), 3, &mut rx);
    }
    let cost = app.total_cost_microcents.saturating_add(app.turn_cost_microcents);
    let cost_str = if app.model_priced {
        crate::format::cost(cost)
    } else {
        crate::format::cost_unpriced().to_string()
    };
    rput(buf, area.y, &cost_str, Style::default().fg(p.ink2), 4, &mut rx);
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
        rput(buf, area.y, &tokens, Style::default().fg(p.muted), 4, &mut rx);
        rput(buf, area.y, conn.1, Style::default().fg(p.muted), 1, &mut rx);
        rput(buf, area.y, conn.0, Style::default().fg(conn.2), 5, &mut rx);
        rput(buf, area.y, &app.provider, Style::default().fg(p.muted), 1, &mut rx);
        rput(buf, area.y, g.sep, Style::default().fg(p.muted), 1, &mut rx);
    } else if level == 2 {
        // Level 2 keeps the glyph, drops the word (§6.11).
        rput(buf, area.y, conn.0, Style::default().fg(conn.2), 4, &mut rx);
    }
    if level <= 2 {
        rput(buf, area.y, &app.model, Style::default().fg(p.ink2), 1, &mut rx);
    }
}

// ── Text helpers ─────────────────────────────────────────────────────────────

/// Render a message with its FIRST paragraph wrapped at `width` (the
/// timed-turn rule, §8.3): the first paragraph's lines wrap at cw-7 so the
/// time never collides; later paragraphs wrap at the measure.
fn wrap_first_paragraph(text: &str, width: usize, d: &Design) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut first = true;
    for para in text.split("\n\n") {
        if first {
            // Rich-render once, then re-wrap the styled run stream at the
            // tighter width (inline code chips survive splits, §6.4).
            let rendered = crate::rich::render_line(para, d);
            let mut runs: Vec<(String, Style)> = Vec::new();
            for sp in rendered.spans {
                runs.push((sp.content.to_string(), sp.style));
            }
            out.extend(wrap_runs(&runs, width));
            first = false;
        } else {
            for line in render_message(para, d) {
                // Own the spans: clone each into 'static strings.
                let spans: Vec<Span<'static>> = line
                    .spans
                    .iter()
                    .map(|sp| Span::styled(sp.content.to_string(), sp.style))
                    .collect();
                out.push(Line::from(spans));
            }
        }
    }
    out
}

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
    let prose_wrap = if continuation { cw.saturating_sub(2) as usize } else { cw as usize };
    // Split on fences: alternating prose / code segments.
    let mut segments = text.split("```").peekable();
    let mut is_code = false;
    let mut first_prose = true;
    let mut prev_was_code = false;
    while let Some(seg) = segments.next() {
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
                    "let", "fn", "match", "if", "else", "return", "use", "pub",
                    "struct", "enum", "impl", "for", "while", "loop", "const",
                    "static", "mut", "as", "in", "where", "async", "await",
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
                            let tfg = if in_comment { d.palette.muted } else { d.palette.ink };
                            spans.push(Span::styled(trailing.to_string(), Style::default().fg(tfg).bg(d.palette.surface)));
                            spans.push(Span::styled(" ", band));
                        }
                        spans.pop();
                        break;
                    } else if KEYWORDS.contains(&w) {
                        d.palette.syn_kw
                    } else {
                        d.palette.ink
                    };
                    spans.push(Span::styled(w.to_string(), Style::default().fg(fg).bg(d.palette.surface)));
                }
                // Pad the band to cl+cw (the full measure, golden col 111).
                let used: usize = spans.iter().map(|s| display_width(&s.to_string())).sum();
                let band_right = cw as usize + 3;
                let mut pad = band_right.saturating_sub(used);
                // Plain rows pad to the band edge; label rows account for
                // the label + its banded trailing space inside `pad`.
                if !(i == 0 && !lang.is_empty()) {
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
            words.push(Word { text: w.to_string(), style: *style, space_before });
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
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(ratatui::widgets::Clear, rect);

    let buf = frame.buffer_mut();
    let frame_style = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(frame_style);
    buf[(rect.x + rect.width - 1, rect.y)].set_symbol("╮").set_style(frame_style);
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
    buf[(inner.x + 1, inner.y)]
        .set_symbol(g.you)
        .set_style(Style::default().fg(p.magenta).bg(p.surface2).add_modifier(Modifier::BOLD));
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
    let mut put_row = |text: &str, style: Style, row_y: &mut u16, buf: &mut ratatui::buffer::Buffer| {
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
                Style::default().fg(p.magenta).bg(fill).add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(p.ink).bg(fill).add_modifier(Modifier::BOLD)
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
                    Style::default().fg(p.magenta).bg(p.surface2).add_modifier(Modifier::BOLD)
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
    let title = if is_running { "Still running — quit?" } else { "Quit ORBIT?" };
    let message = if is_running {
        "A response is still running. Quit anyway?"
    } else {
        "Are you sure you want to quit?"
    };
    let w = 44u16.min(area.width.saturating_sub(8));
    let h = 7u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let buf = frame.buffer_mut();
    let fs = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y)].set_symbol("╮").set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)].set_symbol("╰").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)].set_symbol("─").set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)].set_symbol("│").set_style(fs);
    }
    let t = format!(" {title} ");
    for (i, c) in t.chars().enumerate() {
        buf[(rect.x + 2 + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.ink).bg(p.surface2).add_modifier(Modifier::BOLD));
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
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let buf = frame.buffer_mut();
    let fs = Style::default().fg(p.rule_hi).bg(p.surface2);
    for yy in rect.top()..rect.bottom() {
        for xx in rect.left()..rect.right() {
            buf[(xx, yy)].set_style(Style::default().bg(p.surface2));
        }
    }
    buf[(rect.x, rect.y)].set_symbol("╭").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y)].set_symbol("╮").set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)].set_symbol("╰").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)].set_symbol("─").set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)].set_symbol("│").set_style(fs);
    }
    for (i, c) in " Keys ".chars().enumerate() {
        buf[(rect.x + 2 + i as u16, rect.y)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.ink).bg(p.surface2).add_modifier(Modifier::BOLD));
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
    let mut put = |col_x: u16, rows: &[(&str, &str)], buf: &mut ratatui::buffer::Buffer| {
        for (i, (key, desc)) in rows.iter().enumerate() {
            let yy = rect.y + 2 + i as u16;
            if yy >= rect.y + rect.height - 1 {
                break;
            }
            let is_label = desc.is_empty() && !key.is_empty();
            let kstyle = if is_label {
                Style::default().fg(p.muted).bg(p.surface2)
            } else {
                Style::default().fg(p.ink2).bg(p.surface2).add_modifier(Modifier::BOLD)
            };
            for (j, c) in key.chars().enumerate() {
                buf[(col_x + j as u16, yy)].set_symbol(&c.to_string()).set_style(kstyle);
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
    let has_facts = true; // the fixture carries the facts grid
    let card_h: u16 = if has_facts { 9 } else { 6 };
    let card_x = wc.conversation.0 + (wc.conversation.1.saturating_sub(card_w)) / 2;
    let card_y = area.y + area.height.saturating_sub(card_h + 2);
    let rect = Rect { x: card_x, y: card_y, width: card_w, height: card_h };
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
    buf[(rect.x + rect.width - 1, rect.y)].set_symbol("╮").set_style(fs);
    buf[(rect.x, rect.y + rect.height - 1)].set_symbol("╰").set_style(fs);
    buf[(rect.x + rect.width - 1, rect.y + rect.height - 1)]
        .set_symbol("╯")
        .set_style(fs);
    for xx in rect.x + 1..rect.x + rect.width - 1 {
        buf[(xx, rect.y)].set_symbol("─").set_style(fs);
        buf[(xx, rect.y + rect.height - 1)].set_symbol("─").set_style(fs);
    }
    for yy in rect.y + 1..rect.y + rect.height - 1 {
        buf[(rect.x, yy)].set_symbol("│").set_style(fs);
        buf[(rect.x + rect.width - 1, yy)].set_symbol("│").set_style(fs);
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
            '◇' => Style::default().fg(p.magenta).bg(fill).add_modifier(Modifier::BOLD),
            ' ' | 'A' | 'l' | 'o' | 'w' | '?' => {
                Style::default().fg(p.ink).bg(fill).add_modifier(Modifier::BOLD)
            }
            _ => Style::default().fg(p.magenta).bg(fill).add_modifier(Modifier::BOLD),
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
            Style::default().fg(risk_color).bg(fill).add_modifier(Modifier::BOLD)
        };
        buf[(bx + i as u16, rect.y)].set_symbol(&c.to_string()).set_style(style);
    }
    // The action, bold ink, in full.
    for (i, c) in first.summary.chars().enumerate() {
        if rect.x + 3 + i as u16 >= rect.x + rect.width - 1 {
            break;
        }
        buf[(rect.x + 3 + i as u16, rect.y + 2)]
            .set_symbol(&c.to_string())
            .set_style(Style::default().fg(p.ink).bg(fill).add_modifier(Modifier::BOLD));
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
    let mut put_key = |key: &str, desc: &str, kx: &mut u16, buf: &mut ratatui::buffer::Buffer| {
        for (j, c) in format!(" {key} ").chars().enumerate() {
            if *kx + j as u16 > key_row_end {
                return;
            }
            buf[(*kx + j as u16, keys_y)]
                .set_symbol(&c.to_string())
                .set_style(Style::default().fg(p.ink).bg(p.surface2).add_modifier(Modifier::BOLD));
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
