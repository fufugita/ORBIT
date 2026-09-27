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

/// Interpolate between two colors for the band fade. Returns the nearest
/// step of `steps` colors from a to b (truecolor blends exactly; indexed
/// tiers snap to their own palettes via the token system, so this helper
/// only ever blends truecolor values).
fn blend_color(a: Color, b: Color, t: f32) -> Color {
    match (a, b) {
        (Color::Rgb(ar, ag, ab), Color::Rgb(br, bg_, bb)) => Color::Rgb(
            ar + ((br as f32 - ar as f32) * t).round() as u8,
            ag + ((bg_ as f32 - ag as f32) * t).round() as u8,
            ab + ((bb as f32 - ab as f32) * t).round() as u8,
        ),
        // Non-RGB tiers keep the base color — the fade is a truecolor-only
        // nicety; 256/16/mono get a flat band (still zero glyphs).
        _ => a,
    }
}

/// Draw a header band: a title chip on a background row that fades to the
/// canvas over the last FADE_COLS columns. Pure color — zero line glyphs,
/// so the ASCII tier renders identically (minus color depth) and the
/// ambiguous-width probe can never demote it to `----`.
///
/// Focus is the tmux active-tab convention: the focused pane's title is a
/// FILLED chip (magenta bg, canvas text, bold) and its band rides
/// magenta_dim fading to canvas; unfocused panes get a surface2 band and
/// an ink2 title. Mono falls back to reversed video on the chip only.
const FADE_COLS: u16 = 10;

fn draw_header_band(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
) {
    let p = &d.palette;
    if area.width < 2 {
        return;
    }
    let (band, title_style) = if focused {
        let mut chip = Style::default().fg(p.bg).bg(p.magenta);
        if d.caps.color == crate::tokens::ColorTier::Mono {
            chip = Style::default().fg(p.magenta).add_modifier(Modifier::REVERSED);
        }
        (p.magenta_dim, chip.add_modifier(Modifier::BOLD))
    } else {
        (p.surface2, Style::default().fg(p.ink2).bg(p.surface2))
    };
    // The band: full-row bg fill fading to canvas bg over the tail.
    let fade_start = area.width.saturating_sub(FADE_COLS).max(1);
    for x in 0..area.width {
        let t = if x < fade_start {
            0.0
        } else {
            (x - fade_start) as f32 / (area.width - fade_start) as f32
        };
        let cell_color = blend_color(band, p.bg, t);
        let cell = &mut buf[(area.x + x, area.y)];
        cell.set_symbol(" ").set_style(Style::default().bg(cell_color));
    }
    // The title chip rides the band's left edge.
    let title_text = format!(" {title} ");
    let chars: Vec<char> = title_text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if (i as u16) >= area.width {
            break;
        }
        let cell = &mut buf[(area.x + i as u16, area.y)];
        cell.set_symbol(&c.to_string()).set_style(title_style);
    }
}

/// Render a pane with a banded header (no border, no frame glyphs): one
/// header row of color + a 1-col inset each side for breathing room.
/// Returns the inner content rect.
fn render_pane_frame(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
) -> Rect {
    if area.width >= 2 && area.height >= 2 {
        draw_header_band(frame.buffer_mut(), area, title, focused, d);
    }
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

// ── Keycap chips (§6.15 keycap style, reused in hints) ───────────────────────

/// A keycap chip: surface2 bg, ink2 key. Used in hint rows and approval
/// keys. Mono tier falls back to [key] (brackets survive Reset colors).
fn keycap(key: &str, p: &crate::tokens::ResolvedPalette, mono: bool) -> Span<'static> {
    if mono {
        Span::styled(format!(" [{key}] "), Style::default().fg(p.muted))
    } else {
        Span::styled(format!(" {key} "), Style::default().fg(p.ink2).bg(p.surface2))
    }
}

// ── Main render ──────────────────────────────────────────────────────────────

/// Render the current app state into the frame.
///
/// Layout (§5.3 row priorities): 1 header row | 1 main row | 1 status line.
/// The chrome budget is 3 rows total (the old build spent 11).
pub fn render(frame: &mut ratatui::Frame, app: &App, composer_text: &str, d: &Design) {
    let area = frame.area();
    let g = &Glyphs::for_set(d.caps.glyphs);

    // Vertical: header (1) | main (fill) | status (1).
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    render_header_row(frame, outer[0], app, d, g);

    // Quiet rails (§5, the original spec): the conversation is the hero —
    // no border, full brightness. The rails are dim sidebars behind
    // full-height hairline dividers that double as scroll tracks (§6.14).
    // The herdr pivot boxed all three panes equally, which read as a tmux
    // dashboard; this restores the hierarchy: you sit at the centre with
    // the brightest ink, everything else orbits in progressively dimmer
    // rings. Only zoom mode (Z) retains a frame.
    // Rails collapse responsively (the conversation keeps ≥40 cols):
    // full rails ≥120, right drops 100-119, left drops 80-99, single <80.
    let total = area.width;
    let (left_w, right_w) = if total >= 120 {
        (d.layout_rails.0, d.layout_rails.1)
    } else if total >= 100 {
        (d.layout_rails.0, (total - d.layout_rails.0 - 44).max(0))
    } else if total >= 80 {
        (18, 22)
    } else {
        (0, 0)
    };
    let mut constraints = Vec::new();
    if left_w > 0 {
        constraints.push(Constraint::Length(left_w));
        constraints.push(Constraint::Length(1)); // divider
    }
    constraints.push(Constraint::Min(10)); // conversation
    if right_w > 0 {
        constraints.push(Constraint::Length(1)); // divider
        constraints.push(Constraint::Length(right_w));
    }
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(outer[1]);

    // Pane slots depend on which rails are present.
    // Record the pane rects for the mouse hit-test (interior mutability —
    // the renderer sees &App).
    app.pane_rects.left.set(if left_w > 0 { Some(main[0]) } else { None });
    app.pane_rects.center.set(Some(main[if left_w > 0 { 2 } else { 0 }]));
    app.pane_rects
        .right
        .set(if right_w > 0 { Some(main[main.len() - 1]) } else { None });

    // Zoom: the zoomed pane fills the whole surface, framed (Z is an
    // explicit "give me this pane big" — a frame is honest there).
    if let Some(zoomed) = app.zoomed_pane {
        match zoomed {
            Focus::Left => render_left_pane(frame, outer[1], app, d, g, true),
            Focus::Center => render_center_pane(frame, outer[1], app, composer_text, d, g, true),
            Focus::Right => render_right_pane(frame, outer[1], app, d, g, true),
            _ => {}
        }
        render_status_bar(frame, outer[2], app, d, g);
        return;
    }
    let mut idx = 0;
    let mut left_div: Option<Rect> = None;
    if left_w > 0 {
        render_left_pane(frame, main[idx], app, d, g, false);
        left_div = Some(main[idx + 1]);
        idx += 2; // rail + divider
    }
    render_center_pane(frame, main[idx], app, composer_text, d, g, false);
    let mut right_div: Option<Rect> = None;
    if right_w > 0 {
        right_div = Some(main[idx + 1]);
        render_right_pane(frame, main[idx + 2], app, d, g, false); // divider + rail
    }
    // The dividers: full-height hairlines (§6.14). The right divider is
    // the transcript's scroll track when the transcript overflows.
    if let Some(rect) = left_div.or(right_div) {
        let _ = rect;
    }
    if let Some(rect) = left_div {
        render_divider(frame, rect, d, g);
    }
    if let Some(rect) = right_div {
        render_divider(frame, rect, d, g);
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
        render_palette(frame, outer[1], app, d, g);
    }

    render_status_bar(frame, outer[2], app, d, g);

    // Overlays — the only frames on screen (one at a time, §1).
    if app.quit_confirmation {
        render_quit_modal(frame, area, app, d, g);
    }
    if app.help_open {
        render_help_overlay(frame, area, app, d, g);
    }
    if !app.pending_approvals.is_empty() {
        // Docked inside the pane area (outer[1]) — never collides with the
        // status line.
        render_approval_modal(frame, outer[1], app, d, g);
    }
}

// ── Divider / scrollbar (§6.14) ──────────────────────────────────────────────

/// A full-height hairline divider — the separation between the hero
/// conversation and a dim rail. Doubles as a scroll track (§6.14).
fn render_divider(frame: &mut ratatui::Frame, area: Rect, d: &Design, _g: &Glyphs) {
    // A 1-column color gutter, not a │ glyph — the seam between panes is
    // a surface-tinted column that reads as a soft shadow.
    if area.width < 1 || area.height < 1 {
        return;
    }
    let buf = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        buf[(area.x, y)]
            .set_symbol(" ")
            .set_style(Style::default().bg(d.palette.surface));
    }
}

// ── Left rail (§6.9) ─────────────────────────────────────────────────────────

/// A quiet rail header (§6.1): small-caps title, then a hairline rule
/// filling the rest of the row. The focused rail's title is magenta with a
/// heavier rule; unfocused is ink2. NO box — the rail is a dim sidebar,
/// not a pane.
fn render_rail_header(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    focused: bool,
    d: &Design,
    _g: &Glyphs,
) -> Rect {
    let inner = Rect {
        x: area.x,
        y: area.y + 1,
        width: area.width,
        height: area.height.saturating_sub(1),
    };
    if area.width < 4 || area.height < 2 {
        return inner;
    }
    // The rail rides the same color-band header as the panes — no rule
    // glyphs anywhere. Focused: magenta chip on magenta_dim band;
    // unfocused: ink2 chip on surface2 band.
    draw_header_band(frame.buffer_mut(), area, title, focused, d);
    inner
}

fn render_left_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
    framed: bool,
) {
    let p = &d.palette;
    let title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Activity",
    };
    let body = if framed {
        render_pane_frame(frame, area, title, app.focus == Focus::Left, d)
    } else {
        render_rail_header(frame, area, title, app.focus == Focus::Left, d, g)
    };

    // One blank row of breathing room below the header (matches the
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
    // The label rides a short color tail instead of a ─ glyph: a surface
    // band under the two cells after the word. Zero glyphs, fluid.
    Line::from(vec![
        Span::styled(text.to_string(), Style::default().fg(p.faint)),
        Span::styled("  ".to_string(), Style::default().bg(p.surface)),
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
    framed: bool,
) {
    let p = &d.palette;

    // Quiet rails (§5): the conversation is the hero — NO border, NO
    // title. Its brightness and the hairline dividers set it apart from
    // the dim rails. Zoom mode (Z) frames it: "give me this pane big"
    // is an explicit ask, and a frame is honest there.
    let area = if framed {
        let title = "Conversation".to_string();
        render_pane_frame(frame, area, &title, app.focus == Focus::Center, d)
    } else {
        area
    };
    // The transcript's text width — tool-card meta right-aligns to it.
    let body_w = area.width.saturating_sub(4) as usize;

    // Split: transcript (fill) | queue | composer box | hint row.
    //
    // The composer is a rounded box (the Claude Code / Codex convention):
    // magenta border when the center pane is focused ("you" — one of the
    // six magenta things), cyan while a turn is live, rule otherwise.
    // The hint row beneath carries the context keys; the §6.12 toast
    // rides its right end.
    //
    // Composer auto-height (§5.5): the box grows one row per line of
    // content, capped at half the pane so the transcript always keeps ≥3
    // rows. Lines beyond the cap show the last ones (the newest line
    // stays visible).
    let queue_h = app.queued.len() as u16;
    let text_lines = composer_text.lines().count().max(1) as u16;
    let composer_cap = (area.height / 2).max(1);
    let composer_h = text_lines.min(composer_cap);
    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(queue_h),
            Constraint::Length(composer_h + 2), // box: border + content + border
            Constraint::Length(1),              // hint row
        ])
        .split(area);

    // ── Transcript ─────────────────────────────────────────────────────────
    // The welcome screen (§8.1): an empty session shows the expanded mark,
    // centered in the conversation. The first turn replaces it.
    // One blank row of breathing room below the top border.
    let mut lines: Vec<Line> = vec![Line::from("")];
    if app.transcript.is_empty() && app.in_flight.is_empty() {
        let mut mark = welcome_mark_frame(d, app.startup_frame);
        let mark_w = 36u16; // widest mark row
        let mark_h = mark.len() as u16;
        if center[0].width > mark_w + 4 && center[0].height > mark_h + 4 {
            // Splash orbit: once the reveal settles, a dim satellite dot
            // circles the ring's four corner positions — the mark itself
            // breathes while it waits for the first prompt. Reduced motion
            // keeps the static mark.
            if app.startup_frame >= 5 && !d.caps.reduced_motion {
                let phase = (app.tick_count / 15) % 4;
                // Corner cells around the 3-row mark, hand-placed to trace
                // the ring's arc (row, col) — dim magenta ·
                let spots: [(usize, usize); 4] = [
                    (0, 19), // upper right, beside the star
                    (1, 35), // right
                    (2, 19), // lower right
                    (1, 1),  // left
                ];
                let (r, c) = spots[phase as usize];
                if r < mark.len() {
                    let line = &mut mark[r];
                    if let Some(spot_span) = line.spans.get_mut(c) {
                        let styled = Span::styled(
                            "·".to_string(),
                            Style::default().fg(p.magenta_dim),
                        );
                        *spot_span = styled;
                    }
                }
            }
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
    // The LIVE gutter: the braille busy spinner rides the streaming line
    // so the motion sits where the operator is reading (Cline-style).
    let busy_gutter = || {
        // Reduced motion: the still star, not a spinner frame.
        let glyph = if app.reduced_motion {
            g.orbit
        } else {
            g.busy_frames()[app.spinner_frame as usize % g.busy_frames().len()]
        };
        Span::styled(format!("{glyph}  "), Style::default().fg(p.cyan))
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
            TranscriptLine::Stripped {
                tool_name,
                summary,
                outcome,
                started_at,
            } => {
                // The tool card (§6.5): state glyph, name, argument, meta —
                // one row that reads like a Claude Code tool-call line.
                // Stripping stays silent (§12).
                //   ◉ calculator  expression="2*(3+4)"        running
                //   ✓ calculator  expression="2*(3+4)"
                //   ✕ shell  cargo test                      failed
                // The card is running only while it is the LAST entry of
                // this name AND still unsettled — an earlier same-name card
                // that already settled keeps its outcome even while a later
                // call of the same tool runs.
                let is_running = outcome.is_none()
                    && matches!(&app.tool_state, ToolState::Running(n) if n == tool_name)
                    && app.turn_in_flight;
                // The running card's meta is a LIVE duration (1.4s →
                // 1.6s…), ticking while the call runs — the card itself
                // carries the progress feel.
                let running_meta = match started_at {
                    Some(t) => {
                        let secs = t.elapsed().as_millis() as f64 / 1000.0;
                        format!("{secs:.1}s")
                    }
                    None => "running".to_string(),
                };
                let (glyph, glyph_color, name_color, meta) = match (is_running, outcome) {
                    (true, _) => (g.running, p.cyan, p.ink, running_meta),
                    (false, Some(true)) => (g.done, p.muted, p.ink2, String::new()),
                    (false, Some(false)) => (g.failed, p.red, p.ink2, "failed".to_string()),
                    // Unsettled but not running (e.g. the turn was cancelled
                    // mid-call): the honest neutral state.
                    (false, None) => (g.pending, p.faint, p.ink2, String::new()),
                };
                let mut spans = vec![
                    Span::raw("   "),
                    Span::styled(glyph, Style::default().fg(glyph_color)),
                    Span::raw(" "),
                    Span::styled(
                        tool_name.clone(),
                        Style::default().fg(name_color).add_modifier(if is_running {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                    ),
                ];
                // The argument column: the display-safe summary, muted,
                // truncated head-first (the END of a path/command is its
                // most specific part, §6.5: crates/…/restore.rs).
                if !summary.is_empty() {
                    let budget = body_w.saturating_sub(tool_name.chars().count() + 8);
                    let arg = crate::unicode::truncate_graphemes_tail(summary, budget.max(8));
                    spans.push(Span::styled(
                        format!("  {arg}"),
                        Style::default().fg(p.muted),
                    ));
                }
                if !meta.is_empty() {
                    let meta_w = crate::unicode::display_width(&meta);
                    let used: usize = spans
                        .iter()
                        .map(|sp| crate::unicode::display_width(&sp.to_string()))
                        .sum();
                    // Align to the pane's inner right edge, like the queue toast.
                    let pad = (center[0].width as usize).saturating_sub(used + meta_w);
                    spans.push(Span::raw(" ".repeat(pad)));
                    spans.push(Span::styled(
                        meta,
                        Style::default().fg(if is_running { p.cyan } else { p.red }),
                    ));
                }
                lines.push(Line::from(spans));
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

    // In-flight stream — the busy spinner in the gutter, cyan while
    // working. Motion lives where the eyes are.
    let streaming = !app.in_flight.is_empty();
    if streaming {
        // The gutter rides the first line (no orphan glyph row).
        let mut first = true;
        for rich_line in render_message(&app.in_flight, d) {
            let mut spans = Vec::new();
            if first {
                spans.push(busy_gutter());
                first = false;
            } else {
                spans.push(Span::raw("   "));
            }
            spans.extend(rich_line.spans);
            lines.push(Line::from(spans));
        }
        if first {
            lines.push(Line::from(busy_gutter()));
        }
    }
    // Waiting for the first token: the spinner rides a lone gutter row so
    // dead air still shows life (the old design showed nothing here).
    if app.turn_in_flight && !streaming && app.tool_state == ToolState::Streaming {
        lines.push(Line::from(busy_gutter()));
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

    // ── Queue: pending prompts (the §6.12 toast rides the hint row) ───────
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

    // ── Composer: a rounded box (the Claude Code / Codex convention) ──────
    // The › prompt in magenta (your input is one of the six magenta things),
    // text in ink, inside a rounded box. The border is magenta when the
    // composer is focused, cyan while a turn is live, rule otherwise.
    let composer_focused = app.focus == Focus::Center;
    let turn_live = app.turn_in_flight
        || app.tool_state == ToolState::Streaming
        || matches!(app.tool_state, ToolState::Running(_));

    let prompt_color = if composer_focused { p.magenta } else { p.faint };
    // Standard terminal blink cadence (~530 ms on, ~530 ms off).
    let cursor_on = !turn_live && (app.tick_count / 33).is_multiple_of(2);
    let cursor = if cursor_on { "▍" } else { " " };
    let first_text_line = composer_text.lines().next().unwrap_or("");
    let placeholder = if turn_live {
        "Add to the queue, or wait for ORBIT"
    } else {
        "Ask ORBIT, or / for commands"
    };
    let prompt_line = if composer_text.is_empty() {
        Line::from(vec![
            Span::styled(format!("{} ", g.you), Style::default().fg(prompt_color)),
            Span::styled(placeholder, Style::default().fg(p.faint)),
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
    // The composer is a color-filled surface, not a box: state-colored
    // wash (cyan while a turn is live, magenta when focused, surface
    // idle) with the text inset by one column. No frame glyphs in any
    // tier — the fill IS the affordance.
    let wash = if turn_live {
        blend_color(p.cyan, p.bg, 0.86)
    } else if composer_focused {
        blend_color(p.magenta, p.bg, 0.88)
    } else {
        p.surface
    };
    let inner = Rect {
        x: center[2].x + 1,
        y: center[2].y,
        width: center[2].width.saturating_sub(2),
        height: center[2].height,
    };
    for y in center[2].top()..center[2].bottom() {
        for x in center[2].left()..center[2].right() {
            if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                cell.set_style(Style::default().bg(wash));
            }
        }
    }
    frame.render_widget(Paragraph::new(visible), inner);

    // ── Hint row: keycap chips left, toast right (§5.5, §6.12) ────────────
    let mono = d.caps.color == crate::tokens::ColorTier::Mono;
    let mut hint_spans: Vec<Span> = Vec::new();
    if turn_live {
        hint_spans.push(keycap("ctrl+c", p, mono));
        hint_spans.push(Span::styled(" stop · ", Style::default().fg(p.faint)));
        hint_spans.push(keycap("⏎", p, mono));
        hint_spans.push(Span::styled(" queue", Style::default().fg(p.faint)));
    } else {
        hint_spans.push(keycap("⏎", p, mono));
        hint_spans.push(Span::styled(" send · ", Style::default().fg(p.faint)));
        hint_spans.push(keycap("⇧⏎", p, mono));
        hint_spans.push(Span::styled(" newline · ", Style::default().fg(p.faint)));
        hint_spans.push(keycap("/", p, mono));
        hint_spans.push(Span::styled(" commands · ", Style::default().fg(p.faint)));
        hint_spans.push(keycap("?", p, mono));
        hint_spans.push(Span::styled(" keys", Style::default().fg(p.faint)));
    }
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
        let text_w = crate::unicode::display_width(&text);
        let row = center[3].width as usize;
        let used: usize = hint_spans
            .iter()
            .map(|sp| crate::unicode::display_width(&sp.to_string()))
            .sum();
        // The toast right-aligns within the space LEFT after the hints —
        // never past the row edge (clipped text is invisible text).
        let pad = row.saturating_sub(used + text_w + 2);
        hint_spans.push(Span::raw(" ".repeat(pad)));
        hint_spans.push(Span::styled(text, Style::default().fg(color)));
    }
    frame.render_widget(Paragraph::new(Line::from(hint_spans)), center[3]);
}

// ── Right rail (§6.10) ───────────────────────────────────────────────────────

/// A workspace section label: muted label + faint count (§6.10).
fn section_line(label: &str, count: usize, p: &crate::tokens::ResolvedPalette) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_string(), Style::default().fg(p.muted)),
        Span::styled(format!("  {count}"), Style::default().fg(p.faint)),
    ])
}

fn render_right_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    d: &Design,
    g: &Glyphs,
    framed: bool,
) {
    let p = &d.palette;
    let body = if framed {
        render_pane_frame(frame, area, "Workspace", app.focus == Focus::Right, d)
    } else {
        render_rail_header(frame, area, "Workspace", app.focus == Focus::Right, d, g)
    };
    // One blank row of breathing room below the header.
    let mut lines: Vec<Line> = vec![Line::from("")];

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

/// Product header: compact ORBIT mark, model/session context, and help key.
/// This is the stable identity row; the status bar below remains live activity.
fn render_header_row(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    let conn = match app.connection {
        ConnectionState::Online => (g.conn_online, p.green),
        ConnectionState::Reconnecting => (g.conn_retrying, p.amber),
        ConnectionState::Offline => (g.conn_offline, p.red),
    };
    let sep = Span::styled(
        format!("  {}  ", g.sep),
        Style::default().fg(p.faint),
    );
    let left = vec![
        Span::styled(g.orbit, Style::default().fg(p.magenta).add_modifier(Modifier::BOLD)),
        Span::styled(" ORBIT", Style::default().fg(p.ink2).add_modifier(Modifier::BOLD)),
        sep.clone(),
        Span::styled(&app.model, Style::default().fg(p.ink)),
        sep.clone(),
        Span::styled(&app.session_id_prefix, Style::default().fg(p.muted)),
    ];
    let right = vec![
        Span::styled(conn.0, Style::default().fg(conn.1)),
        Span::styled("  ? keys", Style::default().fg(p.faint)),
    ];
    let left_w: usize = left.iter().map(|s| crate::unicode::display_width(&s.to_string())).sum();
    let right_w: usize = right.iter().map(|s| crate::unicode::display_width(&s.to_string())).sum();
    let gap = (area.width as usize).saturating_sub(left_w + right_w);
    let mut spans = left;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App, d: &Design, g: &Glyphs) {
    let p = &d.palette;
    // The status line rides a surface2 bar — the bottom zone anchor.
    frame.render_widget(
        ratatui::widgets::Block::default().style(Style::default().bg(p.surface2)),
        area,
    );
    // Left side: the compact mark — the braille busy spinner while ORBIT
    // works (waiting, streaming, running tools), the star when idle.
    let mark =
        if matches!(app.logo_phase, LogoPhase::Working) || app.tool_state == ToolState::Streaming {
            if app.reduced_motion {
                g.orbit
            } else {
                g.busy_frames()[app.spinner_frame as usize % g.busy_frames().len()]
            }
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
    // Model + session moved to the header row; the status line's left side
    // is now purely live activity (§6.11's original intent).
    let mut left_spans = vec![
        Span::styled(mark, Style::default().fg(p.magenta)),
        Span::raw(" "),
        mode_chip,
        zoom_chip,
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

/// A filled overlay card (§4.2 evolved): solid surface2 fill, one header
/// row carrying the title in the overlay color, and a 1-col inset. No
/// frame glyphs — the fill + elevation (Clear underneath) IS the frame.
/// Magenta fill tone for approvals (ORBIT asking for your authority),
/// rule tone for confirmations.
fn overlay_block(title: &str, fill: Color, p: &crate::tokens::ResolvedPalette) -> Block<'static> {
    // Solid fill card (the fill is pre-blended toward canvas so text stays
    // readable), title chip in the overlay's accent with canvas text.
    // `fill` carries the authority tone: magenta-tinged for approvals,
    // rule-toned for confirmations.
    Block::default()
        .borders(ratatui::widgets::Borders::NONE)
        .style(Style::default().bg(fill))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(p.bg).bg(p.magenta).add_modifier(Modifier::BOLD),
        ))
        .padding(ratatui::widgets::Padding::horizontal(1))
}

/// Quit confirmation — a small solid card, NO backdrop dimming (§12).
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
    .block(overlay_block(title, blend_color(d.palette.rule_hi, d.palette.bg, 0.92), &d.palette));
    frame.render_widget(ratatui::widgets::Clear, modal_h[1]);
    frame.render_widget(content, modal_h[1]);
}

/// §6.16 help overlay: the same frame as quit, two columns of keys
/// grouped by pane. Any key closes it.
fn render_help_overlay(frame: &mut ratatui::Frame, area: Rect, _app: &App, d: &Design, _g: &Glyphs) {
    let p = &d.palette;
    let w = 64u16.min(area.width.saturating_sub(8));
    let h = 20u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };
    frame.render_widget(ratatui::widgets::Clear, rect);
    let block = overlay_block("Keys", blend_color(p.rule_hi, p.bg, 0.92), p);
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
    .block(overlay_block(&title, blend_color(p.magenta, p.bg, 0.9), p));
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
