//! Ratatui rendering — Bubble Tea visual language ported to ratatui.
//!
//! The whole TUI is styled like a Charm app: Lip Gloss-style rounded blocks
//! everywhere, Bubbles braille spinner, bubble list items, rounded composer
//! with a blinking cursor, scrollable transcript viewport, animated orbital
//! logo, Huh-style modal, and smooth focus transitions. Every color reads
//! from `ResolvedTheme` — no hardcoded colors.

use crate::rich::render_message;
use crate::state::{
    App, ComposerState, ConnectionState, Focus, LeftTab, LogoPhase, ToolState, TranscriptLine,
};
use crate::theme::{ResolvedTheme, BRAILLE_SPINNER, DIVIDER_RAMP, ORBIT_RING, PANE_DIM, ROUNDED};
use crate::unicode::truncate_graphemes;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

/// A Lip Gloss-style rounded block for a pane. Focused = accent color with
/// a bold title + `▶` gutter; unfocused = PANE_DIM. A smooth focus
/// transition blends the border color over 3 frames when focus changes.
fn pane_block<'a>(title: &'a str, focused: bool, app: &App, theme: &ResolvedTheme) -> Block<'a> {
    let accent = if app.shimmer_phase.is_multiple_of(2) {
        theme.colors.accent
    } else {
        theme.colors.accent_bright
    };
    let base = if focused { accent } else { PANE_DIM };
    // Smooth focus blend: interpolate PANE_DIM → accent over the transition.
    let color = match app.focus_transition {
        Some(phase) if focused => blend_color(PANE_DIM, accent, phase as f32 / 3.0),
        Some(phase) if !focused => blend_color(accent, PANE_DIM, phase as f32 / 3.0),
        _ => base,
    };
    let title_text = if focused {
        format!("▶ {title} ")
    } else {
        format!(" {title} ")
    };
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_set(ROUNDED)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            title_text,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    // Focus shimmer divider under the title (4-frame gradient).
    if focused {
        let ramp = DIVIDER_RAMP[app.shimmer_phase as usize % DIVIDER_RAMP.len()];
        block = block.title_bottom(Line::from(vec![Span::styled(
            ramp,
            Style::default().fg(color),
        )]));
    }
    block
}

/// Blend two RGB colors by `t` (0.0 = from, 1.0 = to).
fn blend_color(from: Color, to: Color, t: f32) -> Color {
    let rgb = |c: Color| match c {
        Color::Rgb(r, g, b) => (r as f32, g as f32, b as f32),
        _ => (0.0, 0.0, 0.0),
    };
    let (fr, fg, fb) = rgb(from);
    let (tr, tg, tb) = rgb(to);
    Color::Rgb(
        (fr + (tr - fr) * t) as u8,
        (fg + (tg - fg) * t) as u8,
        (fb + (tb - fb) * t) as u8,
    )
}

/// Render the current app state into the frame.
pub fn render(frame: &mut ratatui::Frame, app: &App, composer_text: &str, theme: &ResolvedTheme) {
    let area = frame.area();

    // Vertical: header | main (fill) | status | help
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(theme.layout.header_lines),
            Constraint::Min(5),
            Constraint::Length(theme.layout.status_lines),
            Constraint::Length(theme.layout.help_lines),
        ])
        .split(area);

    render_header(frame, outer[0], app, theme);

    // Three columns with 1-cell whitespace gutters (no full-height borders
    // between them — the chat breathes; the side panes are styled boxes).
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(theme.layout.left_pct),
            Constraint::Length(1), // gutter
            Constraint::Min(10),   // conversation (fills the rest)
            Constraint::Length(1), // gutter
            Constraint::Percentage(theme.layout.right_pct),
        ])
        .split(outer[1]);

    render_left_pane(frame, main[0], app, theme);
    render_center_pane(frame, main[2], app, composer_text, theme);
    render_right_pane(frame, main[4], app, theme);
    render_status_bar(frame, outer[2], app, theme);
    if theme.tabs.show_help_bar {
        render_help(frame, outer[3], app, theme);
    }

    // Quit confirmation modal — rendered on top of everything.
    if app.quit_confirmation {
        render_quit_modal(frame, area, app, theme);
    }
    // Glass-modal approval sheet (Huh-style) — dim overlay + centered modal.
    if !app.pending_approvals.is_empty() {
        render_approval_modal(frame, area, app, theme);
    }
}

/// Render a centered quit confirmation modal with dim overlay.
fn render_quit_modal(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;

    // Dim overlay.
    let dim_overlay =
        Block::default().style(Style::default().fg(c.dim).add_modifier(Modifier::DIM));
    frame.render_widget(dim_overlay, area);

    let is_running =
        app.tool_state == ToolState::Streaming || matches!(app.tool_state, ToolState::Running(_));
    let title = if is_running {
        " Still running — quit? "
    } else {
        " Quit ORBIT? "
    };
    let message = if is_running {
        "  A response is still running. Quit anyway?"
    } else {
        "  Are you sure you want to quit?"
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

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .border_set(ROUNDED)
        .border_style(Style::default().fg(c.warning))
        .title(Span::styled(
            title,
            Style::default().fg(c.warning).add_modifier(Modifier::BOLD),
        ));

    let modal_content = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![Span::styled(message, Style::default().fg(c.text))]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [y]", Style::default().fg(c.warning)),
            Span::styled(" quit   ", Style::default().fg(c.dim)),
            Span::styled("[n/Esc]", Style::default().fg(c.warning)),
            Span::styled(" cancel", Style::default().fg(c.dim)),
        ]),
    ])
    .block(modal_block);
    frame.render_widget(modal_content, modal_h[1]);
}

/// The animated orbital logo — centered ORBIT in block letters, a ring of
/// `◦` glyphs circling it, and a `✹` star riding the ring. The star advances
/// one ring position per animation tick (8fps while working).
///
/// Phases (DR-21 L19): Splash (star pulses) → Steady (slow orbit) →
/// Working (fast orbit while streaming) → Shutdown (star fades).
pub fn logo_frame(app: &App, theme: &ResolvedTheme) -> Vec<Line<'static>> {
    let c = &theme.colors;
    let accent = if app.shimmer_phase.is_multiple_of(2) {
        c.accent
    } else {
        c.accent_bright
    };

    // Ring position: the star index advances with logo_phase_frames.
    // Steady: 1 position per 8 frames (2fps). Working: 1 per frame (8fps).
    let advance = match app.logo_phase {
        LogoPhase::Working => app.logo_phase_frames as usize,
        LogoPhase::Steady | LogoPhase::Splash => (app.logo_phase_frames / 4) as usize,
        LogoPhase::Shutdown => 0,
    };
    let star_idx = advance % ORBIT_RING.len();
    let star_pos = ORBIT_RING[star_idx];

    // Star glyph by phase.
    let star = match app.logo_phase {
        LogoPhase::Splash => crate::theme::STAR_RAMP[app.logo_phase_frames as usize % 4],
        LogoPhase::Shutdown if app.logo_phase_frames >= 6 => "·",
        LogoPhase::Shutdown if app.logo_phase_frames >= 3 => "◦",
        _ => "✹",
    };

    // Logo block art (7 rows × 21 cols), then overlay the ring + star.
    // ORBIT in the original 2-row ASCII Shadow wordmark (the one that reads
    // clearly), centered vertically.
    let mut rows = vec![vec![' '; 21]; 7];
    let block = ["█▀█ █▀█ █▄▄ █ ▀█▀", "█▄█ █▀▄ █▄█ █  █ "];
    for (r, row) in block.iter().enumerate() {
        for (col, ch) in row.chars().enumerate() {
            // Wordmark occupies cols 2..18 (17 wide), leaving col 0/1 and
            // col 19/20 for the ring's left/right positions.
            if col < 17 {
                rows[r + 2][col + 2] = ch;
            }
        }
    }
    // Ring positions (row, col) — draw `◦` everywhere except the star spot.
    for (r, col) in ORBIT_RING {
        let (r, col) = (*r as usize, *col as usize);
        if r < rows.len()
            && col < rows[0].len()
            && (r, col) != (star_pos.0 as usize, star_pos.1 as usize)
        {
            rows[r][col] = '◦';
        }
    }
    // Star at its position.
    let (sr, sc) = (star_pos.0 as usize, star_pos.1 as usize);
    if sr < rows.len() && sc < rows[0].len() {
        rows[sr][sc] = star.chars().next().unwrap_or('✹');
    }

    // Render rows with the accent color for the ring + star, block letters
    // in composer color. Positions are computed from (row, col) directly.
    let (sr, sc) = (star_pos.0 as usize, star_pos.1 as usize);
    let star_ch = star.chars().next().unwrap_or('✹');
    let mut out = Vec::new();
    for (r, row) in rows.iter().enumerate() {
        let mut spans = Vec::new();
        for (col, ch) in row.iter().enumerate() {
            if *ch == ' ' {
                spans.push(Span::styled(" ", Style::default()));
            } else if (r, col) == (sr, sc) {
                // The star — always accent (even during Shutdown fade).
                spans.push(Span::styled(
                    star_ch.to_string(),
                    Style::default().fg(accent),
                ));
            } else {
                let color = match ch {
                    '◦' => accent,
                    '█' | '▀' | '▄' => c.composer,
                    _ => accent,
                };
                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }
        }
        out.push(Line::from(spans));
    }
    out
}

fn render_header(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    // The header is JUST the orbital logo — clean, no metadata, no rule.
    // Model/provider/session live in the status bar already.
    let logo = logo_frame(app, theme);
    frame.render_widget(Paragraph::new(logo).alignment(Alignment::Center), area);
}

fn render_left_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Verbose",
    };
    let block = pane_block(title, app.focus == Focus::Left, app, theme);

    // Bubble-style list items: rounded mini-cards with a colored left border.
    let items: Vec<ListItem> = match app.left_tab {
        LeftTab::Sessions => vec![ListItem::new(vec![
            Line::from(vec![
                Span::styled("● ", Style::default().fg(c.success)),
                Span::styled(&app.session_id_prefix, Style::default().fg(c.text)),
            ]),
            Line::from(vec![
                Span::styled("  model: ", Style::default().fg(c.dim)),
                Span::styled(&app.model, Style::default().fg(c.text)),
            ]),
        ])],
        LeftTab::Verbose => {
            if app.in_flight.is_empty() {
                vec![ListItem::new(Line::from(vec![Span::styled(
                    "(no active stream)",
                    Style::default().fg(c.dim),
                )]))]
            } else {
                vec![ListItem::new(vec![
                    Line::from(vec![Span::styled(
                        "streaming:",
                        Style::default().fg(c.composer),
                    )]),
                    Line::from(vec![Span::styled(
                        &app.in_flight,
                        Style::default().fg(c.dim),
                    )]),
                ])]
            }
        }
    };
    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

fn render_center_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    composer_text: &str,
    theme: &ResolvedTheme,
) {
    let c = &theme.colors;

    // Split center into: transcript (fill) | queue | composer.
    // The composer is 3 rows: 1 top border + 1 text + 1 bottom border.
    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(app.queued.len() as u16),
            Constraint::Length(3),
        ])
        .split(area);

    // ── Transcript (viewport with scrollbar) ──────────────────────────────
    let mut lines: Vec<Line> = Vec::new();
    let gutter = |color: Color| Span::styled("▌", Style::default().fg(color));
    let orbit_color = c.accent;

    for entry in &app.transcript {
        match entry {
            TranscriptLine::User(text) => {
                lines.push(Line::from(vec![gutter(c.composer)]));
                lines.push(Line::from(vec![Span::styled(
                    "  you",
                    Style::default().fg(c.composer).add_modifier(Modifier::BOLD),
                )]));
                for line in text.lines() {
                    lines.push(Line::from(vec![
                        gutter(c.composer),
                        Span::styled(format!("  {line}"), Style::default().fg(c.text)),
                    ]));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Assistant(text) => {
                lines.push(Line::from(vec![gutter(orbit_color)]));
                lines.push(Line::from(vec![Span::styled(
                    "  orbit",
                    Style::default()
                        .fg(orbit_color)
                        .add_modifier(Modifier::BOLD),
                )]));
                for rich_line in render_message(text, theme) {
                    let mut spans = vec![gutter(orbit_color)];
                    spans.extend(rich_line.spans);
                    lines.push(Line::from(spans));
                }
                lines.push(Line::from(""));
            }
            TranscriptLine::Stripped { tool_name } => {
                lines.push(Line::from(vec![Span::styled(
                    format!("  ⚡ {tool_name} (reasoning stripped)"),
                    Style::default().fg(c.dim),
                )]));
                lines.push(Line::from(""));
            }
            TranscriptLine::System(text) => {
                lines.push(Line::from(vec![Span::styled(
                    text,
                    Style::default().fg(c.dim),
                )]));
                lines.push(Line::from(""));
            }
        }
    }

    // In-flight text with the braille spinner when streaming.
    if !app.in_flight.is_empty() {
        for rich_line in render_message(&app.in_flight, theme) {
            let mut spans = vec![gutter(orbit_color)];
            spans.extend(rich_line.spans);
            lines.push(Line::from(spans));
        }
        lines.push(Line::from(vec![Span::styled(
            "█",
            Style::default().fg(c.composer),
        )]));
    } else if app.tool_state == ToolState::Streaming {
        let spinner = BRAILLE_SPINNER[app.spinner_frame as usize % BRAILLE_SPINNER.len()];
        let phrase = &theme.spinner.phrases[app.thinking_phrase % theme.spinner.phrases.len()];
        lines.push(Line::from(vec![
            Span::styled(spinner, Style::default().fg(c.composer)),
            Span::raw(" "),
            Span::styled(phrase, Style::default().fg(c.dim)),
        ]));
    }

    // Errors
    if let Some(err) = &app.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("error: ", Style::default().fg(c.error)),
            Span::styled(err, Style::default().fg(c.error)),
        ]));
    }

    // Viewport: auto-scroll to bottom unless the operator scrolled up.
    let visible_height = center[0].height.saturating_sub(2) as usize;
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

    // Scrollbar on the right edge of the transcript.
    if total_lines > visible_height && visible_height > 0 {
        let vh = visible_height as u64;
        let total = total_lines as u64;
        let sc = scroll as u64;
        let thumb_h = (vh * vh / total).max(1);
        let range = (vh - thumb_h).max(1);
        let thumb_off = (sc * range / (total - vh).max(1)).min(range);
        for i in 0..visible_height {
            let iu = i as u64;
            if iu >= thumb_off && iu < thumb_off + thumb_h {
                frame.render_widget(
                    Paragraph::new("▏").style(Style::default().fg(c.accent)),
                    Rect::new(
                        center[0].x + center[0].width - 1,
                        center[0].y + i as u16,
                        1,
                        1,
                    ),
                );
            }
        }
    }

    // ── Queue: pending prompts (dimmed) above the composer ────────────────
    let mut queue_rows = Vec::new();
    for q in &app.queued {
        queue_rows.push(Line::from(vec![
            Span::styled("⏳ ", Style::default().fg(c.warning)),
            Span::styled(truncate_graphemes(q, 40), Style::default().fg(c.dim)),
        ]));
    }
    if !queue_rows.is_empty() {
        frame.render_widget(Paragraph::new(queue_rows), center[1]);
    }

    // ── Composer — rounded box with a blinking cursor ─────────────────────
    let composer_focused = app.focus == Focus::Center;
    let glyph = match &app.composer_state {
        ComposerState::Idle => "▸",
        ComposerState::Typing => "▸",
        ComposerState::Sending => {
            const SEND_FRAMES: [&str; 3] = ["↗", "↘", "↗"];
            SEND_FRAMES[app.composer_send_phase as usize % 3]
        }
        ComposerState::Blocked(_) => "⏸",
    };
    let (composer_color, glyph_color) = if composer_focused {
        match &app.composer_state {
            ComposerState::Blocked(_) => (c.warning, c.warning),
            _ => (c.composer, c.composer),
        }
    } else {
        (c.composer_dim, c.composer_dim)
    };
    // Blinking cursor: toggles every 16 ticks (~500ms) — Bubble Tea's
    // default blink rate (~2Hz), not a rapid strobe.
    let cursor_on = (app.tick_count / 16).is_multiple_of(2);
    let cursor = if cursor_on { "█" } else { " " };
    let prompt = if composer_text.is_empty() {
        Line::from(vec![
            Span::styled(format!("{glyph} "), Style::default().fg(glyph_color)),
            Span::styled("ask orbit…", Style::default().fg(c.dim)),
            Span::styled(cursor, Style::default().fg(composer_color)),
        ])
    } else {
        Line::from(vec![
            Span::styled(format!("{glyph} "), Style::default().fg(glyph_color)),
            Span::styled(composer_text, Style::default().fg(c.text)),
            Span::styled(cursor, Style::default().fg(composer_color)),
        ])
    };
    let composer = Paragraph::new(vec![prompt]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(ROUNDED)
            .border_style(Style::default().fg(composer_color))
            .title(Span::styled(
                format!(" {glyph} "),
                Style::default().fg(glyph_color),
            )),
    );
    frame.render_widget(composer, center[2]);
}

fn render_right_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let block = pane_block("Tasks", app.focus == Focus::Right, app, theme);
    let placeholder = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "(workspace file — PR-F)",
            Style::default().fg(c.dim),
        )]),
    ])
    .block(block);
    frame.render_widget(placeholder, area);
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let tool_glyph = match &app.tool_state {
        ToolState::Idle => Span::styled("◯ idle", Style::default().fg(c.dim)),
        ToolState::Streaming => {
            let spinner = BRAILLE_SPINNER[app.spinner_frame as usize % BRAILLE_SPINNER.len()];
            Span::styled(format!("{spinner} stream"), Style::default().fg(c.composer))
        }
        ToolState::AwaitingApproval => Span::styled("? approval", Style::default().fg(c.warning)),
        ToolState::Running(name) => {
            let spinner = BRAILLE_SPINNER[app.spinner_frame as usize % BRAILLE_SPINNER.len()];
            Span::styled(format!("{spinner} {name}"), Style::default().fg(c.success))
        }
        ToolState::AutoGranted(name) => {
            Span::styled(format!("◑ auto({name})"), Style::default().fg(c.accent))
        }
    };
    let conn_glyph = match app.connection {
        ConnectionState::Online => Span::styled("● online", Style::default().fg(c.success)),
        ConnectionState::Reconnecting => {
            let spinner = BRAILLE_SPINNER[app.spinner_frame as usize % BRAILLE_SPINNER.len()];
            Span::styled(
                format!("{spinner} reconnect"),
                Style::default().fg(c.warning),
            )
        }
        ConnectionState::Offline => Span::styled("✕ offline", Style::default().fg(c.error)),
    };

    let tokens = format!(
        "↓{} ↑{}",
        format_count(app.total_input_tokens),
        format_count(app.total_output_tokens)
    );

    let cost = app.total_cost_microcents;
    let cost_str = format!("${}.{:06}", cost / 1_000_000, cost % 1_000_000);
    let cost_flash = if app.cost_flash_frames > 0 {
        " ↗"
    } else {
        ""
    };

    let sep = Span::styled(" │ ", Style::default().fg(c.dim));
    let line = Line::from(vec![
        Span::styled(&app.model, Style::default().fg(c.accent)),
        sep.clone(),
        Span::styled(&app.provider, Style::default().fg(c.text)),
        sep.clone(),
        Span::styled(&app.session_id_prefix, Style::default().fg(c.dim)),
        sep.clone(),
        tool_glyph,
        sep.clone(),
        conn_glyph,
        sep.clone(),
        Span::styled(tokens, Style::default().fg(c.dim)),
        sep,
        Span::styled(
            format!("{cost_str}{cost_flash}"),
            Style::default().fg(c.text),
        ),
    ]);
    frame.render_widget(line, area);
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

fn render_help(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let mut spans = vec![
        Span::raw("  "),
        Span::styled("q", Style::default().fg(c.warning)),
        Span::raw(" quit  "),
        Span::styled("Tab", Style::default().fg(c.warning)),
        Span::raw(" focus  "),
        Span::styled("1/2/3", Style::default().fg(c.warning)),
        Span::raw(" panes  "),
        Span::styled("z+y", Style::default().fg(c.warning)),
        Span::raw(" copy  "),
        Span::styled("g+s/g+v", Style::default().fg(c.warning)),
        Span::raw(" left tab  "),
        Span::styled("Ctrl+C", Style::default().fg(c.warning)),
        Span::raw(" cancel/quit"),
    ];
    if theme.tabs.show_tick_count {
        spans.push(Span::styled("  tick:", Style::default().fg(c.dim)));
        spans.push(Span::styled(
            app.tick_count.to_string(),
            Style::default().fg(c.dim),
        ));
    }
    let para = Paragraph::new(vec![Line::from(spans)]).alignment(Alignment::Left);
    frame.render_widget(para, area);
}

/// Glass-modal approval sheet (Huh-style): dim the frame, show a centered
/// rounded modal with the tool name, summary, and y/n/R button pills.
fn render_approval_modal(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;

    frame.render_widget(Clear, area);
    let dim = Block::default().style(Style::default().fg(Color::Rgb(20, 20, 28)));
    frame.render_widget(dim, area);

    let modal = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(9),
            Constraint::Min(1),
        ])
        .split(area);
    let modal_h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(10),
            Constraint::Percentage(60),
            Constraint::Min(10),
        ])
        .split(modal[1]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(ROUNDED)
        .border_style(Style::default().fg(c.warning))
        .title(Span::styled(
            " ? Approval Required ",
            Style::default().fg(c.warning).add_modifier(Modifier::BOLD),
        ));

    let first = &app.pending_approvals[0];
    let summary = if app.pending_approvals.len() > 1 {
        format!(
            "{}  (+{} more)",
            first.summary,
            app.pending_approvals.len() - 1
        )
    } else {
        first.summary.clone()
    };

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                &first.tool_name,
                Style::default().fg(c.text).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            format!("  {summary}"),
            Style::default().fg(c.text),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [y]", Style::default().fg(c.warning)),
            Span::styled(" once   ", Style::default().fg(c.dim)),
            Span::styled("[n]", Style::default().fg(c.warning)),
            Span::styled(" deny   ", Style::default().fg(c.dim)),
            Span::styled("[R]", Style::default().fg(c.warning)),
            Span::styled(" session", Style::default().fg(c.dim)),
        ]),
        Line::from(vec![Span::styled(
            "  Esc dismisses the request",
            Style::default().fg(c.dim),
        )]),
    ])
    .block(block);
    frame.render_widget(content, modal_h[1]);
}
