//! Ratatui rendering (DR-20 §2.4, §5 polish).
//!
//! Three-pane layout with rounded borders, theme-driven colors, animated
//! thinking indicator, and Markdown-aware text rendering. Every color reads
//! from `ResolvedTheme` — no hardcoded colors.

use crate::rich::render_message;
use crate::state::{App, ConnectionState, Focus, LeftTab, ToolState, TranscriptLine};
use crate::theme::ResolvedTheme;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap};

/// A rounded-border block for a pane: accent color if focused (with shimmer),
/// dim if not. The focused pane gets a `▶` gutter indicator in the title.
fn pane_block<'a>(
    title: &'a str,
    focused: bool,
    shimmer_phase: u8,
    theme: &ResolvedTheme,
) -> Block<'a> {
    let color = if focused {
        // Shimmer: alternate between accent and accent_bright.
        if shimmer_phase.is_multiple_of(2) {
            theme.colors.accent
        } else {
            theme.colors.accent_bright
        }
    } else {
        theme.colors.accent_dim
    };
    let title_text = if focused {
        format!("▶ {title} ")
    } else {
        format!(" {title} ")
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            title_text,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

/// Render the current app state into the frame.
pub fn render(frame: &mut ratatui::Frame, app: &App, composer_text: &str, theme: &ResolvedTheme) {
    let area = frame.area();
    let _c = &theme.colors;

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

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(theme.layout.left_pct),
            Constraint::Percentage(theme.layout.center_pct),
            Constraint::Percentage(theme.layout.right_pct),
        ])
        .split(outer[1]);

    render_left_pane(frame, main[0], app, theme);
    render_center_pane(frame, main[1], app, composer_text, theme);
    render_right_pane(frame, main[2], app, theme);
    render_status_bar(frame, outer[2], app, theme);
    if theme.tabs.show_help_bar {
        render_help(frame, outer[3], app, theme);
    }

    // Quit confirmation modal — rendered on top of everything.
    if app.quit_confirmation {
        render_quit_modal(frame, area, app, theme);
    }
}

/// Render a centered quit confirmation modal with dim overlay.
fn render_quit_modal(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;

    // Dim overlay.
    let dim_overlay =
        Block::default().style(Style::default().fg(c.dim).add_modifier(Modifier::DIM));
    frame.render_widget(dim_overlay, area);

    // Modal message depends on whether a response is running.
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
        .border_type(BorderType::Rounded)
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

fn render_header(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let tab_label = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Verbose",
    };
    let shimmer_color = if app.shimmer_phase.is_multiple_of(2) {
        c.accent
    } else {
        c.accent_bright
    };
    let header = Paragraph::new(vec![Line::from(vec![
        Span::styled("✹ ", Style::default().fg(c.composer)),
        Span::styled(
            "ORBIT",
            Style::default()
                .fg(shimmer_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  [{tab_label}]"), Style::default().fg(c.composer)),
    ])])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(c.accent_dim)),
    );
    frame.render_widget(header, area);
}

fn render_left_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let title = match app.left_tab {
        LeftTab::Sessions => "Sessions",
        LeftTab::Verbose => "Verbose",
    };
    let block = pane_block(title, app.focus == Focus::Left, app.shimmer_phase, theme);

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

    // Split center into: transcript (fill) | composer (fixed)
    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(theme.layout.composer_lines),
        ])
        .split(area);

    // ── Transcript ──────────────────────────────────────────────────────────
    let mut lines: Vec<Line> = Vec::new();
    for entry in &app.transcript {
        match entry {
            TranscriptLine::User(text) => {
                for (i, line) in text.lines().enumerate() {
                    let prefix = if i == 0 { "user> " } else { "      " };
                    lines.push(Line::from(vec![
                        Span::styled(prefix, Style::default().fg(c.composer)),
                        Span::styled(line, Style::default().fg(c.text)),
                    ]));
                }
            }
            TranscriptLine::Assistant(text) => {
                for (i, rich_line) in render_message(text, theme).into_iter().enumerate() {
                    let prefix = if i == 0 { "orbit> " } else { "       " };
                    let mut full = vec![Span::styled(prefix, Style::default().fg(c.accent))];
                    full.extend(rich_line.spans);
                    lines.push(Line::from(full));
                }
            }
            TranscriptLine::Stripped { tool_name } => {
                lines.push(Line::from(vec![Span::styled(
                    format!("  [tool: {tool_name}] (reasoning stripped)"),
                    Style::default().fg(c.dim),
                )]));
            }
        }
    }

    // In-flight streaming text
    if !app.in_flight.is_empty() {
        for (i, rich_line) in render_message(&app.in_flight, theme)
            .into_iter()
            .enumerate()
        {
            let prefix = if i == 0 { "orbit> " } else { "       " };
            let mut full = vec![Span::styled(prefix, Style::default().fg(c.accent))];
            full.extend(rich_line.spans);
            lines.push(Line::from(full));
        }
        lines.push(Line::from(vec![Span::styled(
            "█",
            Style::default().fg(c.composer),
        )]));
    } else if app.tool_state == ToolState::Streaming {
        // Thinking indicator: spinner + rotating phrase.
        let frames = crate::theme::spinner_frames(&theme.spinner.style);
        let spinner = frames[app.thinking_phase as usize % frames.len()];
        let phrase = &theme.spinner.phrases[app.thinking_phrase % theme.spinner.phrases.len()];
        lines.push(Line::from(vec![
            Span::styled("orbit> ", Style::default().fg(c.accent)),
            Span::styled(spinner, Style::default().fg(c.composer)),
            Span::raw(" "),
            Span::styled(phrase, Style::default().fg(c.dim)),
        ]));
    }

    // Pending approvals — rendered as rounded boxes.
    for approval in &app.pending_approvals {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("  ╭─ TOOL: {} ──╮", approval.summary),
            Style::default().fg(c.warning),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "  │  [y] allow  [n] deny  [R] always  │",
            Style::default().fg(c.warning),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "  ╰────────────────────────────────────╯",
            Style::default().fg(c.warning),
        )]));
    }

    // Error
    if let Some(err) = &app.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("error: ", Style::default().fg(c.error)),
            Span::styled(err, Style::default().fg(c.error)),
        ]));
    }

    // Auto-scroll: keep the bottom of the transcript visible.
    let visible_height = center[0].height.saturating_sub(2) as usize;
    let total_lines = lines.len();
    let scroll = if total_lines > visible_height {
        (total_lines - visible_height) as u16
    } else {
        0
    };

    let transcript = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(pane_block(
            "Conversation",
            app.focus == Focus::Center,
            app.shimmer_phase,
            theme,
        ));
    frame.render_widget(transcript, center[0]);

    // ── Composer ────────────────────────────────────────────────────────────
    let composer_focused = app.focus == Focus::Center;
    let composer_color = if composer_focused {
        c.composer
    } else {
        c.composer_dim
    };
    let composer_line = if composer_text.is_empty() {
        Line::from(vec![
            Span::styled("> ", Style::default().fg(composer_color)),
            Span::styled("█", Style::default().fg(composer_color)),
        ])
    } else {
        Line::from(vec![
            Span::styled("> ", Style::default().fg(composer_color)),
            Span::styled(composer_text, Style::default().fg(c.text)),
            Span::styled("█", Style::default().fg(composer_color)),
        ])
    };
    let composer = Paragraph::new(vec![
        composer_line,
        Line::from(vec![Span::styled(
            "  Enter send · Shift+Enter newline · / commands",
            Style::default().fg(c.dim),
        )]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(composer_color))
            .title(Span::styled(" > ", Style::default().fg(composer_color))),
    );
    frame.render_widget(composer, center[1]);
}

fn render_right_pane(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &ResolvedTheme) {
    let c = &theme.colors;
    let block = pane_block("Tasks", app.focus == Focus::Right, app.shimmer_phase, theme);
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
        ToolState::Streaming => Span::styled("◐ stream", Style::default().fg(c.composer)),
        ToolState::AwaitingApproval => Span::styled("? approval", Style::default().fg(c.warning)),
        ToolState::Running(name) => {
            Span::styled(format!("◉ {name}"), Style::default().fg(c.success))
        }
        ToolState::AutoGranted(name) => {
            Span::styled(format!("◑ auto({name})"), Style::default().fg(c.accent))
        }
    };
    let conn_glyph = match app.connection {
        ConnectionState::Online => Span::styled("● online", Style::default().fg(c.success)),
        ConnectionState::Reconnecting => {
            let frames = ["↻", "↺", "↻"];
            let spinner = frames[app.reconnect_phase as usize % 3];
            Span::styled(
                format!("{spinner} reconnect"),
                Style::default().fg(c.warning),
            )
        }
        ConnectionState::Offline => Span::styled("✕ offline", Style::default().fg(c.error)),
    };

    // Token counters with k/M suffixes.
    let fmt_tokens = |n: u64| -> String {
        if n >= 1_000_000 {
            format!("{:.1}M", n as f64 / 1_000_000.0)
        } else if n >= 1_000 {
            format!("{:.1}k", n as f64 / 1_000.0)
        } else {
            n.to_string()
        }
    };
    let tokens = format!(
        "↓{} ↑{}",
        fmt_tokens(app.total_input_tokens),
        fmt_tokens(app.total_output_tokens)
    );

    // Cost with flash indicator.
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
        Span::raw(" quit"),
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
