//! The prototype's runtime: the same `Bus` + `WorkerSpawner` contract
//! as the v1 HUD, but the screen is the prototype's — the layout
//! tree, the panels, the star clock, the composer.
//!
//! `orbit` launches this by default; `--old-tui` keeps the v1 HUD.

use crate::bus::{Bus, BusSender};
use crate::msg::Msg;
use crate::worker::{WorkerCtx, WorkerSpawner};
use crate::ApprovalRegistry;

use super::app::{App, Key};
use super::comps;
use super::core::Token;
use super::layout::View;
use super::panels;
use super::scenario::{Activity, LineKind, Scenario, TranscriptLine, TurnReport};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use std::time::{Duration, Instant};

const UI_TICK: Duration = Duration::from_millis(16);

/// Entry point — the same contract as `crate::run`.
pub fn run_proto(args: &[String], worker_spawner: WorkerSpawner) -> i32 {
    let _ = args;
    let home = std::env::var("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".orbit"));

    // tui.toml: reduced motion + the saved layout ("yours").
    let raw: crate::tokens::Theme = {
        let path = home.join("tui.toml");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| toml::from_str(&raw).ok())
            .unwrap_or_default()
    };
    let reduced = raw.capabilities.reduced;

    let mut guard = match crate::terminal::TerminalGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("orbit-tui: cannot enter terminal: {e}");
            return 1;
        }
    };

    let (bus, sender) = Bus::new();
    let approvals = ApprovalRegistry::new();
    let mut app = App::new(home.clone(), reduced);
    let mut scenario = Scenario::new();
    // The model name arrives via Msg::Identity; the thinking line needs
    // it before then too.
    scenario.model = std::env::var("ORBIT_ACTIVE_MODEL").unwrap_or_default();

    // The composer: text lives here (the event loop owns it).
    let mut composer = String::new();
    let mut mode_insert = true;

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let command_sink = cmd_tx.clone();
    let spawn_ctx = WorkerCtx {
        sender: sender.clone(),
        approvals: approvals.clone(),
        command_rx: cmd_rx,
    };
    let _cancel = worker_spawner(spawn_ctx, cmd_tx);

    // The guard owns the terminal; draw through it (v1's pattern).
    let guard = &mut guard;
    let mut last_tick = Instant::now();
    let mut boot_ms = Instant::now();

    loop {
        // ── Input ─────────────────────────────────────────────────
        let timeout = UI_TICK
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_millis(0));
        let now_ms = boot_ms.elapsed().as_millis() as u64;
        if event::poll(timeout).unwrap_or(false) {
            match event::read().unwrap_or(Event::FocusGained) {
                Event::Key(k) => {
                    if handle_key(
                        k,
                        &mut app,
                        &mut scenario,
                        &mut composer,
                        &mut mode_insert,
                        &command_sink,
                        &sender,
                        &approvals,
                        now_ms,
                    ) {
                        // quit
                        break;
                    }
                }
                Event::Resize(w, h) => {
                    let _ = guard
                        .terminal
                        .resize(Rect { x: 0, y: 0, width: w, height: h });
                }
                _ => {}
            }
        }
        if last_tick.elapsed() >= UI_TICK {
            last_tick = Instant::now();
            // Drain the bus into the scenario.
            while let Some(msg) = bus.try_recv() {
                apply_msg(msg, &mut scenario, &sender, now_ms);
            }
            app.tick(now_ms, &scenario);
            // Redraw only while something animates or the state is
            // dirty (an idle ORBIT draws nothing).
            guard
                .terminal
                .draw(|f| draw(f, &app, &scenario, &composer, mode_insert))
                .unwrap();
        }
    }

    // TerminalGuard's Drop restores the terminal (raw mode off, alt
    // screen off).
    drop(guard);
    // M8 / §9.24: one line to the scrollback after the screen
    // closes. The session id lets `orbit chat --resume` pick it up.
    let session = if scenario.session_id.is_empty() {
        String::new()
    } else {
        format!("\n         resume with orbit chat --resume {}", scenario.session_id)
    };
    let cost = if scenario.priced {
        format!("${:.4}", scenario.cost_microcents as f64 / 1_000_000.0)
    } else {
        "n/a".into()
    };
    println!(
        "✦ ORBIT  session saved · {} turns · {} in · {} out · {cost}{session}",
        scenario.turns, scenario.input_tokens, scenario.output_tokens
    );
    0
}

/// Handle one key. Returns true when the loop should quit.
#[allow(clippy::too_many_arguments)]
fn handle_key(
    k: KeyEvent,
    app: &mut App,
    scenario: &mut Scenario,
    composer: &mut String,
    mode_insert: &mut bool,
    command_sink: &crate::CommandSink,
    sender: &BusSender,
    approvals: &crate::ApprovalRegistry,
    now_ms: u64,
) -> bool {
    // Ctrl+C always quits.
    if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
        return true;
    }
    // The picker is open: 1–8 choose the view, esc cancels.
    if app.picker.is_some() {
        match k.code {
            KeyCode::Esc => {
                app.key(Key::Esc);
            }
            KeyCode::Char(c @ '1'..='8') => {
                let view = [
                    View::Conversation,
                    View::Changes,
                    View::Terminal,
                    View::Plan,
                    View::Activity,
                    View::Context,
                    View::Review,
                    View::Agent,
                ][(c as usize - '1' as usize).min(7)];
                if app.pick(view) {
                    app.save_yours();
                }
            }
            _ => {}
        }
        return false;
    }
    // Arranging is on: the grammar owns the keyboard (esc started
    // it; i or Enter leaves). This check comes BEFORE insert typing
    // so v/s/x/HJKL act instead of landing in the composer.
    if app.arranging {
        match k.code {
            KeyCode::Enter | KeyCode::Char('i') => {
                app.arranging = false;
                *mode_insert = true;
            }
            KeyCode::Esc => {
                app.key(Key::Esc);
            }
            KeyCode::Char(c) => {
                if app.key(Key::Char(c)) {
                    app.save_yours();
                }
            }
            _ => {}
        }
        return false;
    }
    // An approval is pending: y/a allow (this call), R allow the
    // session, n/s deny. Resolving goes through the ApprovalRegistry
    // — its channel is what releases the parked worker thread.
    if scenario.approval_pending.is_some() {
        let call_id = scenario.approval_call_id.clone().unwrap_or_default();
        let response = match k.code {
            KeyCode::Char('y') | KeyCode::Char('a') => Some(crate::ApprovalResponse::Allow),
            KeyCode::Char('R') => Some(crate::ApprovalResponse::AllowSession),
            KeyCode::Char('n') | KeyCode::Char('s') => Some(crate::ApprovalResponse::Deny),
            _ => None,
        };
        if let Some(resp) = response {
            approvals.resolve(&call_id, resp);
            scenario.apply("approval_resolved", 0);
        }
        return false;
    }
    // INSERT mode: typing is the composer; Enter submits.
    if *mode_insert {
        match k.code {
            KeyCode::Enter => {
                let text = composer.trim().to_string();
                composer.clear();
                if text == "quit" || text == "exit" {
                    return true;
                }
                if !text.is_empty() {
                    scenario.transcript.push(TranscriptLine {
                        kind: LineKind::User,
                        text: text.clone(),
                    });
                    command_sink.send(crate::WorkerCommand::Prompt(text.clone()));
                    scenario.turn_started_ms = now_ms;
                    scenario.apply("round_started", 0);
                }
            }
            KeyCode::Backspace => {
                composer.pop();
            }
            KeyCode::Esc => {
                if composer.is_empty() {
                    // Esc with an empty composer: arrange mode. The
                    // grammar now owns the keyboard until i / Enter.
                    app.arranging = true;
                    *mode_insert = false;
                } else {
                    composer.clear();
                }
            }
            KeyCode::Char(c) => {
                if k.modifiers.contains(KeyModifiers::SHIFT) {
                    // crossterm gives lowercase + SHIFT; uppercase it.
                    let upper = c.to_uppercase().next().unwrap_or(c);
                    // H J K L while typing are still text — arrange keys
                    // only apply in arrange mode (esc first).
                    composer.push(upper);
                } else {
                    composer.push(c);
                }
            }
            _ => {}
        }
        return false;
    }
    false
}

/// FrontendEvent-shaped Msgs → the scenario reducer.
fn apply_msg(msg: Msg, scenario: &mut Scenario, sender: &BusSender, now_ms: u64) {
    match msg {
        Msg::TextDelta(text) => {
            scenario.apply("text_delta", 0);
            scenario.last_data_ms = now_ms;
            // Stream into the transcript: append to the open model
            // line, or open one.
            match scenario.transcript.last_mut() {
                Some(l) if l.kind == LineKind::Model => l.text.push_str(&text),
                _ => scenario.transcript.push(TranscriptLine {
                    kind: LineKind::Model,
                    text,
                }),
            }
        }
        Msg::ToolCallStarted { name, summary } => {
            scenario.running.insert(name.clone(), name.clone());
            scenario.apply("tool_started_full", 0);
            scenario.turn_tools += 1;
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::Tool,
                text: format!("{name} {summary}"),
            });
        }
        Msg::ToolCallFinished { name, .. } => {
            scenario.running.remove(&name);
            scenario.apply("tool_finished_full", 0);
        }
        Msg::ApprovalRequested { call_id, tool_name, .. } => {
            scenario.approval_pending = Some(tool_name.clone());
            scenario.approval_call_id = Some(call_id);
            scenario.apply("approval_requested", 0);
            let _ = sender;
        }
        Msg::ResponseFinished { output_tokens, input_tokens, cost_microcents, .. } => {
            // M5: the turn report. Cumulative totals for the
            // shutdown line.
            let duration = scenario.turn_started_ms;
            let _ = duration;
            scenario.turns += 1;
            scenario.input_tokens += input_tokens;
            scenario.output_tokens += output_tokens;
            scenario.cost_microcents += cost_microcents;
            scenario.turn_report = Some(TurnReport {
                duration_ms: now_ms.saturating_sub(scenario.turn_started_ms),
                tools: scenario.turn_tools,
                cost_microcents,
                priced: scenario.priced,
            });
            scenario.apply("turn_ended", 0);
        }
        Msg::Status(text) => {
            scenario.tool_output.push(text.clone());
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text,
            });
        }
        Msg::Identity { model, provider, session_prefix, session_id, priced } => {
            scenario.model = model.clone();
            scenario.model_id = model;
            scenario.provider = provider;
            scenario.session_prefix = session_prefix;
            scenario.session_id = session_id;
            scenario.priced = priced;
        }
        Msg::BackendError(_) => {
            scenario.apply("turn_failed", 0);
        }
        _ => {}
    }
}

/// The whole screen: panels + the status line + the composer.
fn draw(
    f: &mut ratatui::Frame,
    app: &App,
    scenario: &Scenario,
    composer: &str,
    mode_insert: bool,
) {
    let area = f.area();
    // Reserve the status line (1) + composer (3).
    let panels_h = area.height.saturating_sub(4);
    let panels_area = Rect {
        height: panels_h,
        ..area
    };
    app.render_into(f, panels_area, scenario);

    // ── The status line (§9.18): mark + activity left, the right
    // cluster by width level. No background, no separators.
    let star = app.star_glyph(scenario);
    let star_colour = comps::colour(match star.colour {
        super::anim::StarColour::Cyan => Token::Cyan,
        super::anim::StarColour::Magenta => Token::Magenta,
        super::anim::StarColour::Amber => Token::Amber,
        super::anim::StarColour::Red => Token::Red,
    });
    // The activity, first match wins (§9.18). The M5 turn report
    // rides here for 2 s after a successful turn.
    let elapsed_s = |now: u64, from: u64| {
        let d = now.saturating_sub(from);
        if d >= 1000 { format!(" · {}s", d / 1000) } else { String::new() }
    };
    let activity_spans: Vec<Span> = match scenario.activity() {
        Activity::Approval(t) => vec![
            Span::styled(format!("◇ approval needed · {t}"), Style::default().fg(comps::colour(Token::Magenta))),
        ],
        Activity::RunningMany(n) => vec![
            Span::styled(format!("running {n} tools"), Style::default().fg(comps::colour(Token::Cyan))),
            Span::styled(elapsed_s(app.tick_ms, scenario.turn_started_ms), Style::default().fg(comps::colour(Token::Muted))),
        ],
        Activity::Running(t) => vec![
            Span::styled(format!("running {t}"), Style::default().fg(comps::colour(Token::Cyan))),
            Span::styled(elapsed_s(app.tick_ms, scenario.turn_started_ms), Style::default().fg(comps::colour(Token::Muted))),
        ],
        Activity::Streaming => vec![
            Span::styled("streaming", Style::default().fg(comps::colour(Token::Cyan))),
            Span::styled(elapsed_s(app.tick_ms, scenario.turn_started_ms), Style::default().fg(comps::colour(Token::Muted))),
        ],
        Activity::WaitingModel(m) => vec![
            Span::styled(format!("waiting for {m}"), Style::default().fg(comps::colour(Token::Cyan))),
        ],
        Activity::Compacting => vec![
            Span::styled("compacting context", Style::default().fg(comps::colour(Token::Amber))),
        ],
        Activity::Done => vec![
            Span::styled("✓", Style::default().fg(comps::colour(Token::Green))),
            Span::styled(" done", Style::default().fg(comps::colour(Token::Ink))),
        ],
        Activity::Failed => vec![
            Span::styled("✕ failed", Style::default().fg(comps::colour(Token::Red))),
        ],
        Activity::Ready => {
            // The M5 turn report: ✓ done · 41s · 3 tools · +$0.0031,
            // for 2 s or until the next key.
            if let Some(r) = &scenario.turn_report {
                if app.tick_ms.saturating_sub(scenario.turn_started_ms) < 4000 {
                    let mut spans = vec![
                        Span::styled("✓", Style::default().fg(comps::colour(Token::Green))),
                        Span::styled(" done", Style::default().fg(comps::colour(Token::Ink))),
                        Span::styled(format!(" · {}s", r.duration_ms / 1000), Style::default().fg(comps::colour(Token::Muted))),
                    ];
                    if r.tools > 0 {
                        spans.push(Span::styled(format!(" · {} tools", r.tools), Style::default().fg(comps::colour(Token::Muted))));
                    }
                    if r.priced {
                        spans.push(Span::styled(
                            format!(" · +${:.4}", r.cost_microcents as f64 / 1_000_000.0),
                            Style::default().fg(comps::colour(Token::Muted)),
                        ));
                    }
                    spans
                } else {
                    vec![Span::styled("ready", Style::default().fg(comps::colour(Token::Muted)))]
                }
            } else {
                vec![Span::styled("ready", Style::default().fg(comps::colour(Token::Muted)))]
            }
        }
    };
    // The mark: ✦ ORBIT (muted bold word) — the compact mark, every
    // layout (§8.1).
    let mut left = vec![
        Span::styled(star.glyph.to_string(), Style::default().fg(star_colour)),
        Span::styled(" ORBIT", Style::default().fg(comps::colour(Token::Muted)).add_modifier(ratatui::style::Modifier::BOLD)),
        Span::raw("   "),
    ];
    left.extend(activity_spans);
    // The right cluster, by width level (§9.18).
    let w = area.width;
    let mut right: Vec<Span> = Vec::new();
    if w >= 60 {
        // cost slot
        if scenario.priced {
            right.push(Span::styled(
                format!("${:.4}", scenario.cost_microcents as f64 / 1_000_000.0),
                Style::default().fg(comps::colour(Token::Ink)),
            ));
        } else {
            right.push(Span::styled("cost n/a", Style::default().fg(comps::colour(Token::Muted))));
        }
    }
    if w >= 110 {
        // token slot
        right.push(Span::styled(
            format!("↓{} ↑{}", scenario.input_tokens, scenario.output_tokens),
            Style::default().fg(comps::colour(Token::Muted)),
        ));
    }
    if w >= 140 {
        // session prefix
        if !scenario.session_prefix.is_empty() {
            right.push(Span::styled(
                scenario.session_prefix.clone(),
                Style::default().fg(comps::colour(Token::Muted)),
            ));
        }
        // model · provider
        if !scenario.model_id.is_empty() {
            right.push(Span::styled(
                format!("{} · {}", scenario.model_id, scenario.provider),
                Style::default().fg(comps::colour(Token::Ink)),
            ));
        }
    }
    // Right cluster: 3 spaces between segments, right-aligned.
    let left_w: u16 = left.iter().map(|s| s.width() as u16).sum();
    let right_w: u16 = right.iter().map(|s| s.width() as u16).sum::<u16>()
        + (right.len().saturating_sub(1).max(0) as u16) * 3;
    let mut status = left;
    if !right.is_empty() && left_w + 3 + right_w <= w {
        let pad = w - left_w - right_w;
        status.push(Span::raw(" ".repeat(pad as usize)));
        for (i, seg) in right.into_iter().enumerate() {
            if i > 0 {
                status.push(Span::raw("   "));
            }
            status.push(seg);
        }
    }
    let status_area = Rect {
        y: area.y + panels_h,
        height: 1,
        ..area
    };
    f.render_widget(Paragraph::new(Line::from(status)), status_area);

    // ── The composer ─────────────────────────────────────────────
    let composer_area = Rect {
        y: area.y + panels_h + 1,
        height: 3,
        ..area
    };
    // The placeholder per §9.13: idle asks; a live turn queues.
    let placeholder = if scenario.turn_live {
        if area.width < 60 { "Add to the queue, or wait" } else { "Add to the queue, or wait for ORBIT" }
    } else {
        "Ask ORBIT, or type / for commands"
    };
    let prompt_span = if composer.is_empty() {
        Span::styled(placeholder, Style::default().fg(comps::colour(Token::Rule)))
    } else {
        Span::styled(composer.to_string(), Style::default().fg(comps::colour(Token::Ink)))
    };
    // The breathing caret (M06): pulses at 0.9 Hz once 400 ms pass
    // without data; bright cyan while typing.
    let caret = if mode_insert {
        comps::caret(app.tick_ms, scenario.last_data_ms, app.reduced)
    } else {
        Span::styled("▍", Style::default().fg(comps::colour(Token::Rule)))
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(comps::colour(Token::Rule)));
    f.render_widget(
        Paragraph::new(Line::from(vec![prompt_span, caret])).block(block),
        composer_area,
    );
}

// The star glyph for the app's current state (a small bridge the
// runtime needs; the clock itself lives in anim).
impl App {
    pub fn star_glyph(&self, scenario: &Scenario) -> super::anim::StarGlyph {
        let state = scenario.star_state();
        let mut c = self.star;
        c.tick(self.tick_ms, state)
    }

    /// Render into a specific area (the runtime reserves the status
    /// line + composer).
    pub fn render_into(&self, f: &mut ratatui::Frame, area: Rect, scenario: &Scenario) {
        let areas = panels::split_areas(area, &self.tree);
        let single = self.one_at_a_time(area.width);
        let show = if single {
            vec![areas[self.focus.min(areas.len() - 1)]]
        } else {
            areas
        };
        for (i, (rect, view)) in show.iter().enumerate() {
            let idx = if single { self.focus } else { i };
            panels::render_panel(
                f,
                *rect,
                (idx + 1) as u8,
                *view,
                idx == self.focus,
                scenario,
                self.tick_ms,
                self.reduced,
            );
        }
        // The picker overlay.
        if self.picker.is_some() {
            let w = 28u16.min(area.width.saturating_sub(4));
            let h = 10u16.min(area.height.saturating_sub(4));
            let r = Rect {
                x: area.x + (area.width - w) / 2,
                y: area.y + (area.height - h) / 2,
                width: w,
                height: h,
            };
            let views = [
                View::Conversation,
                View::Changes,
                View::Terminal,
                View::Plan,
                View::Activity,
                View::Context,
                View::Review,
                View::Agent,
            ];
            let lines: Vec<Line> = std::iter::once(Line::from(Span::styled(
                "Show what?",
                Style::default().fg(comps::colour(Token::Cyan)).add_modifier(Modifier::BOLD),
            )))
            .chain(views.iter().enumerate().map(|(i, v)| {
                Line::from(vec![
                    Span::styled(format!(" {} ", i + 1), Style::default().fg(comps::colour(v.token()))),
                    Span::styled(v.title(), Style::default().fg(comps::colour(Token::Ink))),
                ])
            }))
            .collect();
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(comps::colour(Token::Cyan)));
            f.render_widget(ratatui::widgets::Clear, r);
            f.render_widget(Paragraph::new(lines).block(block), r);
        }
    }
}
