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
use super::scenario::{Activity, Scenario};
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
            let now_ms = boot_ms.elapsed().as_millis() as u64;
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
    println!("✦ ORBIT  session saved");
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
    // An approval is pending: y/a allow, n/s deny.
    if scenario.approval_pending.is_some() {
        match k.code {
            KeyCode::Char('y') | KeyCode::Char('a') => {
                sender.send(Msg::ApprovalDecision {
                    tool: scenario.approval_pending.clone().unwrap_or_default(),
                    decision: crate::state::ApprovalDecision::Once,
                });
                scenario.apply("approval_resolved", 0);
            }
            KeyCode::Char('n') | KeyCode::Char('s') => {
                sender.send(Msg::ApprovalDecision {
                    tool: scenario.approval_pending.clone().unwrap_or_default(),
                    decision: crate::state::ApprovalDecision::Denied,
                });
                scenario.apply("approval_resolved", 0);
            }
            _ => {}
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
                    command_sink.send(crate::WorkerCommand::Prompt(text.clone()));
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
        Msg::TextDelta(_) => {
            scenario.apply("text_delta", 0);
            scenario.last_data_ms = now_ms;
        }
        Msg::ToolCallStarted { name, .. } => {
            scenario.running.insert(name.clone(), name);
            scenario.apply("tool_started_full", 0);
        }
        Msg::ToolCallFinished { name, .. } => {
            scenario.running.remove(&name);
            scenario.apply("tool_finished_full", 0);
        }
        Msg::ApprovalRequested { tool_name, .. } => {
            scenario.approval_pending = Some(tool_name.clone());
            scenario.apply("approval_requested", 0);
            let _ = sender;
        }
        Msg::ResponseFinished { .. } => {
            scenario.apply("turn_ended", 0);
        }
        Msg::Status(text) => {
            // Statuses surface as terminal-tail lines.
            scenario.tool_output.push(text);
        }
        Msg::Identity { model, .. } => {
            scenario.model = model;
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

    // ── The status line: star + activity + mode ──────────────────
    let star = app.star_glyph(scenario);
    let activity = match scenario.activity() {
        Activity::Ready => "ready".to_string(),
        Activity::WaitingModel(m) => format!("waiting for {m}"),
        Activity::Streaming => "streaming".to_string(),
        Activity::Running(t) => format!("running {t}"),
        Activity::RunningMany(n) => format!("running {n} tools"),
        Activity::Approval(t) => format!("◇ approval needed · {t}"),
        Activity::Compacting => "compacting context".to_string(),
        Activity::Done => "✓ done".to_string(),
        Activity::Failed => "✕ failed".to_string(),
    };
    let status = Line::from(vec![
        Span::styled(
            format!("{} ", star.glyph),
            Style::default().fg(comps::colour(match star.colour {
                super::anim::StarColour::Cyan => Token::Cyan,
                super::anim::StarColour::Magenta => Token::Magenta,
                super::anim::StarColour::Amber => Token::Amber,
                super::anim::StarColour::Red => Token::Red,
            })),
        ),
        Span::styled(activity, Style::default().fg(comps::colour(Token::Muted))),
        Span::styled(
            format!(
                "  · {}",
                if mode_insert { "insert" } else { "normal" }
            ),
            Style::default().fg(comps::colour(Token::Rule)),
        ),
    ]);
    let status_area = Rect {
        y: area.y + panels_h,
        height: 1,
        ..area
    };
    f.render_widget(Paragraph::new(status), status_area);

    // ── The composer ─────────────────────────────────────────────
    let composer_area = Rect {
        y: area.y + panels_h + 1,
        height: 3,
        ..area
    };
    let prompt_span = if composer.is_empty() {
        Span::styled(
            "type a prompt and press ⏎  ·  esc arranges  ·  ? keys",
            Style::default().fg(comps::colour(Token::Muted)),
        )
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
