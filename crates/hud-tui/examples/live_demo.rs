// Live TUI demo: drives the real renderer with the Appendix-B fixture state
// (same data the goldens encode) on a real terminal. No backend, no worker —
// pure display, so the operator can see the actual panel isolation, colours,
// plan/findings/verification workspace, and the approval surface.
//
//   cargo run -p orbit-hud-tui --example live_demo
//
// Timeline (~14s): idle → thinking → approval card → running → settled.
// Keys: y allow · n deny · q/Esc quit.

// Re-use the test fixture data inline (tests/ isn't linkable from examples).
use orbit_hud_tui::msg::Msg;
use orbit_hud_tui::render::render;
use orbit_hud_tui::state::{
    App, ApprovalDecision, ComposerState, ConnectionState, Focus, LeftTab, PendingApproval, Task,
    TaskState, ToolOutcome, ToolState, TranscriptLine,
};

include!("../tests/common/fixture_data.rs");
use orbit_hud_tui::tokens::{Design, Theme};
use std::io::{self};
use std::time::Duration;

fn main() -> io::Result<()> {
    let design = Design::resolve(&Theme::default(), &|_| None);
    let mut app = base_app();
    app.focus = Focus::Center;
    app.left_tab = LeftTab::Sessions;
    // B1 sessions.
    for (g, title, recency, failed) in SESSIONS {
        app.sessions.push(orbit_hud_tui::state::SessionRow {
            title: (*title).into(),
            recency: (*recency).into(),
            group: g,
            failed: *failed,
            open: *recency == "now",
        });
    }
    // B2 conversation history.
    app.transcript.extend(b2_history());
    // B3 workspace: verify 4/5 (identical to wide_idle_app).
    app.workspace = orbit_hud_tui::state::Workspace {
        phase_index: 3, // verify
        plan: vec![
            Task {
                title: "Reproduce restore failure".into(),
                state: TaskState::Done,
                sub: None,
                evidence: 1,
            },
            Task {
                title: "Find where the chain resets".into(),
                state: TaskState::Done,
                sub: None,
                evidence: 0,
            },
            Task {
                title: "Seed chain from exported head".into(),
                state: TaskState::Done,
                sub: None,
                evidence: 1,
            },
            Task {
                title: "Add restore_preserves_head".into(),
                state: TaskState::Done,
                sub: None,
                evidence: 1,
            },
            Task {
                title: "Run clean-machine e2e".into(),
                state: TaskState::Pending,
                sub: None,
                evidence: 0,
            },
        ],
        findings: vec![
            orbit_hud_tui::state::Finding {
                title: "restore writes a fresh genesis record".into(),
                source: Some("restore.rs:88".into()),
            },
            orbit_hud_tui::state::Finding {
                title: "seeded chain digests match exported head".into(),
                source: None,
            },
        ],
        verification: vec![
            orbit_hud_tui::state::Verification {
                name: "unit · orbit-export".into(),
                result: orbit_hud_tui::state::VerificationResult::Passed,
                proof_count: 1,
                result_text: "48 passed".into(),
            },
            orbit_hud_tui::state::Verification {
                name: "ledger · restored home".into(),
                result: orbit_hud_tui::state::VerificationResult::Passed,
                proof_count: 1,
                result_text: "7 records".into(),
            },
            orbit_hud_tui::state::Verification {
                name: "e2e · clean machine".into(),
                result: orbit_hud_tui::state::VerificationResult::Pending,
                proof_count: 0,
                result_text: "retest".into(),
            },
        ],
    };
    app.header_title = "Restore keeps chain head".into();
    app.header_meta = "14 turns".into();
    app.workspace_meta = "4/5".into();
    app.total_turns = 14;
    app.total_input_tokens = 18_200;
    app.total_output_tokens = 2_900;
    app.total_cost_microcents = 21_400;
    app.logo_phase = orbit_hud_tui::state::LogoPhase::Steady;
    app.composer_state = ComposerState::Idle;

    let mut terminal = ratatui::init();
    let mut tick: u64 = 0;
    loop {
        // ── scripted timeline (each tick ≈ 80 ms) ────────────────────────
        match tick {
            0 => {
                app.composer_state = ComposerState::Blocked("thinking".into());
            }
            40 => {
                app.composer_state = ComposerState::Idle;
                app.pending_approvals.push(PendingApproval {
                    call_id: "call-0".into(),
                    tool_name: "shell".into(),
                    summary: "bash -c 'cargo test -p orbit-ledger'".into(),
                    risk: 2,
                });
                app.tool_state = ToolState::AwaitingApproval;
            }
            95 => {
                // operator "allowed"
                app.pending_approvals.clear();
                app.tool_state = ToolState::Running("cargo test".into());
                // §12: answering the card adds an Activity grant row.
                app.reduce(Msg::ApprovalDecision {
                    tool: "shell".into(),
                    decision: ApprovalDecision::Once,
                });
            }
            130 => {
                app.tool_state = ToolState::Idle;
                app.composer_state = ComposerState::Idle;
                app.transcript.push(TranscriptLine::Stripped {
                    tool_name: "shell".into(),
                    summary: "bash -c 'cargo test -p orbit-ledger'".into(),
                    outcome: Some(ToolOutcome::Ok),
                    meta: "48 passed · 3.9s".into(),
                    started_at: None,
                });
                app.transcript.push(TranscriptLine::Assistant {
                    text: "All 48 ledger tests pass. Chain verified — restore now seeds from the exported head digest, digest continuity asserted.".into(),
                    time: None,
                });
            }
            _ => {}
        }

        terminal.draw(|f| render(f, &app, "verify the fix", &design))?;

        // keys: y allow / n deny / q quit
        if crossterm::event::poll(Duration::from_millis(80))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                match (k.code, k.modifiers) {
                    (crossterm::event::KeyCode::Char('q'), _)
                    | (crossterm::event::KeyCode::Esc, _) => break,
                    // herdr panel isolation: Tab cycles focus (the accent
                    // border moves), g v toggles the Activity tab.
                    (crossterm::event::KeyCode::Tab, _) => {
                        app.focus = match app.focus {
                            Focus::Left => Focus::Center,
                            Focus::Center => Focus::Right,
                            Focus::Right | Focus::Status => Focus::Left,
                        };
                    }
                    (crossterm::event::KeyCode::Char('v'), _) => {
                        app.left_tab = if app.left_tab == LeftTab::Sessions {
                            LeftTab::Verbose
                        } else {
                            LeftTab::Sessions
                        };
                    }
                    (crossterm::event::KeyCode::Char('y'), _)
                        if !app.pending_approvals.is_empty() =>
                    {
                        app.pending_approvals.clear();
                        app.tool_state = ToolState::Running("cargo test".into());
                    }
                    (crossterm::event::KeyCode::Char('n'), _)
                        if !app.pending_approvals.is_empty() =>
                    {
                        app.pending_approvals.clear();
                        app.transcript.push(TranscriptLine::Stripped {
                            tool_name: "shell".into(),
                            summary: "bash -c 'cargo test -p orbit-ledger'".into(),
                            outcome: Some(ToolOutcome::Denied),
                            meta: "operator denied".into(),
                            started_at: None,
                        });
                        app.tool_state = ToolState::Idle;
                    }
                    _ => {}
                }
            }
        }
        tick += 1;
        if tick > 170 {
            break;
        } // ~14s total
    }
    ratatui::restore();
    Ok(())
}
