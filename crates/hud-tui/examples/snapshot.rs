// Snapshot renderer: draws the TUI into a 100x30 buffer without a real
// terminal, then prints the cell contents. Run with:
//   cargo run -p orbit-hud-tui --example snapshot          (normal chat)
//   cargo run -p orbit-hud-tui --example snapshot approval (modal shown)

use orbit_hud_tui::render::render;
use orbit_hud_tui::state::{
    App, ComposerState, ConnectionState, Focus, LeftTab, LogoPhase, PendingApproval, ToolState,
    TranscriptLine,
};
use orbit_hud_tui::tokens::{Design, Theme};

fn main() {
    let show_approval = std::env::args().nth(1).as_deref() == Some("approval");
    let design = Design::resolve(&Theme::default(), &|_| None);
    let mut app = App::new();
    app.focus = Focus::Center;
    app.left_tab = LeftTab::Sessions;
    app.model = "coder".into();
    app.provider = "local".into();
    app.session_id_prefix = "01J8K".into();
    app.connection = ConnectionState::Online;
    app.tool_state = ToolState::Idle;
    app.logo_phase = LogoPhase::Steady;
    app.composer_state = ComposerState::Idle;
    app.total_input_tokens = 1234;
    app.total_output_tokens = 567;
    app.total_cost_microcents = 2500;
    app.transcript
        .push(TranscriptLine::User("What is 2*(3+4)?".into()));
    app.transcript.push(TranscriptLine::Assistant(
        "Let me compute that.\n## Result\nThe answer is **14**.\n- computed via `calculator`\n- pure data, no shell"
            .into(),
    ));
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "calculator".into(),
        summary: r#"expression="2*(3+4)""#.into(),
        outcome: Some(true),
        started_at: None,
    });
    if show_approval {
        app.pending_approvals.push(PendingApproval {
            call_id: "call-0".into(),
            tool_name: "calculator".into(),
            summary: "calculator(expression)".into(),
            risk: 1,
        });
        app.tool_state = ToolState::AwaitingApproval;
    }

    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &app, "", &design)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..30 {
        for x in 0..100 {
            let cell = &buffer[(x as u16, y as u16)];
            out.push_str(cell.symbol());
        }
        out.push('\n');
    }
    print!("{out}");
}
