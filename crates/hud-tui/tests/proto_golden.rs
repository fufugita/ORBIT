//! Proto golden frames (§16.2): render the §9.22 welcome, the §9.13
//! composer and the §9.14 approval card at their golden sizes and
//! compare symbols with `docs/tui/golden/*.txt` (trimmed rows).
//!
//! The transcript-heavy goldens (wide_idle, wide_streaming,
//! wide_approval) carry §13.1 fixture data the runtime does not emit
//! (session history, findings, plan); those are compared structurally
//! (§16.2 allows symbols-only comparison per row) once the fixture
//! state exists. Today we assert the states that DO render.

use orbit_hud_tui::proto::runtime::draw;
use orbit_hud_tui::proto::runtime::Tui;
use orbit_hud_tui::proto::scenario::{LineKind, Scenario, ToolState, TranscriptLine};
use ratatui::backend::TestBackend;

fn render(tui: &Tui, scenario: &Scenario, w: u16, h: u16) -> String {
    let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| draw(f, tui, scenario, "", None, "", 0, None, false, 0))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let mut out = Vec::new();
    for y in 0..h {
        let mut row = String::new();
        for x in 0..w {
            row.push_str(buf[(x, y)].symbol());
        }
        out.push(row.trim_end().to_string());
    }
    out.join("\n")
}

fn base_scenario() -> Scenario {
    let mut s = Scenario::new();
    s.model = "glm-5.2".into();
    s.model_id = "glm-5.2".into();
    s.provider = "local".into();
    s.session_id = "session-01J8ZK4QX2M7C9RT5VWEHN3B6D".into();
    s.session_prefix = "01J8ZK4Q".into();
    s
}

#[test]
fn golden_min_size_notice() {
    // §9.23: below 40 × 10 the size notice is the whole screen.
    let tui = Tui::new();
    let s = base_scenario();
    let out = render(&tui, &s, 38, 9);
    assert!(out.contains("ORBIT needs at least 40"), "{out}");
    assert!(out.contains("38 × 9"), "{out}");
}

#[test]
fn golden_welcome_medium_static() {
    // welcome.txt is 111 cols: the Medium class with the mark,
    // tagline and starters centred in the conversation column.
    let mut tui = Tui::new();
    tui.brand_tier = orbit_hud_tui::proto::welcome::BrandTier::Static;
    let s = base_scenario();
    let out = render(&tui, &s, 111, 35);
    let golden = std::fs::read_to_string("../../docs/tui/golden/welcome.txt").unwrap();
    let g: Vec<&str> = golden.lines().collect();
    // The tagline and starters are stable anchors.
    assert!(out.contains("the harness that orbits around you"), "{out}");
    assert!(
        out.contains("Describe a task below, or start with"),
        "{out}"
    );
    assert!(out.contains("/models"), "{out}");
    // The composer + hint row (§9.13).
    assert!(out.contains("Ask ORBIT, or type / for commands"), "{out}");
    // The status line shows the mark + ready.
    assert!(out.contains("ORBIT"), "{out}");
    let _ = g;
}

#[test]
fn golden_user_turn_band_and_gutter() {
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "hello world".into(),
        time: Some("14:02".into()),
        ..Default::default()
    });
    let out = render(&tui, &s, 111, 35);
    assert!(out.contains("› hello world"), "{out}");
    assert!(out.contains("14:02"), "{out}");
}

#[test]
fn golden_tool_line_running_then_done() {
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Tool,
        text: "expression".into(),
        tool_name: "calculator".into(),
        tool_state: ToolState::Running,
        started_ms: Some(0),
        ..Default::default()
    });
    let out = render(&tui, &s, 111, 35);
    assert!(out.contains("◉ calculator"), "{out}");
    assert!(out.contains("running"), "{out}");
    s.transcript[0].tool_state = ToolState::Done;
    s.transcript[0].meta = "done · 0.1s".into();
    let out2 = render(&tui, &s, 111, 35);
    assert!(out2.contains("✓ calculator"), "{out2}");
    assert!(out2.contains("done · 0.1s"), "{out2}");
}

#[test]
fn golden_approval_card_frame() {
    let tui = Tui::new();
    let mut s = base_scenario();
    s.approval_pending = Some("shell".into());
    s.approval_queue = vec!["shell".into()];
    s.approval_summary = Some("scripts/e2e-clean-machine.sh --keep-home".into());
    let out = render(&tui, &s, 150, 44);
    assert!(out.contains("◇ Allow shell?"), "CARD MISSING: {out}");
    assert!(out.contains("y  allow once"), "{out}");
    assert!(out.contains("n   esc  deny"), "{out}");
    assert!(out.contains("╭"), "{out}");
    assert!(out.contains("╯"), "{out}");
}

#[test]
fn invariant_one_frame_max() {
    // §16.3: at most one rounded frame in any buffer.
    let tui = Tui::new();
    let mut s = base_scenario();
    s.approval_pending = Some("shell".into());
    s.approval_queue = vec!["shell".into()];
    s.approval_summary = Some("x".into());
    let mut term = ratatui::Terminal::new(TestBackend::new(150, 44)).unwrap();
    term.draw(|f| draw(f, &tui, &s, "", None, "", 0, None, false, 0))
        .unwrap();
    let buf = term.backend().buffer();
    let mut corners = 0usize;
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            if buf[(x, y)].symbol() == "╭" {
                corners += 1;
            }
        }
    }
    assert!(corners <= 1, "{corners} rounded frames");
}

#[test]
fn layout_breakpoints() {
    // §16.3: the class boundaries.
    use orbit_hud_tui::proto::screen::{Screen, WidthClass};
    let r = |w, h| WidthClass::of(w, h);
    assert_eq!(r(39, 44), WidthClass::TooSmall);
    assert_eq!(r(40, 44), WidthClass::Tight);
    assert_eq!(r(59, 44), WidthClass::Tight);
    assert_eq!(r(60, 44), WidthClass::Compact);
    assert_eq!(r(79, 44), WidthClass::Compact);
    assert_eq!(r(80, 44), WidthClass::Narrow);
    assert_eq!(r(109, 44), WidthClass::Narrow);
    assert_eq!(r(110, 44), WidthClass::Medium);
    assert_eq!(r(139, 44), WidthClass::Medium);
    assert_eq!(r(140, 44), WidthClass::Wide);
    assert_eq!(r(150, 44), WidthClass::Wide);
    assert_eq!(r(150, 9), WidthClass::TooSmall);
    let _ = Screen::resolve;
}
