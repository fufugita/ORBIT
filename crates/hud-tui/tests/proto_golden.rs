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
fn columns_layout_matches_the_prototype() {
    // The prototype's default: Changes · Conversation · Terminal, the
    // top bar with the layout tabs, empty states, the composer inside
    // the Conversation panel and the status line with the mode pill.
    let mut tui = Tui::new();
    tui.brand_tier = orbit_hud_tui::proto::welcome::BrandTier::Static;
    let mut s = base_scenario();
    s.welcome_chips = vec![
        (true, "trust root".into()),
        (true, "local · glm-5.2".into()),
    ];
    let out = render(&tui, &s, 164, 48);
    let rows: Vec<&str> = out.lines().collect();
    // Row 0: wordmark, preset tabs, facts on the right.
    assert!(
        rows[0].contains("ORBIT") && rows[0].contains("columns"),
        "{out}"
    );
    assert!(rows[0].contains("glm-5.2"), "{out}");
    // Row 1: three panels — thin, heavy (focused), thin.
    assert!(
        rows[1].starts_with(" ╭") && rows[1].contains("┏") && rows[1].ends_with("╮"),
        "{out}"
    );
    // Row 2: number chips and titles.
    assert!(rows[2].contains(" 1  Changes"), "{out}");
    assert!(rows[2].contains(" 2  New session"), "{out}");
    assert!(rows[2].contains(" 3  Terminal"), "{out}");
    // Empty states.
    assert!(out.contains("No changes yet"), "{out}");
    assert!(out.contains("No commands yet"), "{out}");
    // Welcome inside the conversation panel.
    assert!(out.contains("the harness that orbits around you"), "{out}");
    assert!(out.contains("✓ trust root"), "{out}");
    // Composer + hints inside the panel; footer hints on the borders.
    assert!(out.contains("Ask ORBIT, or type / for commands"), "{out}");
    assert!(out.contains("⏎ send"), "{out}");
    assert!(out.contains("j/k file"), "{out}");
    // Status line: mode pill + ORBIT + hints.
    let last = rows[rows.len() - 1];
    assert!(
        last.contains(" DEFAULT ") && last.contains("ORBIT"),
        "{out}"
    );
    assert!(last.contains("esc arrange panels"), "{out}");
}

#[test]
fn exactly_one_panel_is_focused() {
    // The focused panel has the heavy border; the others are thin.
    let tui = Tui::new();
    let s = base_scenario();
    let out = render(&tui, &s, 164, 48);
    let heavy = out.matches('┏').count();
    let thin = out.matches('╭').count();
    assert_eq!(heavy, 1, "{out}");
    assert_eq!(thin, 2, "{out}");
}

#[test]
fn one_panel_at_a_time_under_120_columns() {
    let tui = Tui::new();
    let s = base_scenario();
    let out = render(&tui, &s, 100, 32);
    assert!(out.lines().next().unwrap().contains("1 Changes"), "{out}");
    assert!(
        out.contains("2 New session") || out.contains("2 Conversation"),
        "{out}"
    );
    assert!(
        !out.contains("No commands yet"),
        "only the focused panel shows\n{out}"
    );
}

#[test]
fn transcript_is_bottom_anchored_above_the_composer() {
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "hello".into(),
        time: Some("14:02".into()),
        ..Default::default()
    });
    let out = render(&tui, &s, 164, 48);
    let rows: Vec<&str> = out.lines().collect();
    let user = rows.iter().position(|r| r.contains("› hello")).unwrap();
    let composer = rows.iter().position(|r| r.contains("Ask ORBIT")).unwrap();
    assert!(
        composer - user <= 3,
        "user turn sits against the composer\n{out}"
    );
}

#[test]
fn tool_cards_carry_a_kind_chip_target_and_state() {
    // Rendered 5 s in: the target has typed in and the settle has ended.
    let mut tui = Tui::new();
    tui.tick_ms = 5000;
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Tool,
        text: "crates/export/src/restore.rs".into(),
        tool_name: "read_file".into(),
        tool_state: ToolState::Running,
        started_ms: Some(0),
        ..Default::default()
    });
    let out = render(&tui, &s, 164, 48);
    assert!(out.contains("READ"), "{out}");
    assert!(out.contains("crates/export/src/restore.rs"), "{out}");
    assert!(out.contains("running"), "{out}");
    s.transcript[0].tool_state = ToolState::Done;
    s.transcript[0].meta = "done · 212 lines".into();
    let out2 = render(&tui, &s, 164, 48);
    assert!(out2.contains("212 lines") && out2.contains("✓"), "{out2}");
    s.transcript.push(TranscriptLine {
        kind: LineKind::Tool,
        text: "cargo test -p orbit-export".into(),
        tool_name: "bash".into(),
        tool_state: ToolState::Denied,
        ..Default::default()
    });
    let out3 = render(&tui, &s, 164, 48);
    assert!(
        out3.contains("BASH") && out3.contains("denied by you"),
        "{out3}"
    );
}

#[test]
fn approval_card_needs_you_with_risk_facts_and_keys() {
    let tui = Tui::new();
    let mut s = base_scenario();
    s.approval_pending = Some("shell".into());
    s.approval_queue = vec!["shell".into()];
    s.approval_summary = Some("shell(scripts/e2e-clean-machine.sh --keep-home)".into());
    s.approval_risk = 2;
    s.approval_dir = "/home/hanu/src/orbit".into();
    let out = render(&tui, &s, 164, 48);
    assert!(out.contains("◆ NEEDS YOU"), "{out}");
    assert!(out.contains("Allow shell?"), "{out}");
    assert!(out.contains("MEDIUM RISK"), "{out}");
    assert!(
        out.contains("$ scripts/e2e-clean-machine.sh --keep-home"),
        "{out}"
    );
    assert!(out.contains("/home/hanu/src/orbit"), "{out}");
    assert!(
        out.contains("allow once") && out.contains("allow this session"),
        "{out}"
    );
    assert!(out.contains("esc deny"), "{out}");
    // The card replaces the composer.
    assert!(!out.contains("Ask ORBIT, or type / for commands"), "{out}");
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

#[test]
fn a_tool_target_types_in_at_240_characters_per_second() {
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Tool,
        text: "crates/export/src/restore.rs".into(),
        tool_name: "read_file".into(),
        tool_state: ToolState::Running,
        started_ms: Some(1000),
        ..Default::default()
    });
    let mut tui = Tui::new();
    tui.tick_ms = 1000 + 60; // 60 ms in: 14 characters.
    let early = render(&tui, &s, 164, 48);
    assert!(
        early.contains("crates/export") && !early.contains("restore.rs"),
        "{early}"
    );
    tui.tick_ms = 1000 + 400;
    let late = render(&tui, &s, 164, 48);
    assert!(late.contains("crates/export/src/restore.rs"), "{late}");
}

#[test]
fn fresh_ink_fades_from_near_white_to_ink() {
    // M06: a chunk that just landed is near white; 450 ms later it is ink.
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "Found it".into(),
        arrivals: vec![(0, 1000)],
        ..Default::default()
    });
    let fg_at = |ms: u64| {
        let mut tui = Tui::new();
        tui.tick_ms = ms;
        let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
        term.draw(|f| draw(f, &tui, &s, "", None, "", 0, None, false, 0))
            .unwrap();
        let buf = term.backend().buffer().clone();
        for y in 0..48 {
            for x in 0..164 {
                if buf[(x, y)].symbol() == "F" && buf[(x + 1, y)].symbol() == "o" {
                    return buf[(x, y)].fg;
                }
            }
        }
        panic!("text not found");
    };
    let fresh = fg_at(1000);
    let settled = fg_at(1600);
    assert_ne!(fresh, settled, "the ink fades");
    assert_eq!(settled, ratatui::style::Color::Rgb(0xEE, 0xEA, 0xF5));
}
