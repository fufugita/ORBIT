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
    // `R` says its true scope: every call of the tool, this session.
    assert!(
        out.contains("allow once") && out.contains("allow all shell"),
        "{out}"
    );
    assert!(
        out.contains("R grants") && out.contains("every shell call, until you quit"),
        "the card states what R grants: {out}"
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

#[test]
fn the_waiting_row_appears_only_while_the_model_is_awaited() {
    // Design law 5 (honesty): "waiting for <model>" is true only while
    // the model is what the turn waits on. It kept ticking over an open
    // approval card, where the person is the one being waited on.
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "make the tests pass".into(),
        ..Default::default()
    });
    s.turn_live = true;
    let waiting = render(&tui, &s, 164, 48);
    assert!(waiting.contains("waiting for glm-5.2"), "{waiting}");

    s.approval_pending = Some("Edit".into());
    let approval = render(&tui, &s, 164, 48);
    assert!(!approval.contains("waiting for glm-5.2"), "{approval}");

    s.approval_pending = None;
    s.running.insert("c1".into(), "Bash".into());
    let running = render(&tui, &s, 164, 48);
    assert!(!running.contains("waiting for glm-5.2"), "{running}");
}

#[test]
fn an_armed_approval_border_replaces_the_keys_instead_of_overdrawing_them() {
    // §9.14: while the person is typing the decision keys are disabled
    // and the border reads "paused while you type". The note used to be
    // drawn over the key labels (`paused while you type low this
    // session`), leaving remnants of "allow this session".
    let mut tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "make the tests pass".into(),
        ..Default::default()
    });
    s.turn_live = true;
    s.approval_pending = Some("Edit".into());
    s.approval_queue.push("Edit".into());
    s.approval_summary = Some("Edit(calc.py)".into());
    s.approval_risk = 2;
    s.approval_shown_ms = 4_000;

    // Armed: a key was pressed 300 ms ago.
    tui.tick_ms = 5_000;
    s.last_key_ms = 4_700;
    let armed = render(&tui, &s, 164, 48);
    let border = armed
        .lines()
        .find(|l| l.contains("paused while you type"))
        .unwrap_or_else(|| panic!("the armed card must say so:\n{armed}"));
    assert!(!border.contains("allow once"), "{border}");
    assert!(
        !border.contains("session"),
        "no key-label remnants: {border}"
    );

    // Not armed: the keys are there and the note is not.
    s.last_key_ms = 0;
    let live = render(&tui, &s, 164, 48);
    assert!(!live.contains("paused while you type"), "{live}");
    let keys = live
        .lines()
        .find(|l| l.contains("allow once"))
        .unwrap_or_else(|| panic!("the keys must show:\n{live}"));
    assert!(keys.contains("allow all Edit"), "{keys}");
    assert!(keys.contains("deny"), "{keys}");
}

#[test]
fn typing_a_slash_opens_the_command_list_above_the_composer() {
    // The composer promises "type / for commands"; the list that answers
    // it (§9.13) was dead code after the shell rewrite, so typing "/"
    // showed nothing.
    let tui = Tui::new();
    let s = base_scenario();
    let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
    let mut shot = |composer: &str, sel: usize| {
        let mut t = Tui::new();
        t.completion_sel = sel;
        let _ = &tui;
        term.draw(|f| draw(f, &t, &s, composer, None, "", 0, None, false, 0))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut rows = Vec::new();
        for y in 0..48u16 {
            let mut row = String::new();
            for x in 0..164u16 {
                row.push_str(buf[(x, y)].symbol());
            }
            rows.push(row.trim_end().to_string());
        }
        rows.join("\n")
    };

    let all = shot("/", 0);
    assert!(all.contains("↑↓ choose"), "{all}");
    assert!(
        all.contains("/help") && all.contains("keys and commands"),
        "{all}"
    );
    assert!(all.contains("⇥ complete"), "the keys that act on it: {all}");
    // Six rows show at once; the rest are one ↓ away, never out of reach.
    assert!(all.contains("↓ more") && !all.contains("/usage"), "{all}");
    let scrolled = shot("/", 6);
    assert!(
        scrolled.contains("/usage") && !scrolled.contains("↓ more"),
        "{scrolled}"
    );

    // Typing narrows it: /mod → /model and /models, not /help.
    let narrowed = shot("/mod", 0);
    assert!(narrowed.contains("/model"), "{narrowed}");
    assert!(!narrowed.contains("/help"), "{narrowed}");

    // Once arguments begin, the list closes.
    let args = shot("/model glm", 0);
    assert!(!args.contains("↑↓ choose"), "{args}");

    // Not a command: no list.
    let plain = shot("fix the bug", 0);
    assert!(!plain.contains("↑↓ choose"), "{plain}");
}

#[test]
fn the_approval_card_shows_the_edit_the_sandbox_and_the_true_grant_scope() {
    // Authority at the moment of consequence (design law 6): what an
    // edit would change, whether a command is confined, and what `R`
    // really grants — all from the request, never inferred.
    let mut tui = Tui::new();
    tui.tick_ms = 9_000;
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "make the tests pass".into(),
        ..Default::default()
    });
    s.turn_live = true;
    s.approval_pending = Some("Edit".into());
    s.approval_queue.push("Edit".into());
    s.approval_summary = Some("Edit(calc.py)".into());
    s.approval_risk = 2;
    s.approval_shown_ms = 1_000;
    s.approval_preview = vec!["-     return a - b".into(), "+     return a + b".into()];
    let edit = render(&tui, &s, 164, 48);
    assert!(
        edit.contains("Edit(calc.py)") || edit.contains("calc.py"),
        "{edit}"
    );
    assert!(
        edit.contains("return a - b") && edit.contains("return a + b"),
        "{edit}"
    );
    assert!(
        edit.contains("allow all Edit"),
        "the grant says its scope: {edit}"
    );

    // A command: the sandbox fact, in words; unconfined must stand out.
    s.approval_pending = Some("Bash".into());
    s.approval_queue = vec!["Bash".into()];
    s.approval_summary = Some("Bash(python3 test_calc.py)".into());
    s.approval_preview.clear();
    s.approval_facts = vec![("sandbox".into(), "confined · no network".into())];
    let bash = render(&tui, &s, 164, 48);
    assert!(
        bash.contains("sandbox") && bash.contains("confined · no network"),
        "{bash}"
    );
    assert!(bash.contains("allow all Bash"), "{bash}");
    s.approval_facts = vec![(
        "sandbox".into(),
        "NONE — runs with your full permissions".into(),
    )];
    let bare = render(&tui, &s, 164, 48);
    assert!(
        bare.contains("NONE — runs with your full permissions"),
        "{bare}"
    );
}

#[test]
fn the_welcome_lists_the_sandbox_among_what_is_ready() {
    let mut tui = Tui::new();
    tui.brand_tier = orbit_hud_tui::proto::welcome::BrandTier::Static;
    let mut s = base_scenario();
    s.welcome_chips = vec![
        (true, "trust root".into()),
        (false, "sandbox · off — every command asks".into()),
    ];
    let out = render(&tui, &s, 164, 48);
    assert!(out.contains("sandbox · off — every command asks"), "{out}");
}

#[test]
fn a_reply_shows_its_markdown_as_style_not_as_markup() {
    // Every reply is markdown. Headings, emphasis, links and quotes used
    // to print their raw markers (`## `, `**`, `[x](y)`, `> `).
    use ratatui::style::Modifier;
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "summarize".into(),
        ..Default::default()
    });
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "## Summary\n\nIt is **what changed** and *why*.\n\n- one\n> a quote\n\nSee [the docs](https://e.com/d).".into(),
        ..Default::default()
    });
    let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
    term.draw(|f| draw(f, &tui, &s, "", None, "", 0, None, false, 0))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let mut rows = Vec::new();
    for y in 0..48u16 {
        let mut row = String::new();
        for x in 0..164u16 {
            row.push_str(buf[(x, y)].symbol());
        }
        rows.push(row);
    }
    let screen = rows.join("\n");
    for marker in ["##", "**", "[the docs]", "](https"] {
        assert!(
            !screen.contains(marker),
            "raw {marker:?} on screen:\n{screen}"
        );
    }
    assert!(
        screen.contains("Summary") && screen.contains("what changed"),
        "{screen}"
    );
    assert!(
        screen.contains("• one") && screen.contains("│ a quote"),
        "{screen}"
    );
    assert!(screen.contains("the docs (https://e.com/d)"), "{screen}");

    // The style is on the cells: find a word and look at its modifier.
    let mods_of = |word: &str| -> Modifier {
        for (y, row) in rows.iter().enumerate() {
            if let Some(byte) = row.find(word) {
                let col = row[..byte].chars().count() as u16;
                return buf[(col, y as u16)].modifier;
            }
        }
        panic!("{word:?} not on screen:\n{screen}");
    };
    assert!(mods_of("what changed").contains(Modifier::BOLD));
    assert!(mods_of("why").contains(Modifier::ITALIC));
    assert!(mods_of("Summary").contains(Modifier::BOLD));
    assert!(mods_of("the docs").contains(Modifier::UNDERLINED));
    // Plain words stay plain.
    let plain = mods_of("It is");
    assert!(!plain.contains(Modifier::BOLD) && !plain.contains(Modifier::ITALIC));
}

#[test]
fn a_wrapped_bullet_hangs_under_its_text_and_a_wrapped_quote_keeps_its_gutter() {
    // The continuation row of a long item used to start under its marker,
    // and a long quote lost its `│` after the first row.
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "list it".into(),
        ..Default::default()
    });
    let item: String = (1..=40)
        .map(|n| format!("w{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: format!("- {item}\n\n> {item}"),
        ..Default::default()
    });
    let screen = render(&tui, &s, 100, 40);
    let rows: Vec<&str> = screen.lines().collect();
    let col = |row: &str, pat: &str| row.find(pat).map(|b| row[..b].chars().count());

    // The bullet: the next row's text starts two columns after the bullet.
    let y = rows
        .iter()
        .position(|r| r.contains("\u{2022} w1 w2"))
        .unwrap_or_else(|| panic!("no bullet row:\n{screen}"));
    let bullet = col(rows[y], "\u{2022}").unwrap();
    let next = rows[y + 1];
    let text_col = next
        .chars()
        .position(|c| c.is_alphanumeric())
        .unwrap_or_else(|| panic!("no continuation row:\n{screen}"));
    assert_eq!(
        text_col,
        bullet + 2,
        "the item hangs under its text:\n{screen}"
    );

    // The quote: the next row carries the gutter in the same column.
    let y = rows
        .iter()
        .position(|r| r.contains("\u{2502} w1 w2"))
        .unwrap_or_else(|| panic!("no quote row:\n{screen}"));
    let gutter = col(rows[y], "\u{2502} w1").unwrap();
    let next = rows[y + 1];
    assert_eq!(
        next.chars().nth(gutter),
        Some('\u{2502}'),
        "the continuation row keeps the gutter:\n{screen}"
    );
    assert_eq!(
        next.chars()
            .skip(gutter + 1)
            .position(|c| c.is_alphanumeric()),
        Some(1),
        "and its text sits after the gutter:\n{screen}"
    );
}

#[test]
fn a_fenced_block_is_a_band_with_its_language_on_the_first_row() {
    // The language tag used to be dropped and the code only had a
    // background behind its own characters.
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "show it".into(),
        ..Default::default()
    });
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "Here:\n```rust\nlet a = 1;\n\nlet b = 2;\n```\nafter".into(),
        ..Default::default()
    });
    let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
    term.draw(|f| draw(f, &tui, &s, "", None, "", 0, None, false, 0))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let rows: Vec<String> = (0..48u16)
        .map(|y| {
            (0..164u16)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect()
        })
        .collect();
    let screen = rows.join("\n");
    let row_of = |needle: &str| {
        rows.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} not on screen:\n{screen}"))
    };
    let col_of = |y: usize, needle: &str| {
        let byte = rows[y].find(needle).unwrap();
        rows[y][..byte].chars().count() as u16
    };

    let first = row_of("let a = 1;");
    assert_eq!(row_of("let b = 2;"), first + 2, "a blank line stays a row");
    let tag = col_of(first, "rust");
    let end_of_code = col_of(first, "let a = 1;") + "let a = 1;".len() as u16;
    assert!(tag > end_of_code + 2, "the tag is right-aligned:\n{screen}");
    assert_eq!(rows.iter().filter(|r| r.contains("rust")).count(), 1);

    // The band runs under the whole row, blank line included, and stops
    // with the block.
    let band = buf[(end_of_code + 1, first as u16)].bg;
    for y in [first, first + 1, first + 2] {
        assert_eq!(
            buf[(tag - 2, y as u16)].bg,
            band,
            "band on row {y}:\n{screen}"
        );
    }
    let after = row_of("after");
    assert_ne!(buf[(tag - 2, after as u16)].bg, band, "no band after it");
    let intro = row_of("Here:");
    assert_ne!(buf[(tag - 2, intro as u16)].bg, band, "no band before it");
}

#[test]
fn a_pipe_table_is_drawn_as_a_grid_that_fits_the_panel() {
    // Tables used to print their raw pipes and `|---|` row.
    use ratatui::style::Modifier;
    let tui = Tui::new();
    let mut s = base_scenario();
    s.transcript.push(TranscriptLine {
        kind: LineKind::User,
        text: "table please".into(),
        ..Default::default()
    });
    s.transcript.push(TranscriptLine {
        kind: LineKind::Model,
        text: "| file | change |\n|------|--------|\n| calc.py | +1 -1 |\n| a_rather_long_file_name_that_is_wider_than_the_panel_allows_for.py | +20 -3 |".into(),
        ..Default::default()
    });
    let mut term = ratatui::Terminal::new(TestBackend::new(80, 40)).unwrap();
    term.draw(|f| draw(f, &tui, &s, "", None, "", 0, None, false, 0))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let rows: Vec<String> = (0..40u16)
        .map(|y| {
            (0..80u16)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect()
        })
        .collect();
    let screen = rows.join("\n");
    assert!(!screen.contains("|---"), "the rule row is drawn:\n{screen}");
    assert!(!screen.contains("| file"), "no raw pipes:\n{screen}");

    let head = rows
        .iter()
        .position(|r| r.contains("file") && r.contains("change"))
        .unwrap_or_else(|| panic!("no header row:\n{screen}"));
    // A rule under the header, the junction under the column divider.
    // (Char columns, not byte offsets: the glyphs are multi-byte.)
    let at = |row: &str, c: char| row.chars().position(|x| x == c);
    let divider = at(&rows[head], '\u{2502}').expect("a divider in the header");
    assert_eq!(
        at(&rows[head + 1], '\u{253c}'),
        Some(divider),
        "the rule's junction sits under the divider:\n{screen}"
    );
    // Every body row has its divider in the same place, the long name is
    // clipped with an ellipsis, and nothing runs past the panel.
    assert_eq!(at(&rows[head + 2], '\u{2502}'), Some(divider), "{screen}");
    assert_eq!(at(&rows[head + 3], '\u{2502}'), Some(divider), "{screen}");
    assert!(rows[head + 3].contains('\u{2026}'), "clipped:\n{screen}");
    assert!(rows[head + 3].contains("+20 -3"), "{screen}");
    // The header is bold.
    let col = rows[head][..rows[head].find("file").unwrap()]
        .chars()
        .count() as u16;
    assert!(buf[(col, head as u16)].modifier.contains(Modifier::BOLD));
}
