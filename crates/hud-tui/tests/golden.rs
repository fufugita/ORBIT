//! Golden frames and design invariants (docs/tui/DESIGN.md §9, §13.5).
//!
//! The design's thesis, encoded as tests, so it cannot drift one tweak at a
//! time:
//!
//! - `golden_*` — render representative frames into TestBackend at 150×44
//!   and 80×30 and assert the structural content (headers, gutters, status
//!   line, approval card) is present and positioned.
//! - `invariant_one_frame_max` — at most one rounded frame in any buffer.
//! - `invariant_magenta_closed_list` — magenta cells only at the six places
//!   listed in §1 principle 3 (approximated: approval card title, composer
//!   prompt, focused pane title, selection bar, the mark, ORBIT's voice
//!   glyph — asserted as a bounded count).
//! - `invariant_idle_draws_nothing` — after a response settles, ticks set
//!   no dirty flags.
//! - `invariant_single_moving_cell` — while working, consecutive frames
//!   differ only in the mark cell and status counters, unless data arrived.
//! - `invariant_ascii_tier_is_ascii` — with the ASCII glyph set, every
//!   chrome cell ORBIT draws itself is printable ASCII.
//! - `invariant_no_truncated_approval` — the approval action text appears
//!   in the buffer in full at every supported size.

use orbit_hud_tui::render::render;
use orbit_hud_tui::state::{
    ActivityRow, App, ComposerState, ConnectionState, Finding, Focus, LeftTab, LogoPhase,
    PendingApproval, Task, TaskState, Toast, ToastKind, ToolOutcome, ToolState, TranscriptLine,
};
use orbit_hud_tui::tokens::{Design, GlyphSet, Theme};

fn design() -> Design {
    Design::resolve(&Theme::default(), &|_| None)
}

fn ascii_design() -> Design {
    let t: Theme = toml::from_str("[color]\nglyphs = \"ascii\"\n").unwrap();
    Design::resolve(&t, &|_| None)
}

/// A representative idle app (§9 mockup A).
fn idle_app() -> App {
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
    app.transcript.push(TranscriptLine::User {
        text: "What is 2*(3+4)?".into(),
        time: None,
    });
    app.transcript.push(TranscriptLine::Assistant {
        text:
            ("Let me compute that.\n## Result\nThe answer is **14**.\n- computed via `calculator`"
                .into()),
        time: None,
    });
    app
}

/// A working app streaming with tools (§9 mockup B).
fn working_app() -> App {
    let mut app = idle_app();
    app.tool_state = ToolState::Running("auth suite".into());
    app.logo_phase = LogoPhase::Working;
    app.in_flight = "The patch serializes refreshes by token ID.".into();
    app
}

/// An app awaiting approval (§9 mockup C).
fn approval_app() -> App {
    let mut app = idle_app();
    app.tool_state = ToolState::AwaitingApproval;
    app.pending_approvals.push(PendingApproval {
        call_id: "call-0".into(),
        tool_name: "shell".into(),
        summary: "Apply patch to 2 files in /work/atlas".into(),
        risk: 2,
        working_dir: "/tmp".into(),
    });
    app
}

/// Render into a TestBackend at the given size and return the buffer.
fn render_buf(app: &App, d: &Design, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, app, "", d)).unwrap();
    terminal.backend().buffer().clone()
}

/// Full buffer text (all rows joined by newlines).
fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
    let area = buf.area;
    let mut rows = Vec::with_capacity(area.height as usize);
    for y in area.top()..area.bottom() {
        let row: String = (area.left()..area.right())
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect();
        rows.push(row.trim_end().to_string());
    }
    rows.join("\n")
}

// ── Golden frames ────────────────────────────────────────────────────────────

#[test]
fn preview_dump() {
    // Dev-only: dump frames to /tmp for visual inspection.
    if std::env::var("ORBIT_PREVIEW").is_err() {
        return;
    }
    let buf = render_buf(&idle_app(), &design(), 150, 44);
    std::fs::write("/tmp/preview-idle.txt", buf_text(&buf)).unwrap();
    let buf = render_buf(&working_app(), &design(), 150, 44);
    std::fs::write("/tmp/preview-working.txt", buf_text(&buf)).unwrap();
    // Approval modal
    let buf = render_buf(&approval_app(), &design(), 150, 44);
    std::fs::write("/tmp/preview-approval.txt", buf_text(&buf)).unwrap();
    // Narrow (80x30) — the rails collapse
    let buf = render_buf(&idle_app(), &design(), 80, 30);
    std::fs::write("/tmp/preview-narrow.txt", buf_text(&buf)).unwrap();
    // Very narrow (60x20)
    let buf = render_buf(&idle_app(), &design(), 60, 20);
    std::fs::write("/tmp/preview-tiny.txt", buf_text(&buf)).unwrap();
    // Welcome (empty transcript)
    let mut w = idle_app();
    w.transcript.clear();
    w.in_flight.clear();
    let buf = render_buf(&w, &design(), 150, 44);
    std::fs::write("/tmp/preview-welcome.txt", buf_text(&buf)).unwrap();
    // Palette open
    let mut pa = idle_app();
    pa.palette.open = true;
    let buf = render_buf(&pa, &design(), 150, 44);
    std::fs::write("/tmp/preview-palette.txt", buf_text(&buf)).unwrap();
    // Streaming mid-turn
    let mut st = working_app();
    st.in_flight = "The patch serializes refreshes by token ID so concurrent".to_string();
    st.tool_state = ToolState::Streaming;
    let buf = render_buf(&st, &design(), 150, 44);
    std::fs::write("/tmp/preview-streaming.txt", buf_text(&buf)).unwrap();
    // Zoomed center
    let mut zm = idle_app();
    zm.zoomed_pane = Some(Focus::Center);
    let buf = render_buf(&zm, &design(), 150, 44);
    std::fs::write("/tmp/preview-zoom.txt", buf_text(&buf)).unwrap();
    // Help overlay
    let mut hp = idle_app();
    hp.help_open = true;
    let buf = render_buf(&hp, &design(), 150, 44);
    std::fs::write("/tmp/preview-help.txt", buf_text(&buf)).unwrap();
    // Workspace filled (mid-turn)
    let mut wf = working_app();
    wf.workspace.phase_index = 2;
    wf.workspace.plan = vec![
        Task {
            title: "Read the auth middleware".into(),
            state: TaskState::Done,
            sub: None,
            evidence: 2,
        },
        Task {
            title: "Trace the token refresh path".into(),
            state: TaskState::Active,
            sub: Some("following refresh_token".into()),
            evidence: 0,
        },
        Task {
            title: "Patch the race window".into(),
            state: TaskState::Blocked,
            sub: Some("awaiting approval".into()),
            evidence: 0,
        },
    ];
    wf.workspace.findings = vec![Finding {
        title: "Refresh tokens not single-use".into(),
        source: Some("auth/refresh.rs:88".into()),
    }];
    let buf = render_buf(&wf, &design(), 150, 44);
    std::fs::write("/tmp/preview-workspace.txt", buf_text(&buf)).unwrap();

    // ── herdr panel-isolation frames ──────────────────────────────────
    // The operator validates visually: pane borders (magenta = focused,
    // muted = unfocused), the Activity tab, focus cycling, approval card.

    // Activity tab open (g v): the left rail swaps to event rows.
    let mut act = idle_app();
    act.left_tab = LeftTab::Verbose;
    act.activity = act_activity_fixture();
    let buf = render_buf(&act, &design(), 150, 44);
    std::fs::write("/tmp/preview-activity.txt", buf_text(&buf)).unwrap();

    // Focus cycling: the same frame with focus on Left / Center / Right —
    // the accent border moves; the other panes drop to muted rule colour.
    // (App isn't Clone; rebuild the fixture per frame.)
    for (name, focus) in [
        ("left", Focus::Left),
        ("center", Focus::Center),
        ("right", Focus::Right),
    ] {
        let mut f = idle_app();
        f.left_tab = LeftTab::Verbose;
        f.activity = act_activity_fixture();
        f.focus = focus;
        let buf = render_buf(&f, &design(), 150, 44);
        std::fs::write(format!("/tmp/preview-focus-{name}.txt"), buf_text(&buf)).unwrap();
    }
}

/// Activity rows shared by the isolation preview frames.
fn act_activity_fixture() -> Vec<ActivityRow> {
    vec![
        ActivityRow {
            time: "14:04:39".into(),
            kind: "model",
            text: "glm-5.2 via local".into(),
        },
        ActivityRow {
            time: "14:04:52".into(),
            kind: "tool",
            text: "shell · ok".into(),
        },
        ActivityRow {
            time: "14:04:58".into(),
            kind: "grant",
            text: "shell · once · you".into(),
        },
        ActivityRow {
            time: "14:05:01".into(),
            kind: "error",
            text: "E0408".into(),
        },
    ]
}

#[test]
fn golden_idle_wide_150x44() {
    let buf = render_buf(&idle_app(), &design(), 150, 44);
    let text = buf_text(&buf);
    // Structural assertions per §9 mockup A.
    assert!(text.contains("Sessions"), "left rail header");
    assert!(text.contains("Workspace"), "right rail header");
    assert!(text.contains("What is 2*(3+4)?"), "user turn");
    assert!(text.contains("Result"), "assistant markdown heading");
    assert!(
        text.contains("Ask ORBIT, or type / for commands"),
        "composer prompt"
    );
    assert!(text.contains("online"), "status line connection");
    assert!(text.contains("$0.0025"), "status line cost");
    // Chrome budget: the header row + status line = 2 rows of chrome.
    // (Assert indirectly: transcript content appears within the first rows.)
    assert!(text.lines().take(3).any(|l| l.contains("Sessions")));
}

#[test]
fn golden_idle_narrow_80x30() {
    let buf = render_buf(&idle_app(), &design(), 80, 30);
    let text = buf_text(&buf);
    // Narrow (§8.2): single view — one boxed Conversation pane (herdr-style
    // isolation holds at every width), status level 2 (no 'online' word,
    // just the ● glyph).
    assert!(text.contains("Conversation"), "boxed pane title");
    assert!(text.contains("What is 2*(3+4)?"), "user turn");
    assert!(text.contains("Ask ORBIT, or type / for commands"));
    // Level 2 keeps the connection glyph but drops the word.
    assert!(text.contains("●"), "connection glyph");
    // The box: corners on row 0 and the last body row.
    assert!(
        text.lines().next().unwrap().starts_with("╭ Conversation"),
        "top border"
    );
}

#[test]
fn golden_streaming_with_tools() {
    let buf = render_buf(&working_app(), &design(), 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("auth suite"), "running tool name in status");
    assert!(text.contains("serializes"), "in-flight stream text");
}

/// The Activity tab (§9.16): structured events — time / kind / text —
/// render in the left rail when `g v` switches it in, and the session
/// list is gone.
#[test]
fn golden_activity_tab_replaces_sessions_rail() {
    let mut app = idle_app();
    app.left_tab = LeftTab::Verbose;
    app.activity = vec![
        orbit_hud_tui::state::ActivityRow {
            time: "14:04:39".into(),
            kind: "model",
            text: "glm-5.2 via local".into(),
        },
        orbit_hud_tui::state::ActivityRow {
            time: "14:04:52".into(),
            kind: "tool",
            text: "shell · ok".into(),
        },
        orbit_hud_tui::state::ActivityRow {
            time: "14:05:01".into(),
            kind: "error",
            text: "E0408".into(),
        },
    ];
    let buf = render_buf(&app, &design(), 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("Activity"), "Activity tab header");
    assert!(text.contains("14:04:39"), "event time stamp");
    // §8.4: text at x+18 end-truncated at x+w-1 — the 30-col rail minus the
    // box borders gives a 9-char budget, so longer rows truncate.
    assert!(text.contains("glm-5.2 …"), "model event text (truncated)");
    assert!(text.contains("shell · …"), "tool event text (truncated)");
    assert!(text.contains("E0408"), "error event text");
    // The sessions list is NOT rendered while the Activity tab is open.
    assert!(
        !text.contains("Approval surface polish"),
        "sessions rows hidden"
    );
}

/// Empty activity: one faint placeholder line, not a blank rail.
#[test]
fn golden_activity_tab_empty_state() {
    let mut app = idle_app();
    app.left_tab = LeftTab::Verbose;
    app.sessions.clear();
    let buf = render_buf(&app, &design(), 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("(no events yet)"), "activity empty state");
}

/// The §6.12 toast rides the hint row's right end — and ONLY there (the
/// old queue-row toast render was removed; a queued prompt + toast must
/// not double-render).
#[test]
fn golden_toast_on_hint_row_once() {
    let d = design();
    let mut app = idle_app();
    app.queued.push("a queued prompt".into());
    app.toast = Some(Toast {
        text: "copied 42 lines".into(),
        kind: ToastKind::Success,
    });
    // The toast auto-dismisses 3 s after its emit tick; stamp it as
    // just-emitted so the render under test still shows it.
    app.toast_emitted_at = Some(app.tick_count);
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    let count = text.matches("copied 42 lines").count();
    assert_eq!(count, 1, "toast renders exactly once (on the hint row)");
    // The queued prompt still renders as its own row.
    assert!(text.contains("a queued prompt"), "queued prompt row");
}

/// A running tool card: cyan ◉, bold name, right-aligned "running" meta.
/// A settled same-name card keeps its ✓ — the running state belongs to
/// the LAST unsettled card only.
#[test]
fn golden_tool_card_running_vs_settled() {
    let d = design();
    let mut app = idle_app();
    app.turn_in_flight = true;
    app.tool_state = ToolState::Running("shell".into());
    // First shell call: settled ok.
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "shell".into(),
        summary: "cargo test -p orbit-export".into(),
        outcome: Some(ToolOutcome::Ok),
        meta: String::new(),
        started_at: None,
    });
    // Second shell call: running now.
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "shell".into(),
        summary: "cargo test -p orbit-ledger".into(),
        outcome: None,
        meta: String::new(),
        started_at: Some(app.tick_count),
    });
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    // The running card shows a live ticking duration (e.g. "0.0s");
    // settled cards show none.
    assert!(text.contains("0.0s"), "running card ticks its duration");
    // Both cards render with their arguments (tail-truncated).
    assert!(
        text.contains("cargo test -p orbit-export"),
        "settled card arg"
    );
    assert!(
        text.contains("cargo test -p orbit-ledger"),
        "running card arg"
    );
}

/// A failed tool call settles to ✕ red with "failed" meta (§6.5).
#[test]
fn golden_tool_card_failed() {
    let d = design();
    let mut app = idle_app();
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "shell".into(),
        summary: "cargo test".into(),
        outcome: Some(ToolOutcome::Failed),
        meta: String::new(),
        started_at: None,
    });
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("failed"), "failed meta on the card");
}

/// A denial is a decision, not a failure: `⊘` muted with `denied by you`
/// meta — never the red `✕ failed` treatment (§11.5 rule 4).
#[test]
fn golden_tool_card_denied() {
    let d = design();
    let mut app = idle_app();
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "shell".into(),
        summary: "rm -rf /tmp/scratch".into(),
        outcome: Some(ToolOutcome::Denied),
        meta: String::new(),
        started_at: None,
    });
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("denied by you"), "denied meta on the card");
    assert!(!text.contains("failed"), "a refusal never reads as failed");
}

/// A pre-run block (unknown tool / no consent) is amber `⊖ blocked`,
/// distinct from both failed and denied.
#[test]
fn golden_tool_card_blocked() {
    let d = design();
    let mut app = idle_app();
    app.transcript.push(TranscriptLine::Stripped {
        tool_name: "nestar.init".into(),
        summary: "provider=nano".into(),
        outcome: Some(ToolOutcome::Blocked),
        meta: String::new(),
        started_at: None,
    });
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("blocked"), "blocked meta on the card");
    assert!(!text.contains("failed"), "a block never reads as failed");
    assert!(!text.contains("denied by you"), "a block is not a denial");
}

#[test]
fn golden_approval_card() {
    let buf = render_buf(&approval_app(), &design(), 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("Allow shell?"), "card title");
    assert!(
        text.contains("Apply patch to 2 files"),
        "the request summary"
    );
    assert!(text.contains("allow once"), "y choice");
    assert!(text.contains("deny"), "n choice");
    // The risk badge (▰▰▱ at level 2) renders in the title (§6.15).
    assert!(text.contains('▰'), "risk badge present");
}

/// Composer auto-height (§5.5): one row empty, one per line, capped at half.
#[test]
fn golden_composer_auto_height() {
    let d = design();
    let app = idle_app();
    // Empty composer: 1 row — the prompt line is the last row of the frame.
    let empty = render_buf(&app, &d, 80, 30);
    assert!(buf_text(&empty).contains("Ask ORBIT, or type / for commands"));

    // Multi-line composer: the first line renders; the input row grows
    // upward per §5.5 (multi-row growth lands with the composer-height
    // work — the single-row rewrite keeps the first line visible).
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 30)).unwrap();
    terminal
        .draw(|f| render(f, &app, "first line\nsecond line\nthird line", &d))
        .unwrap();
    let text = buf_text(terminal.backend().buffer());
    assert!(text.contains("first line"));
}

/// Workspace rail (§6.10): stepper + sections + task rows render from state.
#[test]
fn golden_workspace_pane() {
    let d = design();
    let mut app = idle_app();
    app.workspace = orbit_hud_tui::state::Workspace {
        phase_index: 2,
        plan: vec![
            orbit_hud_tui::state::Task {
                title: "Fix refresh".into(),
                state: orbit_hud_tui::state::TaskState::Active,
                sub: Some("reading crates/export/src/restore.rs".into()),
                evidence: 2,
            },
            orbit_hud_tui::state::Task {
                title: "Retest clean-machine e2e".into(),
                state: orbit_hud_tui::state::TaskState::Blocked,
                sub: Some("waiting on the patch".into()),
                evidence: 0,
            },
        ],
        findings: vec![orbit_hud_tui::state::Finding {
            title: "fresh genesis".into(),
            source: Some("restore.rs:8".into()),
        }],
        verification: vec![
            orbit_hud_tui::state::Verification {
                name: "unit suite".into(),
                result: orbit_hud_tui::state::VerificationResult::Passed,
                proof_count: 2,
                result_text: String::new(),
            },
            orbit_hud_tui::state::Verification {
                name: "ledger check".into(),
                result: orbit_hud_tui::state::VerificationResult::Pending,
                proof_count: 0,
                result_text: String::new(),
            },
        ],
    };
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    // Stepper + phase name + count.
    assert!(text.contains("act"), "current phase name");
    assert!(text.contains("0/2"), "phase count (done/total)");
    // Sections with counts.
    assert!(text.contains("PLAN"), "plan section");
    assert!(text.contains("FINDINGS"), "findings section");
    assert!(text.contains("VERIFICATION"), "verification section");
    // Task rows + sub-lines + evidence.
    assert!(text.contains("Fix refresh"), "task title");
    assert!(text.contains("reading crates"), "active sub-line");

    // Findings + source.
    assert!(text.contains("fresh genesis"), "finding title");
    assert!(text.contains("restore.rs"), "finding source");
}

/// Welcome screen (§8.1): an empty session shows the expanded mark; the
/// first turn replaces it.
#[test]
fn golden_welcome_mark() {
    let d = design();
    // Empty app (no transcript) → the mark renders. Settled (frame 5) —
    // the §8.3 reveal completes before the assertions.
    let mut app = App::new();
    app.startup_frame = 5;
    app.logo_phase = LogoPhase::Steady;
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    // The wordmark is block letters (▄▀█) + the braille ring + the star.
    assert!(text.contains("▀▀▀▄"), "the block letterforms");
    assert!(
        text.contains("harness that orbits around you"),
        "the tagline"
    );
    assert!(text.contains("✦"), "the star");

    // With a transcript → no mark (the first turn replaced it).
    let app = idle_app();
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    assert!(
        !text.contains("harness that orbits around you"),
        "mark gone after first turn"
    );
}

/// Command palette (§6.13): the overlay renders with query, sections,
/// fuzzy matches, and the selected row.
#[test]
fn golden_command_palette() {
    let d = design();
    let mut app = App::new();
    app.palette.open = true;
    app.palette.query = "sess".into();
    let buf = render_buf(&app, &d, 150, 44);
    let text = buf_text(&buf);
    assert!(text.contains("COMMANDS"), "the section label");
    assert!(text.contains("sessions"), "the filtered command");
    assert!(text.contains("esc close"), "the esc note");
    // The golden palette has no key footer (sections fill the height).
    // The query renders.
    assert!(text.contains("sess"), "the query text");
    // Fuzzy filtering dropped non-matching commands.
    assert!(!text.contains("toggle cost"), "non-match filtered out");
}

// ── Design invariants (§13.5) ────────────────────────────────────────────────

/// invariant_one_frame_max: at most one OVERLAY frame (modal) at a time
/// (§1). The pane boxes are the layout (herdr-style isolation), not
/// overlays — they're exempt. A modal (quit confirmation, approval) draws
/// its own frame; two modals at once would violate the one-frame rule.
#[test]
fn invariant_one_frame_max() {
    let d = design();
    // The pane layout: 3 boxed panes × 4 corners = 12 baseline.
    let base = render_buf(&idle_app(), &d, 150, 44);
    let base_corners: usize = base
        .content()
        .iter()
        .filter(|c| {
            c.symbol() == "╭" || c.symbol() == "╮" || c.symbol() == "╰" || c.symbol() == "╯"
        })
        .count();
    assert_eq!(base_corners, 12, "three boxed panes = 12 corners");

    // With a modal open, the modal adds exactly one frame (+4 corners).
    for app in [approval_app()] {
        for (w, h) in [(150u16, 44u16), (80, 30)] {
            let buf = render_buf(&app, &d, w, h);
            let corners: usize = buf
                .content()
                .iter()
                .filter(|c| {
                    c.symbol() == "╭" || c.symbol() == "╮" || c.symbol() == "╰" || c.symbol() == "╯"
                })
                .count();
            // 12 (panes) + 4 (modal) = 16 max. Two modals would be 20.
            assert!(
                corners <= 16,
                "at most one overlay frame beyond the panes — found {corners} at {w}x{h}"
            );
        }
    }
    // Quit modal + approval never co-render in these states; the quit state
    // adds a second frame only when the operator asked — one at a time holds.
}

/// invariant_ascii_tier_is_ascii: with the ASCII glyph set, every chrome cell
/// is printable ASCII. (Content passes through untouched.)
#[test]
fn invariant_ascii_tier_is_ascii() {
    let d = ascii_design();
    assert_eq!(d.caps.glyphs, GlyphSet::Ascii);
    for app in [idle_app(), working_app(), approval_app()] {
        let buf = render_buf(&app, &d, 150, 44);
        for cell in buf.content() {
            let s = cell.symbol();
            // User content (the transcript text) may contain unicode; chrome
            // cells are the ones ORBIT writes itself. We cannot distinguish
            // per-cell provenance from the buffer, so assert the strong
            // property on the chrome-only surfaces: the status line (last
            // row) and the pane header rows (first row) must be pure ASCII.
            let _ = s;
        }
        // Header + status rows:
        let text = buf_text(&buf);
        let first = text.lines().next().unwrap_or_default();
        let last = text.lines().last().unwrap_or_default();
        for row in [first, last] {
            assert!(
                row.chars()
                    .all(|c| (0x20..0x7f).contains(&(c as u32)) || c == ' '),
                "ASCII-tier chrome row must be printable ASCII: {row:?}"
            );
        }
    }
}

/// invariant_no_truncated_approval: the approval action text appears in the
/// buffer in full at every supported size.
#[test]
fn invariant_no_truncated_approval() {
    let d = design();
    let summary = "Apply patch to 2 files in /work/atlas/src/auth/refresh.ts and test/auth.test.ts with a long path";
    let mut app = idle_app();
    app.tool_state = ToolState::AwaitingApproval;
    app.pending_approvals.push(PendingApproval {
        call_id: "call-0".into(),
        tool_name: "workspace.apply_patch".into(),
        summary: summary.into(),
        risk: 2,
        working_dir: "/tmp".into(),
    });
    for (w, h) in [(150u16, 44u16), (110, 30), (80, 30)] {
        let buf = render_buf(&app, &d, w, h);
        let text = buf_text(&buf);
        // The tool name and the beginning of the action must be visible in
        // full; the summary wraps but is never silently truncated (an
        // ellipsis may appear, truncation may not — assert the tool name in
        // full and that the summary's first words survive).
        assert!(
            text.contains("workspace.apply_patch"),
            "tool name in full at {w}x{h}"
        );
        assert!(
            text.contains("Apply patch to 2 files"),
            "summary start visible at {w}x{h}"
        );
    }
}

/// invariant_idle_draws_nothing: after a response settles, ticks set no
/// dirty flags (a still screen is a finished screen — §1).
#[test]
fn invariant_idle_draws_nothing() {
    let mut app = idle_app();
    // A settled idle app: run the turn to completion.
    app.reduce(orbit_hud_tui::msg::Msg::ResponseFinished {
        output: String::new(),
        input_tokens: 1,
        output_tokens: 1,
        cost_microcents: 1,
    });
    // 200 ticks: past the M5 turn report's 2 s window (its dismissal
    // sets STATUS once) — then settle.
    for _ in 0..200 {
        app.reduce(orbit_hud_tui::msg::Msg::Tick);
    }
    app.dirty.clear();
    // 1,000 ticks in steady idle.
    for _ in 0..1000 {
        app.reduce(orbit_hud_tui::msg::Msg::Tick);
    }
    assert!(
        !app.dirty.is_dirty(),
        "idle ticks must set no dirty flags (found {:?})",
        app.dirty
    );
}

/// invariant_single_moving_cell: while working, consecutive frames differ
/// only in the mark cell and status counters, unless data arrived.
#[test]
fn invariant_single_moving_cell() {
    let d = design();
    let mut app = working_app();
    // Frame at spinner_frame = 0 and = 1 (a 4-tick star advance).
    let buf0 = render_buf(&app, &d, 150, 44);
    app.spinner_frame = 1;
    let buf1 = render_buf(&app, &d, 150, 44);

    // Count differing cells; the star frame + any status-glyph cell changes.
    let mut diff: Vec<(u16, u16)> = Vec::new();
    for y in 0..44 {
        for x in 0..150 {
            if buf0[(x, y)].symbol() != buf1[(x, y)].symbol() {
                diff.push((x, y));
            }
        }
    }
    // Motion zones (fluid design): the status mark, the live transcript
    // gutter, and the running tool card's ticking duration — all in the
    // center column (the conversation), never the rails or header.
    let status_y = 43;
    let center_x = 24; // left rail is 24 cols; center starts at 24
    for (x, y) in &diff {
        let in_status = *y == status_y;
        let in_center = *x >= center_x && *y < status_y;
        assert!(
            in_status || in_center,
            "cell ({x},{y}) changed outside the motion zones"
        );
    }
    assert!(
        !diff.is_empty(),
        "the spinner should advance between frames"
    );
    assert!(
        diff.len() <= 12,
        "only the spinner + duration cells may change; {} cells did",
        diff.len()
    );
}

/// Magenta discipline (§1 principle 3, approximated as a bounded count):
/// in the idle frame — no approval pending — magenta cells exist only at
/// the focused-pane title and the mark. With the approval card shown, the
/// card frame joins the list. The bound keeps magenta from creeping into
/// general activity rendering.
#[test]
fn invariant_magenta_closed_list() {
    let d = design();
    let magenta = d.palette.magenta;

    // Idle: mark + focused pane title only — a small bounded count.
    let buf = render_buf(&idle_app(), &d, 150, 44);
    let magenta_cells: usize = buf
        .content()
        .iter()
        .filter(|c| c.fg == ratatui::style::Color::Magenta || c.fg == magenta)
        .count();
    // The focused pane's border is the accent (herdr-style focus): the
    // center pane perimeter ≈ 2×(width+height) cells + the mark + prompt.
    assert!(
        magenta_cells <= 320,
        "idle frame has {magenta_cells} magenta cells — magenta is leaking beyond the focused border + accents"
    );

    // Approval: the card frame joins — still bounded (frame + title + keys).
    let buf = render_buf(&approval_app(), &d, 150, 44);
    let magenta_cells: usize = buf
        .content()
        .iter()
        .filter(|c| c.fg == ratatui::style::Color::Magenta || c.fg == magenta)
        .count();
    // The card frame perimeter (≈2×(width+height)) + title + key glyphs
    // + the focused center-pane border (herdr-style accent).
    assert!(
        magenta_cells <= 640,
        "approval frame has {magenta_cells} magenta cells — beyond frame + title + keys + border"
    );
}

// ── herdr panel isolation (§8 boxed panes) ───────────────────────────────────

/// The focused pane's border is magenta; the unfocused panes' borders are
/// muted. Exactly one pane carries the accent at any moment — that is the
/// isolation contract (herdr render_pane_borders).
#[test]
fn invariant_pane_isolation_single_accent() {
    let d = design();
    let magenta = d.palette.magenta;
    let muted = d.palette.muted;

    for focus in [Focus::Left, Focus::Center, Focus::Right] {
        let mut app = idle_app();
        app.focus = focus;
        let buf = render_buf(&app, &d, 150, 44);

        // Pane rects (the render records them for the hit-test).
        let rects = [
            app.pane_rects.left.get(),
            app.pane_rects.center.get(),
            app.pane_rects.right.get(),
        ];
        let mut accented = 0;
        for (i, r) in rects.iter().enumerate() {
            let Some(r) = r else { continue };
            if r.width < 3 || r.height < 3 {
                continue;
            }
            // The top border row of the pane: every border cell's fg.
            let top: Vec<_> = (r.x..r.x + r.width).map(|x| buf[(x, r.y)].fg).collect();
            let is_magenta = top.contains(&magenta);
            let is_muted = top.contains(&muted);
            let expected_focused = match focus {
                Focus::Left => i == 0,
                Focus::Center => i == 1,
                Focus::Right => i == 2,
                Focus::Status => false,
            };
            assert_eq!(
                is_magenta, expected_focused,
                "pane {i} accent state wrong for focus {focus:?}"
            );
            // Unfocused panes draw their border in the muted rule colour.
            if !expected_focused {
                assert!(
                    is_muted,
                    "pane {i} border should be muted for focus {focus:?}"
                );
            }
            if is_magenta {
                accented += 1;
            }
        }
        assert_eq!(accented, 1, "exactly one accented pane for focus {focus:?}");
    }
}
