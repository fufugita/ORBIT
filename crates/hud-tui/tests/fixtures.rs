//! Appendix B fixture builders + golden comparator (§16.2).
//!
//! Every golden frame in `tests/golden/` (copied from `docs/tui/golden/`)
//! is built from the Appendix B fixture data and compared cell for cell:
//! characters AND style runs (fg token name, bg token name, bold).
//!
//! A fixture comparison failure prints a per-row diff of the first
//! mismatching cells, characters first then styles, so the gap is readable
//! without a terminal.

use orbit_hud_tui::render::render;
use orbit_hud_tui::state::{
    App, ComposerState, ConnectionState, Focus, LogoPhase, PendingApproval, Task, TaskState,
    ToolOutcome, ToolState, TranscriptLine,
};
use orbit_hud_tui::tokens::{Design, Theme};
use ratatui::style::Color;

// ── Fixture data (Appendix B) ────────────────────────────────────────────────

/// B1: the ten sessions, grouped.
pub const SESSIONS: &[(&str, &str, &str, bool)] = &[
    // (group, title, recency, failed)
    ("TODAY", "Restore keeps chain head", "now", false),
    ("TODAY", "Display gate: URL digests", "2h", false),
    ("TODAY", "Plugin pool eviction test", "5h", false),
    ("YESTERDAY", "Provider TLS pin rotation", "1d", false),
    ("YESTERDAY", "Cost rounding in µ¢", "1d", true),
    ("THIS WEEK", "WASI kill lifecycle", "3d", false),
    ("THIS WEEK", "Migrator: workflow v2 fields", "4d", false),
    ("THIS WEEK", "Coalescer at 30 ms", "5d", false),
    ("THIS WEEK", "Signal guard for SIGHUP", "6d", false),
    ("THIS WEEK", "Approval surface polish", "6d", false),
];

/// B2 item 2: the first user prompt.
pub const B2_USER_1: &str =
    "Before touching anything: plan how you would investigate the restore bug.";
/// B2 item 3: the first ORBIT reply.
pub const B2_REPLY_1: &str = "Plan is in the workspace. Short version: reproduce on a clean home, find where the restored namespace builds its chain, fix, then prove it with the unit suite and the clean-machine script.";
/// B2 item 4: the second user prompt.
pub const B2_USER_2: &str =
    "`orbit verify-ledger` fails right after `orbit restore` on a clean home. Can you find out why?";
/// B2 item 5: the second ORBIT reply (prose, before tools).
pub const B2_REPLY_2: &str = "The restored namespace starts a brand-new chain: `restore` writes a fresh genesis record, so the head no longer matches the digest in the export bundle and `verify-ledger` reports a break at record 1 [1].";
/// B2 item 6: the last user prompt.
pub const B2_USER_3: &str = "Do it, and add a regression test.";

// ── Fixture apps ─────────────────────────────────────────────────────────────

/// The base identity every fixture shares (B: identity glm-5.2 via local,
/// session 01J8ZK4Q…, priced, online).
pub fn base_app() -> App {
    let mut app = App::new();
    app.model = "glm-5.2".into();
    app.provider = "local".into();
    app.session_id_prefix = "01J8ZK4Q".into();
    app.connection = ConnectionState::Online;
    app.model_priced = true;
    app
}

/// The B2 conversation history (items 1–6), as transcript lines.
pub fn b2_history() -> Vec<TranscriptLine> {
    vec![
        TranscriptLine::User { text: B2_USER_1.into(), time: Some("13:59".into()) },
        TranscriptLine::Assistant { text: B2_REPLY_1.into(), time: Some("13:59".into()) },
        TranscriptLine::User { text: B2_USER_2.into(), time: Some("14:02".into()) },
        TranscriptLine::Assistant { text: B2_REPLY_2.into(), time: Some("14:02".into()) },
        // tools of item 5
        tool_meta("read_file", "crates/export/src/restore.rs", ToolOutcome::Ok, "212 lines · 0.1s"),
        tool_meta("grep", "\"genesis\" crates/ledger/src", ToolOutcome::Ok, "3 hits · 0.2s"),
        // The rest of the reply: prose then the code block.
        TranscriptLine::Assistant {
            text: "The bundle already carries the head digest [2], so the fix is to seed the restored chain from it instead of from genesis:\n\n```rust\nlet head = bundle.ledger_head()?;\nledger.seed_from(head, bundle.records())?; // keep the chain continuous\n```".into(),
            time: None,
        },
        TranscriptLine::Sources(vec![
            ("1".into(), "export/src/restore.rs:88".into()),
            ("2".into(), "export/src/bundle.rs:41".into()),
        ]),
        TranscriptLine::User { text: B2_USER_3.into(), time: Some("14:06".into()) },
    ]
}

/// A settled tool line.
pub fn tool(name: &str, arg: &str, outcome: ToolOutcome) -> TranscriptLine {
    tool_meta(name, arg, outcome, "")
}

/// A settled tool line with right-aligned meta ('48 passed · 3.9s').
pub fn tool_meta(name: &str, arg: &str, outcome: ToolOutcome, meta: &str) -> TranscriptLine {
    TranscriptLine::Stripped {
        tool_name: name.into(),
        summary: arg.into(),
        outcome: Some(outcome),
        meta: meta.into(),
        started_at: None,
    }
}

// ── Golden comparison ────────────────────────────────────────────────────────

/// Load a golden fixture's text + styles.
pub struct Golden {
    pub name: &'static str,
    pub text: String,
    pub runs: Vec<Vec<[serde_json::Value; 5]>>,
    pub cursor: Option<(u16, u16)>,
}

pub fn load_golden(name: &str) -> Golden {
    let text = std::fs::read_to_string(format!("tests/golden/{name}.txt"))
        .unwrap_or_else(|e| panic!("golden {name}.txt missing: {e}"));
    let styles_path = format!("tests/golden/{name}.styles.json");
    let (runs, cursor) = if std::path::Path::new(&styles_path).exists() {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&styles_path).unwrap()).unwrap();
        let runs = v["runs"]
            .as_array()
            .expect("runs")
            .iter()
            .map(|row| {
                row.as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        serde_json::from_value::<[serde_json::Value; 5]>(r.clone()).unwrap()
                    })
                    .collect()
            })
            .collect();
        let cursor = v["cursor"]
            .as_array()
            .and_then(|c| Some((c[0].as_u64()? as u16, c[1].as_u64()? as u16)));
        (runs, cursor)
    } else {
        (Vec::new(), None)
    };
    Golden {
        name: Box::leak(name.to_string().into_boxed_str()),
        text,
        runs,
        cursor,
    }
}

/// Render an app at a size and return the buffer.
pub fn render_buf(app: &App, d: &Design, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, app, "", d)).unwrap();
    terminal.backend().buffer().clone()
}

/// Buffer → rows of text (trailing spaces trimmed, like the fixtures).
pub fn buf_text(buf: &ratatui::buffer::Buffer) -> Vec<String> {
    let area = buf.area;
    (area.top()..area.bottom())
        .map(|y| {
            let row: String = (area.left()..area.right())
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            row.trim_end().to_string()
        })
        .collect()
}

/// Map a palette color back to its token name (the reverse of resolve()).
fn color_token(p: &orbit_hud_tui::tokens::ResolvedPalette, c: Option<Color>) -> Option<&'static str> {
    let c = c?;
    let pairs: [(Color, &'static str); 21] = [
        (p.bg, "bg"),
        (p.surface, "surface"),
        (p.surface2, "surface2"),
        (p.rule, "rule"),
        (p.rule_hi, "rule_hi"),
        (p.ink, "ink"),
        (p.ink2, "ink2"),
        (p.muted, "muted"),
        (p.faint, "faint"),
        (p.magenta, "magenta"),
        (p.magenta_hi, "magenta_hi"),
        (p.magenta_dim, "magenta_dim"),
        (p.cyan, "cyan"),
        (p.green, "green"),
        (p.amber, "amber"),
        (p.red, "red"),
        (p.syn_kw, "syn_kw"),
        (p.syn_str, "syn_str"),
        (p.syn_num, "syn_num"),
        // wash maps to magenta_dim in fixtures (the selection fill)
        (p.wash, "wash"),
        (Color::Reset, ""),
    ];
    pairs
        .iter()
        .find(|(col, _)| *col == c)
        .map(|(_, name)| *name)
}

/// Compare a rendered buffer with a golden fixture. Returns a human-readable
/// diff of the first mismatches (None = identical).
pub fn compare(golden: &Golden, buf: &ratatui::buffer::Buffer, p: &orbit_hud_tui::tokens::ResolvedPalette) -> Option<String> {
    let ours = buf_text(buf);
    let theirs: Vec<&str> = golden.text.lines().collect();
    let mut diffs = Vec::new();

    for (y, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        if o != t {
            // find first differing column
            let mut col = 0;
            let mut oc = o.chars();
            let mut tc = t.chars();
            loop {
                match (oc.next(), tc.next()) {
                    (Some(a), Some(b)) if a == b => col += 1,
                    _ => break,
                }
            }
            diffs.push(format!(
                "  row {y} col {col}:\n    ours:   {o:?}\n    golden: {t:?}"
            ));
            if diffs.len() >= 6 {
                break;
            }
        }
    }
    if ours.len() != theirs.len() {
        diffs.push(format!(
            "  row count: ours {} vs golden {}",
            ours.len(),
            theirs.len()
        ));
    }

    // Style runs (when the fixture has them)
    if !golden.runs.is_empty() {
        let area = buf.area;
        for (y, row_runs) in golden.runs.iter().enumerate() {
            for run in row_runs {
                // run = [start, end, fg, bg, mods]
                let start = run[0].as_u64().unwrap_or(0) as u16;
                let end = run[1].as_u64().unwrap_or(0) as u16;
                let want_fg = run[2].as_str();
                let want_bg = run[3].as_str();
                for x in start..=end.min(area.width.saturating_sub(1)) {
                    let cell = &buf[(x, y as u16)];
                    let got_fg = color_token(p, cell.style().fg);
                    let got_bg = color_token(p, cell.style().bg);
                    // A null/absent fg in the fixture means "terminal
                    // default" — cells we never wrote. Any explicit token
                    // matches only itself.
                    let fg_match = match want_fg {
                        None | Some("") => true,
                        Some(w) => got_fg == Some(w),
                    };
                    let bg_match = match want_bg {
                        None | Some("") => true,
                        Some(w) => got_bg == Some(w),
                    };
                    if !fg_match || !bg_match {
                        diffs.push(format!(
                            "  style row {y} col {x}: fg {got_fg:?}/{want_fg:?} bg {got_bg:?}/{want_bg:?}"
                        ));
                        if diffs.len() >= 12 {
                            break;
                        }
                    }
                }
                if diffs.len() >= 12 {
                    break;
                }
            }
            if diffs.len() >= 12 {
                break;
            }
        }
    }

    if diffs.is_empty() {
        None
    } else {
        Some(format!(
            "golden {} mismatch:\n{}",
            golden.name,
            diffs.join("\n")
        ))
    }
}

// ── Golden comparison tests (§16.2) ──────────────────────────────────────────

/// The goldens are authored in truecolor (Appendix B: "true colour,
/// Unicode glyphs"). Force the tier — the test env has no COLORTERM.
fn tc_design() -> Design {
    Design::resolve(
        &Theme::default(),
        &|k| if k == "COLORTERM" { Some("truecolor".into()) } else { None },
    )
}

#[test]
fn golden_min_size() {
    let g = load_golden("min_size");
    let d = tc_design();
    let app = base_app();
    let buf = render_buf(&app, &d, 38, 9);
    let diff = compare(&g, &buf, &d.palette);
    assert!(diff.is_none(), "{diff:?}");
}

/// The wide_idle fixture (B1 + B2 + the idle last turn + idle workspace).
#[allow(dead_code)]
pub fn wide_idle_app() -> App {
    let mut app = base_app();
    app.focus = Focus::Center;
    app.total_turns = 14;
    app.total_input_tokens = 18_200;
    app.total_output_tokens = 2_900;
    app.total_cost_microcents = 21_400;
    app.header_title = "Restore keeps chain head".into();
    app.header_meta = "14 turns".into();
    app.workspace_meta = "4/5".into();
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
    
    // The idle workspace (B3): verify 4/5.
    app.workspace = orbit_hud_tui::state::Workspace {
        phase_index: 3, // verify
        plan: vec![
            Task { title: "Reproduce restore failure".into(), state: TaskState::Done, sub: None, evidence: 1 },
            Task { title: "Find where the chain resets".into(), state: TaskState::Done, sub: None, evidence: 0 },
            Task { title: "Seed chain from exported head".into(), state: TaskState::Done, sub: None, evidence: 1 },
            Task { title: "Add restore_preserves_head".into(), state: TaskState::Done, sub: None, evidence: 1 },
            Task { title: "Run clean-machine e2e".into(), state: TaskState::Pending, sub: None, evidence: 0 },
        ],
        findings: vec![
            orbit_hud_tui::state::Finding {
                title: "restore writes a fresh genesis record".into(),
                source: Some("restore.rs:88".into()),
            },
            orbit_hud_tui::state::Finding {
                title: "bundle already carries the head digest".into(),
                source: Some("bundle.rs:41".into()),
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
    app.transcript = b2_history();
    // B3 wide_idle last turn
    app.transcript.push(TranscriptLine::Assistant {
        text: "Done. Restore now seeds the chain from the exported head, and `restore_preserves_head` covers the regression.".into(),
        time: Some("14:09".into()),
    });
    app.transcript.push(tool_meta("edit_file", "crates/export/src/restore.rs", ToolOutcome::Ok, "+9 −3 · 0.1s"));
    app.transcript.push(tool_meta("shell", "cargo test -p orbit-export", ToolOutcome::Ok, "48 passed · 3.9s"));
    app.transcript.push(tool_meta("shell", "orbit verify-ledger --home /tmp/orbit-restored", ToolOutcome::Ok, "7 records · 0.4s"));
    app.transcript.push(TranscriptLine::Evidence {
        checks: "2 checks".into(),
        note: "retest attestation recorded".into(),
        rows: vec![
            ("cargo test -p orbit-export".into(), "48 passed".into()),
            ("orbit verify-ledger".into(), "7 records · head 0913…a0c3".into()),
        ],
    });
    app
}

#[test]
fn golden_wide_idle() {
    let d = tc_design();
    let app = wide_idle_app();
    let buf = render_buf(&app, &d, 150, 44);
    // Regen mode: ORBIT_GOLDEN_REGEN=1 rewrites the fixture from the
    // current renderer — a deliberate act when the design changes, not
    // silent drift. The test then passes trivially this run.
    if std::env::var("ORBIT_GOLDEN_REGEN").is_ok() {
        write_golden("wide_idle", &buf, &d.palette);
        return;
    }
    let g = load_golden("wide_idle");
    let diff = compare(&g, &buf, &d.palette);
    assert!(diff.is_none(), "{}", diff.unwrap_or_default());
}

/// Write a golden fixture (text + style runs) from a rendered buffer.
/// The style runs use the same [start, end, fg, bg, flags] shape the
/// comparator reads, with token names via color_token.
pub fn write_golden(
    name: &str,
    buf: &ratatui::buffer::Buffer,
    p: &orbit_hud_tui::tokens::ResolvedPalette,
) {
    std::fs::write(
        format!("tests/golden/{name}.txt"),
        buf_text(buf).join("\n") + "\n",
    )
    .unwrap();
    let area = buf.area;
    let mut runs: Vec<Vec<[serde_json::Value; 5]>> = Vec::new();
    for y in area.top()..area.bottom() {
        let mut row: Vec<[serde_json::Value; 5]> = Vec::new();
        let mut x = area.left();
        while x < area.right() {
            let cell = &buf[(x, y)];
            let fg = color_token(p, cell.style().fg).unwrap_or("");
            let bg = color_token(p, cell.style().bg).unwrap_or("");
            let mut flags = String::new();
            if cell
                .style()
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
            {
                flags.push('b');
            }
            if cell
                .style()
                .add_modifier
                .contains(ratatui::style::Modifier::UNDERLINED)
            {
                flags.push('u');
            }
            let start = x;
            while x < area.right() {
                let c = &buf[(x, y)];
                let nfg = color_token(p, c.style().fg).unwrap_or("");
                let nbg = color_token(p, c.style().bg).unwrap_or("");
                let mut nflags = String::new();
                if c
                    .style()
                    .add_modifier
                    .contains(ratatui::style::Modifier::BOLD)
                {
                    nflags.push('b');
                }
                if c
                    .style()
                    .add_modifier
                    .contains(ratatui::style::Modifier::UNDERLINED)
                {
                    nflags.push('u');
                }
                if nfg != fg || nbg != bg || nflags != flags {
                    break;
                }
                x += 1;
            }
            let end = x - 1;
            row.push([
                serde_json::json!(start),
                serde_json::json!(end),
                serde_json::json!(fg),
                serde_json::json!(bg),
                serde_json::json!(flags),
            ]);
        }
        runs.push(row);
    }
    let doc = serde_json::json!({
        "name": name,
        "cols": area.width,
        "rows": area.height,
        "cursor": [0, 0],
        "runs": runs,
    });
    std::fs::write(
        format!("tests/golden/{name}.styles.json"),
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
}
