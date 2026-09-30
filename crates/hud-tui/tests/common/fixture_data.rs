// Fixture data (Appendix B) shared by tests and the live_demo example.
// Included (not module); the includer provides the imports.

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
pub const B2_USER_1: &str =
    "Before touching anything: plan how you would investigate the restore bug.";
pub const B2_REPLY_1: &str = "Plan is in the workspace. Short version: reproduce on a clean home, find where the restored namespace builds its chain, fix, then prove it with the unit suite and the clean-machine script.";
pub const B2_USER_2: &str =
    "`orbit verify-ledger` fails right after `orbit restore` on a clean home. Can you find out why?";
pub const B2_REPLY_2: &str = "The restored namespace starts a brand-new chain: `restore` writes a fresh genesis record, so the head no longer matches the digest in the export bundle and `verify-ledger` reports a break at record 1 [1].";
pub const B2_USER_3: &str = "Do it, and add a regression test.";
pub fn base_app() -> App {
    let mut app = App::new();
    app.model = "glm-5.2".into();
    app.provider = "local".into();
    app.session_id_prefix = "01J8ZK4Q".into();
    app.connection = ConnectionState::Online;
    app.model_priced = true;
    app
}

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

pub fn tool(name: &str, arg: &str, outcome: ToolOutcome) -> TranscriptLine {
    tool_meta(name, arg, outcome, "")
}

pub fn tool_meta(name: &str, arg: &str, outcome: ToolOutcome, meta: &str) -> TranscriptLine {
    TranscriptLine::Stripped {
        tool_name: name.into(),
        summary: arg.into(),
        outcome: Some(outcome),
        meta: meta.into(),
        started_at: None,
    }
}
