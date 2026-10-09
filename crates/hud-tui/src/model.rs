//! The types the worker, the bus and the screen share: how a tool call
//! ended, the workspace snapshot, a transcript line, the readiness rows.
//! They carry no UI behaviour of their own.

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Focus {
    Left,
    /// Default — the operator can type immediately on boot, no Tab needed.
    #[default]
    Center,
    Right,
    Status,
}

impl Focus {
    pub fn next(self) -> Self {
        match self {
            Self::Left => Self::Center,
            Self::Center => Self::Right,
            Self::Right => Self::Status,
            Self::Status => Self::Left,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Left => Self::Status,
            Self::Center => Self::Left,
            Self::Right => Self::Center,
            Self::Status => Self::Right,
        }
    }
}

/// A workspace task (§6.10 task rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub title: String,
    pub state: TaskState,
    /// Optional single sub-line (what it's doing / why blocked / etc.).
    pub sub: Option<String>,
    /// Right-aligned evidence tag: number of verified proofs (0 = claimed).
    pub evidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Active,
    /// Not started yet (the golden's ◌ pending rows).
    Pending,
    Blocked,
    Failed,
    Retest,
    AwaitingApproval,
    Done,
}

/// The workspace snapshot the pane renders (§6.10). All sections optional;
/// the pane renders only the sections with data. The backend fills these
/// (PR-F wires the bridge).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    pub phase_index: usize, // 0..5
    pub plan: Vec<Task>,
    pub findings: Vec<Finding>,
    pub verification: Vec<Verification>,
}

/// One finding row: title + inline source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Neutral,
    Error,
}

/// One verification row: check name + result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub name: String,
    pub result: VerificationResult,
    pub proof_count: u8,
    /// The right-aligned result text ('48 passed', 'retest') — structured
    /// backend data, never model prose (§6.10).
    pub result_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Passed,
    Failed,
    Pending,
}

/// Modal input (the multiplexer pattern): INSERT types into the composer
/// (the boot default — type to talk); NORMAL runs single-key commands
/// (q, g/z leaders, ?). Esc from an empty composer toggles to NORMAL;
/// `i` or Enter returns to INSERT. The status line shows the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    /// Type into the composer (the boot default).
    #[default]
    Insert,
    /// Single-key commands (q, g/z leaders, ?).
    Normal,
    /// Prefix mode (herdr/tmux-style): the next key is a command. Entered
    /// with Ctrl+B; Esc cancels. The status line shows PREFIX.
    Prefix,
    /// Copy mode: j/k move a cursor through the transcript, v selects,
    /// y yanks. Per-pane (herdr-style).
    Copy,
}

/// One computed welcome-screen readiness check. Honesty rule: every
/// glyph and label is drawn from a value the harness measured, never a
/// fixture string.
#[derive(Debug, Clone)]
pub struct ReadinessRow {
    pub ok: bool,
    pub label: String,
}

/// Compute the welcome readiness row from the real environment: trust
/// root present, ledger segment count, active provider · model. Each
/// check is measured, not asserted — a missing trust root shows ✗.
pub fn compute_readiness(home: &std::path::Path) -> Vec<ReadinessRow> {
    let mut rows = Vec::new();
    // Trust root: the signed trust anchor `orbit init` writes. The file
    // is trust/manifest.json (see cmd_init) — an earlier revision of
    // this check looked for trust/root.json, which init never writes,
    // so every fresh home showed ✕ trust root.
    let trust_ok = home.join("trust/manifest.json").exists();
    rows.push(ReadinessRow {
        ok: trust_ok,
        label: "trust root".into(),
    });
    // Ledger: count real segment files under $ORBIT_HOME/ledger/segments.
    let seg_dir = home.join("ledger/segments");
    let segs = std::fs::read_dir(&seg_dir)
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    rows.push(ReadinessRow {
        ok: segs > 0,
        label: format!(
            "ledger · {segs} segment{}",
            if segs == 1 { "" } else { "s" }
        ),
    });
    // Provider · model: the CLI exports the ACTIVE pair before the
    // in-process TUI starts (ORBIT_ACTIVE_MODEL / ORBIT_ACTIVE_PROVIDER).
    let model = std::env::var("ORBIT_ACTIVE_MODEL").unwrap_or_else(|_| "unset".into());
    let provider = std::env::var("ORBIT_ACTIVE_PROVIDER").unwrap_or_else(|_| "local".into());
    rows.push(ReadinessRow {
        ok: model != "unset",
        label: format!("{provider} · {model}"),
    });
    rows
}

/// One line in the transcript — either a user message or an assistant reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptLine {
    /// A user turn. `time` is the HH:MM stamp shown right-aligned on the
    /// first row (None in Compact, which hides timestamps).
    User { text: String, time: Option<String> },
    /// An ORBIT turn. `time` as for User; `live` marks the in-flight turn
    /// (cyan gutter) — settled turns render magenta.
    Assistant { text: String, time: Option<String> },
    /// CoT-stripped placeholder (NEVER shows raw reasoning).
    Stripped {
        tool_name: String,
        /// Display-safe argument summary (the bridge's safe_text output).
        /// Rendered as the tool card's argument column (§6.5).
        summary: String,
        /// The call's settled outcome (None while running). Set by
        /// ToolCallFinished — the card's glyph depends on it (§6.5).
        outcome: Option<ToolOutcome>,
        /// The settled outcome summary ('48 passed', '+9 −3') — right-
        /// aligned meta on the card (§6.5). Empty while running.
        meta: String,
        /// The tick the call started at — drives the live ticking duration
        /// on the running card. None for entries restored from a session
        /// file. (§16.1 seam: ticks, not Instants.)
        started_at: Option<u64>,
    },
    /// System note (cancelled turn, queue drained, etc.) — dim, never bold.
    System(String),
    /// §6.6 evidence card: header + rows, built only from structured
    /// verification data (never model prose).
    Evidence {
        /// The header's count text (e.g. `2 checks`).
        checks: String,
        /// The header's attestation note (e.g. `retest attestation recorded`).
        note: String,
        /// Rows: (check name, result text).
        rows: Vec<(String, String)>,
    },
    /// §6.7 citations: the sources line after a turn's content.
    Sources(Vec<(String, String)>),
    /// A text chunk the bridge rejected (D7). NEVER shows the rejected
    /// text; renders as a one-line chip: `[blocked: <kind>]`.
    Redacted(RedactionKind),
}

/// How a tool call ended (§6.5, §11.5 rule 4). `Denied` and `Blocked` are
/// decisions, not failures: an operator refusal must never render as a red
/// `✕ failed` — audits read refusals and crashes differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOutcome {
    /// Ran and succeeded: `✓` muted.
    Ok,
    /// Ran and failed: `✕` red + `failed` meta.
    Failed,
    /// Denied by the operator (or deny-by-default rules): `⊘` muted +
    /// `denied by you` meta.
    Denied,
    /// Blocked before running (unknown tool, non-interactive without
    /// consent): `⊖` amber + `blocked` meta.
    Blocked,
    /// Stopped by the operator's interrupt (Esc), or cut off because the
    /// turn ended before it reported: `⊘` muted + `cancelled`. Neither
    /// a failure nor a denial.
    Cancelled,
}

/// Why the bridge rejected a text chunk (D7). Names the gate, not the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionKind {
    /// `safe_text` found a secret pattern in the chunk.
    Secret,
    /// The chunk was not valid UTF-8 (`from_utf8` failed).
    InvalidUtf8,
    /// The chunk failed the display-safe escape scan.
    Escape,
    /// Provider died mid-stream (`rx.recv()` returned None).
    StreamInterrupted,
}

impl RedactionKind {
    /// The chip label (§7.3-style: lowercase words, no glyphs needed).
    pub fn label(&self) -> &'static str {
        match self {
            RedactionKind::Secret => "credential",
            RedactionKind::InvalidUtf8 => "encoding",
            RedactionKind::Escape => "escape",
            RedactionKind::StreamInterrupted => "stream interrupted",
        }
    }
}

/// Connection state for the status bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectionState {
    #[default]
    Online,
    Reconnecting,
    Offline,
}

/// The operator's answer to an approval card (§12): drives the Activity
/// `grant` row text (§9.16) and the tool-line marker (◆ once / ◈ session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// `y` — allow this one call.
    Once,
    /// `R` — allow this tool for the session.
    Session,
    /// `n` / Esc — deny.
    Denied,
}
