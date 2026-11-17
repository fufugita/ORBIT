//! Portable, declarative customization. This module never performs I/O.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROFILE_BYTES: usize = 128 * 1024;
/// The built-in themes. Keep in sync with hud-tui's `pal::from_profile`.
pub const THEMES: [&str; 5] = ["orbit", "midnight", "paper", "aespa-pastel", "kwangya-ice"];
pub const MAX_PANE_OUTPUT_BYTES: usize = 32 * 1024;
pub const MAX_PANE_LINES: usize = 512;

/// The top-bar chips a user may toggle. Keep in sync with
/// hud-tui's `bars::top_bar` chip construction.
pub const CHIP_IDS: [&str; 6] = ["cwd", "branch", "model", "context", "cost", "ledger"];
pub const CHIP_IDS_LIST: &str = "cwd, branch, model, context, cost, ledger";

/// Valid chip id for `customize set chip.<id> on|off`.
pub fn valid_chip_id(chip: &str) -> bool {
    CHIP_IDS.contains(&chip)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub name: String,
    pub theme: String,
    #[serde(deserialize_with = "unique_tokens")]
    pub token_overrides: BTreeMap<String, String>,
    pub density: Density,
    pub glyphs: Glyphs,
    pub reduced_motion: bool,
    /// The terminal Reactor scene. Older profiles keep the original scene.
    pub reactor_art: ReactorArt,
    pub color_mode: ColorMode,
    pub browser: BrowserStyle,
    pub layout: Layout,
    pub panes: Vec<PaneDef>,
    /// Per-chip visibility in the top bar: the id is a chip name
    /// (`cwd`, `branch`, `model`, `context`, `cost`, `ledger`) and the value
    /// says whether it shows. Absent ids default to visible.
    #[serde(default)]
    pub chip_visibility: BTreeMap<String, bool>,
    /// Width-responsive chip bounds: a chip with a minimum hides
    /// below that terminal width; a maximum hides above it.
    #[serde(default)]
    pub chip_width_bounds: BTreeMap<String, ChipWidthBounds>,
}

/// The declared width window for one chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChipWidthBounds {
    #[serde(default)]
    pub min: u16,
    #[serde(default)]
    pub max: u16,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            name: "Default".into(),
            theme: "orbit".into(),
            token_overrides: BTreeMap::new(),
            density: Density::Comfortable,
            glyphs: Glyphs::Auto,
            reduced_motion: false,
            reactor_art: ReactorArt::default(),
            color_mode: ColorMode::Auto,
            browser: BrowserStyle::default(),
            layout: Layout::default(),
            panes: Vec::new(),
            chip_visibility: BTreeMap::new(),
            chip_width_bounds: BTreeMap::new(),
        }
    }
}
macro_rules! values {
    ($name:ident, $default:ident, $($variant:ident),+) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all="snake_case")]
        pub enum $name { #[default] $default, $($variant),+ }
    };
}
values!(Density, Comfortable, Compact);
values!(Glyphs, Auto, Unicode, Ascii);
/// Declarative Reactor scenes; selecting one never starts a provider request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactorArt {
    #[default]
    Kwangya,
    Shard,
    Spine,
    Globe,
    Rotate,
}
impl ReactorArt {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kwangya => "kwangya",
            Self::Shard => "shard",
            Self::Spine => "spine",
            Self::Globe => "globe",
            Self::Rotate => "rotate",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Kwangya => Self::Shard,
            Self::Shard => Self::Spine,
            Self::Spine => Self::Globe,
            Self::Globe => Self::Rotate,
            Self::Rotate => Self::Kwangya,
        }
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorMode {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "truecolor")]
    Truecolor,
    #[serde(rename = "256")]
    Ansi256,
    #[serde(rename = "16")]
    Ansi16,
    #[serde(rename = "mono")]
    Mono,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserStyle {
    pub font_family: String,
    pub font_size_px: f32,
}
impl Default for BrowserStyle {
    fn default() -> Self {
        Self {
            font_family: "monospace".into(),
            font_size_px: 13.5,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Layout {
    pub preset: String,
    pub tree: LayoutNode,
}
impl Default for Layout {
    fn default() -> Self {
        Self {
            preset: "default".into(),
            tree: LayoutNode::Split {
                direction: Direction::Right,
                shares: vec![30, 40, 30],
                children: vec![
                    LayoutNode::panel(View::Changes),
                    LayoutNode::panel(View::Conversation),
                    LayoutNode::panel(View::Terminal),
                ],
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayoutNode {
    Panel {
        view: View,
        #[serde(default)]
        agent: String,
    },
    Custom {
        pane_id: String,
    },
    Split {
        #[serde(rename = "dir")]
        direction: Direction,
        shares: Vec<u32>,
        children: Vec<LayoutNode>,
    },
}
impl LayoutNode {
    pub fn panel(view: View) -> Self {
        Self::Panel {
            view,
            agent: String::new(),
        }
    }
}
/// Built-in portable layouts, independent of any terminal renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableLayoutPreset {
    Columns,
    Build,
    Agents,
    Review,
}

/// Build the portable tree while keeping one reachable conversation panel.
pub fn portable_layout_preset(preset: PortableLayoutPreset) -> LayoutNode {
    let split = |direction, shares, children| LayoutNode::Split {
        direction,
        shares,
        children,
    };
    match preset {
        PortableLayoutPreset::Columns => Layout::default().tree,
        PortableLayoutPreset::Build => split(
            Direction::Right,
            vec![56, 44],
            vec![
                LayoutNode::panel(View::Conversation),
                split(
                    Direction::Down,
                    vec![48, 52],
                    vec![
                        LayoutNode::panel(View::Changes),
                        LayoutNode::panel(View::Terminal),
                    ],
                ),
            ],
        ),
        PortableLayoutPreset::Agents => split(
            Direction::Right,
            vec![30, 40, 30],
            vec![
                LayoutNode::Panel {
                    view: View::Agent,
                    agent: "explore".into(),
                },
                LayoutNode::panel(View::Conversation),
                LayoutNode::Panel {
                    view: View::Agent,
                    agent: "review".into(),
                },
            ],
        ),
        PortableLayoutPreset::Review => split(
            Direction::Right,
            vec![40, 60],
            vec![
                LayoutNode::panel(View::Conversation),
                split(
                    Direction::Right,
                    vec![70, 30],
                    vec![
                        LayoutNode::panel(View::Review),
                        split(
                            Direction::Down,
                            vec![45, 55],
                            vec![
                                LayoutNode::panel(View::Plan),
                                LayoutNode::panel(View::Activity),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Conversation,
    Changes,
    Terminal,
    Plan,
    Activity,
    Context,
    Review,
    Agent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Right,
    Down,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Terminal,
    Browser,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaneDef {
    pub id: String,
    pub title: String,
    pub surfaces: Vec<Surface>,
    pub source: PaneSource,
    #[serde(default)]
    pub actions: Vec<PaneAction>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaneSource {
    Text { text: String },
    MarkdownFile { path: String },
    Snapshot { snapshot: SnapshotKind },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Routing,
    Usage,
    Agents,
    Scope,
    Evidence,
    Findings,
    /// The MAGI council state, read from one fixed, code-defined file.
    Council,
    /// The ORBIT session's own token flow, from `PaneContext`.
    Reactor,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaneAction {
    Refresh,
    FocusConversation,
    InsertPrompt {
        text: String,
    },
    OwnerCancel,
    /// Persist the next built-in Reactor scene without submitting a prompt.
    CycleReactorArt,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PaneContext {
    /// The currently bound durable session, never an ambient process override.
    pub session_id: Option<String>,
    pub permission_mode: Option<String>,
    pub routing: Vec<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
    pub agents: Vec<PaneAgent>,
    pub controller: bool,
    /// Session facts for the built-in `reactor` pane. `None` means the
    /// frontend did not report the value; it is never rendered as zero.
    pub model: String,
    pub provider: String,
    pub phase: Option<String>,
    pub used_tokens: Option<u64>,
    pub window_tokens: Option<u64>,
    pub turns: Option<u64>,
    pub turn_tools: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    /// The cost total is unpriced or rests on incomplete usage history.
    pub cost_uncertain: bool,
    /// Output rate in thousandths of a token per second: the last finished
    /// turn (exact), the session peak, and a rough estimate while streaming.
    pub rate_milli: Option<u64>,
    pub peak_rate_milli: Option<u64>,
    pub live_rate_milli: Option<u64>,
    /// Recent per-turn rates, oldest first (at most 40), for a sparkline.
    pub rate_history: Vec<u64>,
    /// The council engine's state, already parsed and bounded by the
    /// frontend that read it. `None` when no council has published anything
    /// this session. The council pane draws it as seat cards; a frontend
    /// that does not understand it falls back to `PaneOutput::text`.
    pub council: Option<CouncilSnapshot>,
}

/// What a published council state said, in the terms the panes draw in.
/// Every list is bounded here, at the point of reading, so a pane can never
/// be handed an unbounded foreign document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CouncilSnapshot {
    /// The engine's phase word (`DELIBERATING`, `VERDICT`, …); empty when
    /// the state was unreadable.
    pub phase: String,
    /// The engine's note for the phase.
    pub note: String,
    /// Up to four seats on the bench.
    pub seats: Vec<CouncilSeat>,
    /// Seats past the bench: name and model only.
    pub extra_seats: Vec<CouncilChip>,
    /// Seat names that carried a majority, when the engine names them.
    pub winner_seats: Vec<String>,
    /// The newest finished council's seats, by bench position.
    pub last_seats: Vec<CouncilSeat>,
    /// Its conclusion, first line, `FINAL:` removed.
    pub last_final: String,
    /// Finished councils in the recent window, and the window's size.
    pub finished: u32,
    pub seen: u32,
    /// When the newest finished council ended, in epoch seconds.
    pub last_at: Option<f64>,
    /// When this state was published, in epoch seconds.
    pub published_at: Option<f64>,
    /// The newest finished council ended without a single winner.
    pub last_tie: bool,
}

impl CouncilSnapshot {
    /// Canonicalize and gate a complete foreign field before clipping it.
    pub fn sanitized_text_with(
        source: &str,
        maximum: usize,
        mut sanitize: impl FnMut(&str) -> String,
    ) -> String {
        fn plain(source: &str) -> String {
            let mut out = String::with_capacity(source.len());
            let mut chars = source.chars();
            while let Some(ch) = chars.next() {
                match ch {
                    '\u{1b}' => match chars.next() {
                        Some('[') => {
                            for next in chars.by_ref() {
                                if ('\u{40}'..='\u{7e}').contains(&next) {
                                    break;
                                }
                            }
                        }
                        Some(']' | 'P' | '_' | '^' | 'X') => {
                            while let Some(next) = chars.next() {
                                if next == '\u{7}'
                                    || (next == '\u{1b}' && chars.next() == Some('\\'))
                                {
                                    break;
                                }
                            }
                        }
                        _ => {}
                    },
                    '\u{9b}' => {
                        for next in chars.by_ref() {
                            if ('\u{40}'..='\u{7e}').contains(&next) {
                                break;
                            }
                        }
                    }
                    '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                        while let Some(next) = chars.next() {
                            if next == '\u{7}'
                                || next == '\u{9c}'
                                || (next == '\u{1b}' && chars.next() == Some('\\'))
                            {
                                break;
                            }
                        }
                    }
                    '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' => out.push(' '),
                    '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}' => {}
                    ch if ch.is_control() => {}
                    ch => out.push(ch),
                }
            }
            out
        }
        // An oversized foreign field is withheld whole: clipping before
        // the gate could expose only the unrecognizable prefix of a key.
        const MAX_FIELD_BYTES: usize = 64 * 1024;
        if source.len() > MAX_FIELD_BYTES {
            return "[content withheld]".chars().take(maximum).collect();
        }
        let clean = sanitize(&plain(source));
        if clean.len() > MAX_FIELD_BYTES {
            return "[content withheld]".chars().take(maximum).collect();
        }
        plain(&clean).chars().take(maximum).collect()
    }

    /// Bound every field and apply the frontend's display gate before any
    /// truncation. This is shared by file readers and native message ingress.
    pub fn sanitized_with(&self, mut sanitize: impl FnMut(&str) -> String) -> Self {
        fn text(source: &str, maximum: usize, sanitize: &mut impl FnMut(&str) -> String) -> String {
            CouncilSnapshot::sanitized_text_with(source, maximum, sanitize)
        }
        fn seat(value: &CouncilSeat, sanitize: &mut impl FnMut(&str) -> String) -> CouncilSeat {
            CouncilSeat {
                name: text(&value.name, 32, sanitize),
                number: text(&value.number, 8, sanitize),
                role: text(&value.role, 24, sanitize),
                lab: text(&value.lab, 32, sanitize),
                model: text(&value.model, 96, sanitize),
                activity: text(&value.activity, 16, sanitize),
                verdict: value
                    .verdict
                    .as_ref()
                    .map(|value| text(value, 16, sanitize)),
                confidence: value.confidence.map(|value| value.min(100)),
            }
        }
        Self {
            phase: text(&self.phase, 24, &mut sanitize),
            note: text(&self.note, 240, &mut sanitize),
            seats: self
                .seats
                .iter()
                .take(4)
                .map(|value| seat(value, &mut sanitize))
                .collect(),
            extra_seats: self
                .extra_seats
                .iter()
                .take(12)
                .map(|value| CouncilChip {
                    name: text(&value.name, 32, &mut sanitize),
                    lab: text(&value.lab, 32, &mut sanitize),
                    activity: text(&value.activity, 16, &mut sanitize),
                })
                .collect(),
            winner_seats: self
                .winner_seats
                .iter()
                .take(4)
                .map(|value| text(value, 32, &mut sanitize))
                .collect(),
            last_seats: self
                .last_seats
                .iter()
                .take(4)
                .map(|value| seat(value, &mut sanitize))
                .collect(),
            last_final: text(&self.last_final, 240, &mut sanitize),
            finished: self.finished,
            seen: self.seen,
            last_at: self
                .last_at
                .filter(|value| value.is_finite() && *value >= 0.0),
            published_at: self
                .published_at
                .filter(|value| value.is_finite() && *value >= 0.0),
            last_tie: self.last_tie,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CouncilSeat {
    pub name: String,
    pub number: String,
    pub role: String,
    pub lab: String,
    pub model: String,
    /// `resting`, `wiring`, `working`, `answered` or `lost`.
    pub activity: String,
    /// `approve`, `reject` or `hold`.
    pub verdict: Option<String>,
    pub confidence: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CouncilChip {
    pub name: String,
    pub lab: String,
    /// `answered`, `lost` or `resting`.
    pub activity: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaneAgent {
    pub id: String,
    pub name: String,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaneState {
    Ready,
    Empty,
    Missing,
    Loading,
    Stale,
    Error,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaneOutput {
    pub id: String,
    pub title: String,
    pub state: PaneState,
    pub text: String,
    pub truncated: bool,
    pub actions: Vec<PaneAction>,
    /// Bounded, display-scanned Council state from the current session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub council: Option<CouncilSnapshot>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveSource {
    Default,
    Legacy,
    Profile,
    Session,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedProfile {
    pub profile: Profile,
    pub sources: BTreeMap<String, EffectiveSource>,
    pub revision: String,
    pub capabilities: CustomizationCapabilities,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomizationCapabilities {
    pub schema_version: u32,
    pub sources: Vec<String>,
    pub actions: Vec<String>,
    pub surfaces: Vec<Surface>,
    pub terminal_font: String,
    pub instruction_mods: String,
    pub signed_packages: String,
}
impl Default for CustomizationCapabilities {
    fn default() -> Self {
        Self {
            schema_version: 1,
            sources: vec!["text".into(), "markdown_file".into(), "snapshot".into()],
            actions: vec![
                "refresh".into(),
                "focus_conversation".into(),
                "insert_prompt".into(),
                "owner_cancel".into(),
                "cycle_reactor_art".into(),
            ],
            surfaces: vec![Surface::Terminal, Surface::Browser],
            terminal_font: "Font family and size are controlled by the terminal host".into(),
            instruction_mods: "Instruction and command bundles; no JavaScript execution".into(),
            signed_packages: "Verified non-executing content".into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum CustomizationError {
    Invalid(String),
    UnsafePath(String),
    Busy,
    Io(String),
    PublicationUncertain(String),
}
impl std::fmt::Display for CustomizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid customization: {s}"),
            Self::UnsafePath(s) => write!(f, "unsafe customization path: {s}"),
            Self::Busy => write!(f, "customization is busy or revision changed"),
            Self::Io(s) => write!(f, "customization I/O: {s}"),
            Self::PublicationUncertain(s) => write!(f, "customization publication uncertain: {s}"),
        }
    }
}
impl std::error::Error for CustomizationError {}
pub trait ProfileHost: Send + Sync {
    fn command_checked(
        &self,
        _command: ProfileCommand,
        _expected_revision: &str,
    ) -> Result<ProfileCommandResult, CustomizationError> {
        Err(CustomizationError::Invalid(
            "checked customization commands unavailable".into(),
        ))
    }
    fn command(
        &self,
        _command: ProfileCommand,
    ) -> Result<ProfileCommandResult, CustomizationError> {
        Err(CustomizationError::Invalid(
            "customization commands unavailable".into(),
        ))
    }
    fn load(&self) -> Result<ResolvedProfile, CustomizationError>;
    fn replace(
        &self,
        profile: Profile,
        expected_revision: &str,
    ) -> Result<ResolvedProfile, CustomizationError>;
    fn reset(&self, expected_revision: &str) -> Result<ResolvedProfile, CustomizationError>;
    fn read_pane(&self, id: &str, context: &PaneContext) -> Result<PaneOutput, CustomizationError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileCommand {
    Show,
    Capabilities,
    Validate { path: String },
    Import { path: String },
    Export { path: String },
    Set { key: String, value: String },
    Reset { key: Option<String> },
    Theme { name: String },
    Reload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileCommandResult {
    pub message: String,
    pub profile: Option<ResolvedProfile>,
}

/// Panes ORBIT knows without a profile entry. They are selectable in any
/// layout, yet `Profile::default()` keeps `panes: []`, so stored and fresh
/// profiles stay byte-identical. A profile pane with the same id wins.
pub const BUILTIN_PANE_IDS: [&str; 2] = ["council", "reactor"];

/// The definition of a built-in pane, or `None` for any other id.
pub fn builtin_pane(id: &str) -> Option<PaneDef> {
    let (title, snapshot, actions) = match id {
        "council" => (
            "Council",
            SnapshotKind::Council,
            vec![
                PaneAction::Refresh,
                PaneAction::FocusConversation,
                PaneAction::InsertPrompt {
                    text: "/council ".into(),
                },
            ],
        ),
        "reactor" => (
            "Reactor",
            SnapshotKind::Reactor,
            vec![
                PaneAction::Refresh,
                PaneAction::FocusConversation,
                PaneAction::CycleReactorArt,
            ],
        ),
        _ => return None,
    };
    Some(PaneDef {
        id: id.into(),
        title: title.into(),
        surfaces: vec![Surface::Terminal, Surface::Browser],
        source: PaneSource::Snapshot { snapshot },
        actions,
    })
}

pub fn valid_id(id: &str) -> bool {
    (1..=48).contains(&id.len())
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
pub fn canonical_token(token: &str) -> Option<&str> {
    Some(match token {
        "accent" => "magenta",
        "accent_bright" => "magenta_hi",
        "accent_dim" => "magenta_dim",
        "composer" => "cyan",
        "composer_dim" => "cyan_dim",
        "text" | "code_fg" => "ink",
        "dim" => "muted",
        "code_bg" => "surface",
        "error" => "red",
        "success" => "green",
        "warning" => "amber",
        "bg" | "surface" | "surface2" | "wash" | "rule" | "rule_hi" | "ink" | "ink2" | "muted"
        | "faint" | "magenta" | "magenta_hi" | "magenta_dim" | "cyan" | "cyan_hi" | "cyan_dim"
        | "green" | "amber" | "red" | "violet" | "blue" | "syn_kw" | "syn_str" | "syn_num"
        | "syn_comment" | "selection" | "focus" | "border" | "background" | "foreground"
        | "app" | "sidebar" | "panel" | "raise" | "raise2" | "inset" | "topbar" | "white"
        | "on_accent" | "add_bg" | "del_bg" | "add_fg" | "del_fg" | "hunk" | "grad0"
        | "mode_default_bg" | "brand0" | "brand1" | "brand2" | "brand3" => token,
        _ => return None,
    })
}
impl Profile {
    /// A pane by id: the profile's own definition first, then the built-ins.
    pub fn pane_def(&self, id: &str) -> Option<PaneDef> {
        self.panes
            .iter()
            .find(|pane| pane.id == id)
            .cloned()
            .or_else(|| builtin_pane(id))
    }
    pub fn validate(&self) -> Result<(), CustomizationError> {
        let invalid = |field: &str| CustomizationError::Invalid(field.into());
        if self.schema_version != 1 {
            return Err(invalid("schema_version must be 1"));
        }
        if self.name.is_empty() || self.name.len() > 64 || self.name.chars().any(char::is_control) {
            return Err(invalid("name must contain 1..64 printable bytes"));
        }
        if !THEMES.contains(&self.theme.as_str()) {
            return Err(invalid("theme is unsupported"));
        }
        for (key, value) in &self.token_overrides {
            if canonical_token(key).is_none() {
                return Err(invalid(&format!("token_overrides.{key}: unknown token")));
            }
            if value.len() != 7
                || !value.starts_with('#')
                || !value[1..].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid(&format!("token_overrides.{key}: expected #RRGGBB")));
            }
        }
        let font = &self.browser.font_family;
        if font.is_empty()
            || font.len() > 128
            || font.split(',').count() > 8
            || font.split(',').any(|f| {
                f.trim().is_empty()
                    || !f
                        .trim()
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-'))
            })
        {
            return Err(invalid(
                "browser.font_family must be a bounded list of literal family names",
            ));
        }
        if !(10.0..=24.0).contains(&self.browser.font_size_px) {
            return Err(invalid("browser.font_size_px must be 10..24"));
        }
        if self.layout.preset.is_empty()
            || self.layout.preset.len() > 64
            || self.layout.preset.chars().any(char::is_control)
        {
            return Err(invalid("layout.preset is invalid"));
        }
        if self.panes.len() > 32 {
            return Err(invalid("panes exceeds 32"));
        }
        // Chip visibility: only known chip ids, bounded entries.
        if self.chip_visibility.len() > 16 {
            return Err(invalid("chip_visibility exceeds 16 entries"));
        }
        for chip in self.chip_visibility.keys() {
            if !CHIP_IDS.contains(&chip.as_str()) {
                return Err(invalid(&format!(
                    "chip_visibility.{chip}: unknown chip (known: {CHIP_IDS_LIST})"
                )));
            }
        }
        if self.chip_width_bounds.len() > 16 {
            return Err(invalid("chip_width_bounds exceeds 16 entries"));
        }
        for (chip, bounds) in &self.chip_width_bounds {
            if !CHIP_IDS.contains(&chip.as_str()) {
                return Err(invalid(&format!(
                    "chip_width_bounds.{chip}: unknown chip (known: {CHIP_IDS_LIST})"
                )));
            }
            if bounds.min != 0 && bounds.max != 0 && bounds.min > bounds.max {
                return Err(invalid(&format!(
                    "chip_width_bounds.{chip}: min {0} exceeds max {1}",
                    bounds.min, bounds.max
                )));
            }
        }
        let mut ids = BTreeSet::new();
        for pane in &self.panes {
            if !valid_id(&pane.id) || !ids.insert(pane.id.as_str()) {
                return Err(invalid("panes.id is invalid or duplicated"));
            }
            if pane.title.is_empty()
                || pane.title.len() > 64
                || pane.title.chars().any(char::is_control)
            {
                return Err(invalid("panes.title must contain 1..64 printable bytes"));
            }
            if pane.surfaces.is_empty()
                || pane.surfaces.len() > 2
                || pane.surfaces.iter().collect::<BTreeSet<_>>().len() != pane.surfaces.len()
            {
                return Err(invalid("panes.surfaces is empty or duplicated"));
            }
            match &pane.source {
                PaneSource::Text { text } if text.len() > 16 * 1024 => {
                    return Err(invalid("panes.source.text exceeds 16 KiB"));
                }
                PaneSource::MarkdownFile { path }
                    if path.is_empty()
                        || path.len() > 256
                        || path.starts_with('/')
                        || path
                            .split('/')
                            .any(|p| p.is_empty() || p == "." || p == "..")
                        || path.chars().any(|c| c.is_control() || c == '\\') =>
                {
                    return Err(invalid(
                        "panes.source.path must be a relative workspace path",
                    ));
                }
                _ => {}
            }
            if pane.actions.len() > 8 {
                return Err(invalid("panes.actions exceeds 8"));
            }
            for action in &pane.actions {
                if let PaneAction::InsertPrompt { text } = action
                    && text.len() > 4096
                {
                    return Err(invalid("panes.actions.insert_prompt exceeds 4096 bytes"));
                }
            }
        }
        let (mut leaves, mut conversation) = (0, 0);
        fn walk(
            node: &LayoutNode,
            depth: usize,
            ids: &BTreeSet<&str>,
            leaves: &mut usize,
            conversation: &mut usize,
        ) -> Result<(), CustomizationError> {
            let err = |s: &str| CustomizationError::Invalid(format!("layout.tree: {s}"));
            if depth > 8 {
                return Err(err("depth exceeds 8"));
            }
            match node {
                LayoutNode::Panel { view, agent } => {
                    *leaves += 1;
                    if *view == View::Conversation {
                        *conversation += 1;
                    }
                    if agent.len() > 128 || agent.chars().any(char::is_control) {
                        return Err(err("agent identity is invalid"));
                    }
                }
                LayoutNode::Custom { pane_id } => {
                    *leaves += 1;
                    if !ids.contains(pane_id.as_str()) {
                        return Err(err("custom pane reference is unresolved"));
                    }
                }
                LayoutNode::Split {
                    shares, children, ..
                } => {
                    if children.is_empty()
                        || children.len() > 8
                        || shares.len() != children.len()
                        || shares.iter().any(|s| !(1..=1000).contains(s))
                    {
                        return Err(err("split geometry is invalid"));
                    }
                    for child in children {
                        walk(child, depth + 1, ids, leaves, conversation)?;
                    }
                }
            }
            if *leaves > 24 {
                return Err(err("leaves exceed 24"));
            }
            Ok(())
        }
        // Built-in panes resolve without a profile entry.
        ids.extend(BUILTIN_PANE_IDS);
        walk(&self.layout.tree, 1, &ids, &mut leaves, &mut conversation)?;
        if conversation != 1 {
            return Err(invalid("layout.tree must retain exactly one conversation"));
        }
        Ok(())
    }
    /// Canonical names win over deprecated aliases, independently of map order.
    pub fn resolved_tokens(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (key, value) in &self.token_overrides {
            if let Some(token) = canonical_token(key) {
                out.entry(token.into()).or_insert_with(|| value.clone());
            }
        }
        for (key, value) in &self.token_overrides {
            if canonical_token(key) == Some(key.as_str()) {
                out.insert(key.clone(), value.clone());
            }
        }
        out
    }
}
fn unique_tokens<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique token keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if out.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate token key"));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(Visitor)
}

#[cfg(test)]
mod builtin_pane_tests {
    use super::*;

    #[test]
    fn reactor_art_defaults_for_old_profiles_and_cycles_all_declared_scenes() {
        let profile: Profile = serde_json::from_str(r#"{"schema_version":1}"#).unwrap();
        assert_eq!(profile.reactor_art, ReactorArt::Kwangya);
        let mut art = profile.reactor_art;
        for expected in ["kwangya", "shard", "spine", "globe", "rotate"] {
            assert_eq!(art.as_str(), expected);
            assert_eq!(serde_json::to_value(art).unwrap(), expected);
            art = art.next();
        }
        assert_eq!(art, ReactorArt::Kwangya);
        assert!(serde_json::from_str::<ReactorArt>(r#""shell:command""#).is_err());
        let reactor = builtin_pane("reactor").unwrap();
        assert!(reactor.actions.contains(&PaneAction::CycleReactorArt));
        let council = builtin_pane("council").unwrap();
        assert!(council.actions.contains(&PaneAction::InsertPrompt {
            text: "/council ".into(),
        }));
    }

    #[test]
    fn default_profile_is_unchanged_and_builtin_panes_resolve_in_layouts() {
        let mut profile = Profile::default();
        assert!(profile.panes.is_empty());
        assert_eq!(profile.layout, Layout::default());
        for id in BUILTIN_PANE_IDS {
            let pane = profile.pane_def(id).expect("built-in pane resolves");
            assert_eq!(pane.id, id);
            assert!(valid_id(&pane.id));
            assert!(pane.actions.len() <= 8);
        }
        assert!(profile.pane_def("notes").is_none());
        profile.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![40, 30, 30],
            children: vec![
                LayoutNode::panel(View::Conversation),
                LayoutNode::Custom {
                    pane_id: "council".into(),
                },
                LayoutNode::Custom {
                    pane_id: "reactor".into(),
                },
            ],
        };
        profile
            .validate()
            .expect("built-in panes need no profile entry");
        profile.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![50, 50],
            children: vec![
                LayoutNode::panel(View::Conversation),
                LayoutNode::Custom {
                    pane_id: "unknown".into(),
                },
            ],
        };
        assert!(profile.validate().is_err());
    }

    #[test]
    fn a_profile_pane_shadows_the_builtin_of_the_same_id() {
        let mut profile = Profile::default();
        profile.panes.push(PaneDef {
            id: "council".into(),
            title: "Mine".into(),
            surfaces: vec![Surface::Terminal],
            source: PaneSource::Text { text: "own".into() },
            actions: Vec::new(),
        });
        profile.validate().unwrap();
        assert_eq!(profile.pane_def("council").unwrap().title, "Mine");
    }

    #[test]
    fn new_snapshot_kinds_use_their_wire_names() {
        assert_eq!(
            serde_json::to_string(&SnapshotKind::Council).unwrap(),
            "\"council\""
        );
        assert_eq!(
            serde_json::to_string(&SnapshotKind::Reactor).unwrap(),
            "\"reactor\""
        );
    }
}

#[cfg(test)]
mod portable_layout_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn portable_presets_keep_the_exact_retained_wire_trees() {
        let cases = [
            (
                PortableLayoutPreset::Columns,
                json!({"kind":"split","dir":"right","shares":[30,40,30],"children":[
                    {"kind":"panel","view":"changes","agent":""},
                    {"kind":"panel","view":"conversation","agent":""},
                    {"kind":"panel","view":"terminal","agent":""}
                ]}),
            ),
            (
                PortableLayoutPreset::Build,
                json!({"kind":"split","dir":"right","shares":[56,44],"children":[
                    {"kind":"panel","view":"conversation","agent":""},
                    {"kind":"split","dir":"down","shares":[48,52],"children":[
                        {"kind":"panel","view":"changes","agent":""},
                        {"kind":"panel","view":"terminal","agent":""}
                    ]}
                ]}),
            ),
            (
                PortableLayoutPreset::Agents,
                json!({"kind":"split","dir":"right","shares":[30,40,30],"children":[
                    {"kind":"panel","view":"agent","agent":"explore"},
                    {"kind":"panel","view":"conversation","agent":""},
                    {"kind":"panel","view":"agent","agent":"review"}
                ]}),
            ),
            (
                PortableLayoutPreset::Review,
                json!({"kind":"split","dir":"right","shares":[40,60],"children":[
                    {"kind":"panel","view":"conversation","agent":""},
                    {"kind":"split","dir":"right","shares":[70,30],"children":[
                        {"kind":"panel","view":"review","agent":""},
                        {"kind":"split","dir":"down","shares":[45,55],"children":[
                            {"kind":"panel","view":"plan","agent":""},
                            {"kind":"panel","view":"activity","agent":""}
                        ]}
                    ]}
                ]}),
            ),
        ];
        for (preset, expected) in cases {
            assert_eq!(
                serde_json::to_value(portable_layout_preset(preset)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn portable_presets_validate_roundtrip_and_keep_the_default_baseline() {
        fn conversations(node: &LayoutNode) -> usize {
            match node {
                LayoutNode::Panel {
                    view: View::Conversation,
                    ..
                } => 1,
                LayoutNode::Panel { .. } | LayoutNode::Custom { .. } => 0,
                LayoutNode::Split { children, .. } => children.iter().map(conversations).sum(),
            }
        }
        let baseline = Layout::default();
        assert_eq!(baseline.preset, "default");
        assert_eq!(
            portable_layout_preset(PortableLayoutPreset::Columns),
            baseline.tree
        );
        for preset in [
            PortableLayoutPreset::Columns,
            PortableLayoutPreset::Build,
            PortableLayoutPreset::Agents,
            PortableLayoutPreset::Review,
        ] {
            let tree = portable_layout_preset(preset);
            assert_eq!(conversations(&tree), 1);
            let mut profile = Profile::default();
            profile.layout.tree = tree.clone();
            profile.validate().unwrap();
            let encoded = serde_json::to_vec(&profile).unwrap();
            let reopened: Profile = serde_json::from_slice(&encoded).unwrap();
            reopened.validate().unwrap();
            assert_eq!(reopened.layout.tree, tree);
        }
        assert_eq!(Layout::default(), baseline);
    }
}
