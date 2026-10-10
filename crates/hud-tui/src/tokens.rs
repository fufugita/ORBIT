//! The `tui.toml` schema (docs/tui/DESIGN.md §13.4): the colour overrides,
//! the earlier layout table and the capability switches (`[color]`: mode,
//! glyphs, reduced motion, brand tier). The screen reads `capabilities`;
//! a file that does not parse falls back to the defaults as a whole.

use serde::{Deserialize, Serialize};

// ── User overrides (tui.toml, §13.4) ─────────────────────────────────────────

/// Colour overrides a `tui.toml` may carry. They are parsed so a file that
/// has them still loads; the screen does not apply them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserColors {
    pub bg: Option<String>,
    pub surface: Option<String>,
    pub surface2: Option<String>,
    pub wash: Option<String>,
    pub rule: Option<String>,
    pub rule_hi: Option<String>,
    pub ink: Option<String>,
    pub ink2: Option<String>,
    pub muted: Option<String>,
    pub faint: Option<String>,
    pub magenta: Option<String>,
    pub magenta_hi: Option<String>,
    pub magenta_dim: Option<String>,
    pub cyan: Option<String>,
    pub green: Option<String>,
    pub amber: Option<String>,
    pub red: Option<String>,
    pub syn_kw: Option<String>,
    pub syn_str: Option<String>,
    pub syn_num: Option<String>,

    // ── deprecated keys (§13.4), kept so an old file still parses ──
    pub accent: Option<String>,
    pub accent_bright: Option<String>,
    pub accent_dim: Option<String>,
    pub composer: Option<String>,
    pub composer_dim: Option<String>,
    pub text: Option<String>,
    pub dim: Option<String>,
    pub code_bg: Option<String>,
    pub code_fg: Option<String>,
    pub error: Option<String>,
    pub success: Option<String>,
    pub warning: Option<String>,
}

/// The earlier layout table (`[layout]`: rail widths, measure, panes). The
/// screen keeps its layout as a panel tree (`[layout.tree]`) and does not
/// read these; they are parsed so an old file still loads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LayoutConfig {
    pub rail_left: u16,
    pub rail_right: u16,
    pub measure: u16,
    /// Pane customization (herdr-style): which panes exist, in what order,
    /// and their preferred widths. The renderer clamps to the terminal.
    /// Names: "sessions", "activity", "conversation", "workspace".
    /// The conversation pane is always present and always last-but-one in
    /// the center; the others are optional and ordered as listed.
    pub panes: PaneLayoutConfig,
}

/// Which panes exist and their widths (tui.toml `[layout.panes]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PaneLayoutConfig {
    /// Pane order, left to right, by name. "conversation" must appear
    /// exactly once; it anchors the center. Unknown names are ignored.
    pub order: Vec<String>,
    /// Preferred width per pane name (columns). Rails clamp to the
    /// terminal; the conversation takes the remainder.
    pub width: std::collections::BTreeMap<String, u16>,
    /// Panes to hide entirely (by name).
    pub hide: Vec<String>,
}

impl Default for PaneLayoutConfig {
    fn default() -> Self {
        Self {
            order: vec![
                "sessions".into(),
                "activity".into(),
                "conversation".into(),
                "workspace".into(),
            ],
            width: std::collections::BTreeMap::from([
                ("sessions".into(), 28),
                ("activity".into(), 22),
                ("workspace".into(), 36),
            ]),
            hide: vec!["activity".into()],
        }
    }
}

impl PaneLayoutConfig {
    /// Is a pane visible (listed, not hidden)?
    pub fn visible(&self, name: &str) -> bool {
        self.order.iter().any(|o| o == name) && !self.hide.iter().any(|h| h == name)
    }
    /// Preferred width for a pane (0 = unset → renderer default).
    pub fn width_of(&self, name: &str) -> u16 {
        self.width.get(name).copied().unwrap_or(0)
    }
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            rail_left: 24,
            rail_right: 40,
            measure: 100,
            panes: PaneLayoutConfig::default(),
        }
    }
}

/// New capability keys (§13.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilitiesConfig {
    /// "auto" | "truecolor" | "256" | "16" | "mono"
    pub mode: String,
    /// "auto" | "unicode" | "ascii"
    pub glyphs: String,
    pub reduced: bool,
    /// "off" | "text" | "static" | "anim"
    pub brand: String,
    pub bell_on_approval: bool,
}

impl Default for CapabilitiesConfig {
    fn default() -> Self {
        Self {
            mode: "auto".into(),
            glyphs: "auto".into(),
            reduced: false,
            brand: "anim".into(),
            bell_on_approval: false,
        }
    }
}

/// The complete user theme file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Theme {
    pub colors: UserColors,
    pub layout: LayoutConfig,
    #[serde(rename = "color")]
    pub capabilities: CapabilitiesConfig,
}
