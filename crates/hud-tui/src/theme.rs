//! User-customizable TUI theme (DR-20 §5 polish).
//!
//! Loaded from `$ORBIT_HOME/tui.toml` if present; falls back to
//! `Theme::default()` (pastel pink + Miku blue + white). Every color in the
//! TUI reads from this struct — no hardcoded colors in render.rs.

use ratatui::style::Color;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Default palette: pastel pink + Miku blue + white ─────────────────────────

/// Pastel pink — focused borders, headings, brand accent.
pub const DEFAULT_ACCENT: Color = Color::Rgb(255, 179, 217);
/// Brighter pink — shimmer phase 1 on focused pane.
pub const DEFAULT_ACCENT_BRIGHT: Color = Color::Rgb(255, 201, 230);
/// Dim pink — unfocused borders.
pub const DEFAULT_ACCENT_DIM: Color = Color::Rgb(184, 122, 160);
/// Pastel blue — composer, user text, cursor.
pub const DEFAULT_COMPOSER: Color = Color::Rgb(160, 216, 239);
/// Dim pastel blue — unfocused composer.
pub const DEFAULT_COMPOSER_DIM: Color = Color::Rgb(111, 168, 199);
/// White — body text.
pub const DEFAULT_TEXT: Color = Color::Rgb(224, 224, 224);
/// Gray — secondary/dim text.
pub const DEFAULT_DIM: Color = Color::Rgb(136, 136, 136);
/// Dark navy — code block background.
pub const DEFAULT_CODE_BG: Color = Color::Rgb(30, 30, 40);
/// Light cyan — code text.
pub const DEFAULT_CODE_FG: Color = Color::Rgb(120, 220, 232);
/// Red — errors.
pub const DEFAULT_ERROR: Color = Color::Rgb(255, 85, 85);
/// Green — success.
pub const DEFAULT_SUCCESS: Color = Color::Rgb(80, 200, 120);
/// Yellow — warnings/approvals.
pub const DEFAULT_WARNING: Color = Color::Rgb(255, 200, 50);

// ── Theme structs ────────────────────────────────────────────────────────────

/// The complete TUI theme — colors, layout, spinner, tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    #[serde(default)]
    pub colors: ThemeColors,
    #[serde(default)]
    pub layout: LayoutConfig,
    #[serde(default)]
    pub spinner: SpinnerConfig,
    #[serde(default)]
    pub tabs: TabConfig,
}

/// All configurable colors. Each is a hex string (`#RRGGBB`) in TOML,
/// parsed to `Color::Rgb` at load time. Every field can be omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThemeColors {
    pub accent: String,
    pub accent_bright: String,
    pub accent_dim: String,
    pub composer: String,
    pub composer_dim: String,
    pub text: String,
    pub dim: String,
    pub code_bg: String,
    pub code_fg: String,
    pub error: String,
    pub success: String,
    pub warning: String,
}

/// Layout proportions — pane widths, bar heights. Every field can be omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LayoutConfig {
    pub left_pct: u16,
    pub center_pct: u16,
    pub right_pct: u16,
    pub header_lines: u16,
    pub status_lines: u16,
    pub help_lines: u16,
    pub composer_lines: u16,
}

/// Spinner configuration. Every field can be omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpinnerConfig {
    pub style: String,
    pub phrases: Vec<String>,
}

/// Tab configuration — which tabs appear, what the help bar shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TabConfig {
    pub left: Vec<String>,
    pub show_help_bar: bool,
    pub show_tick_count: bool,
}

// ── Parsed (Color-resolved) theme ────────────────────────────────────────────

/// The theme with colors resolved to `Color::Rgb` — what the renderer uses.
#[derive(Debug, Clone)]
pub struct ResolvedTheme {
    pub colors: ResolvedColors,
    pub layout: LayoutConfig,
    pub spinner: SpinnerConfig,
    pub tabs: TabConfig,
}

#[derive(Debug, Clone)]
pub struct ResolvedColors {
    pub accent: Color,
    pub accent_bright: Color,
    pub accent_dim: Color,
    pub composer: Color,
    pub composer_dim: Color,
    pub text: Color,
    pub dim: Color,
    pub code_bg: Color,
    pub code_fg: Color,
    pub error: Color,
    pub success: Color,
    pub warning: Color,
}

#[allow(clippy::derivable_impls)] // explicit for documentation clarity
impl Default for Theme {
    fn default() -> Self {
        Self {
            colors: ThemeColors::default(),
            layout: LayoutConfig::default(),
            spinner: SpinnerConfig::default(),
            tabs: TabConfig::default(),
        }
    }
}

impl Default for ThemeColors {
    fn default() -> Self {
        Self {
            accent: "#FFB3D9".into(),
            accent_bright: "#FFC9E6".into(),
            accent_dim: "#B87AA0".into(),
            composer: "#A0D8EF".into(),
            composer_dim: "#6FA8C7".into(),
            text: "#E0E0E0".into(),
            dim: "#888888".into(),
            code_bg: "#1E1E28".into(),
            code_fg: "#78DCE8".into(),
            error: "#FF5555".into(),
            success: "#50C878".into(),
            warning: "#FFC832".into(),
        }
    }
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            left_pct: 22,
            center_pct: 56,
            right_pct: 22,
            header_lines: 3,
            status_lines: 1,
            help_lines: 2,
            composer_lines: 3,
        }
    }
}

impl Default for SpinnerConfig {
    fn default() -> Self {
        Self {
            style: "dot".into(),
            phrases: vec![
                "Orbiting…".into(),
                "Gathering context…".into(),
                "Working through it…".into(),
                "Forming a response…".into(),
                "Almost there…".into(),
            ],
        }
    }
}

impl Default for TabConfig {
    fn default() -> Self {
        Self {
            left: vec!["sessions".into(), "verbose".into()],
            show_help_bar: true,
            show_tick_count: false,
        }
    }
}

impl Theme {
    /// Load from `$ORBIT_HOME/tui.toml` if present; fall back to default.
    /// Never panics — malformed files use the default.
    pub fn load(home: &Path) -> Self {
        let path = home.join("tui.toml");
        match std::fs::read_to_string(&path) {
            Ok(raw) => toml::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Resolve all hex color strings to `Color::Rgb`.
    pub fn resolve(&self) -> ResolvedTheme {
        ResolvedTheme {
            colors: ResolvedColors {
                accent: parse_hex(&self.colors.accent, DEFAULT_ACCENT),
                accent_bright: parse_hex(&self.colors.accent_bright, DEFAULT_ACCENT_BRIGHT),
                accent_dim: parse_hex(&self.colors.accent_dim, DEFAULT_ACCENT_DIM),
                composer: parse_hex(&self.colors.composer, DEFAULT_COMPOSER),
                composer_dim: parse_hex(&self.colors.composer_dim, DEFAULT_COMPOSER_DIM),
                text: parse_hex(&self.colors.text, DEFAULT_TEXT),
                dim: parse_hex(&self.colors.dim, DEFAULT_DIM),
                code_bg: parse_hex(&self.colors.code_bg, DEFAULT_CODE_BG),
                code_fg: parse_hex(&self.colors.code_fg, DEFAULT_CODE_FG),
                error: parse_hex(&self.colors.error, DEFAULT_ERROR),
                success: parse_hex(&self.colors.success, DEFAULT_SUCCESS),
                warning: parse_hex(&self.colors.warning, DEFAULT_WARNING),
            },
            layout: self.layout.clone(),
            spinner: self.spinner.clone(),
            tabs: self.tabs.clone(),
        }
    }
}

/// Parse a hex color string (`#RRGGBB`) to `Color::Rgb`. Falls back to
/// `default` on any parse error.
fn parse_hex(hex: &str, default: Color) -> Color {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return default;
    }
    let r = match u8::from_str_radix(&hex[0..2], 16) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let g = match u8::from_str_radix(&hex[2..4], 16) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let b = match u8::from_str_radix(&hex[4..6], 16) {
        Ok(v) => v,
        Err(_) => return default,
    };
    Color::Rgb(r, g, b)
}

/// Spinner frame glyphs for the thinking indicator. The style name from the
/// theme maps to one of these sets. All glyphs are monospace-safe (present in
/// DejaVu Sans Mono).
pub fn spinner_frames(style: &str) -> &'static [&'static str] {
    match style {
        "pulse" => &["●", "◐", "○", "◐"],
        "jump" => &["⠁", "⠂", "⠄", "⠂"],
        "globe" => &["◐", "◓", "◑", "◒"],
        "moon" => &["🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"],
        "points" => &["∙", "•", "●", "•"],
        _ => &["✦", "✧", "⋆", "·", "⋆", "✧"], // "dot" default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_loads() {
        let theme = Theme::default();
        let resolved = theme.resolve();
        assert_eq!(resolved.colors.accent, DEFAULT_ACCENT);
        assert_eq!(resolved.colors.composer, DEFAULT_COMPOSER);
    }

    #[test]
    fn hex_parse_valid() {
        assert_eq!(
            parse_hex("#FFB3D9", DEFAULT_TEXT),
            Color::Rgb(255, 179, 217)
        );
        assert_eq!(parse_hex("39C5BB", DEFAULT_TEXT), Color::Rgb(57, 197, 187));
    }

    #[test]
    fn hex_parse_invalid_falls_back() {
        assert_eq!(parse_hex("not-a-color", DEFAULT_TEXT), DEFAULT_TEXT);
        assert_eq!(parse_hex("#ABC", DEFAULT_TEXT), DEFAULT_TEXT); // too short
        assert_eq!(parse_hex("#GGGGGG", DEFAULT_TEXT), DEFAULT_TEXT); // bad hex
    }

    #[test]
    fn toml_load_custom_theme() {
        let toml = r##"
[colors]
accent = "#0000FF"
composer = "#00FF00"

[layout]
left_pct = 30
center_pct = 40
right_pct = 30

[spinner]
style = "pulse"
phrases = ["Thinking..."]
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let resolved = theme.resolve();
        assert_eq!(resolved.colors.accent, Color::Rgb(0, 0, 255));
        assert_eq!(resolved.colors.composer, Color::Rgb(0, 255, 0));
        assert_eq!(resolved.layout.left_pct, 30);
        assert_eq!(resolved.spinner.style, "pulse");
        assert_eq!(resolved.spinner.phrases, vec!["Thinking..."]);
    }

    #[test]
    fn toml_partial_uses_defaults_for_missing() {
        let toml = r##"
[colors]
accent = "#FF0000"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let resolved = theme.resolve();
        assert_eq!(resolved.colors.accent, Color::Rgb(255, 0, 0));
        // Missing fields use defaults.
        assert_eq!(resolved.colors.composer, DEFAULT_COMPOSER);
        assert_eq!(resolved.layout.left_pct, 22);
    }

    #[test]
    fn missing_file_uses_default() {
        let theme = Theme::load(Path::new("/nonexistent/path"));
        let resolved = theme.resolve();
        assert_eq!(resolved.colors.accent, DEFAULT_ACCENT);
    }

    #[test]
    fn spinner_frames_dot() {
        let frames = spinner_frames("dot");
        assert!(frames.contains(&"✦"));
    }

    #[test]
    fn spinner_frames_pulse() {
        let frames = spinner_frames("pulse");
        assert!(frames.contains(&"●"));
    }

    #[test]
    fn spinner_frames_unknown_defaults_to_dot() {
        let frames = spinner_frames("nonexistent");
        assert!(frames.contains(&"✦"));
    }
}
