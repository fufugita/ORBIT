//! Theme tokens and capability tiers (docs/tui/DESIGN.md §3, §13.1, §13.4).
//!
//! One token vocabulary resolved once per colour tier (true colour, 256,
//! 16-colour ANSI, monochrome). Tiers step DOWN at runtime, never up
//! (H-5/H-7). No colour literal outside this file.
//!
//! tui.toml migration (§13.4): old keys keep working for one release and log
//! a deprecation notice; a user theme may recolour tokens but may not add
//! colours, animate anything, or change glyph meanings.

use ratatui::style::Color;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Colour tier ──────────────────────────────────────────────────────────────

/// Resolved once at startup, most specific first (§3.7). Steps down at
/// runtime, never up. `TERM=dumb` never reaches the TUI (DR-20 L7 gate).
/// Ordering is by capability (Mono < Ansi16 < T256 < TrueColor) — derived
/// manually because declaration order would give the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorTier {
    TrueColor,
    T256,
    Ansi16,
    Mono,
}

impl PartialOrd for ColorTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ColorTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(t: &ColorTier) -> u8 {
            match t {
                ColorTier::Mono => 0,
                ColorTier::Ansi16 => 1,
                ColorTier::T256 => 2,
                ColorTier::TrueColor => 3,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

impl ColorTier {
    /// Detect from the environment, most specific first (§12.1).
    pub fn detect(env: &dyn Fn(&str) -> Option<String>) -> Self {
        if env("NO_COLOR").is_some() {
            return Self::Mono;
        }
        if let Some(ct) = env("COLORTERM") {
            let ct = ct.to_ascii_lowercase();
            if ct == "truecolor" || ct == "24bit" {
                return Self::TrueColor;
            }
        }
        if env("WT_SESSION").is_some() {
            return Self::TrueColor;
        }
        if let Some(term) = env("TERM") {
            if term.contains("256color") {
                return Self::T256;
            }
        }
        Self::Ansi16
    }
}

// ── The token set (§13.1) ────────────────────────────────────────────────────
//
// One row per token: true colour, xterm-256, ANSI-16, mono. The 256 column
// uses explicit grey-ramp steps so surface bands stay distinguishable —
// nearest-match would put bg and surface both on 233 and erase the user band.

/// A single token resolved for one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub true_color: Color,
    pub c256: Color,
    pub c16: Color,
    pub mono: Color,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

/// All colour tokens, per §13.1.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// canvas
    pub bg: Token,
    /// user band, composer, code, approval fill
    pub surface: Token,
    /// chips, palette fill, unfocused cursor
    pub surface2: Token,
    /// focused cursor row
    pub wash: Token,
    /// hairlines, dividers
    pub rule: Token,
    /// focus rule, overlay frames, thumb
    pub rule_hi: Token,
    /// primary text
    pub ink: Token,
    /// secondary text
    pub ink2: Token,
    /// metadata, labels, hints
    pub muted: Token,
    /// placeholder, disabled
    pub faint: Token,
    /// brand, focus, selection bar, authority
    pub magenta: Token,
    /// startup star flash
    pub magenta_hi: Token,
    /// expanded-mark ring
    pub magenta_dim: Token,
    /// live
    pub cyan: Token,
    /// verified, online
    pub green: Token,
    /// caution
    pub amber: Token,
    /// failure
    pub red: Token,
    /// code: keyword
    pub syn_kw: Token,
    /// code: string
    pub syn_str: Token,
    /// code: number
    pub syn_num: Token,
}

impl Palette {
    pub const fn standard() -> Self {
        use Color::{Blue, Cyan, DarkGray, Green, Indexed, Magenta, Red, Reset, Yellow};
        Self {
            bg: Token {
                true_color: rgb(16, 14, 22),
                c256: Indexed(233),
                c16: Reset,
                mono: Reset,
            },
            surface: Token {
                true_color: rgb(23, 20, 31),
                c256: Indexed(234),
                c16: Reset,
                mono: Reset,
            },
            surface2: Token {
                true_color: rgb(33, 28, 43),
                c256: Indexed(235),
                c16: Reset,
                mono: Reset,
            },
            // wash marks the focused cursor row; mono/16 use DarkGray + the
            // renderer's selection indicator (§1: colour is the third signal).
            wash: Token {
                true_color: rgb(43, 22, 49),
                c256: Indexed(236),
                c16: DarkGray,
                mono: DarkGray,
            },
            rule: Token {
                true_color: rgb(45, 40, 57),
                c256: Indexed(236),
                c16: DarkGray,
                mono: DarkGray,
            },
            rule_hi: Token {
                true_color: rgb(70, 63, 85),
                c256: Indexed(239),
                c16: DarkGray,
                mono: DarkGray,
            },
            ink: Token {
                true_color: rgb(236, 232, 243),
                c256: Indexed(255),
                c16: Reset,
                mono: Reset,
            },
            ink2: Token {
                true_color: rgb(189, 182, 202),
                c256: Indexed(250),
                c16: Reset,
                mono: Reset,
            },
            muted: Token {
                true_color: rgb(139, 132, 153),
                c256: Indexed(103),
                c16: DarkGray,
                mono: DarkGray,
            },
            faint: Token {
                // Lifted from (101,95,115): section labels and hints need
                // to stay legible on the dark bg (WCAG-ish ≥4.5:1).
                true_color: rgb(117, 110, 133),
                c256: Indexed(60),
                c16: DarkGray,
                mono: DarkGray,
            },
            // In mono, emphasis is BOLD — the renderer applies Modifier::BOLD
            // for magenta/cyan/red (§13.1 mono column); the Color here is Reset.
            magenta: Token {
                true_color: rgb(227, 86, 208),
                c256: Indexed(170),
                c16: Magenta,
                mono: Reset,
            },
            magenta_hi: Token {
                true_color: rgb(245, 140, 228),
                c256: Indexed(212),
                c16: Magenta,
                mono: Reset,
            },
            magenta_dim: Token {
                true_color: rgb(142, 60, 127),
                c256: Indexed(96),
                c16: Magenta,
                mono: DarkGray,
            },
            cyan: Token {
                true_color: rgb(92, 198, 221),
                c256: Indexed(81),
                c16: Cyan,
                mono: Reset,
            },
            green: Token {
                true_color: rgb(98, 204, 142),
                c256: Indexed(78),
                c16: Green,
                mono: Reset,
            },
            amber: Token {
                true_color: rgb(233, 178, 82),
                c256: Indexed(179),
                c16: Yellow,
                mono: Reset,
            },
            red: Token {
                true_color: rgb(240, 106, 94),
                c256: Indexed(203),
                c16: Red,
                mono: Reset,
            },
            syn_kw: Token {
                true_color: rgb(195, 166, 255),
                c256: Indexed(183),
                c16: Blue,
                mono: Reset,
            },
            syn_str: Token {
                true_color: rgb(166, 214, 160),
                c256: Indexed(151),
                c16: Green,
                mono: Reset,
            },
            syn_num: Token {
                true_color: rgb(239, 192, 141),
                c256: Indexed(180),
                c16: Yellow,
                mono: Reset,
            },
        }
    }

    /// Resolve a token for a tier.
    pub fn resolve(&self, tier: ColorTier) -> ResolvedPalette {
        let f = |t: &Token| match tier {
            ColorTier::TrueColor => t.true_color,
            ColorTier::T256 => t.c256,
            ColorTier::Ansi16 => t.c16,
            ColorTier::Mono => t.mono,
        };
        ResolvedPalette {
            tier,
            bg: f(&self.bg),
            surface: f(&self.surface),
            surface2: f(&self.surface2),
            wash: f(&self.wash),
            rule: f(&self.rule),
            rule_hi: f(&self.rule_hi),
            ink: f(&self.ink),
            ink2: f(&self.ink2),
            muted: f(&self.muted),
            faint: f(&self.faint),
            magenta: f(&self.magenta),
            magenta_hi: f(&self.magenta_hi),
            magenta_dim: f(&self.magenta_dim),
            cyan: f(&self.cyan),
            green: f(&self.green),
            amber: f(&self.amber),
            red: f(&self.red),
            syn_kw: f(&self.syn_kw),
            syn_str: f(&self.syn_str),
            syn_num: f(&self.syn_num),
        }
    }
}

/// Palette resolved for one tier — what the renderer uses.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedPalette {
    pub tier: ColorTier,
    pub bg: Color,
    pub surface: Color,
    pub surface2: Color,
    pub wash: Color,
    pub rule: Color,
    pub rule_hi: Color,
    pub ink: Color,
    pub ink2: Color,
    pub muted: Color,
    pub faint: Color,
    pub magenta: Color,
    pub magenta_hi: Color,
    pub magenta_dim: Color,
    pub cyan: Color,
    pub green: Color,
    pub amber: Color,
    pub red: Color,
    pub syn_kw: Color,
    pub syn_str: Color,
    pub syn_num: Color,
}

// ── User overrides (tui.toml, §13.4) ─────────────────────────────────────────

/// A user theme may recolour TOKENS (true-colour hex only). It may not add
/// colours, animate anything, or change glyph meanings. Old keys are accepted
/// for one release and mapped with a deprecation notice.
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

    // ── deprecated keys (§13.4) → mapped, one release ──
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

/// Layout — columns and measure, not percentages (§13.4). Fixed rows:
/// header 1, status 1, help 0 (the `?` overlay replaces the help bar),
/// composer auto.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LayoutConfig {
    pub rail_left: u16,
    pub rail_right: u16,
    pub measure: u16,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            rail_left: 24,
            rail_right: 40,
            measure: 100,
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

    /// Build the palette: standard tokens, then apply user overrides
    /// (including deprecated-key mapping). Returns the palette plus any
    /// deprecation notices for the operator.
    pub fn palette(&self) -> (Palette, Vec<String>) {
        let mut p = Palette::standard();
        let mut notices = Vec::new();
        let u = &self.colors;

        // Deprecated key mapping (§13.4) — applied only when the new key is
        // absent, so a mixed file behaves predictably.
        let dep = |notices: &mut Vec<String>, old: &str, new: &str| {
            notices.push(format!(
                "tui.toml: '{old}' is deprecated; use '{new}' (supported one release)"
            ));
        };
        if u.accent.is_some() && u.magenta.is_none() {
            p.magenta.true_color = parse_hex(u.accent.as_deref().unwrap(), p.magenta.true_color);
            dep(&mut notices, "accent", "magenta");
        }
        if u.accent_dim.is_some() && u.magenta_dim.is_none() {
            p.magenta_dim.true_color =
                parse_hex(u.accent_dim.as_deref().unwrap(), p.magenta_dim.true_color);
            dep(&mut notices, "accent_dim", "magenta_dim");
        }
        // accent_bright: removed (magenta_hi is startup-only, not themeable).
        if u.accent_bright.is_some() {
            notices
                .push("tui.toml: 'accent_bright' is removed (magenta_hi is startup-only)".into());
        }
        // composer/composer_dim: removed (composer uses magenta prompt + ink text).
        if u.composer.is_some() || u.composer_dim.is_some() {
            notices.push(
                "tui.toml: 'composer'/'composer_dim' are removed (composer uses magenta/ink)"
                    .into(),
            );
        }
        if u.text.is_some() && u.ink.is_none() {
            p.ink.true_color = parse_hex(u.text.as_deref().unwrap(), p.ink.true_color);
            dep(&mut notices, "text", "ink");
        }
        if u.dim.is_some() && u.muted.is_none() {
            p.muted.true_color = parse_hex(u.dim.as_deref().unwrap(), p.muted.true_color);
            dep(&mut notices, "dim", "muted");
        }
        if u.code_bg.is_some() && u.surface.is_none() {
            // code bands sit on surface in the new system; honour the old key
            // by leaving surface alone but noting the change.
            notices.push("tui.toml: 'code_bg' is removed (code uses surface)".into());
        }
        if u.code_fg.is_some() {
            notices.push("tui.toml: 'code_fg' is removed (code uses ink + syn_*)".into());
        }
        if u.error.is_some() && u.red.is_none() {
            p.red.true_color = parse_hex(u.error.as_deref().unwrap(), p.red.true_color);
            dep(&mut notices, "error", "red");
        }
        if u.success.is_some() && u.green.is_none() {
            p.green.true_color = parse_hex(u.success.as_deref().unwrap(), p.green.true_color);
            dep(&mut notices, "success", "green");
        }
        if u.warning.is_some() && u.amber.is_none() {
            p.amber.true_color = parse_hex(u.warning.as_deref().unwrap(), p.amber.true_color);
            dep(&mut notices, "warning", "amber");
        }

        // New-key overrides.
        let apply = |t: &mut Token, v: &Option<String>| {
            if let Some(hex) = v {
                t.true_color = parse_hex(hex, t.true_color);
            }
        };
        apply(&mut p.bg, &u.bg);
        apply(&mut p.surface, &u.surface);
        apply(&mut p.surface2, &u.surface2);
        apply(&mut p.wash, &u.wash);
        apply(&mut p.rule, &u.rule);
        apply(&mut p.rule_hi, &u.rule_hi);
        apply(&mut p.ink, &u.ink);
        apply(&mut p.ink2, &u.ink2);
        apply(&mut p.muted, &u.muted);
        apply(&mut p.faint, &u.faint);
        apply(&mut p.magenta, &u.magenta);
        apply(&mut p.magenta_hi, &u.magenta_hi);
        apply(&mut p.magenta_dim, &u.magenta_dim);
        apply(&mut p.cyan, &u.cyan);
        apply(&mut p.green, &u.green);
        apply(&mut p.amber, &u.amber);
        apply(&mut p.red, &u.red);
        apply(&mut p.syn_kw, &u.syn_kw);
        apply(&mut p.syn_str, &u.syn_str);
        apply(&mut p.syn_num, &u.syn_num);

        (p, notices)
    }
}

/// Parse a hex colour string (`#RRGGBB`) to `Color::Rgb`. Falls back to
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

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(ek, _)| *ek == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn tier_detect_truecolor() {
        let f = env(&[("COLORTERM", "truecolor")]);
        assert_eq!(ColorTier::detect(&f), ColorTier::TrueColor);
    }

    #[test]
    fn tier_detect_256() {
        let f = env(&[("TERM", "xterm-256color")]);
        assert_eq!(ColorTier::detect(&f), ColorTier::T256);
    }

    #[test]
    fn tier_detect_no_color_wins() {
        let f = env(&[("NO_COLOR", "1"), ("COLORTERM", "truecolor")]);
        assert_eq!(ColorTier::detect(&f), ColorTier::Mono);
    }

    #[test]
    fn tier_detect_default_16() {
        let f = env(&[]);
        assert_eq!(ColorTier::detect(&f), ColorTier::Ansi16);
    }

    #[test]
    fn tier_steps_down_never_up() {
        assert!(ColorTier::Mono < ColorTier::Ansi16);
        assert!(ColorTier::Ansi16 < ColorTier::T256);
        assert!(ColorTier::T256 < ColorTier::TrueColor);
    }

    #[test]
    fn palette_resolves_per_tier() {
        let p = Palette::standard();
        let tc = p.resolve(ColorTier::TrueColor);
        let t256 = p.resolve(ColorTier::T256);
        let mono = p.resolve(ColorTier::Mono);
        assert_eq!(tc.bg, Color::Rgb(16, 14, 22));
        assert_eq!(t256.bg, Color::Indexed(233));
        // mono: emphasis is Modifier::BOLD at render time; Color is Reset.
        assert_eq!(mono.magenta, Color::Reset);
        assert_eq!(mono.muted, Color::DarkGray);
    }

    #[test]
    fn surface_bands_distinct_in_256() {
        // §13.1 note: nearest-match would put bg and surface both on 233 and
        // erase the user band. Explicit steps must differ.
        let p = Palette::standard().resolve(ColorTier::T256);
        assert_ne!(p.bg, p.surface);
        assert_ne!(p.surface, p.surface2);
    }

    #[test]
    fn magenta_resets_in_mono_bold_at_render() {
        let p = Palette::standard().resolve(ColorTier::Mono);
        // Colour is the third signal (§1): in mono the emphasis tokens all
        // reset to default fg — the renderer adds Modifier::BOLD — and
        // green/amber rely on glyph + word alone.
        assert_eq!(p.magenta, Color::Reset);
        assert_eq!(p.cyan, Color::Reset);
        assert_eq!(p.red, Color::Reset);
        assert_eq!(p.green, Color::Reset);
        assert_eq!(p.amber, Color::Reset);
    }

    #[test]
    fn user_override_recolors_token() {
        let toml = r##"
[colors]
magenta = "#FF00FF"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let (p, notices) = theme.palette();
        assert!(notices.is_empty());
        assert_eq!(p.magenta.true_color, Color::Rgb(255, 0, 255));
        // other tokens untouched
        assert_eq!(p.ink.true_color, Color::Rgb(236, 232, 243));
    }

    #[test]
    fn deprecated_keys_map_with_notice() {
        let toml = r##"
[colors]
accent = "#0000FF"
text = "#00FF00"
error = "#FF0000"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let (p, notices) = theme.palette();
        assert_eq!(p.magenta.true_color, Color::Rgb(0, 0, 255));
        assert_eq!(p.ink.true_color, Color::Rgb(0, 255, 0));
        assert_eq!(p.red.true_color, Color::Rgb(255, 0, 0));
        assert!(notices.iter().any(|n| n.contains("'accent'")));
        assert!(notices.iter().any(|n| n.contains("'text'")));
        assert!(notices.iter().any(|n| n.contains("'error'")));
    }

    #[test]
    fn removed_keys_notice_only() {
        let toml = r##"
[colors]
accent_bright = "#FFFFFF"
composer = "#FFFFFF"
code_bg = "#000000"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let (_, notices) = theme.palette();
        assert!(notices
            .iter()
            .any(|n| n.contains("accent_bright' is removed")));
        assert!(notices.iter().any(|n| n.contains("'composer'")));
        assert!(notices.iter().any(|n| n.contains("'code_bg'")));
    }

    #[test]
    fn new_key_wins_over_deprecated() {
        let toml = r##"
[colors]
accent = "#0000FF"
magenta = "#FF00FF"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let (p, _) = theme.palette();
        assert_eq!(p.magenta.true_color, Color::Rgb(255, 0, 255));
    }

    #[test]
    fn hex_parse_invalid_falls_back() {
        assert_eq!(parse_hex("not-a-color", Color::Reset), Color::Reset);
        assert_eq!(parse_hex("#ABC", Color::Reset), Color::Reset);
        assert_eq!(parse_hex("#GGGGGG", Color::Reset), Color::Reset);
        assert_eq!(parse_hex("#E356D0", Color::Reset), Color::Rgb(227, 86, 208));
    }

    #[test]
    fn missing_file_uses_default() {
        let theme = Theme::load(Path::new("/nonexistent/path"));
        let (p, notices) = theme.palette();
        assert!(notices.is_empty());
        assert_eq!(p.magenta.true_color, Color::Rgb(227, 86, 208));
    }

    #[test]
    fn malformed_file_uses_default() {
        let theme: Theme = toml::from_str("!!!not toml!!!").unwrap_or_default();
        let (p, _) = theme.palette();
        assert_eq!(p.magenta.true_color, Color::Rgb(227, 86, 208));
    }

    #[test]
    fn layout_defaults_are_columns_not_percent() {
        let l = LayoutConfig::default();
        // herdr-style bordered panes need wider rails: the border eats 2
        // columns each side, so 24/40 keep the same content budget the old
        // 22/28 borderless rails had (22 ≈ 24-2, 28 < 40-2 for sub-lines).
        assert_eq!(l.rail_left, 24);
        assert_eq!(l.rail_right, 40);
        assert_eq!(l.measure, 100);
    }

    #[test]
    fn capabilities_default_auto() {
        let c = CapabilitiesConfig::default();
        assert_eq!(c.mode, "auto");
        assert_eq!(c.glyphs, "auto");
        assert!(!c.reduced);
        assert_eq!(c.brand, "anim");
        assert!(!c.bell_on_approval);
    }
}

// ── Capabilities resolver (§3.7, §11.3, §13.4) ───────────────────────────────

/// Glyph set — unicode by default, ASCII tier keeps every chrome cell
/// printable (invariant_ascii_tier_is_ascii, §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlyphSet {
    Unicode,
    Ascii,
}

/// Brand tier (§8): full (animated star) | static | text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrandTier {
    Anim,
    Static,
    Text,
    Off,
}

impl BrandTier {
    fn degrade(self, floor: Self) -> Self {
        self.max(floor)
    }
}

impl PartialOrd for BrandTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BrandTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(tier: &BrandTier) -> u8 {
            match tier {
                BrandTier::Anim => 0,
                BrandTier::Static => 1,
                BrandTier::Text => 2,
                BrandTier::Off => 3,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

/// All display capabilities, resolved ONCE at startup from environment +
/// tui.toml. Steps down at runtime, never up.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub color: ColorTier,
    pub glyphs: GlyphSet,
    pub brand: BrandTier,
    pub reduced_motion: bool,
    pub ambiguous_wide: bool,
    /// D17: tui.toml `[color] bell_on_approval = true` — ring the terminal
    /// bell when an approval card appears (audible attention for
    /// background-watching operators).
    pub bell_on_approval: bool,
}

/// The complete design context the renderer consumes: the palette resolved
/// for the detected tier, plus capability flags. Built once in `run()`.
/// (Clone but not Copy — `notices` owns strings.)
#[derive(Debug, Clone)]
pub struct Design {
    pub palette: ResolvedPalette,
    pub caps: Capabilities,
    /// Rail widths in columns (LayoutConfig, §13.4) — (left, right).
    pub layout_rails: (u16, u16),
    /// Prose measure cap in columns (§5.2). Content centers past measure+16.
    pub layout_measure: u16,
    /// Deprecation notices from tui.toml migration (§13.4), shown once at
    /// startup, then dropped.
    pub notices: Vec<String>,
}

impl Design {
    /// Resolve from the environment + a loaded theme. `env` is injectable for
    /// tests. Order (§3.7): tui.toml override > NO_COLOR > COLORTERM > TERM.
    pub fn resolve(theme: &Theme, env: &dyn Fn(&str) -> Option<String>) -> Self {
        let mut color = ColorTier::detect(env);
        // §12.1: config can only lower the detected tier. NO_COLOR is sticky.
        let no_color = env("NO_COLOR").is_some();
        match theme.capabilities.mode.as_str() {
            "truecolor" if color == ColorTier::TrueColor => {}
            "256" if color >= ColorTier::T256 => color = ColorTier::T256,
            "16" if color >= ColorTier::Ansi16 => color = ColorTier::Ansi16,
            "mono" => color = ColorTier::Mono,
            "truecolor" | "256" | "16" => {}
            _ => {} // "auto"
        }
        if no_color {
            color = ColorTier::Mono;
        }
        // §12.2: the first non-empty LC_ALL/LC_CTYPE/LANG decides UTF-8.
        // A non-UTF-8 locale is a hard downgrade no config can override.
        // No locale vars at all → assume UTF-8 (the modern default); Windows
        // Terminal reports no vars either, so WT_SESSION also implies UTF-8.
        let locale_utf8 = [env("LC_ALL"), env("LC_CTYPE"), env("LANG")]
            .into_iter()
            .flatten()
            .find(|value| !value.is_empty())
            .map(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("utf-8") || lower.contains("utf8")
            })
            .unwrap_or(true);
        let requested_glyphs = match theme.capabilities.glyphs.as_str() {
            "ascii" => GlyphSet::Ascii,
            _ => GlyphSet::Unicode,
        };
        let auto_glyphs = theme.capabilities.glyphs == "auto";
        let probe_required = locale_utf8 && auto_glyphs;
        let ambiguous_wide = probe_required && crate::terminal::probe_ambiguous_width();
        let glyphs = if !locale_utf8 || requested_glyphs == GlyphSet::Ascii || ambiguous_wide {
            GlyphSet::Ascii
        } else {
            GlyphSet::Unicode
        };
        let reduced_motion =
            theme.capabilities.reduced || env("ORBIT_REDUCED_MOTION").as_deref() == Some("1");
        let configured_brand = match theme.capabilities.brand.as_str() {
            "anim" => BrandTier::Anim,
            "static" => BrandTier::Static,
            "text" => BrandTier::Text,
            _ => BrandTier::Off,
        };
        let mut brand = configured_brand;
        if no_color || glyphs == GlyphSet::Ascii {
            brand = brand.degrade(BrandTier::Text);
        }
        if reduced_motion {
            brand = brand.degrade(BrandTier::Static);
        }
        let (palette, notices) = theme.palette();
        Design {
            palette: palette.resolve(color),
            caps: Capabilities {
                color,
                glyphs,
                brand,
                reduced_motion,
                ambiguous_wide,
                bell_on_approval: theme.capabilities.bell_on_approval,
            },
            layout_rails: (theme.layout.rail_left, theme.layout.rail_right),
            layout_measure: theme.layout.measure,
            notices,
        }
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn design_resolves_anim_by_default() {
        let theme = Theme::default();
        let d = Design::resolve(&theme, &no_env);
        assert_eq!(d.caps.color, ColorTier::Ansi16);
        assert_eq!(d.caps.glyphs, GlyphSet::Unicode);
        assert_eq!(d.caps.brand, BrandTier::Anim);
        assert!(!d.caps.reduced_motion);
        assert!(d.notices.is_empty());
    }

    #[test]
    fn design_toml_mode_overrides_env() {
        let toml = r##"
[color]
mode = "mono"
glyphs = "ascii"
brand = "text"
reduced = true
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let env = |k: &str| {
            if k == "COLORTERM" {
                Some("truecolor".to_string())
            } else {
                None
            }
        };
        let d = Design::resolve(&theme, &env);
        assert_eq!(d.caps.color, ColorTier::Mono);
        assert_eq!(d.caps.glyphs, GlyphSet::Ascii);
        assert_eq!(d.caps.brand, BrandTier::Text);
        assert!(d.caps.reduced_motion);
    }

    #[test]
    fn auto_glyphs_detect_locale() {
        // "auto" + UTF-8 locale → unicode.
        let t: Theme = toml::from_str("[color]\nglyphs = \"auto\"\n").unwrap();
        let d = Design::resolve(&t, &|k| (k == "LANG").then(|| "en_US.UTF-8".into()));
        assert_eq!(d.caps.glyphs, GlyphSet::Unicode);
        // "auto" + C locale → ascii (§11.3: a non-UTF-8 locale cannot render
        // the unicode set).
        let d = Design::resolve(&t, &|k| (k == "LANG").then(|| "C".into()));
        assert_eq!(d.caps.glyphs, GlyphSet::Ascii);
        // "auto" + no locale vars at all → unicode (the common modern default).
        let d = Design::resolve(&t, &|_| None);
        assert_eq!(d.caps.glyphs, GlyphSet::Unicode);
    }

    #[test]
    fn design_no_color_env_beats_toml_auto() {
        let theme = Theme::default();
        let env = |k: &str| match k {
            "NO_COLOR" => Some("1".to_string()),
            "COLORTERM" => Some("truecolor".to_string()),
            _ => None,
        };
        let d = Design::resolve(&theme, &env);
        assert_eq!(d.caps.color, ColorTier::Mono);
    }

    #[test]
    fn design_carries_deprecation_notices() {
        let toml = r##"
[colors]
accent = "#0000FF"
"##;
        let theme: Theme = toml::from_str(toml).unwrap();
        let d = Design::resolve(&theme, &no_env);
        assert!(d.notices.iter().any(|n| n.contains("'accent'")));
    }

    #[test]
    fn bell_on_approval_plumbs_through_design() {
        // D17: the [color] table's bell_on_approval reaches Capabilities.
        let theme = Theme {
            capabilities: CapabilitiesConfig {
                bell_on_approval: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let d = Design::resolve(&theme, &|_| None);
        assert!(d.caps.bell_on_approval);
        // And the default stays off.
        let off = Design::resolve(&Theme::default(), &|_| None);
        assert!(!off.caps.bell_on_approval);
    }
}
