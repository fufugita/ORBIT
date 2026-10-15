//! The prototype's palette, verbatim (§ colour tokens). Colour means
//! state or content; each panel has an identity colour.

use super::canvas::Rgb;

pub const APP: Rgb = (0x08, 0x07, 0x0C);
pub const SIDEBAR: Rgb = (0x0C, 0x0A, 0x11);
pub const PANEL: Rgb = (0x10, 0x0E, 0x16);
pub const RAISE: Rgb = (0x18, 0x15, 0x1F);
pub const RAISE2: Rgb = (0x20, 0x1C, 0x2A);
pub const INSET: Rgb = (0x0B, 0x0A, 0x10);
pub const TOPBAR: Rgb = (0x11, 0x0E, 0x18);
pub const RULE: Rgb = (0x2A, 0x25, 0x34);
pub const RULE_HI: Rgb = (0x4A, 0x42, 0x58);
pub const INK: Rgb = (0xEE, 0xEA, 0xF5);
pub const INK2: Rgb = (0xC0, 0xB9, 0xCD);
pub const MUTED: Rgb = (0x8C, 0x85, 0x99);
pub const FAINT: Rgb = (0x62, 0x5C, 0x70);
pub const WHITE: Rgb = (0xFF, 0xFF, 0xFF);
pub const MAGENTA: Rgb = (0xE3, 0x56, 0xD0);
pub const MAGENTA_HI: Rgb = (0xFF, 0x7B, 0xEA);
pub const MAGENTA_DIM: Rgb = (0x8E, 0x3C, 0x7F);
pub const ON_ACCENT: Rgb = (0x17, 0x09, 0x1A);
pub const VIOLET: Rgb = (0xB3, 0x9D, 0xFF);
pub const BLUE: Rgb = (0x7A, 0xA2, 0xF7);
pub const CYAN: Rgb = (0x5C, 0xC6, 0xDD);
pub const GREEN: Rgb = (0x62, 0xCC, 0x8E);
pub const AMBER: Rgb = (0xE9, 0xB2, 0x52);
pub const RED: Rgb = (0xF0, 0x6A, 0x5E);
pub const ADD_BG: Rgb = (0x11, 0x29, 0x1B);
pub const DEL_BG: Rgb = (0x36, 0x16, 0x1A);
pub const ADD_FG: Rgb = (0x86, 0xDC, 0xA0);
pub const DEL_FG: Rgb = (0xF5, 0x97, 0x8F);
pub const HUNK: Rgb = (0x6B, 0x88, 0xC9);
pub const GRAD0: Rgb = (0x3B, 0x12, 0x58);
pub const MODE_DEFAULT_BG: Rgb = (0x3A, 0x34, 0x48);

/// The brand gradient (wordmark and top bar only).
pub const BRAND: [Rgb; 4] = [
    (0xE3, 0x56, 0xD0),
    (0xB0, 0x7B, 0xF2),
    (0x7F, 0xA5, 0xF5),
    (0x5C, 0xC6, 0xDD),
];

/// Sample the brand ramp at `u` in 0..=1.
pub fn brand_at(u: f32) -> Rgb {
    let u = u.clamp(0.0, 1.0);
    let n = (BRAND.len() - 1) as f32;
    let i = ((u * n).floor() as usize).min(BRAND.len() - 2);
    super::canvas::mix(BRAND[i], BRAND[i + 1], u * n - i as f32)
}

/// Semantic colors resolved once for a frame, before any tint or interpolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub app: Rgb,
    pub sidebar: Rgb,
    pub panel: Rgb,
    pub raise: Rgb,
    pub raise2: Rgb,
    pub inset: Rgb,
    pub topbar: Rgb,
    pub rule: Rgb,
    pub rule_hi: Rgb,
    pub ink: Rgb,
    pub ink2: Rgb,
    pub muted: Rgb,
    pub faint: Rgb,
    pub white: Rgb,
    pub magenta: Rgb,
    pub magenta_hi: Rgb,
    pub magenta_dim: Rgb,
    pub on_accent: Rgb,
    pub violet: Rgb,
    pub blue: Rgb,
    pub cyan: Rgb,
    pub green: Rgb,
    pub amber: Rgb,
    pub red: Rgb,
    pub add_bg: Rgb,
    pub del_bg: Rgb,
    pub add_fg: Rgb,
    pub del_fg: Rgb,
    pub hunk: Rgb,
    pub grad0: Rgb,
    pub mode_default_bg: Rgb,
    pub syn_kw: Rgb,
    pub syn_str: Rgb,
    pub syn_num: Rgb,
    pub syn_comment: Rgb,
    pub selection: Rgb,
    pub focus: Rgb,
    pub cyan_hi: Rgb,
    pub cyan_dim: Rgb,
    pub brand: [Rgb; 4],
    pub focus_override: Option<Rgb>,
    pub selection_override: Option<Rgb>,
}
impl Default for Palette {
    fn default() -> Self {
        Self {
            app: APP,
            sidebar: SIDEBAR,
            panel: PANEL,
            raise: RAISE,
            raise2: RAISE2,
            inset: INSET,
            topbar: TOPBAR,
            rule: RULE,
            rule_hi: RULE_HI,
            ink: INK,
            ink2: INK2,
            muted: MUTED,
            faint: FAINT,
            white: WHITE,
            magenta: MAGENTA,
            magenta_hi: MAGENTA_HI,
            magenta_dim: MAGENTA_DIM,
            on_accent: ON_ACCENT,
            violet: VIOLET,
            blue: BLUE,
            cyan: CYAN,
            green: GREEN,
            amber: AMBER,
            red: RED,
            add_bg: ADD_BG,
            del_bg: DEL_BG,
            add_fg: ADD_FG,
            del_fg: DEL_FG,
            hunk: HUNK,
            grad0: GRAD0,
            mode_default_bg: MODE_DEFAULT_BG,
            syn_kw: INK,
            syn_str: INK,
            syn_num: INK,
            syn_comment: MUTED,
            selection: super::canvas::mix(PANEL, CYAN, 0.32),
            focus: MAGENTA,
            cyan_hi: CYAN,
            cyan_dim: super::canvas::mix(CYAN, PANEL, 0.5),
            brand: BRAND,
            focus_override: None,
            selection_override: None,
        }
    }
}
impl Palette {
    pub fn from_profile(profile: &orbit_frontend_protocol::customization::Profile) -> Self {
        let mut p = Self::default();
        match profile.theme.as_str() {
            "midnight" => {
                p.app = (5, 12, 25);
                p.panel = (12, 23, 39);
                p.raise = (20, 35, 54);
                p.raise2 = (28, 45, 66);
                p.sidebar = (8, 17, 30);
                p.inset = (6, 15, 28);
                p.topbar = (9, 20, 35);
                p.rule = (39, 61, 85);
                p.rule_hi = (64, 93, 123);
                p.magenta = (98, 170, 255);
                p.magenta_hi = (155, 203, 255);
                p.magenta_dim = (48, 91, 145);
                p.cyan = (76, 214, 211);
                p.violet = (171, 161, 255);
                p.blue = (114, 172, 255);
            }
            "paper" => {
                p.app = (245, 243, 235);
                p.panel = (255, 253, 246);
                p.raise = (237, 233, 222);
                p.raise2 = (228, 223, 210);
                p.sidebar = (239, 236, 226);
                p.inset = (246, 243, 233);
                p.topbar = (233, 229, 216);
                p.rule = (194, 186, 168);
                p.rule_hi = (132, 121, 101);
                p.ink = (37, 34, 29);
                p.ink2 = (72, 65, 53);
                p.muted = (99, 89, 73);
                p.faint = (120, 108, 87);
                p.white = (0, 0, 0);
                p.magenta = (143, 43, 116);
                p.magenta_hi = (112, 20, 87);
                p.magenta_dim = (169, 94, 143);
                p.on_accent = (255, 253, 246);
                p.cyan = (14, 108, 128);
                p.violet = (111, 68, 157);
                p.blue = (40, 96, 155);
                p.green = (35, 117, 69);
                p.amber = (139, 88, 18);
                p.red = (176, 49, 41);
            }
            _ => {}
        }
        let tokens = profile.resolved_tokens();
        let color = |name: &str| {
            tokens.get(name).and_then(|s| {
                Some((
                    u8::from_str_radix(s.get(1..3)?, 16).ok()?,
                    u8::from_str_radix(s.get(3..5)?, 16).ok()?,
                    u8::from_str_radix(s.get(5..7)?, 16).ok()?,
                ))
            })
        };
        if let Some(v) = color("bg").or_else(|| color("background")) {
            p.app = v;
        }
        if let Some(v) = color("surface") {
            p.panel = v;
            p.sidebar = v;
            p.inset = v;
        }
        if let Some(v) = color("surface2") {
            p.raise = v;
            p.raise2 = v;
            p.topbar = v;
        }
        if let Some(v) = color("rule") {
            p.rule = v;
        }
        if let Some(v) = color("rule_hi") {
            p.rule_hi = v;
        }
        if let Some(v) = color("ink") {
            p.ink = v;
        }
        if let Some(v) = color("ink2") {
            p.ink2 = v;
        }
        if let Some(v) = color("muted") {
            p.muted = v;
        }
        if let Some(v) = color("faint") {
            p.faint = v;
        }
        if let Some(v) = color("magenta") {
            p.magenta = v;
        }
        if let Some(v) = color("magenta_hi") {
            p.magenta_hi = v;
        }
        if let Some(v) = color("magenta_dim") {
            p.magenta_dim = v;
        }
        if let Some(v) = color("cyan") {
            p.cyan = v;
        }
        if let Some(v) = color("green") {
            p.green = v;
        }
        if let Some(v) = color("amber") {
            p.amber = v;
        }
        if let Some(v) = color("red") {
            p.red = v;
        }
        if let Some(v) = color("violet") {
            p.violet = v;
        }
        if let Some(v) = color("blue") {
            p.blue = v;
        }
        if let Some(v) = color("foreground") {
            if color("ink").is_none() {
                p.ink = v;
            }
        }
        if let Some(v) = color("border") {
            if color("rule").is_none() {
                p.rule = v;
            }
        }
        if let Some(v) = color("app") {
            p.app = v;
        }
        if let Some(v) = color("sidebar") {
            p.sidebar = v;
        }
        if let Some(v) = color("panel") {
            p.panel = v;
        }
        if let Some(v) = color("raise") {
            p.raise = v;
        }
        if let Some(v) = color("raise2") {
            p.raise2 = v;
        }
        if let Some(v) = color("inset") {
            p.inset = v;
        }
        if let Some(v) = color("topbar") {
            p.topbar = v;
        }
        if let Some(v) = color("white") {
            p.white = v;
        }
        if let Some(v) = color("on_accent") {
            p.on_accent = v;
        }
        // Derived operands are already resolved; equal RGB values never remap a role twice.
        p.selection =
            color("selection").unwrap_or_else(|| super::canvas::mix(p.panel, p.cyan, 0.32));
        p.focus = color("focus").unwrap_or(p.magenta);
        p.syn_kw = color("syn_kw").unwrap_or(p.ink);
        p.syn_str = color("syn_str").unwrap_or(p.ink);
        p.syn_num = color("syn_num").unwrap_or(p.ink);
        p.syn_comment = color("syn_comment").unwrap_or(p.muted);
        p.cyan_hi = color("cyan_hi").unwrap_or(p.cyan);
        p.cyan_dim = color("cyan_dim").unwrap_or_else(|| super::canvas::mix(p.cyan, p.panel, 0.5));
        p.mode_default_bg = super::canvas::mix(p.panel, p.rule_hi, 0.5);
        if profile.theme == "orbit" && tokens.is_empty() {
            p.mode_default_bg = MODE_DEFAULT_BG;
        }
        p.add_bg = super::canvas::tint(p.green, p.panel, 0.12);
        p.del_bg = super::canvas::tint(p.red, p.panel, 0.12);
        p.add_fg = super::canvas::mix(p.green, p.ink, 0.3);
        p.del_fg = super::canvas::mix(p.red, p.ink, 0.3);
        p.hunk = p.violet;
        p.grad0 = super::canvas::mix(p.magenta, p.app, 0.75);
        p.brand = [
            p.magenta,
            super::canvas::mix(p.magenta, p.violet, 0.6),
            super::canvas::mix(p.blue, p.cyan, 0.2),
            p.cyan,
        ];
        if let Some(v) = color("add_bg") {
            p.add_bg = v;
        }
        if let Some(v) = color("del_bg") {
            p.del_bg = v;
        }
        if let Some(v) = color("add_fg") {
            p.add_fg = v;
        }
        if let Some(v) = color("del_fg") {
            p.del_fg = v;
        }
        if let Some(v) = color("hunk") {
            p.hunk = v;
        }
        if let Some(v) = color("grad0") {
            p.grad0 = v;
        }
        if let Some(v) = color("mode_default_bg") {
            p.mode_default_bg = v;
        }
        if let Some(v) = color("brand0") {
            p.brand[0] = v;
        }
        if let Some(v) = color("brand1") {
            p.brand[1] = v;
        }
        if let Some(v) = color("brand2") {
            p.brand[2] = v;
        }
        if let Some(v) = color("brand3") {
            p.brand[3] = v;
        }
        p.focus_override = color("focus");
        p.selection_override = color("selection").or_else(|| color("wash"));
        if profile.theme == "orbit" && tokens.is_empty() {
            p = Self::default();
        }
        p
    }
    pub fn brand_at(self, u: f32) -> Rgb {
        let u = u.clamp(0.0, 1.0);
        let i = ((u * 3.0).floor() as usize).min(2);
        super::canvas::mix(self.brand[i], self.brand[i + 1], u * 3.0 - i as f32)
    }
    pub fn token(self, t: crate::proto::core::Token) -> Rgb {
        if self == Self::default() {
            return t.rgb();
        }
        use crate::proto::core::Token::*;
        match t {
            App => self.app,
            Panel | Bg => self.panel,
            Raise | Surface2 => self.raise,
            Inset => self.inset,
            Rule => self.rule,
            Ink => self.ink,
            Muted => self.muted,
            Magenta => self.magenta,
            Cyan => self.cyan,
            Green => self.green,
            Red => self.red,
            Amber => self.amber,
            Violet => self.violet,
            Blue => self.blue,
            Surface => self.panel,
            Wash => self.selection,
            RuleHi => self.rule_hi,
            Ink2 => self.ink2,
            Faint => self.faint,
            MagentaHi => self.magenta_hi,
            MagentaDim => self.magenta_dim,
        }
    }
}
