//! Portable, declarative customization. This module never performs I/O.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROFILE_BYTES: usize = 128 * 1024;
pub const MAX_PANE_OUTPUT_BYTES: usize = 32 * 1024;
pub const MAX_PANE_LINES: usize = 512;

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
    pub color_mode: ColorMode,
    pub browser: BrowserStyle,
    pub layout: Layout,
    pub panes: Vec<PaneDef>,
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
            color_mode: ColorMode::Auto,
            browser: BrowserStyle::default(),
            layout: Layout::default(),
            panes: Vec::new(),
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
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaneAction {
    Refresh,
    FocusConversation,
    InsertPrompt { text: String },
    OwnerCancel,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PaneContext {
    pub permission_mode: Option<String>,
    pub routing: Vec<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
    pub agents: Vec<PaneAgent>,
    pub controller: bool,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneOutput {
    pub id: String,
    pub title: String,
    pub state: PaneState,
    pub text: String,
    pub truncated: bool,
    pub actions: Vec<PaneAction>,
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
    pub fn validate(&self) -> Result<(), CustomizationError> {
        let invalid = |field: &str| CustomizationError::Invalid(field.into());
        if self.schema_version != 1 {
            return Err(invalid("schema_version must be 1"));
        }
        if self.name.is_empty() || self.name.len() > 64 || self.name.chars().any(char::is_control) {
            return Err(invalid("name must contain 1..64 printable bytes"));
        }
        if !["orbit", "midnight", "paper"].contains(&self.theme.as_str()) {
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
                    return Err(invalid("panes.source.text exceeds 16 KiB"))
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
                    ))
                }
                _ => {}
            }
            if pane.actions.len() > 8 {
                return Err(invalid("panes.actions exceeds 8"));
            }
            for action in &pane.actions {
                if let PaneAction::InsertPrompt { text } = action {
                    if text.len() > 4096 {
                        return Err(invalid("panes.actions.insert_prompt exceeds 4096 bytes"));
                    }
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
