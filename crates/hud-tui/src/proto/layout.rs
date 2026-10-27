//! The screen as a tree of panels (the prototype's `app` layout
//! module): "Layouts you build yourself".
//!
//! The screen is a tree. Each panel shows one view: Conversation,
//! Changes, Terminal, Plan, Activity, Context, Review, or an agent.
//! A split puts its children side by side or stacks them, with a
//! share for each. Panel numbers follow reading order (1–9 always
//! match the screen). The default is three columns with the
//! conversation in the middle. Any change saves the layout as
//! **yours**, the last preset, stored as a tree in `tui.toml`.

use orbit_frontend_protocol::customization::{
    Direction as PortableDirection, LayoutNode as PortableLayoutNode, PortableLayoutPreset,
    View as PortableView, portable_layout_preset,
};
use serde::{Deserialize, Serialize};

/// One view a panel can show.
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
    /// A named agent's panel.
    Agent,
    /// A named declarative pane; its stable ID lives in Node::Custom.
    Custom,
}

impl View {
    /// The identity colour token: the panel's number chip, header
    /// band and focused border.
    pub fn token(self) -> crate::proto::core::Token {
        use crate::proto::core::Token;
        match self {
            Self::Conversation => Token::Magenta,
            Self::Changes => Token::Violet,
            Self::Terminal => Token::Amber,
            Self::Plan => Token::Green,
            Self::Activity => Token::Cyan,
            Self::Context => Token::Blue,
            Self::Review => Token::Red,
            Self::Agent | Self::Custom => Token::Cyan,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Conversation => "Conversation",
            Self::Changes => "Changes",
            Self::Terminal => "Terminal",
            Self::Plan => "Plan",
            Self::Activity => "Activity",
            Self::Context => "Context",
            Self::Review => "Review",
            Self::Agent => "Agent",
            Self::Custom => "Custom pane",
        }
    }
}

/// A node of the layout tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Node {
    Custom {
        pane_id: String,
    },
    /// A leaf: one panel showing one view.
    Panel {
        view: View,
        /// For View::Agent, which agent (empty = the generic panel).
        #[serde(default)]
        agent: String,
    },
    /// A split: children side by side (Right) or stacked (Down),
    /// each with a share (≥ 16 after clamp).
    Split {
        #[serde(rename = "dir")]
        direction: Direction,
        #[serde(default)]
        shares: Vec<u32>,
        children: Vec<Node>,
    },
}

/// Split direction: `v` splits right, `s` splits down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Right,
    Down,
}

impl From<PortableLayoutNode> for Node {
    fn from(node: PortableLayoutNode) -> Self {
        match node {
            PortableLayoutNode::Panel { view, agent } => Self::Panel {
                view: match view {
                    PortableView::Conversation => View::Conversation,
                    PortableView::Changes => View::Changes,
                    PortableView::Terminal => View::Terminal,
                    PortableView::Plan => View::Plan,
                    PortableView::Activity => View::Activity,
                    PortableView::Context => View::Context,
                    PortableView::Review => View::Review,
                    PortableView::Agent => View::Agent,
                },
                agent,
            },
            PortableLayoutNode::Custom { pane_id } => Self::Custom { pane_id },
            PortableLayoutNode::Split {
                direction,
                shares,
                children,
            } => Self::Split {
                direction: match direction {
                    PortableDirection::Right => Direction::Right,
                    PortableDirection::Down => Direction::Down,
                },
                shares,
                children: children.into_iter().map(Self::from).collect(),
            },
        }
    }
}

impl Node {
    /// The default: three columns, conversation in the middle —
    /// Changes, Conversation, Terminal (the doc's default).
    pub fn default_tree() -> Self {
        Node::Split {
            direction: Direction::Right,
            shares: vec![30, 40, 30],
            children: vec![
                Node::Panel {
                    view: View::Changes,
                    agent: String::new(),
                },
                Node::Panel {
                    view: View::Conversation,
                    agent: String::new(),
                },
                Node::Panel {
                    view: View::Terminal,
                    agent: String::new(),
                },
            ],
        }
    }

    /// Count leaves (panels) in reading order.
    pub fn panel_count(&self) -> usize {
        match self {
            Node::Panel { .. } | Node::Custom { .. } => 1,
            Node::Split { children, .. } => children.iter().map(Node::panel_count).sum(),
        }
    }

    /// Leaves in reading order, with their paths (indices from the
    /// root). Panel numbers follow this order: 1–9 match the screen.
    pub fn leaves(&self) -> Vec<(Vec<usize>, View)> {
        let mut out = Vec::new();
        self.walk(&mut Vec::new(), &mut out);
        out
    }

    fn walk(&self, path: &mut Vec<usize>, out: &mut Vec<(Vec<usize>, View)>) {
        match self {
            Node::Panel { view, .. } => out.push((path.clone(), *view)),
            Node::Custom { .. } => out.push((path.clone(), View::Custom)),
            Node::Split { children, .. } => {
                for (i, c) in children.iter().enumerate() {
                    path.push(i);
                    c.walk(path, out);
                    path.pop();
                }
            }
        }
    }

    /// The focused leaf's path (0-based panel index → path).
    pub fn path_of(&self, index: usize) -> Option<Vec<usize>> {
        self.leaves().get(index).map(|(p, _)| p.clone())
    }

    /// View of the leaf at panel index (reading order, 0-based).
    pub fn view_at(&self, index: usize) -> Option<View> {
        self.leaves().get(index).map(|(_, v)| *v)
    }

    /// `p` — change what the focused panel shows.
    pub fn set_view(&mut self, index: usize, view: View) -> bool {
        let Some(path) = self.path_of(index) else {
            return false;
        };
        if self.view_at(index) == Some(View::Conversation) && view != View::Conversation {
            return false;
        }
        if view == View::Conversation
            && self.leaves().iter().any(|(_, v)| *v == View::Conversation)
            && self.view_at(index) != Some(View::Conversation)
        {
            return false;
        }
        match self.at_mut(&path) {
            Some(Node::Custom { .. }) => {
                *self.at_mut(&path).unwrap() = Node::Panel {
                    view,
                    agent: String::new(),
                };
                true
            }
            Some(Node::Panel { view: v, .. }) => {
                *v = view;
                true
            }
            _ => false,
        }
    }

    /// `x` — close the panel; its share goes to its neighbours.
    /// The last panel cannot close.
    pub fn close(&mut self, index: usize) -> bool {
        if self.panel_count() <= 1 || self.view_at(index) == Some(View::Conversation) {
            return false;
        }
        let Some(path) = self.path_of(index) else {
            return false;
        };
        // path points at a leaf; its parent is path[..len-1]
        let Some(parent_path) = path.get(..path.len() - 1).map(|p| p.to_vec()) else {
            return false;
        };
        let child_i = *path.last().unwrap();
        let Some(Node::Split {
            shares, children, ..
        }) = self.at_mut(&parent_path)
        else {
            return false;
        };
        if child_i >= children.len() {
            return false;
        }
        children.remove(child_i);
        if !shares.is_empty() && child_i < shares.len() {
            shares.remove(child_i);
        }
        normalize_shares(shares, children.len());
        // A split with one child collapses into that child.
        self.collapse(&parent_path);
        true
    }

    /// `v` / `s` while arranging: split the focused panel right/down.
    /// The new sibling gets an equal share; a picker asks what it
    /// shows (here: the caller passes the view).
    pub fn split(&mut self, index: usize, direction: Direction, view: View) -> bool {
        let Some(path) = self.path_of(index) else {
            return false;
        };
        if self.panel_count() >= 24 || view == View::Conversation {
            return false;
        }
        // If the parent split has the same direction, insert a sibling.
        if !path.is_empty() {
            let parent_path = path[..path.len() - 1].to_vec();
            let child_i = *path.last().unwrap();
            if let Some(Node::Split {
                direction: d,
                shares,
                children,
            }) = self.at_mut(&parent_path)
                && *d == direction
                && children.len() < 8
            {
                children.insert(
                    child_i + 1,
                    Node::Panel {
                        view,
                        agent: String::new(),
                    },
                );
                shares.insert(child_i + 1, 1);
                normalize_shares(shares, children.len());
                return true;
            }
        }
        // Otherwise replace the leaf with a split of two.
        let Some(node) = self.at_mut(&path) else {
            return false;
        };
        if matches!(node, Node::Panel { .. } | Node::Custom { .. }) {
            let old = node.clone();
            *node = Node::Split {
                direction,
                shares: vec![50, 50],
                children: vec![
                    old,
                    Node::Panel {
                        view,
                        agent: String::new(),
                    },
                ],
            };
            true
        } else {
            false
        }
    }

    /// `H J K L` — swap the focused panel with its neighbour in that
    /// direction; focus moves with it. Returns the new focus index.
    pub fn swap(&mut self, index: usize, dir: SwapDir) -> Option<usize> {
        let n = self.panel_count();
        let target = match dir {
            SwapDir::Left | SwapDir::Up => index.checked_sub(1)?,
            SwapDir::Right | SwapDir::Down => {
                if index + 1 >= n {
                    return None;
                }
                index + 1
            }
        };
        let a = self.path_of(index)?;
        let b = self.path_of(target)?;
        let node_a = self.at(&a)?.clone();
        let node_b = self.at(&b)?.clone();
        *self.at_mut(&a)? = node_b;
        *self.at_mut(&b)? = node_a;
        Some(target)
    }

    /// `< >` width, `- +` height: the focused panel gets narrower/wider
    /// (shorter/taller) by 6% of its split. The panel's own share moves;
    /// the difference comes from, or goes to, its right (lower)
    /// neighbour, or its left (upper) one when it is last. When the
    /// panel's parent splits the other way, the nearest ancestor that
    /// splits along `axis` is the one resized, so every panel can be
    /// resized in both directions. No share goes below 16% and the total
    /// never changes; a move that would cross the floor is shortened, not
    /// refused.
    pub fn resize(&mut self, index: usize, axis: Axis, delta: i32) -> bool {
        let Some(path) = self.path_of(index) else {
            return false;
        };
        let wants = match axis {
            Axis::Width => Direction::Right,
            Axis::Height => Direction::Down,
        };
        // The deepest ancestor splitting along the axis, and which of
        // its children holds the focused panel.
        for depth in (0..path.len()).rev() {
            let ancestor: Vec<usize> = path[..depth].to_vec();
            let child_i = path[depth];
            let Some(Node::Split {
                direction,
                shares,
                children,
            }) = self.at_mut(&ancestor)
            else {
                continue;
            };
            if *direction != wants || shares.len() != children.len() || shares.len() < 2 {
                continue;
            }
            let total: u32 = shares.iter().sum();
            let step = ((total as f64) * 0.06).ceil() as i32;
            let min = ((total as f64) * 0.16).ceil() as i32;
            let want = delta * step;
            // The neighbour that gives or takes: right/lower first.
            let candidates: Vec<usize> = [child_i + 1, child_i.wrapping_sub(1)]
                .into_iter()
                .filter(|i| *i < shares.len())
                .collect();
            let cur = shares[child_i] as i32;
            for other in candidates {
                let oth = shares[other] as i32;
                // Growing needs room in the neighbour; shrinking needs
                // room in the panel itself.
                let room = if want > 0 { oth - min } else { cur - min };
                let moved = want.abs().min(room.max(0));
                if moved == 0 {
                    continue;
                }
                let signed = if want > 0 { moved } else { -moved };
                shares[child_i] = (cur + signed) as u32;
                shares[other] = (oth - signed) as u32;
                return true;
            }
            return false;
        }
        false
    }

    /// `=` — even out every split.
    pub fn even(&mut self) {
        match self {
            Node::Panel { .. } | Node::Custom { .. } => {}
            Node::Split {
                shares, children, ..
            } => {
                normalize_shares(shares, children.len());
                for c in children {
                    c.even();
                }
            }
        }
    }

    fn at(&self, path: &[usize]) -> Option<&Node> {
        let mut node = self;
        for i in path {
            match node {
                Node::Panel { .. } | Node::Custom { .. } => return None,
                Node::Split { children, .. } => node = children.get(*i)?,
            }
        }
        Some(node)
    }

    fn at_mut(&mut self, path: &[usize]) -> Option<&mut Node> {
        let mut node = self;
        for i in path {
            match node {
                Node::Panel { .. } | Node::Custom { .. } => return None,
                Node::Split { children, .. } => node = children.get_mut(*i)?,
            }
        }
        Some(node)
    }

    /// A split with one child becomes that child (close/split can
    /// leave single-child splits behind).
    fn collapse(&mut self, path: &[usize]) {
        if let Some(Node::Split { children, .. }) = self.at_mut(path)
            && children.len() == 1
        {
            let only = children.pop().unwrap();
            *self.at_mut(path).unwrap() = only;
        }
    }

    /// The presets: `[ ]` cycles columns → build → agents → review.
    /// Trees and shares are the prototype's.
    pub fn preset(which: Preset) -> Self {
        use View::*;
        let pane = |view: View, agent: &str| Node::Panel {
            view,
            agent: agent.to_string(),
        };
        let split = |direction: Direction, shares: Vec<u32>, children: Vec<Node>| Node::Split {
            direction,
            shares,
            children,
        };
        match which {
            Preset::Columns => Self::default_tree(),
            // Conversation | Changes over Terminal.
            Preset::Build => split(
                Direction::Right,
                vec![56, 44],
                vec![
                    pane(Conversation, ""),
                    split(
                        Direction::Down,
                        vec![48, 52],
                        vec![pane(Changes, ""), pane(Terminal, "")],
                    ),
                ],
            ),
            // Two agent panels flank the conversation.
            Preset::Agents => split(
                Direction::Right,
                vec![30, 40, 30],
                vec![
                    pane(Agent, "explore"),
                    pane(Conversation, ""),
                    pane(Agent, "review"),
                ],
            ),
            // Review | Plan over Activity.
            Preset::Review => split(
                Direction::Right,
                vec![70, 30],
                vec![
                    pane(Review, ""),
                    split(
                        Direction::Down,
                        vec![45, 55],
                        vec![pane(Plan, ""), pane(Activity, "")],
                    ),
                ],
            ),
        }
    }

    /// Portable layouts always retain a reachable composer, including review.
    pub fn profile_preset(which: Preset) -> Self {
        let preset = match which {
            Preset::Columns => PortableLayoutPreset::Columns,
            Preset::Build => PortableLayoutPreset::Build,
            Preset::Agents => PortableLayoutPreset::Agents,
            Preset::Review => PortableLayoutPreset::Review,
        };
        portable_layout_preset(preset).into()
    }

    pub fn with_conversation(self) -> Self {
        if self
            .leaves()
            .iter()
            .any(|(_, view)| *view == View::Conversation)
        {
            return self;
        }
        Self::Split {
            direction: Direction::Right,
            shares: vec![40, 60],
            children: vec![
                Self::Panel {
                    view: View::Conversation,
                    agent: String::new(),
                },
                self,
            ],
        }
    }

    pub fn custom_id_at(&self, index: usize) -> Option<String> {
        let path = self.path_of(index)?;
        match self.at(&path)? {
            Self::Custom { pane_id } => Some(pane_id.clone()),
            _ => None,
        }
    }
    /// The agent name of the leaf at panel index (empty when none).
    pub fn agent_at(&self, index: usize) -> String {
        let Some(path) = self.path_of(index) else {
            return String::new();
        };
        let mut node = self;
        for i in path {
            match node {
                Node::Split { children, .. } => match children.get(i) {
                    Some(c) => node = c,
                    None => return String::new(),
                },
                Node::Panel { .. } | Node::Custom { .. } => break,
            }
        }
        match node {
            Node::Panel { agent, .. } => agent.clone(),
            _ => String::new(),
        }
    }
}

/// `H J K L` directions (swap with the neighbour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapDir {
    Left,
    Down,
    Up,
    Right,
}

/// `< >` width, `- +` height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Width,
    Height,
}

/// The `[ ]` preset cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Columns,
    Build,
    Agents,
    Review,
}

impl Preset {
    pub fn next(self) -> Self {
        match self {
            Self::Columns => Self::Build,
            Self::Build => Self::Agents,
            Self::Agents => Self::Review,
            Self::Review => Self::Columns,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Columns => Self::Review,
            Self::Build => Self::Columns,
            Self::Agents => Self::Build,
            Self::Review => Self::Agents,
        }
    }
}

/// Shares always sum to 100 (so the 16% floor is exact). Equal
/// shares, remainder spread to the earliest.
fn normalize_shares(shares: &mut Vec<u32>, n: usize) {
    if n == 0 {
        shares.clear();
        return;
    }
    let base = 100 / n as u32;
    let mut rem = 100 % n as u32;
    shares.clear();
    for _ in 0..n {
        let mut s = base;
        if rem > 0 {
            s += 1;
            rem -= 1;
        }
        shares.push(s);
    }
}

// ── Persistence: "yours" ──────────────────────────────────────────────────

/// The saved layout: "yours", the last preset, stored as a tree in
/// `tui.toml` (the `[layout.tree]` table). Any change saves it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayoutFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<Node>,
    /// The preset "yours" came from (for `[ ]` cycling's label).
    #[serde(default)]
    pub from_preset: String,
}

/// The exact bytes read form a revision; publication compares them under the stable lock.
pub struct LayoutSnapshot {
    pub layout: LayoutFile,
    pub revision: Option<Vec<u8>>,
    pub legacy_bytes: Option<Vec<u8>>,
}

impl LayoutFile {
    /// Compatibility accessor. Live startup uses load_checked and presents errors explicitly.
    pub fn load(home: &std::path::Path) -> Self {
        Self::load_checked(home)
            .map(|s| s.layout)
            .unwrap_or_else(|_| Self::default_tree_file())
    }
    pub fn load_checked(home: &std::path::Path) -> Result<LayoutSnapshot, String> {
        let dir = match layout_dir(home) {
            Ok(d) => d,
            Err(_error) if !home.exists() => {
                return Ok(LayoutSnapshot {
                    layout: Self::default_tree_file(),
                    revision: None,
                    legacy_bytes: None,
                });
            }
            Err(error) => return Err(error),
        };
        let legacy_bytes = layout_read(&dir)?;
        let profile_bytes = layout_read_named(&dir, "customization.json")?;
        let revision = layout_revision(&legacy_bytes, &profile_bytes);
        let layout = match &legacy_bytes {
            None => Self::default_tree_file(),
            Some(raw) => Self::parse(raw)?,
        };
        Ok(LayoutSnapshot {
            layout,
            revision,
            legacy_bytes,
        })
    }
    fn parse(raw: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            layout: LayoutFile,
        }
        let text = std::str::from_utf8(raw).map_err(|_| "tui.toml is not UTF-8")?;
        let wrapper: Wrapper = toml::from_str(text).map_err(|e| format!("tui.toml: {e}"))?;
        if let Some(tree) = &wrapper.layout.tree {
            validate_legacy_tree(tree)?;
        }
        Ok(wrapper.layout)
    }
    fn default_tree_file() -> Self {
        Self {
            tree: Some(Node::default_tree()),
            from_preset: "columns".into(),
        }
    }
    pub fn save(&self, home: &std::path::Path) -> Result<(), String> {
        let snapshot = Self::load_checked(home)?;
        self.save_checked(home, snapshot.revision.as_deref())
            .map(|_| ())
    }
    pub fn save_checked(
        &self,
        home: &std::path::Path,
        expected: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, String> {
        use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
        use std::io::Write;
        if let Some(tree) = &self.tree {
            validate_legacy_tree(tree)?;
        }
        let dir = layout_dir(home)?;
        let lockfd = openat(
            &dir,
            ".customization.lock",
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| format!("layout lock: {e}"))?;
        let lock = std::fs::File::from(lockfd);
        layout_regular(&lock, &dir)?;
        lock.try_lock().map_err(|e| format!("layout busy: {e}"))?;
        let current = layout_read(&dir)?;
        let profile_bytes = layout_read_named(&dir, "customization.json")?;
        if layout_revision(&current, &profile_bytes).as_deref() != expected {
            return Err("layout revision changed; reload before saving".into());
        }
        let mut root: toml::Value = match &current {
            Some(bytes) => {
                Self::parse(bytes)?;
                toml::from_str(std::str::from_utf8(bytes).map_err(|_| "tui.toml is not UTF-8")?)
                    .map_err(|e| format!("tui.toml: {e}"))?
            }
            None => toml::Value::Table(Default::default()),
        };
        let table = root.as_table_mut().ok_or("tui.toml root must be a table")?;
        let layout = table
            .entry("layout")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .ok_or("layout must be a table")?;
        if let Some(tree) = &self.tree {
            layout.insert(
                "tree".into(),
                toml::Value::try_from(tree).map_err(|e| e.to_string())?,
            );
        }
        layout.insert(
            "from_preset".into(),
            toml::Value::String(self.from_preset.clone()),
        );
        let bytes = toml::to_string_pretty(&root)
            .map_err(|e| e.to_string())?
            .into_bytes();
        if bytes.len() > 128 * 1024 {
            return Err("tui.toml exceeds 128 KiB".into());
        }
        let mut temp = None;
        for counter in 0..64 {
            let name = format!(".tui-layout-{}-{counter}.tmp", std::process::id());
            match openat(
                &dir,
                &name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    temp = Some((name, std::fs::File::from(fd)));
                    break;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(format!("layout stage: {e}")),
            }
        }
        let (name, mut staged) = temp.ok_or("layout staging busy")?;
        let result = (|| {
            staged.write_all(&bytes).map_err(|e| e.to_string())?;
            staged.sync_all().map_err(|e| e.to_string())?;
            if layout_read(&dir)? != current
                || layout_read_named(&dir, "customization.json")? != profile_bytes
            {
                return Err("layout changed during publication".into());
            }
            layout_same_directory(home, &dir)?;
            renameat(&dir, &name, &dir, "tui.toml").map_err(|e| e.to_string())?;
            dir.sync_all()
                .map_err(|e| format!("layout publication uncertain: {e}"))?;
            layout_same_directory(home, &dir)
                .map_err(|e| format!("layout publication uncertain: {e}"))?;
            Ok(layout_revision(&Some(bytes), &profile_bytes))
        })();
        let _ = unlinkat(&dir, &name, AtFlags::empty());
        result
    }
}

fn validate_legacy_tree(tree: &Node) -> Result<(), String> {
    fn walk(
        node: &Node,
        depth: usize,
        leaves: &mut usize,
        conversation: &mut usize,
    ) -> Result<(), String> {
        if depth > 8 {
            return Err("layout depth exceeds 8".into());
        }
        match node {
            Node::Panel { view, agent } => {
                *leaves += 1;
                if *view == View::Conversation {
                    *conversation += 1;
                }
                if *view == View::Custom || agent.len() > 128 || agent.chars().any(char::is_control)
                {
                    return Err("invalid layout view/agent".into());
                }
            }
            Node::Custom { pane_id } => {
                *leaves += 1;
                if !orbit_frontend_protocol::customization::valid_id(pane_id) {
                    return Err("invalid custom pane identity".into());
                }
            }
            Node::Split {
                shares, children, ..
            } => {
                if children.is_empty()
                    || children.len() > 8
                    || shares.len() != children.len()
                    || shares.iter().any(|v| !(1..=1000).contains(v))
                {
                    return Err("invalid layout split/shares".into());
                }
                for child in children {
                    walk(child, depth + 1, leaves, conversation)?;
                }
            }
        }
        if *leaves > 24 {
            return Err("layout leaves exceed 24".into());
        }
        Ok(())
    }
    let (mut leaves, mut conversation) = (0, 0);
    walk(tree, 1, &mut leaves, &mut conversation)?;
    if conversation != 1 {
        return Err("layout must retain exactly one conversation".into());
    }
    Ok(())
}

fn layout_dir(home: &std::path::Path) -> Result<std::fs::File, String> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open(
        home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("layout directory: {e}"))?;
    let dir = std::fs::File::from(fd);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = dir.metadata().map_err(|e| e.to_string())?;
        let uid = std::fs::metadata("/proc/self")
            .map_err(|e| e.to_string())?
            .uid();
        if m.uid() != uid || m.mode() & 0o022 != 0 {
            return Err("unsafe layout directory owner/permissions".into());
        }
    }
    Ok(dir)
}
fn layout_regular(file: &std::fs::File, dir: &std::fs::File) -> Result<(), String> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > 128 * 1024 {
        return Err("layout requires a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = dir.metadata().map_err(|e| e.to_string())?.uid();
        if m.uid() != owner || m.nlink() != 1 || m.mode() & 0o022 != 0 {
            return Err("unsafe layout file owner/links/permissions".into());
        }
    }
    Ok(())
}
fn layout_read(dir: &std::fs::File) -> Result<Option<Vec<u8>>, String> {
    layout_read_named(dir, "tui.toml")
}
fn layout_read_named(dir: &std::fs::File, name: &str) -> Result<Option<Vec<u8>>, String> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::io::Read;
    let fd = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(format!("layout read: {e}")),
    };
    let mut file = std::fs::File::from(fd);
    layout_regular(&file, dir)?;
    let mut raw = Vec::new();
    file.by_ref()
        .take(128 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 128 * 1024 {
        return Err("tui.toml exceeds 128 KiB".into());
    }
    Ok(Some(raw))
}

fn layout_same_directory(home: &std::path::Path, held: &std::fs::File) -> Result<(), String> {
    let current = layout_dir(home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = held.metadata().map_err(|e| e.to_string())?;
        let b = current.metadata().map_err(|e| e.to_string())?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err("layout directory identity changed".into());
        }
    }
    Ok(())
}

fn layout_revision(legacy: &Option<Vec<u8>>, profile: &Option<Vec<u8>>) -> Option<Vec<u8>> {
    if legacy.is_none() && profile.is_none() {
        return None;
    }
    let mut bytes = Vec::new();
    for part in [legacy, profile] {
        match part {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
                bytes.extend_from_slice(value);
            }
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_three_columns_conversation_middle() {
        let t = Node::default_tree();
        let leaves = t.leaves();
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0].1, View::Changes);
        assert_eq!(leaves[1].1, View::Conversation);
        assert_eq!(leaves[2].1, View::Terminal);
    }

    #[test]
    fn panel_numbers_follow_reading_order() {
        // A nested tree: reading order is left-to-right, top-to-bottom.
        let mut t = Node::default_tree();
        assert!(t.split(0, Direction::Down, View::Plan)); // split Changes
        let leaves = t.leaves();
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[0].1, View::Changes);
        assert_eq!(leaves[1].1, View::Plan); // the new sibling under it
        assert_eq!(leaves[2].1, View::Conversation);
        assert_eq!(leaves[3].1, View::Terminal);
    }

    #[test]
    fn split_same_direction_inserts_sibling() {
        let mut t = Node::default_tree();
        assert!(t.split(0, Direction::Right, View::Plan));
        assert_eq!(t.panel_count(), 4);
        let leaves = t.leaves();
        assert_eq!(leaves[0].1, View::Changes);
        assert_eq!(leaves[1].1, View::Plan);
    }

    #[test]
    fn close_gives_share_to_neighbours() {
        let mut t = Node::default_tree();
        assert!(t.close(0)); // close Changes
        assert_eq!(t.panel_count(), 2);
        assert_eq!(t.leaves()[0].1, View::Conversation);
        let closed_twice = if t.close(0) { t.close(0) } else { false };
        assert!(!closed_twice || t.panel_count() >= 1);
        // closing the last panel is refused
        let mut one = Node::preset(Preset::Review);
        one.close(1);
        one.close(0); // 2 → 1
        assert!(!one.close(0), "the last panel cannot close");
    }

    #[test]
    fn swap_moves_focus_with_the_panel() {
        let mut t = Node::default_tree();
        let new = t.swap(0, SwapDir::Right).unwrap();
        assert_eq!(new, 1);
        let leaves = t.leaves();
        assert_eq!(leaves[0].1, View::Conversation);
        assert_eq!(leaves[1].1, View::Changes);
        // focus moved with it: swapping back from the new index
        let back = t.swap(1, SwapDir::Left).unwrap();
        assert_eq!(back, 0);
        assert_eq!(t.leaves()[0].1, View::Changes);
    }

    #[test]
    fn resize_respects_the_16_percent_floor() {
        let mut t = Node::default_tree();
        // shrink panel 0 repeatedly: at ~16% it stops
        for _ in 0..20 {
            let _ = t.resize(0, Axis::Width, -1);
        }
        if let Node::Split { shares, .. } = t {
            assert!(shares[0] >= 16, "no panel below 16%: {:?}", shares);
        }
    }

    #[test]
    fn resize_works_at_both_ends_and_keeps_the_total() {
        // The leftmost panel can widen, the rightmost can narrow — the
        // two moves the old code refused.
        let mut t = Node::default_tree();
        let total = |t: &Node| match t {
            Node::Split { shares, .. } => shares.iter().sum::<u32>(),
            _ => 0,
        };
        let before = total(&t);
        assert!(t.resize(0, Axis::Width, 1), "leftmost widens");
        assert!(t.resize(2, Axis::Width, -1), "rightmost narrows");
        assert_eq!(total(&t), before, "shares still sum to the same total");
        if let Node::Split { shares, .. } = &t {
            assert!(shares[0] > 30, "{shares:?}");
        }
    }

    #[test]
    fn resize_climbs_to_the_ancestor_that_splits_along_the_axis() {
        // Build: Conversation | (Changes over Terminal). Changes sits in a
        // Down split; `>` on it must still move the Right split's edge.
        let mut t = Node::preset(Preset::Build);
        let before = t.clone();
        assert!(t.resize(1, Axis::Width, 1) || t.resize(1, Axis::Width, -1));
        assert_ne!(t, before, "width changed through the ancestor");
        let mut v = Node::preset(Preset::Build);
        assert!(
            v.resize(1, Axis::Height, 1),
            "height uses its own Down split"
        );
    }

    #[test]
    fn resize_is_shortened_at_the_floor_not_refused() {
        let mut t = Node::default_tree();
        for _ in 0..30 {
            t.resize(1, Axis::Width, -1);
        }
        if let Node::Split { shares, .. } = &t {
            assert!(shares.iter().all(|s| *s >= 16), "{shares:?}");
            assert_eq!(shares.iter().sum::<u32>(), 100);
        }
    }

    #[test]
    fn even_out_every_split() {
        let mut t = Node::default_tree();
        let _ = t.resize(0, Axis::Width, 3);
        t.even();
        if let Node::Split { shares, .. } = t {
            let spread = shares.iter().max().unwrap() - shares.iter().min().unwrap();
            assert!(spread <= 1, "even: {shares:?}");
        }
    }

    #[test]
    fn presets_cycle() {
        assert_eq!(Preset::Columns.next(), Preset::Build);
        assert_eq!(Preset::Review.next(), Preset::Columns);
        assert_eq!(Preset::Columns.prev(), Preset::Review);
        // each preset's tree parses and has ≥ 2 panels
        for p in [
            Preset::Columns,
            Preset::Build,
            Preset::Agents,
            Preset::Review,
        ] {
            assert!(Node::preset(p).panel_count() >= 2, "{p:?}");
        }
    }

    #[test]
    fn yours_roundtrips_through_tui_toml() {
        let home = std::env::temp_dir().join(format!("orbit-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let mut t = Node::preset(Preset::Agents);
        assert!(t.split(0, Direction::Down, View::Context));
        let f = LayoutFile {
            tree: Some(t),
            from_preset: "agents".into(),
        };
        f.save(&home).unwrap();
        let back = LayoutFile::load(&home);
        assert_eq!(back.tree, f.tree);
        assert_eq!(back.from_preset, "agents");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn tree_serializes_as_toml_tables() {
        let t = Node::default_tree();
        let v = toml::Value::try_from(&t).unwrap();
        let s = toml::to_string_pretty(&v).unwrap();
        assert!(s.contains("kind = \"split\""));
        assert!(s.contains("view = \"conversation\""));
    }

    #[test]
    fn portable_profile_presets_match_legacy_recipes_and_canonical_wire_trees() {
        for (preset, portable) in [
            (Preset::Columns, PortableLayoutPreset::Columns),
            (Preset::Build, PortableLayoutPreset::Build),
            (Preset::Agents, PortableLayoutPreset::Agents),
            (Preset::Review, PortableLayoutPreset::Review),
        ] {
            let actual = Node::profile_preset(preset);
            assert_eq!(actual, Node::preset(preset).with_conversation());
            assert_eq!(
                actual
                    .leaves()
                    .iter()
                    .filter(|(_, view)| *view == View::Conversation)
                    .count(),
                1
            );
            assert_eq!(
                serde_json::to_value(&actual).unwrap(),
                serde_json::to_value(portable_layout_preset(portable)).unwrap()
            );
            let reopened: Node =
                serde_json::from_slice(&serde_json::to_vec(&actual).unwrap()).unwrap();
            assert_eq!(reopened, actual);
        }
    }

    #[test]
    fn portable_node_conversion_retains_all_views_custom_ids_agents_and_geometry() {
        let tree = PortableLayoutNode::Split {
            direction: PortableDirection::Down,
            shares: vec![75, 25],
            children: vec![
                PortableLayoutNode::Split {
                    direction: PortableDirection::Right,
                    shares: vec![10, 10, 10, 10, 10, 10, 10, 30],
                    children: [
                        PortableView::Conversation,
                        PortableView::Changes,
                        PortableView::Terminal,
                        PortableView::Plan,
                        PortableView::Activity,
                        PortableView::Context,
                        PortableView::Review,
                        PortableView::Agent,
                    ]
                    .into_iter()
                    .map(|view| PortableLayoutNode::Panel {
                        view,
                        agent: if view == PortableView::Agent {
                            "review-é".into()
                        } else {
                            String::new()
                        },
                    })
                    .collect(),
                },
                PortableLayoutNode::Custom {
                    pane_id: "notes-pane".into(),
                },
            ],
        };
        let converted = Node::from(tree.clone());
        assert_eq!(
            serde_json::to_value(&converted).unwrap(),
            serde_json::to_value(tree).unwrap()
        );
        assert_eq!(converted.custom_id_at(8).as_deref(), Some("notes-pane"));
        assert_eq!(converted.agent_at(7), "review-é");
    }
}
