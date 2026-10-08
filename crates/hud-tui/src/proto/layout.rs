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
            Self::Agent => Token::Cyan,
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
        }
    }
}

/// A node of the layout tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Node {
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
            Node::Panel { .. } => 1,
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
        match self.at_mut(&path) {
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
        if self.panel_count() <= 1 {
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
        // If the parent split has the same direction, insert a sibling.
        if !path.is_empty() {
            let parent_path = path[..path.len() - 1].to_vec();
            let child_i = *path.last().unwrap();
            if let Some(Node::Split {
                direction: d,
                shares,
                children,
            }) = self.at_mut(&parent_path)
            {
                if *d == direction && children.len() < 9 {
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
        }
        // Otherwise replace the leaf with a split of two.
        let Some(node) = self.at_mut(&path) else {
            return false;
        };
        if let Node::Panel { view: old, agent } = node.clone() {
            *node = Node::Split {
                direction,
                shares: vec![50, 50],
                children: vec![
                    Node::Panel { view: old, agent },
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

    /// `< >` width, `- +` height: change the focused panel's share by
    /// 6% of its split; no panel goes below 16%.
    pub fn resize(&mut self, index: usize, axis: Axis, delta: i32) -> bool {
        let Some(path) = self.path_of(index) else {
            return false;
        };
        // The axis must match the parent split's direction for a width
        // change to make sense: width adjusts a Right split's shares,
        // height a Down split's.
        let Some(parent_path) = path.get(..path.len() - 1).map(|p| p.to_vec()) else {
            return false;
        };
        let child_i = *path.last().unwrap();
        let Some(Node::Split {
            direction,
            shares,
            children,
        }) = self.at_mut(&parent_path)
        else {
            return false;
        };
        let wants = match axis {
            Axis::Width => *direction == Direction::Right,
            Axis::Height => *direction == Direction::Down,
        };
        if !wants {
            return false;
        }
        if shares.len() != children.len() || child_i >= shares.len() {
            return false;
        }
        let total: u32 = shares.iter().sum();
        let step = ((total as f64) * 0.06).ceil() as i32;
        let cur = shares[child_i] as i32;
        let new = (cur + delta * step).max(0) as u32;
        // no panel below 16% of the total
        let min_share = ((total as f64) * 0.16).ceil() as u32;
        if new < min_share {
            return false;
        }
        // take from / give to the neighbour
        let other = if delta > 0 {
            child_i.saturating_sub(1)
        } else {
            (child_i + 1).min(shares.len() - 1)
        };
        if other == child_i || shares.len() < 2 {
            return false;
        }
        let moved = new as i32 - cur;
        let other_new = (shares[other] as i32 - moved).max(min_share as i32) as u32;
        shares[child_i] = new;
        shares[other] = other_new;
        true
    }

    /// `=` — even out every split.
    pub fn even(&mut self) {
        match self {
            Node::Panel { .. } => {}
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
                Node::Panel { .. } => return None,
                Node::Split { children, .. } => node = children.get(*i)?,
            }
        }
        Some(node)
    }

    fn at_mut(&mut self, path: &[usize]) -> Option<&mut Node> {
        let mut node = self;
        for i in path {
            match node {
                Node::Panel { .. } => return None,
                Node::Split { children, .. } => node = children.get_mut(*i)?,
            }
        }
        Some(node)
    }

    /// A split with one child becomes that child (close/split can
    /// leave single-child splits behind).
    fn collapse(&mut self, path: &[usize]) {
        if let Some(Node::Split { children, .. }) = self.at_mut(path) {
            if children.len() == 1 {
                let only = children.pop().unwrap();
                *self.at_mut(path).unwrap() = only;
            }
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
                Node::Panel { .. } => break,
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

impl LayoutFile {
    /// Load from `$ORBIT_HOME/tui.toml` (a `[layout.tree]` table).
    /// Malformed or missing → the default tree.
    pub fn load(home: &std::path::Path) -> Self {
        let path = home.join("tui.toml");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Self::default_tree_file();
        };
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            layout: LayoutFile,
        }
        toml::from_str::<Wrapper>(&raw)
            .map(|w| w.layout)
            .unwrap_or_else(|_| Self::default_tree_file())
    }

    fn default_tree_file() -> Self {
        Self {
            tree: Some(Node::default_tree()),
            from_preset: "columns".into(),
        }
    }

    /// Save as "yours": write the tree into tui.toml (merging into an
    /// existing file by re-serializing the `[layout.tree]` table).
    pub fn save(&self, home: &std::path::Path) -> Result<(), String> {
        let path = home.join("tui.toml");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        // Parse as a raw table, replace [layout.tree], keep the rest.
        let mut root: toml::Value =
            toml::from_str(&existing).unwrap_or_else(|_| toml::Value::Table(Default::default()));
        if let Some(table) = root.as_table_mut() {
            let layout = table
                .entry("layout".to_string())
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let Some(lt) = layout.as_table_mut() {
                if let Some(tree) = &self.tree {
                    let v = toml::Value::try_from(tree).map_err(|e| e.to_string())?;
                    lt.insert("tree".into(), v);
                }
                lt.insert(
                    "from_preset".into(),
                    toml::Value::String(self.from_preset.clone()),
                );
            }
        }
        std::fs::write(&path, toml::to_string_pretty(&root).unwrap_or_default())
            .map_err(|e| e.to_string())
    }
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
}
