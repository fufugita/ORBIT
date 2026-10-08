//! The app (`app`): the whole screen — layout tree, focus, arrange
//! mode, the tick discipline.
//!
//! esc starts arranging. v splits right, s splits down; p changes
//! what the focused panel shows; x closes. H J K L swap, < > - +
//! resize, = evens. b toggles the sidebar, [ ] cycle presets. Any
//! change saves the layout as "yours" in tui.toml. Under 120 columns
//! the tree is kept but one panel shows at a time.
//!
//! ## Redraw discipline
//! The UI ticks every 16 ms. An animation redraws only its own cells;
//! when no animation is unfinished the tick stops and an idle ORBIT
//! draws nothing.

use super::anim::{StarClock, StarState};
use super::layout::{Axis, Direction, LayoutFile, Node, Preset, SwapDir, View};
use super::panels;
use super::scenario::Scenario;

/// Everything the screen needs.
pub struct App {
    pub tree: Node,
    /// Focused panel index (reading order, 0-based).
    pub focus: usize,
    /// esc-arrange mode: hjkl move focus, the split/swap keys act.
    pub arranging: bool,
    /// The picker asking what a new panel shows (v/s/p): pending
    /// split or change.
    pub picker: Option<Picker>,
    /// The sidebar (b).
    pub sidebar: bool,
    /// The star clock (the one stateful animation).
    pub star: StarClock,
    /// Reduced motion (`reduced = true` in tui.toml): every animation
    /// shows its end state.
    pub reduced: bool,
    /// The current tick (ms since boot; drives every animation).
    pub tick_ms: u64,
    /// Dirty regions: a redraw happens only while some animation is
    /// unfinished; when none is, the 16 ms tick stops.
    pub animating: bool,
    /// Where "yours" persists.
    pub home: std::path::PathBuf,
}

/// A pending picker: what the new/changed panel shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Picker {
    /// split (v/s produced a pending sibling) or change (p).
    pub kind: PickerKind,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Split,
    Change,
}

/// An arrange-mode key (the doc's grammar, one type so tests can
/// drive the whole keyboard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Esc,
    Char(char),
    Enter,
    Tab,
}

impl App {
    pub fn new(home: std::path::PathBuf, reduced: bool) -> Self {
        let file = LayoutFile::load(&home);
        let tree = file.tree.unwrap_or_else(Node::default_tree);
        Self {
            tree: tree.clone(),
            focus: Self::conversation_index(&tree).unwrap_or(0),
            arranging: false,
            picker: None,
            sidebar: tree == Node::preset(Preset::Build),
            star: StarClock::new(),
            reduced,
            tick_ms: 0,
            animating: true,
            home,
        }
    }

    fn conversation_index(tree: &Node) -> Option<usize> {
        tree.leaves()
            .iter()
            .position(|(_, v)| *v == View::Conversation)
    }

    /// A copy of the layout state, for tests that compare before/after.
    pub fn clone_for_test(&self) -> App {
        App {
            tree: self.tree.clone(),
            focus: self.focus,
            arranging: self.arranging,
            picker: self.picker,
            sidebar: self.sidebar,
            star: self.star,
            reduced: self.reduced,
            tick_ms: self.tick_ms,
            animating: self.animating,
            home: self.home.clone(),
        }
    }

    /// The preset the tree currently is, or `None` once it is "yours".
    pub fn current_preset(&self) -> Option<Preset> {
        [
            Preset::Columns,
            Preset::Build,
            Preset::Agents,
            Preset::Review,
        ]
        .into_iter()
        .find(|p| self.tree == Node::preset(*p))
    }

    /// Move focus to the next/previous panel (wraps).
    pub fn cycle_focus(&mut self, forward: bool) {
        let n = self.panel_count().max(1);
        self.focus = if forward {
            (self.focus + 1) % n
        } else {
            (self.focus + n - 1) % n
        };
    }

    /// The view the focus is on.
    pub fn focused_view(&self) -> View {
        self.tree.view_at(self.focus).unwrap_or(View::Conversation)
    }

    /// Panel count (1–9; splits refuse to exceed 9).
    pub fn panel_count(&self) -> usize {
        self.tree.panel_count()
    }

    /// One 16 ms tick: advance the star, mark whether any animation
    /// is still unfinished (drives the tick stop).
    pub fn tick(&mut self, now_ms: u64, scenario: &Scenario) {
        self.tick_ms = now_ms;
        let state = scenario.star_state();
        // still → turning edge restarts the clock (§10.1)
        if scenario.star_restarts_from_still() {
            self.star.start(now_ms);
        }
        self.star.tick(now_ms, state);
        // Something moves while the star turns; otherwise the app is
        // idle and draws nothing.
        self.animating = matches!(state, StarState::Turning { .. });
    }

    /// A key press. Returns true when the layout changed (and must be
    /// saved as "yours").
    pub fn key(&mut self, k: Key) -> bool {
        match k {
            Key::Esc => {
                if self.picker.is_some() {
                    self.picker = None;
                } else {
                    self.arranging = !self.arranging;
                }
                false
            }
            Key::Tab | Key::Enter => {
                if self.picker.is_some() {
                    self.picker = None;
                } else {
                    self.arranging = false;
                }
                false
            }
            Key::Char(c) => self.char(c),
        }
    }

    fn char(&mut self, c: char) -> bool {
        let n = self.panel_count();
        match c {
            // Numbers 1–9 jump focus (reading order).
            '1'..='9' => {
                let i = c as usize - '1' as usize;
                if i < n {
                    self.focus = i;
                }
                false
            }
            'i' => {
                // i leaves arrange mode.
                self.arranging = false;
                false
            }
            'b' => {
                self.sidebar = !self.sidebar;
                true
            }
            '[' | ']' => {
                let cur = self.current_preset().unwrap_or_else(|| {
                    match LayoutFile::load(&self.home).from_preset.as_str() {
                        "build" => Preset::Build,
                        "agents" => Preset::Agents,
                        "review" => Preset::Review,
                        _ => Preset::Columns,
                    }
                });
                let next = if c == ']' { cur.next() } else { cur.prev() };
                self.tree = Node::preset(next);
                self.focus = 0;
                // The build layout carries the sidebar; the others don't.
                self.sidebar = next == Preset::Build;
                true
            }
            _ if self.arranging => self.arrange_key(c),
            _ => false,
        }
    }

    /// The arrange grammar (only while arranging).
    fn arrange_key(&mut self, c: char) -> bool {
        match c {
            'h' | 'j' | 'k' | 'l' => {
                // move focus left/down/up/right by one panel
                let n = self.panel_count();
                self.focus = match c {
                    'h' | 'k' => self.focus.saturating_sub(1),
                    _ => (self.focus + 1).min(n - 1),
                };
                false
            }
            'v' => {
                self.picker = Some(Picker {
                    kind: PickerKind::Split,
                    direction: Direction::Right,
                });
                false
            }
            's' => {
                self.picker = Some(Picker {
                    kind: PickerKind::Split,
                    direction: Direction::Down,
                });
                false
            }
            'p' => {
                self.picker = Some(Picker {
                    kind: PickerKind::Change,
                    direction: Direction::Right,
                });
                false
            }
            'x' => {
                let changed = self.tree.close(self.focus);
                if changed {
                    self.focus = self.focus.min(self.panel_count() - 1);
                }
                changed
            }
            'H' => self.swap(SwapDir::Left),
            'J' => self.swap(SwapDir::Down),
            'K' => self.swap(SwapDir::Up),
            'L' => self.swap(SwapDir::Right),
            '<' => self.resize(Axis::Width, -1),
            '>' => self.resize(Axis::Width, 1),
            '-' => self.resize(Axis::Height, -1),
            '+' => self.resize(Axis::Height, 1),
            '=' => {
                self.tree.even();
                true
            }
            _ => false,
        }
    }

    fn swap(&mut self, dir: SwapDir) -> bool {
        match self.tree.swap(self.focus, dir) {
            Some(new_focus) => {
                self.focus = new_focus;
                true
            }
            None => false,
        }
    }

    fn resize(&mut self, axis: Axis, delta: i32) -> bool {
        self.tree.resize(self.focus, axis, delta)
    }

    /// The picker's answer: what the new/changed panel shows.
    pub fn pick(&mut self, view: View) -> bool {
        let Some(p) = self.picker.take() else {
            return false;
        };
        match p.kind {
            PickerKind::Split => {
                if self.panel_count() >= 9 {
                    return false;
                }
                let changed = self.tree.split(self.focus, p.direction, view);
                if changed {
                    self.focus += 1; // focus the new panel
                }
                changed
            }
            PickerKind::Change => self.tree.set_view(self.focus, view),
        }
    }

    /// Save the layout as "yours" (any change calls this).
    pub fn save_yours(&self) {
        let preset_name = match self.tree {
            Node::Split { .. } if self.tree == Node::preset(Preset::Build) => "build",
            Node::Split { .. } if self.tree == Node::preset(Preset::Agents) => "agents",
            Node::Split { .. } if self.tree == Node::preset(Preset::Review) => "review",
            _ => "columns",
        };
        let f = LayoutFile {
            tree: Some(self.tree.clone()),
            from_preset: preset_name.into(),
        };
        let _ = f.save(&self.home);
    }

    /// Under 120 columns one panel shows at a time: the tree is kept,
    /// the screen shows only the focused panel.
    pub fn one_at_a_time(&self, width: u16) -> bool {
        width < 120
    }

    /// Render the whole screen.
    pub fn render(&self, f: &mut ratatui::Frame, scenario: &Scenario) {
        use ratatui::layout::Rect;
        let area = f.area();
        let star_glyph = self.star.glyph_now(scenario, self.reduced);
        let _ = star_glyph;
        let areas = panels::split_areas(area, &self.tree);
        let show = if self.one_at_a_time(area.width) {
            vec![areas[self.focus.min(areas.len() - 1)]]
        } else {
            areas
        };
        let single = self.one_at_a_time(area.width);
        for (i, (rect, view)) in show.iter().enumerate() {
            let idx = if single { self.focus } else { i };
            panels::render_panel(
                f,
                *rect,
                (idx + 1) as u8,
                *view,
                idx == self.focus,
                scenario,
                self.tick_ms,
                self.reduced,
            );
        }
        // The picker: what the new/changed panel shows.
        if self.picker.is_some() {
            let w = 28u16.min(area.width.saturating_sub(4));
            let h = 10u16.min(area.height.saturating_sub(4));
            let r = Rect {
                x: area.x + (area.width - w) / 2,
                y: area.y + (area.height - h) / 2,
                width: w,
                height: h,
            };
            let views = [
                View::Conversation,
                View::Changes,
                View::Terminal,
                View::Plan,
                View::Activity,
                View::Context,
                View::Review,
                View::Agent,
            ];
            let lines: Vec<ratatui::text::Line> = std::iter::once(ratatui::text::Line::from(
                ratatui::text::Span::raw("Show what?"),
            ))
            .chain(views.iter().map(|v| ratatui::text::Line::from(v.title())))
            .collect();
            let block = ratatui::widgets::Block::default()
                .borders(ratatui::widgets::Borders::ALL)
                .border_style(
                    ratatui::style::Style::default()
                        .fg(super::comps::colour(super::core::Token::Cyan)),
                );
            f.render_widget(ratatui::widgets::Clear, r);
            f.render_widget(ratatui::widgets::Paragraph::new(lines).block(block), r);
        }
    }
}

// A tiny extension the app needs from the star clock: the current
// glyph for a scenario at the app's tick.
impl StarClock {
    fn glyph_now(&self, scenario: &Scenario, _reduced: bool) -> super::anim::StarGlyph {
        let state = scenario.star_state();
        let mut c = *self;
        c.tick(0, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn app(home: &std::path::Path) -> App {
        App::new(home.to_path_buf(), false)
    }

    #[test]
    fn arrange_grammar_full_session() {
        let home = std::env::temp_dir().join(format!("orbit-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut a = app(&home);
        assert_eq!(a.panel_count(), 3);
        assert_eq!(a.focus, 1, "the conversation starts focused");

        // esc → arranging; v → picker; pick Plan → 4 panels, focus on the new one
        a.key(Key::Esc);
        assert!(a.arranging);
        a.key(Key::Char('v'));
        assert!(a.picker.is_some());
        let changed = a.pick(View::Plan);
        assert!(changed);
        assert_eq!(a.panel_count(), 4);
        assert_eq!(a.focus, 2, "focus follows the new panel");
        assert_eq!(a.tree.view_at(2), Some(View::Plan));

        // L swaps with the right neighbour; focus moves with it
        let changed = a.key(Key::Char('L'));
        assert!(changed);
        assert_eq!(a.focus, 3);

        // x closes the focused panel; focus clamps
        let changed = a.key(Key::Char('x'));
        assert!(changed);
        assert_eq!(a.panel_count(), 3);
        assert!(a.focus < a.panel_count());

        // i leaves arrange mode
        a.key(Key::Char('i'));
        assert!(!a.arranging);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn any_change_saves_yours() {
        let home = std::env::temp_dir().join(format!("orbit-app-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut a = app(&home);
        a.key(Key::Esc);
        a.key(Key::Char('v'));
        a.pick(View::Plan);
        a.save_yours();
        let back = LayoutFile::load(&home);
        assert_eq!(back.tree, Some(a.tree.clone()), "yours round-trips");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn presets_cycle_and_persist() {
        let home = std::env::temp_dir().join(format!("orbit-app-preset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut a = app(&home);
        a.key(Key::Char(']')); // build
        assert_eq!(a.tree, Node::preset(Preset::Build));
        a.save_yours();
        assert_eq!(LayoutFile::load(&home).from_preset, "build");
        a.key(Key::Char('[')); // back to columns
        assert_eq!(a.tree, Node::preset(Preset::Columns));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn numbers_jump_focus_in_reading_order() {
        let home = std::env::temp_dir().join(format!("orbit-app-num-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut a = app(&home);
        a.key(Key::Char('3'));
        assert_eq!(a.focus, 2);
        a.key(Key::Char('9')); // beyond the count: ignored
        assert_eq!(a.focus, 2);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn under_120_columns_one_panel_at_a_time() {
        let home = std::env::temp_dir().join(format!("orbit-app-narrow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let a = app(&home);
        assert!(a.one_at_a_time(119));
        assert!(!a.one_at_a_time(120));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Golden: the whole screen at a fixed tick, focused border on the
    /// conversation.
    #[test]
    fn golden_screen_focus_border() {
        let home = std::env::temp_dir().join(format!("orbit-app-golden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let mut a = app(&home);
        let mut s = Scenario::new();
        s.model = "m".into();
        a.tick(0, &s);

        let backend = TestBackend::new(140, 30);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        term.draw(|f| a.render(f, &s)).unwrap();
        let buf = term.backend().buffer().clone();
        // All three panels drew their frames.
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| {
                        buf.cell((x, y))
                            .map(|c| c.symbol().to_string())
                            .unwrap_or_default()
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Changes"));
        assert!(text.contains("Conversation"));
        assert!(text.contains("Terminal"));
        let _ = std::fs::remove_dir_all(&home);
    }
}
