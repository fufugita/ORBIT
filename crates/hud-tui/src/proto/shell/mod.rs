//! The redesigned screen (the prototype's `app` + panels): a top bar,
//! a tree of panels, and a status line. Every panel draws from the
//! scenario state and the tick alone; every motion is a function of the
//! clock and of timestamps recorded when something changed.
//!
//! Under 120 columns the tree is kept but one panel shows at a time and
//! the top bar becomes the panel switcher.

pub mod bars;
pub mod canvas;
pub mod convo;
pub mod diffrows;
pub mod frame;
pub mod hits;
pub mod mark;
pub mod md;
pub mod motion;
pub mod overlays;
pub mod pal;
pub mod panes;
pub mod side;
pub mod tier;

use crate::proto::app::App;
use crate::proto::core::Tier;
use crate::proto::layout::{Node, Preset, View};
use crate::proto::panels::split_areas;
use crate::proto::scenario::Scenario;
use canvas::{clip_text, mix, Cv};
use motion::{ease_in_out, ease_out, prog, secs};
use ratatui::layout::Rect;

fn preset_index(p: Option<Preset>) -> Option<usize> {
    p.map(|p| match p {
        Preset::Columns => 0,
        Preset::Build => 1,
        Preset::Agents => 2,
        Preset::Review => 3,
    })
}

/// Shrink every rect so panels sit one cell apart, keeping the edges
/// that touch the body's right and bottom flush.
fn with_gaps(body: Rect, rects: Vec<(Rect, View)>) -> Vec<(Rect, View)> {
    rects
        .into_iter()
        .map(|(mut r, v)| {
            if r.right() < body.right() {
                r.width = r.width.saturating_sub(1);
            }
            if r.bottom() < body.bottom() {
                r.height = r.height.saturating_sub(1);
            }
            (r, v)
        })
        .collect()
}

/// The views the picker offers, in digit order.
pub const PICKER_VIEWS: [View; 8] = [
    View::Conversation,
    View::Changes,
    View::Terminal,
    View::Plan,
    View::Activity,
    View::Context,
    View::Review,
    View::Agent,
];

/// A snapshot of what changes the animations: taken before and after
/// each key, so `Fx::observe` can stamp what moved.
#[derive(Clone, Debug)]
pub struct Snap {
    tree: Node,
    focus: usize,
    arranging: bool,
    sidebar: bool,
    picker: bool,
    overlay: u8,
    sel: usize,
}

impl Snap {
    /// `overlay`: 0 none, 1 palette, 2 help, 3 quit.
    pub fn of(app: &App, overlay: u8, sel: usize) -> Self {
        Snap {
            tree: app.tree.clone(),
            focus: app.focus,
            arranging: app.arranging,
            sidebar: app.sidebar,
            picker: app.picker.is_some(),
            overlay,
            sel,
        }
    }
}

/// Timestamps of the interface's own changes (focus, layout, arrange
/// mode, overlays), so the screen can animate between states.
#[derive(Clone, Debug, Default)]
pub struct Fx {
    pub focus_ms: Option<u64>,
    pub prev_focus: Option<usize>,
    pub layout_ms: Option<u64>,
    pub prev_tree: Option<Node>,
    pub prev_sidebar: bool,
    pub arrange_ms: Option<u64>,
    pub arrange_on: bool,
    pub picker_ms: u64,
    pub saved_ms: Option<u64>,
    pub overlay_ms: u64,
    pub sel_prev: usize,
    pub sel_ms: u64,
}

impl Fx {
    /// Stamp whatever differs between `before` and `after`.
    pub fn observe(&mut self, before: &Snap, after: &Snap, now_ms: u64) {
        if before.tree != after.tree || before.sidebar != after.sidebar {
            self.layout_ms = Some(now_ms);
            self.prev_tree = Some(before.tree.clone());
            self.prev_sidebar = before.sidebar;
            if before.tree != after.tree && !Self::is_preset(&after.tree) {
                self.saved_ms = Some(now_ms);
            }
        }
        if before.focus != after.focus {
            self.prev_focus = Some(before.focus);
            self.focus_ms = Some(now_ms);
        }
        if before.arranging != after.arranging {
            self.arrange_ms = Some(now_ms);
            self.arrange_on = after.arranging;
        }
        if !before.picker && after.picker {
            self.picker_ms = now_ms;
        }
        if before.overlay != after.overlay {
            self.overlay_ms = now_ms;
            self.sel_prev = 0;
            self.sel_ms = now_ms;
        }
        if before.sel != after.sel {
            self.sel_prev = before.sel;
            self.sel_ms = now_ms;
        }
    }

    fn is_preset(t: &Node) -> bool {
        [
            Preset::Columns,
            Preset::Build,
            Preset::Agents,
            Preset::Review,
        ]
        .into_iter()
        .any(|p| *t == Node::preset(p))
    }

    /// True while any interface motion is in flight (keeps the redraw
    /// alive).
    pub fn active(&self, now_ms: u64) -> bool {
        let recent =
            |t: Option<u64>, d: u64| t.map(|t| now_ms.saturating_sub(t) < d).unwrap_or(false);
        recent(self.focus_ms, 200)
            || recent(self.layout_ms, 300)
            || recent(self.arrange_ms, 200)
            || recent(self.saved_ms, 1900)
            || now_ms.saturating_sub(self.overlay_ms) < 400
            || now_ms.saturating_sub(self.picker_ms) < 300
            || now_ms.saturating_sub(self.sel_ms) < 150
    }
}

/// A text selection: the panel it belongs to and the two screen cells
/// that bound it. Isolation lives here — it never leaves its panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub panel: usize,
    pub a: (u16, u16),
    pub b: (u16, u16),
}

/// A panel's content cells: inside the border and below the header band.
pub fn content_rect(r: Rect) -> Rect {
    Rect {
        x: r.x + 2,
        y: r.y + 2,
        width: r.width.saturating_sub(4),
        height: r.height.saturating_sub(3),
    }
}

impl Selection {
    /// The selected spans as `(x, y, width)` rows, clamped to `inner`
    /// and read as a stream: the first row from the anchor to the edge,
    /// middle rows whole, the last row up to the other end.
    pub fn rows(&self, inner: Rect) -> Vec<(i32, i32, i32)> {
        if inner.width == 0 || inner.height == 0 {
            return Vec::new();
        }
        let clamp = |p: (u16, u16)| {
            (
                p.0.clamp(inner.x, inner.right() - 1),
                p.1.clamp(inner.y, inner.bottom() - 1),
            )
        };
        let (mut p, mut q) = (clamp(self.a), clamp(self.b));
        if (q.1, q.0) < (p.1, p.0) {
            std::mem::swap(&mut p, &mut q);
        }
        (p.1..=q.1)
            .map(|y| {
                let x0 = if y == p.1 { p.0 } else { inner.x };
                let x1 = if y == q.1 { q.0 } else { inner.right() - 1 };
                (x0 as i32, y as i32, (x1 as i32 - x0 as i32 + 1).max(1))
            })
            .collect()
    }
}

/// The final panel rectangles for hit-testing the mouse: `(index, outer
/// rect, view)` as drawn once any glide has settled.
pub fn panel_rects(area: Rect, app: &App) -> Vec<(usize, Rect, View)> {
    let (areas, _) = layout(area, &app.tree, app.sidebar && !app.zoom);
    let focus = app.focus.min(areas.len().saturating_sub(1));
    if area.width < 120 || app.zoom {
        return vec![(
            focus,
            Rect {
                x: 1,
                y: 1,
                width: area.width.saturating_sub(2),
                height: area.height.saturating_sub(2),
            },
            areas.get(focus).map(|a| a.1).unwrap_or(View::Conversation),
        )];
    }
    areas
        .into_iter()
        .enumerate()
        .map(|(i, (r, v))| (i, r, v))
        .collect()
}

/// A toast to show.
pub struct ToastIn<'a> {
    pub text: &'a str,
    pub ok: bool,
    pub shown_ms: u64,
}

/// What `draw` needs beyond the scenario.
pub struct DrawIn<'a> {
    pub app: &'a App,
    pub fx: &'a Fx,
    pub scenario: &'a Scenario,
    pub composer: &'a str,
    /// The highlighted row of the `/` command list.
    pub completion_sel: usize,
    pub now_ms: u64,
    pub reduced: bool,
    /// Colour effects off (the spec): under 16 colours or no colour,
    /// shimmer/fades/flashes switch off at the source — glyph motion
    /// (typing, reveals, stars) is unaffected and stays on `reduced`.
    pub mono: bool,
    pub tier: Tier,
    pub scroll_offset: usize,
    /// One scroll offset per panel (reading order): the wheel and
    /// PgUp/PgDn move only the panel they are aimed at.
    pub scrolls: &'a [usize],
    /// The text selection, bound to one panel.
    pub selection: Option<Selection>,
    pub brand: crate::proto::welcome::BrandTier,
    pub toast: Option<ToastIn<'a>>,
    pub overlay: Option<overlays::Overlay<'a>>,
}

fn lerp_rect(a: Rect, b: Rect, p: f32) -> Rect {
    let l = |x: u16, y: u16| (x as f32 + (y as f32 - x as f32) * p).round().max(0.0) as u16;
    Rect {
        x: l(a.x, b.x),
        y: l(a.y, b.y),
        width: l(a.width, b.width).max(1),
        height: l(a.height, b.height).max(1),
    }
}

/// The panel rectangles for `tree` (with the sidebar's column).
fn layout(area: Rect, tree: &Node, sidebar: bool) -> (Vec<(Rect, View)>, u16) {
    let one = area.width < 120;
    let side_w = if sidebar && !one { side::WIDTH } else { 0 };
    let body_x = if side_w > 0 { side_w + 1 } else { 1 };
    let body = Rect {
        x: body_x,
        y: 1,
        width: area.width.saturating_sub(body_x),
        height: area.height.saturating_sub(2),
    };
    (with_gaps(body, split_areas(body, tree)), side_w)
}

/// Draw the whole screen into `f`.
pub fn draw(f: &mut ratatui::Frame, inp: &DrawIn) {
    let _ = draw_with_hits(f, inp);
}

/// Draw the whole screen into `f` and return what the frame made
/// clickable, in drawing order (later = on top).
pub fn draw_with_hits(f: &mut ratatui::Frame, inp: &DrawIn) -> Vec<hits::Hit> {
    let area = f.area();
    let (w, h) = (area.width as i32, area.height as i32);
    let s = inp.scenario;
    let sh = inp.app;
    let now = secs(inp.now_ms);
    let red = inp.reduced;
    let narrow = area.width < 120;
    // A zoomed panel fills the screen the way a narrow one does.
    let one_at_a_time = narrow || sh.zoom;
    let hits = {
        let mut cv = Cv::new(f.buffer_mut());
        cv.fill(0, 0, w, h, pal::APP);

        let (new_areas, side_w) = layout(area, &sh.tree, sh.sidebar && !sh.zoom);
        let focus = sh.focus.min(new_areas.len().saturating_sub(1));

        // M21: panel rectangles glide from the old layout to the new.
        let mut rects: Vec<(Rect, View)> = new_areas.clone();
        // The closing panel's ghost: old rects whose view vanished
        // shrink to their centre and fade — a close should feel like
        // the panel leaving, not the neighbours sliding over nothing.
        let mut ghosts: Vec<(Rect, View, f32)> = Vec::new();
        if let (Some(t0), Some(prev)) = (inp.fx.layout_ms, &inp.fx.prev_tree) {
            let p = ease_in_out(prog(now, Some(secs(t0)), 0.24, red));
            if p < 1.0 {
                let (old, _) = layout(area, prev, inp.fx.prev_sidebar);
                rects = new_areas
                    .iter()
                    .enumerate()
                    .map(|(i, (nr, v))| {
                        let from = old.get(i).map(|o| o.0).unwrap_or_else(|| {
                            // A new panel grows out of its own centre.
                            Rect {
                                x: nr.x + nr.width / 2,
                                y: nr.y + nr.height / 2,
                                width: 1,
                                height: 1,
                            }
                        });
                        (lerp_rect(from, *nr, p), *v)
                    })
                    .collect();
                // Old views with no surviving same-view panel are the
                // closed one(s): a view can appear at most once, so
                // absence means closed.
                for (or, ov) in &old {
                    if !new_areas.iter().any(|(_, v)| v == ov) {
                        let to = Rect {
                            x: or.x + or.width / 2,
                            y: or.y + or.height / 2,
                            width: 1,
                            height: 1,
                        };
                        ghosts.push((lerp_rect(*or, to, p), *ov, 1.0 - p));
                    }
                }
            }
        }

        let areas: Vec<(usize, Rect, View)> = if one_at_a_time {
            vec![(
                focus,
                Rect {
                    x: 1,
                    y: 1,
                    width: area.width.saturating_sub(2),
                    height: area.height.saturating_sub(2),
                },
                new_areas
                    .get(focus)
                    .map(|a| a.1)
                    .unwrap_or(View::Conversation),
            )]
        } else {
            rects
                .iter()
                .enumerate()
                .map(|(i, (r, v))| (i, *r, *v))
                .collect()
        };

        // Top bar.
        let switcher = narrow.then(|| {
            new_areas
                .iter()
                .enumerate()
                .map(|(i, (_, v))| {
                    let attn = *v == View::Conversation && s.approval_pending.is_some();
                    (i + 1, v.title().to_string(), attn)
                })
                .collect::<Vec<_>>()
        });
        bars::top_bar(
            &mut cv,
            w,
            &bars::TopBar {
                scenario: s,
                preset: preset_index(sh.current_preset()),
                approval_pending: s.approval_pending.is_some(),
                now_ms: inp.now_ms,
                mono: inp.mono,
                reduced: red,
                switcher,
                focus_idx: focus,
                cwd: bars::cwd_label(),
                branch: bars::branch_label(),
                saved_ms: inp.fx.saved_ms,
                zoom: sh.zoom,
            },
        );

        // M01: at launch the conversation unfolds first (320 ms), the
        // other panels 120 ms apart after it.
        let conv_idx = new_areas
            .iter()
            .position(|a| a.1 == View::Conversation)
            .unwrap_or(0);
        let animate_start = inp.brand == crate::proto::welcome::BrandTier::Anim && !red;

        if side_w > 0 {
            // The sidebar fades in over 260 ms at launch — the
            // conversation unfolds into it, so it arrives just before.
            let side_reveal = if animate_start {
                ease_out((now / 0.26).clamp(0.0, 1.0))
            } else {
                1.0
            };
            let side_rect = Rect {
                x: 0,
                y: 1,
                width: side_w,
                height: area.height.saturating_sub(2),
            };
            if side_reveal >= 1.0 {
                side::draw(&mut cv, side_rect, s, inp.now_ms, red, inp.mono);
            } else {
                cv.veil(
                    0,
                    1,
                    side_w as i32,
                    side_rect.height as i32,
                    pal::SIDEBAR,
                    1.0 - side_reveal,
                );
                cv.clipped(side_rect, |cv| {
                    side::draw(cv, side_rect, s, inp.now_ms, red, inp.mono);
                });
            }
        }

        // Panels.
        let panel_hits = cv.hit_mark();
        let heavy_ms = inp.fx.focus_ms;
        for (i, r, view) in &areas {
            // M20: the heavy border grows from the panel number both
            // ways in 140 ms; the old one fades to thin.
            let (sweep, fade) = if *i == focus {
                (ease_out(prog(now, heavy_ms.map(secs), 0.14, red)), None)
            } else if Some(*i) == inp.fx.prev_focus {
                let f = prog(now, heavy_ms.map(secs), 0.14, red);
                (0.0, (f < 1.0).then_some(f))
            } else {
                (0.0, None)
            };
            let focus_in = frame::FocusFx { sweep, fade };
            let reveal = if animate_start && !one_at_a_time {
                let rank = (*i as i32 - conv_idx as i32).unsigned_abs() as f32;
                let start = if rank == 0.0 { 0.0 } else { 0.12 * rank };
                ease_out(((now - start) / 0.32).clamp(0.0, 1.0))
            } else {
                1.0
            };
            let shown = if reveal < 1.0 {
                let hh = ((r.height as f32 * reveal).round() as u16).max(1);
                Rect {
                    x: r.x,
                    y: r.y + (r.height - hh) / 2,
                    width: r.width,
                    height: hh,
                }
            } else {
                *r
            };
            cv.clipped(shown, |cv| {
                if *view == View::Conversation {
                    convo::draw(
                        cv,
                        *r,
                        &convo::ConvIn {
                            s,
                            now_ms: inp.now_ms,
                            reduced: red,
                            mono: inp.mono,
                            composer: inp.composer,
                            completion_sel: inp.completion_sel,
                            focused: *i == focus,
                            focus_fx: focus_in,
                            scroll_offset: inp
                                .scrolls
                                .get(*i)
                                .copied()
                                .unwrap_or(inp.scroll_offset),
                            num: i + 1,
                            brand: inp.brand,
                        },
                    );
                } else {
                    panes::draw(
                        cv,
                        *r,
                        *view,
                        &panes::PaneIn {
                            s,
                            now_ms: inp.now_ms,
                            reduced: red,
                            mono: inp.mono,
                            focused: *i == focus,
                            focus_fx: focus_in,
                            num: i + 1,
                            agent: &sh.tree.agent_at(*i),
                            scroll: inp.scrolls.get(*i).copied().unwrap_or(0),
                        },
                    );
                }
            });
        }

        // While arranging, the panels are dimmed and numbered: a click
        // focuses one (the runtime does that), it does not press the keys
        // of a footer hint under the veil.
        if sh.arranging {
            cv.truncate_hits(panel_hits);
        }

        // The closing panel's ghost: a fading flat card behind the
        // gliding survivors — read as the panel shrinking away.
        for (r, view, fade) in &ghosts {
            if *fade <= 0.02 {
                continue;
            }
            let col = view_colour(*view);
            cv.clipped(*r, |cv| {
                cv.fill(
                    r.x as i32,
                    r.y as i32,
                    r.width as i32,
                    r.height as i32,
                    mix(pal::PANEL, col, 0.25 * fade),
                );
                let title = clip_text(view.title(), r.width as i32 - 4);
                cv.text(
                    r.x as i32 + 2,
                    r.y as i32,
                    &title,
                    mix(pal::FAINT, col, *fade),
                    Some(mix(pal::PANEL, col, 0.25 * fade)),
                );
            });
        }

        // The selection is bound to one panel: it is clamped to that
        // panel's content and drawn only inside it.
        if let Some(sel) = &inp.selection {
            if let Some((_, r, _)) = areas.iter().find(|(i, _, _)| *i == sel.panel) {
                for (x, y, w) in sel.rows(content_rect(*r)) {
                    cv.wash(x, y, w, 1, canvas::mix(pal::PANEL, pal::CYAN, 0.32));
                }
            }
        }

        // M22: arranging dims every panel and shows its number big.
        let nav_a = match (inp.fx.arrange_ms, sh.arranging) {
            (Some(t), true) => ease_out(prog(now, Some(secs(t)), 0.12, red)),
            (Some(t), false) => 1.0 - prog(now, Some(secs(t)), 0.12, red),
            (None, true) => 1.0,
            _ => 0.0,
        };
        if nav_a > 0.0 && !one_at_a_time {
            for (i, r, view) in &areas {
                cv.veil(
                    r.x as i32,
                    r.y as i32,
                    r.width as i32,
                    r.height as i32,
                    pal::APP,
                    0.55 * nav_a,
                );
                overlays::nav_badge(&mut cv, *r, i + 1, view_colour(*view), nav_a, view.title());
            }
        }

        // Status line.
        let fv = sh.focused_view();
        bars::status_line(
            &mut cv,
            w,
            h - 1,
            s,
            inp.now_ms,
            red,
            inp.mono,
            fv == View::Conversation,
            matches!(fv, View::Changes | View::Review),
            sh.arranging,
        );

        // Overlays on top: the picker, the palette/help/quit card, the toast.
        // A modal swallows the clicks aimed at what is behind it: this
        // region sits under the overlay's own, so only the overlay's
        // controls (drawn after) answer, and a click anywhere else closes
        // it.
        if sh.picker.is_some() || inp.overlay.is_some() {
            cv.hit(0, 0, w, h, hits::Click::Dismiss);
        }
        if sh.picker.is_some() {
            overlays::picker(&mut cv, w, h, inp.fx.picker_ms, inp.now_ms, red);
        }
        if let Some(ov) = &inp.overlay {
            overlays::draw(&mut cv, w, h, ov, inp.now_ms, red);
        }
        if let Some(t) = &inp.toast {
            overlays::toast(
                &mut cv, w, h, t.text, t.ok, t.shown_ms, 3000, inp.now_ms, red,
            );
        }
        cv.take_hits()
    };
    tier::apply(f.buffer_mut(), inp.tier);
    hits
}

fn view_colour(v: View) -> canvas::Rgb {
    match v {
        View::Conversation | View::Agent => pal::MAGENTA,
        View::Changes | View::Review => pal::VIOLET,
        View::Terminal => pal::AMBER,
        View::Plan => pal::CYAN,
        View::Activity => pal::GREEN,
        View::Context => pal::BLUE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn render(sh: &App, s: &Scenario, w: u16, h: u16) -> String {
        let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| {
            draw(
                f,
                &DrawIn {
                    app: sh,
                    fx: &Fx::default(),
                    scenario: s,
                    composer: "",
                    completion_sel: 0,
                    now_ms: 5_000,
                    reduced: true,
                    tier: Tier::TrueColor,
                    mono: false,
                    scroll_offset: 0,
                    scrolls: &[],
                    selection: None,
                    brand: crate::proto::welcome::BrandTier::Static,
                    toast: None,
                    overlay: None,
                },
            )
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn default_layout_has_three_numbered_panels() {
        let out = render(
            &App::new(std::path::PathBuf::new(), true),
            &Scenario::new(),
            164,
            48,
        );
        assert!(out.contains(" 1 "), "{out}");
        assert!(out.contains("Changes"), "{out}");
        assert!(out.contains("New session"), "{out}");
        assert!(out.contains("Terminal"), "{out}");
        assert!(out.contains("No changes yet"), "{out}");
        assert!(out.contains("No commands yet"), "{out}");
        assert!(out.contains("columns"), "{out}");
        assert!(out.contains("ORBIT"), "{out}");
    }

    fn app_with(preset: Preset) -> App {
        let mut a = App::new(std::path::PathBuf::new(), true);
        a.key(crate::proto::app::Key::Esc);
        // `]` walks columns → build → agents → review.
        let steps = match preset {
            Preset::Columns => 0,
            Preset::Build => 1,
            Preset::Agents => 2,
            Preset::Review => 3,
        };
        for _ in 0..steps {
            a.key(crate::proto::app::Key::Char(']'));
        }
        a.key(crate::proto::app::Key::Esc);
        a
    }

    fn busy() -> Scenario {
        use crate::proto::panels::{FileChangeRow, TaskRow};
        use crate::proto::scenario::{LineKind, ToolState, TranscriptLine};
        let mut s = Scenario::new();
        s.model_id = "opus 5.5".into();
        s.file_changes = vec![FileChangeRow {
            path: "crates/export/src/restore.rs".into(),
            added: 3,
            removed: 1,
            hunks: None,
        }];
        s.tasks = vec![
            TaskRow {
                title: "Find the chain".into(),
                status: "done".into(),
            },
            TaskRow {
                title: "Run the tests".into(),
                status: "active".into(),
            },
        ];
        s.transcript.push(TranscriptLine {
            kind: LineKind::Tool,
            text: "cargo test -p orbit-export".into(),
            tool_name: "bash".into(),
            tool_state: ToolState::Done,
            meta: "done · 4.8s".into(),
            ..Default::default()
        });
        s.tool_output = vec!["running 6 tests".into()];
        s.activity = vec![
            crate::proto::scenario::ActivityRow {
                time: "14:02:11".into(),
                kind: "verdict".into(),
                target: "Bash(cargo test -p orbit-export)".into(),
                fact: "allowed — operator approved".into(),
                digest: Some("a1b2c3d4e5f6".into()),
            },
            crate::proto::scenario::ActivityRow {
                time: "14:02:16".into(),
                kind: "result".into(),
                target: "Bash(cargo test -p orbit-export)".into(),
                fact: "ok".into(),
                digest: Some("0f9e8d7c6b5a".into()),
            },
        ];
        s
    }

    #[test]
    fn build_preset_shows_the_sidebar_and_stacks_changes_over_terminal() {
        let out = render(&app_with(Preset::Build), &busy(), 164, 48);
        for want in [
            "SESSIONS",
            "AGENTS",
            "SHELLS",
            "PLAN",
            "1/2",
            " 1  Conversation",
            " 2  Changes",
            " 3  Terminal",
        ] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
        assert!(out.contains("restore.rs") && out.contains("+3"), "{out}");
        assert!(out.contains("running 6 tests"), "{out}");
    }

    #[test]
    fn agents_preset_names_its_agent_panels() {
        let out = render(&app_with(Preset::Agents), &busy(), 164, 48);
        assert!(
            out.contains("Agent · explore") && out.contains("Agent · review"),
            "{out}"
        );
        assert!(out.contains("No agent yet"), "{out}");
    }

    #[test]
    fn review_preset_lists_files_beside_plan_and_activity() {
        let out = render(&app_with(Preset::Review), &busy(), 164, 48);
        for want in [
            "Review",
            "FILES",
            "Plan",
            "1/2 done",
            "Activity",
            "2 events",
            "allowed",
            "Bash(cargo test",
            "#a1b2c3",
            "#0f9e8d",
        ] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
    }

    /// The screen with the diff overlay open on `file`.
    fn render_diff_overlay(file: &crate::proto::panels::FileChangeRow, w: u16, h: u16) -> String {
        let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        let s = busy();
        let app = App::new(std::path::PathBuf::new(), true);
        term.draw(|f| {
            draw(
                f,
                &DrawIn {
                    app: &app,
                    fx: &Fx::default(),
                    scenario: &s,
                    composer: "",
                    completion_sel: 0,
                    now_ms: 5_000,
                    reduced: true,
                    tier: Tier::TrueColor,
                    mono: false,
                    scroll_offset: 0,
                    scrolls: &[],
                    selection: None,
                    brand: crate::proto::welcome::BrandTier::Static,
                    toast: None,
                    overlay: Some(overlays::Overlay::Diff {
                        path: &file.path,
                        added: file.added,
                        removed: file.removed,
                        hunks: &file.hunks,
                        opened_ms: 0,
                    }),
                },
            )
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn row_of(out: &str, needle: &str) -> usize {
        out.lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no row with {needle:?}\n{out}"))
    }

    /// The overlay's hint used to share a row with the last diff line
    /// (box height and footer row agreed on the same row).
    #[test]
    fn the_diff_overlay_footer_sits_below_the_last_line() {
        let f = &two_files().file_changes[0];
        let out = render_diff_overlay(f, 110, 40);
        let last = row_of(&out, "+ new_tail()");
        let hint = row_of(&out, "esc close");
        let border = row_of(&out, "┗");
        assert!(
            last < hint && hint < border,
            "{last} {hint} {border}\n{out}"
        );
    }

    /// With no diff to show the box holds both note lines — they used to
    /// be drawn over its bottom border.
    #[test]
    fn the_diff_overlay_note_stays_inside_the_box() {
        let f = &two_files().file_changes[1]; // hunks: None
        let out = render_diff_overlay(f, 110, 40);
        let note = row_of(&out, "◌ no diff captured");
        let why = row_of(&out, "without a \"before\"");
        let hint = row_of(&out, "esc close");
        let border = row_of(&out, "┗");
        assert!(note < why && why < hint && hint < border, "{out}");
    }

    /// A short terminal cannot hold the whole diff: the last row says how
    /// much is cut instead of dropping lines silently.
    #[test]
    fn the_diff_overlay_in_a_short_terminal_says_what_is_cut() {
        let many: Vec<(char, String)> = (0..40).map(|i| ('+', format!("line {i}"))).collect();
        let f = crate::proto::panels::FileChangeRow {
            path: "big.rs".into(),
            added: 40,
            removed: 0,
            hunks: Some(vec![orbit_frontend_protocol::DiffHunk {
                old_start: 0,
                old_lines: 0,
                new_start: 1,
                new_lines: 40,
                lines: many,
            }]),
        };
        let out = render_diff_overlay(&f, 110, 20);
        assert!(out.contains("more lines"), "{out}");
        assert!(!out.contains("line 39"), "{out}");
        assert!(
            row_of(&out, "more lines") < row_of(&out, "esc close"),
            "{out}"
        );
    }

    fn hunk(start: u32, lines: &[(char, &str)]) -> orbit_frontend_protocol::DiffHunk {
        orbit_frontend_protocol::DiffHunk {
            old_start: start,
            old_lines: 1,
            new_start: start,
            new_lines: 1,
            lines: lines.iter().map(|(m, t)| (*m, t.to_string())).collect(),
        }
    }

    fn two_files() -> Scenario {
        use crate::proto::panels::FileChangeRow;
        let mut s = busy();
        s.file_changes = vec![
            FileChangeRow {
                path: "src/a.rs".into(),
                added: 2,
                removed: 2,
                hunks: Some(vec![
                    hunk(
                        3,
                        &[
                            (' ', "fn keep() {}"),
                            ('-', "let x = 1;"),
                            ('+', "let x = 2;"),
                        ],
                    ),
                    hunk(40, &[('-', "old_tail()"), ('+', "new_tail()")]),
                ]),
            },
            FileChangeRow {
                path: "src/b.rs".into(),
                added: 1,
                removed: 0,
                hunks: None,
            },
        ];
        s
    }

    /// The Review panel used to print a fixed sentence under the file name
    /// whether or not the engine had sent hunks. It draws the selected
    /// file's real hunks, from the current one, and says which of how many.
    #[test]
    fn review_draws_the_selected_files_real_hunks() {
        let mut s = two_files();
        let out = render(&app_with(Preset::Review), &s, 164, 48);
        assert!(!out.contains("The diff appears here"), "{out}");
        for want in [
            "src/a.rs",
            "hunk 1/2",
            "@@ -3,1 +3,1 @@",
            "fn keep() {}",
            "- let x = 1;",
            "+ let x = 2;",
        ] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
        // `n`: the second hunk leads, the first is scrolled off.
        s.move_hunk_selection(1);
        let out = render(&app_with(Preset::Review), &s, 164, 48);
        assert!(
            out.contains("hunk 2/2") && out.contains("@@ -40,1 +40,1 @@"),
            "{out}"
        );
        assert!(out.contains("+ new_tail()"), "{out}");
        assert!(!out.contains("let x = 2;"), "{out}");
    }

    /// `j` moves the selection to the next file and the pane follows. A
    /// file with no captured "before" says so plainly.
    #[test]
    fn review_follows_the_file_selection_and_is_honest_without_hunks() {
        let mut s = two_files();
        s.move_file_selection(1);
        let out = render(&app_with(Preset::Review), &s, 164, 48);
        assert!(out.contains("◌ no diff captured"), "{out}");
        assert!(!out.contains("let x = 2;"), "{out}");
        // The selection bar is on b.rs, not a.rs.
        // (The path also heads the right pane; the list row carries counts.)
        let row = |name: &str, counts: &str| {
            out.lines()
                .find(|l| l.contains(name) && l.contains(counts))
                .unwrap_or_else(|| panic!("no list row for {name}\n{out}"))
                .to_string()
        };
        assert!(
            row("src/b.rs", "+1").contains('▌'),
            "{}",
            row("src/b.rs", "+1")
        );
        assert!(
            !row("src/a.rs", "+2").contains('▌'),
            "{}",
            row("src/a.rs", "+2")
        );
    }

    /// A hunk longer than the pane gives its last row to "N more" instead
    /// of cutting a line off silently.
    #[test]
    fn review_says_how_much_more_there_is() {
        use crate::proto::panels::FileChangeRow;
        let mut s = busy();
        let many: Vec<(char, String)> = (0..80).map(|i| ('+', format!("line {i}"))).collect();
        s.file_changes = vec![FileChangeRow {
            path: "big.rs".into(),
            added: 80,
            removed: 0,
            hunks: Some(vec![orbit_frontend_protocol::DiffHunk {
                old_start: 1,
                old_lines: 0,
                new_start: 1,
                new_lines: 80,
                lines: many,
            }]),
        }];
        let out = render(&app_with(Preset::Review), &s, 164, 30);
        assert!(out.contains("more · ⏎ full diff"), "{out}");
        assert!(out.contains("line 0") && !out.contains("line 79"), "{out}");
    }

    /// The footers only advertise keys that do something.
    #[test]
    fn panel_footers_name_only_keys_that_work() {
        let s = two_files();
        let out = render(&app_with(Preset::Review), &s, 164, 48);
        assert!(!out.contains("revert"), "no revert exists yet\n{out}");
        assert!(
            !out.contains("step"),
            "the plan has no step selection\n{out}"
        );
    }

    fn agent(
        name: &str,
        task: &str,
        action: &str,
        done: Option<(bool, &str)>,
    ) -> crate::proto::scenario::Agent {
        crate::proto::scenario::Agent {
            name: name.into(),
            task: task.into(),
            action: action.into(),
            report: done.map(|(_, r)| r.to_string()).unwrap_or_default(),
            done: done.is_some(),
            ok: done.map(|(ok, _)| ok).unwrap_or(true),
            started_ms: 1_500,
            done_ms: done.map(|_| 3_500),
        }
    }

    /// A running subagent shows who, for how long, what it was asked, and
    /// what it is doing right now.
    #[test]
    fn the_agent_panel_shows_a_running_subagent() {
        let mut s = busy();
        s.agents.insert(
            "a1".into(),
            agent(
                "Explore",
                "find where add() is defined",
                "Read calc.py",
                None,
            ),
        );
        let out = render(&app_with(Preset::Agents), &s, 164, 48);
        for want in [
            "Agent · explore",
            "Explore",
            "3.5s",
            "find where add() is defined",
            "▸ Read calc.py",
        ] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
        // The panel named `review` shows nobody else's agent.
        assert!(out.contains("No agent yet"), "{out}");
    }

    /// A finished subagent shows its report, wrapped; a failed one says
    /// failed, in words and a glyph.
    #[test]
    fn the_agent_panel_shows_how_it_ended() {
        let mut s = busy();
        s.agents.insert(
            "a1".into(),
            agent(
                "Explore",
                "find add()",
                "Read calc.py",
                Some((
                    true,
                    "add() is defined in calc.py and it subtracts instead of adding.",
                )),
            ),
        );
        let out = render(&app_with(Preset::Agents), &s, 164, 48);
        for want in ["✓", "done · 2.0s", "subtracts instead", "find add()"] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
        assert!(
            !out.contains("▸ Read calc.py"),
            "a finished agent shows its report, not its last action"
        );

        let mut f = busy();
        f.agents.insert(
            "a1".into(),
            agent(
                "Explore",
                "find add()",
                "",
                Some((false, "ORBIT-E0403 credential_rejected")),
            ),
        );
        let out = render(&app_with(Preset::Agents), &f, 164, 48);
        for want in ["✕", "failed · 2.0s", "credential_rejected"] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
        }
    }

    /// The panel is named in lower case ("explore"), the agent in its own
    /// ("Explore"): they still match.
    #[test]
    fn an_agent_panel_matches_its_agent_whatever_the_case() {
        let mut s = busy();
        s.agents
            .insert("a1".into(), agent("explore", "t", "", None));
        let out = render(&app_with(Preset::Agents), &s, 164, 48);
        assert!(out.contains("starting…"), "{out}");
    }

    /// In a side column a record takes two lines: the OUTCOME and the proof
    /// hash on the first (nothing a long command can clip), the target
    /// under it.
    #[test]
    fn activity_in_a_side_column_leads_with_the_outcome() {
        let out = render(&app_with(Preset::Review), &busy(), 164, 48);
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("allowed"))
            .unwrap_or_else(|| panic!("no verdict row\n{out}"));
        assert!(lines[i].contains("14:02:11"), "time\n{}", lines[i]);
        assert!(
            lines[i].contains("#a1b2c3"),
            "hash on the same line\n{}",
            lines[i]
        );
        assert!(
            lines[i + 1].contains("Bash(cargo test"),
            "target on the next line\n{}",
            lines[i + 1]
        );
    }

    /// Given room (a zoomed panel, a big terminal) every record is ONE
    /// line: time, kind, outcome, target, reason and hash together.
    #[test]
    fn activity_given_room_is_one_line_per_record() {
        let out = render(&app_with(Preset::Review), &busy(), 300, 48);
        let row = out
            .lines()
            .find(|l| l.contains("allowed"))
            .unwrap_or_else(|| panic!("no verdict row\n{out}"));
        for want in [
            "14:02:11",
            "allowed",
            "Bash(cargo test -p orbit-export)",
            "operator approved",
            "#a1b2c3",
        ] {
            assert!(row.contains(want), "missing {want:?}\n{row}");
        }
    }

    #[test]
    fn top_bar_carries_cwd_model_context_and_cost() {
        let mut s = busy();
        s.window_tokens = 1000;
        s.used_tokens = 500;
        s.ctx_to = 0.5;
        s.priced = true;
        s.cost_microcents = 66_000;
        s.ledger_count = Some(1314);
        let out = render(&App::new(std::path::PathBuf::new(), true), &s, 164, 48);
        let row0 = out.lines().next().unwrap();
        for want in ["opus 5.5", "ctx", "50%", "1,314", "$0.066"] {
            assert!(row0.contains(want), "missing {want:?}\n{row0}");
        }
    }

    #[test]
    fn one_panel_at_a_time_under_120() {
        let out = render(
            &App::new(std::path::PathBuf::new(), true),
            &Scenario::new(),
            100,
            32,
        );
        assert!(!out.contains("No changes yet"), "{out}");
        assert!(
            out.contains("1 Changes"),
            "switcher lists every panel\n{out}"
        );
    }

    fn cells(
        sh: &App,
        fx: &Fx,
        s: &Scenario,
        now_ms: u64,
        tier: Tier,
        ov: Option<overlays::Overlay>,
        toast: Option<ToastIn>,
    ) -> ratatui::buffer::Buffer {
        let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
        term.draw(|f| {
            draw(
                f,
                &DrawIn {
                    app: sh,
                    fx,
                    scenario: s,
                    composer: "",
                    completion_sel: 0,
                    now_ms,
                    reduced: false,
                    tier,
                    mono: tier >= Tier::T16,
                    scroll_offset: 0,
                    scrolls: &[],
                    selection: None,
                    brand: crate::proto::welcome::BrandTier::Static,
                    toast,
                    overlay: ov,
                },
            )
        })
        .unwrap();
        term.backend().buffer().clone()
    }

    fn row(buf: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    #[test]
    fn a_layout_change_glides_over_240_ms() {
        let before = App::new(std::path::PathBuf::new(), true);
        let mut after = before.clone_for_test();
        after.tree = Node::preset(Preset::Review);
        let mut fx = Fx::default();
        fx.observe(&Snap::of(&before, 0, 0), &Snap::of(&after, 0, 0), 1000);
        let s = Scenario::new();
        let mid = cells(&after, &fx, &s, 1100, Tier::TrueColor, None, None);
        let end = cells(&after, &fx, &s, 1400, Tier::TrueColor, None, None);
        assert_ne!(
            row(&mid, 2),
            row(&end, 2),
            "panels are between layouts mid-glide"
        );
        assert!(row(&end, 2).contains("Review"), "{}", row(&end, 2));
    }

    #[test]
    fn the_focus_border_sweeps_out_from_the_number_chip() {
        let mut app = App::new(std::path::PathBuf::new(), true);
        let before = app.clone_for_test();
        app.focus = 0;
        let mut fx = Fx::default();
        fx.observe(&Snap::of(&before, 0, 0), &Snap::of(&app, 0, 0), 1000);
        let s = Scenario::new();
        let heavy = |buf: &ratatui::buffer::Buffer| {
            (0..48u16)
                .map(|y| row(buf, y))
                .collect::<String>()
                .matches('┃')
                .count()
        };
        let early = cells(&app, &fx, &s, 1020, Tier::TrueColor, None, None);
        let done = cells(&app, &fx, &s, 1300, Tier::TrueColor, None, None);
        assert!(
            heavy(&early) < heavy(&done),
            "the heavy border grows ({} → {})",
            heavy(&early),
            heavy(&done)
        );
    }

    #[test]
    fn arrange_mode_dims_panels_and_shows_big_numbers() {
        let mut app = App::new(std::path::PathBuf::new(), true);
        app.arranging = true;
        let fx = Fx::default();
        let buf = cells(
            &app,
            &fx,
            &Scenario::new(),
            5000,
            Tier::TrueColor,
            None,
            None,
        );
        let all: String = (0..48u16)
            .map(|y| row(&buf, y))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("NAVIGATE") && all.contains("▄█"), "{all}");
    }

    #[test]
    fn the_palette_rows_drop_in_and_the_toast_slides() {
        let app = App::new(std::path::PathBuf::new(), true);
        let fx = Fx::default();
        let s = Scenario::new();
        let ov = |t| {
            Some(overlays::Overlay::Palette {
                query: "",
                sel: 0,
                sel_prev: 0,
                opened_ms: 1000,
                sel_ms: 0,
            })
            .map(|o| (o, t))
        };
        let early = cells(
            &app,
            &fx,
            &s,
            1020,
            Tier::TrueColor,
            ov(0).map(|o| o.0),
            None,
        );
        let late = cells(
            &app,
            &fx,
            &s,
            1400,
            Tier::TrueColor,
            ov(0).map(|o| o.0),
            None,
        );
        let count =
            |b: &ratatui::buffer::Buffer| (0..48u16).filter(|y| row(b, *y).contains("/")).count();
        assert!(count(&early) < count(&late), "rows drop in");
        let t0 = cells(
            &app,
            &fx,
            &s,
            1010,
            Tier::TrueColor,
            None,
            Some(ToastIn {
                text: "saved",
                ok: true,
                shown_ms: 1000,
            }),
        );
        let t1 = cells(
            &app,
            &fx,
            &s,
            1400,
            Tier::TrueColor,
            None,
            Some(ToastIn {
                text: "saved",
                ok: true,
                shown_ms: 1000,
            }),
        );
        let pos = |b: &ratatui::buffer::Buffer| (0..48u16).find_map(|y| row(b, y).find("saved"));
        assert!(pos(&t1).is_some());
        assert!(
            pos(&t0).map(|p| p > pos(&t1).unwrap()).unwrap_or(true),
            "slides in from the right"
        );
    }

    #[test]
    fn the_mode_pill_wipes_between_modes() {
        let app = App::new(std::path::PathBuf::new(), true);
        let mut s = Scenario::new();
        s.permission_mode = Some("acceptEdits".into());
        s.mode_prev = Some("default".into());
        s.mode_changed_ms = Some(1000);
        let colours = |ms| {
            let b = cells(&app, &Fx::default(), &s, ms, Tier::TrueColor, None, None);
            (1..15u16)
                .map(|x| b[(x, 47)].bg)
                .collect::<std::collections::HashSet<_>>()
                .len()
        };
        assert!(colours(1120) >= 2, "both colours show mid-wipe");
        assert_eq!(colours(1500), 1, "settled on one colour");
    }

    #[test]
    fn colour_tiers_map_the_whole_screen() {
        let app = App::new(std::path::PathBuf::new(), true);
        let s = Scenario::new();
        for (tier, ok) in [(Tier::T256, 1), (Tier::T16, 2), (Tier::None, 3)] {
            let b = cells(&app, &Fx::default(), &s, 5000, tier, None, None);
            let rgb = (0..48u16)
                .flat_map(|y| (0..164u16).map(move |x| (x, y)))
                .filter(|&(x, y)| {
                    matches!(b[(x, y)].fg, ratatui::style::Color::Rgb(..))
                        || matches!(b[(x, y)].bg, ratatui::style::Color::Rgb(..))
                })
                .count();
            assert_eq!(rgb, 0, "no true-colour cells left under {tier:?} ({ok})");
        }
    }

    #[test]
    fn zoom_shows_only_the_focused_panel_with_a_zoom_pill() {
        let mut app = App::new(std::path::PathBuf::new(), true);
        app.focus = 2; // Terminal
        app.zoom = true;
        let out = render(&app, &Scenario::new(), 164, 48);
        assert!(out.contains("ZOOM"), "{out}");
        assert!(out.contains("No commands yet"), "{out}");
        assert!(
            !out.contains("No changes yet"),
            "other panels are gone\n{out}"
        );
        let rects = panel_rects(Rect::new(0, 0, 164, 48), &app);
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].0, 2);
        assert_eq!(rects[0].1.width, 162, "the panel fills the screen");
    }

    #[test]
    fn a_selection_never_leaves_its_panel() {
        let app = App::new(std::path::PathBuf::new(), true);
        let rects = panel_rects(Rect::new(0, 0, 164, 48), &app);
        let (_, conv, _) = rects[1];
        let inner = content_rect(conv);
        // Dragged far outside — into the neighbouring panel and off the
        // bottom of the screen: every selected row stays inside `inner`.
        let sel = Selection {
            panel: 1,
            a: (inner.x + 3, inner.y + 4),
            b: (163, 47),
        };
        let rows = sel.rows(inner);
        assert!(!rows.is_empty());
        for (x, y, w) in rows {
            assert!(
                x >= inner.x as i32 && x + w <= inner.right() as i32,
                "x range {x}+{w}"
            );
            assert!(y >= inner.y as i32 && y < inner.bottom() as i32, "row {y}");
        }
        // The other direction (anchor right/below the end) reads the same.
        let rev = Selection {
            a: sel.b,
            b: sel.a,
            ..sel
        };
        assert_eq!(rev.rows(inner), sel.rows(inner));
    }

    #[test]
    fn each_panel_scrolls_alone() {
        use crate::proto::scenario::{LineKind, ToolState, TranscriptLine};
        let app = App::new(std::path::PathBuf::new(), true);
        let mut s = Scenario::new();
        for i in 0..40 {
            s.transcript.push(TranscriptLine {
                kind: LineKind::User,
                text: format!("message number {i}"),
                ..Default::default()
            });
        }
        s.tool_output = (0..60).map(|i| format!("out line {i}")).collect();
        s.transcript.push(TranscriptLine {
            kind: LineKind::Tool,
            text: "cargo test".into(),
            tool_name: "bash".into(),
            tool_state: ToolState::Running,
            ..Default::default()
        });
        let draw_with = |scrolls: &[usize]| {
            let mut term = ratatui::Terminal::new(TestBackend::new(164, 48)).unwrap();
            term.draw(|f| {
                draw(
                    f,
                    &DrawIn {
                        app: &app,
                        fx: &Fx::default(),
                        scenario: &s,
                        composer: "",
                        completion_sel: 0,
                        now_ms: 5_000,
                        reduced: true,
                        tier: Tier::TrueColor,
                        mono: false,
                        scroll_offset: 0,
                        scrolls,
                        selection: None,
                        brand: crate::proto::welcome::BrandTier::Static,
                        toast: None,
                        overlay: None,
                    },
                )
            })
            .unwrap();
            let buf = term.backend().buffer().clone();
            let side = |x0: u16, x1: u16| {
                (0..48u16)
                    .map(|y| {
                        (x0..x1)
                            .map(|x| buf[(x, y)].symbol().to_string())
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            (side(53, 112), side(113, 164))
        };
        let (conv0, term0) = draw_with(&[0, 0, 0]);
        // Scroll ONLY the conversation (panel index 1): the terminal panel
        // must not change at all.
        let (conv1, term1) = draw_with(&[0, 9, 0]);
        assert_ne!(conv0, conv1, "the conversation moved");
        assert_eq!(term0, term1, "the terminal panel did not");
        // And the other way round.
        let (conv2, term2) = draw_with(&[0, 0, 5]);
        assert_eq!(conv0, conv2, "the conversation did not move");
        assert_ne!(term0, term2, "the terminal panel did");
    }
}
