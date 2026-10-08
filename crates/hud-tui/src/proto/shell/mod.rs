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
pub mod frame;
pub mod mark;
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
use canvas::Cv;
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
    pub now_ms: u64,
    pub reduced: bool,
    pub tier: Tier,
    pub scroll_offset: usize,
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
    let area = f.area();
    let (w, h) = (area.width as i32, area.height as i32);
    let s = inp.scenario;
    let sh = inp.app;
    let now = secs(inp.now_ms);
    let red = inp.reduced;
    let one_at_a_time = area.width < 120;
    {
        let mut cv = Cv::new(f.buffer_mut());
        cv.fill(0, 0, w, h, pal::APP);

        let (new_areas, side_w) = layout(area, &sh.tree, sh.sidebar);
        let focus = sh.focus.min(new_areas.len().saturating_sub(1));

        // M21: panel rectangles glide from the old layout to the new.
        let mut rects: Vec<(Rect, View)> = new_areas.clone();
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
        let switcher = one_at_a_time.then(|| {
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
                reduced: red,
                switcher,
                focus_idx: focus,
                cwd: bars::cwd_label(),
                branch: bars::branch_label(),
                saved_ms: inp.fx.saved_ms,
            },
        );

        if side_w > 0 {
            side::draw(
                &mut cv,
                Rect {
                    x: 0,
                    y: 1,
                    width: side_w,
                    height: area.height.saturating_sub(2),
                },
                s,
                inp.now_ms,
                red,
            );
        }

        // M01: at launch the conversation unfolds first (320 ms), the
        // other panels 120 ms apart after it.
        let conv_idx = new_areas
            .iter()
            .position(|a| a.1 == View::Conversation)
            .unwrap_or(0);
        let animate_start = inp.brand == crate::proto::welcome::BrandTier::Anim && !red;

        // Panels.
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
                            composer: inp.composer,
                            focused: *i == focus,
                            focus_fx: focus_in,
                            scroll_offset: inp.scroll_offset,
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
                            focused: *i == focus,
                            focus_fx: focus_in,
                            num: i + 1,
                            agent: &sh.tree.agent_at(*i),
                        },
                    );
                }
            });
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
            fv == View::Conversation,
            matches!(fv, View::Changes | View::Review),
            sh.arranging,
        );

        // Overlays on top: the picker, the palette/help/quit card, the toast.
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
    }
    tier::apply(f.buffer_mut(), inp.tier);
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
                    now_ms: 5_000,
                    reduced: true,
                    tier: Tier::TrueColor,
                    scroll_offset: 0,
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
        for want in ["Review", "FILES", "Plan", "1/2 done", "Activity", "BASH"] {
            assert!(out.contains(want), "missing {want:?}\n{out}");
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
                    now_ms,
                    reduced: false,
                    tier,
                    scroll_offset: 0,
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
}
