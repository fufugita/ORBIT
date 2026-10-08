//! The ORBIT mark and the welcome hero, drawn procedurally every frame
//! (the prototype's `drawMark` / `welcomeHero`): the ring traces in, the
//! star arrives along it, the letters shine in, and while the first
//! prompt waits the star circles the O — twelve stations, one orbit per
//! three seconds. Nothing here is a canned frame: each cell is a
//! function of the clock.

use super::canvas::{mix, tint, Cv, Rgb};
use super::motion::star_at;
use super::pal::*;
use ratatui::style::Modifier;
use unicode_width::UnicodeWidthStr;

/// The mark's three rows (33 columns).
pub const MARK: [&str; 3] = [
    "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
    "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
    "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
];

/// Star stations around the O, `(col, row)`; 2 and 3 are behind it.
const STATIONS: [(i32, i32); 12] = [
    (10, 0),
    (8, 0),
    (6, 0),
    (3, 0),
    (1, 1),
    (0, 1),
    (0, 2),
    (2, 2),
    (4, 2),
    (7, 2),
    (9, 1),
    (10, 1),
];
const HIDDEN: [usize; 2] = [2, 3];

/// Ring cells in trace order, for the startup trace.
const RING_ORDER: [(i32, i32); 14] = [
    (10, 0),
    (9, 0),
    (8, 0),
    (11, 1),
    (10, 1),
    (9, 1),
    (8, 1),
    (3, 2),
    (2, 2),
    (1, 2),
    (0, 2),
    (0, 1),
    (1, 1),
    (2, 1),
];

/// How to draw the mark this frame.
#[derive(Debug, Clone, Copy)]
pub struct MarkOpts {
    /// Station index of the star (`None` = not yet arrived).
    pub star_k: Option<usize>,
    pub star_col: Rgb,
    /// Column of the white shine sweeping over the letters.
    pub shine: Option<f32>,
    /// 0..=1 reveal of R B I T.
    pub letters: f32,
    /// 0..=1 trace of the ring.
    pub ring: f32,
    /// 0..=1 fade of the O.
    pub o_alpha: f32,
    pub bg: Rgb,
}

impl MarkOpts {
    /// The settled mark.
    pub fn rest(bg: Rgb) -> Self {
        MarkOpts {
            star_k: Some(0),
            star_col: MAGENTA_HI,
            shine: None,
            letters: 1.0,
            ring: 1.0,
            o_alpha: 1.0,
            bg,
        }
    }
}

/// Paint the mark with its top-left at (x, y).
pub fn draw_mark(cv: &mut Cv, x: i32, y: i32, o: &MarkOpts) {
    let ring_n = (o.ring * RING_ORDER.len() as f32).round() as usize;
    let ring_on = &RING_ORDER[..ring_n.min(RING_ORDER.len())];
    for (r, row) in MARK.iter().enumerate() {
        for (c, ch) in row.chars().enumerate() {
            if ch == ' ' {
                continue;
            }
            let (c, r) = (c as i32, r as i32);
            let cp = ch as u32;
            let ch = if ch == '✦' { '⣄' } else { ch };
            if (0x2800..=0x28FF).contains(&cp) || ch == '⣄' {
                if !ring_on.contains(&(c, r)) {
                    continue;
                }
                cv.text(x + c, y + r, &ch.to_string(), MAGENTA_DIM, Some(o.bg));
                continue;
            }
            // Letter strokes: the O is columns 3..=7, R B I T follow.
            let mut col = super::pal::brand_at(c as f32 / 32.0);
            if (3..=7).contains(&c) {
                if o.o_alpha <= 0.0 {
                    continue;
                }
                if o.o_alpha < 1.0 {
                    col = mix(o.bg, col, o.o_alpha);
                }
            } else {
                let order = (c - 12) as f32 / 20.0 * 0.8;
                let vis = ((o.letters - order) * 5.0).clamp(0.0, 1.0);
                if vis <= 0.0 {
                    continue;
                }
                col = mix(o.bg, col, vis);
            }
            if let Some(shine) = o.shine {
                let d = (c as f32 - shine).abs();
                col = mix(col, WHITE, (1.0 - d / 3.0).max(0.0) * 0.85);
            }
            cv.put(
                x + c,
                y + r,
                &ch.to_string(),
                col,
                Some(o.bg),
                Modifier::BOLD,
            );
        }
    }
    if let Some(k) = o.star_k {
        if !HIDDEN.contains(&k) {
            let (sc, sr) = STATIONS[k % 12];
            cv.bold(x + sc, y + sr, "✦", o.star_col, Some(o.bg));
        }
    }
}

/// The hero's timeline inputs.
pub struct Hero<'a> {
    /// Seconds since the screen started.
    pub since_start: f32,
    /// Seconds since the first prompt began waiting, when it is.
    pub waiting_for: Option<f32>,
    pub reduced: bool,
    /// Measured readiness `(ok, label)`.
    pub checks: &'a [(bool, String)],
}

/// Rows the hero takes (without the sections below it).
pub fn hero_height(waiting: bool) -> i32 {
    if waiting {
        7
    } else {
        9
    }
}

/// Draw the welcome hero in the panel interior `(x, y, w, h)`; returns
/// the rows it used.
pub fn draw_hero(cv: &mut Cv, x: i32, y: i32, w: i32, h: i32, hero: &Hero) -> i32 {
    let waiting = hero.waiting_for.is_some();
    let hh = hero_height(waiting);
    let (hx, hw) = (x + 4, w - 8);
    if hw < 36 || h < hh + 1 {
        return 0;
    }
    let glow = tint(MAGENTA, PANEL, 0.07);
    cv.fill(hx, y + 1, hw, hh, glow);
    for yy in y + 1..y + 1 + hh {
        cv.text(hx, yy, "▏", tint(MAGENTA, PANEL, 0.35), Some(glow));
    }
    let t = hero.since_start;
    let red = hero.reduced;
    let mx = x + (w - 33) / 2;
    let my = y + 3;
    // Startup: ring traces, the O fades in, the star arrives along the
    // ring, R B I T shine in.
    let ring = if red {
        1.0
    } else {
        ((t - 0.25) / 0.45).clamp(0.0, 1.0)
    };
    let o_alpha = if red {
        1.0
    } else {
        ((t - 0.2) / 0.35).clamp(0.0, 1.0)
    };
    let letters = if red {
        1.0
    } else {
        ((t - 0.8) / 0.45).clamp(0.0, 1.0)
    };
    let mut star_k = Some(0);
    let mut star_col = MAGENTA_HI;
    if !red && t < 1.1 {
        star_k = if t < 0.7 {
            None
        } else {
            Some(6usize.saturating_sub(((t - 0.7) / 0.065) as usize))
        };
    }
    if let Some(wt) = hero.waiting_for {
        star_col = CYAN;
        if !red {
            star_k = Some(((wt / 0.25) as usize) % 12);
        }
    }
    let shine = (!red && t > 0.8 && t < 1.85).then(|| (t - 0.8) / 1.0 * 40.0 - 4.0);
    cv.clipped(
        ratatui::layout::Rect {
            x: hx as u16,
            y: (y + 1) as u16,
            width: hw as u16,
            height: hh as u16,
        },
        |cv| {
            draw_mark(
                cv,
                mx,
                my,
                &MarkOpts {
                    star_k,
                    star_col,
                    shine,
                    letters,
                    ring,
                    o_alpha,
                    bg: glow,
                },
            );
            let tag = "the harness that orbits around you";
            let ta = if red {
                1.0
            } else {
                ((t - 1.25) / 0.4).clamp(0.0, 1.0)
            };
            cv.text(
                x + (w - tag.width() as i32) / 2,
                my + 4,
                tag,
                mix(glow, INK2, ta),
                Some(glow),
            );
        },
    );
    if waiting {
        return hh + 1;
    }
    // Readiness: a turning star while it runs, then ✓ with a green flash.
    let mut yy = y + hh + 2;
    if hero.checks.is_empty() || yy + 4 > y + h {
        return hh + 1;
    }
    cv.bold(x + 6, yy, "READY", FAINT, None);
    yy += 2;
    for (i, (ok, label)) in hero.checks.iter().enumerate() {
        // Each check lands 120 ms after the last, from 1.3 s.
        let done_at = 1.3 + i as f32 * 0.12;
        let done = red || t >= done_at;
        let fl = if done && !red {
            (1.0 - ((t - done_at) / 0.4)).clamp(0.0, 1.0)
        } else {
            0.0
        };
        if done {
            let (g, col) = if *ok { ("✓", GREEN) } else { ("✕", RED) };
            cv.bold(x + 7, yy, g, mix(col, WHITE, fl), None);
            cv.bold(
                x + 9,
                yy,
                &super::canvas::clip_text(label, w - 12),
                INK,
                None,
            );
        } else {
            cv.bold(x + 7, yy, star_at(t, 4.0, false), CYAN, None);
            cv.bold(x + 9, yy, "checking", MUTED, None);
        }
        yy += 1;
    }
    yy += 2;
    if yy + 7 > y + h {
        return hh + 1;
    }
    cv.bold(x + 6, yy, "START WITH", FAINT, None);
    yy += 2;
    let cards: [(&str, Rgb, &str); 4] = [
        ("/models", VIOLET, "list models from providers"),
        ("/sessions", MAGENTA, "browse and resume work"),
        ("/help", BLUE, "keys and commands"),
        ("?", INK2, "keys and commands"),
    ];
    let cw = ((w - 14) / 2).max(10);
    for (i, (cmd, col, desc)) in cards.iter().enumerate() {
        let cx = x + 6 + (i as i32 % 2) * (cw + 2);
        let cy = yy + (i as i32 / 2) * 3;
        let a = if red {
            1.0
        } else {
            ((t - 1.45 - i as f32 * 0.08) / 0.25).clamp(0.0, 1.0)
        };
        if a <= 0.0 {
            continue;
        }
        let bg = mix(PANEL, RAISE, a);
        cv.fill(cx, cy, cw, 2, bg);
        cv.text(cx, cy, "▌", mix(PANEL, *col, a), Some(bg));
        let (fg, chip) = if *col == INK2 {
            (INK, RULE_HI)
        } else {
            (ON_ACCENT, *col)
        };
        cv.put(
            cx + 2,
            cy,
            &format!(" {cmd} "),
            fg,
            Some(chip),
            Modifier::BOLD,
        );
        cv.text(
            cx + 2,
            cy + 1,
            &super::canvas::clip_text(desc, cw - 3),
            mix(RAISE, INK2, a),
            Some(bg),
        );
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn render(t: f32, waiting: Option<f32>) -> String {
        let area = Rect::new(0, 0, 70, 24);
        let mut buf = Buffer::empty(area);
        let mut cv = Cv::new(&mut buf);
        draw_hero(
            &mut cv,
            0,
            0,
            70,
            24,
            &Hero {
                since_start: t,
                waiting_for: waiting,
                reduced: false,
                checks: &[(true, "trust root".into())],
            },
        );
        (0..8u16)
            .map(|y| {
                (0..70u16)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_logo_builds_up_over_the_startup_window() {
        let early = render(0.1, None);
        let mid = render(0.9, None);
        let done = render(2.0, None);
        assert!(!early.contains('█'), "nothing drawn at 0.1 s\n{early}");
        assert!(
            mid.contains('█') && !mid.contains("▀█▀"),
            "O only, letters still arriving\n{mid}"
        );
        assert!(
            done.contains("▀█▀") && done.contains("the harness that orbits"),
            "{done}"
        );
    }

    #[test]
    fn the_star_circles_while_the_first_prompt_waits() {
        let frames: Vec<String> = (0..12)
            .map(|i| render(2.0, Some(i as f32 * 0.25)))
            .collect();
        let distinct = frames
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            distinct >= 8,
            "the star moves station to station ({distinct} distinct frames)"
        );
    }
}
