//! Motion helpers: every animation is a pure function of the tick, so
//! a test can render any frame at any time. Times are seconds as `f32`.
//! Under reduced motion every curve collapses to its end state.

use super::canvas::{Rgb, Seg, mix, text_width};
use super::pal::*;
use unicode_segmentation::UnicodeSegmentation;

pub fn secs(ms: u64) -> f32 {
    ms as f32 / 1000.0
}

/// Ease-out cubic.
pub fn ease_out(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

/// Ease in-out cubic.
pub fn ease_in_out(t: f32) -> f32 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

/// Progress 0..=1 of an animation that began at `t0` and lasts `dur`.
pub fn prog(now: f32, t0: Option<f32>, dur: f32, reduced: bool) -> f32 {
    match t0 {
        Some(t0) if !reduced => ((now - t0) / dur).clamp(0.0, 1.0),
        _ => 1.0,
    }
}

/// 0 → 1 → 0 breathing at `hz`.
pub fn pulse(now: f32, hz: f32, reduced: bool) -> f32 {
    if reduced {
        1.0
    } else {
        0.5 - 0.5 * (std::f32::consts::TAU * hz * now).cos()
    }
}

/// A decaying flash: 1 at `t0`, 0 after `dur`.
pub fn flash(now: f32, t0: Option<f32>, dur: f32, reduced: bool) -> f32 {
    match t0 {
        Some(t0) if !reduced => {
            let p = (now - t0) / dur;
            if !(0.0..=1.0).contains(&p) {
                0.0
            } else {
                1.0 - ease_out(p)
            }
        }
        _ => 0.0,
    }
}

/// A free-running status star (`◐ ◓ ◑ ◒`) at `fps`.
pub fn star_at(now: f32, fps: f32, reduced: bool) -> &'static str {
    if reduced {
        return "✦";
    }
    ["◐", "◓", "◑", "◒"][((now * fps) as usize) & 3]
}

/// A bright band sweeping across `text` once per 1.6 s (M03).
pub fn shimmer(text: &str, now: f32, base: Rgb, reduced: bool) -> Vec<Seg> {
    if reduced {
        return vec![Seg::new(text, base)];
    }
    let graphemes: Vec<&str> = text.graphemes(true).collect();
    let widths: Vec<usize> = graphemes
        .iter()
        .map(|grapheme| text_width(grapheme).max(0) as usize)
        .collect();
    let n: usize = widths.iter().sum();
    let (period, band) = (1.6_f32, 6.0_f32);
    let pos = ((now % period) / period) * (n as f32 + band * 2.0) - band;
    let mut cell = 0usize;
    graphemes
        .iter()
        .zip(widths)
        .map(|(grapheme, width)| {
            let center = if width == 0 {
                cell as f32
            } else {
                cell as f32 + (width as f32 - 1.0) / 2.0
            };
            cell += width;
            let d = (center - pos).abs();
            let a = (1.0 - d / (band / 2.0)).max(0.0);
            Seg::new(*grapheme, mix(base, WHITE, 0.85 * a * a))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_clamps_and_collapses_when_reduced() {
        assert_eq!(prog(0.0, Some(1.0), 0.5, false), 0.0);
        assert_eq!(prog(2.0, Some(1.0), 0.5, false), 1.0);
        assert_eq!(prog(0.0, Some(1.0), 0.5, true), 1.0);
        assert!((prog(1.25, Some(1.0), 0.5, false) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn flash_decays_to_zero() {
        assert!(flash(1.0, Some(1.0), 0.5, false) > 0.99);
        assert_eq!(flash(2.0, Some(1.0), 0.5, false), 0.0);
        assert_eq!(flash(1.0, Some(1.0), 0.5, true), 0.0);
    }

    #[test]
    fn shimmer_sweeps_across_the_text() {
        let a = shimmer("working", 0.0, CYAN, false);
        let b = shimmer("working", 0.8, CYAN, false);
        assert_eq!(a.len(), 7);
        assert_ne!(
            a.iter().map(|s| s.fg).collect::<Vec<_>>(),
            b.iter().map(|s| s.fg).collect::<Vec<_>>()
        );
        assert_eq!(shimmer("x", 0.8, CYAN, true)[0].fg, CYAN);
    }

    #[test]
    fn shimmer_keeps_graphemes_whole_and_positions_by_display_cells() {
        let text = "e\u{301}界🇧🇷☀️👨‍👩‍👧‍👦";
        let first = shimmer(text, 0.1, CYAN, false);
        let later = shimmer(text, 0.8, CYAN, false);
        assert_eq!(
            first
                .iter()
                .map(|segment| segment.text.as_str())
                .collect::<String>(),
            text
        );
        assert_eq!(first.len(), text.graphemes(true).count());
        assert_eq!(first.iter().map(Seg::width).sum::<i32>(), text_width(text));
        assert_ne!(
            first.iter().map(|segment| segment.fg).collect::<Vec<_>>(),
            later.iter().map(|segment| segment.fg).collect::<Vec<_>>()
        );
    }

    #[test]
    fn star_turns_four_frames() {
        assert_ne!(star_at(0.0, 4.0, false), star_at(0.25, 4.0, false));
        assert_eq!(star_at(0.0, 4.0, true), "✦");
    }
}
