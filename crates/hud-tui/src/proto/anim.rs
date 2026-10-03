//! Curves and the star clock (the prototype's `anim` module).
//!
//! The star clock is the one stateful animation (§10.1): a frame
//! index `k` (0–3) and `last`, advanced at most one frame per tick.

/// One animation: pure progress of a tick count. The state that
/// changed stores it, never the widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anim {
    pub start_tick: u64,
    pub dur_ticks: u64,
    pub curve: Curve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Linear,
    EaseOut,
    EaseInOut,
}

impl Curve {
    /// Map elapsed fraction → progress fraction.
    pub fn at(self, t: f64) -> f64 {
        let t = t.clamp(0.0, 1.0);
        match self {
            Self::Linear => t,
            Self::EaseOut => 1.0 - (1.0 - t) * (1.0 - t),
            Self::EaseInOut => {
                // smoothstep
                t * t * (3.0 - 2.0 * t)
            }
        }
    }
}

impl Anim {
    pub fn new(start_tick: u64, dur_ticks: u64, curve: Curve) -> Self {
        Self {
            start_tick,
            dur_ticks,
            curve,
        }
    }

    /// Progress in 0..=1 at `tick`; 1.0 once done.
    pub fn progress(&self, tick: u64) -> f64 {
        if self.dur_ticks == 0 {
            return 1.0;
        }
        let elapsed = tick.saturating_sub(self.start_tick) as f64 / self.dur_ticks as f64;
        self.curve.at(elapsed)
    }

    pub fn done(&self, tick: u64) -> bool {
        tick.saturating_sub(self.start_tick) >= self.dur_ticks
    }
}

/// A breathing pulse (the caret, the approval border): 0..=1 at `hz`.
pub fn pulse(tick: u64, hz: f64) -> f64 {
    let period = 1000.0 / hz.max(0.001);
    let ms = tick as f64; // tick = ms under the 16 ms UI clock
    let phase = (ms % period) / period;
    // sine breathe, 0..1..0
    0.5 - 0.5 * (std::f64::consts::TAU * phase).cos()
}

/// A flash: 1.0 inside [start, start+dur), else 0.0.
pub fn flash(tick: u64, start: u64, dur: u64) -> bool {
    tick >= start && tick < start + dur
}

// ── The star clock (§10.1) ─────────────────────────────────────────────────

/// The star's frames, in order (ASCII: `- \ | /`).
pub const STAR_FRAMES: [&str; 4] = ["◐", "◓", "◑", "◒"];

/// What the star is doing — the state light, not branding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StarState {
    /// Still `✦` magenta — ready, needs you, or the turn report.
    StillMagenta,
    /// Still `✦` cyan (reduced motion's turning states).
    StillCyan,
    /// Still `✦` amber — reconnecting or rate-limited.
    StillAmber,
    /// Still `✦` red — offline or the last turn failed.
    StillRed,
    /// Turning cyan. `period_ms` is 500 (thinking) or 250 (writing,
    /// agents running).
    Turning { period_ms: u64 },
}

/// The star clock: `k` (frame 0–3) and `last` (ms of the last frame
/// change). The one stateful animation; everything else derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarClock {
    pub k: u8,
    pub last: u64,
}

impl StarClock {
    pub const fn new() -> Self {
        StarClock { k: 0, last: 0 }
    }

    /// The clock rule (§10.1), exact:
    /// - starting (still → turning): `k = 0`, `last = now`;
    /// - advancing: if turning and `now − last ≥ period`, advance ONE
    ///   frame (`k = (k+1) mod 4`, `last = now`); a late tick never
    ///   skips frames;
    /// - changing speed: keep `k` and `last`, only the period changes;
    /// - stopping: the still state draws and `k` is discarded.
    pub fn tick(&mut self, now_ms: u64, state: StarState) -> StarGlyph {
        match state {
            StarState::Turning { period_ms } => {
                if now_ms.saturating_sub(self.last) >= period_ms {
                    self.k = (self.k + 1) % 4;
                    self.last = now_ms;
                }
                StarGlyph {
                    glyph: STAR_FRAMES[self.k as usize],
                    turning: true,
                    colour: StarColour::Cyan,
                }
            }
            still => StarGlyph {
                glyph: "✦",
                turning: false,
                colour: match still {
                    StarState::StillMagenta => StarColour::Magenta,
                    StarState::StillCyan => StarColour::Cyan,
                    StarState::StillAmber => StarColour::Amber,
                    StarState::StillRed => StarColour::Red,
                    StarState::Turning { .. } => unreachable!(),
                },
            },
        }
    }

    /// A transition to turning resets the clock (`k = 0`, `last = now`).
    /// The caller invokes this on the still→turning edge (TurnStarted,
    /// a call starting after an approval).
    pub fn start(&mut self, now_ms: u64) {
        self.k = 0;
        self.last = now_ms;
    }
}

impl Default for StarClock {
    fn default() -> Self {
        Self::new()
    }
}

/// What the draw shows for the star.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarGlyph {
    pub glyph: &'static str,
    pub turning: bool,
    pub colour: StarColour,
}

impl StarGlyph {
    /// Turning frames are always cyan.
    pub fn turning(glyph: &'static str) -> Self {
        StarGlyph {
            glyph,
            turning: true,
            colour: StarColour::Cyan,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StarColour {
    Cyan,
    Magenta,
    Amber,
    Red,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from §10.1, exact: TurnStarted at 0 ms draws
    /// `◐`. With 16 ms ticks the frame changes at 512 and 1024 ms
    /// (thinking, 500 ms period). The first visible text arrives at
    /// 1200 ms; the next change comes at 1280 ms — the first tick
    /// where `now − last ≥ 250`.
    #[test]
    fn star_clock_worked_example() {
        let mut c = StarClock::new();
        c.start(0);
        let thinking = StarState::Turning { period_ms: 500 };
        // frames at 0..511 are ◐ (k=0)
        let g = c.tick(0, thinking);
        assert_eq!(g.glyph, "◐");
        // UI ticks land on multiples of 16 ms: 496 is the last before
        // the 500 ms period elapses, 512 is the first that advances.
        let g = c.tick(496, thinking);
        assert_eq!(g.glyph, "◐", "496 < 500: no change before 512");
        let g = c.tick(512, thinking);
        assert_eq!(g.glyph, "◓", "512 is the first tick where now-last>=500");
        let g = c.tick(1024, thinking);
        assert_eq!(g.glyph, "◑");
        // speed change to writing (250 ms): keep k and last
        let writing = StarState::Turning { period_ms: 250 };
        let g = c.tick(1200, writing);
        assert_eq!(g.glyph, "◑", "a speed change keeps the frame");
        let g = c.tick(1280, writing);
        assert_eq!(g.glyph, "◒", "1280 is the first tick where now-last>=250");
        // stopping: the still glyph draws in the same tick
        let g = c.tick(1281, StarState::StillMagenta);
        assert_eq!(g.glyph, "✦");
        assert!(!g.turning);
    }

    #[test]
    fn a_late_tick_never_skips_frames() {
        let mut c = StarClock::new();
        c.start(0);
        let t = StarState::Turning { period_ms: 500 };
        // jump far ahead: still only ONE frame advance
        let g = c.tick(5000, t);
        assert_eq!(g.glyph, "◓");
        let g = c.tick(5500, t);
        assert_eq!(g.glyph, "◑");
    }

    #[test]
    fn curves_are_monotonic_and_terminate() {
        for curve in [Curve::Linear, Curve::EaseOut, Curve::EaseInOut] {
            let a = Anim::new(0, 100, curve);
            assert_eq!(a.progress(0), 0.0);
            let mut prev = 0.0;
            for t in [25u64, 50, 75, 100, 200] {
                let p = a.progress(t);
                assert!(p >= prev - 1e-9, "{curve:?} monotonic at {t}");
                assert!((0.0..=1.0).contains(&p));
                prev = p;
            }
            assert_eq!(a.progress(200), 1.0);
            assert!(a.done(100));
        }
    }

    #[test]
    fn pulse_breathes_and_flash_windows() {
        // 0.9 Hz caret: period ≈ 1111 ms
        let a = pulse(0, 0.9);
        let b = pulse(555, 0.9);
        assert!(a < 0.1 && b > 0.9, "pulse rises through its period: {a} {b}");
        assert!(flash(100, 100, 250));
        assert!(!flash(350, 100, 250));
        assert!(!flash(99, 100, 250));
    }
}
