//! The two console panes this interface is asked to carry, drawn natively.
//!
//! The council pane and the reactor pane began as standalone terminal
//! programs beside the agent. Their look is the point of them: a bench of
//! seat cards that animate while a council deliberates, and a scene that
//! moves while a turn streams. These types reproduce that behaviour inside
//! the panel: the same states, the same motion, the same vocabulary.
//!
//! Nothing here reads a file, starts a process or makes a request. The
//! callers pass in what they already loaded — the parsed council state, the
//! session's token and cost facts, the frame clock — so a pane is a pure
//! function of its inputs and renders identically in a test.
//!
//! Motion is a function of the clock the caller lends (see `PaneClock`):
//! with `reduced` set, every animated pane draws one still frame.

use crate::proto::shell::canvas::{Cv, Rgb, mix, text_width};

// ── shared facts ────────────────────────────────────────────────────

/// What one seat of the council bench is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatActivity {
    /// Nothing running, or a council that has gone quiet.
    Resting,
    /// Connecting to the seat's model.
    Wiring,
    /// The seat is deliberating (or its answer has landed and a vote is next).
    Working,
    /// Answered, waiting on the others.
    Answered,
    /// The seat's model failed.
    Lost,
}

/// One seat as the pane draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchSeat {
    /// The seat's call name, shown on the name plate.
    pub name: String,
    /// Two-digit bench number.
    pub number: String,
    /// What the seat is for, in one word (its role).
    pub role: String,
    /// The provider, spelled the way the pane spells it.
    pub lab: String,
    /// The model as configured.
    pub model: String,
    /// Current activity.
    pub activity: SeatActivity,
    /// The verdict this seat carried, once it has one.
    pub verdict: Option<Verdict>,
    /// Confidence, when the engine reported one.
    pub confidence: Option<u8>,
}

/// A seat's standing vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Reject,
    Hold,
}

impl Verdict {
    pub fn hangul(self) -> &'static str {
        match self {
            Verdict::Approve => "승인",
            Verdict::Reject => "거부",
            Verdict::Hold => "보류",
        }
    }
    pub fn english(self) -> &'static str {
        match self {
            Verdict::Approve => "YES",
            Verdict::Reject => "NO",
            Verdict::Hold => "HOLD",
        }
    }
    /// The word the engine writes for this verdict.
    pub fn engine(self) -> &'static str {
        match self {
            Verdict::Approve => "APPROVE",
            Verdict::Reject => "REJECT",
            Verdict::Hold => "CONDITIONAL",
        }
    }
    fn rank(self) -> u8 {
        match self {
            Verdict::Approve => 0,
            Verdict::Reject => 1,
            Verdict::Hold => 2,
        }
    }
}

/// How often the pane redraws, by phase (see `Phase::beat_ms`).
const BEAT_RUNNING_MS: u64 = 125;
const BEAT_SETTLED_MS: u64 = 167;
const BEAT_AT_REST_MS: u64 = 500;
const BEAT_DEEP_REST_MS: u64 = 5_000;
/// A pane that has rested this long drops to its slowest beat.
pub const BEAT_DEEP_REST_AFTER_MS: u64 = 600_000;

/// The council's phase, in the engine's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase {
    /// The engine's phase word (`DELIBERATING`, `VERDICT`, …).
    pub name: String,
    /// The engine's free-text note for this phase.
    pub note: String,
}

impl Phase {
    /// No council is running: the cards rest, and the strip remembers the
    /// last one. Triage is not resting; the bench is being consulted then.
    pub fn is_resting(&self) -> bool {
        matches!(self.name.as_str(), "IDLE" | "FAIL") || self.name.is_empty()
    }
    /// Milliseconds between redraws. The standalone pane runs at eight frames
    /// a second while a council runs, six for the triage verdict and for a
    /// failure, two at rest, and one every five seconds once it has rested for
    /// ten minutes; the embedded pane keeps the same pace. `rested_ms` is how
    /// long the council has been idle.
    pub fn beat_ms(&self, rested_ms: u64) -> u64 {
        match self.name.as_str() {
            "" | "IDLE" if rested_ms >= BEAT_DEEP_REST_AFTER_MS => BEAT_DEEP_REST_MS,
            "" | "IDLE" => BEAT_AT_REST_MS,
            "TRIAGED" | "FAIL" => BEAT_SETTLED_MS,
            _ => BEAT_RUNNING_MS,
        }
    }
    /// Nothing is in flight and the last council's conclusion is on show, so
    /// the pane only keeps time.
    pub fn is_idle(&self) -> bool {
        matches!(self.name.as_str(), "" | "IDLE")
    }
    fn hangul(&self) -> &str {
        phase_hangul(&self.name)
    }
    fn english(&self) -> Option<&str> {
        match self.name.as_str() {
            "SYNC" => Some("SYNK"),
            "DELIBERATING" => Some("DELIBERATE"),
            "JUDGING" => Some("JUDGE"),
            _ => None,
        }
    }
}

/// What the pane learned from the engine's record of past councils.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CouncilHistory {
    /// Finished councils in the recent window.
    pub finished: usize,
    /// Councils in that window.
    pub seen: usize,
    /// The newest finished council's seats, by bench position.
    pub last_seats: Vec<BenchSeat>,
    /// The newest finished council's conclusion, first line, marker removed.
    pub last_final: String,
    /// When that council finished, in epoch seconds.
    pub last_at: Option<f64>,
    /// The newest finished council ended without a single winner (a split).
    pub tie: bool,
}

/// Where wall-clock time sits on the process clock the pane animates by, so
/// the header can show the local time without the pane reading a clock.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WallOrigin {
    /// Unix seconds at the process clock's zero.
    pub epoch_at_zero: f64,
    /// Local time's distance from UTC, in seconds.
    pub utc_offset_secs: i32,
}

impl WallOrigin {
    /// `HH:MM` local time at `now_ms` on the process clock.
    pub fn hhmm(self, now_ms: u64) -> String {
        let local = self.epoch_at_zero + now_ms as f64 / 1_000.0 + f64::from(self.utc_offset_secs);
        let second_of_day = local.rem_euclid(86_400.0) as u64;
        format!(
            "{:02}:{:02}",
            second_of_day / 3_600,
            (second_of_day % 3_600) / 60
        )
    }
}

/// Everything the council pane draws from.
#[derive(Debug, Clone, PartialEq)]
pub struct CouncilState {
    pub phase: Phase,
    pub seats: Vec<BenchSeat>,
    /// Seats beyond the drawn bench, as compact chips.
    pub extra_seats: Vec<BenchSeat>,
    /// Seat names that carried a majority, when the engine names them.
    pub winner_seats: Vec<String>,
    pub history: CouncilHistory,
    /// The wall clock, when the caller knows it; the header omits the time
    /// otherwise.
    pub clock: Option<WallOrigin>,
}

impl CouncilState {
    /// The bench as a single line, for a pane too small to draw cards.
    pub fn one_line(&self) -> String {
        let mut out = format!("MAGI · {} {}\n", self.phase.hangul(), self.phase.name);
        for seat in self.seats.iter().take(4) {
            out.push_str(&format!(
                "{} {} {} {} {} {}\n",
                seat.name,
                seat.number,
                seat.role,
                seat.lab,
                seat.model,
                seat_word(seat)
            ));
        }
        out
    }
}

impl CouncilState {
    /// The pane's state from what the frontend published. Unknown activity
    /// words rest rather than animate, and an unknown verdict is no verdict,
    /// so a foreign document can never drive a pane into an unnamed state.
    pub fn from_snapshot(
        snapshot: &orbit_frontend_protocol::customization::CouncilSnapshot,
    ) -> Self {
        use orbit_frontend_protocol::customization::{CouncilChip, CouncilSeat, CouncilSnapshot};
        let seat_of = |seat: &CouncilSeat| BenchSeat {
            name: seat.name.clone(),
            number: seat.number.clone(),
            role: seat.role.clone(),
            lab: seat.lab.clone(),
            model: seat.model.clone(),
            activity: seat_activity(&seat.activity),
            verdict: seat_verdict(seat.verdict.as_deref()),
            confidence: seat.confidence,
        };
        let chip_of = |chip: &CouncilChip| BenchSeat {
            name: chip.name.clone(),
            number: String::new(),
            role: String::new(),
            lab: chip.lab.clone(),
            model: String::new(),
            activity: seat_activity(&chip.activity),
            verdict: None,
            confidence: None,
        };
        let _ = CouncilSnapshot::default;
        Self {
            phase: Phase {
                name: snapshot.phase.clone(),
                note: snapshot.note.clone(),
            },
            seats: snapshot.seats.iter().map(seat_of).collect(),
            extra_seats: snapshot.extra_seats.iter().map(chip_of).collect(),
            winner_seats: snapshot.winner_seats.clone(),
            history: CouncilHistory {
                finished: snapshot.finished as usize,
                seen: snapshot.seen as usize,
                last_seats: snapshot.last_seats.iter().map(seat_of).collect(),
                last_final: snapshot.last_final.clone(),
                last_at: snapshot.last_at,
                tie: snapshot.last_tie,
            },
            clock: None,
        }
    }
}

fn seat_activity(word: &str) -> SeatActivity {
    match word {
        "answered" => SeatActivity::Answered,
        "working" => SeatActivity::Working,
        "wiring" => SeatActivity::Wiring,
        "lost" => SeatActivity::Lost,
        _ => SeatActivity::Resting,
    }
}

fn seat_verdict(word: Option<&str>) -> Option<Verdict> {
    match word {
        Some("approve") => Some(Verdict::Approve),
        Some("reject") => Some(Verdict::Reject),
        Some("hold") => Some(Verdict::Hold),
        _ => None,
    }
}

fn seat_word(seat: &BenchSeat) -> &'static str {
    match (seat.verdict, seat.activity) {
        (Some(verdict), _) => verdict.hangul(),
        (None, SeatActivity::Wiring) => "SYNK",
        (None, SeatActivity::Working) => "심의중",
        (None, SeatActivity::Answered) => "응답완료",
        (None, SeatActivity::Lost) => "신호없음",
        (None, SeatActivity::Resting) => "대기",
    }
}

// ── fonts and colour ────────────────────────────────────────────────

/// The palette a ported pane draws in. Kept separate from the interface's
/// own palette so a pane's colours do not shift when the shell's do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchPalette {
    /// The warm accent (the council's voice).
    pub warm: Rgb,
    /// The cool accent (the engine's voice).
    pub cool: Rgb,
    /// The blend of the two, used for votes and secondary chrome.
    pub blend: Rgb,
    /// Body text.
    pub body: Rgb,
    /// Receding chrome: rules, empty bars, resting text.
    pub dim: Rgb,
    /// Text laid over an accent block.
    pub on_accent: Rgb,
}

impl BenchPalette {
    /// The default bench colours: a soft warm and a soft cool, carried at
    /// the same weight the standalone pane gave them.
    pub const PASTEL: Self = Self {
        warm: (255, 182, 213),
        cool: (150, 220, 240),
        blend: (203, 201, 227),
        body: (236, 228, 244),
        dim: (96, 88, 110),
        on_accent: (24, 20, 32),
    };

    /// The bench colours for a shell palette: the pane keeps its own accent
    /// pairing but picks up the theme's text and chrome tones.
    pub fn from_shell(palette: &crate::proto::shell::pal::Palette) -> Self {
        Self {
            warm: palette.magenta,
            cool: palette.cyan,
            blend: mix(palette.magenta, palette.cyan, 0.5),
            body: palette.ink,
            dim: palette.faint,
            on_accent: palette.on_accent,
        }
    }

    /// Derived shades the cards use.
    fn mute(self) -> Rgb {
        mix(self.body, self.dim, 0.55)
    }
    fn half_accent(self, accent: Rgb) -> Rgb {
        mix(accent, self.dim, 0.45)
    }
    fn soft_accent(self, accent: Rgb) -> Rgb {
        mix(accent, self.dim, 0.6)
    }
    fn verdict_colour(self, verdict: Verdict) -> Rgb {
        match verdict {
            Verdict::Approve => OK,
            Verdict::Reject => NO,
            Verdict::Hold => HOLD_COLOUR,
        }
    }
}

const OK: Rgb = (150, 235, 180);
const NO: Rgb = (250, 150, 170);
const HOLD_COLOUR: Rgb = (245, 220, 140);

/// The four seat accents, in bench order.
fn seat_accent(index: usize, palette: BenchPalette) -> Rgb {
    match index {
        0 => palette.cool,
        1 => palette.warm,
        2 => mix(mix(palette.warm, palette.cool, 0.5), palette.body, 0.25),
        _ => mix(palette.warm, palette.body, 0.45),
    }
}

// ── small text helpers ──────────────────────────────────────────────

/// `s` in exactly `w` cells, truncated first, then padded.
fn fit(s: &str, w: i32, align: Align) -> String {
    if w <= 0 {
        return String::new();
    }
    let mut s = clip_cells(s, w);
    let pad = w - text_width(&s);
    if pad <= 0 {
        return s;
    }
    let pad = pad as usize;
    match align {
        Align::Left => {
            s.push_str(&" ".repeat(pad));
            s
        }
        Align::Right => {
            let mut out = " ".repeat(pad);
            out.push_str(&s);
            out
        }
        Align::Centre => {
            let left = pad / 2;
            let mut out = " ".repeat(left);
            out.push_str(&s);
            out.push_str(&" ".repeat(pad - left));
            out
        }
    }
}

#[derive(Clone, Copy)]
enum Align {
    Left,
    #[allow(dead_code)]
    Right,
    Centre,
}

/// Truncate to at most `w` cells, on a character boundary.
fn clip_cells(s: &str, w: i32) -> String {
    if w <= 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let mut buf = [0u8; 4];
        let width = text_width(ch.encode_utf8(&mut buf));
        if used + width > w {
            break;
        }
        out.push(ch);
        used += width;
    }
    out
}

/// Centre in `w` cells, marking a cut with an ellipsis.
fn fit_centre(s: &str, w: i32) -> String {
    if text_width(s) <= w {
        return fit(s, w, Align::Centre);
    }
    fit(&format!("{}…", clip_cells(s, w - 1)), w, Align::Centre)
}

/// The first candidate that fits, else the last one truncated.
fn first_fit(candidates: &[String], w: i32) -> String {
    for candidate in candidates {
        if text_width(candidate) <= w {
            return candidate.clone();
        }
    }
    candidates
        .last()
        .map(|last| clip_cells(last, w))
        .unwrap_or_default()
}

/// Greedy word wrap into at most `maxlines`, the last line marked if cut.
fn wrap(s: &str, w: i32, maxlines: usize) -> Vec<String> {
    if w <= 0 || maxlines == 0 {
        return Vec::new();
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        let mut word = word.to_owned();
        while text_width(&word) > w {
            let room = w - (text_width(&current) + 1);
            let head = clip_cells(&word, room.max(0));
            if head.is_empty() {
                lines.push(std::mem::take(&mut current));
                continue;
            }
            current.push_str(if current.is_empty() { "" } else { " " });
            current.push_str(&head);
            lines.push(std::mem::take(&mut current));
            word = word.chars().skip(head.chars().count()).collect();
        }
        let joined = if current.is_empty() {
            word.clone()
        } else {
            format!("{current} {word}")
        };
        if text_width(&joined) > w && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
            current = word;
        } else {
            current = joined;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.len() > maxlines {
        lines.truncate(maxlines);
        if let Some(last) = lines.last_mut() {
            *last = format!("{}…", clip_cells(last, w - 1));
        }
    }
    lines
}

// ── the council pane ────────────────────────────────────────────────

/// How a seat is drawn right now: the verdict it landed, or the body that
/// shows what it is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeatMode {
    Resting,
    /// Triage: the bench is being weighed.
    Scanning,
    Stamping(Verdict),
    Computing,
    Wiring,
    Answered,
    Lost,
}

fn seat_mode(phase: &Phase, seat: &BenchSeat, verdict: Option<Verdict>) -> SeatMode {
    // An idle council rests whatever the seats were doing last; a failed one
    // rests too, except for the seats that lost their signal.
    if seat.name.is_empty() || phase.name == "IDLE" || phase.name.is_empty() {
        return SeatMode::Resting;
    }
    if seat.activity == SeatActivity::Lost {
        return SeatMode::Lost;
    }
    match phase.name.as_str() {
        "FAIL" => return SeatMode::Resting,
        "TRIAGE" | "TRIAGED" => return SeatMode::Scanning,
        "SYNC" => return SeatMode::Wiring,
        _ => {}
    }
    if let Some(verdict) = verdict {
        return SeatMode::Stamping(verdict);
    }
    if phase.name == "DELIBERATING" {
        return match seat.activity {
            SeatActivity::Answered => SeatMode::Answered,
            SeatActivity::Working => SeatMode::Computing,
            SeatActivity::Resting => SeatMode::Resting,
            SeatActivity::Wiring => SeatMode::Wiring,
            SeatActivity::Lost => SeatMode::Lost,
        };
    }
    SeatMode::Answered
}

/// Draw the council pane into `(x, y, w, h)`. `now_ms` is the process clock
/// the animation runs by; the wall-clock time in the header comes from the
/// state's own `clock`, so a test renders the same frame twice.
pub fn draw_council(
    cv: &mut Cv,
    (x, y, w, h): (i32, i32, i32, i32),
    state: &CouncilState,
    palette: BenchPalette,
    now_ms: u64,
    reduced: bool,
) -> bool {
    let width = w.max(1);
    let t = if reduced {
        0.0
    } else {
        (now_ms % 3_600_000) as f32 / 1_000.0
    };
    let now_secs = now_ms as f64 / 1_000.0;
    let spin = SPIN[(t * 6.0) as usize % SPIN.len()];
    let mut row = y;

    // Header: a mark, the name in shifting warm/cool, a subtitle when there
    // is room for it, and the local time.
    let mut at = cv.bold(x, row, " ▲ ", palette.cool, None);
    for (i, ch) in "MAGI".chars().enumerate() {
        let phase = 0.5 + 0.5 * ((i as f32 * 0.9) - t * 1.5).sin();
        let letter = format!("{ch} ");
        at = cv.bold(
            at,
            row,
            &letter,
            mix(palette.warm, palette.cool, phase),
            None,
        );
    }
    at = cv.bold(at, row, "◢", palette.warm, None);
    let subtitle = " 에스파 의사결정 기구";
    if width >= (at - x) + text_width(subtitle) + 8 {
        at = cv.bold(at, row, subtitle, palette.body, None);
    } else if width >= (at - x) + 9 + 8 {
        at = cv.bold(at, row, " KWANGYA", palette.body, None);
    }
    if let Some(origin) = state.clock {
        let clock = format!("{} ", origin.hhmm(now_ms));
        let clock_at = x + width - text_width(&clock);
        if clock_at > at {
            cv.text(clock_at, row, &clock, palette.dim, None);
        }
    }
    row += 1;

    // A rule that runs warm to cool.
    gradient_rule(
        cv,
        x,
        row,
        width,
        '━',
        [palette.warm, palette.blend, palette.cool],
    );

    // The narration strip is laid out first, so the cards get every row it
    // does not need.
    let strip = narration(state, spin, palette);
    let budget: usize = match h {
        24.. => 4,
        18..=23 => 3,
        14..=17 => 2,
        _ => 1,
    };
    let mut strip_lines: Vec<(String, Rgb, String, Rgb)> = Vec::new();
    for (label, label_colour, body, body_colour) in &strip {
        let room = budget.saturating_sub(strip_lines.len());
        if room == 0 {
            break;
        }
        let head = format!(" {label} ");
        let lines = wrap(body, (width - text_width(&head) - 2).max(8), room);
        for (index, line) in lines.iter().enumerate() {
            strip_lines.push((
                if index == 0 {
                    head.clone()
                } else {
                    " ".repeat(text_width(&head) as usize)
                },
                *label_colour,
                format!(" {line}"),
                *body_colour,
            ));
        }
    }

    row = y + 2;
    // The bench is one row of cards when the pane is wide: four when they
    // fit at ten cells each, otherwise three, with the rest as chips below.
    // A narrower pane stacks them two by two, and draws a list only when
    // even a pair cannot fit.
    let seats = if state.seats.is_empty() {
        &state.history.last_seats
    } else {
        &state.seats
    };
    let seat_count = seats.len().min(4);
    let (columns, rows_of_cards) = if seat_count == 0 {
        (0, 0)
    } else if width >= 38 {
        let columns = (if (width - 4) / 4 >= 10 { 4 } else { 3 }).min(seat_count);
        (columns, 1)
    } else if (width - 2) / 2 >= 13 && h >= 13 {
        let columns = 2.min(seat_count);
        (columns, seat_count.div_ceil(columns))
    } else {
        (0, 1)
    };
    // Seats the cards leave out: the fourth when only three fit, and any seat
    // past the bench.
    let chips: Vec<(String, String, SeatActivity)> = seats
        .iter()
        .take(4)
        .enumerate()
        // A one-row bench leaves out the seats its cards could not hold; a
        // pane that lists the bench holds all four, and a stack holds them too.
        .skip(if rows_of_cards == 1 && columns > 0 {
            columns
        } else {
            4
        })
        .map(|(index, seat)| {
            (
                format!("{}·{:02}", seat.name, index + 1),
                seat.lab.clone(),
                seat.activity,
            )
        })
        .chain(
            state
                .extra_seats
                .iter()
                .map(|seat| (seat.name.clone(), seat.lab.clone(), seat.activity)),
        )
        .collect();
    let keys_row = h >= 20 && width >= 40;
    let fixed = 2 + usize::from(!chips.is_empty()) + 2 + usize::from(keys_row);
    let body_rows = h as usize;
    let panel_h = body_rows
        .saturating_sub(fixed + strip_lines.len().max(1))
        .saturating_div(rows_of_cards.max(1));

    if columns > 0 && panel_h >= 6 {
        // The cards fill the width they are given: as wide as four (or two)
        // fit, as tall as the body allows, so the pane adapts to any size.
        let panel_h = (panel_h.min(if rows_of_cards == 1 { 24 } else { 16 })) as i32;
        let columns = columns as i32;
        let card_w = ((width - 1 - (columns - 1)) / columns).clamp(1, 30);
        let used = columns * card_w + (columns - 1);
        let left = ((width - used) / 2).max(1);
        for index in 0..(columns as usize * rows_of_cards).min(seat_count) {
            let seat = seats.get(index);
            let verdict = seat.and_then(|seat| resolved_verdict(state, index, seat, now_secs));
            let mode = seat.map_or(SeatMode::Resting, |seat| {
                seat_mode(&state.phase, seat, verdict)
            });
            let seed = state
                .history
                .last_at
                .map(|at| (at as i64).rem_euclid(1_000) as f32)
                .unwrap_or(0.0)
                + index as f32 * 37.0;
            let crown = seat.is_some_and(|seat| state.winner_seats.contains(&seat.name));
            let cards = seat_card(
                index,
                seat,
                mode,
                verdict,
                state.history.last_seats.get(index),
                crown,
                t,
                card_w,
                panel_h,
                seed,
                palette,
            );
            let column = index as i32 % columns;
            let band = index as i32 / columns;
            let cx = x + left + column * (card_w + 1);
            let cy = row + band * panel_h;
            for (offset, runs) in cards.iter().enumerate() {
                if offset as i32 >= panel_h {
                    break;
                }
                let mut at = cx;
                for run in runs {
                    at = if run.bold {
                        cv.bold(at, cy + offset as i32, &run.text, run.fg, run.bg)
                    } else {
                        cv.text(at, cy + offset as i32, &run.text, run.fg, run.bg)
                    };
                }
            }
        }
        row += panel_h * rows_of_cards as i32;
    } else {
        // A narrow pane lists the bench instead.
        for index in 0..seat_count {
            let seat = seats.get(index);
            let verdict = seat.and_then(|seat| resolved_verdict(state, index, seat, now_secs));
            let mode = seat.map_or(SeatMode::Resting, |seat| {
                seat_mode(&state.phase, seat, verdict)
            });
            let (name, number) = seat
                .map(|seat| (seat.name.clone(), seat.number.clone()))
                .unwrap_or_else(|| {
                    (
                        COUNCIL_NAMES.get(index).copied().unwrap_or("AE").into(),
                        format!("{:02}", index + 1),
                    )
                });
            let accent = seat_accent(index, palette);
            let live = mode != SeatMode::Resting;
            let (word, colour) = match mode {
                SeatMode::Stamping(verdict) => (
                    format!("{} {}", verdict.hangul(), verdict.english()),
                    palette.verdict_colour(verdict),
                ),
                SeatMode::Computing => (format!("심의중 {spin}"), accent),
                SeatMode::Scanning => (format!("선별중 {spin}"), accent),
                SeatMode::Wiring => ("SYNK".into(), accent),
                SeatMode::Answered => ("응답완료".into(), accent),
                SeatMode::Lost => ("신호없음".into(), NO),
                SeatMode::Resting => ("대기".into(), palette.mute()),
            };
            let label = fit(&format!("{name}·{number}"), 12, Align::Left);
            cv.text(x, row, " ▍", if live { accent } else { palette.dim }, None);
            cv.bold(
                x + 2,
                row,
                &label,
                if live { accent } else { palette.mute() },
                None,
            );
            if matches!(mode, SeatMode::Stamping(_)) {
                cv.bold(x + 15, row, &word, colour, None);
            } else {
                cv.text(x + 15, row, &word, colour, None);
            }
            row += 1;
        }
    }

    // Seats the cards left out, as one chip each.
    if !chips.is_empty() {
        let mut at = x + 1;
        for (name, lab, activity) in &chips {
            let (dot, colour) = match activity {
                SeatActivity::Answered => ("●", OK),
                SeatActivity::Lost => ("×", NO),
                _ => ("○", palette.mute()),
            };
            at = cv.text(at, row, &format!("{name} "), palette.mute(), None);
            at = cv.text(at, row, lab, palette.body, None);
            at = cv.text(at, row, &format!(" {dot}  "), colour, None);
        }
        row += 1;
    }

    // The strip.
    for (label, label_colour, body, body_colour) in strip_lines {
        let mut at = x;
        at = cv.bold(at, row, &label, label_colour, None);
        at = cv.text(at, row, "▏", palette.dim, None);
        cv.text(at, row, &body, body_colour, None);
        row += 1;
    }

    // Footer: a rule, the phase, the record. The standalone pane keeps a third
    // row under them for its key hints where it is wide and tall enough, so
    // there the last row stays empty; elsewhere the phase sits on the last row.
    let tail = (if keys_row { 3 } else { 2 }).min(h - 1);
    if tail >= 2 {
        let rule_row = y + h - tail;
        if rule_row > row {
            row = rule_row;
        }
        gradient_rule(
            cv,
            x,
            row,
            width,
            '─',
            [palette.dim, palette.dim, palette.dim],
        );
        row += 1;
        let failed = state.phase.name == "FAIL";
        let colour = if failed {
            NO
        } else if state.phase.name == "IDLE" || state.phase.name.is_empty() {
            palette.mute()
        } else {
            palette.cool
        };
        let blink = if (t * 2.0) as i32 % 2 == 0 {
            "▌"
        } else {
            " "
        };
        let mut at = x;
        at = cv.text(at, row, " PHASE ", palette.mute(), None);
        at = cv.bold(at, row, state.phase.hangul(), colour, None);
        if width >= 44 {
            at = cv.text(at, row, " ", palette.dim, None);
            at = cv.text(
                at,
                row,
                state.phase.english().unwrap_or(&state.phase.name),
                palette.dim,
                None,
            );
        }
        at = cv.text(at, row, &format!(" {blink}"), colour, None);
        if state.history.seen > 0 {
            let mut record = format!("기록 {}/{}", state.history.finished, state.history.seen);
            if let Some(last_at) = state.history.last_at {
                let age = (now_secs - last_at).max(0.0);
                record.push_str(&format!(" · {}", age_text(age)));
            }
            let record_at = x + width - text_width(&record) - 1;
            if record_at >= at + 2 {
                cv.text(record_at, row, &record, palette.dim, None);
            }
        }
    }
    true
}

fn age_text(seconds: f64) -> String {
    if seconds >= 5_400.0 {
        format!("{:.0}h 전", seconds / 3_600.0)
    } else if seconds >= 90.0 {
        format!("{:.0}m 전", seconds / 60.0)
    } else {
        format!("{seconds:.0}s 전")
    }
}

/// How recent a finished council's record must be to count as this council.
const SAME_COUNCIL_SECS: f64 = 30.0;

/// The verdict drawn for a seat: what the live state says. Only when a council
/// has just reached its verdict, and the record is the one it wrote, may the
/// record fill in a seat the state file left bare. At any other time the
/// record belongs to an earlier council, and showing its votes would stamp
/// seats that have not answered yet.
fn resolved_verdict(
    state: &CouncilState,
    index: usize,
    seat: &BenchSeat,
    now_secs: f64,
) -> Option<Verdict> {
    seat.verdict.or_else(|| {
        let this_council = state.phase.name == "VERDICT"
            && state
                .history
                .last_at
                .is_some_and(|at| (now_secs - at).abs() < SAME_COUNCIL_SECS);
        if !this_council {
            return None;
        }
        state
            .history
            .last_seats
            .get(index)
            .and_then(|last| last.verdict)
    })
}

/// The narration lines: a label, its colour, the body, the body's colour.
#[allow(clippy::type_complexity)]
fn narration(
    state: &CouncilState,
    spin: &str,
    palette: BenchPalette,
) -> Vec<(String, Rgb, String, Rgb)> {
    let mut strip = Vec::new();
    let mut votes: Vec<Verdict> = state.seats.iter().filter_map(|seat| seat.verdict).collect();
    votes.sort_by_key(|vote| vote.rank());
    let note = state.phase.note.trim();
    let judge = "nævis";
    match state.phase.name.as_str() {
        "VERDICT" => {
            if !votes.is_empty() {
                let top = [Verdict::Approve, Verdict::Reject, Verdict::Hold]
                    .into_iter()
                    .map(|verdict| votes.iter().filter(|vote| **vote == verdict).count())
                    .max()
                    .unwrap_or(0);
                let lead: Vec<Verdict> = [Verdict::Approve, Verdict::Hold, Verdict::Reject]
                    .into_iter()
                    .filter(|verdict| {
                        top > 0 && votes.iter().filter(|vote| *vote == verdict).count() == top
                    })
                    .collect();
                if lead.len() == 1 {
                    let major = lead[0];
                    let colour = palette.verdict_colour(major);
                    strip.push((
                        "다수결".into(),
                        colour,
                        format!(
                            "{} {} · {top}/{}",
                            major.hangul(),
                            major.english(),
                            votes.len()
                        ),
                        colour,
                    ));
                    if !state.winner_seats.is_empty() {
                        strip.push((
                            "승자".into(),
                            colour,
                            state.winner_seats.join(" · "),
                            colour,
                        ));
                    }
                } else {
                    let names: Vec<&str> = lead.iter().map(|verdict| verdict.hangul()).collect();
                    strip.push((
                        "동률".into(),
                        HOLD_COLOUR,
                        format!(
                            "{} · {top}/{} · {judge} 결정",
                            names.join(" = "),
                            votes.len()
                        ),
                        HOLD_COLOUR,
                    ));
                    strip.push((
                        "무승자".into(),
                        palette.mute(),
                        format!("동률 — {judge} 판정"),
                        palette.mute(),
                    ));
                }
            }
            let conclusion = note.strip_prefix("FINAL:").unwrap_or(note).trim();
            strip.push((
                judge.into(),
                palette.warm,
                if conclusion.is_empty() {
                    "결론에 도달했습니다.".into()
                } else {
                    conclusion.to_string()
                },
                palette.body,
            ));
        }
        "JUDGING" => strip.push((
            judge.into(),
            palette.warm,
            format!("판정 중 {spin}"),
            palette.body,
        )),
        "VOTING" | "VOTED" => strip.push((
            "표결".into(),
            palette.blend,
            if state.phase.name == "VOTED" && !note.is_empty() {
                note.to_string()
            } else {
                format!("익명 상호 평가 {spin}")
            },
            palette.body,
        )),
        "DELIBERATING" => {
            let done = state
                .seats
                .iter()
                .filter(|seat| seat.activity == SeatActivity::Answered)
                .count();
            let mut body = format!("{done}/{} 응답", state.seats.len());
            if !votes.is_empty() {
                body.push_str(&format!(" · 표 {}", votes.len()));
            }
            strip.push(("심의".into(), palette.cool, body, palette.body));
        }
        "SYNC" => strip.push((
            "SYNK".into(),
            palette.cool,
            format!("DIVE · seats {}", state.seats.len()),
            palette.body,
        )),
        "TRIAGE" => strip.push((
            "선별".into(),
            palette.cool,
            format!("분석 중 {spin}"),
            palette.body,
        )),
        "TRIAGED" => {
            let class = note.to_uppercase();
            let colour = match class.as_str() {
                "SKIP" => palette.mute(),
                "QUICK" => palette.cool,
                "TRIAL" => palette.warm,
                _ => palette.body,
            };
            strip.push((
                "선별".into(),
                palette.cool,
                format!("→ {}", if class.is_empty() { "?" } else { &class }),
                colour,
            ));
        }
        "FAIL" => strip.push((
            "고장".into(),
            NO,
            if note.is_empty() {
                "council failed".into()
            } else {
                note.to_string()
            },
            NO,
        )),
        _ => {}
    }
    if state.phase.is_resting() {
        // The winner STAYS after the council ends: the record of who won the
        // choice outlives the VERDICT phase, until the next council replaces it.
        if !state.winner_seats.is_empty() {
            // The verdict the winners carried, from the record's seats.
            let carried = state
                .winner_seats
                .first()
                .and_then(|name| {
                    state
                        .history
                        .last_seats
                        .iter()
                        .find(|seat| &seat.name == name)
                })
                .and_then(|seat| seat.verdict);
            let colour = carried
                .map(|verdict| palette.verdict_colour(verdict))
                .unwrap_or(OK);
            let mut body = state.winner_seats.join(" · ");
            if let Some(verdict) = carried {
                body.push_str(&format!(" → {}", verdict.engine()));
            }
            strip.push(("승자".into(), colour, body, colour));
        } else if state.history.tie {
            strip.push((
                "무승자".into(),
                palette.mute(),
                format!("동률 — {judge} 판정"),
                palette.mute(),
            ));
        }
        if !state.history.last_final.is_empty() {
            strip.push((
                "최근".into(),
                palette.mute(),
                state.history.last_final.clone(),
                palette.mute(),
            ));
        }
    }
    strip
}

/// One styled stretch of a card row.
#[derive(Debug, Clone, PartialEq)]
struct Run {
    text: String,
    fg: Rgb,
    bg: Option<Rgb>,
    bold: bool,
}

fn run(text: impl Into<String>, fg: Rgb, bold: bool) -> Run {
    Run {
        text: text.into(),
        fg,
        bg: None,
        bold,
    }
}

/// Dark text on an accent block, like the standalone pane's name plates.
fn chip(text: impl Into<String>, ink: Rgb, block: Rgb) -> Run {
    Run {
        text: text.into(),
        fg: ink,
        bg: Some(block),
        bold: true,
    }
}

/// The seat's role in the bench's own language.
fn role_hangul(role: &str) -> &str {
    match role {
        "LEAD" => "총괄",
        "EDGE" => "반론",
        "EXACT" => "검증",
        "BOLD" => "확장",
        // The roles of a council convened in this terminal, in the same voice.
        "SKEPTIC" => "반론",
        "BUILDER" => "구현",
        "RISK" => "위험",
        other => other,
    }
}

/// One seat card: name plate, lab, model, a body that shows what the seat is
/// doing, and the footer (its verdict, or what it is waiting on). `crown`
/// marks a resting seat that carried the last council's choice.
#[allow(clippy::too_many_arguments)]
fn seat_card(
    index: usize,
    seat: Option<&BenchSeat>,
    mode: SeatMode,
    _verdict: Option<Verdict>,
    last: Option<&BenchSeat>,
    crown: bool,
    t: f32,
    w: i32,
    h: i32,
    seed: f32,
    palette: BenchPalette,
) -> Vec<Vec<Run>> {
    let accent = seat_accent(index, palette);
    let live = !matches!(mode, SeatMode::Resting);
    let inner = (w - 2).max(0);
    let verdict_colour = match mode {
        SeatMode::Stamping(verdict) => Some(palette.verdict_colour(verdict)),
        _ => None,
    };
    let edge = verdict_colour.unwrap_or(if live { accent } else { palette.dim });

    let name = seat
        .map(|seat| seat.name.clone())
        .unwrap_or_else(|| COUNCIL_NAMES.get(index).copied().unwrap_or("AE").into());
    let number = seat
        .map(|seat| seat.number.clone())
        .unwrap_or_else(|| format!("{:02}", index + 1));
    let mut rows = Vec::new();
    // Name plate, an accent block; shorter forms when the card is thin.
    let plate_colour = if live {
        accent
    } else {
        palette.soft_accent(accent)
    };
    let mut top = None;
    for tag in [
        format!(" {name}·{number} "),
        format!("{name}·{number}"),
        format!(" {name} "),
        name.clone(),
        format!(" {number} "),
        number.clone(),
    ] {
        let rest = inner - text_width(&tag);
        if rest >= 2 && tag.starts_with(' ') && tag.contains('·') {
            top = Some(vec![
                run("╭─", edge, false),
                chip(tag, palette.on_accent, plate_colour),
                run(
                    format!("{}╮", "─".repeat((rest - 1).max(0) as usize)),
                    edge,
                    false,
                ),
            ]);
        } else if rest >= 0 {
            let left = rest / 2;
            top = Some(vec![
                run(format!("╭{}", "─".repeat(left as usize)), edge, false),
                chip(tag, palette.on_accent, plate_colour),
                run(
                    format!("{}╮", "─".repeat((rest - left) as usize)),
                    edge,
                    false,
                ),
            ]);
        }
        if top.is_some() {
            break;
        }
    }
    rows.push(top.unwrap_or_else(|| {
        vec![run(
            format!("╭{}╮", "─".repeat(inner.max(0) as usize)),
            edge,
            false,
        )]
    }));
    let lab = seat
        .map(|seat| seat.lab.clone())
        .filter(|lab| !lab.is_empty())
        .or_else(|| last.map(|last| last.lab.clone()))
        .unwrap_or_else(|| "ae".into());
    rows.push(vec![
        run("│", edge, false),
        run(
            fit_centre(&lab, inner),
            if live { palette.body } else { palette.mute() },
            live,
        ),
        run("│", edge, false),
    ]);
    if h >= 11 {
        let model = seat
            .map(|seat| seat.model.clone())
            .filter(|model| !model.is_empty())
            .or_else(|| last.map(|last| last.model.clone()))
            .unwrap_or_default();
        let (line, colour) = if live {
            // A name too long for the card is cut with an ellipsis, as the
            // standalone pane cuts it; the dash is only for a seat with no
            // model at all.
            let shown = short_model(&model);
            (
                if shown.is_empty() {
                    "—".to_string()
                } else {
                    shown
                },
                palette.mute(),
            )
        } else {
            let role = seat
                .map(|seat| seat.role.clone())
                .filter(|role| !role.is_empty())
                .unwrap_or_else(|| {
                    ["LEAD", "EDGE", "EXACT", "BOLD"]
                        .get(index)
                        .copied()
                        .unwrap_or("LEAD")
                        .into()
                });
            let tag = role_hangul(&role).to_string();
            (
                first_fit(&[format!("{tag} · {role}"), tag.clone()], inner),
                palette.half_accent(accent),
            )
        };
        rows.push(vec![
            run("│", edge, false),
            run(fit_centre(&line, inner), colour, false),
            run("│", edge, false),
        ]);
    }
    rows.push(vec![run(
        format!("├{}┤", "─".repeat(inner.max(0) as usize)),
        edge,
        false,
    )]);
    let body_rows = (h - rows.len() as i32 - 3).max(1);
    let (body, body_colour, bold, foot, foot_colour, foot_bold) = match mode {
        SeatMode::Stamping(verdict) => {
            let colour = palette.verdict_colour(verdict);
            (
                seal(verdict.hangul(), inner, body_rows),
                colour,
                true,
                verdict.english().to_string(),
                colour,
                true,
            )
        }
        SeatMode::Computing => (
            equaliser(seed, t, inner, body_rows, 1.0),
            accent,
            false,
            fit_centre(
                &format!("심의중 {}", SPIN[(t * 6.0) as usize % SPIN.len()]),
                inner,
            ),
            accent,
            false,
        ),
        SeatMode::Scanning => (
            equaliser(seed, t, inner, body_rows, 0.35),
            accent,
            false,
            first_fit(
                &[
                    format!("선별중 {}", SPIN[(t * 6.0) as usize % SPIN.len()]),
                    "선별중".to_string(),
                ],
                inner,
            ),
            accent,
            false,
        ),
        SeatMode::Wiring => (
            sweep(t + index as f32 * 0.35, inner, body_rows),
            accent,
            false,
            "SYNK".to_string(),
            accent,
            true,
        ),
        SeatMode::Answered => (
            equaliser(seed, t, inner, body_rows, 0.25),
            accent,
            false,
            "응답완료".to_string(),
            accent,
            false,
        ),
        SeatMode::Lost => (
            centred_text(
                &[
                    "신호없음".to_string(),
                    first_fit(&["SIGNAL LOST".into(), "LOST".into()], inner),
                ],
                inner,
                body_rows,
            ),
            NO,
            false,
            "ERROR".to_string(),
            NO,
            true,
        ),
        SeatMode::Resting => {
            let (foot, foot_colour, foot_bold) = match last.and_then(|last| last.verdict) {
                Some(verdict) => {
                    let kr = verdict.hangul();
                    if crown {
                        (
                            first_fit(
                                &[format!("♛ 승자 {kr}"), format!("♛ {kr}"), "♛".to_string()],
                                inner,
                            ),
                            palette.verdict_colour(verdict),
                            true,
                        )
                    } else {
                        let mut options = match last.and_then(|last| last.confidence) {
                            Some(confidence) => {
                                vec![
                                    format!("최근 {kr} {confidence}"),
                                    format!("{kr} {confidence}"),
                                ]
                            }
                            None => vec![format!("최근 {kr}")],
                        };
                        options.push(kr.to_string());
                        (
                            first_fit(&options, inner),
                            palette.half_accent(palette.verdict_colour(verdict)),
                            false,
                        )
                    }
                }
                None => ("대기".to_string(), palette.mute(), false),
            };
            (
                stars(seed, t, inner, body_rows),
                palette.dim,
                false,
                foot,
                foot_colour,
                foot_bold,
            )
        }
    };
    for line in body {
        rows.push(vec![
            run("│", edge, false),
            run(line, body_colour, bold),
            run("│", edge, false),
        ]);
    }
    rows.push(vec![run(
        format!("├{}┤", "─".repeat(inner.max(0) as usize)),
        edge,
        false,
    )]);
    rows.push(vec![
        run("│", edge, false),
        run(fit_centre(&foot, inner), foot_colour, foot_bold),
        run("│", edge, false),
    ]);
    rows.push(vec![run(
        format!("╰{}╯", "─".repeat(inner.max(0) as usize)),
        edge,
        false,
    )]);
    rows
}

const COUNCIL_NAMES: [&str; 4] = ["KARINA", "GISELLE", "WINTER", "NINGNING"];
const SPIN: [&str; 4] = ["▖", "▘", "▝", "▗"];

/// The engine's phase word in Hangul, as both panes label it.
fn phase_hangul(name: &str) -> &str {
    match name {
        "TRIAGE" => "분석중",
        "TRIAGED" => "선별",
        "SYNC" => "기동",
        "DELIBERATING" => "심의",
        "VOTING" => "표결",
        "VOTED" => "투표완료",
        "JUDGING" => "판정",
        "VERDICT" => "결론도달",
        "FAIL" => "고장",
        _ => "대기",
    }
}

/// The model name without the prefixes the pane hides.
fn short_model(model: &str) -> String {
    let trimmed = model
        .strip_prefix("claude-")
        .or_else(|| model.strip_prefix("or-"))
        .unwrap_or(model);
    trimmed.to_string()
}

fn gradient_rule(cv: &mut Cv, x: i32, y: i32, w: i32, ch: char, stops: [Rgb; 3]) {
    let chunks = (w.clamp(1, 12)).max(1);
    for i in 0..chunks {
        let a = i * w / chunks;
        let b = (i + 1) * w / chunks;
        let t = if chunks > 1 {
            i as f32 / (chunks - 1) as f32
        } else {
            0.0
        };
        let colour = if t < 0.5 {
            mix(stops[0], stops[1], t * 2.0)
        } else {
            mix(stops[1], stops[2], (t - 0.5) * 2.0)
        };
        let run = (b - a).max(0) as usize;
        if run > 0 {
            cv.text(x + a, y, &ch.to_string().repeat(run), colour, None);
        }
    }
}

/// A still field of faint marks that drift as time passes.
fn stars(seed: f32, t: f32, w: i32, rows: i32) -> Vec<String> {
    let mut out = Vec::new();
    for r in 0..rows {
        let mut line = String::new();
        for c in 0..w.max(0) {
            let pick = noise(r as u32, c as u32, seed as u32);
            if pick >= 0.07 {
                line.push(' ');
                continue;
            }
            // Each star twinkles at its own rate from its own offset, so the
            // field shimmers instead of blinking as one.
            let rate = noise(r as u32, c as u32, (seed as u32).wrapping_add(0x51ED));
            let offset = noise(c as u32, r as u32, (seed as u32).wrapping_add(0xA17));
            let phase = (t * (0.5 + rate) + offset * std::f32::consts::TAU).sin();
            line.push(if phase > 0.75 {
                '+'
            } else if phase > -0.3 {
                '·'
            } else {
                ' '
            });
        }
        out.push(line);
    }
    out
}

fn noise(a: u32, b: u32, c: u32) -> f32 {
    let mut x = a
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(b.wrapping_mul(0x85EB_CA6B))
        .wrapping_add(c.wrapping_mul(0xC2B2_AE35));
    x ^= x >> 15;
    x = x.wrapping_mul(0x2C1B_3C6D);
    x ^= x >> 12;
    (x % 10_000) as f32 / 10_000.0
}

/// Bars rising and falling like a level meter, one per other column.
fn equaliser(seed: f32, t: f32, w: i32, rows: i32, amp: f32) -> Vec<String> {
    const EIGHTHS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let heights: Vec<i32> = (0..w.max(0))
        .map(|c| {
            if c % 2 == 1 {
                return 0;
            }
            let c = c as f32;
            let v = (0.55 + 0.45 * (t * 2.3 + c * 0.9 + seed).sin())
                * (0.60 + 0.40 * (t * 3.7 + c * 1.7 + seed * 1.9).sin());
            ((v * amp).max(0.04) * rows as f32 * 8.0) as i32
        })
        .collect();
    (0..rows)
        .map(|row| {
            let base = (rows - 1 - row) * 8;
            heights
                .iter()
                .map(|height| EIGHTHS[(height - base).clamp(0, 8) as usize])
                .collect()
        })
        .collect()
}

/// A pulse sweeping along a baseline.
fn sweep(t: f32, w: i32, rows: i32) -> Vec<String> {
    let mut out = vec![" ".repeat(w.max(0) as usize); rows.max(0) as usize];
    if rows <= 0 {
        return out;
    }
    let pos = ((t * 9.0) as i32).rem_euclid(w + 6) - 3;
    let line: String = (0..w.max(0))
        .map(|c| match (c - pos).abs() {
            0 => '█',
            1 => '▓',
            2 => '▒',
            _ => '─',
        })
        .collect();
    out[(rows / 2) as usize] = line;
    out
}

/// Lines centred in a block of `rows` lines.
fn centred_text(lines: &[String], w: i32, rows: i32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let top = ((rows - lines.len() as i32) / 2).max(0);
    for _ in 0..top {
        out.push(fit("", w, Align::Left));
    }
    for line in lines.iter().take(rows.max(0) as usize) {
        out.push(fit_centre(line, w));
    }
    while out.len() < rows.max(0) as usize {
        out.push(fit("", w, Align::Left));
    }
    out.truncate(rows.max(0) as usize);
    out
}

/// Pixels along a side of a stored glyph.
const GLYPH_SIDE: usize = 32;

/// The stored glyph of one syllable of a verdict word.
fn glyph(syllable: char) -> Option<&'static [&'static str; GLYPH_SIDE]> {
    match syllable {
        '승' => Some(&GLYPH_C2B9),
        '인' => Some(&GLYPH_C778),
        '거' => Some(&GLYPH_AC70),
        '부' => Some(&GLYPH_BD80),
        '보' => Some(&GLYPH_BCF4),
        '류' => Some(&GLYPH_B958),
        _ => None,
    }
}

/// The quadrant blocks, indexed by which sub-pixels are lit:
/// top-left 1, top-right 2, bottom-left 4, bottom-right 8.
const QUADRANTS: [char; 16] = [
    ' ', '▘', '▝', '▀', '▖', '▌', '▞', '▛', '▗', '▚', '▐', '▜', '▄', '▙', '▟', '█',
];

/// A verdict word drawn large in a box of `w` by `rows` cells, with quadrant
/// blocks (two by two sub-pixels a cell). The syllables go side by side or
/// stacked, whichever gives the larger glyph; each is sized to 98% of the
/// smaller side of its slot and centred in it, and a sub-pixel is lit when
/// the glyph covers more than a third of it. That is how the standalone pane
/// draws its stamps, from the same face; here the glyphs are stored
/// (`ported_seal.rs`), so a seat card needs no font and no image library.
/// A box too small for the glyphs to read, or a word with no stored glyphs,
/// gets the word itself.
fn seal(word: &str, w: i32, rows: i32) -> Vec<String> {
    let plain = || centred_text(&[word.to_string()], w, rows);
    let glyphs: Option<Vec<&'static [&'static str; GLYPH_SIDE]>> =
        word.chars().map(glyph).collect();
    let Some(glyphs) = glyphs.filter(|glyphs| !glyphs.is_empty()) else {
        return plain();
    };
    if w < 6 || rows < 3 {
        return plain();
    }
    let count = glyphs.len() as f64;
    // A square-pixel canvas: a cell is two pixels wide and four tall.
    let (canvas_w, canvas_h) = (f64::from(2 * w), f64::from(4 * rows));
    let side_by_side = (canvas_w / count).min(canvas_h);
    let stacked = canvas_w.min(canvas_h / count);
    let (slot, stacked) = if stacked > side_by_side {
        (stacked, true)
    } else {
        (side_by_side, false)
    };
    let size = slot * 0.98;
    if size < 12.0 {
        return plain();
    }
    let (columns, grid_rows) = (2 * w as usize, 2 * rows as usize);
    let mut ink = vec![0.0f64; columns * grid_rows];
    let step = size / GLYPH_SIDE as f64;
    for (index, glyph) in glyphs.iter().enumerate() {
        let middle = index as f64 + 0.5;
        let (cx, cy) = if stacked {
            (canvas_w / 2.0, canvas_h * middle / count)
        } else {
            (canvas_w * middle / count, canvas_h / 2.0)
        };
        let (x0, y0) = (cx - size / 2.0, cy - size / 2.0);
        let cover: Vec<[f64; GLYPH_SIDE]> = glyph
            .iter()
            .map(|row| {
                let mut line = [0.0; GLYPH_SIDE];
                for (pixel, digit) in line.iter_mut().zip(row.chars()) {
                    *pixel = f64::from(digit.to_digit(16).unwrap_or(0)) / 15.0;
                }
                line
            })
            .collect();
        for gy in 0..grid_rows {
            // A sub-pixel is one canvas pixel wide and two tall.
            let (ya, yb) = ((2 * gy) as f64, (2 * gy + 2) as f64);
            if yb <= y0 || ya >= y0 + size {
                continue;
            }
            let v_lo = ((ya - y0) / step).floor().max(0.0) as usize;
            let v_hi = (((yb - y0) / step).floor().max(0.0) as usize).min(GLYPH_SIDE - 1);
            for gx in 0..columns {
                let (xa, xb) = (gx as f64, (gx + 1) as f64);
                if xb <= x0 || xa >= x0 + size {
                    continue;
                }
                let u_lo = ((xa - x0) / step).floor().max(0.0) as usize;
                let u_hi = (((xb - x0) / step).floor().max(0.0) as usize).min(GLYPH_SIDE - 1);
                let mut covered = 0.0;
                for (v, line) in cover.iter().enumerate().take(v_hi + 1).skip(v_lo) {
                    let down = yb.min(y0 + (v + 1) as f64 * step) - ya.max(y0 + v as f64 * step);
                    if down <= 0.0 {
                        continue;
                    }
                    for (u, pixel) in line.iter().enumerate().take(u_hi + 1).skip(u_lo) {
                        let across =
                            xb.min(x0 + (u + 1) as f64 * step) - xa.max(x0 + u as f64 * step);
                        if across > 0.0 {
                            covered += pixel * across * down;
                        }
                    }
                }
                ink[gy * columns + gx] += covered / 2.0;
            }
        }
    }
    let lit = |gx: usize, gy: usize| ink[gy * columns + gx] > 88.0 / 255.0;
    (0..rows as usize)
        .map(|r| {
            (0..w as usize)
                .map(|c| {
                    let index = usize::from(lit(2 * c, 2 * r))
                        | usize::from(lit(2 * c + 1, 2 * r)) << 1
                        | usize::from(lit(2 * c, 2 * r + 1)) << 2
                        | usize::from(lit(2 * c + 1, 2 * r + 1)) << 3;
                    QUADRANTS[index]
                })
                .collect()
        })
        .collect()
}
// ── the reactor's council bench ─────────────────────────────────────

/// The council seen from the reactor: a compact bench on the panel's bottom
/// edge, present only while a council is running or has just finished.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CouncilBench {
    pub phase: String,
    pub seats: Vec<SeatActivity>,
    pub verdicts: Vec<Option<Verdict>>,
}

impl CouncilBench {
    /// The bench for a council state, or `None` when it is not worth
    /// showing: a quiet council, or one whose phase the bench does not cover.
    pub fn of(state: &CouncilState, now_secs: f64) -> Option<Self> {
        // The bench holds a finished verdict for a while, then releases the
        // panel back to its own rotation.
        const HOLD_SECS: f64 = 6.0;
        let live = matches!(
            state.phase.name.as_str(),
            "SYNC" | "DELIBERATING" | "VOTING" | "VOTED" | "JUDGING"
        );
        let recent = state.phase.name == "VERDICT"
            && state
                .history
                .last_at
                .is_some_and(|at| now_secs - at <= HOLD_SECS);
        if !live && !recent {
            return None;
        }
        Some(Self {
            phase: state.phase.name.clone(),
            seats: state.seats.iter().map(|seat| seat.activity).collect(),
            verdicts: state.seats.iter().map(|seat| seat.verdict).collect(),
        })
    }
}

/// Draw the council bench on a row. `right` is the column the bench ends
/// before; the caller places it on the panel's bottom edge.
pub fn draw_council_bench(
    cv: &mut Cv,
    x: i32,
    y: i32,
    width: i32,
    bench: &CouncilBench,
    palette: BenchPalette,
    now_secs: f64,
) {
    let word = format!(" {} ", phase_hangul(&bench.phase));
    let dots = bench.seats.len().max(bench.verdicts.len()).max(1) as i32;
    let chip = " ∴ MAGI ";
    let word_w = text_width(&word);
    let total = text_width(chip) + word_w + dots * 2 + 1;
    let bx = x + width - total - 3;
    if bx <= x + 2 || bx + total > x + width {
        return;
    }
    cv.text(bx, y, chip, palette.on_accent, Some(palette.warm));
    cv.bold(bx + text_width(chip), y, &word, palette.body, None);
    let dx = bx + total - dots * 2 - 1;
    for i in 0..dots {
        let verdict = bench.verdicts.get(i as usize).copied().flatten();
        let activity = bench
            .seats
            .get(i as usize)
            .copied()
            .unwrap_or(SeatActivity::Resting);
        let (dot, colour) = match (verdict, activity) {
            (Some(verdict), _) => ("●", palette.verdict_colour(verdict)),
            (None, SeatActivity::Lost) => ("×", NO),
            (None, SeatActivity::Answered) => ("●", palette.body),
            // A seat still working blinks, so the bench reads as live.
            (None, _) => (
                if (now_secs * 3.0 + i as f64) as i64 % 2 == 0 {
                    "◌"
                } else {
                    "○"
                },
                palette.dim,
            ),
        };
        cv.bold(dx + i * 2, y, &format!("{dot} "), colour, None);
    }
}

include!("ported_seal.rs");

#[cfg(test)]
mod tests {
    use super::*;

    fn bench() -> CouncilState {
        CouncilState {
            phase: Phase {
                name: "DELIBERATING".into(),
                note: String::new(),
            },
            seats: COUNCIL_NAMES
                .iter()
                .enumerate()
                .map(|(index, name)| BenchSeat {
                    name: (*name).into(),
                    number: format!("{:02}", index + 1),
                    role: ["LEAD", "EDGE", "EXACT", "BOLD"][index].into(),
                    lab: "ZHIPU".into(),
                    model: "glm-5.3".into(),
                    activity: if index == 0 {
                        SeatActivity::Answered
                    } else {
                        SeatActivity::Working
                    },
                    verdict: None,
                    confidence: None,
                })
                .collect(),
            extra_seats: Vec::new(),
            winner_seats: Vec::new(),
            history: CouncilHistory::default(),
            clock: None,
        }
    }

    #[test]
    fn fitting_is_exact_in_cells() {
        assert_eq!(fit("abc", 5, Align::Left), "abc  ");
        assert_eq!(fit("abc", 5, Align::Centre), " abc ");
        assert_eq!(fit("abc", 5, Align::Right), "  abc");
        assert_eq!(fit("abcdef", 3, Align::Left), "abc");
        // Wide characters count two cells.
        assert_eq!(text_width(&fit("日本", 4, Align::Left)), 4);
        assert_eq!(fit_centre("abcdef", 4), "abc…");
    }

    #[test]
    fn wrapping_respects_the_line_budget_and_marks_a_cut() {
        let lines = wrap("one two three four five six", 9, 2);
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with('…'));
        assert!(lines.iter().all(|line| text_width(line) <= 9));
        assert_eq!(wrap("short", 20, 3), vec!["short"]);
    }

    #[test]
    fn council_text_positions_translate_with_the_panel_origin() {
        use ratatui::{buffer::Buffer, layout::Rect};
        let mut state = bench();
        state.seats.push(state.seats[0].clone());
        let render = |x, y| {
            let area = Rect::new(x, y, 70, 18);
            let mut buffer = Buffer::empty(Rect::new(0, 0, 140, 60));
            let mut cv = Cv::new(&mut buffer);
            let palette = BenchPalette::from_shell(&cv.palette);
            cv.clipped(area, |cv| {
                draw_council(
                    cv,
                    (x as i32, y as i32, 70, 18),
                    &state,
                    palette,
                    4_000,
                    true,
                );
            });
            (0..area.height)
                .flat_map(|row| {
                    let buffer = &buffer;
                    (0..area.width).map(move |column| buffer[(x + column, y + row)].clone())
                })
                .collect::<Vec<_>>()
        };
        for (index, (origin, moved)) in render(0, 0).iter().zip(render(37, 11)).enumerate() {
            assert_eq!(origin, &moved, "at {},{}", index % 70, index / 70);
        }
    }

    const GOLDEN_APPROVE_8X17: [&str; 17] = [
        "        ",
        "        ",
        "   ▗▖   ",
        " ▄█▀▀█▖ ",
        "▝▀▜██▛▀▘",
        " ▐█▄▄█▌ ",
        "        ",
        "        ",
        "        ",
        "        ",
        "        ",
        " ▟▛█▖▐█ ",
        " █▄▟▛▐█ ",
        "  █  ▝▀ ",
        "  ▀▀▀▀▀ ",
        "        ",
        "        ",
    ];
    const GOLDEN_HOLD_10X12: [&str; 12] = [
        "          ",
        " ▐█▄▄▄▄█▖ ",
        " ▐█▀▀▀▀█▌ ",
        " ▝▀▀█▛▀▀▘ ",
        " ████████ ",
        "          ",
        "  ▄▄▄▄▄▄  ",
        "  ██████  ",
        "  █▙▄▄▄▄▖ ",
        " ████████ ",
        "  ▐█  █▌  ",
        "   ▀  ▀   ",
    ];
    const GOLDEN_REJECT_28X17: [&str; 17] = [
        "                 ▗▄▄        ",
        "       ▐███████  ▐██        ",
        "            ▐█▌  ▐██        ",
        "           ▗██▚█████        ",
        "          ▄██▘ ▀▀▜██        ",
        "       ▄▟██▛▘    ▐██        ",
        "       ▀▛▀       ▐██        ",
        "                 ▐██        ",
        "                            ",
        "        ▐██      ██▌        ",
        "        ▐██████████▌        ",
        "        ▐██▄▄▄▄▄▄██▌        ",
        "        ▝▀▀▀▀▀▀▀▀▀▀▘        ",
        "       ██████████████       ",
        "            ▝██             ",
        "             ██             ",
        "             ▀▀             ",
    ];

    #[test]
    fn the_seal_draws_quadrant_blocks_in_the_requested_box() {
        for word in ["승인", "거부", "보류"] {
            for (w, rows) in [(8, 17), (10, 12), (16, 6), (28, 17)] {
                let art = seal(word, w, rows);
                assert_eq!(art.len(), rows as usize, "{word} {w}x{rows}");
                assert!(art.iter().all(|line| text_width(line) == w), "{word}");
                assert!(
                    art.iter().any(|line| line.chars().any(|ch| ch != ' ')),
                    "{word} {w}x{rows} drew nothing"
                );
                assert!(
                    art.iter()
                        .all(|line| line.chars().all(|ch| QUADRANTS.contains(&ch))),
                    "{word} {w}x{rows} drew outside the quadrant set"
                );
            }
        }
        // An unknown word, or a box too small for glyphs, gets the word itself.
        let art = seal("???", 10, 3);
        assert_eq!(art.len(), 3);
        assert!(art.iter().any(|line| line.contains('?')));
        for (w, rows) in [(5, 8), (8, 2), (6, 4)] {
            let art = seal("승인", w, rows);
            assert!(
                art.iter().any(|line| line.contains("승인")),
                "{w}x{rows} is too small for glyphs: {art:?}"
            );
        }
    }

    #[test]
    fn a_narrow_card_stacks_the_syllables_and_a_wide_one_sets_them_side_by_side() {
        // Eight cells wide and tall: the two syllables sit one above the other,
        // with the middle of the box between them empty.
        let tall = seal("승인", 8, 17);
        let inked: Vec<usize> = tall
            .iter()
            .enumerate()
            .filter(|(_, line)| line.chars().any(|ch| ch != ' '))
            .map(|(row, _)| row)
            .collect();
        assert!(inked.first().is_some_and(|row| *row <= 3), "{tall:?}");
        assert!(inked.last().is_some_and(|row| *row >= 13), "{tall:?}");
        assert!(
            tall[8].trim().is_empty(),
            "the middle row separates them\n{}",
            tall.join("\n")
        );
        // Forty cells by ten rows: one row of two syllables, each in half the width.
        let wide = seal("보류", 40, 10);
        let left: usize = wide
            .iter()
            .map(|line| line.chars().take(20).filter(|ch| *ch != ' ').count())
            .sum();
        let right: usize = wide
            .iter()
            .map(|line| line.chars().skip(20).filter(|ch| *ch != ' ').count())
            .sum();
        assert!(
            left > 10 && right > 10,
            "{left} {right}\n{}",
            wide.join("\n")
        );
    }

    #[test]
    fn the_seal_matches_the_prototype_it_was_ported_from() {
        // Golden stamps from the prototype in the parity harness, which matches
        // the standalone pane's own stamps in 86 to 97% of cells.
        assert_eq!(seal("승인", 8, 17), GOLDEN_APPROVE_8X17, "승인 8x17");
        assert_eq!(seal("보류", 10, 12), GOLDEN_HOLD_10X12, "보류 10x12");
        assert_eq!(seal("거부", 28, 17), GOLDEN_REJECT_28X17, "거부 28x17");
    }

    #[test]
    fn the_verdict_a_seat_carried_wins_over_what_it_is_doing() {
        let mut state = bench();
        state.phase.name = "VERDICT".into();
        state.seats[1].verdict = Some(Verdict::Reject);
        let mode = seat_mode(&state.phase, &state.seats[1], state.seats[1].verdict);
        assert_eq!(mode, SeatMode::Stamping(Verdict::Reject));
        // A quiet council rests whatever the seats were doing last.
        state.phase.name = "IDLE".into();
        assert_eq!(
            seat_mode(&state.phase, &state.seats[0], None),
            SeatMode::Resting
        );
    }

    #[test]
    fn deliberating_cards_only_mark_the_actual_working_seat_as_computing() {
        use ratatui::{buffer::Buffer, layout::Rect};
        let mut state = bench();
        for (seat, activity) in state.seats.iter_mut().zip([
            SeatActivity::Working,
            SeatActivity::Resting,
            SeatActivity::Wiring,
            SeatActivity::Answered,
        ]) {
            seat.activity = activity;
        }
        let area = Rect::new(0, 0, 100, 30);
        let mut buffer = Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        let palette = BenchPalette::from_shell(&cv.palette);
        assert!(draw_council(
            &mut cv,
            (0, 0, 100, 30),
            &state,
            palette,
            4_000,
            true
        ));
        let text = (0..area.height)
            .map(|row| {
                (0..area.width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            text.matches("심의중").count(),
            1,
            "queued seats must not claim to be computing"
        );
        for label in ["대기", "SYNK", "응답완료"] {
            assert!(text.contains(label), "{label} remains visible");
        }
        state.seats[1].activity = SeatActivity::Lost;
        assert_eq!(
            seat_mode(&state.phase, &state.seats[1], None),
            SeatMode::Lost
        );
    }

    fn render_council_text(state: &CouncilState, width: u16, height: u16) -> String {
        use ratatui::{buffer::Buffer, layout::Rect};
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        let mut cv = Cv::new(&mut buffer);
        let palette = BenchPalette::from_shell(&cv.palette);
        assert!(draw_council(
            &mut cv,
            (0, 0, width.into(), height.into()),
            state,
            palette,
            4_000,
            true
        ));
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn three_current_or_historical_seats_never_invent_a_fourth_card() {
        let mut current = bench();
        current.seats.truncate(3);
        let mut historical = current.clone();
        historical.phase.name = "IDLE".into();
        historical.history.last_seats = std::mem::take(&mut historical.seats);
        for state in [current, historical] {
            for (width, height) in [(100, 30), (32, 24), (18, 12)] {
                let text = render_council_text(&state, width, height);
                for name in &COUNCIL_NAMES[..3] {
                    assert!(text.contains(name), "{width}x{height} lost {name}");
                }
                assert!(
                    !text.contains(COUNCIL_NAMES[3]),
                    "{width}x{height} invented a fourth seat"
                );
            }
        }
    }

    #[test]
    fn a_restored_conclusion_without_metadata_never_fabricates_seats() {
        let mut state = bench();
        state.phase.name = "IDLE".into();
        state.phase.note = "Restored saved Council conclusion; seat metadata unavailable".into();
        state.seats.clear();
        state.history.last_seats.clear();
        state.history.last_final = "Saved conclusion".into();
        for (width, height) in [(100, 30), (32, 24), (18, 12)] {
            let text = render_council_text(&state, width, height);
            assert!(
                text.contains("Saved"),
                "{width}x{height} lost the saved conclusion"
            );
            for name in COUNCIL_NAMES {
                assert!(!text.contains(name), "{width}x{height} invented {name}");
            }
            assert!(!text.contains("LEAD"), "a role requires actual metadata");
            assert!(
                !text.contains(" ae "),
                "a provider label requires actual metadata"
            );
        }
    }

    #[test]
    fn a_majority_names_the_winner_and_a_tie_names_the_judge() {
        let palette = BenchPalette::PASTEL;
        let mut state = bench();
        state.phase.name = "VERDICT".into();
        state.seats[0].verdict = Some(Verdict::Approve);
        state.seats[1].verdict = Some(Verdict::Approve);
        state.seats[2].verdict = Some(Verdict::Reject);
        state.seats[3].verdict = Some(Verdict::Reject);
        state.winner_seats = vec!["KARINA".into(), "GISELLE".into()];
        let strip = narration(&state, "▖", palette);
        assert!(
            strip
                .iter()
                .any(|(label, _, body, _)| { label == "동률" && body.contains("nævis") })
        );
        state.seats[3].verdict = Some(Verdict::Approve);
        let strip = narration(&state, "▖", palette);
        let (label, _, body, _) = strip
            .iter()
            .find(|(label, _, _, _)| label == "다수결")
            .expect("a majority line");
        assert_eq!(label, "다수결");
        assert!(body.contains("3/4"), "{body}");
        assert!(
            strip
                .iter()
                .any(|(label, _, body, _)| { label == "승자" && body == "KARINA · GISELLE" })
        );
    }

    #[test]
    fn a_quiet_council_shows_its_last_conclusion() {
        let palette = BenchPalette::PASTEL;
        let mut state = bench();
        state.phase.name = "IDLE".into();
        state.history.last_final = "ship it".into();
        state.history.last_seats = state.seats.clone();
        state.history.last_seats[0].verdict = Some(Verdict::Approve);
        let strip = narration(&state, "▖", palette);
        assert!(
            strip
                .iter()
                .any(|(label, _, body, _)| { label == "최근" && body == "ship it" })
        );
        // The resting card's footer remembers the seat's last verdict.
        let card = seat_card(
            0,
            Some(&state.seats[0]),
            SeatMode::Resting,
            None,
            state.history.last_seats.first(),
            false,
            1.0,
            24,
            12,
            3.0,
            palette,
        );
        let footer_row = &card[card.len() - 2];
        let footer: String = footer_row.iter().map(|run| run.text.clone()).collect();
        assert!(footer.contains("최근"), "{footer}");
    }

    // ── parity with the standalone pane, on states the engine really writes ──

    fn engine_bench(phase: &str) -> CouncilState {
        let mut state = bench();
        state.phase.name = phase.into();
        let models = [
            "claude-haiku-5-5",
            "claude-deepseek-v4-pro",
            "claude-glm-5.3-flash",
            "claude-minimax-m3",
        ];
        let labs = ["ANTHROPIC", "DEEPSEEK", "ZHIPU", "MINIMAX"];
        for (index, seat) in state.seats.iter_mut().enumerate() {
            seat.model = models[index].into();
            seat.lab = labs[index].into();
        }
        state
    }

    /// The record of an earlier council: four verdicts with a confidence each.
    fn last_council(state: &mut CouncilState) {
        let verdicts = [
            Verdict::Approve,
            Verdict::Reject,
            Verdict::Approve,
            Verdict::Hold,
        ];
        let confidences = [70, 75, 80, 85];
        state.history.last_seats = state.seats.clone();
        for (index, seat) in state.history.last_seats.iter_mut().enumerate() {
            seat.activity = SeatActivity::Resting;
            seat.verdict = Some(verdicts[index]);
            seat.confidence = Some(confidences[index]);
        }
        state.history.finished = 3;
        state.history.seen = 3;
        state.history.last_at = Some(-10_000.0);
    }

    #[test]
    fn a_resting_star_field_twinkles_star_by_star() {
        // Each star has its own rate and offset, so the number showing at any
        // moment stays near its average. Sharing one draw between the pick,
        // the rate and the offset made the whole field blink on and off
        // together, and every card looked empty for seconds at a time.
        let counts: Vec<usize> = (0..120)
            .map(|step| {
                stars(71.0, step as f32 * 0.5, 40, 20)
                    .iter()
                    .flat_map(|line| line.chars())
                    .filter(|ch| *ch != ' ')
                    .count()
            })
            .collect();
        let mean = counts.iter().sum::<usize>() as f32 / counts.len() as f32;
        let low = *counts.iter().min().unwrap() as f32;
        let high = *counts.iter().max().unwrap() as f32;
        assert!(mean > 20.0, "expected a field of stars, mean {mean}");
        assert!(low >= mean * 0.6, "the field went dark: {low} of {mean}");
        assert!(high <= mean * 1.4, "the field flared: {high} of {mean}");
    }

    #[test]
    fn a_model_name_too_long_for_the_card_is_cut_with_an_ellipsis() {
        let state = engine_bench("DELIBERATING");
        let text = render_council_text(&state, 46, 33);
        for cut in ["haiku-5…", "deepsee…", "glm-5.3…", "minimax…"] {
            assert!(text.contains(cut), "missing {cut} in\n{text}");
        }
        assert!(
            !text.contains('—'),
            "a dash stands for a seat with no model, not for a long name"
        );
        let mut bare = engine_bench("DELIBERATING");
        bare.seats[0].model.clear();
        assert!(render_council_text(&bare, 46, 33).contains('—'));
    }

    #[test]
    fn seats_that_have_not_answered_never_wear_the_last_councils_votes() {
        let mut state = engine_bench("DELIBERATING");
        last_council(&mut state);
        for (index, verdict) in [(0, Verdict::Approve), (2, Verdict::Hold)] {
            state.seats[index].activity = SeatActivity::Answered;
            state.seats[index].verdict = Some(verdict);
        }
        for index in [1, 3] {
            state.seats[index].activity = SeatActivity::Working;
            state.seats[index].verdict = None;
        }
        let text = render_council_text(&state, 46, 33);
        assert_eq!(text.matches("심의중").count(), 2, "{text}");
        assert!(text.contains(" YES ") && text.contains(" HOLD "), "{text}");
        assert!(
            !text.contains(" NO "),
            "the seat that rejected last time has not voted yet\n{text}"
        );
    }

    #[test]
    fn a_fresh_record_fills_in_a_bare_seat_only_in_the_verdict_phase() {
        let mut state = engine_bench("VERDICT");
        last_council(&mut state);
        state.seats[3].verdict = None;
        state.history.last_at = Some(3.9);
        let bare = state.seats[3].clone();
        assert_eq!(
            resolved_verdict(&state, 3, &bare, 4.0),
            Some(Verdict::Hold),
            "the record this council just wrote"
        );
        state.history.last_at = Some(-100.0);
        assert_eq!(
            resolved_verdict(&state, 3, &bare, 4.0),
            None,
            "an older council"
        );
        state.history.last_at = Some(3.9);
        state.phase.name = "DELIBERATING".into();
        assert_eq!(resolved_verdict(&state, 3, &bare, 4.0), None, "still live");
    }

    #[test]
    fn every_phase_maps_a_seat_to_the_card_the_standalone_pane_draws() {
        let mut state = engine_bench("IDLE");
        let seat = state.seats[1].clone();
        let mode = |phase: &str, seat: &BenchSeat, verdict| {
            seat_mode(
                &Phase {
                    name: phase.into(),
                    note: String::new(),
                },
                seat,
                verdict,
            )
        };
        assert_eq!(
            mode("IDLE", &seat, Some(Verdict::Reject)),
            SeatMode::Resting
        );
        assert_eq!(mode("FAIL", &seat, None), SeatMode::Resting);
        assert_eq!(mode("TRIAGE", &seat, None), SeatMode::Scanning);
        assert_eq!(mode("TRIAGED", &seat, None), SeatMode::Scanning);
        assert_eq!(mode("SYNC", &seat, None), SeatMode::Wiring);
        assert_eq!(
            mode("VOTING", &seat, Some(Verdict::Reject)),
            SeatMode::Stamping(Verdict::Reject)
        );
        assert_eq!(mode("VOTING", &seat, None), SeatMode::Answered);
        // A seat that lost its signal says so, in a failed council too.
        state.seats[1].activity = SeatActivity::Lost;
        assert_eq!(mode("FAIL", &state.seats[1], None), SeatMode::Lost);
        assert_eq!(mode("IDLE", &state.seats[1], None), SeatMode::Resting);
    }

    #[test]
    fn triage_scans_the_bench_and_shows_only_the_triage_line() {
        let mut state = engine_bench("TRIAGED");
        state.phase.note = "QUICK".into();
        last_council(&mut state);
        state.history.last_final = "old news".into();
        state.winner_seats = vec!["KARINA".into()];
        state.seats.clear(); // the engine lists no seats while it triages
        let text = render_council_text(&state, 46, 33);
        assert_eq!(text.matches("선별중").count(), 4, "{text}");
        assert!(text.contains("→ QUICK"), "{text}");
        assert!(
            !text.contains("승자") && !text.contains("old news"),
            "the last council waits until triage is over\n{text}"
        );
    }

    #[test]
    fn an_idle_card_remembers_the_confidence_and_crowns_the_winner() {
        let mut state = engine_bench("IDLE");
        last_council(&mut state);
        state.seats.clear();
        state.winner_seats = vec!["KARINA".into(), "WINTER".into()];
        let text = render_council_text(&state, 46, 33);
        assert_eq!(text.matches("♛ 승인").count(), 2, "{text}");
        assert!(
            text.contains("거부 75") && text.contains("보류 85"),
            "{text}"
        );
        for tag in ["총괄", "반론", "검증", "확장"] {
            assert!(text.contains(tag), "the role {tag} in the bench's language");
        }
        assert!(
            text.contains("KARINA · WINTER → APPROVE"),
            "the winner line names what they carried\n{text}"
        );
    }

    #[test]
    fn the_phase_line_names_the_engines_phase() {
        let mut state = engine_bench("VERDICT");
        for seat in &mut state.seats {
            seat.verdict = Some(Verdict::Approve);
        }
        let text = render_council_text(&state, 46, 33);
        assert!(text.contains("VERDICT"), "{text}");
        assert!(!text.contains("REACHED"), "{text}");
    }

    #[test]
    fn the_wall_clock_origin_gives_local_time_on_any_side_of_midnight() {
        let origin = WallOrigin {
            epoch_at_zero: 0.0,
            utc_offset_secs: 0,
        };
        assert_eq!(origin.hhmm(3_660_000), "01:01");
        let behind = WallOrigin {
            epoch_at_zero: 0.0,
            utc_offset_secs: -3 * 3_600,
        };
        assert_eq!(behind.hhmm(60_000), "21:01", "three hours behind UTC");
        let ahead = WallOrigin {
            epoch_at_zero: 86_400.0 - 60.0,
            utc_offset_secs: 5_400,
        };
        assert_eq!(ahead.hhmm(0), "01:29");
    }

    #[test]
    fn the_header_shows_the_local_time_and_a_subtitle_when_they_fit() {
        let mut state = engine_bench("IDLE");
        // 2026-11-26 14:49 UTC, in a zone three hours behind it; the frame
        // clock reads four seconds.
        let epoch = chrono::NaiveDate::from_ymd_opt(2026, 11, 26)
            .unwrap()
            .and_hms_opt(14, 49, 0)
            .unwrap()
            .and_utc()
            .timestamp() as f64;
        state.clock = Some(WallOrigin {
            epoch_at_zero: epoch - 4.0,
            utc_offset_secs: -3 * 3_600,
        });
        let wide = render_council_text(&state, 46, 33);
        let head = wide.lines().next().unwrap();
        assert!(head.contains("11:49"), "{head}");
        assert!(head.contains("에스파 의사결정 기구"), "{head}");
        let medium = render_council_text(&state, 30, 24);
        let head = medium.lines().next().unwrap();
        assert!(head.contains("KWANGYA") && head.contains("11:49"), "{head}");
        let narrow = render_council_text(&state, 24, 24);
        let head = narrow.lines().next().unwrap();
        assert!(
            head.contains("11:49") && !head.contains("KWANGYA"),
            "{head}"
        );
        // Without a clock to show, the header shows none rather than a wrong one.
        state.clock = None;
        let head = render_council_text(&state, 46, 33)
            .lines()
            .next()
            .unwrap()
            .to_string();
        assert!(!head.contains(':'), "{head}");
    }

    #[test]
    fn under_forty_four_columns_the_fourth_seat_is_a_chip_not_a_second_row() {
        let state = engine_bench("DELIBERATING");
        let three = render_council_text(&state, 42, 33);
        let rows_of_cards = three.lines().filter(|line| line.contains('╭')).count();
        assert_eq!(rows_of_cards, 1, "{three}");
        assert!(three.contains("NINGNING·04"), "{three}");
        assert!(
            three.contains("KARINA") && three.contains("WINTER"),
            "{three}"
        );
        let four = render_council_text(&state, 44, 33);
        assert_eq!(
            four.lines().filter(|line| line.contains('╭')).count(),
            1,
            "{four}"
        );
        assert!(
            four.contains("NINGNING") && !four.contains("NINGNING·04"),
            "four cards fit at 44 columns, so there is no chip\n{four}"
        );
    }

    #[test]
    fn a_failed_council_marks_the_seat_that_lost_its_signal() {
        let mut state = engine_bench("FAIL");
        state.phase.note = "TimeoutError: all seats errored".into();
        state.seats[0].activity = SeatActivity::Lost;
        for seat in &mut state.seats[1..] {
            seat.activity = SeatActivity::Resting;
        }
        let text = render_council_text(&state, 46, 33);
        assert!(
            text.contains("신호없음") && text.contains("ERROR"),
            "{text}"
        );
        assert!(text.contains("고장"), "{text}");
        assert_eq!(
            text.matches("ERROR").count(),
            1,
            "only the lost seat: {text}"
        );
    }

    #[test]
    fn seats_past_the_bench_are_chips_under_the_cards() {
        let mut state = engine_bench("DELIBERATING");
        state.extra_seats = vec![BenchSeat {
            name: "ae·05".into(),
            number: String::new(),
            role: String::new(),
            lab: "MISTRAL".into(),
            model: String::new(),
            activity: SeatActivity::Answered,
            verdict: None,
            confidence: None,
        }];
        let text = render_council_text(&state, 46, 33);
        assert!(text.contains("ae·05 MISTRAL ●"), "{text}");
        // Four cards fit here, so the chip row is only the fifth seat.
        assert!(!text.contains("NINGNING·04"), "{text}");
    }

    #[test]
    fn a_pane_that_lists_the_bench_names_each_seat_once() {
        // Too narrow for cards: one line a seat, and no chip repeating them.
        let state = engine_bench("VERDICT");
        let text = render_council_text(&state, 26, 33);
        assert!(!text.contains('╭'), "no cards at 26 columns\n{text}");
        for name in ["KARINA", "GISELLE", "WINTER", "NINGNING"] {
            assert_eq!(text.matches(name).count(), 1, "{name}\n{text}");
        }
        assert!(!text.contains("ANTHROPIC"), "no chip row\n{text}");
    }

    #[test]
    fn a_council_convened_here_gets_hangul_tags_for_its_roles() {
        let mut state = engine_bench("IDLE");
        for (seat, role) in state
            .seats
            .iter_mut()
            .zip(["LEAD", "SKEPTIC", "BUILDER", "RISK"])
        {
            seat.role = role.into();
        }
        let text = render_council_text(&state, 100, 33);
        for tag in [
            "총괄 · LEAD",
            "반론 · SKEPTIC",
            "구현 · BUILDER",
            "위험 · RISK",
        ] {
            assert!(text.contains(tag), "{tag}\n{text}");
        }
        assert!(!text.contains("SKEPTIC · SKEPTIC"), "{text}");
    }

    #[test]
    fn the_footer_sits_where_the_standalone_pane_puts_it() {
        let state = engine_bench("VERDICT");
        let last_rows = |width: u16, height: u16| -> Vec<String> {
            let text = render_council_text(&state, width, height);
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len() - 3..]
                .iter()
                .map(|l| l.trim().to_string())
                .collect()
        };
        // Wide and tall: rule, phase, then the row the standalone pane gives its keys.
        let wide = last_rows(46, 33);
        assert!(
            wide[0].starts_with('─') && wide[1].starts_with("PHASE") && wide[2].is_empty(),
            "{wide:?}"
        );
        // Narrow: no key row, so the phase is on the very last row.
        let narrow = last_rows(26, 33);
        assert!(
            narrow[1].starts_with('─') && narrow[2].starts_with("PHASE"),
            "{narrow:?}"
        );
        // Short: the same.
        let short = last_rows(46, 18);
        assert!(
            short[1].starts_with('─') && short[2].starts_with("PHASE"),
            "{short:?}"
        );
    }

    #[test]
    fn the_pane_redraws_at_the_standalone_panes_pace() {
        let phase = |name: &str| Phase {
            name: name.into(),
            note: String::new(),
        };
        // Eight a second whenever a council runs, the verdict on screen included.
        for running in [
            "TRIAGE",
            "SYNC",
            "DELIBERATING",
            "VOTING",
            "JUDGING",
            "VERDICT",
        ] {
            assert_eq!(phase(running).beat_ms(0), 125, "{running}");
        }
        // Six for the triage verdict and for a failure.
        assert_eq!(phase("TRIAGED").beat_ms(0), 167);
        assert_eq!(phase("FAIL").beat_ms(0), 167);
        // Two at rest, and one in five seconds after ten quiet minutes.
        assert_eq!(phase("IDLE").beat_ms(0), 500);
        assert_eq!(phase("").beat_ms(BEAT_DEEP_REST_AFTER_MS - 1), 500);
        assert_eq!(phase("IDLE").beat_ms(BEAT_DEEP_REST_AFTER_MS), 5_000);
        // A council that runs again is not rested, however long it rested.
        assert_eq!(phase("SYNC").beat_ms(3_600_000), 125);
        assert!(phase("IDLE").is_idle() && phase("").is_idle());
        assert!(!phase("FAIL").is_idle() && !phase("VERDICT").is_idle());
    }

    #[test]
    fn name_plates_are_accent_blocks_with_dark_ink() {
        use ratatui::{buffer::Buffer, layout::Rect, style::Color};
        let state = engine_bench("DELIBERATING");
        let mut buffer = Buffer::empty(Rect::new(0, 0, 46, 33));
        let mut cv = Cv::new(&mut buffer);
        let palette = BenchPalette::from_shell(&cv.palette);
        assert!(draw_council(
            &mut cv,
            (0, 0, 46, 33),
            &state,
            palette,
            4_000,
            true
        ));
        let (row, column) = (2..6)
            .find_map(|row| {
                (0..46u16)
                    .find(|column| buffer[(*column, row)].symbol() == "K")
                    .map(|column| (row, column))
            })
            .expect("KARINA's plate");
        let cell = &buffer[(column, row)];
        let accent = seat_accent(0, palette);
        assert_eq!(cell.bg, Color::Rgb(accent.0, accent.1, accent.2));
        let ink = palette.on_accent;
        assert_eq!(cell.fg, Color::Rgb(ink.0, ink.1, ink.2));
    }
}

#[cfg(test)]
mod bench_tests {
    use super::*;

    fn council(phase: &str) -> CouncilState {
        CouncilState {
            phase: Phase {
                name: phase.into(),
                note: String::new(),
            },
            seats: ["KARINA", "GISELLE"]
                .iter()
                .enumerate()
                .map(|(index, name)| BenchSeat {
                    name: (*name).into(),
                    number: format!("{:02}", index + 1),
                    role: "LEAD".into(),
                    lab: "ZHIPU".into(),
                    model: "glm-5.3".into(),
                    activity: SeatActivity::Working,
                    verdict: None,
                    confidence: None,
                })
                .collect(),
            extra_seats: Vec::new(),
            winner_seats: Vec::new(),
            history: CouncilHistory::default(),
            clock: None,
        }
    }

    #[test]
    fn the_bench_appears_only_while_a_council_is_live_or_just_finished() {
        assert!(CouncilBench::of(&council("DELIBERATING"), 0.0).is_some());
        assert!(
            CouncilBench::of(&council("VERDICT"), 0.0).is_none(),
            "a verdict with no record is not fresh"
        );
        assert!(CouncilBench::of(&council("IDLE"), 0.0).is_none());
        let mut finished = council("VERDICT");
        finished.history.last_at = Some(100.0);
        assert!(
            CouncilBench::of(&finished, 103.0).is_some(),
            "held after the verdict"
        );
        assert!(
            CouncilBench::of(&finished, 120.0).is_none(),
            "released back to the panel"
        );
    }

    #[test]
    fn the_bench_reports_each_seat_once() {
        let mut state = council("VERDICT");
        state.seats[0].verdict = Some(Verdict::Approve);
        state.seats[1].verdict = Some(Verdict::Reject);
        state.history.last_at = Some(0.0);
        let bench = CouncilBench::of(&state, 0.0).expect("a live bench");
        assert_eq!(
            bench.verdicts,
            vec![Some(Verdict::Approve), Some(Verdict::Reject)]
        );
        assert_eq!(bench.phase, "VERDICT");
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use orbit_frontend_protocol::customization::{CouncilChip, CouncilSeat, CouncilSnapshot};

    fn snapshot() -> CouncilSnapshot {
        CouncilSnapshot {
            phase: "DELIBERATING".into(),
            note: "KARINA is first".into(),
            seats: vec![
                CouncilSeat {
                    name: "KARINA".into(),
                    number: "01".into(),
                    role: "LEAD".into(),
                    lab: "ANTHROPIC".into(),
                    model: "claude-haiku-5-5".into(),
                    activity: "answered".into(),
                    verdict: Some("approve".into()),
                    confidence: None,
                },
                CouncilSeat {
                    name: "GISELLE".into(),
                    number: "02".into(),
                    role: "EDGE".into(),
                    lab: "ZHIPU".into(),
                    model: "glm-5.3-flash".into(),
                    activity: "working".into(),
                    verdict: None,
                    confidence: None,
                },
            ],
            extra_seats: vec![CouncilChip {
                name: "ae·05".into(),
                lab: "ALIBABA".into(),
                activity: "answered".into(),
            }],
            winner_seats: vec!["KARINA".into(), "WINTER".into()],
            last_seats: vec![],
            last_final: "ship it".into(),
            finished: 7,
            seen: 9,
            last_at: Some(100.0),
            published_at: Some(101.0),
            last_tie: false,
        }
    }

    #[test]
    fn a_published_snapshot_becomes_the_state_the_pane_draws() {
        let state = CouncilState::from_snapshot(&snapshot());
        assert_eq!(state.phase.name, "DELIBERATING");
        assert_eq!(state.phase.note, "KARINA is first");
        assert_eq!(state.seats.len(), 2);
        assert_eq!(state.seats[0].activity, SeatActivity::Answered);
        assert_eq!(state.seats[0].verdict, Some(Verdict::Approve));
        assert_eq!(state.seats[1].activity, SeatActivity::Working);
        assert_eq!(state.extra_seats.len(), 1);
        assert_eq!(state.extra_seats[0].name, "ae·05");
        assert_eq!(state.winner_seats, vec!["KARINA", "WINTER"]);
        assert_eq!(state.history.finished, 7);
        assert_eq!(state.history.last_at, Some(100.0));
    }

    #[test]
    fn every_activity_word_maps_and_an_unknown_one_rests() {
        for (word, expected) in [
            ("answered", SeatActivity::Answered),
            ("working", SeatActivity::Working),
            ("wiring", SeatActivity::Wiring),
            ("lost", SeatActivity::Lost),
            ("resting", SeatActivity::Resting),
            ("nonsense", SeatActivity::Resting),
        ] {
            let seat = CouncilSeat {
                activity: word.into(),
                ..snapshot().seats[1].clone()
            };
            assert_eq!(seat_activity(&seat.activity), expected, "{word}");
        }
    }

    #[test]
    fn an_unparseable_verdict_is_no_verdict() {
        let seat = CouncilSeat {
            verdict: Some("MAYBE".into()),
            ..snapshot().seats[0].clone()
        };
        assert_eq!(seat_verdict(seat.verdict.as_deref()), None);
        assert_eq!(seat_verdict(Some("hold")), Some(Verdict::Hold));
    }
}
