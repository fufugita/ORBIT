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
    fn rank(self) -> u8 {
        match self {
            Verdict::Approve => 0,
            Verdict::Reject => 1,
            Verdict::Hold => 2,
        }
    }
}

/// The council's phase, in the engine's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase {
    /// The engine's phase word (`DELIBERATING`, `VERDICT`, …).
    pub name: String,
    /// The engine's free-text note for this phase.
    pub note: String,
}

impl Phase {
    pub fn is_quiet(&self) -> bool {
        matches!(self.name.as_str(), "IDLE" | "TRIAGE" | "TRIAGED" | "FAIL") || self.name.is_empty()
    }
    fn hangul(&self) -> &str {
        phase_hangul(&self.name)
    }
    fn english(&self) -> Option<&str> {
        match self.name.as_str() {
            "SYNC" => Some("SYNK"),
            "DELIBERATING" => Some("DELIBERATE"),
            "JUDGING" => Some("JUDGE"),
            "VERDICT" => Some("REACHED"),
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
    Stamping(Verdict),
    Computing,
    Wiring,
    Answered,
    Lost,
}

fn seat_mode(phase: &Phase, seat: &BenchSeat, verdict: Option<Verdict>) -> SeatMode {
    if phase.is_quiet() || seat.name.is_empty() {
        return SeatMode::Resting;
    }
    if seat.activity == SeatActivity::Lost {
        return SeatMode::Lost;
    }
    if phase.name == "SYNC" {
        return SeatMode::Wiring;
    }
    if let Some(verdict) = verdict {
        return SeatMode::Stamping(verdict);
    }
    if phase.name == "DELIBERATING" {
        return match seat.activity {
            SeatActivity::Answered => SeatMode::Answered,
            _ => SeatMode::Computing,
        };
    }
    SeatMode::Answered
}

/// Draw the council pane into `(x, y, w, h)`. `text` is the pane's
/// one-line snapshot, used when the panel is too small for cards.
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
    let spin = SPIN[(t * 6.0) as usize % SPIN.len()];
    let mut row = y;

    // Header: a mark, the name in shifting warm/cool, and a time.
    cv.text(x, row, " ▲ ", palette.cool, None);
    let mut at = x + 3;
    for (i, ch) in "MAGI".chars().enumerate() {
        let phase = 0.5 + 0.5 * ((i as f32 * 0.9) - t * 1.5).sin();
        let letter = format!("{ch} ");
        at = cv.text(
            at,
            row,
            &letter,
            mix(palette.warm, palette.cool, phase),
            None,
        );
    }
    at = cv.text(at, row, "◢", palette.warm, None);
    let clock = clock_text(now_ms);
    let clock_at = x + width - text_width(&clock) - 1;
    if clock_at > at + 1 {
        cv.text(clock_at, row, &clock, palette.dim, None);
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
    // The bench fits one row when the pane is wide, two by two when it is
    // narrow, and draws as a list only when even a pair cannot fit.
    let (columns, rows_of_cards) = if width >= 38 {
        (if (width - 4) / 4 >= 10 { 4 } else { 3 }, 1)
    } else if (width - 2) / 2 >= 13 && h >= 13 {
        (2, 2)
    } else {
        (0, 1)
    };
    let extra: Vec<&BenchSeat> = state.seats.iter().skip(columns.max(4)).collect();
    let keys_row = h >= 20 && width >= 40;
    let fixed = 2 + usize::from(!extra.is_empty()) + 2 + usize::from(keys_row);
    let body_rows = h as usize;
    let panel_h = body_rows
        .saturating_sub(fixed + strip_lines.len().max(1))
        .saturating_div(rows_of_cards.max(1));

    if columns > 0 && panel_h >= 6 {
        // The cards fill the width they are given: as wide as four (or two)
        // fit, as tall as the body allows, so the pane adapts to any size.
        let panel_h = (panel_h.min(if rows_of_cards == 2 { 16 } else { 30 })) as i32;
        let columns = columns as i32;
        let card_w = ((width - 1 - (columns - 1)) / columns).clamp(1, 30);
        let used = columns * card_w + (columns - 1);
        let left = ((width - used) / 2).max(1);
        for index in 0..(columns as usize * rows_of_cards).min(4) {
            let seat = state.seats.get(index);
            let verdict = seat.and_then(|seat| resolved_verdict(state, index, seat));
            let mode = seat.map_or(SeatMode::Resting, |seat| {
                seat_mode(&state.phase, seat, verdict)
            });
            let seed = state
                .history
                .last_at
                .map(|at| (at as i64).rem_euclid(1_000) as f32)
                .unwrap_or(0.0)
                + index as f32 * 37.0;
            let cards = seat_card(
                index,
                seat,
                mode,
                verdict,
                state.history.last_seats.get(index),
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
                for (text, colour, bold) in runs {
                    at = if *bold {
                        cv.bold(at, cy + offset as i32, text, *colour, None)
                    } else {
                        cv.text(at, cy + offset as i32, text, *colour, None)
                    };
                }
            }
        }
        row += panel_h * rows_of_cards as i32;
    } else {
        // A narrow pane lists the bench instead.
        for index in 0..4 {
            let seat = state.seats.get(index);
            let verdict = seat.and_then(|seat| resolved_verdict(state, index, seat));
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

    // Seats past the bench, as one chip each.
    if !extra.is_empty() {
        let mut at = x + 1;
        for (offset, seat) in extra.iter().enumerate() {
            let index = columns.max(4) + offset;
            let (dot, colour) = match seat.activity {
                SeatActivity::Answered | SeatActivity::Working => ("●", OK),
                SeatActivity::Lost => ("×", NO),
                _ => ("○", palette.mute()),
            };
            let name = format!("{}·{:02} ", seat.name, index + 1);
            at = cv.text(at, row, &name, palette.mute(), None);
            at = cv.text(at, row, &format!("{} ", seat.lab), palette.body, None);
            at = cv.text(at, row, &format!(" {dot}  ",), colour, None);
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

    // Footer: a rule, the phase, the record.
    let tail = 3.min(h - 1);
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
        let _ = at;
        if state.history.seen > 0 {
            let mut record = format!("기록 {}/{}", state.history.finished, state.history.seen);
            if let Some(at) = state.history.last_at {
                let age = (now_ms as f64 / 1_000.0 - at).max(0.0);
                record.push_str(&format!(" · {}", age_text(age)));
            }
            let record_at = x + width - text_width(&record) - 1;
            if record_at > row_at_after_state(width, x, palette) {
                cv.text(record_at, row, &record, palette.dim, None);
            }
        }
    }
    true
}

/// A crude lower bound on where the phase words ended, so the record does
/// not overprint them.
fn row_at_after_state(width: i32, x: i32, _palette: BenchPalette) -> i32 {
    // Conservative: reserve a third of the width for the phase.
    x + (width / 3).max(20)
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

/// The verdict drawn for a seat: what the live state says, else what the
/// record says it landed.
fn resolved_verdict(state: &CouncilState, index: usize, seat: &BenchSeat) -> Option<Verdict> {
    seat.verdict.or_else(|| {
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
    if state.phase.is_quiet() {
        // The winner STAYS after the council ends: the record of who won the
        // choice outlives the VERDICT phase, until the next council replaces it.
        if !state.winner_seats.is_empty() {
            let colour = state
                .history
                .last_seats
                .iter()
                .find_map(|seat| seat.verdict.map(|v| palette.verdict_colour(v)))
                .unwrap_or(OK);
            strip.push((
                "승자".into(),
                colour,
                state.winner_seats.join(" · "),
                colour,
            ));
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

/// One seat card: name plate, lab, model, a body that shows what the seat is
/// doing, and the footer (its verdict, or what it is waiting on).
#[allow(clippy::too_many_arguments)]
fn seat_card(
    index: usize,
    seat: Option<&BenchSeat>,
    mode: SeatMode,
    _verdict: Option<Verdict>,
    last: Option<&BenchSeat>,
    t: f32,
    w: i32,
    h: i32,
    seed: f32,
    palette: BenchPalette,
) -> Vec<Vec<(String, Rgb, bool)>> {
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
    // Name plate, in the accent block; shorter forms when the card is thin.
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
        let chip_colour = if live {
            accent
        } else {
            palette.soft_accent(accent)
        };
        if rest >= 2 && tag.starts_with(' ') && tag.contains('·') {
            top = Some(vec![
                ("╭─".to_string(), edge, false),
                (tag, chip_colour, false),
                (
                    format!("{}╮", "─".repeat((rest - 1).max(0) as usize)),
                    edge,
                    false,
                ),
            ]);
        } else if rest >= 0 {
            let left = rest / 2;
            top = Some(vec![
                (format!("╭{}", "─".repeat(left as usize)), edge, false),
                (tag, chip_colour, false),
                (
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
    // The chip's text is laid over the accent, so it does not use `edge`.
    rows.push(top.unwrap_or_else(|| {
        vec![(
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
        ("│".into(), edge, false),
        (
            fit_centre(&lab, inner),
            if live { palette.body } else { palette.mute() },
            live,
        ),
        ("│".into(), edge, false),
    ]);
    if h >= 11 {
        let model = seat
            .map(|seat| seat.model.clone())
            .filter(|model| !model.is_empty())
            .or_else(|| last.map(|last| last.model.clone()))
            .unwrap_or_default();
        let (line, colour) = if live {
            (
                first_fit(&[short_model(&model), "—".into()], inner),
                palette.mute(),
            )
        } else {
            let role = seat
                .map(|seat| seat.role.clone())
                .filter(|role| !role.is_empty())
                .unwrap_or_else(|| "LEAD".into());
            (
                first_fit(&[format!("{role} · {}", index + 1), role], inner),
                palette.half_accent(accent),
            )
        };
        rows.push(vec![
            ("│".into(), edge, false),
            (fit_centre(&line, inner), colour, false),
            ("│".into(), edge, false),
        ]);
    }
    rows.push(vec![(
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
            let foot = match last.and_then(|last| last.verdict) {
                Some(verdict) => {
                    let confidence = last
                        .and_then(|last| last.confidence)
                        .map(|confidence| format!(" {confidence}"))
                        .unwrap_or_default();
                    first_fit(
                        &[
                            format!("최근 {}{confidence}", verdict.hangul()),
                            verdict.hangul().to_string(),
                        ],
                        inner,
                    )
                }
                None => "대기".to_string(),
            };
            let foot_colour = match last.and_then(|last| last.verdict) {
                Some(verdict) => palette.half_accent(palette.verdict_colour(verdict)),
                None => palette.mute(),
            };
            (
                stars(seed, t, inner, body_rows),
                palette.dim,
                false,
                foot,
                foot_colour,
                false,
            )
        }
    };
    for line in body {
        rows.push(vec![
            ("│".into(), edge, false),
            (line, body_colour, bold),
            ("│".into(), edge, false),
        ]);
    }
    rows.push(vec![(
        format!("├{}┤", "─".repeat(inner.max(0) as usize)),
        edge,
        false,
    )]);
    rows.push(vec![
        ("│".into(), edge, false),
        (fit_centre(&foot, inner), foot_colour, foot_bold),
        ("│".into(), edge, false),
    ]);
    rows.push(vec![(
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

fn clock_text(now_ms: u64) -> String {
    // Local time from the epoch milliseconds the caller lends; no clock read
    // here, so a test renders the same frame twice.
    let seconds = now_ms / 1_000;
    let day = (seconds / 86_400) % 86_400;
    // UTC, marked, rather than pretending to know the zone offset.
    format!("{:02}:{:02}Z", (day / 3_600) % 24, (day % 3_600) / 60)
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
            let noise = noise(r as u32, c as u32, seed as u32);
            if noise >= 0.07 {
                line.push(' ');
                continue;
            }
            let phase = (t * (0.5 + noise * 2.0) + noise * std::f32::consts::TAU).sin();
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

/// A verdict drawn large. Each verdict has a small bitmap; the bitmap is
/// scaled to the card with quadrant blocks (two by two sub-cells per cell),
/// so the same three words read at any panel size without a font.
fn seal(word: &str, w: i32, rows: i32) -> Vec<String> {
    let Some(bitmap) = seal_bitmap(word) else {
        return centred_text(&[word.to_string()], w, rows);
    };
    // Below this the half-block art is mush; the word itself reads better.
    if w < 11 || rows < 3 {
        return centred_text(&[word.to_string()], w, rows);
    }
    // One bitmap pixel per cell across, two per cell down, drawn with half
    // blocks. The bitmap already sits in that aspect, so the art keeps its
    // shape without resampling.
    let bw = bitmap[0].chars().count() as i32;
    let bh = bitmap.len() as i32;
    let art_h = ((bh + 1) / 2).min(rows.max(1));
    // Two cells per pixel keeps the words large; when the card is narrower
    // than the bitmap, sample it down instead of cutting its right side.
    let scale = if w >= bw * 2 { 2 } else { 1 };
    let art_w = w.min(bw * scale);
    let step = bw as f32 / (art_w / scale).max(1) as f32;
    let ink = |sx: i32, sy: i32| -> bool {
        bitmap
            .get(sy as usize)
            .and_then(|row| row.chars().nth(sx as usize))
            .is_some_and(|ch| ch == '#')
    };
    let mut art = Vec::new();
    for cy in 0..art_h {
        let mut line = String::new();
        for cx in 0..art_w {
            let sx = ((cx / scale) as f32 * step) as i32;
            let top = ink(sx.min(bw - 1), cy * 2);
            let bottom = ink(sx.min(bw - 1), cy * 2 + 1);
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        art.push(line);
    }
    // Centre the art in the card's body.
    let pad_x = ((w - art_w) / 2).max(0) as usize;
    let pad_y = ((rows - art_h) / 2).max(0);
    let mut out = Vec::new();
    for _ in 0..pad_y {
        out.push(" ".repeat(w.max(0) as usize));
    }
    for line in art {
        let mut row = " ".repeat(pad_x);
        row.push_str(&line);
        out.push(fit(&row, w, Align::Left));
    }
    while out.len() < rows.max(0) as usize {
        out.push(" ".repeat(w.max(0) as usize));
    }
    out.truncate(rows.max(0) as usize);
    out
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

/// Bitmaps for the three verdicts, 24 by 12 cells, drawn from a glyph grid
/// at one resolution. `#` is ink, `.` is paper. Kept in the source so the
/// seal needs neither a font nor a dependency.
fn seal_bitmap(word: &str) -> Option<&'static [&'static str]> {
    match word {
        "승인" => Some(&SEAL_APPROVE),
        "거부" => Some(&SEAL_REJECT),
        "보류" => Some(&SEAL_HOLD),
        _ => None,
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

    #[test]
    fn the_seal_draws_quadrant_blocks_in_the_requested_box() {
        for word in ["승인", "거부", "보류"] {
            let art = seal(word, 16, 6);
            assert_eq!(art.len(), 6, "{word}");
            assert!(art.iter().all(|line| text_width(line) == 16), "{word}");
            assert!(
                art.iter().any(|line| line.chars().any(|ch| ch != ' ')),
                "{word} drew nothing"
            );
            assert!(
                art.iter()
                    .all(|line| line.chars().all(|ch| " ▀▄█".contains(ch))),
                "{word} drew outside the half-block set"
            );
        }
        // An unknown word falls back to plain text rather than nothing.
        let art = seal("???", 10, 3);
        assert_eq!(art.len(), 3);
        assert!(art.iter().any(|line| line.contains('?')));
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
            1.0,
            24,
            12,
            3.0,
            palette,
        );
        let footer_row = &card[card.len() - 2];
        let footer: String = footer_row.iter().map(|(text, _, _)| text.clone()).collect();
        assert!(footer.contains("최근"), "{footer}");
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
