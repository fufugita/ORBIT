//! Checked frontend presentation and explicit actions for portable profiles.
use crate::proto::{
    layout::{Node, View},
    shell::{
        canvas::{Cv, Rgb, clip_text, wrap_ranges},
        frame::{FocusFx, FrameSpec, panel_frame},
        hits::Click,
    },
};
use orbit_frontend_protocol::customization::{
    BUILTIN_PANE_IDS, CustomizationError, LayoutNode, MAX_PANE_LINES, MAX_PANE_OUTPUT_BYTES,
    PaneAction, PaneContext, PaneOutput, PaneState, Profile, ProfileHost, ReactorArt,
    ResolvedProfile, Surface,
};
use ratatui::layout::Rect;
use std::{collections::BTreeMap, sync::Arc};

pub struct CustomizationSession {
    pub host: Arc<dyn ProfileHost>,
    pub resolved: ResolvedProfile,
    pub outputs: BTreeMap<String, PaneOutput>,
    pub context: PaneContext,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionEffect {
    Refreshed,
    FocusConversation,
    InsertDraft(String),
    OwnerCancel,
    CycleReactorArt,
}

impl CustomizationSession {
    pub fn invalidate_session(&mut self, context: PaneContext) {
        self.context = context;
        for pane in self.outputs.values_mut() {
            pane.state = PaneState::Stale;
            pane.text = "Session changed; refresh this pane".into();
            pane.council = None;
        }
    }
    pub fn open(host: Arc<dyn ProfileHost>) -> Result<Self, CustomizationError> {
        let resolved = host.load()?;
        resolved.profile.validate()?;
        Ok(Self {
            host,
            resolved,
            outputs: BTreeMap::new(),
            context: PaneContext::default(),
        })
    }
    pub fn accept(&mut self, resolved: ResolvedProfile) -> Result<(), CustomizationError> {
        resolved.profile.validate()?;
        if resolved.revision.len() > 256 {
            return Err(CustomizationError::Invalid(
                "profile revision exceeds bounds".into(),
            ));
        }
        self.resolved = resolved;
        self.outputs
            .retain(|id, _| self.resolved.profile.pane_def(id).is_some());
        Ok(())
    }
    pub fn refresh(&mut self, id: &str) -> Result<(), CustomizationError> {
        let def = self
            .resolved
            .profile
            .pane_def(id)
            .ok_or_else(|| CustomizationError::Invalid("unknown pane".into()))?;
        if !def.surfaces.contains(&Surface::Terminal) {
            self.outputs.insert(
                id.into(),
                PaneOutput {
                    id: id.into(),
                    title: def.title.clone(),
                    state: PaneState::Error,
                    text: "This pane does not support the terminal surface".into(),
                    truncated: false,
                    council: None,
                    actions: Vec::new(),
                },
            );
            return Err(CustomizationError::Invalid(
                "pane does not support terminal".into(),
            ));
        }
        let result = self
            .host
            .read_pane(id, &self.context)
            .and_then(|mut output| {
                if output.id != id
                    || output.text.len() > MAX_PANE_OUTPUT_BYTES
                    || output.text.lines().count() > MAX_PANE_LINES
                    || output.actions.iter().any(|a| !def.actions.contains(a))
                {
                    return Err(CustomizationError::Invalid(
                        "pane output does not match declared bounds/actions".into(),
                    ));
                }
                output.title = def.title.clone();
                output.text = safe_pane_text(&output.text)?;
                output.council = output.council.map(|snapshot| {
                    snapshot.sanitized_with(|text| {
                        crate::bridge::terminal_safe(&crate::bridge::safe_text(
                            &crate::bridge::strip_cot(text),
                        ))
                    })
                });
                if output.text.is_empty() && output.state == PaneState::Ready {
                    output.state = PaneState::Empty;
                }
                Ok(output)
            });
        match result {
            Ok(output) => {
                self.outputs.insert(id.into(), output);
                Ok(())
            }
            Err(error) => {
                self.outputs.insert(
                    id.into(),
                    PaneOutput {
                        id: id.into(),
                        title: def.title.clone(),
                        state: PaneState::Error,
                        text: crate::bridge::terminal_safe(&crate::bridge::safe_text(
                            &error.to_string(),
                        )),
                        truncated: false,
                        council: None,
                        actions: vec![PaneAction::Refresh],
                    },
                );
                Err(error)
            }
        }
    }
    /// Built-in panes (council, reactor) the layout currently shows and the
    /// profile does not redefine. Only these are read without being asked.
    /// Whether `id` is a built-in pane the profile has not replaced with a
    /// pane of its own under the same name.
    pub fn is_builtin_pane(&self, id: &str) -> bool {
        BUILTIN_PANE_IDS.contains(&id) && !self.resolved.profile.panes.iter().any(|p| p.id == id)
    }
    pub fn builtin_ids_in_layout(&self) -> Vec<String> {
        fn walk(node: &LayoutNode, out: &mut Vec<String>) {
            match node {
                LayoutNode::Custom { pane_id } => {
                    if BUILTIN_PANE_IDS.contains(&pane_id.as_str()) && !out.contains(pane_id) {
                        out.push(pane_id.clone());
                    }
                }
                LayoutNode::Split { children, .. } => {
                    for child in children {
                        walk(child, out);
                    }
                }
                LayoutNode::Panel { .. } => {}
            }
        }
        let mut out = Vec::new();
        walk(&self.resolved.profile.layout.tree, &mut out);
        out.retain(|id| !self.resolved.profile.panes.iter().any(|p| p.id == *id));
        out
    }
    pub fn refresh_all(&mut self) {
        let mut ids: Vec<_> = self
            .resolved
            .profile
            .panes
            .iter()
            .map(|p| p.id.clone())
            .collect();
        ids.extend(self.builtin_ids_in_layout());
        for id in ids {
            let _ = self.refresh(&id);
        }
    }
    pub fn action(&mut self, id: &str, index: usize) -> Result<ActionEffect, CustomizationError> {
        let def = self
            .resolved
            .profile
            .pane_def(id)
            .ok_or_else(|| CustomizationError::Invalid("unknown pane".into()))?;
        let action = self
            .outputs
            .get(id)
            .and_then(|output| output.actions.get(index))
            .cloned()
            .ok_or_else(|| {
                CustomizationError::Invalid("pane action unavailable until refresh".into())
            })?;
        if !def.actions.contains(&action) {
            return Err(CustomizationError::Invalid(
                "pane action is undeclared".into(),
            ));
        }
        if !def.surfaces.contains(&Surface::Terminal) {
            return Err(CustomizationError::Invalid(
                "pane does not support terminal".into(),
            ));
        }
        match action {
            PaneAction::Refresh => {
                self.refresh(id)?;
                Ok(ActionEffect::Refreshed)
            }
            PaneAction::FocusConversation => Ok(ActionEffect::FocusConversation),
            PaneAction::InsertPrompt { text } => Ok(ActionEffect::InsertDraft(
                crate::bridge::terminal_safe(&crate::bridge::safe_text(&text)),
            )),
            PaneAction::OwnerCancel if self.context.controller => Ok(ActionEffect::OwnerCancel),
            PaneAction::OwnerCancel => Err(CustomizationError::Invalid(
                "owner cancellation requires controller authority".into(),
            )),
            PaneAction::CycleReactorArt if self.context.controller => {
                Ok(ActionEffect::CycleReactorArt)
            }
            PaneAction::CycleReactorArt => Err(CustomizationError::Invalid(
                "art changes require controller authority".into(),
            )),
        }
    }
    pub fn persist_tree(&mut self, tree: &Node) -> Result<(), CustomizationError> {
        let mut profile = self.resolved.profile.clone();
        profile.layout.tree = serde_json::from_value(
            serde_json::to_value(tree)
                .map_err(|_| CustomizationError::Invalid("layout cannot be encoded".into()))?,
        )
        .map_err(|_| CustomizationError::Invalid("layout contains an unsupported view".into()))?;
        profile.layout.preset = "custom".into();
        profile.validate()?;
        let next = self.host.replace(profile, &self.resolved.revision)?;
        self.accept(next)
    }
}

pub fn profile_tree(profile: &Profile) -> Result<Node, CustomizationError> {
    profile.validate()?;
    serde_json::from_value(
        serde_json::to_value(&profile.layout.tree)
            .map_err(|_| CustomizationError::Invalid("layout cannot be encoded".into()))?,
    )
    .map_err(|_| CustomizationError::Invalid("layout cannot be displayed".into()))
}

pub fn pane_title<'a>(
    tree: &Node,
    index: usize,
    outputs: &'a BTreeMap<String, PaneOutput>,
) -> Option<&'a str> {
    let id = tree.custom_id_at(index)?;
    outputs.get(&id).map(|p| p.title.as_str())
}

fn safe_pane_text(text: &str) -> Result<String, CustomizationError> {
    if text.len() > MAX_PANE_OUTPUT_BYTES || text.lines().count() > MAX_PANE_LINES {
        return Err(CustomizationError::Invalid(
            "pane output exceeds display bounds".into(),
        ));
    }
    // Keep refusals on the original input, even when a forbidden marker is
    // hidden inside an escape sequence. Parse escapes before display_safe
    // removes ESC, then gate the visible result as well.
    let text = if !crate::bridge::safe_text_probe(text) {
        crate::bridge::safe_text(text)
    } else {
        crate::bridge::safe_text(&crate::bridge::terminal_safe_multiline(text))
    };
    if text.len() > MAX_PANE_OUTPUT_BYTES || text.lines().count() > MAX_PANE_LINES {
        return Err(CustomizationError::Invalid(
            "pane output exceeds display bounds".into(),
        ));
    }
    Ok(text)
}

/// A council seat's identity colour, as in the MAGI pane, from its name tag
/// (`KARINA·01`, or `KARINA-01` in ASCII).
fn seat_colour(tag: &str, palette: &crate::proto::shell::pal::Palette) -> Option<Rgb> {
    ["KARINA", "GISELLE", "WINTER", "NINGNING", "AE"]
        .iter()
        .zip([
            palette.cyan,
            palette.magenta,
            palette.violet,
            palette.amber,
            palette.blue,
        ])
        .find(|(name, _)| {
            tag.strip_prefix(**name)
                .is_some_and(|tail| tail.starts_with(['·', '-']))
        })
        .map(|(_, colour)| colour)
}

/// The frame clock a caller can lend a pane: built-in panes animate with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneClock {
    pub now_ms: u64,
    pub reduced: bool,
    pub reactor_art: ReactorArt,
}

/// One parsed seat row of the council text.
struct CouncilSeat<'a> {
    tag: &'a str,
    lab: &'a str,
    model: &'a str,
    label: &'a str,
}

fn council_seat(line: &str) -> Option<CouncilSeat<'_>> {
    let mark = line.rfind("● ").or_else(|| line.rfind("◌ "))?;
    let label = line[mark..].split_once(' ')?.1.trim();
    let mut words = line[..mark].split_whitespace();
    let tag = words.next()?;
    let mut rest: Vec<&str> = words.collect();
    if rest
        .first()
        .is_some_and(|word| matches!(*word, "LEAD" | "EDGE" | "EXACT" | "BOLD"))
    {
        rest.remove(0);
    }
    Some(CouncilSeat {
        tag,
        lab: rest.first().copied().unwrap_or(""),
        model: rest.get(1).copied().unwrap_or(""),
        label,
    })
}

/// A cheap, stable pseudo-random value in 0..1 for the resting star field.
fn star_noise(a: u32, b: u32, c: u32) -> f32 {
    let mut x = a
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(b.wrapping_mul(0x85EB_CA6B))
        .wrapping_add(c.wrapping_mul(0xC2B2_AE35));
    x ^= x >> 15;
    x = x.wrapping_mul(0x2C1B_3C6D);
    x ^= x >> 12;
    (x % 10_000) as f32 / 10_000.0
}

/// The council as seat cards, like the MAGI pane: a name plate, the lab and
/// model, a body that shows what the seat is doing, and its verdict. Returns
/// `false` (draw the text instead) when the text is not the Unicode council
/// layout or the cards do not fit.
fn draw_council_cards(
    cv: &mut Cv,
    (x, y, w, h): (i32, i32, i32, i32),
    text: &str,
    clock: PaneClock,
) -> bool {
    let palette = cv.palette;
    let mut lines = text.lines();
    let Some(header) = lines.next().filter(|line| line.starts_with("MAGI · ")) else {
        return false;
    };
    let mut seats = Vec::new();
    let mut strip = Vec::new();
    for line in lines {
        match council_seat(line).filter(|seat| seat_colour(seat.tag, &palette).is_some()) {
            Some(seat) if strip.is_empty() => seats.push(seat),
            _ if !line.trim().is_empty() => strip.push(line),
            _ => {}
        }
    }
    let count = seats.len() as i32;
    if !(1..=4).contains(&count) || strip.len() > 3 {
        return false;
    }
    let pitch = (w - 1) / count;
    let card_h = h - 1 - strip.len() as i32;
    if pitch < 15 || card_h < 7 {
        return false;
    }
    let (card_w, inner) = (pitch - 1, pitch - 3);
    let body_rows = card_h - 6;
    // Reduced motion keeps one still frame.
    let t = if clock.reduced {
        0.0
    } else {
        (clock.now_ms % 3_600_000) as f32 / 1_000.0
    };
    let mut at = x + 1;
    for (segment, colour) in builtin_segments("council", header, &palette) {
        at = cv.text(at, y, segment, colour, None);
    }
    let centre = |cv: &mut Cv, cx: i32, row: i32, text: &str, colour: Rgb| {
        let text = clip_text(text, inner);
        let pad = (inner - crate::proto::shell::canvas::text_width(&text)).max(0) / 2;
        cv.text(cx + 1 + pad, row, &text, colour, None);
    };
    const EIGHTHS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    for (index, seat) in seats.iter().enumerate() {
        let cx = x + 1 + index as i32 * pitch;
        let top = y + 1;
        let accent = seat_colour(seat.tag, &palette).unwrap_or(palette.cyan);
        let verdict = [
            ("승인", palette.green),
            ("거부", palette.red),
            ("보류", palette.amber),
        ]
        .into_iter()
        .find(|(word, _)| seat.label.starts_with(word));
        let lost = seat.label.starts_with("신호없음");
        let live = verdict.is_some()
            || ["심의중", "SYNK", "응답완료"]
                .iter()
                .any(|word| seat.label.starts_with(word));
        let edge = match verdict {
            Some((_, colour)) => colour,
            None if lost => palette.red,
            None if live => accent,
            None => palette.faint,
        };
        // Frame and name plate.
        let rule = "─".repeat(inner.max(0) as usize);
        cv.text(cx, top, &format!("╭{rule}╮"), edge, None);
        cv.text(cx, top + 3, &format!("├{rule}┤"), edge, None);
        cv.text(cx, top + card_h - 1, &format!("╰{rule}╯"), edge, None);
        for row in (1..card_h - 1).filter(|row| *row != 3) {
            cv.text(cx, top + row, "│", edge, None);
            cv.text(cx + card_w - 1, top + row, "│", edge, None);
        }
        let plate = format!(" {} ", seat.tag);
        if crate::proto::shell::canvas::text_width(&plate) <= inner - 2 {
            cv.text(
                cx + 2,
                top,
                &plate,
                if live || lost { accent } else { palette.muted },
                None,
            );
        }
        centre(
            cv,
            cx,
            top + 1,
            seat.lab,
            if live { palette.ink } else { palette.muted },
        );
        centre(cv, cx, top + 2, seat.model, palette.muted);
        // Body: what the seat is doing.
        let body_top = top + 4;
        let seed = index as f32 * 1.7;
        let (foot, foot_colour) = if let Some((word, colour)) = verdict {
            // The verdict stamp: the Hangul word, spaced out, mid-card.
            let stamp: String = word
                .chars()
                .flat_map(|c| [c, ' '])
                .collect::<String>()
                .trim_end()
                .to_string();
            centre(cv, cx, body_top + body_rows / 2, &stamp, colour);
            (seat.label.split_whitespace().nth(1).unwrap_or(word), colour)
        } else if lost {
            centre(cv, cx, body_top + body_rows / 2, "신호없음", palette.red);
            if body_rows >= 2 {
                centre(
                    cv,
                    cx,
                    body_top + body_rows / 2 + 1,
                    "SIGNAL LOST",
                    palette.red,
                );
            }
            ("ERROR", palette.red)
        } else if seat.label.starts_with("SYNK") {
            // A pulse sweeping a baseline.
            let pos = ((t * 9.0) as i32).rem_euclid(inner + 6) - 3;
            let line: String = (0..inner)
                .map(|c| match (c - pos).abs() {
                    0 => '█',
                    1 => '▓',
                    2 => '▒',
                    _ => '─',
                })
                .collect();
            cv.text(cx + 1, body_top + body_rows / 2, &line, accent, None);
            ("SYNK", accent)
        } else if live {
            // Deliberation: an equaliser, quieter once the seat has answered.
            let amp = if seat.label.starts_with("응답완료") {
                0.25
            } else {
                1.0
            };
            let heights: Vec<i32> = (0..inner)
                .map(|c| {
                    if c % 2 == 1 {
                        return 0;
                    }
                    let c = c as f32;
                    let v = (0.55 + 0.45 * (t * 2.3 + c * 0.9 + seed).sin())
                        * (0.60 + 0.40 * (t * 3.7 + c * 1.7 + seed * 1.9).sin());
                    ((v * amp).max(0.04) * body_rows as f32 * 8.0) as i32
                })
                .collect();
            for row in 0..body_rows {
                let base = (body_rows - 1 - row) * 8;
                let line: String = heights
                    .iter()
                    .map(|height| EIGHTHS[(height - base).clamp(0, 8) as usize])
                    .collect();
                cv.text(cx + 1, body_top + row, &line, accent, None);
            }
            (seat.label, accent)
        } else {
            // At rest: a sparse star field.
            for row in 0..body_rows {
                let line: String = (0..inner)
                    .map(|c| {
                        let (r, c, i) = (row as u32, c as u32, index as u32);
                        if star_noise(r, c, i) >= 0.07 {
                            return ' ';
                        }
                        let phase = (t * (0.5 + star_noise(c, i, r))
                            + star_noise(i, r, c) * std::f32::consts::TAU)
                            .sin();
                        if phase > 0.75 {
                            '+'
                        } else if phase > -0.3 {
                            '·'
                        } else {
                            ' '
                        }
                    })
                    .collect();
                cv.text(cx + 1, body_top + row, &line, palette.faint, None);
            }
            (seat.label, palette.muted)
        };
        centre(cv, cx, top + card_h - 2, foot, foot_colour);
    }
    for (row, line) in strip.iter().enumerate() {
        let mut at = x + 1;
        let line = clip_text(line, (w - 2).max(1));
        for (segment, colour) in builtin_segments("council", &line, &palette) {
            at = cv.text(at, y + 1 + card_h + row as i32, segment, colour, None);
        }
    }
    true
}

/// A dot canvas, two by four dots per cell, drawn as braille. Each cell
/// keeps the colour of its brightest dot.
struct DotBuf {
    cols: i32,
    rows: i32,
    on: Vec<bool>,
    colour: Vec<Rgb>,
    bright: Vec<f32>,
}

impl DotBuf {
    fn new(cols: i32, rows: i32) -> Self {
        let (cols, rows) = (cols.max(0), rows.max(0));
        Self {
            cols,
            rows,
            on: vec![false; (cols * 2 * rows * 4) as usize],
            colour: vec![(0, 0, 0); (cols * rows) as usize],
            bright: vec![0.0; (cols * rows) as usize],
        }
    }
    fn width(&self) -> i32 {
        self.cols * 2
    }
    fn height(&self) -> i32 {
        self.rows * 4
    }
    fn dot(&mut self, x: f32, y: f32, colour: Rgb, bright: f32) {
        if !x.is_finite() || !y.is_finite() {
            return;
        }
        let (xi, yi) = (x as i32, y as i32);
        if xi < 0 || yi < 0 || xi >= self.width() || yi >= self.height() {
            return;
        }
        let index = (yi * self.width() + xi) as usize;
        self.on[index] = true;
        let cell = ((yi >> 2) * self.cols + (xi >> 1)) as usize;
        if bright >= self.bright[cell] {
            self.bright[cell] = bright;
            self.colour[cell] = colour;
        }
    }
    /// A line whose brightness runs from `b0` to `b1`; `dash` skips every
    /// other run of that many dots.
    #[allow(clippy::too_many_arguments)]
    fn line(
        &mut self,
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        colour: Rgb,
        b0: f32,
        b1: f32,
        dash: i32,
    ) {
        let (dx, dy) = (x1 - x0, y1 - y0);
        let steps = dx.abs().max(dy.abs());
        if !steps.is_finite() || steps > 3_000.0 {
            return;
        }
        let n = steps as i32 + 1;
        for i in 0..=n {
            if dash > 0 && (i / dash) & 1 == 1 {
                continue;
            }
            let t = i as f32 / n as f32;
            self.dot(x0 + dx * t, y0 + dy * t, colour, b0 + (b1 - b0) * t);
        }
    }
    fn blit(&self, cv: &mut Cv, x: i32, y: i32) {
        let w = self.width();
        let lit = |dx: i32, dy: i32| self.on[(dy * w + dx) as usize];
        for cy in 0..self.rows {
            // Cells of one colour in a row go out as one run.
            let mut run = String::new();
            let mut run_at = 0;
            let mut run_colour = (0, 0, 0);
            for cx in 0..self.cols {
                let (px, py) = (cx * 2, cy * 4);
                let bits = [
                    lit(px, py),
                    lit(px, py + 1),
                    lit(px, py + 2),
                    lit(px + 1, py),
                    lit(px + 1, py + 1),
                    lit(px + 1, py + 2),
                    lit(px, py + 3),
                    lit(px + 1, py + 3),
                ]
                .iter()
                .enumerate()
                .fold(0u32, |bits, (bit, on)| bits | (u32::from(*on) << bit));
                let cell = (cy * self.cols + cx) as usize;
                let k = 0.38 + 0.62 * self.bright[cell].min(1.0);
                let (r, g, b) = self.colour[cell];
                let colour = (
                    (f32::from(r) * k) as u8,
                    (f32::from(g) * k) as u8,
                    (f32::from(b) * k) as u8,
                );
                if bits == 0 || (!run.is_empty() && colour != run_colour) {
                    if !run.is_empty() {
                        cv.text(x + run_at, y + cy, &run, run_colour, None);
                        run.clear();
                    }
                    if bits == 0 {
                        continue;
                    }
                }
                if run.is_empty() {
                    run_at = cx;
                    run_colour = colour;
                }
                run.push(char::from_u32(0x2800 + bits).unwrap_or(' '));
            }
            if !run.is_empty() {
                cv.text(x + run_at, y + cy, &run, run_colour, None);
            }
        }
    }
}

fn mix(a: Rgb, b: Rgb, p: f32) -> Rgb {
    let lerp =
        |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * p.clamp(0.0, 1.0)) as u8;
    (lerp(a.0, b.0), lerp(a.1, b.1), lerp(a.2, b.2))
}

/// The 8x8 ordered-dither thresholds the Reactor scene uses for glow and haze.
fn bayer8() -> [[f32; 8]; 8] {
    let mut m = [[0u32; 8]; 8];
    let mut k = 1;
    while k < 8 {
        let mut next = [[0u32; 8]; 8];
        for y in 0..k {
            for x in 0..k {
                let v = m[y][x] * 4;
                next[y][x] = v;
                next[y][x + k] = v + 2;
                next[y + k][x] = v + 3;
                next[y + k][x + k] = v + 1;
            }
        }
        m = next;
        k *= 2;
    }
    let mut out = [[0.0; 8]; 8];
    for y in 0..8 {
        for x in 0..8 {
            out[y][x] = (m[y][x] as f32 + 0.5) / 64.0;
        }
    }
    out
}

/// The Kwangya scene from the Reactor: stars, a wireframe glacier with a
/// scan line, a glowing horizon and a perspective grid sea with a pulse ring.
/// It is a pure function of time; `energy` (0..1) sets the pace.
fn kwangya_scene(buf: &mut DotBuf, t: f32, energy: f32, ice: Rgb, white: Rgb) {
    const PEAKS: [(f32, f32); 16] = [
        (0.0, 0.05),
        (0.05, 0.2),
        (0.1, 0.1),
        (0.17, 0.38),
        (0.23, 0.22),
        (0.3, 0.5),
        (0.36, 0.3),
        (0.43, 0.68),
        (0.5, 0.42),
        (0.56, 0.6),
        (0.62, 0.32),
        (0.7, 0.5),
        (0.77, 0.2),
        (0.84, 0.36),
        (0.91, 0.14),
        (1.0, 0.06),
    ];
    let (w, h) = (buf.width(), buf.height());
    if w < 6 || h < 6 {
        return;
    }
    let (wf, hf) = (w as f32, h as f32);
    let hy = (hf * 0.44) as i32;
    let hyf = hy as f32;
    let cx = wf / 2.0;
    let depth = (h - 1 - hy) as f32;
    let bayer = bayer8();
    // Stars.
    for star in 0..36u32 {
        let (u, v) = (star_noise(star, 1, 7), star_noise(star, 2, 7).powf(1.4));
        let twinkle =
            (t * (0.6 + star_noise(star, 4, 7) * 2.2) + star_noise(star, 3, 7) * 6.3).sin();
        if twinkle > 0.15 {
            buf.dot(u * wf, v * hyf * 0.5, white, 0.25 + 0.6 * twinkle);
        }
    }
    // The glacier, lit where the scan line passes.
    let glacier = hyf * 0.6;
    let scan = hyf - (t * (0.06 + 0.1 * energy)).fract() * hyf * 1.3;
    let points: Vec<(f32, f32)> = PEAKS
        .iter()
        .map(|(u, height)| (u * (wf - 1.0), hyf - height * glacier))
        .collect();
    for pair in points.windows(2) {
        let ((x0, y0), (x1, y1)) = (pair[0], pair[1]);
        let lit = (1.0 - ((y0 + y1) / 2.0 - scan).abs() / 5.0).max(0.0);
        let bright = 0.6 + 0.4 * lit;
        buf.line(x0, y0, x1, y1, mix(ice, white, lit), bright, bright, 0);
    }
    for i in 1..points.len() - 1 {
        if PEAKS[i].1 > 0.28 {
            let (x, y) = points[i];
            buf.line(x, y, (points[i - 1].0 + x) / 2.0, hyf, ice, 0.3, 0.3, 2);
            buf.line(x, y, (points[i + 1].0 + x) / 2.0, hyf, ice, 0.3, 0.3, 2);
        }
    }
    if (0.0..hyf).contains(&scan) {
        for x in (0..w).step_by(2) {
            buf.dot(x as f32, scan, ice, 0.4);
        }
    }
    // Glow on the horizon.
    for y in (hy - 8).max(0)..hy {
        let k = 1.0 - (hy - y) as f32 / 8.0;
        for x in 0..w {
            let falloff = 1.0 - 0.7 * (x as f32 - cx).abs() / (wf / 2.0);
            if bayer[(y & 7) as usize][(x & 7) as usize] < 0.55 * k * k * falloff {
                buf.dot(x as f32, y as f32, white, 0.45 + 0.45 * k);
            }
        }
    }
    buf.line(0.0, hyf, wf - 1.0, hyf, white, 1.0, 1.0, 0);
    // The grid sea: x - cx = 8X/Z, y - hy = depth/Z (Z = 1 at the bottom row).
    let cell = 8.0;
    let step = cell / depth.max(1.0);
    for k in -30..=30i32 {
        let y0 = if k == 0 {
            hf - 1.0
        } else {
            (hf - 1.0).min(hyf + (wf / 2.0 + 2.0) * depth / (k.abs() as f32 * cell))
        };
        let y_end = hyf + (depth * 0.3).max(3.0);
        if y0 <= hyf + 1.5 || y0 <= y_end {
            continue;
        }
        let x0 = cx + k as f32 * cell * (y0 - hyf) / depth;
        let x1 = cx + k as f32 * cell * (y_end - hyf) / depth;
        buf.line(
            x0,
            y0,
            x1,
            y_end,
            ice,
            0.25 + 0.65 * (y0 - hyf) / depth,
            0.18,
            0,
        );
    }
    let scroll = (t * (0.35 + 1.6 * energy)).fract();
    let mut previous: Option<f32> = None;
    for m in 0..80 {
        let z = 1.0 + (m as f32 - scroll) * step;
        if z < 0.98 {
            continue;
        }
        let y = hyf + depth / z;
        if previous.is_some_and(|previous| previous - y < 2.5) {
            break;
        }
        previous = Some(y);
        let bright = 0.2 + 0.75 * (y - hyf) / depth;
        buf.line(0.0, y, wf - 1.0, y, ice, bright, bright, 0);
    }
    // Haze just under the horizon.
    let haze = (depth * 0.12).max(3.0);
    for y in hy + 1..(hyf + haze) as i32 {
        let k = 1.0 - (y - hy) as f32 / haze;
        for x in 0..w {
            if bayer[(y & 7) as usize][(x & 7) as usize] < 0.22 * k {
                buf.dot(x as f32, y as f32, ice, 0.35);
            }
        }
    }
    // Moonlight on the water.
    let beat = (t * 8.0) as u32;
    for y in hy + 1..(hyf + depth * 0.6) as i32 {
        let spread = 0.8 + (y - hy) as f32 * 0.16;
        if star_noise(y as u32, beat, 11) < 0.35 {
            let offset = (star_noise(beat, y as u32, 13) - 0.5) * 2.0 * spread;
            buf.dot(cx + offset, y as f32, white, 0.85);
        }
    }
    // One pulse ring travelling out across the sea.
    let radius = (t * (5.0 + 9.0 * energy)) % 44.0;
    if radius >= 1.2 {
        let bright = 0.35 + 0.65 * (0.6 + 0.4 * energy) * (1.0 - radius / 44.0);
        let mut previous: Option<(f32, f32)> = None;
        for j in 0..=96 {
            let angle = j as f32 * std::f32::consts::TAU / 96.0;
            let z = 1.9 + radius * step * angle.sin();
            if z < 0.95 {
                previous = None;
                continue;
            }
            let point = (cx + cell * radius * angle.cos() / z, hyf + depth / z);
            if let Some((px, py)) = previous {
                buf.line(px, py, point.0, point.1, white, bright, bright, 0);
            }
            previous = Some(point);
        }
    }
}

/// Shards orbit a turning star above a faint reflection. The seeded shape
/// stays stable across frames; activity changes its pace rather than its data.
fn shard_scene(buf: &mut DotBuf, t: f32, energy: f32, teal: Rgb, white: Rgb) {
    let (w, h) = (buf.width() as f32, buf.height() as f32);
    let (cx, cy) = (w / 2.0, h * 0.42);
    let radius = (w * 0.47).min(h * 0.95);
    let water = h * 0.74;
    let rotation = t * (0.12 + 0.7 * energy);
    for y in (water as i32 + 2..buf.height()).step_by(3) {
        for x in 0..buf.width() {
            if (x + (t * 9.0) as i32 + y * 3) % 7 == 0 {
                buf.dot(x as f32, y as f32, teal, 0.22);
            }
        }
    }
    for i in 0..120u32 {
        let fraction = 0.72 + 0.28 * star_noise(i, 1, 11);
        let angle =
            star_noise(i, 0, 11) * std::f32::consts::TAU + rotation * (1.5 - 0.7 * fraction);
        let (sine, cosine) = angle.sin_cos();
        let x = cx + radius * fraction * cosine;
        let y = cy + radius * fraction * 0.3 * sine + (star_noise(i, 2, 11) - 0.5) * 0.12 * h;
        let depth = (sine + 1.0) / 2.0;
        let bright = 0.3 + 0.7 * depth;
        let length = 1.5 + star_noise(i, 3, 11) * 2.5;
        let tilt = angle + std::f32::consts::FRAC_PI_2 + (star_noise(i, 4, 11) - 0.5) * 1.3;
        let (dy, dx) = tilt.sin_cos();
        let (dx, dy) = (dx * length / 2.0, dy * length * 0.4);
        buf.line(
            x - dx,
            y - dy,
            x + dx,
            y + dy,
            mix(teal, white, depth * 0.55),
            bright,
            bright,
            0,
        );
        if i.is_multiple_of(6)
            && (t * 2.4 + star_noise(i, 5, 11) * 6.3 + rotation * 2.0).sin() > 0.82
        {
            for (gx, gy) in [(0.0, 0.0), (1.0, 0.0), (-1.0, 0.0), (0.0, 1.0), (0.0, -1.0)] {
                buf.dot(x + dx + gx, y + dy + gy, white, 1.0);
            }
        }
        let reflection = 2.0 * water - y;
        if reflection > water + 1.0 && reflection < h {
            buf.dot(
                x + (reflection * 0.8 + t * 3.0).sin() * 1.3,
                reflection,
                teal,
                bright * 0.45,
            );
        }
    }
    for ray in 0..8 {
        let angle = -rotation * 1.8 + ray as f32 * std::f32::consts::FRAC_PI_4;
        let length =
            h * 0.22 * (1.0 + 0.12 * (t * 3.0).sin()) * if ray % 2 == 0 { 1.0 } else { 0.42 };
        buf.line(
            cx,
            cy,
            cx + angle.cos() * length * 1.2,
            cy + angle.sin() * length * 0.85,
            white,
            1.0,
            0.45,
            0,
        );
    }
    for i in 0..46u32 {
        let x = star_noise(i, 0, 17) * w + (t + i as f32).sin() * 2.0;
        let y = (star_noise(i, 1, 17) - t * (0.03 + star_noise(i, 2, 17) * 0.06)).rem_euclid(1.0)
            * water;
        buf.dot(x, y, teal, 0.45);
    }
}

/// Three chrome spines carry travelling waves and thorns through drifting dust.
fn spine_scene(buf: &mut DotBuf, t: f32, energy: f32, ice: Rgb, white: Rgb) {
    let (w, h) = (buf.width(), buf.height());
    let (wf, hf) = (w as f32, h as f32);
    let bayer = bayer8();
    for i in 0..30u32 {
        buf.dot(
            star_noise(i, 0, 5) * wf + (t * 0.7 + i as f32).sin() * 2.0,
            (star_noise(i, 1, 5) - t * (0.02 + star_noise(i, 2, 5) * 0.05)).rem_euclid(1.0) * hf,
            ice,
            0.35,
        );
    }
    for (base, amplitude, waves, speed, phase, radius) in [
        (0.22, 0.08, 1.1, 0.8, 0.0, 0.045),
        (0.52, 0.11, 0.8, -0.6, 1.9, 0.062),
        (0.81, 0.07, 1.35, 1.1, 3.6, 0.04),
    ] {
        for x in 0..w {
            let u = x as f32 / (wf - 1.0).max(1.0);
            let taper = (u / 0.1)
                .sqrt()
                .min(((1.0 - u).max(0.0) / 0.1).sqrt())
                .min(1.0);
            let centre = hf
                * (base
                    + amplitude
                        * (waves * std::f32::consts::TAU * u
                            + speed * (0.5 + 1.6 * energy) * t
                            + phase)
                            .sin()
                    + 0.025 * (5.0 * std::f32::consts::TAU * u - t * 1.3 + phase).sin());
            let radius = hf * radius * taper * (1.0 + 0.1 * (u * 40.0 - t * 3.0 + phase).sin());
            if radius < 0.6 {
                continue;
            }
            let (top, bottom) = (centre - radius, centre + radius);
            for y in (top as i32).max(0)..=(bottom as i32).min(h - 1) {
                let v = (y as f32 - centre) / radius;
                let intensity = 0.05 + 0.25 * (-((v - 0.55) / 0.25).powi(2)).exp();
                let index = (y * w + x) as usize;
                buf.on[index] = false;
                if intensity > bayer[(y & 7) as usize][(x & 7) as usize] {
                    buf.dot(x as f32, y as f32, ice, 0.45);
                }
            }
            buf.dot(x as f32, top, mix(ice, white, 0.5), 0.95);
            buf.dot(x as f32, bottom, ice, 0.6);
            let specular = (u * 7.0 - t * 1.4 + phase).sin().max(0.0).powi(6);
            if radius > 1.6 && (specular > 0.15 || x % 3 != 1) {
                buf.dot(
                    x as f32,
                    centre - radius * 0.42,
                    white,
                    0.55 + 0.45 * specular,
                );
            }
            if x % 8 == 0 && taper > 0.6 {
                let pulse = 0.5 + 0.5 * (x as f32 * 0.22 - t * (2.5 + 5.0 * energy) + phase).sin();
                let thorn = radius * (0.35 + pulse * pulse);
                buf.line(
                    x as f32,
                    top,
                    x as f32 - 1.2,
                    top - thorn,
                    mix(ice, white, pulse),
                    0.5 + 0.5 * pulse,
                    0.5 + 0.5 * pulse,
                    0,
                );
            }
        }
    }
}

/// Latitude rings and meridians form a rotating, activity-reactive globe.
fn globe_scene(buf: &mut DotBuf, t: f32, energy: f32, ice: Rgb, white: Rgb) {
    let (w, h) = (buf.width() as f32, buf.height() as f32);
    let radius = (w / 2.0).min(h / 2.0) * 0.92;
    let (sine, cosine) = (t * (0.35 + 2.6 * energy)).sin_cos();
    let (tilt_sine, tilt_cosine) = (0.45 + 0.15 * (t * 0.4).sin()).sin_cos();
    let mut point = |x: f32, y: f32, z: f32, index: usize| {
        let wobble = 1.0
            + energy * 0.13 * (3.0 * y * std::f32::consts::PI + t * 6.0 + x * 4.0).sin()
            + energy * 0.06 * (t * 9.0 + index as f32).sin();
        let (x, y, z) = (x * wobble, y * wobble, z * wobble);
        let (x, z) = (x * cosine + z * sine, -x * sine + z * cosine);
        let (y, z) = (
            y * tilt_cosine - z * tilt_sine,
            y * tilt_sine + z * tilt_cosine,
        );
        if z >= -0.35 {
            let brightness = 0.35 + 0.65 * (z + 1.0) / 2.0;
            buf.dot(
                w / 2.0 + x * radius,
                h / 2.0 + y * radius,
                mix(ice, white, ((z + 1.0) / 2.0).clamp(0.0, 1.0)),
                brightness,
            );
        }
    };
    for latitude in 1..8 {
        let phi = -std::f32::consts::FRAC_PI_2 + latitude as f32 * std::f32::consts::PI / 8.0;
        for j in 0..70 {
            let angle = j as f32 * std::f32::consts::TAU / 70.0;
            point(
                phi.cos() * angle.cos(),
                phi.sin(),
                phi.cos() * angle.sin(),
                latitude * 70 + j,
            );
        }
    }
    for longitude in 0..9 {
        let angle = longitude as f32 * std::f32::consts::PI / 9.0;
        for j in 0..70 {
            let phi = j as f32 * std::f32::consts::TAU / 70.0;
            point(
                phi.cos() * angle.cos(),
                phi.sin(),
                phi.cos() * angle.sin(),
                560 + longitude * 70 + j,
            );
        }
    }
}

fn reactor_art_at(art: ReactorArt, now_ms: u64, reduced: bool) -> ReactorArt {
    match art {
        ReactorArt::Rotate => [
            ReactorArt::Kwangya,
            ReactorArt::Shard,
            ReactorArt::Spine,
            ReactorArt::Globe,
        ][if reduced {
            0
        } else {
            (now_ms / 40_000 % 4) as usize
        }],
        selected => selected,
    }
}

fn reactor_scene(buf: &mut DotBuf, art: ReactorArt, t: f32, energy: f32, ice: Rgb, white: Rgb) {
    match art {
        ReactorArt::Kwangya | ReactorArt::Rotate => kwangya_scene(buf, t, energy, ice, white),
        ReactorArt::Shard => shard_scene(buf, t, energy, ice, white),
        ReactorArt::Spine => spine_scene(buf, t, energy, ice, white),
        ReactorArt::Globe => globe_scene(buf, t, energy, ice, white),
    }
}

/// The Reactor's 3x5 digit font.
fn big_glyph(c: char) -> [&'static str; 5] {
    match c {
        '0' => ["███", "█ █", "█ █", "█ █", "███"],
        '1' => [" █ ", "██ ", " █ ", " █ ", "███"],
        '2' => ["███", "  █", "███", "█  ", "███"],
        '3' => ["███", "  █", "███", "  █", "███"],
        '4' => ["█ █", "█ █", "███", "  █", "  █"],
        '5' => ["███", "█  ", "███", "  █", "███"],
        '6' => ["███", "█  ", "███", "█ █", "███"],
        '7' => ["███", "  █", "  █", "  █", "  █"],
        '8' => ["███", "█ █", "███", "█ █", "███"],
        '9' => ["███", "█ █", "███", "  █", "███"],
        '.' => ["   ", "   ", "   ", "   ", " █ "],
        _ => ["   ", "   ", "███", "   ", "   "],
    }
}

/// The Reactor as a native view, like the Reactor's own box: the Kwangya
/// scene on the left, the output rate in big digits and the meters on the
/// right. Returns `false` (draw the text instead) when the text is not the
/// Unicode reactor layout or the view does not fit.
/// The reactor as a scene, a rate, and — while a council runs — the MAGI
/// bench on the panel's bottom edge.
fn draw_reactor_view_with_bench(
    cv: &mut Cv,
    (x, y, w, h): (i32, i32, i32, i32),
    text: &str,
    clock: PaneClock,
    bench: Option<crate::proto::ported::CouncilBench>,
) -> bool {
    let palette = cv.palette;
    let mut lines = text.lines();
    let Some(header) = lines.next().filter(|line| line.starts_with("REACTOR · ")) else {
        return false;
    };
    let lines: Vec<&str> = lines.filter(|line| !line.trim().is_empty()).collect();
    // A narrow pane still gets the scene (it takes the width); only a
    // genuinely tiny one falls back to its text lines.
    if w < 24 || h < 6 {
        return false;
    }
    let mut at = x + 1;
    for (segment, colour) in builtin_segments("reactor", header, &palette) {
        at = cv.text(at, y, segment, colour, None);
    }
    // The pace follows the session: streaming text, a working phase, or rest.
    let rate_line = lines.iter().find(|line| line.starts_with("tok/s"));
    let streaming = rate_line.is_some_and(|line| line.contains(" live"));
    let energy = if streaming {
        1.0
    } else if ["ORIENT", "REASON", "ACT", "VERIFY", "RESPOND", "COMPACT"]
        .iter()
        .any(|phase| header.ends_with(phase))
        || bench.as_ref().is_some_and(|bench| bench.phase != "VERDICT")
    {
        0.6
    } else {
        0.15
    };
    let t = if clock.reduced {
        0.0
    } else {
        (clock.now_ms % 3_600_000) as f32 / 1_000.0
    };
    // The scene takes what the pane can spare: a share of the width, never
    // so much that the meters lose their column, and all of it when the
    // pane is too narrow for both. The dot canvas follows the same math, so
    // the picture fills whatever rectangle it is given.
    let meters_min = 22;
    let scene_w = if w - meters_min >= 18 {
        ((w * 45) / 100).clamp(18, (w - meters_min - 4).max(18))
    } else {
        (w - 2).max(1)
    };
    let (right, right_w) = (x + 1 + scene_w + 2, w - scene_w - 4);
    // Even a scene-only narrow pane keeps its live rate visible below the art.
    let room = h - 1 - i32::from(right_w < 12);
    let mut scene = DotBuf::new(scene_w.max(1), room.max(1));
    reactor_scene(
        &mut scene,
        reactor_art_at(clock.reactor_art, clock.now_ms, clock.reduced),
        t,
        energy,
        palette.cyan,
        palette.white,
    );
    scene.blit(cv, x + 1, y + 1);
    // The meters, when there is a column left for them.
    if right_w < 12 {
        if let Some(rate) = rate_line {
            let rate = clip_text(rate, (w - 2).max(1));
            let mut at = x + 1;
            for (segment, colour) in builtin_segments("reactor", &rate, &palette) {
                at = cv.text(at, y + h - 1, segment, colour, None);
            }
        }
        return true;
    }
    let mut row = y + 1;
    let value = rate_line
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|value| value.trim_start_matches('≈'))
        .filter(|value| value.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .unwrap_or("-");
    // Big digits when there is room for them above the meter lines.
    let scale = [2, 1]
        .into_iter()
        .find(|scale| value.chars().count() as i32 * (3 * scale + 1) <= right_w);
    if let Some(scale) = scale.filter(|_| h > 6 + lines.len() as i32) {
        let colour = if streaming {
            palette.cyan_hi
        } else {
            palette.cyan
        };
        let mut glyph_x = right;
        for c in value.chars() {
            for (line, cells) in big_glyph(c).iter().enumerate() {
                let wide: String = cells
                    .chars()
                    .flat_map(|cell| std::iter::repeat_n(cell, scale as usize))
                    .collect();
                cv.text(glyph_x, row + line as i32, &wide, colour, None);
            }
            glyph_x += 3 * scale + 1;
        }
        row += 6;
    }
    for line in &lines {
        if row >= y + h {
            break;
        }
        let line = clip_text(line, right_w.max(1));
        let mut at = right;
        for (segment, colour) in builtin_segments("reactor", &line, &palette) {
            at = cv.text(at, row, segment, colour, None);
        }
        row += 1;
    }
    // The council bench, on the panel's bottom edge, only while a council
    // is live or has just landed.
    if let Some(bench) = bench {
        let bench_y = y + h - 1;
        if bench_y > row {
            crate::proto::ported::draw_council_bench(
                cv,
                x,
                bench_y,
                w,
                &bench,
                crate::proto::ported::BenchPalette::from_shell(&palette),
                clock.now_ms as f64 / 1_000.0,
            );
        }
    }
    true
}

/// Colour for the built-in panes: seat identity, verdicts, meters. The text
/// itself is unchanged, so `glyphs: ascii` and `color_mode: mono` still read.
/// Any other pane, or a line this does not recognise, stays one plain run.
fn builtin_segments<'a>(
    id: &str,
    line: &'a str,
    palette: &crate::proto::shell::pal::Palette,
) -> Vec<(&'a str, Rgb)> {
    let plain = vec![(line, palette.ink)];
    let Some(head_end) = line.find(' ') else {
        return if matches!(id, "council" | "reactor") && !line.is_empty() {
            vec![(line, palette.ink2)]
        } else {
            plain
        };
    };
    let (head, rest) = line.split_at(head_end);
    match id {
        "council" => {
            if head == "MAGI" {
                return vec![(head, palette.magenta), (rest, palette.ink)];
            }
            // Seat identity colours, as in the MAGI pane.
            if let Some(identity) = seat_colour(head, palette) {
                let mark = ["● ", "◌ ", " * ", " . "]
                    .iter()
                    .filter_map(|mark| rest.rfind(mark))
                    .max();
                let Some(mark) = mark else {
                    return vec![(head, identity), (rest, palette.muted)];
                };
                let (middle, verdict) = rest.split_at(mark);
                let colour = if ["승인", "APPROVE"]
                    .iter()
                    .any(|word| verdict.contains(word))
                {
                    palette.green
                } else if ["거부", "REJECT", "신호없음", "SIGNAL LOST"]
                    .iter()
                    .any(|word| verdict.contains(word))
                {
                    palette.red
                } else if ["보류", "HOLD"].iter().any(|word| verdict.contains(word)) {
                    palette.amber
                } else if ["심의중", "deliberating", "SYNK"]
                    .iter()
                    .any(|word| verdict.contains(word))
                {
                    identity
                } else {
                    palette.muted
                };
                return vec![(head, identity), (middle, palette.muted), (verdict, colour)];
            }
            // The narration strip: a coloured label, then the note.
            let label = match head {
                "nævis" | "naevis" => palette.magenta_hi,
                "다수결" | "majority" => palette.green,
                "동률" | "tie" => palette.amber,
                "고장" | "fail" => palette.red,
                "최근" | "last" => palette.muted,
                "표결" | "vote" => palette.violet,
                "심의" | "deliberate" | "SYNK" | "선별" | "triage" => palette.cyan,
                _ => return plain,
            };
            let body = if matches!(head, "최근" | "last") {
                palette.muted
            } else {
                palette.ink
            };
            vec![(head, label), (rest, body)]
        }
        "reactor" => {
            if head == "REACTOR" {
                return vec![(head, palette.magenta), (rest, palette.ink)];
            }
            if !matches!(head, "tok/s" | "rate" | "out" | "cache" | "ctx" | "cost") {
                return plain;
            }
            // Labels recede, values carry the colour; the empty part of the
            // context bar is drawn faint.
            let mut out = vec![(head, palette.muted)];
            let value = if head == "tok/s" {
                palette.cyan_hi
            } else {
                palette.cyan
            };
            match (rest.find(['░', '.']), head) {
                (Some(start), "ctx") => {
                    let end = rest[start..]
                        .find(|c: char| !matches!(c, '░' | '.'))
                        .map_or(rest.len(), |offset| start + offset);
                    out.push((&rest[..start], value));
                    out.push((&rest[start..end], palette.faint));
                    out.push((&rest[end..], palette.ink2));
                }
                _ => out.push((rest, value)),
            }
            out
        }
        _ => plain,
    }
}

/// The custom view shares the same production frame, hit map and clipping engine.
pub fn draw_pane(
    cv: &mut Cv,
    r: Rect,
    id: &str,
    output: Option<&PaneOutput>,
    num: usize,
    focused: bool,
    scroll: usize,
) {
    draw_pane_at_with_council(cv, r, id, output, num, focused, scroll, None, None);
}

/// `draw_pane` with the frame clock: the built-in council pane then draws
/// its seats as cards when they fit, and animates unless motion is reduced.
#[allow(clippy::too_many_arguments)]
pub fn draw_pane_at(
    cv: &mut Cv,
    r: Rect,
    id: &str,
    output: Option<&PaneOutput>,
    num: usize,
    focused: bool,
    scroll: usize,
    clock: Option<PaneClock>,
) {
    draw_pane_at_with_council(cv, r, id, output, num, focused, scroll, clock, None);
}

/// `draw_pane_at` plus the session's council state, which the council and
/// reactor panes draw from instead of the text snapshot.
#[allow(clippy::too_many_arguments)]
pub fn draw_pane_at_with_council(
    cv: &mut Cv,
    r: Rect,
    id: &str,
    output: Option<&PaneOutput>,
    num: usize,
    focused: bool,
    scroll: usize,
    clock: Option<PaneClock>,
    council: Option<&crate::proto::ported::CouncilState>,
) {
    let palette = cv.palette;
    let title = output.map(|o| o.title.as_str()).unwrap_or(id);
    let Some(inner) = panel_frame(
        cv,
        r,
        &FrameSpec {
            num,
            title,
            subtitle: "",
            ident: palette.cyan,
            focused,
            focus_fx: FocusFx::settled(focused),
            badge: None,
            attention: 0.0,
            footer: Vec::new(),
            footer_parts: Vec::new(),
        },
    ) else {
        return;
    };
    let (x, y, w, h) = (
        inner.x as i32,
        inner.y as i32,
        inner.width as i32,
        inner.height as i32,
    );
    let Some(output) = output else {
        cv.text(x, y, "loading · refresh with r", palette.muted, None);
        return;
    };
    let (state, mut text) = match safe_pane_text(&output.text) {
        Ok(text) => (output.state.clone(), text),
        Err(error) => (
            PaneState::Error,
            crate::bridge::safe_text(&error.to_string()),
        ),
    };
    let state = match state {
        PaneState::Ready => "",
        PaneState::Empty => "empty",
        PaneState::Missing => "missing",
        PaneState::Loading => "loading",
        PaneState::Stale => "stale · refresh",
        PaneState::Error => "error",
    };
    if !state.is_empty() {
        text = format!("{state}\n{text}");
    }
    if output.truncated {
        text.push_str("\n[truncated]");
    }
    let width = (w - 2).max(1);
    let ranges = wrap_ranges(&text, width);
    let chars: Vec<char> = text.chars().collect();
    let content_height = h.saturating_sub(if output.actions.is_empty() { 0 } else { 2 });
    let cards = scroll == 0
        && clock.is_some_and(|clock| match id {
            "council" => {
                // The structured state is authoritative when the session
                // carries it; the text parser remains for frontends that
                // have only the snapshot. Small panes must keep the body
                // inside its content area, clear of frames and actions.
                let content = Rect {
                    height: content_height.max(0) as u16,
                    ..inner
                };
                cv.clipped(content, |cv| match council {
                    Some(state) => crate::proto::ported::draw_council(
                        cv,
                        (x, y, w, content_height),
                        state,
                        crate::proto::ported::BenchPalette::from_shell(&palette),
                        clock.now_ms,
                        clock.reduced,
                    ),
                    None => draw_council_cards(cv, (x, y, w, content_height), &text, clock),
                })
            }
            "reactor" => {
                let content = Rect {
                    height: content_height.max(0) as u16,
                    ..inner
                };
                cv.clipped(content, |cv| {
                    draw_reactor_view_with_bench(
                        cv,
                        (x, y, w, content_height),
                        &text,
                        clock,
                        council.as_ref().and_then(|state| {
                            crate::proto::ported::CouncilBench::of(
                                state,
                                clock.now_ms as f64 / 1_000.0,
                            )
                        }),
                    )
                })
            }
            _ => false,
        });
    if !cards {
        for (row, (a, b)) in ranges
            .into_iter()
            .skip(scroll)
            .take(content_height.max(0) as usize)
            .enumerate()
        {
            let line: String = chars[a..b].iter().collect();
            let mut at = x + 1;
            for (segment, colour) in builtin_segments(id, &line, &palette) {
                at = cv.text(at, y + row as i32, segment, colour, None);
            }
        }
    }
    if !output.actions.is_empty() && h >= 2 {
        let mut at = x + 1;
        for (i, action) in output.actions.iter().take(8).enumerate() {
            let label = match action {
                PaneAction::Refresh => "refresh",
                PaneAction::FocusConversation => "conversation",
                PaneAction::InsertPrompt { .. } => "insert draft",
                PaneAction::OwnerCancel => "cancel turn",
                PaneAction::CycleReactorArt => "next art",
            };
            let label = clip_text(&format!("{} {label}  ", i + 1), (x + w - at).max(0));
            if label.is_empty() {
                break;
            }
            let end = cv.text(at, y + h - 1, &label, palette.cyan, None);
            cv.hit(
                at,
                y + h - 1,
                end - at,
                1,
                Click::CustomAction {
                    panel: num - 1,
                    action: i,
                },
            );
            at = end;
        }
    }
}

pub fn focus_conversation(app: &mut crate::proto::app::App) {
    if let Some(index) = app
        .tree
        .leaves()
        .iter()
        .position(|(_, view)| *view == View::Conversation)
    {
        app.focus = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_frontend_protocol::customization::{
        CustomizationCapabilities, LayoutNode, PaneDef, PaneSource, Surface,
    };
    struct Host(
        String,
        Option<orbit_frontend_protocol::customization::CouncilSnapshot>,
    );
    impl Host {
        fn new(text: impl Into<String>) -> Self {
            Self(text.into(), None)
        }
    }
    impl ProfileHost for Host {
        fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
            let mut p = Profile::default();
            p.panes.push(PaneDef {
                id: "notes".into(),
                title: "Local notes".into(),
                surfaces: vec![Surface::Terminal],
                source: PaneSource::Text {
                    text: "fixture proof".into(),
                },
                actions: vec![PaneAction::Refresh],
            });
            p.layout.tree = LayoutNode::Split {
                direction: orbit_frontend_protocol::customization::Direction::Right,
                shares: vec![1, 1],
                children: vec![
                    LayoutNode::panel(orbit_frontend_protocol::customization::View::Conversation),
                    LayoutNode::Custom {
                        pane_id: "notes".into(),
                    },
                ],
            };
            Ok(ResolvedProfile {
                profile: p,
                sources: Default::default(),
                revision: "1".into(),
                capabilities: CustomizationCapabilities::default(),
            })
        }
        fn replace(&self, _: Profile, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            self.load()
        }
        fn reset(&self, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            self.load()
        }
        fn read_pane(&self, id: &str, _: &PaneContext) -> Result<PaneOutput, CustomizationError> {
            Ok(PaneOutput {
                id: id.into(),
                title: "untrusted host title".into(),
                state: PaneState::Ready,
                text: self.0.clone(),
                truncated: false,
                council: self.1.clone(),
                actions: vec![PaneAction::Refresh],
            })
        }
    }
    #[test]
    fn custom_pane_tracer_renders_named_host_data_alongside_conversation() {
        let mut session = CustomizationSession::open(Arc::new(Host::new("fixture proof"))).unwrap();
        session.refresh_all();
        let tree = profile_tree(&session.resolved.profile).unwrap();
        assert!(tree.leaves().iter().any(|(_, v)| *v == View::Conversation));
        let mut buffer = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 12));
        let mut cv = Cv::new(&mut buffer);
        draw_pane(
            &mut cv,
            Rect::new(0, 0, 60, 12),
            "notes",
            session.outputs.get("notes"),
            2,
            true,
            0,
        );
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Local notes"));
        assert!(text.contains("fixture proof"));
    }

    fn buffer_row(buffer: &ratatui::buffer::Buffer, row: u16) -> String {
        (1..buffer.area.width - 1)
            .map(|col| buffer[(col, row)].symbol())
            .collect::<String>()
            .trim()
            .to_string()
    }

    #[test]
    fn refresh_keeps_blank_and_trailing_lines_and_renders_separate_rows() {
        let mut session =
            CustomizationSession::open(Arc::new(Host::new("alpha\n\nomega\n"))).unwrap();
        session.refresh("notes").unwrap();
        let output = session.outputs.get("notes").unwrap();
        assert_eq!(output.text, "alpha\n\nomega\n");
        assert_eq!(output.state, PaneState::Ready);
        assert_eq!(output.title, "Local notes");

        let area = Rect::new(0, 0, 40, 10);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(output), 2, true, 0);
        let hits = cv.take_hits();
        assert_eq!(buffer_row(&buffer, 2), "alpha");
        assert_eq!(buffer_row(&buffer, 3), "");
        assert_eq!(buffer_row(&buffer, 4), "omega");
        assert_eq!(buffer_row(&buffer, 5), "");
        let action = hits
            .iter()
            .find(|hit| matches!(hit.click, Click::CustomAction { .. }))
            .unwrap();
        assert_eq!(
            action.click,
            Click::CustomAction {
                panel: 1,
                action: 0
            }
        );
        assert_eq!(buffer_row(&buffer, action.rect.y), "1 refresh");

        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(output), 2, true, 2);
        assert_eq!(buffer_row(&buffer, 2), "omega");
        assert_eq!(buffer_row(&buffer, action.rect.y), "1 refresh");
        assert_eq!(session.action("notes", 0).unwrap(), ActionEffect::Refreshed);
        assert_eq!(session.outputs["notes"].text, "alpha\n\nomega\n");
    }

    #[test]
    fn refresh_sanitizes_raw_multiline_escapes_controls_and_secrets() {
        let mut session = CustomizationSession::open(Arc::new(Host::new(concat!(
            "first\n\u{1b}]0;hidden\nOSC title\u{7}\u{1b}[31\nmred\u{1b}[0m\n",
            "token=ghp_0123456789abcdef0123456789abcdef0123 done\r\u{7}\u{85}\n",
            "last\tcell\n"
        ))))
        .unwrap();
        session.refresh("notes").unwrap();
        let text = &session.outputs["notes"].text;
        assert!(text.starts_with("first\nred\ntoken="), "{text}");
        assert!(text.ends_with(" done\nlast    cell\n"), "{text}");
        assert!(!text.contains("ghp_0123"), "{text}");
        assert!(!text.contains("hidden"), "{text}");
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn refresh_sanitizes_and_bounds_typed_council_state_from_an_untrusted_host() {
        use orbit_frontend_protocol::customization::{CouncilSeat, CouncilSnapshot};
        let token = "ghp_0123456789abcdef0123456789abcdef0123";
        let secret = format!("\u{1b}]0;hidden title\u{7}token={token}");
        let mut host = Host::new("Council ready");
        host.1 = Some(CouncilSnapshot {
            phase: "DELIBERATING".into(),
            note: format!("{secret}<think>private unclosed reasoning"),
            last_final: "<think>private reasoning</think>Public conclusion".into(),
            seats: vec![
                CouncilSeat {
                    model: secret.clone(),
                    ..CouncilSeat::default()
                };
                20
            ],
            winner_seats: vec![secret; 20],
            ..CouncilSnapshot::default()
        });
        let mut session = CustomizationSession::open(Arc::new(host)).unwrap();
        session.refresh("council").unwrap();
        let state = session.outputs["council"].council.as_ref().unwrap();
        let encoded = serde_json::to_string(state).unwrap();
        assert!(!encoded.contains(token));
        assert!(!encoded.contains("hidden title"));
        assert!(!encoded.contains("private"));
        assert!(!encoded.contains("think"));
        assert!(!encoded.contains("\\u001b"));
        assert!(state.note.contains("[redacted:github token]"));
        assert_eq!(state.last_final, "Public conclusion");
        assert_eq!(state.seats.len(), 4);
        assert_eq!(state.winner_seats.len(), 4);
    }

    #[test]
    fn reactor_art_action_requires_controller_and_does_not_mutate_on_open() {
        let mut session = CustomizationSession::open(Arc::new(Host::new("Reactor ready"))).unwrap();
        session.refresh("reactor").unwrap();
        assert_eq!(session.resolved.profile.reactor_art, ReactorArt::Kwangya);
        session.outputs.get_mut("reactor").unwrap().actions = vec![PaneAction::CycleReactorArt];
        assert!(session.action("reactor", 0).is_err());
        session.context.controller = true;
        assert_eq!(
            session.action("reactor", 0).unwrap(),
            ActionEffect::CycleReactorArt
        );
        assert_eq!(session.resolved.profile.reactor_art, ReactorArt::Kwangya);
    }

    #[test]
    fn session_invalidation_clears_typed_council_before_any_refresh() {
        use orbit_frontend_protocol::customization::CouncilSnapshot;
        let mut host = Host::new("Council ready");
        host.1 = Some(CouncilSnapshot {
            phase: "VERDICT".into(),
            note: "old session conclusion".into(),
            ..CouncilSnapshot::default()
        });
        let mut session = CustomizationSession::open(Arc::new(host)).unwrap();
        session.context.session_id = Some("old-session".into());
        session.refresh("council").unwrap();
        assert!(session.outputs["council"].council.is_some());
        session.invalidate_session(PaneContext {
            session_id: Some("new-session".into()),
            ..PaneContext::default()
        });
        assert_eq!(session.context.session_id.as_deref(), Some("new-session"));
        let pane = &session.outputs["council"];
        assert!(pane.council.is_none());
        assert_eq!(pane.state, PaneState::Stale);
        assert!(!pane.text.contains("old session conclusion"));
    }

    #[test]
    fn refresh_preserves_raw_and_visible_content_gate_refusals() {
        for text in [
            "first\nprompt: hidden\nlast",
            "first\nuser_message\nlast",
            "first\nchain_of_thought\nlast",
            "first\n\u{1b}]0;prompt: hidden\u{7}last",
            "first\npro\u{1b}[31mmpt: hidden\nlast",
        ] {
            let mut session = CustomizationSession::open(Arc::new(Host::new(text))).unwrap();
            session.refresh("notes").unwrap();
            assert_eq!(session.outputs["notes"].text, "[redacted]", "{text:?}");
        }
    }

    #[test]
    fn refresh_rejects_in_bound_text_that_expands_beyond_display_bounds() {
        let raw = "\t".repeat(MAX_PANE_OUTPUT_BYTES);
        assert_eq!(raw.len(), MAX_PANE_OUTPUT_BYTES);
        assert!(raw.lines().count() <= MAX_PANE_LINES);
        let mut session = CustomizationSession::open(Arc::new(Host::new(raw))).unwrap();
        assert!(matches!(
            session.refresh("notes"),
            Err(CustomizationError::Invalid(_))
        ));
        let output = &session.outputs["notes"];
        assert_eq!(output.state, PaneState::Error);
        assert!(output.text.contains("exceeds display bounds"));
        assert!(output.text.len() <= MAX_PANE_OUTPUT_BYTES);
        assert_eq!(output.actions, vec![PaneAction::Refresh]);
    }

    #[test]
    fn refresh_accepts_tab_expansion_at_exact_display_limit() {
        let raw = "\t".repeat(MAX_PANE_OUTPUT_BYTES / 4);
        let mut session = CustomizationSession::open(Arc::new(Host::new(raw))).unwrap();
        session.refresh("notes").unwrap();
        let output = &session.outputs["notes"];
        assert_eq!(output.state, PaneState::Ready);
        assert_eq!(output.text.len(), MAX_PANE_OUTPUT_BYTES);
        assert!(output.text.chars().all(|c| c == ' '));
    }

    #[test]
    fn direct_pane_render_sanitizes_multiline_input_without_refresh() {
        let output = PaneOutput {
            id: "notes".into(),
            title: "Local notes".into(),
            state: PaneState::Ready,
            text: "\u{1b}[31malpha\u{1b}[0m\n\u{1b}]0;hidden\ntext\u{7}omega\n".into(),
            truncated: false,
            council: None,
            actions: Vec::new(),
        };
        let area = Rect::new(0, 0, 40, 9);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane(&mut cv, area, "notes", Some(&output), 2, true, 0);
        assert_eq!(buffer_row(&buffer, 2), "alpha");
        assert_eq!(buffer_row(&buffer, 3), "omega");
        assert_eq!(buffer_row(&buffer, 4), "");
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(!text.contains("hidden"));
        assert!(!text.contains("[31m"));
    }

    #[test]
    fn direct_pane_render_keeps_secret_redaction_and_content_refusals() {
        for (text, expected) in [
            ("alpha\nchain_of_thought hidden\nlast", "[redacted]"),
            (
                "token=ghp_0123456789abcdef0123456789abcdef0123\nlast",
                "[redacted:github token]",
            ),
        ] {
            let output = PaneOutput {
                id: "notes".into(),
                title: "Local notes".into(),
                state: PaneState::Ready,
                text: text.into(),
                truncated: false,
                council: None,
                actions: Vec::new(),
            };
            let area = Rect::new(0, 0, 60, 9);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            draw_pane(
                &mut Cv::new(&mut buffer),
                area,
                "notes",
                Some(&output),
                2,
                true,
                0,
            );
            let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("ghp_0123"), "{text}");
            assert!(!text.contains("chain_of_thought"), "{text}");
        }
    }

    #[test]
    fn direct_pane_render_rejects_raw_and_expanded_over_bound_text() {
        for text in [
            "x".repeat(MAX_PANE_OUTPUT_BYTES + 1),
            "\t".repeat(MAX_PANE_OUTPUT_BYTES),
            "row\n".repeat(MAX_PANE_LINES + 1),
        ] {
            let output = PaneOutput {
                id: "notes".into(),
                title: "Local notes".into(),
                state: PaneState::Ready,
                text,
                truncated: false,
                council: None,
                actions: vec![PaneAction::Refresh],
            };
            let area = Rect::new(0, 0, 80, 9);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            let mut cv = Cv::new(&mut buffer);
            draw_pane(&mut cv, area, "notes", Some(&output), 2, true, 0);
            let hits = cv.take_hits();
            assert_eq!(buffer_row(&buffer, 2), "error");
            assert_eq!(
                buffer_row(&buffer, 3),
                "invalid customization: pane output exceeds display bounds"
            );
            assert!(hits.iter().any(|hit| hit.click
                == Click::CustomAction {
                    panel: 1,
                    action: 0
                }));
            let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
            assert!(!text.contains("row"), "{text}");
            assert!(!text.contains("xxx"), "{text}");
        }
    }

    #[test]
    fn builtin_pane_lines_split_into_coloured_runs_without_changing_the_text() {
        let palette = crate::proto::shell::pal::Palette::default();
        let join = |parts: &[(&str, Rgb)]| parts.iter().map(|(text, _)| *text).collect::<String>();

        let seat = "KARINA·01    LEAD  ANTHROPIC  haiku-5-5          ● 승인 YES";
        let parts = builtin_segments("council", seat, &palette);
        assert_eq!(join(&parts), seat);
        assert_eq!(parts[0], ("KARINA·01", palette.cyan));
        assert_eq!(parts.last().unwrap(), &("● 승인 YES", palette.green));

        let ascii = "WINTER-03    EXACT ZHIPU      glm-5.3-flash      * HOLD";
        let parts = builtin_segments("council", ascii, &palette);
        assert_eq!(join(&parts), ascii);
        assert_eq!(parts[0].1, palette.violet);
        assert_eq!(parts.last().unwrap().1, palette.amber);

        let lost = "GISELLE·02   EDGE  DEEPSEEK   deepseek-v4-pro    ◌ 신호없음";
        assert_eq!(
            builtin_segments("council", lost, &palette)
                .last()
                .unwrap()
                .1,
            palette.red
        );
        let note = "nævis  Adopt SQLite in WAL mode";
        assert_eq!(
            builtin_segments("council", note, &palette)[0],
            ("nævis", palette.magenta_hi)
        );

        let ctx = "ctx     ████████░░░░░░░░░░░░  412k / 1M  41%";
        let parts = builtin_segments("reactor", ctx, &palette);
        assert_eq!(join(&parts), ctx);
        assert_eq!(parts[0], ("ctx", palette.muted));
        assert_eq!(parts[2], ("░░░░░░░░░░░░", palette.faint));

        // Other panes, and lines these panes do not define, stay one run.
        for (id, line) in [
            ("notes", seat),
            ("council", "plain words here"),
            ("reactor", ""),
        ] {
            assert_eq!(
                builtin_segments(id, line, &palette),
                vec![(line, palette.ink)]
            );
        }
    }

    #[test]
    fn builtin_panes_refresh_only_while_the_layout_shows_them() {
        let mut session = CustomizationSession::open(Arc::new(Host::new("x"))).unwrap();
        assert!(session.builtin_ids_in_layout().is_empty());
        session.resolved.profile.layout.tree = LayoutNode::Split {
            direction: orbit_frontend_protocol::customization::Direction::Right,
            shares: vec![50, 25, 25],
            children: vec![
                LayoutNode::panel(orbit_frontend_protocol::customization::View::Conversation),
                LayoutNode::Custom {
                    pane_id: "reactor".into(),
                },
                LayoutNode::Custom {
                    pane_id: "notes".into(),
                },
            ],
        };
        assert_eq!(session.builtin_ids_in_layout(), vec!["reactor".to_string()]);
    }

    fn council_output(text: &str) -> PaneOutput {
        PaneOutput {
            id: "council".into(),
            title: "Council".into(),
            state: PaneState::Ready,
            text: text.into(),
            truncated: false,
            council: None,
            actions: vec![PaneAction::Refresh],
        }
    }

    fn frame_rows(
        output: &PaneOutput,
        width: u16,
        height: u16,
        clock: Option<PaneClock>,
    ) -> Vec<String> {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane_at(&mut cv, area, "council", Some(output), 2, true, 0, clock);
        (0..height).map(|row| buffer_row(&buffer, row)).collect()
    }

    const COUNCIL_TEXT: &str = "MAGI · 심의 DELIBERATE\n\
KARINA·01    LEAD  ANTHROPIC  haiku-5-5          ● 승인 YES\n\
GISELLE·02   EDGE  DEEPSEEK   deepseek-v4-pro    ◌ 심의중\n\
WINTER·03    EXACT ZHIPU      glm-5.3-flash      ● 보류 HOLD\n\
NINGNING·04  BOLD  MINIMAX    minimax-m3         ◌ 신호없음\n\
심의  2/4 응답 · 표 2\n";

    #[test]
    fn council_pane_draws_seat_cards_when_they_fit_and_text_otherwise() {
        let output = council_output(COUNCIL_TEXT);
        let still = Some(PaneClock {
            now_ms: 4_000,
            reduced: true,
            reactor_art: ReactorArt::Kwangya,
        });
        let rows = frame_rows(&output, 80, 18, still);
        let all = rows.join("\n");
        assert!(rows[2].starts_with("MAGI · 심의 DELIBERATE"));
        for plate in ["KARINA·01", "GISELLE·02", "WINTER·03", "NINGNING·04"] {
            assert!(rows[3].contains(plate), "{plate} names its card");
        }
        assert!(rows[3].starts_with('╭') && rows[3].ends_with('╮'));
        for word in [
            "ANTHROPIC",
            "deepseek-v4-pro",
            "승 인",
            "YES",
            "보 류",
            "HOLD",
            "심의중",
            "SIGNAL LOST",
            "ERROR",
        ] {
            assert!(all.contains(word), "{word} is on a card");
        }
        assert!(all.contains("심의  2/4 응답 · 표 2"));
        assert!(all.contains("1 refresh"));
        // Reduced motion draws the same frame at any time.
        let later = Some(PaneClock {
            now_ms: 9_999,
            reduced: true,
            reactor_art: ReactorArt::Kwangya,
        });
        assert_eq!(frame_rows(&output, 80, 18, later), rows);
        // With motion the equaliser moves.
        let moving = |now_ms| {
            frame_rows(
                &output,
                80,
                18,
                Some(PaneClock {
                    now_ms,
                    reduced: false,
                    reactor_art: ReactorArt::Kwangya,
                }),
            )
        };
        assert_ne!(moving(1_000), moving(1_400));

        // Too narrow, too short, no clock, or ASCII text: the plain list.
        for rows in [
            frame_rows(&output, 40, 18, still),
            frame_rows(&output, 80, 8, still),
            frame_rows(&output, 80, 18, None),
        ] {
            assert!(!rows.join("\n").contains('╭'), "no card frames");
            assert!(rows.iter().any(|row| row.starts_with("KARINA·01")));
        }
        let ascii = council_output(
            "MAGI - DELIBERATE\nKARINA-01    LEAD  ANTHROPIC  haiku-5-5          * APPROVE\n",
        );
        assert!(frame_rows(&ascii, 80, 18, still)[3].starts_with("KARINA-01"));
    }

    #[test]
    fn council_content_preserves_small_panel_frames_and_action_rows() {
        use orbit_frontend_protocol::customization::CouncilSnapshot;
        use ratatui::buffer::Buffer;
        let mut state =
            crate::proto::ported::CouncilState::from_snapshot(&CouncilSnapshot::default());
        state.phase.name = "TRIAGED".into();
        state.phase.note = "TRIAL".into();
        let output = council_output("MAGI · 선별 TRIAGED");
        for (width, height) in [(4, 3), (12, 5), (24, 8), (40, 12), (80, 18)] {
            let panel = Rect::new(37, 11, width, height);
            let canvas = Rect::new(0, 0, 140, 60);
            let mut expected = Buffer::empty(canvas);
            let mut cv = Cv::new(&mut expected);
            let palette = cv.palette;
            let inner = panel_frame(
                &mut cv,
                panel,
                &FrameSpec {
                    num: 3,
                    title: "Council",
                    subtitle: "",
                    ident: palette.cyan,
                    focused: true,
                    focus_fx: FocusFx::settled(true),
                    badge: None,
                    attention: 0.0,
                    footer: Vec::new(),
                    footer_parts: Vec::new(),
                },
            )
            .unwrap();
            let mut actual = Buffer::empty(canvas);
            let mut cv = Cv::new(&mut actual);
            draw_pane_at_with_council(
                &mut cv,
                panel,
                "council",
                Some(&output),
                3,
                true,
                0,
                Some(PaneClock {
                    now_ms: 4_000,
                    reduced: true,
                    reactor_art: ReactorArt::Kwangya,
                }),
                Some(&state),
            );
            for y in 0..canvas.height {
                for x in 0..canvas.width {
                    if !inner.contains((x, y).into())
                        || (inner.height >= 2 && y == inner.bottom() - 2)
                    {
                        assert_eq!(
                            actual[(x, y)],
                            expected[(x, y)],
                            "{width}x{height} at {x},{y}"
                        );
                    }
                }
            }
            if inner.height >= 2 && inner.width >= 10 {
                let actions: String = (inner.x..inner.right())
                    .map(|x| actual[(x, inner.bottom() - 1)].symbol())
                    .collect();
                assert!(actions.contains("1 refresh"));
            }
        }
    }

    #[test]
    fn reactor_pane_draws_the_scene_and_big_digits_when_they_fit() {
        let text = "REACTOR · claude-opus-5-5  RESPOND\n\
tok/s   42.7         peak 118.0\n\
rate    ▁▄█\n\
out     18,204     in  412,880\n\
cache   read 1,204,113  write 88,020  reason 0  (this run)\n\
ctx     ████████░░░░░░░░░░░░  412k / 1M  41%\n\
cost    $0.8400  turns 12  tools 3\n";
        let output = PaneOutput {
            id: "reactor".into(),
            title: "Reactor".into(),
            state: PaneState::Ready,
            text: text.into(),
            truncated: false,
            council: None,
            actions: vec![PaneAction::Refresh],
        };
        let render = |width: u16, height: u16, clock: Option<PaneClock>| {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            let mut cv = Cv::new(&mut buffer);
            draw_pane_at(&mut cv, area, "reactor", Some(&output), 2, true, 0, clock);
            (0..height)
                .map(|row| buffer_row(&buffer, row))
                .collect::<Vec<_>>()
        };
        let still = Some(PaneClock {
            now_ms: 2_000,
            reduced: true,
            reactor_art: ReactorArt::Kwangya,
        });
        let rows = render(100, 22, still);
        let all = rows.join("\n");
        assert!(rows[2].starts_with("REACTOR · claude-opus-5-5  RESPOND"));
        let braille = all
            .chars()
            .filter(|c| ('\u{2801}'..='\u{28ff}').contains(c))
            .count();
        assert!(
            braille > 100,
            "the scene is drawn in braille ({braille} cells)"
        );
        // 42.7 in the 3x5 font, doubled: the top row of "4" then "2".
        assert!(all.contains("██  ██ ██████"));
        for word in [
            "tok/s   42.7",
            "peak 118.0",
            "18,204",
            "read 1,204,113",
            "41%",
            "$0.8400",
            "1 refresh",
        ] {
            assert!(all.contains(word), "{word} is shown");
        }
        // Reduced motion holds the frame; with motion the scene moves.
        let at = |now_ms, reduced| {
            render(
                100,
                22,
                Some(PaneClock {
                    now_ms,
                    reduced,
                    reactor_art: ReactorArt::Kwangya,
                }),
            )
        };
        assert_eq!(at(9_000, true), rows);
        assert_ne!(at(1_000, false), at(1_500, false));
        // Too small, or no clock: the text. 48 columns still carries the
        // scene (the picture takes the width), so only a very narrow pane
        // falls back.
        for rows in [render(100, 5, still), render(100, 22, None)] {
            let all = rows.join("\n");
            assert!(!all.chars().any(|c| ('\u{2801}'..='\u{28ff}').contains(&c)));
        }
        assert!(render(100, 22, None).join("\n").contains("tok/s   42.7"));
        // A narrow-but-usable pane keeps the scene and drops the meters
        // column rather than falling back to text.
        let narrow = render(30, 22, still).join("\n");
        assert!(
            narrow
                .chars()
                .any(|c| ('\u{2801}'..='\u{28ff}').contains(&c)),
            "a narrow pane still draws the scene"
        );
        assert!(
            narrow.contains("tok/s   42.7"),
            "the narrow scene keeps its rate"
        );
    }

    fn reactor_test_output(ascii: bool) -> PaneOutput {
        PaneOutput {
            id: "reactor".into(),
            title: "Reactor".into(),
            state: PaneState::Ready,
            text: format!(
                "REACTOR {} fixture  RESPOND\ntok/s   42.7 live    peak 118.0\nout     24      in  100\nctx     1 / 100  1%\ncost    $0.0000  turns 1  tools 0\n",
                if ascii { "-" } else { "·" }
            ),
            truncated: false,
            council: None,
            actions: vec![PaneAction::Refresh, PaneAction::CycleReactorArt],
        }
    }

    fn render_reactor_art(art: ReactorArt, now_ms: u64, reduced: bool, ascii: bool) -> Vec<String> {
        let area = Rect::new(0, 0, 100, 24);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        let mut cv = Cv::new(&mut buffer);
        draw_pane_at(
            &mut cv,
            area,
            "reactor",
            Some(&reactor_test_output(ascii)),
            3,
            true,
            0,
            Some(PaneClock {
                now_ms,
                reduced,
                reactor_art: art,
            }),
        );
        (0..area.height)
            .map(|row| buffer_row(&buffer, row))
            .collect()
    }

    #[test]
    fn reactor_art_choices_draw_distinct_graphics_and_keep_live_meters() {
        let palette = crate::proto::shell::pal::Palette::from_profile(&Profile::default());
        let mut shapes = Vec::new();
        for art in [
            ReactorArt::Kwangya,
            ReactorArt::Shard,
            ReactorArt::Spine,
            ReactorArt::Globe,
        ] {
            let mut dots = DotBuf::new(42, 20);
            reactor_scene(&mut dots, art, 4.0, 1.0, palette.cyan, palette.white);
            assert!(
                dots.on.iter().filter(|on| **on).count() > 50,
                "{art:?} paints its scene"
            );
            for prior in &shapes {
                assert_ne!(
                    &dots.on, prior,
                    "the graphic itself changes, not only a label"
                );
            }
            shapes.push(dots.on);
            let painted = render_reactor_art(art, 4_000, false, false).join("\n");
            for label in ["42.7", "peak 118.0", "100", "next art"] {
                assert!(painted.contains(label), "{art:?} keeps {label}");
            }
            assert_ne!(
                render_reactor_art(art, 4_000, false, false),
                render_reactor_art(art, 4_500, false, false),
                "{art:?} animates"
            );
        }
    }

    #[test]
    fn reactor_waiting_for_output_and_live_council_move_at_working_pace() {
        let render = |phase: &str, bench| {
            let area = Rect::new(0, 0, 80, 18);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            let text =
                format!("REACTOR · fixture  {phase}\ntok/s   —   peak —\nout     0      in  0\n");
            assert!(draw_reactor_view_with_bench(
                &mut Cv::new(&mut buffer),
                (0, 0, 80, 18),
                &text,
                PaneClock {
                    now_ms: 4_000,
                    reduced: false,
                    reactor_art: ReactorArt::Kwangya
                },
                bench,
            ));
            // Exclude labels, meters and the right-aligned Council bench:
            // only the art's activity should differ.
            (1..area.height)
                .map(|row| {
                    (1..=32)
                        .map(|column| buffer[(column, row)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
        };
        let resting = render("IDLE", None);
        assert_ne!(resting, render("ORIENT", None));
        assert_ne!(resting, render("RESPOND", None));
        assert_ne!(resting, render("COMPACT", None));
        assert_ne!(
            resting,
            render(
                "IDLE",
                Some(crate::proto::ported::CouncilBench {
                    phase: "DELIBERATING".into(),
                    ..crate::proto::ported::CouncilBench::default()
                })
            )
        );
    }

    #[test]
    fn reactor_rotation_reduced_motion_and_ascii_follow_the_selected_art() {
        let choices = [
            ReactorArt::Kwangya,
            ReactorArt::Shard,
            ReactorArt::Spine,
            ReactorArt::Globe,
        ];
        for (index, art) in choices.into_iter().enumerate() {
            let time = index as u64 * 40_000 + 2_000;
            assert_eq!(reactor_art_at(ReactorArt::Rotate, time, false), art);
            assert_eq!(
                render_reactor_art(ReactorArt::Rotate, time, false, false),
                render_reactor_art(art, time, false, false)
            );
        }
        assert_eq!(
            reactor_art_at(ReactorArt::Rotate, 160_000, false),
            ReactorArt::Kwangya
        );
        for art in choices.into_iter().chain([ReactorArt::Rotate]) {
            assert_eq!(
                render_reactor_art(art, 4_000, true, false),
                render_reactor_art(art, 99_999, true, false),
                "{art:?} stays still with reduced motion"
            );
            let ascii = render_reactor_art(art, 4_000, false, true).join("\n");
            assert!(ascii.contains("REACTOR - fixture  RESPOND"));
            assert!(ascii.contains("tok/s   42.7"));
            assert!(
                !ascii
                    .chars()
                    .any(|ch| ('\u{2800}'..='\u{28ff}').contains(&ch))
            );
        }
    }

    #[test]
    fn every_reactor_art_stays_inside_small_offset_panels_and_keeps_actions() {
        use ratatui::buffer::Buffer;
        for art in [
            ReactorArt::Kwangya,
            ReactorArt::Shard,
            ReactorArt::Spine,
            ReactorArt::Globe,
            ReactorArt::Rotate,
        ] {
            for (width, height) in [(4, 3), (24, 8), (48, 12), (100, 22)] {
                let canvas = Rect::new(0, 0, 160, 60);
                let panel = Rect::new(37, 11, width, height);
                let mut expected = Buffer::empty(canvas);
                let mut cv = Cv::new(&mut expected);
                let palette = cv.palette;
                let inner = panel_frame(
                    &mut cv,
                    panel,
                    &FrameSpec {
                        num: 3,
                        title: "Reactor",
                        subtitle: "",
                        ident: palette.cyan,
                        focused: true,
                        focus_fx: FocusFx::settled(true),
                        badge: None,
                        attention: 0.0,
                        footer: Vec::new(),
                        footer_parts: Vec::new(),
                    },
                )
                .unwrap();
                let mut actual = Buffer::empty(canvas);
                let mut cv = Cv::new(&mut actual);
                draw_pane_at(
                    &mut cv,
                    panel,
                    "reactor",
                    Some(&reactor_test_output(false)),
                    3,
                    true,
                    0,
                    Some(PaneClock {
                        now_ms: 4_000,
                        reduced: false,
                        reactor_art: art,
                    }),
                );
                for y in 0..canvas.height {
                    for x in 0..canvas.width {
                        if !inner.contains((x, y).into())
                            || (inner.height >= 2 && y == inner.bottom() - 2)
                        {
                            assert_eq!(
                                actual[(x, y)],
                                expected[(x, y)],
                                "{art:?} {width}x{height} at {x},{y}"
                            );
                        }
                    }
                }
                if inner.height >= 2 && inner.width >= 10 {
                    let actions: String = (inner.x..inner.right())
                        .map(|x| actual[(x, inner.bottom() - 1)].symbol())
                        .collect();
                    assert!(actions.contains("1 refresh"));
                }
            }
        }
    }

    #[test]
    fn every_built_in_theme_validates_and_the_aespa_palettes_carry_their_colours() {
        use orbit_frontend_protocol::customization::THEMES;
        let themed = |theme: &str| Profile {
            theme: theme.into(),
            ..Profile::default()
        };
        for theme in THEMES {
            themed(theme).validate().expect("built-in theme validates");
        }
        assert!(themed("unknown").validate().is_err());
        let palette = crate::proto::shell::pal::Palette::from_profile;
        let pastel = palette(&themed("aespa-pastel"));
        assert_eq!(pastel.magenta, (0xFF, 0xB6, 0xD5));
        assert_eq!(pastel.app, (0x12, 0x10, 0x19));
        let ice = palette(&themed("kwangya-ice"));
        assert_eq!(ice.magenta, (0x92, 0xD3, 0xF7));
        assert_eq!(ice.violet, (0xA2, 0xA6, 0xF6));
        // A colour override still wins over the theme.
        let mut custom = themed("kwangya-ice");
        custom
            .token_overrides
            .insert("magenta".into(), "#102030".into());
        assert_eq!(palette(&custom).magenta, (0x10, 0x20, 0x30));
        assert_ne!(palette(&themed("midnight")), ice);
    }
}
