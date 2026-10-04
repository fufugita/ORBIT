//! The mark box's frame data (§10.2–10.3), verbatim from the design
//! doc: the 12 orbit stations and the 17 startup frames. Hard rule
//! 10: no glyph literal outside the glyph table modules.

/// The static mark rows (33 columns).
pub const MARK_ROWS: [&str; 3] = [
    "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
    "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
    "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
];

/// M9's station frames — the 33-column box at each of the 12
/// stations, star cyan. Rows shown without trailing spaces.
pub const M9_STATIONS: [[&str; 3]; 12] = [
    [
        "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄✦⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠✦⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "✦⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "✦⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒✦▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀✦▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄✦    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠✦⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤⣄ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴✦ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
];

/// M1's 17 startup frames, verbatim. F4's star is magenta_hi; F5+ is
/// magenta; the leading space of each row belongs to the box.
pub const M1_FRAMES: [[&str; 3]; 17] = [
    ["   ▄▀▀▀▄", "   █   █", "   ▀▄▄▄▀"],
    ["   ▄▀▀▀▄", "⣠  █   █", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤", "⣠⠖⠋█   █", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤✦", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄✦⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠✦⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "✦⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "✦⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒✦▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀✦▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴⠋", "⠙⠒⠒▀▄▄▄✦"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠✦⠋", "⠙⠒⠒▀▄▄▄▀"],
    ["   ▄▀▀▀▄⠤⠤⣄", "⣠⠖⠋█   █⣠⠴✦", "⠙⠒⠒▀▄▄▄▀"],
    [
        "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
    [
        "   ▄▀▀▀▄⠤⠤✦ █▀▀▀▄ █▀▀▀▄ ▀█▀ ▀▀█▀▀",
        "⣠⠖⠋█   █⣠⠴⠋ █▄▄▄▀ █▀▀▀▄  █    █",
        "⠙⠒⠒▀▄▄▄▀    █  ▀▄ █▄▄▄▀ ▄█▄   █",
    ],
];

/// The tagline, added at F17.
pub const TAGLINE: &str = "the harness that orbits around you";

#[cfg(test)]
mod tests {
    use super::*;

    /// The stations are 33 columns and differ from the static mark in
    /// at most two cells (§10.2).
    #[test]
    fn stations_match_static_width_and_two_cell_delta() {
        for (si, frame) in M9_STATIONS.iter().enumerate() {
            for (ri, row) in frame.iter().enumerate() {
                let row = row.trim_end();
                assert!(
                    row.chars().count() <= 33,
                    "station {si} row {ri} wider than 33: {row:?}"
                );
            }
            let mut diff = 0;
            for ri in 0..3 {
                let a: Vec<char> = MARK_ROWS[ri].chars().collect();
                let b: Vec<char> = frame[ri].trim_end().chars().collect();
                for ci in 0..a.len().max(b.len()) {
                    if a.get(ci) != b.get(ci) {
                        diff += 1;
                    }
                }
            }
            assert!(diff <= 2, "station {si} changes {diff} cells (max 2)");
        }
    }

    /// M1's F17 equals the static mark.
    #[test]
    fn f17_is_the_static_mark() {
        for (ri, _) in M1_FRAMES.iter().enumerate().take(3) {
            assert_eq!(M1_FRAMES[16][ri], MARK_ROWS[ri]);
        }
    }

    /// M1's star frames (F5–F16, stations 1–11 then rest) each differ
    /// from the previous in at most two cells. F1–F4 build the ring
    /// and legitimately change more.
    #[test]
    fn m1_frames_step_two_cells() {
        for fi in 4..15 {
            let mut diff = 0;
            for (ri, row) in M1_FRAMES[fi].iter().enumerate().take(3) {
                let a: Vec<char> = M1_FRAMES[fi - 1][ri].chars().collect();
                let b: Vec<char> = row.chars().collect();
                for ci in 0..a.len().max(b.len()) {
                    if a.get(ci) != b.get(ci) {
                        diff += 1;
                    }
                }
            }
            assert!(diff <= 2, "M1 F{fi}→F{} changes {diff} cells", fi + 1);
        }
    }
}
