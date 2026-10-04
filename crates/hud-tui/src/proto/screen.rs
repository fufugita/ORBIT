//! The screen geometry of §8: the row budget of §8.1 and the width
//! classes of §8.2. Layout is a function of the terminal size — no
//! user tree, no arrange mode.

use ratatui::layout::Rect;

/// The width classes (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthClass {
    /// W ≥ 140: Sessions │ Conversation │ Workspace
    Wide,
    /// 110–139: Conversation │ Workspace (Sessions pushes in when focused)
    Medium,
    /// 80–109: one view, switcher in row 0
    Narrow,
    /// 60–79: one view, no timestamps
    Compact,
    /// 40–59: one view, no hint row
    Tight,
    /// W < 40 or H < 10: the size notice only
    TooSmall,
}

impl WidthClass {
    pub fn of(w: u16, h: u16) -> Self {
        if w < 40 || h < 10 {
            WidthClass::TooSmall
        } else if w >= 140 {
            WidthClass::Wide
        } else if w >= 110 {
            WidthClass::Medium
        } else if w >= 80 {
            WidthClass::Narrow
        } else if w >= 60 {
            WidthClass::Compact
        } else {
            WidthClass::Tight
        }
    }

    /// Single-view layouts show the switcher in row 0 (§9.2).
    pub fn single_view(self) -> bool {
        matches!(
            self,
            WidthClass::Narrow | WidthClass::Compact | WidthClass::Tight
        )
    }

    /// The status-line level (§9.18).
    pub fn status_level(self) -> u8 {
        match self {
            WidthClass::Wide => 0,
            WidthClass::Medium => 1,
            WidthClass::Narrow | WidthClass::Compact => 2,
            WidthClass::Tight => 3,
            WidthClass::TooSmall => 3,
        }
    }
}

/// The three focus targets of §11.1 (Status is reachable by Tab but
/// owns no pane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Sessions,
    Conversation,
    Workspace,
    Status,
}

impl Focus {
    /// Tab order: Sessions → Conversation → Workspace → Status.
    pub fn next(self) -> Self {
        match self {
            Focus::Sessions => Focus::Conversation,
            Focus::Conversation => Focus::Workspace,
            Focus::Workspace => Focus::Status,
            Focus::Status => Focus::Sessions,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Focus::Sessions => Focus::Status,
            Focus::Conversation => Focus::Sessions,
            Focus::Workspace => Focus::Conversation,
            Focus::Status => Focus::Workspace,
        }
    }

    /// In single-view layouts Tab cycles the three views and skips
    /// Status (§11.1).
    pub fn next_view(self) -> Self {
        match self {
            Focus::Sessions => Focus::Conversation,
            Focus::Conversation => Focus::Workspace,
            Focus::Workspace => Focus::Sessions,
            Focus::Status => Focus::Sessions,
        }
    }
}

/// A pane's rectangle (inside the body rows, no header).
#[derive(Debug, Clone, Copy)]
pub struct Pane {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// The whole screen's geometry, resolved once per draw.
#[derive(Debug, Clone)]
pub struct Screen {
    pub class: WidthClass,
    /// Row 0 area (headers or switcher).
    pub header: Rect,
    /// The body rows (2 … H−5 by default).
    pub body: Rect,
    /// The left rail (Sessions/Activity), Wide only unless pushed.
    pub left: Option<Pane>,
    /// The conversation column.
    pub conv: Pane,
    /// The right rail (Workspace).
    pub right: Option<Pane>,
    /// Divider columns: (x, y_top, y_bottom).
    pub dividers: Vec<(u16, u16, u16)>,
    /// The composer input row (H−3), the hint row (H−2), the status
    /// line (H−1). Tight has no hint row.
    pub composer: Rect,
    pub hint: Option<Rect>,
    pub status: Rect,
    /// The air row above the composer (H−4) — rails continue through.
    pub air_y: u16,
}

impl Screen {
    /// Resolve the geometry (§8.1 rows, §8.2 classes). `sessions_pushed`
    /// is the Medium-with-Sessions-focused push.
    pub fn resolve(area: Rect, sessions_pushed: bool) -> Screen {
        let class = WidthClass::of(area.width, area.height);
        let height = area.height;
        let width = area.width;
        let tight = class == WidthClass::Tight;
        // §8.1: composer at H−3 input and H−2 hint; Tight: H−2 input,
        // no hint. Status H−1. Body 2 … H−5 (tight: 2 … H−4).
        let (input_y, hint, body_bottom) = if tight {
            (height - 2, None, height - 4)
        } else {
            (
                height - 3,
                Some(Rect {
                    x: area.x,
                    y: height - 2,
                    width,
                    height: 1,
                }),
                height - 5,
            )
        };
        let header = Rect {
            x: area.x,
            y: area.y,
            width,
            height: 1,
        };
        // Row 1 is air for every pane; bodies start at row 2.
        let body = Rect {
            x: area.x,
            y: area.y + 2,
            width,
            height: body_bottom.saturating_sub(area.y + 2),
        };
        let air_y = input_y.saturating_sub(1);

        let mut left = None;
        let mut right = None;
        let mut dividers = Vec::new();
        let conv;
        match class {
            WidthClass::Wide => {
                let l = clamp(28, (width as u32 * 20 / 100) as u16, 34);
                let r = clamp(32, (width as u32 * 24 / 100) as u16, 44);
                let c = width.saturating_sub(l + r + 2);
                left = Some(Pane {
                    x: area.x,
                    y: body.y,
                    w: l,
                    h: body.height,
                });
                conv = Pane {
                    x: area.x + l + 1,
                    y: body.y,
                    w: c,
                    h: body.height,
                };
                right = Some(Pane {
                    x: area.x + l + 1 + c + 1,
                    y: body.y,
                    w: r,
                    h: body.height,
                });
                dividers.push((area.x + l, body.y, body.y + body.height.saturating_sub(1)));
                dividers.push((
                    area.x + l + 1 + c,
                    body.y,
                    body.y + body.height.saturating_sub(1),
                ));
            }
            WidthClass::Medium if sessions_pushed => {
                // The push: Sessions │ Conversation, Workspace hidden.
                let l = 30;
                let c = width - 31;
                left = Some(Pane {
                    x: area.x,
                    y: body.y,
                    w: l,
                    h: body.height,
                });
                conv = Pane {
                    x: area.x + l + 1,
                    y: body.y,
                    w: c,
                    h: body.height,
                };
                dividers.push((area.x + l, body.y, body.y + body.height.saturating_sub(1)));
            }
            WidthClass::Medium => {
                let r = clamp(30, (width as u32 * 30 / 100) as u16, 36);
                let c = width - r - 1;
                conv = Pane {
                    x: area.x,
                    y: body.y,
                    w: c,
                    h: body.height,
                };
                right = Some(Pane {
                    x: area.x + c + 1,
                    y: body.y,
                    w: r,
                    h: body.height,
                });
                dividers.push((area.x + c, body.y, body.y + body.height.saturating_sub(1)));
            }
            // Narrow/Compact/Tight: one full-width view.
            _ => {
                conv = Pane {
                    x: area.x,
                    y: body.y,
                    w: width,
                    h: body.height,
                };
            }
        }
        Screen {
            class,
            header,
            body,
            left,
            conv,
            right,
            dividers,
            composer: Rect {
                x: area.x,
                y: input_y,
                width,
                height: 1,
            },
            hint,
            status: Rect {
                x: area.x,
                y: height - 1,
                width,
                height: 1,
            },
            air_y,
        }
    }

    /// The conversation column's content geometry (§8.3): `cl` the
    /// content left, `cw` the measure.
    pub fn conv_column(&self) -> (u16, u16) {
        let x = self.conv.x;
        let w = self.conv.w;
        let mut cl = x + 3;
        let cw = (w - 5).min(100);
        if w - 5 > 100 {
            cl = x + 3 + (w - 5 - 100) / 2;
        }
        (cl, cw)
    }
}

fn clamp(lo: u16, v: u16, hi: u16) -> u16 {
    v.max(lo).min(hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_150_matches_the_spec_numbers() {
        // §8.2: at 150 → 30 │ 82 │ 36, dividers at 30 and 113.
        let s = Screen::resolve(
            Rect {
                x: 0,
                y: 0,
                width: 150,
                height: 40,
            },
            false,
        );
        assert_eq!(s.left.unwrap().w, 30);
        assert_eq!(s.conv.w, 82);
        assert_eq!(s.right.unwrap().w, 36);
        assert_eq!(s.dividers[0].0, 30);
        assert_eq!(s.dividers[1].0, 113);
    }

    #[test]
    fn medium_120_is_83_36() {
        let s = Screen::resolve(
            Rect {
                x: 0,
                y: 0,
                width: 120,
                height: 36,
            },
            false,
        );
        assert_eq!(s.conv.w, 83);
        assert_eq!(s.right.unwrap().w, 36);
        assert_eq!(s.dividers[0].0, 83);
    }

    #[test]
    fn tight_has_no_hint_row() {
        let s = Screen::resolve(
            Rect {
                x: 0,
                y: 0,
                width: 50,
                height: 20,
            },
            false,
        );
        assert!(s.hint.is_none());
        assert_eq!(s.composer.y, 18);
        assert_eq!(s.status.y, 19);
    }

    #[test]
    fn rows_follow_the_budget() {
        let s = Screen::resolve(
            Rect {
                x: 0,
                y: 0,
                width: 150,
                height: 40,
            },
            false,
        );
        // H−3 input, H−2 hint, H−1 status, body 2 … H−5.
        assert_eq!(s.composer.y, 37);
        assert_eq!(s.hint.unwrap().y, 38);
        assert_eq!(s.status.y, 39);
        assert_eq!(s.body.y, 2);
        assert_eq!(s.body.height, 33); // 2 … 34 inclusive = 33 rows
    }

    #[test]
    fn conv_column_measure_is_capped() {
        // §8.3: cw = min(w − 5, 100). At conv width 82 there is no
        // centring (82 − 5 < 100); cl = x + 3.
        let s = Screen::resolve(
            Rect {
                x: 0,
                y: 0,
                width: 150,
                height: 40,
            },
            false,
        );
        let (cl, cw) = s.conv_column();
        assert_eq!(cw, 77);
        assert_eq!(cl, s.conv.x + 3);
    }
}
