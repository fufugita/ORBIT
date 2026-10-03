//! The ORBIT TUI prototype (motion-first redesign): a fresh module
//! set beside the v1 HUD, per the prototype's "building it in
//! ratatui" map.
//!
//! - [`anim`]: curves, the star clock (§10.1) — pure functions of
//!   state and tick, so a golden test can render any frame at any
//!   tick.
//! - [`core`]: the glyph and token vocabulary.
//! - [`scenario`]: the event reducer a scripted session drives.
//!
//! Every animation is tied to an engine event, has a rate and an end,
//! and collapses to its end state under reduced motion.

pub mod anim;
pub mod core;
pub mod scenario;
