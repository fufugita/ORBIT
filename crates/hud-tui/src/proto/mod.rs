//! The ORBIT terminal screen (the motion-first redesign), built from the
//! prototype's "building it in ratatui" map.
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
pub mod app;
pub mod chrome;
pub mod composer;
pub mod comps;
pub mod core;
pub mod keybindings;
pub mod layout;
pub mod mark;
pub mod panels;
pub mod ported;
pub mod runtime;
pub mod saved_sessions;
pub mod scenario;
pub mod screen;
pub mod shell;
pub mod view;
pub mod vim;
pub mod welcome;
