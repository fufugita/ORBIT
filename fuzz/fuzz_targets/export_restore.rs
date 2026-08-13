//! Fuzz target: export bundle restore (orbit-export).
//!
//! Feeds arbitrary bytes as an export envelope and asserts restore never
//! panics — a corrupt bundle must return Err, never crash (E0508).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (_, identity) = orbit_export::generate_local_key();
    let _ = orbit_export::restore(data, &identity, "new-session", "src-session");
});
