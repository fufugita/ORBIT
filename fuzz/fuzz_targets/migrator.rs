//! Fuzz target: migration construct decode (orbit-migrator).
//!
//! Feeds arbitrary bytes as a ClaudeConstruct list and asserts decode +
//! migration never panic — unresolvable constructs fail closed (E18xx),
//! never crash.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(constructs) =
        serde_json::from_slice::<Vec<orbit_migrator::ClaudeConstruct>>(data)
    {
        let _ = orbit_migrator::Migrator.migrate(&constructs);
    }
});
