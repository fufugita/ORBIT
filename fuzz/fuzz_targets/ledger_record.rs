//! Fuzz target: Ledger record decode (orbit-ledger).
//!
//! Feeds arbitrary bytes as a LedgerRecord and asserts serde decode never
//! panics — malformed frames must return Err, never crash.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _: Result<orbit_ledger::LedgerRecord, _> = serde_json::from_slice(data);
});
