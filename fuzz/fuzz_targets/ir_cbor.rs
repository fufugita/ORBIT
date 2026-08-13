//! Fuzz target: IR CBOR encoder (orbit-ir).
//!
//! Feeds arbitrary bytes as a JSON Value and asserts the encoder never
//! panics (floats → Err, deep nesting bounded, sorted keys stable).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = orbit_ir::cbor::encode(&v);
        }
    }
});
