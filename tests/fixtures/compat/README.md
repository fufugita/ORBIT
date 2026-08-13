# ORBIT persisted-format compatibility fixtures

These fixtures pin every v0.1 persisted format named by the accepted DRs.

- `ledger-record-v1.json` — DR-06 `ledger/record/v1` shape
- `trust-manifest-v0_1.json` — DR-05 `orbit.trust/v0.1`
- `export-envelope-v1.json` — DR-02 §8 / `orbit.export/v1`
- `ir-spawn-v0_1.json` — DR-11 `orbit:ir@0.1.0` JSON mirror
- `memory-entry-v1.json` — DR-08 memory metadata + digest
- `session-header-v1.json` — DR-08 session header

The Rust integration tests parse these fixtures, reserialize them, and assert
stable schema tags and mandatory fields. Corruption tests cover bad Ledger
self-hash/torn frames, bad export ciphertext, invalid trust signatures, and
memory digest mismatch. Forward-compatible unknown fields are accepted by the
serde model; unsupported major versions are rejected by the IR version gate.
