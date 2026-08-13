# ORBIT v0.1 Adapter Conformance Fixtures

Every released adapter/profile must pass the same harness in `conformance/src/adapter.rs`.
The fixtures are pinned, deterministic, offline, and contain no credentials or prompt bytes.

Schema: `orbit.adapter-conformance/v1`.

Coverage: success, partial stream, rate-limit, timeout, mixed currency, drift,
credential non-disclosure, fixed-point sampling, skipped/duplicate/post-terminal
sequence violations, decreasing usage, EOF without Finished, rejected route,
and TLS SPKI mismatch.
