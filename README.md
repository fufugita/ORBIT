# ORBIT

**The harness that orbits around you.**

ORBIT is an open-source AI orchestration harness. The user is the locus of
authority: natural-language or typed directives become typed, confirmed,
Ledger-recorded grants; the harness enforces the user's declared policy,
proves what it did, and protects the user's information with a strict,
non-overridable compliance kernel.

> **Prove what your agent did. Replay it differently. Route it cheaper.**

## Status

This repository is **scaffolded — no product code exists yet.** The v0.1
specification is in final audit (DR-01..DR-14). See the freeze gate in
`vaults/ORBIT/decisions/03-v0.1-definition-of-done.md`; implementation begins
only after the specification-frozen gate is satisfied.

## Kernel (non-overridable)

- Credentials, keys, hashes, and internal identifiers **never** leave the
  user's machine to external providers.
- Truthful append-only Ledger. No hidden actions.
- Prompt bytes never enter the Ledger, exports, logs, or HUD — only digests.
- Untrusted quoted/tool/provider/subagent content can never become user
  authority.
- `Attested` trust level is reserved in v0.1.

## Layout

```
crates/            Rust workspace (reactor, capability, sandbox, context,
                   gateway, ledger, trust, session, pib, memory, export,
                   plugin, egress, hud, cli, orbit-core, orbit-api,
                   orbit-ledger, orbit-ir)
sdk/typescript     TypeScript SDK (lead)
sdk/python         Python SDK (parity)
sdk/wit            WIT shims
conformance/       Cross-language IR conformance corpus
migrator/          Claude Workflow → ORBIT migration
spec/              Machine-readable error registry + traceability
```

## License

Core: Apache-2.0. WIT/SDK shims: dual-licensed `(MIT OR Apache-2.0)`.
See DR-13 §4.
