# ORBIT

**The harness that orbits around you.**

ORBIT is an open-source AI orchestration harness where the user is the locus
of authority. Natural-language or typed directives become typed, confirmed,
Ledger-recorded grants; the harness enforces the user's declared policy,
proves what it did, and protects the user's information with a strict,
non-overridable compliance kernel.

> **Prove what your agent did. Replay it differently. Route it cheaper.**

---

## Status

**Active development.** The v0.1 specification is frozen and all three
release gates are satisfied: specification-frozen, implementation-complete,
and audited release-ready. The v0.2 track (async provider adapters, WASI
plugin runtime, terminal UI) is in progress on `main`.

| Track | State |
|---|---|
| v0.1 spec (DR-01..DR-14) | Frozen, all gates YES |
| v0.1 release candidate | Tagged `v0.1.0-rc.1` |
| v0.2 async + plugins | Complete, on `v0.2-dev` |
| v0.2 terminal UI | In progress, on `main` |

## What is ORBIT

ORBIT gives senior technical operators a trustworthy, auditable,
provider-aware orchestration environment. It can prove what an agent did,
replay the same work under controlled differences, and route the orchestrator
deliberately without silently weakening trust or semantics.

The product spine:

- **Trust Spine** — trust root, append-only Ledger, PIB identity, encrypted
  export/restore.
- **Phase Router + HUD** — five-phase reactor FSM, display-safe event
  rendering, brand/output-mode negotiation.
- **Trace / Replay** — hash-chained Ledger events, deterministic replay
  planning, no-dispatch dry runs.
- **Six Primitives** — Prompt-Execution Block (PEB), Task-To-Execute (TTE),
  Memory-Log (ML), Retest-Attestation (RTA), Evidence-Publish-Block (EPB),
  Subagent-Dispatch-Envelope (SDE).

A strict proof/privacy kernel is non-overridable: credentials, keys, hashes,
and internal identifiers never leave the user's machine to external
providers; the Ledger is truthful and append-only; prompt bytes never enter
the Ledger, exports, logs, or HUD; untrusted quoted/tool/provider/subagent
content can never become user authority.

## Features

- **Multi-provider configuration** — declare one or more OpenAI-compatible
  providers in `providers.toml`; the CLI aggregates models and resolves the
  right provider at dispatch time. Credentials are referenced by environment
  variable name, never stored on disk.
- **Four-gate gateway admission** — trust → capability → egress → fsync, with
  retry bounded to two same-route attempts and never-retry on unsafe errors.
- **Interactive REPL** — streaming multi-turn conversation with slash
  commands (`/help`, `/model`, `/clear`, `/usage`, `/models`, `/sessions`),
  session persistence, and resume.
- **Terminal UI** — a ratatui + crossterm front-end with a three-pane layout
  (Sessions/Verbose, Conversation, Tasks), dedicated composer, animated
  status, markdown/code/slash-command rendering, and a customizable theme.
  Launches automatically when stdin/stdout are a TTY; `--no-tui` opts out.
- **Tool calling with approval** — `y` (allow once), `n` (deny), `R`
  (always-allow-this-tool-this-session, ledger-logged, revocable), `Esc`
  (deny). Session-scoped grants never bypass the known-tool check.
- **Usage and cost accounting** — per-turn and cumulative token counts and
  microcent costs, surfaced in the status bar and session files.
- **WASI plugin runtime** — wasmtime 47 with an import allowlist, bounded
  instance pool, and WASI-kill lifecycle.
- **Trace, replay, export, restore** — verify the Ledger hash chain, emit a
  no-dispatch replay plan, encrypt an age bundle, restore into a fresh
  namespace.
- **SDKs** — TypeScript (lead) and Python (parity) expose the IR types and
  workflow descriptors for cross-language conformance.
- **Release evidence** — `orbit version --evidence` emits version, build
  metadata, SBOM hash, provenance, and reproducibility claims.

## Quickstart

```sh
# Build (requires Rust 1.94 — see rust-toolchain.toml)
cargo build --release

# Initialize the trust root, PIB, and Ledger
./target/release/orbit init

# Start the interactive harness (TUI when a TTY is detected)
./target/release/orbit

# Or the explicit alias
./target/release/orbit chat

# Send a single prompt through the pipeline
./target/release/orbit ask "reply with exactly: pong" --model <model>

# List configured models
./target/release/orbit models
```

The harness reads provider configuration from `$ORBIT_HOME/providers.toml`
(default `~/.orbit/`). A missing config falls back to the
`ORBIT_GATE_URL` / `ORBIT_MODEL` / `ORBIT_GATE_TOKEN` environment contract.

## CLI reference

```
orbit [chat]           start the interactive harness (TUI or REPL)
orbit ask PROMPT       send one prompt through a configured gateway
orbit init             initialize trust root + PIB + Ledger
orbit models           list models from all configured providers
orbit run              run the example phase chain
orbit cancel           cancel the session (terminal: cancelled)
orbit verify-ledger    verify the Ledger hash chain
orbit replay --dry     verify + emit a no-dispatch replay plan
orbit export --to      encrypt an age bundle
orbit restore          restore into a fresh namespace
orbit version          release evidence (claims + hashes)
```

Common flags: `--model <M>`, `--gate <URL>`, `--provider <name>`,
`--no-tui`, `--auto-tools`.

## Architecture

```
crates/
  reactor          five-phase FSM (init|plan|execute|verify|checkpoint)
  capability       capability card schema + trust-root manifest
  sandbox          Landlock/seccomp profiles, deny-by-default
  context          segmented context, token-window ceiling, eviction
  gateway          four-gate admission, retry policy, cost checking
  ledger           append-only hash-chained event log, single-writer
  trust            trust root, issuer allowlist, policy snapshot
  session          session FSM, restricted ACL, cost tracking
  pib              PibId identity, cross-machine allowlist
  memory           layered global<project<path-local resolution
  export           age-encrypted bundle, immutable restore
  plugin           wasmtime 47 WASI runtime, import allowlist, pool
  egress           EgressIntent digest, allowlist, route-pin
  hud              display gate, output mode, brand, event renderer
  hud-tui          ratatui + crossterm terminal UI front-end
  cli              command dispatch, REPL, TUI gate
  orbit-core       authority kernel, six primitives
  orbit-api        request/response envelopes, route table
  orbit-ledger     primitive-specific Ledger events
  orbit-ir         deterministic CBOR encoder, cross-language IR
  adapter          provider stream event types, cost rates
  provider-http    async OpenAI-compatible adapter, TLS pinning
  mock-provider    v0.2 conformance target
  release          version evidence, SBOM, provenance
sdk/
  typescript       TypeScript SDK (lead)
  python           Python SDK (parity)
  wit              WIT boundary shims
conformance/       cross-language IR conformance corpus
migrator/          Claude Workflow → ORBIT migration
spec/              machine-readable error registry + traceability
evidence/          release evidence bundle (v0.1)
```

## Configuration

### `$ORBIT_HOME`

Defaults to `~/.orbit`. Holds the trust root, PIB, Ledger, sessions, and
provider config.

### `providers.toml`

```toml
[[provider]]
name = "local"
url = "http://127.0.0.1:4001"
env = "ORBIT_GATE_TOKEN"   # env-var NAME, never the value

[[provider.models]]
id = "model-a"

[provider.models.pricing]
input_per_million_microcents = 200000
output_per_million_microcents = 600000
```

### `tui.toml`

Customizable theme and layout: accent colors, composer color, spinner style,
pane proportions, tab behavior. Missing or malformed values fall back to
defaults.

### Environment

| Variable | Purpose |
|---|---|
| `ORBIT_HOME` | Config directory (default `~/.orbit`) |
| `ORBIT_GATE_URL` | Gateway base URL (fallback) |
| `ORBIT_MODEL` | Default model id (fallback) |
| `ORBIT_GATE_TOKEN` | Bearer token (referenced by `providers.toml`) |
| `ORBIT_ASCII_EMOJI` | Set to `0` to disable ASCII emoji fallback |

## Development

```sh
# Toolchain is pinned to Rust 1.94 via rust-toolchain.toml
cargo build
cargo test --workspace
cargo clippy --workspace --tests -- -D warnings
cargo fmt --check

# Dependency policy (permissive-only, default deny)
cargo deny check
```

The workspace forbids `unsafe` in all crates. The dependency policy
(`deny.toml`) allows MIT, Apache-2.0, BSD-2/3, ISC, 0BSD, Unlicense, and
CC0-1.0; anything else fails the check.

## Project layout

```
.
├── crates/            Rust workspace (22 crates)
├── sdk/               TypeScript + Python SDKs, WIT shims
├── conformance/       cross-language IR conformance corpus
├── migrator/          Claude Workflow → ORBIT migration
├── spec/              error registry + traceability
├── evidence/          release evidence bundle
├── deploy/            mock provider deployment
├── scripts/           build, e2e, fuzz, packaging scripts
├── fuzz/              coverage-guided fuzzing
├── Cargo.toml         workspace manifest
├── deny.toml          cargo-deny policy
└── rust-toolchain.toml
```

## License

Core: **Apache-2.0**. WIT/SDK shims: dual-licensed `(MIT OR Apache-2.0)`.
