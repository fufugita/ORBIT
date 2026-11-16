# Release verification

Release readiness requires completed checks against the reviewed source revision
and the exact binaries that will be installed. A build, environment preflight or
offline configuration check alone is insufficient.

## Supported scope

The distribution bundle supports Linux glibc on x86-64 and ARM64. Both native
architectures must pass their distribution jobs. The bundle does not advertise
macOS or Windows support.

## Run native verification

Use Linux with Python 3.11+, Node.js 22, a C compiler, bubblewrap, cargo-deny
0.20.2 and the repository-pinned Rust toolchain with rustfmt and Clippy.
The machine must permit loopback and Unix sockets, PTYs, child processes and
unprivileged user namespaces.

From the repository root:

```sh
bash scripts/verify-release.sh
```

The verifier selects the pinned toolchain explicitly, checks environment
capabilities, and checks dependency policy before compiling. It then runs
formatting, strict Clippy, a workspace build, release-script contracts, serial
workspace tests, required terminal/sandbox coverage, npm distribution contracts,
optimized builds, installed-release acceptance, documented commands and packaging.

The process-isolation wrapper protects the desktop from tests that exercise
process-group cancellation. Required environment capabilities cannot silently
turn into passing skips. The coverage checker requires successful real-terminal
compact, Escape and clear cases plus all three confinement cases.

Logs and the candidate archive are retained under
`target/release-verification.*`. Source fingerprints before and after must
match. Keep source files and build outputs stable during the run; concurrent
builds can invalidate binary identity checks. The verifier uses temporary
installation prefixes rather than replacing the operator's installation, and
does not publish packages.

A dependency or runtime change requires fresh affected checks and rebuilt
binaries. Saved evidence may be reused only where source and binary identity
remain valid; never relabel a blocked test as a pass.

## Validate installation and migration

Installed acceptance checks the actual two-component bundle away from the
checkout. It covers private initialization, identity preservation, provider
configuration, doctor, routing, customization, documented commands, repeated
installation and failed-upgrade recovery. The archive checksum and each
component's size and hash must match its manifest and acceptance receipt.
The package identity check compares the final archived components with the
installed-test receipt, so a rebuild between acceptance and packaging fails.
Unsigned archives must continue to report that their signature is absent.

Use the [migration guide](migration.md) for a read-only configuration assessment
and a trial with the intended provider. Daily-use acceptance additionally covers
a real short prompt, a harmless tool turn, cancellation and continuation,
resume, compaction, permissions, hooks and required integrations. Offline
doctor/migration output explicitly does not establish provider connectivity.

## Validate the reviewed commit

A main push triggers quality checks and native x86-64/ARM64 distribution jobs.
Each native job runs installed acceptance and npm installation checks before
packaging. Package assembly depends on quality and both native jobs. Retain the
exact commit SHA, job results and package hashes when recording acceptance.

Before committing, review the selected product files, check formatting and
strict linting, run relevant regressions, and inspect the staged tree for
credentials, local agent state, generated outputs and authorship artifacts.
Preserve unrelated operator changes and use the operator's Git identity.

Publishing is a separate explicit workflow dispatch with `publish=true`;
ordinary validation does not publish. Final sign-off requires the reviewed
revision, both native jobs, the quality job and the live-provider daily-use
trial to pass, with no unresolved important review findings.
