#!/usr/bin/env bash
# Run native Linux release checks sequentially, preserving logs and source identity.
# No commit, installation into the operator's home, or publication is performed.
set -Eeuo pipefail
umask 077
ORBIT_CHECK_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ORBIT_CHECK_ROOT"
test "$(uname -s)" = Linux || { printf '%s\n' 'This verification entry point supports Linux only.' >&2; exit 2; }
mkdir -p "$ORBIT_CHECK_ROOT/target"
ORBIT_CHECK_LOGS="$(mktemp -d "$ORBIT_CHECK_ROOT/target/release-verification.XXXXXX")"
ORBIT_CHECK_STAGE=source-before
trap 'printf "Stopped at %s. Logs: %s\n" "$ORBIT_CHECK_STAGE" "$ORBIT_CHECK_LOGS" >&2' ERR
printf 'Verification logs: %s\n' "$ORBIT_CHECK_LOGS"

snapshot_source() {
  python3 -B - "$1" <<'PY'
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path.cwd() / "scripts"))
from priorities_3_5_acceptance import fingerprint
Path(sys.argv[1]).write_text(json.dumps(fingerprint({}), sort_keys=True))
PY
}

run() {
  ORBIT_CHECK_STAGE="$1"
  shift
  printf '\nChecking %s\n' "$ORBIT_CHECK_STAGE"
  "$@" 2>&1 | tee "$ORBIT_CHECK_LOGS/$ORBIT_CHECK_STAGE.log"
}

# An inherited RUSTUP_TOOLCHAIN/RUSTC or an older toolchain ahead of rustup
# on PATH can otherwise override rust-toolchain.toml, including for Clippy.
ORBIT_CHECK_STAGE=toolchain
ORBIT_CHECK_TOOLCHAIN="$(python3 -B -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
if ! command -v rustup >/dev/null 2>&1; then
  printf '%s\n' 'Release verification requires rustup to select the repository-pinned toolchain.' >&2
  exit 2
fi
if ! ORBIT_CHECK_CARGO="$(rustup which --toolchain "$ORBIT_CHECK_TOOLCHAIN" cargo)"; then
  printf 'Install the pinned tools: rustup toolchain install %s --profile minimal --component rustfmt --component clippy\n' "$ORBIT_CHECK_TOOLCHAIN" >&2
  exit 2
fi
ORBIT_CHECK_TOOLCHAIN_BIN="$(dirname -- "$ORBIT_CHECK_CARGO")"
for ORBIT_CHECK_TOOL in cargo rustc rustdoc cargo-clippy clippy-driver cargo-fmt rustfmt; do
  if ! test -x "$ORBIT_CHECK_TOOLCHAIN_BIN/$ORBIT_CHECK_TOOL"; then
    printf 'Missing %s in toolchain %s. Run: rustup toolchain install %s --profile minimal --component rustfmt --component clippy\n' "$ORBIT_CHECK_TOOL" "$ORBIT_CHECK_TOOLCHAIN" "$ORBIT_CHECK_TOOLCHAIN" >&2
    exit 2
  fi
done
export RUSTUP_TOOLCHAIN="$ORBIT_CHECK_TOOLCHAIN"
export RUSTC="$ORBIT_CHECK_TOOLCHAIN_BIN/rustc"
export RUSTDOC="$ORBIT_CHECK_TOOLCHAIN_BIN/rustdoc"
export RUSTFMT="$ORBIT_CHECK_TOOLCHAIN_BIN/rustfmt"
export PATH="$ORBIT_CHECK_TOOLCHAIN_BIN:$PATH"
# Match CI: isolated fixtures repeatedly hash these binaries. Debug symbols
# add hundreds of megabytes without changing the acceptance assertions.
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
hash -r
run toolchain rustc --version
run cargo-version cargo --version
run clippy-version cargo clippy --version
run formatter-version cargo fmt --version

snapshot_source "$ORBIT_CHECK_LOGS/source-before.json"
run environment python3 -B scripts/release_preflight.py
run process-isolation scripts/in-jail.sh true
run shell-sandbox command -v bwrap
# Reject dependency advisories before spending time building and testing.
run dependency-policy cargo deny --locked check
run format cargo fmt --all -- --check
run clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run build cargo build --workspace --locked
run terminal-dependencies python3 -B scripts/prepare_manual_pty_dependencies.py
for ORBIT_CHECK_CONTRACT in test_prepare_manual_pty_dependencies test_priorities_3_5_acceptance test_homebrew_distribution test_release_preflight test_check_release_test_log test_check_release_package; do
  run "$ORBIT_CHECK_CONTRACT" scripts/in-jail.sh python3 -B -m unittest discover -s scripts -p "$ORBIT_CHECK_CONTRACT.py" -v
done
# Isolated CLI cases repeatedly hash large debug binaries and have bounded
# watchdogs. Match the acceptance runner's serial libtest scheduling.
run workspace-tests scripts/in-jail.sh env ORBIT_REQUIRE_SANDBOX=1 ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION=1 cargo test --workspace --locked --no-fail-fast -- --test-threads=1
run required-coverage python3 -B scripts/check_release_test_log.py "$ORBIT_CHECK_LOGS/workspace-tests.log"
run npm-distribution scripts/in-jail.sh node scripts/npm_distribution_test.mjs
run release-build cargo build --release --locked -p orbit-cli --bin orbit -p orbit-web --bin orbit-web
run installed-release scripts/in-jail.sh python3 -B scripts/rc_release_checks.py --binary-dir target/release --check-doc-commands

ORBIT_CHECK_STAGE=package
ORBIT_CHECK_VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')"
ORBIT_CHECK_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
run package python3 -B scripts/package_install_bundle.py --orbit target/release/orbit --orbit-web target/release/orbit-web --version "$ORBIT_CHECK_VERSION" --target "$ORBIT_CHECK_TARGET" --output "$ORBIT_CHECK_LOGS/package"
run package-identity python3 -B scripts/check_release_package.py --acceptance-log "$ORBIT_CHECK_LOGS/installed-release.log" --package-dir "$ORBIT_CHECK_LOGS/package"
ORBIT_CHECK_STAGE=source-after
snapshot_source "$ORBIT_CHECK_LOGS/source-after.json"
cmp "$ORBIT_CHECK_LOGS/source-before.json" "$ORBIT_CHECK_LOGS/source-after.json"
printf '%s\n' 'Automated checks passed for this native host and unchanged source. Source review, the other supported architecture, and daily-use provider acceptance remain separate gates.' | tee "$ORBIT_CHECK_LOGS/result.txt"
printf 'Completed logs and candidate: %s\n' "$ORBIT_CHECK_LOGS"
