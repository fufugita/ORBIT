#!/usr/bin/env bash
# ORBIT fuzz smoke — reproducible cargo-fuzz runs (DR-03 §6 row 3).
#
# Runs each fuzz target for a bounded time with the seeded corpus and prints
# the run counts. A nonzero exit or a crash artifact fails the smoke.
# Requires: nightly toolchain + cargo-fuzz (`cargo +nightly install cargo-fuzz`).
#
# Usage: bash scripts/run-fuzz-smoke.sh [seconds_per_target]
set -euo pipefail
cd "$(dirname "$0")/.."

SECS="${1:-15}"
echo "== fuzz smoke: ${SECS}s per target =="

for t in ir_cbor ledger_record export_restore migrator; do
  echo "--- $t ---"
  cargo +nightly fuzz run "$t" -- -max_total_time="$SECS" -max_len=8192 2>&1 | grep -E "Done [0-9]+ runs" | tail -1
  if [ -n "$(find fuzz/artifacts/$t -type f 2>/dev/null)" ]; then
    echo "!! crash artifact in fuzz/artifacts/$t"
    exit 1
  fi
done
echo "== fuzz smoke: clean (0 crashes) =="
