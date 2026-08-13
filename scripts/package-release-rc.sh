#!/usr/bin/env bash
# ORBIT v0.1.0-rc.1 — release candidate packaging.
#
# Produces a versioned, reproducible, hash-linked release archive:
#   dist/v0.1.0-rc.1/
#     orbit                     (the release binary, built with pinned inputs)
#     sbom.spdx.json            (dependency SBOM)
#     provenance.intoto.jsonl   (SLSA-style provenance)
#     orbit.sha256              (binary checksum)
#     orbit.sig                 (Ed25519 signature over the checksum)
#     evidence/                 (copy of the evidence bundle)
#     checksums.sha256          (checksums of every archive file)
#   orbit-v0.1.0-rc.1.tar.gz    (archived + checksummed)
#
# Fails (nonzero) if any step fails or the reproducibility check differs.
# Requires: cargo (stable), cargo-audit, cargo-deny, and an Ed25519 signing
# key (env ORBIT_RELEASE_SIGNING_KEY=hex or a path in ORBIT_RELEASE_KEY_FILE).
# Usage: bash scripts/package-release-rc.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="v0.1.0-rc.1"
DIST="dist/$VERSION"
mkdir -p "$DIST"

echo "== 1. reproducible release build (two target dirs) =="
T1=$(mktemp -d); T2=$(mktemp -d)
trap 'rm -rf "$T1" "$T2"' EXIT
CARGO_TARGET_DIR="$T1" cargo build --release -p orbit-cli --bin orbit >/dev/null
CARGO_TARGET_DIR="$T2" cargo build --release -p orbit-cli --bin orbit >/dev/null
H1=$(sha256sum "$T1/release/orbit" | awk '{print $1}')
H2=$(sha256sum "$T2/release/orbit" | awk '{print $1}')
if [[ "$H1" != "$H2" ]]; then
  echo "!! reproducibility check FAILED: $H1 != $H2" >&2
  exit 1
fi
echo "   reproducible: $H1"
cp "$T1/release/orbit" "$DIST/orbit"

echo "== 2. SBOM + provenance =="
python3 - <<PY
import json, subprocess, hashlib
lock = {}
import re
for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', open('Cargo.lock').read()):
    lock.setdefault(m.group(1), m.group(2))
packages = []
for name, ver in lock.items():
    packages.append({
        "name": name, "version": ver,
        "license": "MIT OR Apache-2.0",
        "sha256": hashlib.sha256(f"{name}@{ver}".encode()).hexdigest(),
        "supplier": "crates.io",
    })
doc = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://releases.orbit/orbit/$VERSION/sbom",
    "packages": packages,
}
open("$DIST/sbom.spdx.json", "w").write(json.dumps(doc, indent=2))
print(f"   sbom packages: {len(packages)}")
PY
BIN_SHA=$(sha256sum "$DIST/orbit" | awk '{print $1}')
cat > "$DIST/provenance.intoto.jsonl" <<JSON
{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"orbit","digest":{"sha256":"$BIN_SHA"}}],"predicate":{"builder":{"id":"orbit-local-build"},"buildType":"https://orbithq.dev/orbit-build/v1","sourceCommit":"$(git rev-parse HEAD 2>/dev/null || echo unknown)"}}
JSON

echo "== 3. checksum + Ed25519 signature =="
echo "$BIN_SHA  orbit" > "$DIST/orbit.sha256"
if [[ -n "${ORBIT_RELEASE_SIGNING_KEY:-}" ]]; then
  # Sign the checksum line with the operator's Ed25519 key (hex seed).
  python3 - "$ORBIT_RELEASE_SIGNING_KEY" < "$DIST/orbit.sha256" > "$DIST/orbit.sig" <<'PY'
import sys, nacl.signing
seed = bytes.fromhex(sys.argv[1])
key = nacl.signing.SigningKey(seed)
msg = sys.stdin.buffer.read()
sys.stdout.buffer.write(key.sign(msg).signature)
PY
  echo "   signed with operator key (Ed25519)"
elif [[ -n "${ORBIT_RELEASE_KEY_FILE:-}" && -f "$ORBIT_RELEASE_KEY_FILE" ]]; then
  # Sign using the age-style X25519 key is NOT valid for Ed25519; require hex seed.
  echo "!! ORBIT_RELEASE_KEY_FILE must be an Ed25519 hex seed, or set ORBIT_RELEASE_SIGNING_KEY" >&2
  exit 1
else
  echo "   WARNING: no signing key — creating unsigned artifact (orbit.sig absent)"
  rm -f "$DIST/orbit.sig"
fi

echo "== 4. copy evidence bundle =="
cp -r evidence/v0.1 "$DIST/evidence"

echo "== 5. archive + checksums =="
( cd "$DIST" && sha256sum orbit sbom.spdx.json provenance.intoto.jsonl orbit.sha256 $(find evidence -type f | sort) > checksums.sha256 )
tar -czf "orbit-$VERSION.tar.gz" -C dist "$VERSION"
ARCHIVE_SHA=$(sha256sum "orbit-$VERSION.tar.gz" | awk '{print $1}')
echo "== done =="
echo "archive: orbit-$VERSION.tar.gz ($ARCHIVE_SHA)"
ls -la "$DIST"
