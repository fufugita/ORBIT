#!/usr/bin/env bash
# Build both locked components and create an unsigned checksummed install bundle.
set -Eeuo pipefail
ORBIT_PACKAGE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ORBIT_PACKAGE_ROOT"
command -v cargo >/dev/null || { printf '%s\n' 'package: Cargo is required' >&2; exit 1; }
command -v python3 >/dev/null || { printf '%s\n' 'package: Python 3.11+ is required' >&2; exit 1; }
export RUSTUP_TOOLCHAIN=1.99.0
export CARGO_BUILD_JOBS=1
ORBIT_PACKAGE_VERSION="$(cargo metadata --no-deps --locked --format-version 1 | python3 -c 'import json,sys; p=json.load(sys.stdin)["packages"]; v={x["version"] for x in p if x["name"] in ("orbit-cli","orbit-web")}; assert len(v)==1, "component versions differ"; print(v.pop())')"
ORBIT_PACKAGE_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
ORBIT_PACKAGE_OUTPUT="${1:-$ORBIT_PACKAGE_ROOT/dist/$ORBIT_PACKAGE_VERSION}"
ORBIT_PACKAGE_BUILD="$(mktemp -d)"
trap 'rm -rf -- "$ORBIT_PACKAGE_BUILD"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cargo build --locked --release --target "$ORBIT_PACKAGE_TARGET" --target-dir "$ORBIT_PACKAGE_BUILD" -p orbit-cli --bin orbit -p orbit-web --bin orbit-web
python3 scripts/package_install_bundle.py --orbit "$ORBIT_PACKAGE_BUILD/$ORBIT_PACKAGE_TARGET/release/orbit" --orbit-web "$ORBIT_PACKAGE_BUILD/$ORBIT_PACKAGE_TARGET/release/orbit-web" --version "$ORBIT_PACKAGE_VERSION" --target "$ORBIT_PACKAGE_TARGET" --output "$ORBIT_PACKAGE_OUTPUT"
printf '%s\n' 'Checksums verify archive integrity. This artifact is unsigned; publisher identity is not established.'
