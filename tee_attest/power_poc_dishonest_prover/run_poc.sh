#!/usr/bin/env bash
# Drive the A3S Power PoC.
# A separate Cargo binary that path-depends on Power's crate.
# Power's source tree is not modified.

set -euo pipefail

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$POC_DIR"

RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-nightly-2025-07-01}"

echo "================================================================="
echo "Build Power PoC (toolchain: $RUST_TOOLCHAIN)"
echo "================================================================="
rustup run "$RUST_TOOLCHAIN" cargo build --release

echo
echo "================================================================="
echo "Run F5 PoC (Attack 3) — stale attestation cache"
echo "================================================================="
./target/release/poc

echo
echo "================================================================="
echo "Run F4 PoC (Attack 10) — operator-controlled Jinja template"
echo "================================================================="
./target/release/poc_f4_minijinja

echo
echo "================================================================="
echo "Run F8 PoC (Attack 12) — CPU↔GPU attestation chain unbound"
echo "================================================================="
./target/release/poc_f8_chain_unbound

echo
echo "================================================================="
echo "Run F2 PoC (Attack 15) — hardware_verifier: None opt-in"
echo "================================================================="
./target/release/poc_f2_hardware_verifier_none

echo
echo "================================================================="
echo "PoC complete."
echo "================================================================="
