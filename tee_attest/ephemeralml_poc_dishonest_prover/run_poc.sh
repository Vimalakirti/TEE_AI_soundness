#!/usr/bin/env bash
# Drive the EphemeralML PoC.
# Builds and runs a small Rust binary that path-depends on
# EphemeralML's `common/` crate. EphemeralML's source is not modified.

set -euo pipefail

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$POC_DIR"

# Pick a nightly that satisfies edition2024 deps in EphemeralML's lock.
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-nightly-2025-07-01}"

echo "================================================================="
echo "Build EphemeralML PoC (toolchain: $RUST_TOOLCHAIN)"
echo "================================================================="
rustup run "$RUST_TOOLCHAIN" cargo build --release

echo
echo "================================================================="
echo "Run P17 (F3) — default policy accepts arbitrary model_hash"
echo "================================================================="
./target/release/poc

echo
echo "================================================================="
echo "Run P7 (F7) — sampling parameters unattested"
echo "================================================================="
./target/release/poc_f7

echo
echo "================================================================="
echo "Run P15 (F9) — application-layer (RAG) context unattested"
echo "================================================================="
./target/release/poc_f9_context_unattested

echo
echo "================================================================="
echo "Run P10 (F6) — signing-key chain unbound"
echo "================================================================="
./target/release/poc_f6_signing_key_chain

echo
echo "================================================================="
echo "PoC complete."
echo "================================================================="
