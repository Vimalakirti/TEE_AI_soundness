#!/usr/bin/env bash
# Drive the PoC stages in sequence.
# Laminator's source tree is never modified; this script only writes to
# the current directory and a fresh /tmp/laminator-poc-* working dir.

set -euo pipefail

# Prevent CPython from writing __pycache__ bytecode into the imported
# Laminator source tree when the demos `import` from it. Without this,
# `__pycache__/` directories appear under generate_attestations/ as a
# side-effect of running these PoCs.
export PYTHONDONTWRITEBYTECODE=1

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
LAMINATOR_SRC="${LAMINATOR_SRC:-/scratch/bjchen4_icgpu/tee_attest/laminator/generate_attestations}"

cd "$POC_DIR"

if [[ ! -d "$LAMINATOR_SRC" ]]; then
  echo "error: LAMINATOR_SRC not found: $LAMINATOR_SRC" >&2
  echo "       set LAMINATOR_SRC env var to override." >&2
  exit 1
fi

echo "================================================================="
echo "Stage 1/3 — build evil census_model.pth"
echo "================================================================="
python3 build_evil_model.py --laminator-src "$LAMINATOR_SRC"

echo
echo "================================================================="
echo "Stage 2/3 — prove pickle attack patches utils.test in-process"
echo "================================================================="
python3 demo_pickle_attack.py --laminator-src "$LAMINATOR_SRC"

echo
echo "================================================================="
echo "Stage 3/4 — drive accuracy_attestation end-to-end and dump"
echo "             the forged output_accuracy.json payload"
echo "================================================================="
python3 forge_attestation_payload.py --laminator-src "$LAMINATOR_SRC"

echo
echo "================================================================="
echo "Stage 4/5 — switchable loader (variant)"
echo "             fixed SHA-512, host-swappable model between calls"
echo "================================================================="
python3 demo_model_switching.py --laminator-src "$LAMINATOR_SRC"

echo
echo "================================================================="
echo "Stage 5/5 — argv unmeasured (Attack #14, F1)"
echo "             same model, different argv → different PoT payloads"
echo "================================================================="
python3 demo_argv_unmeasured.py

echo
echo "================================================================="
echo "All five stages completed. Stages 1-3 + Stage 4 are strict"
echo "model-switching attacks (F4 + F5). Stage 5 is the F1 argv-"
echo "unmeasured demo (Attack #14)."
echo "================================================================="
