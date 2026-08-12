#!/usr/bin/env bash
# Drive the modelwrap PoC. modelwrap's source tree is not modified.

set -euo pipefail

# Prevent CPython from writing __pycache__ bytecode into the imported
# modelwrap source tree.
export PYTHONDONTWRITEBYTECODE=1

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
MODELWRAP_SRC="${MODELWRAP_SRC:-$(cd "$(dirname "$0")/../tinfoil/modelwrap" 2>/dev/null && pwd)}"

cd "$POC_DIR"

if [[ ! -d "$MODELWRAP_SRC" ]]; then
  echo "error: MODELWRAP_SRC not found: $MODELWRAP_SRC" >&2
  exit 1
fi

# Clean any residue from previous runs.
rm -rf output cache

echo "=================================================================="
echo "Stage 1/2 — pre-place evil artifacts in output/"
echo "=================================================================="
python3 build_evil_artifacts.py

echo
echo "=================================================================="
echo "Stage 2/2 — run modelwrap pack.py and observe idempotency skip"
echo "=================================================================="
python3 demo_skip_attack.py --modelwrap-src "$MODELWRAP_SRC" --require-prepopulated

echo
echo "=================================================================="
echo "PoC complete. The .info file emitted to a downstream consumer"
echo "contains the attacker's chosen root hash; modelwrap never read"
echo "the real model bytes."
echo "=================================================================="
