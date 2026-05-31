#!/usr/bin/env bash
# Drive the Tinfoil SDK F3 PoC.
# Tinfoil's tinfoil-go source tree is not modified.

set -euo pipefail

# Prevent CPython from writing __pycache__ bytecode in case any future
# demo `import`s from an external source tree.
export PYTHONDONTWRITEBYTECODE=1

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$POC_DIR"

echo "=================================================================="
echo "Tinfoil SDK — F3 (rollback via github-proxy.tinfoil.sh)"
echo "=================================================================="
python3 demo_proxy_rollback.py

echo
echo "=================================================================="
echo "PoC complete."
echo "=================================================================="
