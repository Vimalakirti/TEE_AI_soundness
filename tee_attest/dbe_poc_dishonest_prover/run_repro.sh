#!/usr/bin/env bash
# Reproduce issues 1-3 against a PySyft checkout.
#   PYSYFT=/path/to/PySyft   PySyft checkout at the commit under test
#   PY=/path/to/python       interpreter with syft-enclave installed from that checkout
#   RESTRICT_SRC=/path       optional: syft-restrict to test in issue 1 (e.g. an unpacked
#                            PyPI wheel); default is the copy in $PYSYFT
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
: "${PYSYFT:?set PYSYFT to a PySyft checkout}"
: "${PY:?set PY to a python with syft-enclave installed from \$PYSYFT}"
export PYSYFT
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
echo "PySyft: $(git -C "$PYSYFT" log -1 --format='%h %ad' --date=short 2>/dev/null || echo unknown)"

echo "syft-restrict under test: ${RESTRICT_SRC:-$PYSYFT/packages/syft-restrict/src}"
echo "=== Issue 1a: syft-restrict verdicts (allow-list from gemma/colab-3-persona) ==="
for f in restrict/poc*.py restrict/neg_direct.py restrict/regression/*.py; do
  printf '%-46s ' "$f"; "$PY" restrict/harness.py "$f" | head -2 | paste -sd' '
done
rm -f restrict/*.obfuscated.py restrict/regression/*.obfuscated.py

echo; echo "=== Issue 1b: runtime effect of the two gadgets ==="
"$PY" restrict/demo_restrict_exfil.py || true
rm -f restrict/*.obfuscated.py

echo; echo "=== Issue 2: verify_receipt accepts a re-signed receipt with altered results ==="
"$PY" issue2_receipt_forgery.py || true

echo; echo "=== Issue 3: job output on the enclave process's stdout without a log release ==="
if grep -q 'def read_permissions_to_share' "$PYSYFT/packages/syft-enclave/src/syft_enclaves/client.py"; then
  demo=issue3_log_stdout.py
else
  demo=issue3_log_stdout_pre_354b283bb6.py
fi
UV_LINK_MODE=symlink "$PY" "$demo" 2>&1 | grep -E '^\[(enclave|container)|^    \[|RESULT' || true
