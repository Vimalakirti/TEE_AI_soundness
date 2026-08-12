#!/usr/bin/env bash
# Drive the nearai-cloud-verifier PoC demos.

set -euo pipefail

# Prevent CPython from writing __pycache__ bytecode into the imported
# nearai-cloud-verifier source tree when the demos `import` from it.
export PYTHONDONTWRITEBYTECODE=1

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
NEARAI_SRC="${NEARAI_SRC:-$(cd "$(dirname "$0")/../nearai-cloud-verifier" 2>/dev/null && pwd)}"

cd "$POC_DIR"

if [[ ! -d "$NEARAI_SRC" ]]; then
  echo "error: NEARAI_SRC not found: $NEARAI_SRC" >&2
  exit 1
fi

# The earlier "no model-identity binding" demo (demo_no_model_binding.py)
# was withdrawn: NEAR binds the model through mr_config_id over the signed
# app_compose. The file is kept for reference but is not one of the 18 PoCs.

echo "=================================================================="
echo "Stage 1/5 — P13: NRAS JWT signature is never verified (F4)"
echo "=================================================================="
echo "Demonstrates: model_verifier.base64url_decode_jwt_payload accepts"
echo "a JWT whose signature segment is empty."
echo
python3 demo_nras_jwt_unsigned.py --nearai-src "$NEARAI_SRC"

echo
echo "=================================================================="
echo "Stage 2/5 — P9: Live TLS channel binding is opt-in (F6)"
echo "=================================================================="
echo "Demonstrates: the default verifier flow validates the attestation's"
echo "internal consistency but never checks that the live TLS endpoint"
echo "actually terminates at the attested key."
echo
python3 demo_channel_unbound.py --nearai-src "$NEARAI_SRC"

echo
echo "=================================================================="
echo "Stage 3/5 — P8: Sampling parameters unattested (F7)"
echo "=================================================================="
echo "Demonstrates: signed text chat_id:request_hash:response_hash has"
echo "no slot for temperature/top_p/seed; two different sampling regimes"
echo "produce two verifier-accepting receipts."
echo
python3 demo_sampling_unattested.py

echo
echo "=================================================================="
echo "Stage 4/5 — P12: CPU<->GPU verdict reusable across CPU quotes (F8)"
echo "=================================================================="
echo "Demonstrates: same NRAS verdict accepted with two different Intel"
echo "TDX quotes; the illustrative client prints but does not reject the"
echo "GPU-nonce mismatch."
echo
python3 demo_cpu_gpu_chain_unbound.py

echo
echo "=================================================================="
echo "Stage 5/5 — P16: Conversation-history injection (F9)"
echo "=================================================================="
echo "Demonstrates: signed text covers request_hash over the gateway-"
echo "constructed body; nothing distinguishes user-typed bytes from"
echo "operator-mediated context (system prompt, fake prior turns)."
echo
python3 demo_history_injection.py

echo
echo "=================================================================="
echo "PoC complete."
echo "=================================================================="
