#!/usr/bin/env bash
# Drive the nearai-cloud-verifier PoC demos.

set -euo pipefail

# Prevent CPython from writing __pycache__ bytecode into the imported
# nearai-cloud-verifier source tree when the demos `import` from it.
export PYTHONDONTWRITEBYTECODE=1

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
NEARAI_SRC="${NEARAI_SRC:-/scratch/bjchen4_icgpu/tee_attest/nearai-cloud-verifier}"

cd "$POC_DIR"

if [[ ! -d "$NEARAI_SRC" ]]; then
  echo "error: NEARAI_SRC not found: $NEARAI_SRC" >&2
  exit 1
fi

echo "=================================================================="
echo "Stage 1/2 — no-model-binding demo"
echo "=================================================================="
echo "Demonstrates: every attestation field is identical across a model"
echo "swap, except the nonce slot. No field identifies model weights."
echo
python3 demo_no_model_binding.py

echo
echo "=================================================================="
echo "Stage 2/3 — NRAS JWT signature is never verified (F3)"
echo "=================================================================="
echo "Demonstrates: model_verifier.base64url_decode_jwt_payload accepts"
echo "a JWT whose signature segment is empty."
echo
python3 demo_nras_jwt_unsigned.py --nearai-src "$NEARAI_SRC"

echo
echo "=================================================================="
echo "Stage 3/6 — Live TLS channel unbound from attestation (F6)"
echo "=================================================================="
echo "Demonstrates: the default verifier flow validates the attestation's"
echo "internal consistency but never checks that the live TLS endpoint"
echo "actually terminates at the attested key."
echo
python3 demo_channel_unbound.py --nearai-src "$NEARAI_SRC"

echo
echo "=================================================================="
echo "Stage 4/6 — Sampling parameters unattested (Attack #17, F7)"
echo "=================================================================="
echo "Demonstrates: signed text chat_id:request_hash:response_hash has"
echo "no slot for temperature/top_p/seed; two different sampling regimes"
echo "produce two verifier-accepting receipts."
echo
python3 demo_sampling_unattested.py

echo
echo "=================================================================="
echo "Stage 5/6 — CPU↔GPU chain unbound (Attack #18, F8)"
echo "=================================================================="
echo "Demonstrates: same NRAS verdict accepted with two different Intel"
echo "TDX quotes; the verifier checks each link independently and has"
echo "no field binding the NRAS verdict's GPU UUID to the CPU enclave."
echo
python3 demo_cpu_gpu_chain_unbound.py

echo
echo "=================================================================="
echo "Stage 6/6 — Conversation-history injection (Attack #19, F9)"
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
