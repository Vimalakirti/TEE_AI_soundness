# NEAR AI Cloud Verifier Dishonest-Prover PoCs

> **Paper PoC IDs:** P13 (NRAS JWT unsigned, F4), P9 (live channel opt-in, F6), P8 (sampling
> unattested, F7), P12 (CPU/GPU verdict reuse, F8), P16 (conversation-history injection, F9).
> See [`../POC_INDEX.md`](../POC_INDEX.md).

Five PoCs against NEAR AI Cloud's published verification client,
[`nearai-cloud-verifier`](https://github.com/nearai/nearai-cloud-verifier), reviewed at commit
`8b7830e9` (the `../nearai-cloud-verifier` submodule).

NEAR AI's platform does bind the properties we tested into its hardware evidence: the model
identity (through `mr_config_id` over the signed `app_compose`), the GPU attestation result, and the
live network channel. These PoCs target the published client, which as written under-enforces those
bindings or exposes no checkable claim for them. The maintainer described the scripts as
illustrative clients rather than the intended trust boundary; we report what a user running them
as published would accept.

The verifier source is never modified. P13 and P9 import functions from the submodule
(`model_verifier.base64url_decode_jwt_payload`, `model_verifier.check_report_data`); P8, P12 and P16
rebuild the client's signed-text and report-data formats with synthetic inputs.

## Threat model

- **Prover:** the operator of the NEAR AI Cloud service. It controls the TDX VM, the network path to
  NVIDIA's attestation service (NRAS), the gateway that builds the request body, and the inference
  container's settings.
- **Verifier:** a user running the published `model_verifier.py` / `chat_verifier.py` scripts.
- **Trusted:** Intel TDX collateral, NVIDIA's signing keys, and the client's own logic.

## The five PoCs

| Stage | PoC | Class | Script | What it shows |
|---|---|---|---|---|
| 1 | P13 | F4 | `demo_nras_jwt_unsigned.py` | `base64url_decode_jwt_payload` reads only the payload segment of the NRAS JWT; the signature is never checked, so a forged token with an empty signature yields any verdict (`MATCH`, `anything-we-want`). |
| 2 | P9 | F6 | `demo_channel_unbound.py` | `check_report_data` accepts an attestation that correctly binds TLS key K_A while the live HTTPS endpoint presents K_B. Only the opt-in live-key comparison (`--verify-tls` / `tls_verifier.py`) detects the mismatch. |
| 3 | P8 | F7 | `demo_sampling_unattested.py` | Two signed responses to the same request, produced under different sampling settings, both verify; the signed text binds `(chat_id, request_hash, response_hash)` and has no sampling slot. |
| 4 | P12 | F8 | `demo_cpu_gpu_chain_unbound.py` | The same NRAS verdict is accepted alongside two different Intel quotes. The client prints, but does not enforce, the GPU-nonce match, and the GPU identity is not hashed into either quote. |
| 5 | P16 | F9 | `demo_history_injection.py` | The signed `request_hash` covers the gateway-built body, so operator-injected conversation history is indistinguishable from user-typed turns. |

## How to run

Requires Python 3.10+ with `cryptography` (see the top-level README).

```bash
cd tee_attest/nearai_poc_dishonest_prover
./run_poc.sh
```

To use a verifier checkout elsewhere:

```bash
NEARAI_SRC=/path/to/nearai-cloud-verifier ./run_poc.sh
```

## Expected output

Each stage ends with a confirmation banner:

```text
Stage 1/5 — P13: NRAS JWT signature is never verified (F4)
    forged verdict 'MATCH'   -> decoder reads -> 'MATCH'
    forged verdict 'anything-we-want'   -> decoder reads -> 'anything-we-want'
[+] ATTACK CONFIRMED

Stage 2/5 — P9: Live TLS channel binding is opt-in (F6)
    Default verifier (internal-only) accepts: True
    Live-SPKI binding detects mismatch:        True
[+] ATTACK CONFIRMED (F6)

Stage 3/5 — P8: Sampling parameters unattested (F7)
    [+] ATTACK CONFIRMED (F7 — sampling unattested)

Stage 4/5 — P12: CPU<->GPU verdict reusable across CPU quotes (F8)
    Are the NRAS gpu_uuid bytes hashed into ANY field of
    either Intel quote? False
    [+] ATTACK CONFIRMED (F8 — CPU↔GPU chain unbound)

Stage 5/5 — P16: Conversation-history injection (F9)
    [+] ATTACK CONFIRMED (F9 — conversation-history injection)
```

## Suggested fixes

- **P13:** verify the NRAS JWT signature against NVIDIA's published keys before reading any claim.
- **P9:** make the live-channel check the default and fail when the live key does not match the
  attested one.
- **P8, P16:** sign a structured claims object that includes the sampling settings and separates
  user turns from operator-supplied context, and have the verifier pin each field.
- **P12:** reject, rather than print, a GPU-nonce mismatch.

## Responsible disclosure

These findings were disclosed to NEAR AI before publication; see the top-level README.
