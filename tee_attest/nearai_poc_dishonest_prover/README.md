# NEAR AI Cloud-Verifier Dishonest-Prover PoC

Standalone proof of concept for the two structural soundness gaps
in `nearai-cloud-verifier`:

- **Finding N-1** (NRAS JWT signature is never verified).
- **No model identity binding** — the verifier-observable surface
  carries no field that identifies model weights, so an operator
  can swap models freely. (See "5. nearai-cloud-verifier" in
  `../model_switching.md`.)

`nearai-cloud-verifier`'s source tree is **not** modified by this
PoC. `demo_nras_jwt_unsigned.py` imports the real
`model_verifier.base64url_decode_jwt_payload` function from the
cloned repository and exercises it with a forged JWT.

## Threat model

- The "prover" is the operator of `cloud-api.near.ai` (closed
  source). The client/verifier runs the open-source
  `model_verifier.py` / `chat_verifier.py` / `tls_verifier.py`
  scripts to validate attestations the operator returns.
- The operator controls the TDX VM, the network path to NVIDIA NRAS,
  and the inference container's model-loading code.
- The client trusts only: Intel TDX collateral (via `dcap-qvl`),
  NVIDIA NRAS (HTTPS to `nras.attestation.nvidia.com`), Sigstore
  (HEAD checks of container digests), and the verifier scripts'
  own logic.

**Goal:** show that the operator can serve attacker-chosen model
weights while every attestation field the verifier inspects remains
identical to a legitimate run.

## How the attacks work

### Gap A — no model-identity field

`model_verifier.py`'s payload (decoded TDX `report_data`) carries:

- `report_data[0..32]` = padded `signing_address` (ECDSA pubkey
  for response signing), or `SHA256(signing_address || tls_fp)` if
  `include_tls_fingerprint=true`.
- `report_data[32..64]` = client nonce.

`mr_config_id` binds `sha256("01" + app_compose)`. `app_compose`
references container images by `@sha256:` digest.

**No slot identifies model weights.** Multi-GB model files are
loaded at container runtime from object storage; the OCI image's
filesystem typically excludes them. The Sigstore "check" in the
verifier (`model_verifier.py:236-268`) is HEAD-reachability, not
provenance.

So the operator keeps `signing_address`, `mr_config_id`, container
images, and TLS fingerprint constant — and the verifier observes a
byte-identical attestation while the inference server inside the
container loads whichever weights the operator chooses.

### Gap B — NRAS JWT signature unverified

`model_verifier.py:42-47`:

```python
def base64url_decode_jwt_payload(jwt_token):
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode()
```

The function reads only the middle segment of a JWT. The header
(`alg`) is not checked; the signature is not verified against
NVIDIA's JWKS. An attacker who controls the response from NRAS
(or who MITMs the call between the verifier and NRAS) can return
any verdict the verifier will print as `NVIDIA attestation
verdict:`.

## What this PoC does NOT do

- It does not reproduce a live Intel TDX quote-verification
  failure-mode. The mock returns synthetic quote bytes; running
  the full `model_verifier.py` against the mock would fail at
  `dcap_qvl.get_collateral_and_verify`. The structural claim — that
  no field in the attestation identifies the model — does not
  depend on the quote bytes being valid; it depends only on what
  fields the attestation carries. The PoC demonstrates that
  directly.
- It does not modify `nearai-cloud-verifier` source. The
  `model_verifier.base64url_decode_jwt_payload` function is imported
  from the cloned repo and exercised on a forged JWT.

## Files

| File | Purpose |
|---|---|
| `mock_cloud_api.py` | Tiny HTTP server (stdlib) mimicking `cloud-api.near.ai`'s `/v1/attestation/report`, `/v1/chat/completions`, and an `/admin/swap` toggle. |
| `demo_no_model_binding.py` | (F1) Spawns the mock, requests attestations before and after `/admin/swap`, diffs the two payloads field-by-field. Shows every diff is a nonce-bound field; nothing identifies the model. |
| `demo_nras_jwt_unsigned.py` | (F3) Imports `model_verifier.base64url_decode_jwt_payload` from the cloned `nearai-cloud-verifier` repo; feeds it a forged JWT whose signature segment is empty; shows the decoder accepts any verdict. |
| `demo_channel_unbound.py` | (F6) Generates two ECDSA-P256 self-signed certs (K_A, K_B). Spawns an HTTPS server that presents K_B at the TLS layer while the attestation response claims `tls_cert_fingerprint = SPKI(K_A)`. Imports `model_verifier.check_report_data` (real verifier code, not modified) and shows it passes the internal-consistency check. Then mirrors `tls_verifier.py`'s SPKI extraction over a fresh TLS socket and shows the live SPKI doesn't match the claimed value. |
| `run_poc.sh` | Runs all three demos. |

## How to run

```bash
cd nearai_poc_dishonest_prover
./run_poc.sh
```

Override the verifier source location:

```bash
NEARAI_SRC=/path/to/nearai-cloud-verifier ./run_poc.sh
```

## Expected output

### Stage 1 — no model binding

```text
Stage 1 — backend toggled to 'good'
    chat response:     The capital of France is Paris. ...

Stage 2 — operator runs /admin/swap
    backend now: evil

Stage 3 — backend toggled to 'evil'
    chat response:     The capital of France is Berlin. ...

Stage 4 — field-by-field diff between the two attestations
    Total fields differing: 6
    Differences explained by the changed nonce alone: 6
    Unexplained diffs: NONE

[+] ATTACK CONFIRMED
```

### Stage 2 — NRAS JWT decode

```text
[+] Loaded decoder: model_verifier.base64url_decode_jwt_payload

[+] Forged JWT (empty signature segment): ...
    Signature segment: '' (0 chars — empty!)

[+] Verdict the verifier would print: 'MATCH'

    forged verdict 'MATCH'   -> decoder reads -> 'MATCH'
    forged verdict 'PARTIAL_MATCH'   -> decoder reads -> 'PARTIAL_MATCH'
    forged verdict 'anything-we-want'   -> decoder reads -> 'anything-we-want'
```

## Mitigations

**For the no-model-binding gap (Gap A):** extend the TDX
`report_data` layout to include a 32-byte slot for `model_hash`.
Have the inference server inside the TEE compute that hash from the
weight bytes it actually loaded, and have `cloud-api` bind it into
the quote before signing. Update `model_verifier.py` to check the
slot against a pinned expected hash (analogous to A3S Power's
`report_data[32..64] = model_hash` design).

**For the JWT gap (Gap B):** fetch NVIDIA's JWKS (e.g., from
`https://nras.attestation.nvidia.com/.well-known/jwks.json` or
equivalent), pin the signing keys, and use a JWT library that
verifies the signature before trusting any claim. Alternatively,
use NVIDIA's official attestation SDK.

## Responsible disclosure

`nearai-cloud-verifier` is published by NEAR AI
(`github.com/nearai/nearai-cloud-verifier`) and the underlying
`cloud-api.near.ai` is a live commercial service. Before publishing
this finding alongside a paper, coordinate disclosure with NEAR AI
and give the standard 60–90-day fix window.
