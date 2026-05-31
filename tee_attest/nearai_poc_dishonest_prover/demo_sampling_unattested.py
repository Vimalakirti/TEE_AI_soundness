#!/usr/bin/env python3
"""
Attack #17 — F7 (NEAR AI sampling parameters unattested)

NEAR AI's cloud-verifier signs a per-chat `text` payload of the form

    f"{chat_id}:{request_hash}:{response_hash}"

(see `nearai-cloud-verifier/py/chat_verifier.py:78-96`). The verifier
recomputes `sha256(request_body)` and `sha256(response_text)`, then
compares to the second and third colon-separated parts of the signed
text. If both match and the ECDSA signature recovers to the
attestation's signing address, the chat is "verified."

There is no field — anywhere in `chat_verifier.py`, in the signed
`text`, or in the surrounding attestation — that names the sampling
parameters (`temperature`, `top_p`, `seed`, decoding strategy) that
turned the request into the response. The model is non-deterministic
by design, so the verifier *cannot* pin `expected_response_hash`; it
can only pin `request_hash`. Once the request is pinned, every
operator-chosen sampling regime produces a different but
verifier-accepting `response_hash`.

This complements Attack 9 (EphemeralML F7) by showing the same
failure mode in a different system with a different receipt schema:
EphemeralML uses AIR v1 CWT/COSE_Sign1; NEAR AI uses raw ECDSA over
`chat_id:request_hash:response_hash`. Neither schema carries
sampling parameters.

NEAR AI source is NOT modified; the PoC faithfully ports the
verification logic from `chat_verifier.py:70-107`.
"""

import hashlib
import sys
import json


def sha256_text(text: str) -> str:
    """Mirror of chat_verifier.py's sha256_text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_signed_text(chat_id: str,
                       request_body: str,
                       response_text: str,
                       signed_text: str) -> tuple[bool, bool]:
    """
    Faithfully replicates the parsing + comparison logic from
    chat_verifier.py:79-91.

    Returns (request_hash_matches, response_hash_matches).
    """
    parts = signed_text.split(":")
    if len(parts) not in (2, 3):
        raise ValueError(
            f"Invalid signature payload text format: expected 2 or 3 "
            f"colon-separated parts, got {len(parts)}: {signed_text!r}"
        )
    if len(parts) == 3:
        request_hash_server, response_hash_server = parts[1], parts[2]
    else:
        request_hash_server, response_hash_server = parts[0], parts[1]
    request_hash = sha256_text(request_body)
    response_hash = sha256_text(response_text)
    return (request_hash == request_hash_server,
            response_hash == response_hash_server)


def main():
    print("=" * 66)
    print("NEAR AI F7 PoC — sampling parameters unattested (Attack #17)")
    print("=" * 66)
    print()

    # The user's question. Same request_body in both scenarios.
    request_body = json.dumps({
        "model": "deepseek-ai/DeepSeek-V3.1",
        "messages": [
            {"role": "user", "content": "Is this contract safe to sign?"}
        ],
        # Note: nothing in the signed payload covers the temperature
        # field. The operator can ignore it server-side and pick any
        # value they like.
        "stream": False,
    })

    chat_id = "chatcmpl-AAAAAA1111"

    # Scenario A — operator runs the model with temperature=0.
    # (Honest deterministic answer.)
    response_a = (
        "I can review the contract terms if you paste them. "
        "Without seeing the document I cannot give a recommendation."
    )

    # Scenario B — same user, same request, but the operator chose
    # temperature=1.5 to nudge the model toward agreeable output.
    response_b = (
        "Yes, this contract appears safe to sign. The terms look "
        "consistent with industry standards. Proceed when ready."
    )

    request_hash = sha256_text(request_body)
    response_hash_a = sha256_text(response_a)
    response_hash_b = sha256_text(response_b)

    signed_text_a = f"{chat_id}:{request_hash}:{response_hash_a}"
    signed_text_b = f"{chat_id}:{request_hash}:{response_hash_b}"

    print("[+] Single user request, two operator-chosen sampling regimes:")
    print(f"    request_hash = {request_hash}")
    print()
    print("Scenario A — operator-chosen temperature=0 (honest):")
    print(f"    response_text   = {response_a!r}")
    print(f"    response_hash   = {response_hash_a}")
    print(f"    signed text     = chat_id:request_hash:response_hash")
    print(f"                    = {signed_text_a}")
    print()
    print("Scenario B — operator-chosen temperature=1.5 (manipulated):")
    print(f"    response_text   = {response_b!r}")
    print(f"    response_hash   = {response_hash_b}")
    print(f"    signed text     = chat_id:request_hash:response_hash")
    print(f"                    = {signed_text_b}")
    print()

    print("=" * 66)
    print("Verifier's view (driving chat_verifier.py:79-91 logic)")
    print("=" * 66)

    # Scenario A passes the verifier.
    rh_a, oh_a = verify_signed_text(chat_id, request_body, response_a, signed_text_a)
    # Scenario B also passes the verifier — the operator's sampling
    # choice is invisible at the signed-text layer.
    rh_b, oh_b = verify_signed_text(chat_id, request_body, response_b, signed_text_b)

    print()
    print(f"Scenario A: request_hash matches = {rh_a}, response_hash matches = {oh_a}")
    print(f"Scenario B: request_hash matches = {rh_b}, response_hash matches = {oh_b}")
    print()

    assert rh_a and oh_a, "Scenario A should pass."
    assert rh_b and oh_b, "Scenario B should pass."

    print("    Both signed payloads pass chat_verifier.py's hash checks.")
    print("    The verifier has NO field to pin sampling parameters")
    print("    against — the signed text is exactly")
    print()
    print("        chat_id:request_hash:response_hash")
    print()
    print("    with no temperature, top_p, top_k, seed, or decoding-")
    print("    strategy slot. A verifier representing the user has no")
    print("    way to detect that response B came from a different")
    print("    sampling regime than response A.")
    print()

    print("=" * 66)
    print("Result")
    print("=" * 66)
    print()
    print("    [+] ATTACK CONFIRMED (F7 — sampling unattested)")
    print()
    print("    NEAR AI's `signed_text` format (chat_verifier.py:78-96)")
    print("    binds (chat_id, request_hash, response_hash) but no")
    print("    sampling parameter. The operator can vary temperature")
    print("    per request to manipulate the model's behavior, and")
    print("    every signed text the verifier sees is structurally")
    print("    honest about the bytes that flowed.")
    print()
    print("    Fix: extend the signed text format to a JSON or")
    print("    CBOR-encoded claims object that includes")
    print("    (chat_id, request_hash, response_hash,")
    print("     sampling_params_hash, guardrail_config_hash) and")
    print("    require chat_verifier.py to pin sampling_params_hash")
    print("    against a policy-supplied value.")
    print()
    print("    Pair this with Attack 9 (EphemeralML F7): two systems,")
    print("    two receipt formats, same missing fields.")


if __name__ == "__main__":
    main()
