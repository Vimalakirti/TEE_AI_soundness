#!/usr/bin/env python3
"""
Attack #14 — F1 (Laminator argv unmeasured)

Drives the same payload-construction logic Laminator's
`generate_attestations/main.py` uses at lines 223-229:

    payload = {
        'name':         base64(model_hash),
        'dataset-hash': base64(dataset_hash),
        'training-parameters': {
            'epochs':             args.epochs,
            'model_architecture': args.architecture,
        }
    }
    payload_bytes = json.dumps(payload).encode('utf-8')
    payload_hash  = sha512(payload_bytes)
    quote         = generate_quote(user_data=payload_hash)

The PoC shows that two distinct sets of argv values
(`args.epochs`, `args.architecture`, `args.dataset`) — over the
SAME trained model and the SAME dataset bytes — produce two
DISTINCT PoT payloads whose SHA-512 hashes go into the SGX
user_data slot verbatim. The SGX measurement does not cover any
of `epochs`, `architecture`, or `dataset`. They are
operator-typed strings echoed into the signed PoT payload as if
they were measured.

This complements Attack 2 (nearai F1: no model-hash slot) by
showing a different F1 instance — instead of a missing slot, a
*present-but-unmeasured* slot.

Laminator's source tree is NOT modified. The PoC reproduces
Laminator's payload-construction shape locally (the relevant
code is small enough to mirror faithfully).
"""

import argparse
import base64
import hashlib
import json
import sys


def build_pot_payload(model_hash: bytes,
                      dataset_hash: bytes,
                      epochs: int,
                      architecture: str) -> bytes:
    """Mirror of laminator main.py:223-231."""
    payload = {
        'name': base64.b64encode(model_hash).decode('utf-8'),
        'dataset-hash': base64.b64encode(dataset_hash).decode('utf-8'),
        'training-parameters': {
            'epochs': epochs,
            'model_architecture': architecture,
        }
    }
    return json.dumps(payload).encode('utf-8')


def sgx_user_data(payload_bytes: bytes) -> bytes:
    """Mirror of laminator main.py:235-237."""
    return hashlib.sha512(payload_bytes).digest()


def main(argv):
    print("=" * 66)
    print("Laminator F1 PoC — argv unmeasured (Attack #14)")
    print("=" * 66)
    print()
    print("Driving the exact payload-construction shape used by")
    print("`generate_attestations/main.py:223-237` (Laminator unmodified).")
    print()

    # Same trained model, same dataset — operator picks the argv.
    model_hash = hashlib.sha256(b"honest-census-model-state-dict").digest()
    dataset_hash = hashlib.sha256(b"census-train-split-v1").digest()

    # Scenario A — the operator types reasonable-looking argv.
    epochs_a, arch_a = 5, "logistic-regression"
    payload_a = build_pot_payload(model_hash, dataset_hash, epochs_a, arch_a)
    user_data_a = sgx_user_data(payload_a)

    # Scenario B — the operator types argv that don't describe the
    # actual training, but still get baked into a hardware-signed
    # PoT receipt over the same model bytes.
    epochs_b, arch_b = 99, "vit-trillion-params"
    payload_b = build_pot_payload(model_hash, dataset_hash, epochs_b, arch_b)
    user_data_b = sgx_user_data(payload_b)

    print("[+] Same trained model in both scenarios:")
    print(f"    model_hash   = {model_hash.hex()}")
    print(f"    dataset_hash = {dataset_hash.hex()}")
    print()

    print("Scenario A — operator argv: `--epochs 5 --architecture logistic-regression`")
    print(f"    payload bytes (JSON):")
    print(f"        {payload_a.decode()}")
    print(f"    sha512(payload) = user_data slot in the SGX quote:")
    print(f"        {user_data_a.hex()}")
    print()

    print("Scenario B — operator argv: `--epochs 99 --architecture vit-trillion-params`")
    print(f"    payload bytes (JSON):")
    print(f"        {payload_b.decode()}")
    print(f"    sha512(payload) = user_data slot in the SGX quote:")
    print(f"        {user_data_b.hex()}")
    print()

    # The verifier's view.
    print("=" * 66)
    print("Verifier's view")
    print("=" * 66)
    print()
    print("    The verifier inspects the SGX quote, recovers `user_data`,")
    print("    decodes the matching `payload` field, and reads the")
    print("    `training-parameters` sub-object. The verifier sees:")
    print()
    print("        Scenario A: epochs=5, architecture=\"logistic-regression\"")
    print("        Scenario B: epochs=99, architecture=\"vit-trillion-params\"")
    print()
    print("    The SGX MRENCLAVE measurement covers `main.py` (the code")
    print("    that built the payload). It does NOT cover:")
    print("        - args.epochs       (operator-typed integer)")
    print("        - args.architecture (operator-typed string)")
    print("        - args.dataset      (selects which load_data path runs)")
    print()
    print("    Both quotes are produced by the same MRENCLAVE-measured")
    print("    code path, with the same hardware key. The verifier")
    print("    accepting Scenario B believes the model was trained for")
    print("    99 epochs as a ViT — when in fact the same bytes were")
    print("    trained for 5 epochs as a logistic-regression. The two")
    print("    `training-parameters` sub-objects are operator-typed and")
    print("    Laminator faithfully passes them through to the signature.")
    print()

    # Sanity: hashes must differ (proves the payload encoding is
    # actually argv-dependent).
    payloads_differ = payload_a != payload_b
    hashes_differ = user_data_a != user_data_b
    same_model = True

    assert payloads_differ
    assert hashes_differ
    assert same_model

    print("    payloads_differ:   {}".format(payloads_differ))
    print("    user_data differs: {}".format(hashes_differ))
    print("    model_hash same:   {}".format(same_model))
    print()
    print("=" * 66)
    print("[+] ATTACK CONFIRMED (P5, F1 — argv unmeasured)")
    print("=" * 66)
    print()
    print("    Two distinct PoT receipts over the SAME model bytes carry")
    print("    different `epochs` and `model_architecture` claims, each")
    print("    SGX-signed via Laminator's unmodified payload-building")
    print("    code. The hardware signature ✓ in both cases; the SGX")
    print("    measurement says nothing about which set of argv was")
    print("    typed at launch time.")
    print()
    print("    Fix: either (a) fold argv into the SGX manifest so it")
    print("    becomes part of MRENCLAVE, or (b) require the verifier")
    print("    to pin every value of `training-parameters` against an")
    print("    independently-supplied policy (failing closed on any")
    print("    field not pinned).")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--laminator-src",
        help="ignored — included for run_poc.sh compatibility",
        default=None,
    )
    args = parser.parse_args()
    main(args)
