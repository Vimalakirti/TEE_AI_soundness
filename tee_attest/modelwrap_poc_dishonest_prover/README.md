# Modelwrap Dishonest-Prover PoC

Standalone proof of concept for **Finding M-1** from
`../modelwrap_soundness_finding.md` (pre-existing output files bypass
the actual build). Modelwrap's source tree is not modified.

## Threat model

- The "prover" is a builder who runs `modelwrap` and ships the
  resulting `<commit>.mpk` and `<commit>.info` to a downstream
  consumer (typically Tinfoil's `cvmimage`, which bakes the root
  hash from `.info` into a measured CVM boot image).
- The builder controls the host that invokes the modelwrap Docker
  container, including the bind-mounted `output/` directory.
- The downstream consumer reads `<commit>.info`, embeds its root
  hash into the CVM build, and trusts that the hash was computed
  from the legitimate Hugging Face revision named by `MODEL`.

**Goal:** ship an `.info` file whose root hash corresponds to
attacker-chosen bytes, while the modelwrap container exit code, the
stdout, and the file format are indistinguishable from a legitimate
build.

## How the attack works

`pack.py:58-71` and `pack.py:77-102`:

```python
if not os.path.exists(mpk_file):
    mkfs_cmd = ["mkfs.erofs", ...]
    subprocess.run(mkfs_cmd, check=True)
    os.rename(mpk_file+".tmp", mpk_file)
else:
    print(f"Using existing EROFS image {mpk_file}")

if not os.path.exists(info_file):
    veritysetup_cmd = ["veritysetup", ...]
    subprocess.run(veritysetup_cmd, check=True)
    ...
else:
    print(f"dm-verity volume already exists at {mpk_file}")
```

The script is idempotent: when outputs exist, it skips the actual
work. Because `output/` is bind-mounted from the host, the builder
can pre-place arbitrary `.mpk` / `.info` content there. No integrity
check ever compares pre-existing files against a fresh build.

## What this PoC does NOT do

- It does not need an HF token. The HF download path is patched out
  in `demo_skip_attack.py` because the skip branch doesn't read
  model bytes anyway.
- It does not need `mkfs.erofs` (which is the only tool the attack
  bypasses). The `--fake-bytes` variant of
  `build_evil_artifacts.py` uses arbitrary bytes; the
  `--real-verity` variant additionally invokes `veritysetup` to
  produce a Merkle tree that downstream consumers could actually
  mount.
- It does not modify `pack.py` on disk. All overrides are runtime:
  `huggingface_hub.snapshot_download` and `HfApi.model_info` are
  rebound in this process before `runpy.run_path('pack.py', ...)`
  executes.

## Files

| File | Purpose |
|---|---|
| `build_evil_artifacts.py` | Forges the attacker-controlled `<commit>.mpk` and `<commit>.info`. Two modes: `--fake-bytes` (default, no external tools) and `--real-verity` (uses `veritysetup` if present). |
| `demo_skip_attack.py` | Patches `huggingface_hub.snapshot_download` to a no-op, then `runpy.run_path('pack.py', ...)` so we exercise the real modelwrap entry point. Asserts the idempotency-skip lines fired and the `.info` contents the user sees are the attacker's. |
| `run_poc.sh` | Runs the two stages in order. |

## How to run

```bash
cd modelwrap_poc_dishonest_prover
./run_poc.sh
```

Override the source location:

```bash
MODELWRAP_SRC=/path/to/modelwrap ./run_poc.sh
```

Build a verity-real artifact (needs `veritysetup` on the host):

```bash
python3 build_evil_artifacts.py --real-verity
python3 demo_skip_attack.py --require-prepopulated
```

## Expected output

The successful run prints:

```text
Stage 1/2 — pre-place evil artifacts in output/
...
        attacker root hash: e1bdb9ea28461a6cca56a8553c3642462c15349159c9388037b0044696bcac9c

Stage 2/2 — run modelwrap pack.py and observe idempotency skip
...
Using existing EROFS image .../deadbeefdeadbeefdeadbeefdeadbeefdeadbeef.mpk
dm-verity volume already exists at .../deadbeefdeadbeefdeadbeefdeadbeefdeadbeef.mpk
e1bdb9ea28461a6cca56a8553c3642462c15349159c9388037b0044696bcac9c_131072_d7a4b7fd-21f1-5642-a9ea-35616abdda39

Post-run assertions
    pack.py said 'Using existing EROFS image':   True
    pack.py said 'dm-verity volume exists':       True
    info contents AFTER pack.py:                  e1bdb9ea28461a6cca56a8553c3642462c15349159c9388037b0044696bcac9c_...

[+] ATTACK CONFIRMED
```

The final line of pack.py's own output is the attacker's chosen root
hash. A downstream consumer reading this file as input to a CVM
build will bake that hash into the launch measurement.

## Where model switching fits

This is **build-layer forgery** — the build-time variant of the
model-switching pattern documented in `../model_switching.md`. The
runtime dm-verity Merkle tree binds bytes to root hash strongly, so
in-place swap of a deployed CVM image is not possible. The weakness
is that the root hash itself is mintable: the builder can issue
*any* root hash for *any* contents, and there is no signature on the
`.info` file that a downstream consumer could pin against.

## Mitigations

- Refuse to start when output files already exist, or always
  rebuild and compare root hashes against the cached file before
  accepting.
- Sign `.info` with a build-time key whose public counterpart is
  pinned in `cvmimage`. Reject any `.info` whose signature does not
  verify.
- Embed `(model_name, commit_hash, image_tag_digest)` inside `.info`
  in a structured format so downstream consumers cross-check
  identity, not just root hash.

## Responsible disclosure

modelwrap is published by Tinfoil
(`github.com/tinfoilsh/modelwrap`) and used by their commercial
inference service. Before publishing this finding alongside a
paper, coordinate disclosure with the maintainers and give the
standard 60–90-day fix window.
