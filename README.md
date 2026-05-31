# TEE-AI Attestation Soundness

Research artifact for an offensive study of **soundness** in
TEE-based AI attestation systems: a malicious-prover threat model,
nine vulnerability classes, and nineteen runnable proof-of-concept
attacks against six surveyed systems (one academic prototype, one
open build-time tool, and four commercial / research-stage cloud
services). The work targets the gap between *confidentiality*
(extensively studied) and *soundness* (the question of whether the
claims a verifier accepts about a TEE-AI computation are actually
true), which prior TEE-ML literature has largely ignored.

A draft paper introduction is in [`tee_attest/intro.md`](tee_attest/intro.md).
The unified findings document
([`tee_attest/unified_tee_ai_attestation_soundness.md`](tee_attest/unified_tee_ai_attestation_soundness.md))
is the master reference: threat model (§2), nine-class taxonomy
F1–F9 (§3), cross-system matrix (§4), defenses (§5).

---

## Repository layout

```
TEE_AI_soundness/
├── README.md                  ← you are here
├── .gitignore
├── .gitmodules                ← 10 upstream submodules
└── tee_attest/
    ├── intro.md                                       paper draft (intro)
    ├── unified_tee_ai_attestation_soundness.md        master findings (160 KB)
    ├── attack_catalog.md                              19 attacks, indexed
    ├── model_switching.md                             cross-cutting attack family
    ├── mats.md                                        confidentiality-audit benchmark notes
    ├── advisor_pitch_slides.md
    ├── responsible_disclosure_emails.md
    ├── paper/
    │   └── laminator.pdf                              reference paper (CODASPY 2025)
    │
    ├── <system>_soundness_finding.md      ×6          per-system findings
    ├── <system>_poc_dishonest_prover/     ×6          runnable PoCs
    │
    └── <upstream submodules>              ×10         third-party code under audit
        EphemeralML/  Power/  laminator/  nearai-cloud-verifier/
        tinfoil/{confidential-model-router, verifiable-reviewer,
                  tinfoil-python, tinfoil-go, modelwrap, cvmimage}
```

### Documentation map

| Read this | For |
|---|---|
| `tee_attest/intro.md` | The one-page pitch (S&P/NDSS-style paper intro draft). |
| `tee_attest/unified_tee_ai_attestation_soundness.md` | Threat model, nine-class taxonomy F1–F9, cross-system matrix, defenses, glossary. |
| `tee_attest/attack_catalog.md` | The 19 attacks at a glance with severity and links. |
| `tee_attest/<system>_soundness_finding.md` | Per-system audit, line-numbered against the submodule sources. |
| `tee_attest/<system>_poc_dishonest_prover/README.md` | Per-PoC threat model, code map, and exact reproduction steps. |

---

## Cloning

The six audited upstream systems live as **git submodules**, pinned
to the commits the findings were written against. Clone with
submodules in one shot:

```bash
git clone --recurse-submodules <repo-url> TEE_AI_soundness
cd TEE_AI_soundness
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

The submodules total ~210 MB; the rest of the tree is small.

---

## Environment

Two toolchains cover everything: a Python venv for the four
Python-based PoCs and a Rust nightly for the two Rust-based PoCs.

### 1. Python (Laminator, modelwrap, NEAR AI, Tinfoil PoCs)

```bash
python3 -m venv .venv               # Python ≥ 3.10
source .venv/bin/activate
pip install --upgrade pip
pip install torch numpy cryptography
```

Stdlib covers the rest. No GPU is required — the PoCs do not
perform real inference; they exercise verifier/attestation logic
on CPU.

### 2. Rust (Power, EphemeralML PoCs)

Both Rust PoCs pin `nightly-2025-07-01` (required by
`edition2024` deps in the upstream lockfiles). Install via
[rustup](https://rustup.rs/):

```bash
rustup install nightly-2025-07-01
```

The PoCs invoke this toolchain explicitly via `rustup run`; no
default-toolchain change is needed.

### 3. Paths

After cloning, set these once per shell — the PoC `run_poc.sh`
scripts read them as env vars (with stale defaults from the
original author's machine, so set them explicitly):

```bash
export REPO_ROOT="$(pwd)/tee_attest"
export LAMINATOR_SRC="$REPO_ROOT/laminator/generate_attestations"
export MODELWRAP_SRC="$REPO_ROOT/tinfoil/modelwrap"
export NEARAI_SRC="$REPO_ROOT/nearai-cloud-verifier"
```

---

## Reproducing the PoCs

Each PoC is a self-contained directory with its own `README.md`
(threat model, code map, expected output) and a top-level
`run_poc.sh` that drives every stage in order. The convention
across all PoCs is: **the upstream system's source tree is never
modified.** Python PoCs `import` from the upstream tree; Rust PoCs
path-depend on the upstream crate.

| System | PoC dir | Lang | Drives | Demonstrates |
|---|---|---|---|---|
| Laminator | `laminator_poc_dishonest_prover/` | Python (`torch`) | unmodified `laminator/generate_attestations/` | 5 stages: pickle RCE inside enclave (F4), model switching (F4+F5), argv unmeasured (F1, attack 14) |
| modelwrap | `modelwrap_poc_dishonest_prover/` | Python | unmodified `tinfoil/modelwrap` | F5 build-time: pre-placed output bypasses the actual build |
| Power / A3S | `power_poc_dishonest_prover/` | Rust (nightly) | path-deps `Power/` crate, unmodified | 4 binaries: F5 stale attestation cache (attack 3), F4 minijinja template hijack (attack 10), F8 CPU↔GPU chain unbound (attack 12), F2 `hardware_verifier: None` (attack 15) |
| EphemeralML | `ephemeralml_poc_dishonest_prover/` | Rust (nightly) | path-deps `EphemeralML/common`, unmodified | 4 binaries: F2 default policy accepts arbitrary `model_hash` (attack 5), F7 sampling unattested (attack 9), F9 RAG-context injection (attack 13), F6 signing-key chain (attack 16) |
| NEAR AI Cloud | `nearai_poc_dishonest_prover/` | Python (`cryptography`) | unmodified `nearai-cloud-verifier` | 6 stages: no-model-binding (attack 2), NRAS JWT unverified (attack 6, F3), live-channel unbound (attack 8, F6), sampling unattested (attack 17, F7), CPU↔GPU chain unbound (attack 18, F8), conversation-history injection (attack 19, F9) |
| Tinfoil SDK | `tinfoil_poc_dishonest_prover/` | Python | re-implements `github-proxy.tinfoil.sh` URL logic; SDK source untouched | F3 rollback (attack 11): proxy chooses which Sigstore bundle the verifier ever sees |

### Run a single PoC

```bash
cd "$REPO_ROOT/laminator_poc_dishonest_prover"
./run_poc.sh                       # prints stage-by-stage banners
```

### Run all six PoCs

```bash
for poc in laminator modelwrap power ephemeralml nearai tinfoil; do
  echo "=========================================="
  echo "Running $poc PoC"
  echo "=========================================="
  ( cd "$REPO_ROOT/${poc}_poc_dishonest_prover" && ./run_poc.sh )
done
```

Each PoC ends with a stage banner stating what it produced. Most
PoCs verify their own result and exit nonzero on unexpected
output; see the per-PoC `README.md` for what each banner means
and what to inspect in the dumped payloads / quotes / receipts.

### Coverage map

Of the 19 attacks catalogued in
[`tee_attest/attack_catalog.md`](tee_attest/attack_catalog.md),
the PoCs collectively run the demonstrators for attacks
**1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
18, 19** — every class F1–F9 is anchored by ≥2 PoCs across ≥2
systems (F4 has 3). Of the 19, **eight** drive the surveyed
systems' *original, unmodified* code; the rest build a small mock
at an external trust boundary (e.g., a fake NRAS endpoint, a fake
`github-proxy.tinfoil.sh`) so the system's own verifier logic is
what accepts the attack.

---

## Responsible disclosure

The vulnerabilities demonstrated here have been or are being
coordinated with the affected vendors;
[`tee_attest/responsible_disclosure_emails.md`](tee_attest/responsible_disclosure_emails.md)
tracks the per-system status, templates, and timelines. Please do
not retarget the PoCs against live production endpoints; they are
designed to run against local checkouts of the open-source code.

---

## Citation

A draft paper introduction is in `tee_attest/intro.md`. Citation
metadata will be added when the paper appears.
