# TEE-AI Attestation Soundness

Research artifact for an offensive study of **soundness** in
TEE-based AI attestation systems: a dishonest-provider threat model,
nine failure classes (F1–F9), and **eighteen runnable
proof-of-concept attacks (P1–P18)** against six surveyed systems
(one academic prototype, one open build-time tool, and four
commercial / research-stage cloud services). The work targets the
gap between *confidentiality* (extensively studied) and *soundness*
(the question of whether the claims a verifier accepts about a
TEE-AI computation are actually true), which prior TEE-ML literature
has largely ignored.

[`tee_attest/POC_INDEX.md`](tee_attest/POC_INDEX.md) is the
canonical map from the paper's PoC identifiers **P1–P18** to each
PoC's system, reviewed commit, source path, and expected output.
The unified findings document
([`tee_attest/unified_tee_ai_attestation_soundness.md`](tee_attest/unified_tee_ai_attestation_soundness.md))
is the long-form reference: threat model, nine-class taxonomy
F1–F9, cross-system matrix, and defenses. (The working notes
predate the P1–P18 numbering and use older internal labels;
`POC_INDEX.md` is authoritative.)

---

## Repository layout

```
TEE_AI_soundness/
├── README.md                  ← you are here
├── .gitignore
├── .gitmodules                ← 10 upstream submodules
└── tee_attest/
    ├── POC_INDEX.md                                   canonical P1–P18 index
    ├── unified_tee_ai_attestation_soundness.md        long-form findings
    ├── attack_catalog.md                              working attack catalog
    ├── model_switching.md                             cross-cutting attack family
    ├── paper/
    │   └── laminator.pdf                              reference paper (CODASPY 2025)
    │
    ├── <system>_soundness_finding.md      ×6          per-system findings
    ├── <system>_poc_dishonest_prover/     ×6          runnable PoCs (P1–P18)
    │
    └── <upstream submodules>              ×10         third-party code under audit
        EphemeralML/  Power/  laminator/  nearai-cloud-verifier/
        tinfoil/{confidential-model-router, verifiable-reviewer,
                  tinfoil-python, tinfoil-go, modelwrap, cvmimage}
```

### Documentation map

| Read this | For |
|---|---|
| `tee_attest/POC_INDEX.md` | Canonical P1–P18 → system, reviewed commit, source path, expected output. |
| `tee_attest/unified_tee_ai_attestation_soundness.md` | Threat model, nine-class taxonomy F1–F9, cross-system matrix, defenses, glossary. |
| `tee_attest/attack_catalog.md` | Long-form working catalog (older internal numbering; see `POC_INDEX.md`). |
| `tee_attest/<system>_soundness_finding.md` | Per-system audit, line-numbered against the submodule sources. |
| `tee_attest/<system>_poc_dishonest_prover/README.md` | Per-PoC threat model, code map, and exact reproduction steps. |

---

## Cloning

The six audited upstream systems live as **git submodules**, pinned
to the commits the findings were written against (see `POC_INDEX.md`).
Clone with submodules in one shot:

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

Two toolchains cover everything: a Python venv for the Python-based
PoCs and a Rust nightly for the two Rust-based PoCs.

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

The PoC scripts resolve their upstream source tree relative to the
PoC directory by default (each upstream system is a sibling
submodule under `tee_attest/`), so no per-machine setup is needed
after `git submodule update --init --recursive`. Every `run_poc.sh`
still honors an override env var if you keep the sources elsewhere:

```bash
export LAMINATOR_SRC=/path/to/laminator/generate_attestations
export MODELWRAP_SRC=/path/to/tinfoil/modelwrap
export NEARAI_SRC=/path/to/nearai-cloud-verifier
```

---

## Reproducing the PoCs

Each PoC directory is self-contained, with its own `README.md`
(threat model, code map, expected output) and a `run_poc.sh` that
drives every stage in order. The convention across all PoCs is:
**the upstream system's source tree is never modified.** Python
PoCs `import` from the upstream tree; Rust PoCs path-depend on the
upstream crate. See `tee_attest/POC_INDEX.md` for the per-PoC
source path and expected output.

| System | PoC dir | Lang | PoCs (class) |
|---|---|---|---|
| Laminator | `laminator_poc_dishonest_prover/` | Python (`torch`) | P1 pickle RCE + model switching (F5, F2), P2 accuracy-metric forgery (F5), P5 argv unmeasured (F1) |
| modelwrap | `modelwrap_poc_dishonest_prover/` | Python | P4 build-cache skip accepts pre-placed output (F2) |
| A3S/Power | `power_poc_dishonest_prover/` | Rust (nightly) | P3 stale attestation cache (F2), P6 Jinja template hijack (F5), P11 CPU↔GPU chain unbound (F8), P18 `hardware_verifier: None` (F3) |
| EphemeralML | `ephemeralml_poc_dishonest_prover/` | Rust (nightly) | P7 sampling unattested (F7), P10 signing-key chain (F6), P15 RAG-context unattested (F9), P17 default policy pins no identity (F3) |
| NEAR AI Cloud | `nearai_poc_dishonest_prover/` | Python (`cryptography`) | P13 NRAS JWT unverified (F4), P9 live-channel opt-in (F6), P8 sampling unattested (F7), P12 CPU↔GPU verdict reuse (F8), P16 conversation-history injection (F9) |
| tinfoil-go | `tinfoil_poc_dishonest_prover/` | Python | P14 proxy-mediated release rollback (F4) |

The `nearai_poc_dishonest_prover/` directory also retains a
withdrawn `demo_no_model_binding.py` (NEAR binds the model through
`mr_config_id` over the signed `app_compose`); it is not one of the
eighteen PoCs and is not run by `run_poc.sh`.

### Run a single PoC

```bash
cd tee_attest/laminator_poc_dishonest_prover
./run_poc.sh                       # prints stage-by-stage banners
```

### Run all six PoC suites

```bash
for poc in laminator modelwrap power ephemeralml nearai tinfoil; do
  echo "=========================================="
  echo "Running $poc PoC suite"
  echo "=========================================="
  ( cd "tee_attest/${poc}_poc_dishonest_prover" && ./run_poc.sh )
done
```

Each PoC ends with a stage banner stating what it produced. See the
per-PoC `README.md` (and `POC_INDEX.md`) for what each banner means
and what to inspect in the dumped payloads / quotes / receipts.

### Coverage

The eighteen PoCs span all six systems and anchor every failure
class F1–F9. Several drive the surveyed systems' *original,
unmodified* code directly; the rest build a small mock at an
external trust boundary (e.g., a fake NRAS endpoint, a fake
`github-proxy.tinfoil.sh`) so that the system's own verifier logic
is what accepts the result. For four PoCs (P3, P9, P17, P18) the
audited code already ships a stricter check that, once enabled,
turns the accepted result into a rejection — the positive controls
in `POC_INDEX.md`.

---

## Responsible disclosure

Every finding was coordinated with the affected vendor before
publication under a coordinated-disclosure embargo, which has since
elapsed. Please do not retarget the PoCs against live production
endpoints; they are designed to run against local checkouts of the
open-source code under the dishonest-provider threat model.

---

## Citation

Citation metadata will be added when the paper appears.
