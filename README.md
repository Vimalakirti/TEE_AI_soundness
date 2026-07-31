# TEE-AI Attestation Soundness

This repository is the research artifact for **Attested Code, Unattested
Behavior: Soundness Gaps in TEE-Based Attestation for AI Inference**. It
contains the source-grounded audit records and eighteen executable witnesses
used in the paper.

The paper uses *executable witness* as the umbrella term. Several witnesses
demonstrate concrete attacks under a dishonest-provider threat model. Others
exercise a narrower boundary of an evidence format, low-level API, or
illustrative verifier. [`tee_attest/poc_index.md`](tee_attest/poc_index.md) is
the authoritative P1--P18 map and states the evaluated boundary of every case.

## Current paper-aligned scope

- Six audited artifacts spanning build, runtime attestation, receipt formats,
  and verifier-side checks.
- Nine diagnostic failure classes, F1--F9.
- Eighteen active executable witnesses, P1--P18.
- Audited upstream revisions pinned as git submodules.
- Per-system finding documents and coordinated-disclosure correspondence.

Earlier working documents used a nineteen-attack numbering that included a
NEAR AI model-identity finding. That finding was withdrawn after the maintainer
showed that the platform binds model identity through `mr_config_id` and its
compose measurement. Historical documents and scripts are retained for
reproducibility, but the current paper and `poc_index.md` supersede their old
aggregate counts and labels.

## Repository layout

```text
TEE_AI_soundness/
├── README.md
├── .gitmodules
└── tee_attest/
    ├── poc_index.md                         current P1--P18 index
    ├── responsible_disclosure_emails.md    disclosure record
    ├── *_soundness_finding.md              per-system source audits
    ├── *_poc_dishonest_prover/             runnable witness harnesses
    ├── unified_tee_ai_attestation_soundness.md  historical synthesis
    ├── attack_catalog.md                    historical attack numbering
    └── upstream submodules                  code at audited revisions
```

## Active witness map

| System | Paper witnesses | Main evaluated boundary |
|---|---|---|
| Laminator | P1, P2, P5 | loader and payload-construction behavior; SGX quote generation is stubbed |
| A3S/Power | P3, P6, P11, P18 | real library helpers; no confidential-VM or H100 execution |
| EphemeralML / AIR | P7, P10, P15, P17 | real AIR builders and verifiers; no Nitro hardware execution |
| NEAR AI Cloud verifier | P8, P9, P12, P13, P16 | published illustrative-client and signed-text behavior; synthetic external evidence where stated |
| Tinfoil `modelwrap` | P4 | unmodified standalone build-tool cache path; first-party deployment has additional checks |
| Tinfoil SDK | P14 | release-resolution behavior against a mock proxy; bundle bodies are placeholders |

See [`tee_attest/poc_index.md`](tee_attest/poc_index.md) for the property,
source boundary, adversary capability, and post-disclosure status of every
witness.

## Cloning

The audited upstream systems are git submodules pinned to the revisions used
by the finding documents:

```bash
git clone --recurse-submodules <repo-url> TEE_AI_soundness
cd TEE_AI_soundness
```

For an existing clone:

```bash
git submodule update --init --recursive
```

## Environment

Python witnesses require Python 3.10 or newer. Rust witnesses use
`nightly-2025-07-01` because of the upstream dependency lockfiles.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install torch numpy cryptography
rustup install nightly-2025-07-01
```

Set the source paths used by the harnesses:

```bash
export REPO_ROOT="$(pwd)/tee_attest"
export LAMINATOR_SRC="$REPO_ROOT/laminator/generate_attestations"
export MODELWRAP_SRC="$REPO_ROOT/tinfoil/modelwrap"
export NEARAI_SRC="$REPO_ROOT/nearai-cloud-verifier"
```

## Reproducing the witnesses

Each system directory has its own `README.md` and `run_poc.sh`. The upstream
source trees are not modified: Python harnesses import audited functions, and
Rust harnesses use path dependencies on the audited crates.

Run one system's harness:

```bash
cd "$REPO_ROOT/laminator_poc_dishonest_prover"
./run_poc.sh
```

Run all six harnesses:

```bash
for poc in laminator modelwrap power ephemeralml nearai tinfoil; do
  (cd "$REPO_ROOT/${poc}_poc_dishonest_prover" && ./run_poc.sh)
done
```

No harness contacts a production service. The witnesses do not require a GPU
or TEE hardware. Some exercise unmodified implementation functions directly;
others reproduce a published evidence layout or decision path while mocking an
external hardware or service boundary. The P1--P18 index identifies this
distinction so an accepted local result is not mistaken for an end-to-end
hardware compromise.

## Responsible disclosure

The findings were disclosed to all affected maintainers under a coordinated
60-day embargo. The embargo expired before paper submission, so the complete
eighteen-witness artifact is available to reviewers. The repository records
the audited behavior and separately records shipped fixes, remediation
commitments, and maintainer clarifications.

