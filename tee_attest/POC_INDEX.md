# PoC Index (P1–P18)

Canonical map from the paper's proof-of-concept identifiers **P1–P18**
(Table 1, "The eighteen PoCs") to each PoC's surveyed system, reviewed
commit, source path, and expected output. This index is the
authoritative numbering; the per-system `*_poc_dishonest_prover/`
directories and working notes (`attack_catalog.md`,
`unified_tee_ai_attestation_soundness.md`) predate this scheme and use
older internal labels.

The PoCs are grouped by the execution-profile component each targets:
model identity `M`, configuration/decoding policy `C`, live channel
`x`, hardware path `H`, system-provided context `A`, and a
cross-cutting opt-in verifier policy (`F3`).

All paths are relative to this `tee_attest/` directory. Each PoC dir
has a `run_poc.sh` that drives every stage; the "Run" column gives the
single-PoC command (from inside that PoC dir).

## Model identity (M)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P1 | Laminator | F5, F2 | `ce2d10b` | `laminator_poc_dishonest_prover/demo_pickle_attack.py`, `demo_model_switching.py` | `python3 demo_pickle_attack.py` | `torch.load` runs the injected pickle; `utils.test` is patched to return 0.99; the attested identity stays fixed while the served weights swap. |
| P2 | Laminator | F5 | `ce2d10b` | `laminator_poc_dishonest_prover/forge_attestation_payload.py` | `python3 forge_attestation_payload.py` | Forged payload reports 99% accuracy for a randomly-initialized model; `REPORTDATA == SHA-512(payload)` still holds. |
| P3 | A3S/Power | F2 | `7bbaebee` | `power_poc_dishonest_prover/src/main.rs` (bin `poc`) | `./target/release/poc` | `/v1/attestation` reports the cached registration-time hash after the on-disk bytes are overwritten; the reported hash and the loaded bytes diverge while the quote stays genuine. |
| P4 | modelwrap | F2 | `6d514838` | `modelwrap_poc_dishonest_prover/demo_skip_attack.py` | `python3 demo_skip_attack.py` | The skip-rebuild path returns a pre-placed root hash; exit code, stdout, and `.info` format are indistinguishable from a real build. |

## Configuration and decoding policy (C)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P5 | Laminator | F1 | `ce2d10b` | `laminator_poc_dishonest_prover/demo_argv_unmeasured.py` | `python3 demo_argv_unmeasured.py` | Fixed model/dataset hashes but changed `argv` yield different signed metadata; `argv` is absent from the launch measurement. |
| P6 | A3S/Power | F5 | `7bbaebee` | `power_poc_dishonest_prover/src/bin/poc_f4_minijinja.rs` | `./target/release/poc_f4_minijinja` | Two Jinja templates render identical messages into different model inputs; the receipt still verifies. |
| P7 | EphemeralML | F7 | `44cb844e` | `ephemeralml_poc_dishonest_prover/src/bin/poc_f7.rs` | `./target/release/poc_f7` | Two AIR receipts with the same model and input but different sampling both verify; the format has no sampling field to pin. |
| P8 | NEAR AI Cloud | F7 | `8b7830e9` | `nearai_poc_dishonest_prover/demo_sampling_unattested.py` | `python3 demo_sampling_unattested.py` | Two receipts differing only in sampling both verify; the signed text has no sampling slot. |

## Live channel (x)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P9 | NEAR AI Cloud | F6 | `8b7830e9` | `nearai_poc_dishonest_prover/demo_channel_unbound.py` | `python3 demo_channel_unbound.py` | The report-data check accepts a synthetic quote with a mismatched live TLS key; only the opt-in key-comparison check detects the mismatch. |
| P10 | EphemeralML | F6 | `44cb844e` | `ephemeralml_poc_dishonest_prover/src/bin/poc_f6_signing_key_chain.rs` | `./target/release/poc_f6_signing_key_chain` | The low-level verifier accepts a receipt signed by a software key that is not chained to a Nitro NSM document. |

## Hardware path (H)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P11 | A3S/Power | F8 | `7bbaebee` | `power_poc_dishonest_prover/src/bin/poc_f8_chain_unbound.rs` | `./target/release/poc_f8_chain_unbound` | The 64-byte report-data carries only nonce + model hash, with no GPU-verdict commitment; a mock GPU verdict pairs freely. |
| P12 | NEAR AI Cloud | F8 | `8b7830e9` | `nearai_poc_dishonest_prover/demo_cpu_gpu_chain_unbound.py` | `python3 demo_cpu_gpu_chain_unbound.py` | The illustrative client prints, but does not reject, a GPU-nonce mismatch; the same verdict is reusable across CPU quotes. |
| P13 | NEAR AI Cloud | F4 | `8b7830e9` | `nearai_poc_dishonest_prover/demo_nras_jwt_unsigned.py` | `python3 demo_nras_jwt_unsigned.py` | `base64url_decode_jwt_payload` accepts an unsigned NRAS JWT; the signature is never checked. |
| P14 | tinfoil-go | F4 | `ff185e53` | `tinfoil_poc_dishonest_prover/demo_proxy_rollback.py` | `python3 demo_proxy_rollback.py` | The SDK's release resolution follows the mock proxy; an older, still-validly-signed release is selected without breaking any signature. |

## System-provided context (A)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P15 | EphemeralML | F9 | `44cb844e` | `ephemeralml_poc_dishonest_prover/src/bin/poc_f9_context_unattested.rs` | `./target/release/poc_f9_context_unattested` | An AIR receipt for a bare question and one for the same question prefixed with retrieved context both verify; the format has no separate context field. |
| P16 | NEAR AI Cloud | F9 | `8b7830e9` | `nearai_poc_dishonest_prover/demo_history_injection.py` | `python3 demo_history_injection.py` | The signed-text check cannot distinguish user-typed bytes from operator-injected conversation history. |

## Opt-in verifier policy (F3)

| P | System | Class | Reviewed commit | Source | Run | Expected output |
|---|---|---|---|---|---|---|
| P17 | EphemeralML | F3 | `44cb844e` | `ephemeralml_poc_dishonest_prover/src/main.rs` (bin `poc`) | `./target/release/poc` | `AirVerifyPolicy::default()` returns `verified=true` for two receipts with different model hashes; a `strict()` policy with `expected_model_hash` rejects the substituted one. |
| P18 | A3S/Power | F3 | `7bbaebee` | `power_poc_dishonest_prover/src/bin/poc_f2_hardware_verifier_none.rs` | `./target/release/poc_f2_hardware_verifier_none` | `hardware_verifier: None` returns success with `hardware_verified=false`; supplying a hardware verifier rejects the fabricated report. |

## Positive controls

For four PoCs the audited code already ships a stricter check that
detects the demonstrated mismatch once enabled: **P3** (pin
`model_hashes`), **P9** (compare the attested key with the live TLS
key), **P17** (set `expected_model_hash`), and **P18** (supply the
hardware verifier). Re-running each with the check enabled turns the
accepted witness into a rejection, confirming the acceptance came from
a disabled check.

## Withdrawn

An earlier "no model-identity binding" attack against NEAR AI Cloud
was **withdrawn**: NEAR binds the model through `mr_config_id` over
the signed `app_compose`, so the property is bound at the platform.
Its demo has been removed from the artifact; it is not one of the
eighteen PoCs.
