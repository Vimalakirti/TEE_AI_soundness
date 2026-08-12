 EphemeralML / Cyntrisec Dishonest-Prover PoC
# EphemeralML / Cyntrisec Dishonest-Prover PoC

> **Paper PoC IDs:** P7 (sampling unattested, F7), P10 (signing-key chain, F6), P15 (RAG context, F9), P17 (default policy pins no identity, F3). See [`../POC_INDEX.md`](../POC_INDEX.md).

Standalone proof of concept for **Finding E-1** from
`../ephemeralml_soundness_finding.md` (`AirVerifyPolicy::default()`
accepts arbitrary `model_hash`).

EphemeralML's source tree is **not** modified. The PoC is a separate
Rust crate that path-depends on `EphemeralML/common`.

## Threat model

- The "prover" is the operator of an EphemeralML deployment. The
  Cyntrisec AWS BYOC pilot ships a customer-controlled Nitro
  enclave; the worker inside computes per-inference receipts and
  the verifier-API (or any third-party AIR v1 implementor) verifies
  them.
- Per inference, the worker constructs an `AirReceiptClaims` (with
  `model_hash` set to the SHA-256 of the actually-loaded model
  bytes), CBOR-encodes the claims, COSE_Sign1-signs with the
  per-session Ed25519 key, and returns the bytes. The session
  public key is bound into the Nitro NSM attestation's `user_data`
  alongside `model_hash`.
- A verifier calls `verify_air_v1_receipt(data, public_key, policy)`.

**Within a single enclave instance** the operator cannot serve a
different model than `user_data.model_hash` advertises — the bytes
are loaded into Nitro-encrypted memory at boot and not re-readable
from disk during the session.

**Across enclave instances** the operator chooses which model each
instance loads. Each instance's receipts are internally consistent
(the receipt's `model_hash` matches the bytes that instance saw).
The verifier never cross-checks `model_hash` against an expected
value unless the caller explicitly sets
`AirVerifyPolicy.expected_model_hash`.

**Goal:** show that two receipts carrying different `model_hash`
values, both signed by the same valid Ed25519 key, both verify
under `AirVerifyPolicy::default()`. Pinning the expected hash via
`expected_model_hash` correctly distinguishes them.

## How the attack works

`common/src/air_verify.rs:250-301`:

```rust
pub struct AirVerifyPolicy {
    pub max_age_secs: u64,
    // ...
    pub expected_model_hash: Option<[u8; 32]>,
    pub expected_model_id: Option<String>,
    pub expected_attestation_doc_hash: Option<[u8; 32]>,
    pub expected_nonce: Option<Vec<u8>>,
    // ...
}

impl Default for AirVerifyPolicy {
    fn default() -> Self {
        Self {
            // ... every expected_* is None
        }
    }
}
```

`common/src/air_verify.rs:385-415`:

```rust
fn verified_from_checks(checks: &[AirCheck]) -> bool {
    let critical_skip = checks.iter().any(|c|
        matches!(c.status, AirCheckStatus::Skip) && is_critical_check_name(c.name));
    !critical_skip && checks.iter().all(|c|
        matches!(c.status, AirCheckStatus::Pass | AirCheckStatus::Skip))
}

fn is_critical_check_name(name: &str) -> bool {
    matches!(name,
        "SIZE" | "COSE_DECODE" | "UNPROTECTED" | "ALG" | "CONTENT_TYPE"
        | "PAYLOAD" | "CLAIMS_DECODE" | "EAT_PROFILE" | "SIG" | "CTI"
        | "MHASH_PRESENT" | "MEAS" | "MTYPE" | "MHASH_SCHEME"
        | "SECURITY_MODE")
}
```

`MHASH` (the policy match against `expected_model_hash`) is **not**
in `is_critical_check_name`. When the policy field is `None`, the
layer-5 `MHASH` check emits `Skip`. `Skip` for a non-critical name
counts as Pass for the overall verdict, so `verified = true` even
though the receipt's `model_hash` was never checked against a
pinned value.

Same applies to `MODEL`, `ADHASH`, `PLATFORM`, and the nonce match.

## Files

| File | Purpose |
|---|---|
| `Cargo.toml` | Standalone crate with a path dependency on `../EphemeralML/common`. Defines two binaries. |
| `src/main.rs` | (F2 / E-1) Builds two AIR v1 receipts with distinct `model_hash` values, signed by the same Ed25519 key. Verifies each under `AirVerifyPolicy::default()` (both pass) and a strict policy with `expected_model_hash` pinned (only the legitimate one passes). |
| `src/bin/poc_f7.rs` | (F7 / Attack 9) Same enclave, same prompt, two different responses. Both receipts pass `AirVerifyPolicy::default()` and also pass a strict policy pinning `expected_model_hash` and `expected_request_hash`. Demonstrates that the verifier *cannot* pin `expected_response_hash` because the LLM is non-deterministic by design — closing F7 requires extending the receipt schema with sampling-parameter claims. |
| `src/bin/poc_f9_context_unattested.rs` | (F9 / Attack 13) Same user, same question, two different model inputs: scenario A sends only the user's question to the model; scenario B silently prepends a RAG document the user never specified. Both receipts pass any deployable policy for a RAG-enabled service. Demonstrates that AIR v1 has no field distinguishing user-input bytes from operator-mediated context bytes (RAG documents, tool outputs, conversation history, output filters). Closing F9 requires extending the CDDL with `prepended_context_hash`, `tool_call_log_hash`, and `post_processing_pipeline_hash` claims. |
| `run_poc.sh` | Convenience wrapper that picks a nightly Rust toolchain compatible with the workspace lockfile, builds, and runs all three binaries in sequence. |

## How to run

```bash
cd ephemeralml_poc_dishonest_prover
./run_poc.sh
```

If you have a recent stable Rust ≥ 1.85 the toolchain override is
not needed; you can just `cargo run --release`.

Override the toolchain:

```bash
RUST_TOOLCHAIN=stable ./run_poc.sh
```

## Expected output

```text
[+] Built two AIR v1 receipts signed by the same Ed25519 key.
    legit model_hash:  1111...
    evil  model_hash:  2222...

Scenario 1 — verify both receipts under AirVerifyPolicy::default()
    label: legit (default policy)
    verified: true
        check MHASH        -> Skip
        check ADHASH       -> Skip
        check MODEL        -> Skip
    label: evil  (default policy)
    verified: true
        check MHASH        -> Skip

[+] BOTH receipts verified under default policy.

Scenario 2 — pin expected_model_hash = legit; verify both
    label: legit (strict policy)
    verified: true
        check MHASH        -> Pass
    label: evil  (strict policy)
    verified: false
        check MHASH        -> Fail

[+] ATTACK CONFIRMED (E-1)
```

## What this PoC does NOT do

- It does not exercise a real Nitro NSM attestation. The point is
  the verifier-side check; the receipt's signature is real
  (Ed25519, `verify_strict`), the COSE_Sign1 layering is real, the
  CBOR encoding is real. The Ed25519 key used here corresponds to
  a hypothetical session key — in production the same key would be
  bound into a Nitro NSM document, but `verify_air_v1_receipt`
  itself never inspects the NSM document (that's the caller's
  job).
- It does not modify EphemeralML source. The PoC is a separate
  Cargo crate that imports the public crate API of
  `ephemeral-ml-common`.

## Where model switching fits

This is the **opt-in policy** instance of the model-switching
pattern documented in `../model_switching.md`. EphemeralML's
runtime *does* bind `model_hash` correctly — the gap is purely on
the verifier side, in the default policy's treatment of
unmatched-on-purpose Skip values. The fix is one line:

```rust
fn is_critical_check_name(name: &str) -> bool {
    matches!(name,
        // ... existing critical checks ...
        | "MHASH" | "MODEL" | "ADHASH" | "PLATFORM"  // new
    )
}
```

This breaks every caller using `AirVerifyPolicy::default()`, which
is the desired behaviour: callers must explicitly say "yes, I
intend to skip this check," not have it elided silently.

## Mitigations

- Promote `MHASH`, `MODEL`, `ADHASH`, and `PLATFORM` to the
  critical-check set (one-line fix above).
- Or: provide an explicit `AirVerifyPolicy::strict()` constructor
  and document `default()` as developer-only.
- Or: change the policy struct semantics so `Option<T>::None`
  fails closed for these fields.

## Responsible disclosure

EphemeralML is published by Cyntrisec
(`github.com/cyntrisec/EphemeralML`) and used in their AWS BYOC
confidential AI pilot. Before publishing this finding alongside a
paper, coordinate disclosure with the maintainers and give the
standard 60–90-day fix window.
