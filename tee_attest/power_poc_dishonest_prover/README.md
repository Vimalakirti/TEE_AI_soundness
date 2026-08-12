 A3S Power Dishonest-Prover PoC
# A3S Power Dishonest-Prover PoC

> **Paper PoC IDs:** P3 (stale attestation cache, F2), P6 (Jinja template, F5), P11 (CPU/GPU chain unbound, F8), P18 (hardware_verifier None, F3). See [`../POC_INDEX.md`](../POC_INDEX.md).

Standalone proof of concept for the composed **P-1 + P-2** attack
from `../power_soundness_finding.md` (cached attestation hash + opt-
in load-time re-check), which is the stale-cache instance of model
switching documented in `../model_switching.md`.

Power's source tree is **not** modified. The PoC is a separate Rust
crate that path-depends on `Power/` and exercises the actual library
functions that the live attestation handler and model loader call
into.

## Threat model

- The "prover" is the operator of a Power VM. Per the SEV-SNP / TDX
  threat model, the operator controls the host: the bare-metal
  CPU/firmware (within the bounds of what the trusted hardware
  vendor permits), the hypervisor, the network, and the VM's disk
  (virtio-blk backing storage).
- The operator cannot read or tamper with VM memory at runtime once
  the enclave is booted; CPU memory encryption prevents it.
- The verifier is the SDK client; it pins
  `expected_measurement` against a known-good launch digest and
  checks `report_data[32..64]` against `expected_model_hash` if it
  knows what to expect.

**Goal:** show that with the *default* Power configuration
(`model_hashes` unset), the cached `manifest.sha256` that
`/v1/attestation?model=X` reports is allowed to drift from the
bytes the backend actually loads from disk on a subsequent
`ensure_loaded`. The SGX/SEV-SNP/TDX quote remains genuine and the
launch measurement is unchanged; only the in-payload `model_hash`
field becomes a lie.

## How the attack works

### P-1 — attestation reports a cached hash

`src/api/openai/attestation.rs:91-105`:

```rust
let hash_str = state.config.model_hashes
    .get(model_name).cloned()
    .unwrap_or_else(|| manifest.sha256.clone());
```

The handler takes `model_hash` from (a) `state.config.model_hashes`
(set at startup from HCL) or (b) `manifest.sha256` (computed at
model-registration time and never re-read). Neither path re-hashes
the file at attestation time.

### P-2 — load-time re-hash is opt-in

`src/api/autoload.rs:152-165`:

```rust
if let Some(expected_hash) = state.config.model_hashes.get(model_name) {
    let ok = verify_model_integrity(&load_manifest.path, expected_hash)?;
    if !ok { return Err(...); }
}
```

The integrity re-check fires only when `model_hashes[model_name]`
is set. The default Power deployment leaves the map empty.

### Composed

1. Boot Power with a legitimate model at `./saved_models/X`. First
   registration computes `manifest.sha256 = H_good` and caches it.
2. Verifier requests `/v1/attestation?model=X&nonce=N`. Server
   returns a quote with `report_data[32..64] = H_good`.
3. Operator overwrites the file on the host's backing storage with
   evil bytes (hash `H_evil`).
4. `keep_alive` (default 5 min) expires, or LRU eviction forces a
   reload. The backend re-reads the file. With `model_hashes`
   unset, **no re-hash fires**.
5. Backend now serves the evil bytes.
6. `/v1/attestation?model=X&nonce=N'` returns a *fresh* quote that
   still binds `H_good` — the cached `manifest.sha256` is still
   `H_good` even though the file on disk is `H_evil`.

## Files

| File | Purpose |
|---|---|
| `Cargo.toml` | Standalone crate with `a3s-power = { path = "../Power", default-features = false }`. Two binaries. |
| `src/main.rs` | (F5 / Attack 3) Writes a model file, registers a `ModelManifest`, overwrites the file, then replicates the lookup logic from `attestation.rs:91-105` and the gate from `autoload.rs:152-165`. Shows the endpoint-reported hash is unchanged across the swap; default load-gate allows it; strict load-gate (with `model_hashes` pinned) refuses it. |
| `src/bin/poc_f4_minijinja.rs` | (F4-narrow / Attack 10) Calls Power's `chat_template::render_jinja` directly with two templates — one benign Llama-3 template, one malicious template that silently rewrites the user's system prompt and injects a hidden suffix into every user message. The receipts Power signs (`request_hash`, `response_hash`) cover neither the template nor the rendered prompt, so a verifier sees a faithful transcript with no signal that prompt semantics were hijacked between request validation and `model.forward()`. |
| `src/bin/poc_f8_chain_unbound.rs` | (F8 / Attack 12) Drives the real `a3s_power::tee::attestation::build_report_data` to produce two distinct CPU attestations (different client nonces, same model_hash). Constructs one mock NVIDIA NRAS verdict. Shows the 64-byte `report_data` layout is exactly `[nonce(32) ‖ model_hash(32)]` — no slot for `gpu_uuid` or `nras_verdict_hash`. Therefore the same NRAS verdict can be attached to both CPU attestations and a verifier that has independently verified both signatures has no field to detect the reuse / cross-component mismatch. Demonstrates the vertical-composition gap: each link in the chain is honest, but the chain itself is unbound. |
| `run_poc.sh` | Picks a Rust nightly compatible with Power's lockfile and builds + runs all three binaries. |

## How to run

```bash
cd power_poc_dishonest_prover
./run_poc.sh
```

If your default toolchain is stable Rust ≥ 1.85, plain
`cargo run --release` works.

Override the toolchain:

```bash
RUST_TOOLCHAIN=stable ./run_poc.sh
```

## Expected output

```text
[1] Wrote LEGITIMATE model bytes:
        sha256: c34bf591f66c3e91...

[2] Created ModelManifest (cached at registration time).
        manifest.sha256 = c34bf591f66c3e91...

Scenario A — /v1/attestation?model=census-s (BEFORE swap)
    Endpoint would bind report_data[32..64] = c34bf591f66c3e91...
    ensure_loaded gate: no model_hashes configured — load proceeds with NO re-hash

[3] HOST OVERWROTE the file on disk.
        new on-disk sha256 = 486d2a72d9c85e4a...
        manifest.sha256 (cached) still = c34bf591f66c3e91...

Scenario B — /v1/attestation?model=census-s (AFTER swap)
    Endpoint would STILL bind report_data[32..64] = c34bf591f66c3e91...
    ensure_loaded gate (model_hashes UNSET): no model_hashes configured — load proceeds with NO re-hash

Scenario C — what STRICT policy would catch
    ensure_loaded gate (model_hashes PINNED to H_good): config-pinned hash MISMATCH — load refused

Result
    Endpoint-reported hash unchanged across swap: true
    On-disk bytes changed:                          true
    Default-policy load gate allows swap:           true
    Strict-policy load gate refuses swap:           true

[+] ATTACK CONFIRMED (P-1 composed with P-2)
```

## What this PoC does NOT do

- It does not boot a real Power VM or generate real SEV-SNP / TDX
  quotes. The point is the *application-layer* binding between
  the attestation payload and the on-disk model bytes; that binding
  is what's broken in the default configuration. The hardware quote
  on top of the broken binding is honest — it faithfully commits to
  whatever bytes the handler put into `report_data`, which here is
  the stale cached hash.
- It does not modify Power's source tree. The PoC is a separate
  Cargo crate; the integrity check is the live
  `tee::model_seal::verify_model_integrity` function imported from
  the published crate.

## Where model switching fits

This is the **stale-cache** instance of the model-switching pattern
in `../model_switching.md`. Power's design is structurally fine —
the model_hash field exists in `report_data`, and the load-time
gate exists in `ensure_loaded`. The gap is that both depend on
configuration the tenant admin must set up. The default Power
deployment has `model_hashes` unset, which leaves the attestation
free to drift.

The fix is one config flag promoted to mandatory:

```toml
[model_hashes]
"census-s" = "sha256:c34bf591f66c3e91..."
```

Better still: have `/v1/attestation` re-hash the *currently loaded*
model bytes (from the backend's in-memory buffer, not from disk) so
the cached value can't go stale.

## Mitigations

- Make `model_hashes[model_name]` mandatory when TEE mode is on.
  Refuse to start with `tee_mode = true` and an empty
  `model_hashes` map.
- Or: have `/v1/attestation` recompute the hash on every call.
- Or: bind the attestation to the *currently-loaded* model object
  rather than to a cached config value.
- Or: extend the launch measurement to cover model bytes via a
  modelwrap-style dm-verity mount.

## Responsible disclosure

A3S Power is published on crates.io (`a3s-power`) and is positioned
as a production-aimed TEE inference server. Before publishing this
finding alongside a paper, coordinate disclosure with the A3S Lab
maintainers and give the standard 60–90-day fix window.
