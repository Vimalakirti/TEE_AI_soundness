# Responsible Disclosure — Draft Emails

Six drafts, one per surveyed project. Each is intended to start a
T0 = "the day this email is sent" dialogue per the timeline in
`unified_tee_ai_attestation_soundness.md` §7.2:

- **T0**: vendor acknowledges receipt; send PoC + finding doc.
- **T0 + 7d**: vendor confirms reproduction or asks for help.
- **T0 + 30d**: ask for a fix ETA.
- **T0 + 60d**: confirm fix shipped or extension request.
- **T0 + 90d**: publish.

Bracketed `[PLACEHOLDER]` markers must be filled in before
sending. Each email lists the per-system finding-doc as the
attachment; the runnable PoC under
`<system>_poc_dishonest_prover/` is offered on request.

**Attack #N references** throughout point at the corresponding
row in `attack_catalog.md`. The catalog has 19 PoCs total, with
≥2 PoCs anchored per F-class across ≥2 surveyed systems. After
this disclosure round, per-vendor PoC counts are: Laminator 3
(#1, #7, #14); modelwrap 1 (#4); A3S Power 4 (#3, #10, #12, #15);
NEAR AI 6 (#2, #6, #8, #17, #18, #19); EphemeralML 4 (#5, #9,
#13, #16); Tinfoil SDK 1 (#11). All PoCs print `ATTACK CONFIRMED`
end-to-end against the unmodified system source trees.

---

## 1. Laminator (academic, CODASPY 2025)

**To:** [corresponding author email — see paper's first page]
**CC:** Vasisht Duddu; Antti Järvinen; Lachlan J. Gunn; N. Asokan
**Subject:** Soundness findings in Laminator (CODASPY '25) —
              `torch.load` RCE inside the enclave, plus four
              other gaps

> Dear Prof. Asokan and co-authors,
>
> I am [NAME], a researcher at [AFFILIATION] working on a
> systematization-of-knowledge survey of soundness gaps in
> TEE-based AI attestation systems. Laminator (CODASPY 2025,
> `github.com/ssg-research/laminator`,
> `arxiv.org/abs/2406.17548`) is one of six surveyed systems
> and the only academic prototype in the set.
>
> While reviewing the implementation against the paper's
> Property-of-Training (PoT), Input/Output Attestation (IOAtt),
> and Accuracy Attestation (AccAtt) protocols, I identified
> five soundness findings. The headline result is a `torch.load`
> pickle-RCE inside the SGX enclave that single-handedly forges
> every attestation type Laminator produces.
>
> **Affected** (against commit at HEAD on the public repo):
>
> - Finding 1 — `torch.load` pickle deserialization at
>   `generate_attestations/main.py:291, 384`. The host-supplied
>   `.pth` file's pickle `__reduce__` runs arbitrary code
>   inside the enclave at parse time, before
>   `load_state_dict()` runs. Severity: **Critical** (single-
>   handedly forges any AccAtt / IOAtt / PoT). F-class: F4
>   (trusted code interprets attacker-controlled inputs).
> - Finding 2 — `argv` flows verbatim into the PoT payload via
>   `loader.insecure__use_cmdline_argv = true`
>   (`main.manifest.template:17`). Severity: **High** (decouples
>   reported metadata from cryptographic bindings). F-class: F1.
>   Runnable PoC: Attack #14 in our catalog —
>   `laminator_poc_dishonest_prover/demo_argv_unmeasured.py`.
> - Finding 4 — `h(M)` (model state-dict hash) does not bind a
>   model architecture. Severity: **High** when combined with
>   Finding 1. F-class: F1.
> - Finding 5 — No secure user→enclave channel for IOAtt
>   inputs. Severity: **High** (lets a dishonest prover answer
>   arbitrary inputs in place of the user's). F-class: F6.
> - Three Medium / Low findings (training config `T` empty;
>   PoT non-determinism; placeholder MRENCLAVE entries in the
>   verifier).
>
> Three runnable proofs-of-concept drive `main.py` and
> `audit_attestation.py` **unmodified** against crafted
> inputs:
>   - Attack #1 (switchable pickle loader): same-`SHA-512`
>     payload, host-swappable model between calls.
>   - Attack #7 (metric forgery): `output_accuracy.json`
>     reports `"value": 0.99` for a random-init model.
>   - Attack #14 (argv unmeasured): same trained model with
>     different `--epochs` / `--architecture` argv produces two
>     distinct SGX-signed PoT payloads.
> All three run end-to-end without any code change to the
> Laminator tree and end with the relevant `ATTACK CONFIRMED`
> or forged-attestation output.
>
> **Suggested fixes:**
>
> - Replace `torch.load` with safetensors loaders, or pass
>   `weights_only=True` (PyTorch ≥ 2.0).
> - Either fold `argv` into the SGX manifest (so it becomes part
>   of MRENCLAVE) or hash it as a first-class claim in the PoT
>   payload that the verifier must pin.
> - Add `h(architecture_spec)` as a separate first-class claim
>   in the PoT payload alongside `h(M)`.
> - Bind IOAtt inputs into a verifier-supplied nonce / channel
>   key.
>
> I am drafting a SoK paper to submit on [DATE]. Because
> Laminator is an academic prototype rather than a deployed
> service, I propose a 30-day courtesy window before public
> disclosure, with the explicit goal of acknowledging the
> response in the paper. I am happy to share the full
> per-system finding doc and the runnable PoCs immediately on
> request.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `laminator_soundness_finding.md`
- `laminator_poc_dishonest_prover/` (all PoCs)

---

## 2. Tinfoil — `modelwrap` build-time tool

**To:** security@tinfoil.sh (or as listed in `tinfoilsh/tinfoil`
        `SECURITY.md`)
**Subject:** modelwrap idempotency-skip allows attacker-chosen
              dm-verity root hash

> Hi Tinfoil security team,
>
> I am [NAME], a researcher at [AFFILIATION] conducting a
> systematization-of-knowledge survey of soundness gaps in
> TEE-based AI attestation systems. Tinfoil's `modelwrap` is
> one of six surveyed systems.
>
> I have one **High-severity** finding in modelwrap. The
> idempotency-skip optimization in `pack.py:58-71, 77-102`
> lets a malicious builder pre-place an attacker-chosen
> `<commit>.mpk` + `<commit>.info` pair before running
> modelwrap. The tool sees the outputs exist, skips
> `mkfs.erofs` and `veritysetup`, exits 0, and the downstream
> CVM image-builder bakes the attacker's chosen dm-verity
> root hash into the measured CVM image.
>
> **Affected** (against the public source tree at HEAD):
>
> - Finding M-1 — Pre-existing output files bypass the build
>   (`pack.py:58-71, 77-102`). Severity: **High**. F-class:
>   F5 (build-time variant: cached / pre-existing state stands
>   in for fresh state). PoC: Attack #4 drives the unmodified
>   `pack.py` against a pre-placed output directory.
> - Finding M-2 — Optional `@revision` lets HEAD float
>   (`pack.py:25-31`). Severity: **Medium**. F-class: F1.
> - Three Low-severity findings (HF Hub LFS trust root;
>   unsigned outputs; `HF_TOKEN` unmeasured selects content;
>   bind-mounted cache directory).
>
> A runnable proof-of-concept under
> `modelwrap_poc_dishonest_prover/` drives the unmodified
> `pack.py` against a pre-placed output directory and ends with
> `[+] ATTACK CONFIRMED`. The pre-placed `.info` file's root
> hash differs from the hash that would be computed from a
> fresh build of the named HF revision, but `pack.py` exits 0.
>
> **Suggested fixes:**
>
> - When outputs already exist for the requested
>   `(model, revision)`, either (a) re-build to a temp dir and
>   compare against the existing artefact byte-for-byte, or
>   (b) refuse to proceed until the operator clears the output
>   directory.
> - Add `model_signing_key`-style publisher-signature gates so
>   downstream tools can refuse to consume modelwrap outputs
>   whose `.info` is not signed by an expected key.
>
> I am drafting a SoK paper to submit on [DATE]. I would like
> to coordinate a 60–90-day embargo window, and I am happy to
> share the PoC, the finding doc, and to walk an engineer
> through the reproduction.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `modelwrap_soundness_finding.md`
- `modelwrap_poc_dishonest_prover/`

---

## 3. A3S / Power (Rust crate + EthCC demo)

**To:** [crate maintainer's GitHub-public email, see crates.io
        `power` crate page]
**Subject:** Eight soundness findings in A3S / Power
              (model_hashes default-skip, minijinja
              chat-template hijack, cached attestation hash,
              hardware_verifier opt-in, CPU↔GPU chain unbound)

> Hi [MAINTAINER],
>
> I am [NAME], a researcher at [AFFILIATION] conducting a
> systematization-of-knowledge survey of soundness gaps in
> TEE-based AI attestation systems. A3S / Power is one of
> six surveyed systems; it was selected because it is one of
> the very few public Rust implementations of TEE-AI runtime
> attestation with NVIDIA H100 confidential-compute support.
>
> I have eight findings (four with High-severity
> consequences) and four runnable PoCs that drive Power's
> real, unmodified source. The chained scenario (P-1 cached
> `manifest.sha256` + P-2 default-skip on `model_hashes`)
> produces a verifier-accepting attestation over swapped model
> bytes. A separate finding shows the GGUF chat-template path
> can rewrite user prompts inside the enclave without changing
> any attested claim. Two additional PoCs anchor F2
> (`hardware_verifier: None`) and F8 (CPU↔GPU chain unbound)
> as drop-in demonstrations against Power's published crate
> API.
>
> **Affected** (against the public source tree at HEAD):
>
> - Finding P-2 — `model_hashes`, `model_signing_key`, and
>   `hardware_verifier` are all `Option<>` and default to
>   skip-the-check (`autoload.rs:152-165`). Severity: **High**.
>   F-class: F2 (opt-in policy). PoC: Attacks #3 + #15.
> - Finding P-1 — `/v1/attestation` returns a registration-time
>   `manifest.sha256` rather than re-hashing the currently-
>   loaded model (`api/openai/attestation.rs:91-105`).
>   Severity: **Medium** standalone, but composes with P-2
>   into a **High-severity** chained attack. F-class: F5.
> - Finding (Attack #10) — `backend/chat_template.rs:57-104`
>   renders operator-supplied chat templates from GGUF metadata
>   through minijinja. The sandbox prevents shell access but
>   the template engine can rewrite prompts, jailbreak suffixes,
>   etc. Severity: **Medium** (sandboxed F4 — semantics hijack,
>   not RCE). F-class: F4 (narrow). PoC: Attack #10.
> - Finding (Attack 9 analog) — Power's OpenAI-compatible API
>   honours `temperature`, `top_p`, `seed` per request, but
>   nothing in the attestation payload echoes the sampling
>   regime. Severity: **High**. F-class: F7.
> - Finding P-6 — `A3S_TEE_SIMULATE=1` env var swaps the real
>   attestation path for a synthetic one
>   (`tee/attestation.rs:147-154`); `tee_type == "simulated"`
>   is not auto-rejected by `verify_report`. Severity:
>   **Low / acknowledged**. F-class: F1.
> - Finding P-7 — Hardware-signature verification on the report
>   is optional (`VerifyOptions.hardware_verifier:
>   Option<&dyn HardwareVerifier>`). Severity: **High** in the
>   sense that the most load-bearing check in the chain is
>   defaulted off. F-class: F2. PoC: Attack #15 drives the
>   real `a3s_power::verify::verify_report` with
>   `hardware_verifier: None` and shows a forged report is
>   accepted with `hardware_verified: false` buried in the
>   `VerifyResult` struct.
> - Finding P-8 — `/v1/models/pull` extends the trust surface
>   to HF Hub; HF identifies by name not by publisher
>   signature. Severity: **Low**. F-class: F3.
> - Finding (new, F8) — Power's `report_data` layout
>   (`build_report_data` at `tee/attestation.rs:184-201`) is
>   exactly `[nonce(32) ‖ model_hash(32)]` with no slot for
>   binding an NVIDIA NRAS verdict to the specific CPU
>   computation. Power's marketing of NVIDIA H100
>   confidential-compute support is accurate at each link —
>   but the chain between the CPU TEE attestation and the GPU
>   CC attestation is not cryptographically bound at the
>   `report_data` schema layer. Severity: **High** for any
>   H100-CC deployment. F-class: F8. PoC: Attack #12 drives
>   the real `build_report_data` to show the same NRAS verdict
>   accepted across two distinct CPU attestations.
>
> Four runnable proofs-of-concept under
> `power_poc_dishonest_prover/`, all driving real Power crate
> functions:
>
> 1. **Attack #3** (P-1+P-2 chain): stale-cache demo
>    producing a verifier-accepting attestation over swapped
>    model bytes.
> 2. **Attack #10** (minijinja prompt-rewrite): GGUF chat-template
>    that overrides the system prompt without changing
>    `model_hash`.
> 3. **Attack #12** (F8 CPU↔GPU chain unbound): drives the real
>    `a3s_power::tee::attestation::build_report_data` to show
>    the layout has no slot for NRAS-verdict binding.
> 4. **Attack #15** (F2 `hardware_verifier: None`): drives the
>    real `a3s_power::verify::verify_report` to show forged
>    reports pass when the verifier is None.
>
> **Suggested fixes:**
>
> - Refuse to start when `tee_mode = true` and `model_hashes`
>   is empty; turn `hardware_verifier: None` into a runtime
>   error rather than a silent skip.
> - Re-hash on every `/v1/attestation` call (or bind the
>   in-memory buffer's hash rather than the registration-time
>   value).
> - Add `sha256(chat_template_string)` as a first-class claim
>   in the attestation payload, and have policy pin it.
> - Add `temperature`, `top_p`, `top_k`, `seed`,
>   `presence_penalty`, `frequency_penalty`, `stop_tokens_hash`
>   to the receipt schema; require the verifier's policy to pin
>   them.
> - Auto-reject `tee_type == "simulated"` unless an explicit
>   opt-in flag was passed.
>
> I am drafting a SoK paper to submit on [DATE]. I would like
> to coordinate a 60-day embargo window. A semver-major release
> that flips the defaults and ships the schema additions is
> the most user-friendly fix; let me know how I can help.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `power_soundness_finding.md`
- `power_poc_dishonest_prover/`

---

## 4. NEAR AI Cloud

**To:** [security@near.ai or as listed at
        `https://near.ai/security` / `cloud.near.ai/security`]
**Subject:** Multiple soundness findings in NEAR AI Cloud
              verifier — including three live H-severity gaps
              (NRAS JWT unverified, no model binding, channel
              binding opt-in) and three new composition gaps
              (sampling unattested, CPU↔GPU chain unbound,
              conversation-history injection)

> Hi NEAR AI security team,
>
> I am [NAME], a researcher at [AFFILIATION] conducting a
> systematization-of-knowledge survey of soundness gaps in
> TEE-based AI attestation systems. The NEAR AI Cloud verifier
> (the `nearai-cloud-verifier` repo at
> `github.com/nearai/...`) is one of six surveyed systems.
>
> I have nine original findings plus three additional
> composition-class findings (F7 sampling unattested, F8
> cross-component chain unbound, F9 conversation-history
> injection) added in a follow-up pass. Six PoCs total against
> NEAR AI Cloud — the most of any system in the survey. Three
> original findings are **High-severity** and each independently
> allows a dishonest-prover scenario where the verifier prints
> a "verified" verdict over an inference that did not match the
> claim:
>
> **Affected** (against the public source tree at HEAD):
>
> - Finding N-1 — NVIDIA NRAS JWT signature is not verified.
>   `py/model_verifier.py:42-47` calls
>   `base64url_decode_jwt_payload` and reads the JWT payload
>   without checking the signature against NVIDIA's JWKS.
>   Severity: **High**. F-class: F3. PoC: Attack #6. A MITM
>   (or a malicious gateway forwarding stale GPU evidence) can
>   return any verdict.
> - "No model-binding" — The `report_data` layout has no
>   `model_hash` slot (`py/model_verifier.py:66-126`). The
>   operator can swap model weights between requests and
>   every attestation field is identical. Severity: **High**.
>   F-class: F1. PoC: Attack #2.
> - Finding N-4 — `tls_verifier.py` channel binding is opt-in
>   (`--verify-tls`). Default flows in `model_verifier.py` /
>   `chat_verifier.py` validate `report_data` internally but
>   never compare live TLS cert SPKI to the attested
>   fingerprint. Severity: **High**. F-class: F6. PoC: Attack
>   #8. An MITM with a different cert succeeds.
>
> **Three new composition-class findings (added in follow-up):**
>
> - Finding (F7 second-system anchor) — `chat_verifier.py:78-91`
>   signs a text payload of the form
>   `chat_id:request_hash:response_hash` with no slot for
>   sampling parameters. The operator can vary `temperature`,
>   `top_p`, `seed` per request to manipulate model output;
>   every signed text remains structurally honest. Severity:
>   **Medium**. F-class: F7. PoC: Attack #17.
> - Finding (F8 second-system anchor) — `model_verifier.py:129-184`
>   checks the Intel TDX quote (`check_tdx_quote`) and the
>   NVIDIA NRAS verdict (`check_gpu`) as two independent
>   pipelines. No field in either attestation binds the NRAS
>   verdict's `gpu_uuid` to the CPU's `signing_address`. The
>   same NRAS verdict can be paired with two distinct TDX
>   quotes and the verifier accepts both. Severity: **High**
>   for any H100-CC deployment. F-class: F8. PoC: Attack #18.
> - Finding (F9 second-system anchor) — The signed `text`
>   format collapses everything-the-model-saw into one
>   `request_hash`, with no field distinguishing user-typed
>   bytes from operator-mediated context (system prompt, RAG
>   documents, tool outputs, conversation history). A gateway
>   that prepends extra messages to the user's request can
>   produce a verifier-accepting receipt over the modified
>   input. Severity: **Medium** (today's chat is single-turn);
>   **High** as the service scales to agentic / RAG workloads.
>   F-class: F9. PoC: Attack #19.
>
> Plus six Medium / Low original findings:
>
> - N-2: GPU nonce mismatch is `print`, not `raise`.
> - N-3: TDX `OutOfDate` is treated as a pass.
> - N-5: ECDSA "encryption" is ECIES with secp256k1 + key reuse.
> - N-6: Signed `text` carries no `chat_id` binding.
> - N-7: Sigstore "provenance" check is reachability-only.
> - N-8: `mr_config_id` prefix-matches the magic `"01"`.
> - N-9: Verifier defaults emit `print` lines, never `raise`.
>
> Six runnable proofs-of-concept under
> `nearai_poc_dishonest_prover/` (Attacks #2, #6, #8, #17, #18,
> #19) drive `py/model_verifier.py` / `chat_verifier.py`
> against small mocks where needed, and each prints
> `[+] ATTACK CONFIRMED`. None of the originals are modified.
>
> **Suggested fixes:**
>
> - Fetch NVIDIA's JWKS at startup (with pinned trust root),
>   cache, rotate; verify the NRAS JWT signature **before**
>   reading any payload field. Reject the verdict if the JWKS
>   fetch ever fails — do not soft-fail.
> - Add a `model_hash` (or `model_hash_scheme` + hash) slot to
>   the `report_data` layout. Require the verifier's policy to
>   pin it.
> - Make TLS channel binding mandatory at SDK level: emit a
>   `RoundTripper`-style wrapper that checks the live leaf cert
>   SPKI against `tls_cert_fingerprint` before any request body
>   is sent. (Tinfoil's `TLSBoundRoundTripper` is the reference
>   for this pattern.)
> - Promote N-2's `check_gpu` mismatch from `print` to `raise`.
> - Tighten `_tdx_status_ok` to `{"UpToDate"}` and require an
>   explicit opt-in flag listing the accepted advisories to
>   include `"OutOfDate"`.
> - Decode and verify Sigstore DSSE bundles (signer-identity,
>   transparency-log inclusion, observer timestamp), not just
>   HEAD-check the URL.
> - **(F7 fix)** Replace the signed `text` format with a
>   structured claims object that includes
>   `sampling_params_hash` (covering `temperature`, `top_p`,
>   `top_k`, `seed`, decoding strategy) and require
>   `chat_verifier.py` to pin it against a policy value.
> - **(F8 fix)** Extend the Intel TDX `report_data` (or add a
>   sibling field in the attestation) to include
>   `sha256(nvidia_payload_bytes)`. Have `check_attestation`
>   require: NRAS signature ✓ AND
>   `sha256(payload) == cpu_report_data.nras_hash`.
> - **(F9 fix)** Replace `chat_id:request_hash:response_hash`
>   with a structured claims object that separately commits to
>   `user_messages_hash`, `system_context_hash`,
>   `retrieved_context_hash`, `tool_call_log_hash`, and
>   `prior_receipt_hash` (for multi-turn chain binding).
>
> I am drafting a SoK paper to submit on [DATE]. I would like
> to coordinate a 90-day embargo window given that NEAR AI
> Cloud is a live service. I am happy to share the PoCs, the
> full finding doc, and to walk an engineer through the
> reproduction.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `nearai_cloud_verifier_soundness_finding.md`
- `nearai_poc_dishonest_prover/`

---

## 5. Cyntrisec / EphemeralML

**To:** [security@cyntrisec.com / security@ephemeralml.com,
        per the project's stated security policy]
**Subject:** Soundness findings in EphemeralML / AIR v1
              (default policy fails open; sampling parameters
              unattested; RAG-injected context unattested;
              signing-key chain unbound to NSM)

> Hi Cyntrisec security team,
>
> I am [NAME], a researcher at [AFFILIATION] conducting a
> systematization-of-knowledge survey of soundness gaps in
> TEE-based AI attestation systems. EphemeralML's AIR v1
> implementation is one of six surveyed systems and is the
> only one in the set whose receipt format (CWT / COSE_Sign1
> over a CBOR closed-map claims schema) we use as a reference
> for several mitigation patterns.
>
> Two **High-severity** findings, plus four Medium and two
> positive notes. I want to flag up front that EphemeralML's
> code is the cleanest in the survey on the F4 (trusted code
> interprets attacker bytes) front — the closed CDDL claims
> map and `verify-before-parse` discipline are reference fixes
> we cite by name in the unified writeup. The two H findings
> are about *defaults* and *schema completeness*, not about
> code-level interpretation bugs.
>
> **Affected** (against the public source tree at HEAD):
>
> - Finding E-1 — `AirVerifyPolicy::default()` leaves every
>   `expected_*` field as `None`; `MHASH`, `MODEL`, `ADHASH`,
>   `NONCE`, `PLATFORM` are not in `is_critical_check_name`
>   (`common/src/air_verify.rs:283-301, 385-415`). Severity:
>   **High**. F-class: F2. PoC: Attack #5. The verifier returns
>   `verified = true` on `Skip` for every policy slot that
>   isn't critical, including the model-identity slots.
> - Finding (Attack #9) — AIR v1 CDDL has no fields for sampling
>   parameters (`common/src/air_receipt.rs:82-108`); CDDL
>   defines `model_id`, `model_version`, `model_hash`,
>   `request_hash`, `response_hash`, `policy_version`,
>   `security_mode` but no `temperature` / `top_p` / `top_k` /
>   `seed` / decoding-strategy slot. Severity: **High**.
>   F-class: F7. PoC: Attack #9.
> - Finding (new, F9) — AIR v1 CDDL also has no fields for
>   *application-layer context bytes*. The receipt commits to
>   `request_hash` over whatever entered the model's input
>   buffer, with no slot distinguishing user-typed bytes from
>   operator-mediated context (RAG documents, tool-call
>   outputs, conversation history, output-pipeline rewrites).
>   Severity: **Medium** today; **High** for any agentic /
>   tool-using deployment built on AIR. F-class: F9. PoC:
>   Attack #13 drives the real `air_verify.rs` against a
>   RAG-injected receipt.
> - Finding E-2 — `feature = "mock"` produces structurally
>   valid AIR receipts in non-TEE deployment. Severity:
>   **Medium**. F-class: F1.
> - Finding E-3 — `seen_cti: Option<SeenCtiFn>`; replay
>   detection only if caller passes a callback. Severity:
>   **Medium**. F-class: F2.
> - Finding E-4 — The verifier does not check that the
>   receipt-signing pubkey was bound into the hardware
>   attestation `user_data` along the way to the caller.
>   Severity: **Architectural / consequential**. F-class:
>   F6 + F2. PoC: Attack #16 drives the real
>   `verify_air_v1_receipt` with an attacker-generated
>   Ed25519 key and shows the receipt verifies (signature ✓)
>   despite the key never appearing in any NSM document.
> - Finding E-6 — `expected_attestation_doc_hash` would close
>   the chain-of-custody between Nitro NSM attestation and the
>   receipt signature, but it is currently not present.
>   Severity: **Medium**.
>
> Four runnable proofs-of-concept under
> `ephemeralml_poc_dishonest_prover/`, all driving real
> EphemeralML crate functions unmodified:
>
> 1. **Attack #5** (F2 default policy): default-policy verifier
>    accepts a forged-model receipt because `MHASH`, `MODEL`,
>    `ADHASH` are not in `is_critical_check_name`.
> 2. **Attack #9** (F7 sampling unattested): receipt verifies
>    cleanly across `temperature=2.0` / `seed=42` swaps; no
>    field in the receipt records sampling.
> 3. **Attack #13** (F9 RAG-injected context): receipt verifies
>    cleanly when the operator silently prepends a RAG document
>    to the user's question; no field distinguishes
>    user-supplied from operator-mediated bytes.
> 4. **Attack #16** (F6 signing-key chain unbound):
>    `verify_air_v1_receipt` accepts a receipt signed by an
>    attacker-generated key never bound into any NSM document.
>
> **Suggested fixes:**
>
> - Promote `MHASH`, `MODEL`, `ADHASH`, `PLATFORM` to
>   `is_critical_check_name` so an unset policy field
>   makes verification fail closed.
> - Default `seen_cti` to `Some(<in-memory bounded LRU>)` when
>   no caller override; emit a `verify_warnings` entry when it
>   is left at `None`.
> - Add `temperature`, `top_p`, `top_k`, `seed`,
>   `presence_penalty`, `frequency_penalty`,
>   `stop_tokens_hash`, and `active_safety_classifier_id` to
>   the AIR v1 CDDL as required fields (bumped to AIR v2 to
>   preserve backward compatibility, or as optional-but-
>   policy-pinnable in AIR v1.1).
> - Add `expected_attestation_doc_hash` to the policy struct
>   so the verifier can require the receipt-signing pubkey
>   trace through the Nitro NSM document.
> - Have `feature = "mock"` produce receipts whose
>   `security_mode` is a sentinel that `default()` always
>   rejects.
> - **(F6 fix)** Ship a chained verifier in the EphemeralML
>   SDK that takes a Nitro NSM attestation document as input,
>   verifies it against the AWS Nitro CA, extracts the
>   receipt-signing pubkey from `user_data`, and only then
>   calls `verify_air_v1_receipt`. Document
>   `verify_air_v1_receipt(receipt, key, policy)` as low-level
>   — callers should use the chained variant by default.
> - **(F9 fix)** Add `prepended_context_hash`,
>   `tool_call_log_hash`, and `post_processing_pipeline_hash`
>   to the AIR v1 CDDL so a receipt can distinguish user-input
>   bytes from operator-mediated bytes. Have `AirVerifyPolicy`
>   expose `expected_*` fields for each. For multi-turn
>   support, add `prior_receipt_hash` for inter-receipt chain
>   binding.
>
> I am drafting a SoK paper to submit on [DATE]. EphemeralML
> is in early access; I would like to coordinate a 90-day
> embargo window. I am happy to share the PoCs, the full
> finding doc, and to coordinate a joint blog post if
> Cyntrisec wants to publish the mitigation story alongside
> the paper.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `ephemeralml_soundness_finding.md`
- `ephemeralml_poc_dishonest_prover/`

---

## 6. Tinfoil SDK (`tinfoilsh/tinfoil-go`)

**To:** security@tinfoil.sh (same as modelwrap; flag the SDK
        scope explicitly in the subject)
**Subject:** `tinfoil-go` SDK — `github-proxy.tinfoil.sh`
              mediates currency for SecureClient resolution

> Hi Tinfoil security team,
>
> Following up separately on the `tinfoil-go` SDK side of the
> survey. (My modelwrap email is the other half — these
> findings concern different parts of the Tinfoil codebase
> and have different blast radius, so I am splitting them
> rather than bundling.)
>
> The `tinfoil-go` SDK (`tinfoilsh/tinfoil-go`) is the
> client-side verifier end-users integrate against to talk to
> `inference.tinfoil.sh` and other Tinfoil-hosted services.
> The SDK does several things right (mandatory
> `TLSBoundRoundTripper`, mandatory Sigstore consensus
> checks, no eval-equivalent in the Go code path), and we
> cite it as a reference fix for F2, F4, and F6.
>
> The one **High-severity** soundness finding is that the SDK
> resolves "current release of repo X" entirely through
> `github-proxy.tinfoil.sh`, with no independent path for
> currency.
>
> **Affected** (against `tinfoilsh/tinfoil-go` at the SHA you
> link as latest):
>
> - Finding Tinfoil-1 — `verifier/github/github.go:11` hard-
>   codes `githubProxy = "https://github-proxy.tinfoil.sh"`.
>   Every `FetchLatestTag`, `FetchDigest`, and
>   `FetchAttestationBundle` call hits this hostname.
>   `util.Get` (`verifier/util/fetch_other.go:9-23`) is
>   `http.Get` + a status check; TLS validates the proxy
>   hostname but nothing validates the response body against
>   GitHub's canonical Release API. The Sigstore bundle is
>   downstream-verified properly, but the bundle the SDK
>   verifies is whatever the proxy returned. Severity:
>   **High**. F-class: F3 (currency variant — silent
>   rollback to any historically-valid release). PoC: Attack
>   #11 — a faithful Python port of `FetchLatestTag` /
>   `FetchDigest` / `FetchAttestationBundle` against a mock
>   `github-proxy.tinfoil.sh` with switchable `current` /
>   `rolled-back` modes.
> - Finding Tinfoil-2 — Certificate identity regex in the
>   Sigstore client permits any workflow file (not specifically
>   the build workflow expected). Severity: **Low** (supply-
>   chain framing; not directly exploitable without an
>   adversary who has compromised the Tinfoil CI). F-class:
>   F1-flavoured.
> - Finding Tinfoil-3 — `LatestHardwareMeasurements` is itself
>   pinned via the same proxy, so the same trust-root
>   centralization applies. Severity:
>   **Acknowledged-by-design**. F-class: F1 + F3.
>
> A runnable proof-of-concept under
> `tinfoil_poc_dishonest_prover/` faithfully ports
> `FetchLatestTag`, `FetchDigest`, `FetchLatestDigest`, and
> `FetchAttestationBundle` from `verifier/github/github.go`
> into Python and drives them against a mock proxy that
> implements the proxy's URL grammar. The mock has two modes
> (`current`, `rolled-back`); the SDK's resolution logic
> accepts whichever the proxy returned. The bundle bodies are
> placeholders — a faithful end-to-end PoC would need to
> construct two real Sigstore bundles (one current, one
> historical), which requires Tinfoil-internal signing
> identities. The structural claim (the SDK's *logic* accepts
> whatever (tag, digest, bundle) the proxy returns) does not
> require minting real signatures.
>
> **Suggested fixes:**
>
> - Resolve `(tag, digest)` from at least one trust root
>   independent of `github-proxy.tinfoil.sh` (e.g., a direct
>   call to `api.github.com`) and require agreement before
>   accepting the resolution.
> - Enforce a Sigstore observer-timestamp freshness floor
>   (reject bundles whose newest observer timestamp is older
>   than a configurable window, e.g., 72 hours).
> - Expose `min_tag` / `min_digest` policy fields the caller
>   can pin against a known floor; or accept a separately-
>   signed `(repo, tag, digest)` manifest the caller obtains
>   out of band.
> - Tighten the SAN regex to a specific workflow path +
>   release-tag pattern.
>
> I am drafting a SoK paper to submit on [DATE]. I would like
> to coordinate a 90-day embargo window. A semver-major SDK
> release that adds the second-source resolution and the
> freshness floor is the most user-friendly fix; let me know
> how I can help.
>
> Please confirm receipt.
>
> Best,
> [NAME], [AFFILIATION]

**Attachments to send on first reply:**
- `tinfoil_sdk_soundness_finding.md`
- `tinfoil_poc_dishonest_prover/`

---

## Operational notes for the discloser

- **Send each email separately.** Do not bcc multiple vendors
  on the same thread — disclosure conversations leak.
- **Use a researcher email at the affiliation,** not a personal
  account, so vendors can verify the affiliation.
- **Track each thread.** A spreadsheet with columns
  `vendor | T0 | last_contact | embargo_end | fix_status |
  PoC_shared` is sufficient.
- **Do not share the unified-survey doc on first contact** —
  share only the per-system finding doc and the relevant PoC.
  Vendors should learn about the cross-system regularity
  through the paper, not through a disclosure email.
- **CVE assignment.** For commercial deployments, request a
  CVE through the vendor (or via MITRE if the vendor declines).
  For the academic Laminator finding, an acknowledgement in
  the paper is sufficient — no CVE needed.
- **If a vendor goes silent past T0+30d,** send one polite
  follow-up. If silent past T0+60d, send a final notice that
  publication is proceeding on T0+90d regardless. Do not
  extend embargoes without a stated reason from the vendor.
