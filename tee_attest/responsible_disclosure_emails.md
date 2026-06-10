# Responsible Disclosure — Draft Emails

Five drafts, one per vendor (Tinfoil's `modelwrap` and
`tinfoil-go` SDK are bundled into a single email to
security@tinfoil.sh). Each is intended to start a
T0 = "the day this email is sent" dialogue:

- **T0**: vendor acknowledges receipt; we send the per-vendor
  finding doc and the runnable PoCs.
- **T0 + 7d**: vendor confirms reproduction or asks for help.
- **T0 + 21d**: we ask for a fix ETA.
- **T0 + 45d**: vendor confirms fix shipped or requests an
  extension.
- **T0 + 60d**: we publish a blog post and arXiv preprint.

Bracketed `[PLACEHOLDER]` markers must be filled in before
sending. Each email lists the per-vendor finding doc as the
attachment; the runnable PoCs under
`<system>_poc_dishonest_prover/` are offered on request.

---

## 1. Laminator (academic, CODASPY 2025)

**To:** [corresponding author email — see paper's first page]
**CC:** Vasisht Duddu; Antti Järvinen; Lachlan J. Gunn; N. Asokan
**Subject:** Soundness findings in Laminator (CODASPY '25) —
              `torch.load` RCE inside the enclave, plus seven
              other gaps

> Dear Prof. Asokan and co-authors,
>
> We are a research team at [AFFILIATION] working on a paper
> about soundness gaps in TEE-based AI attestation systems.
> Laminator (CODASPY 2025,
> `github.com/ssg-research/laminator`,
> `arxiv.org/abs/2406.17548`) is one of the systems we
> reviewed.
>
> While reviewing the implementation against the paper's
> Property-of-Training (PoT), Input/Output Attestation (IOAtt),
> and Accuracy Attestation (AccAtt) protocols, we identified
> eight findings (five primary + three Medium/Low). The
> headline result is a `torch.load` pickle-RCE inside the SGX
> enclave that single-handedly forges every attestation type
> Laminator produces.
>
> **Affected** (against `github.com/ssg-research/laminator`,
> branch `main`, commit `ce2d10bb` of 2025-03-06):
>
> - Finding 1 — `torch.load` pickle deserialization at
>   `generate_attestations/main.py:291, 384`. The host-supplied
>   `.pth` file's pickle `__reduce__` runs arbitrary code
>   inside the enclave at parse time, before
>   `load_state_dict()` runs. This single-handedly forges any
>   AccAtt / IOAtt / PoT.
> - Finding 2 — `argv` flows verbatim into the PoT payload via
>   `loader.insecure__use_cmdline_argv = true`
>   (`main.manifest.template:17`), decoupling reported
>   metadata from cryptographic bindings.
> - Finding 4 — `h(M)` (model state-dict hash) does not bind a
>   model architecture; combined with Finding 1, an attacker
>   can swap architectures under the same recorded hash.
> - Finding 5 — No secure user→enclave channel for IOAtt
>   inputs; a dishonest prover can answer arbitrary inputs in
>   place of the user's.
> - Finding 6 — Datasets (`data/adult.data`, `utkface.csv`,
>   `IMDB_Dataset.csv`) are `allowed_files`
>   (`main.manifest.template:69-71`). The host writes them; the
>   enclave hashes whatever bytes are there at read time, so
>   AccAtt's soundness depends on an external certifier
>   publishing canonical `h(D_te)` mappings — and the repo ships
>   no certifier wiring (`scripts/verifier.py:23` uses a
>   placeholder `test_certifications` dict).
> - Three additional findings (training config `T` is empty;
>   PoT non-determinism does not pin a unique `M`; the verifier
>   ships with placeholder MRENCLAVE entries).
>
> Three runnable proofs-of-concept drive `main.py` and
> `audit_attestation.py` **unmodified** against crafted inputs:
>
>   - A switchable pickle loader: same-`SHA-512` payload, host-
>     swappable model between calls.
>   - A metric forgery: `output_accuracy.json` reports
>     `"value": 0.99` for a random-init model.
>   - An argv-unmeasured demo: the same trained model with
>     different `--epochs` / `--architecture` argv produces two
>     distinct SGX-signed PoT payloads.
>
> All three run end-to-end without any code change to the
> Laminator tree and print a forged-attestation result.
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
> We plan to release a blog post and an arXiv preprint on
> [DATE], 60 days from this email. We are happy to share the
> full finding doc and the runnable PoCs immediately on
> request, and would like to acknowledge your response in the
> writeup.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAMES], [AFFILIATION]

**Attachments to send on first reply:**
- `laminator_soundness_finding.md`
- `laminator_poc_dishonest_prover/` (all PoCs)

---

## 2. Tinfoil — `modelwrap` build-time tool + `tinfoil-go` SDK

**To:** security@tinfoil.sh (or as listed in `tinfoilsh/tinfoil`
        `SECURITY.md`)
**Subject:** Soundness findings in Tinfoil's stack — modelwrap
              idempotency-skip (build-time root-hash forgery) and
              `tinfoil-go` SDK currency mediation via
              `github-proxy.tinfoil.sh`

> Hi Tinfoil security team,
>
> We are a research team at [AFFILIATION] working on a paper
> about soundness gaps in TEE-based AI attestation systems. Two
> parts of the Tinfoil stack are in scope — the `modelwrap`
> build-time tool and the `tinfoil-go` client-side verifier
> SDK. We are bundling both into one disclosure thread; they
> sit at different parts of the codebase but the responsible
> owner is the same.
>
> **Part A — `modelwrap` (`tinfoilsh/modelwrap`).** The
> idempotency-skip optimization in `pack.py:58-71, 77-102` lets
> a malicious builder pre-place an attacker-chosen
> `<commit>.mpk` + `<commit>.info` pair before running
> modelwrap. The tool sees the outputs exist, skips
> `mkfs.erofs` and `veritysetup`, exits 0, and the downstream
> CVM image-builder bakes the attacker's chosen dm-verity root
> hash into the measured CVM image.
>
> **Affected** (against `github.com/tinfoilsh/modelwrap`,
> branch `main`, commit `6d514838` of 2026-05-04):
>
> - Finding M-1 — Pre-existing output files bypass the build
>   (`pack.py:58-71, 77-102`). The pre-placed `.info` file's
>   root hash differs from the hash a fresh build of the named
>   HF revision would produce, but `pack.py` exits 0 with the
>   attacker-chosen hash.
> - Finding M-2 — Optional `@revision` lets HEAD float
>   (`pack.py:25-31`); different env values produce different
>   root hashes, but the verifier sees only the root hash.
> - Finding M-3 — HF Hub LFS verification is the entire data
>   trust root for the model bytes.
> - Finding M-4 — Output artefacts (`.mpk`, `.info`) are
>   unsigned. Anything between the build container and cvmimage
>   can substitute the files.
> - Finding M-5 — `.info` carries no model identity
>   (`pack.py:99-100`). The format is
>   `ROOTHASH_OFFSET_VERITYUUID` — no model name, no HF
>   revision, no tool-version, no publisher signature. A
>   consumer cannot link the root hash back to a named model
>   without an external mapping, which is exactly what makes
>   M-1 silent.
> - Finding M-6 — `HF_TOKEN` is unmeasured and selects content
>   (`pack.py:11, 42`); relevant for gated or private models.
> - Finding M-7 — Cache directory is bind-mounted.
>
> A runnable proof-of-concept under
> `modelwrap_poc_dishonest_prover/` drives the unmodified
> `pack.py` against a pre-placed output directory and ends with
> `[+] ATTACK CONFIRMED`.
>
> **Suggested fixes for Part A:**
>
> - When outputs already exist for the requested
>   `(model, revision)`, either (a) re-build to a temp dir and
>   compare against the existing artefact byte-for-byte, or
>   (b) refuse to proceed until the operator clears the output
>   directory.
> - Extend `.info` to a structured format (JSON / TOML) that
>   records model name, HF revision, tool versions, and a
>   publisher signature; have cvmimage refuse outputs whose
>   `.info` is unsigned.
> - Drive modelwrap from CI with in-toto / SLSA provenance and
>   have cvmimage require provenance.
>
> **Part B — `tinfoil-go` SDK (`tinfoilsh/tinfoil-go`).** The
> SDK resolves "current release of repo X" entirely through
> `github-proxy.tinfoil.sh`, with no independent path for
> currency. Even though the Sigstore bundle is downstream-
> verified properly, the bundle the SDK ever sees is whatever
> the proxy returned.
>
> **Affected** (against `github.com/tinfoilsh/tinfoil-go`,
> branch `main`, commit `ff185e53` of 2026-05-08):
>
> - Finding Tinfoil-1 — `verifier/github/github.go:11` hard-
>   codes `githubProxy = "https://github-proxy.tinfoil.sh"`.
>   Every `FetchLatestTag`, `FetchDigest`, and
>   `FetchAttestationBundle` call hits this hostname.
>   `util.Get` (`verifier/util/fetch_other.go:9-23`) is
>   `http.Get` + a status check; TLS validates the proxy
>   hostname but nothing validates the response body against
>   GitHub's canonical Release API. A malicious or rolled-back
>   proxy can pin the SDK to any historically-valid release.
> - Finding Tinfoil-2 — Certificate identity regex in the
>   Sigstore client permits any workflow file (not specifically
>   the build workflow expected). Not directly exploitable
>   without an adversary who has compromised the Tinfoil CI.
> - Finding Tinfoil-3 — `LatestHardwareMeasurements` is itself
>   pinned via the same proxy, so the same trust-root
>   centralization applies to the GPU half of the chain.
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
> identities. The structural claim — that the SDK's *logic*
> accepts whatever (tag, digest, bundle) the proxy returns —
> does not require minting real signatures.
>
> **Suggested fixes for Part B:**
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
> We plan to release a blog post and an arXiv preprint on
> [DATE], 60 days from this email. A semver-major SDK release
> that adds the second-source resolution and the freshness
> floor, paired with a modelwrap release that closes the
> idempotency-skip and signs outputs, is the most user-friendly
> fix; let us know how we can help.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAMES], [AFFILIATION]

**Attachments to send on first reply:**
- `modelwrap_soundness_finding.md`
- `modelwrap_poc_dishonest_prover/`
- `tinfoil_sdk_soundness_finding.md`
- `tinfoil_poc_dishonest_prover/`

---

## 3. A3S / Power (Rust crate + EthCC demo)

**To:** [crate maintainer's GitHub-public email, see crates.io
        `power` crate page]
**Subject:** Soundness findings in A3S / Power
              (model_hashes default-skip, minijinja
              chat-template hijack, cached attestation hash,
              hardware_verifier opt-in, CPU↔GPU chain unbound)

> Hi [MAINTAINER],
>
> We are a research team at [AFFILIATION] working on a paper
> about soundness gaps in TEE-based AI attestation systems.
> A3S / Power is one of the systems we reviewed; we selected it
> because it is one of the very few public Rust implementations
> of TEE-AI runtime attestation with NVIDIA H100 confidential-
> compute support.
>
> We have eleven findings and four runnable PoCs that drive
> Power's real, unmodified source. The chained scenario
> (P-1 cached `manifest.sha256` + P-2 default-skip on
> `model_hashes`) produces a verifier-accepting attestation
> over swapped model bytes. A separate finding shows the GGUF
> chat-template path can rewrite user prompts inside the
> enclave without changing any attested claim. Two additional
> PoCs demonstrate `hardware_verifier: None` and the unbound
> CPU↔GPU chain as drop-in demonstrations against Power's
> published crate API.
>
> **Affected** (against `github.com/A3S-Lab/Power`,
> branch `main`, commit `7bbaebee` of 2026-05-10):
>
> - Finding P-2 — `model_hashes`, `model_signing_key`, and
>   `hardware_verifier` are all `Option<>` and default to
>   skip-the-check (`autoload.rs:152-165`). Re-hash on load
>   happens only if config maps the model.
> - Finding P-1 — `/v1/attestation` returns a registration-time
>   `manifest.sha256` rather than re-hashing the currently-
>   loaded model (`api/openai/attestation.rs:91-105`); composes
>   with P-2 into a chained attack.
> - Finding P-3 — Model weights are not in the launch
>   measurement (SEV-SNP `MEASUREMENT` offset 0x90 / TDX `MRTD`
>   offset 528 cover only the VM image at boot; model files are
>   read from disk at runtime). Architectural rather than a bug,
>   but it is the reason the entire post-boot hash chain has to
>   be perfect.
> - Finding P-4 — Encrypted-model hash semantics are ambiguous
>   (`api/autoload.rs:99-147`, `tee/encrypted_model.rs`,
>   `api/openai/attestation.rs:91-105`). `DecryptedModel` ends
>   up comparing `expected_hash` against `sha256(.dec)` at load
>   while the attestation endpoint always reports
>   `sha256(.enc)`; `MemoryDecryptedModel` / `LayerStreaming`
>   use `sha256(.enc)` in both places. Result: "model hash"
>   means different bytes in different code paths, and a
>   verifier holding only the publisher's plaintext hash cannot
>   verify the encrypted form.
> - Finding P-5 — TOCTOU between `/v1/attestation` and
>   `ensure_loaded` (`api/openai/attestation.rs:124-130` and
>   `api/autoload.rs:149-179`). With `model_hashes` set the
>   window is closed by the load-time SHA-256 check; without it,
>   P-1 + P-2 + P-5 compose into a trivial swap.
> - GGUF chat-template hijack — `backend/chat_template.rs:57-104`
>   renders operator-supplied chat templates from GGUF metadata
>   through minijinja. The sandbox prevents shell access but the
>   template engine can rewrite prompts, inject jailbreak
>   suffixes, etc.
> - Sampling unattested — Power's OpenAI-compatible API honours
>   `temperature`, `top_p`, `seed` per request, but nothing in
>   the attestation payload echoes the sampling regime.
> - Finding P-6 — `A3S_TEE_SIMULATE=1` env var swaps the real
>   attestation path for a synthetic one
>   (`tee/attestation.rs:147-154`); `tee_type == "simulated"`
>   is not auto-rejected by `verify_report`.
> - Finding P-7 — Hardware-signature verification on the report
>   is optional (`VerifyOptions.hardware_verifier:
>   Option<&dyn HardwareVerifier>`). The most load-bearing check
>   in the chain is defaulted off; a PoC drives the real
>   `a3s_power::verify::verify_report` with
>   `hardware_verifier: None` and shows a forged report is
>   accepted with `hardware_verified: false` buried in the
>   `VerifyResult` struct.
> - Finding P-8 — `/v1/models/pull` extends the trust surface
>   to HF Hub (`src/model/pull.rs`); HF identifies by name not
>   by publisher signature, so a compromised publisher account
>   swaps bytes under the same `model_name` and Power registers
>   the new hash. The `HF_TOKEN` flow can also access gated
>   content the verifier may not expect.
> - CPU↔GPU chain unbound — Power's `report_data` layout
>   (`build_report_data` at `tee/attestation.rs:184-201`) is
>   exactly `[nonce(32) ‖ model_hash(32)]` with no slot for
>   binding an NVIDIA NRAS verdict to the specific CPU
>   computation. Power's marketing of NVIDIA H100 confidential-
>   compute support is accurate at each link — but the chain
>   between the CPU TEE attestation and the GPU CC attestation
>   is not cryptographically bound at the `report_data` schema
>   layer. A PoC drives the real `build_report_data` to show the
>   same NRAS verdict accepted across two distinct CPU
>   attestations.
>
> Four runnable proofs-of-concept under
> `power_poc_dishonest_prover/`, all driving real Power crate
> functions:
>
> 1. P-1 + P-2 chain: stale-cache demo producing a verifier-
>    accepting attestation over swapped model bytes.
> 2. minijinja prompt-rewrite: GGUF chat-template that overrides
>    the system prompt without changing `model_hash`.
> 3. CPU↔GPU chain unbound: drives the real
>    `a3s_power::tee::attestation::build_report_data` to show
>    the layout has no slot for NRAS-verdict binding.
> 4. `hardware_verifier: None`: drives the real
>    `a3s_power::verify::verify_report` to show forged reports
>    pass when the verifier is `None`.
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
> - Bind the NVIDIA NRAS verdict bytes into the CPU's
>   `report_data` (e.g., add an `nras_verdict_hash` slot) so a
>   verifier can require that the GPU verdict referred to the
>   same computation as the CPU attestation.
>
> We plan to release a blog post and an arXiv preprint on
> [DATE], 60 days from this email. A semver-major release that
> flips the defaults and ships the schema additions is the most
> user-friendly fix; let us know how we can help.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAMES], [AFFILIATION]

**Attachments to send on first reply:**
- `power_soundness_finding.md`
- `power_poc_dishonest_prover/`

---

## 4. NEAR AI Cloud

**To:** [security@near.ai or as listed at
        `https://near.ai/security` / `cloud.near.ai/security`]
**Subject:** Multiple soundness findings in NEAR AI Cloud
              verifier — NRAS JWT unverified, no model binding,
              channel binding opt-in, sampling unattested,
              CPU↔GPU chain unbound, conversation-history
              injection

> Hi NEAR AI security team,
>
> We are a research team at [AFFILIATION] working on a paper
> about soundness gaps in TEE-based AI attestation systems.
> The NEAR AI Cloud verifier
> (`github.com/nearai/nearai-cloud-verifier`) is one of the
> systems we reviewed.
>
> We have twelve findings and six runnable PoCs against NEAR AI
> Cloud. Three findings each independently allow a dishonest-
> prover scenario where the verifier prints a "verified"
> verdict over an inference that did not match the claim:
>
> **Affected** (against
> `github.com/nearai/nearai-cloud-verifier`, branch `main`,
> commit `8b7830e9` of 2026-05-06):
>
> - Finding N-1 — NVIDIA NRAS JWT signature is not verified.
>   `py/model_verifier.py:42-47` calls
>   `base64url_decode_jwt_payload` and reads the JWT payload
>   without checking the signature against NVIDIA's JWKS. A
>   MITM (or a malicious gateway forwarding stale GPU evidence)
>   can return any verdict.
> - No model-binding — The `report_data` layout has no
>   `model_hash` slot (`py/model_verifier.py:66-126`). The
>   operator can swap model weights between requests and every
>   attestation field is identical.
> - Finding N-4 — `tls_verifier.py:80-82` disables CA
>   verification by design (`CERT_NONE` + single-socket
>   `fetch_attestation_and_spki`). The argument is sound *iff*
>   the operator pins `signing_address` to a known good value
>   — but `--signing-address` is optional, so a server can
>   supply both `signing_address = X` and a TDX quote whose
>   `report_data[0..32] = SHA256(X || F)` and pass binding
>   trivially. A future refactor that splits the fetch into
>   separate connections also silently breaks the property.
>   Mitigation: require `--signing-address` and refuse to run
>   without it.
> - Channel-binding opt-in — Even past N-4, the default flow
>   for `model_verifier.py` / `chat_verifier.py` doesn't invoke
>   `tls_verifier.py` at all unless `--verify-tls` is set, so
>   the verifier validates `report_data` internally but never
>   compares the live TLS cert SPKI to the attested fingerprint.
>   An MITM with a different cert succeeds.
> - Sampling unattested — `chat_verifier.py:78-91` signs a text
>   payload of the form `<field>:request_hash:response_hash`
>   with no slot for sampling parameters. The operator can vary
>   `temperature`, `top_p`, `seed` per request to manipulate
>   model output; every signed text remains structurally honest.
> - CPU↔GPU chain unbound — `model_verifier.py:129-184` checks
>   the Intel TDX quote (`check_tdx_quote`) and the NVIDIA NRAS
>   verdict (`check_gpu`) as two independent pipelines. No
>   field in either attestation binds the NRAS verdict's
>   `gpu_uuid` to the CPU's `signing_address`. The same NRAS
>   verdict can be paired with two distinct TDX quotes and the
>   verifier accepts both.
> - Conversation-history injection — The signed `text` format
>   collapses everything-the-model-saw into one `request_hash`,
>   with no field distinguishing user-typed bytes from
>   operator-mediated context (system prompt, RAG documents,
>   tool outputs, conversation history). A gateway that prepends
>   extra messages to the user's request can produce a verifier-
>   accepting receipt over the modified input.
>
> Plus six additional findings:
>
> - N-2: GPU nonce mismatch is `print`, not `raise`.
> - N-3: TDX `OutOfDate` is treated as a pass.
> - N-5: ECDSA "encryption" is ECIES with secp256k1 + key reuse.
> - N-6: Verifier discards the leading field of the signed `text`
>   (`parts[0]`), so any `chat_id` it may carry goes unchecked
>   (informational; the content-hash pair carries the integrity
>   guarantee).
> - N-7: Sigstore "provenance" check is reachability-only.
> - N-8: `mr_config_id` prefix-matches the magic `"01"`.
> - N-9: Verifier defaults emit `print` lines, never `raise`.
>
> Six runnable proofs-of-concept under
> `nearai_poc_dishonest_prover/` drive `py/model_verifier.py` /
> `chat_verifier.py` against small mocks where needed, and each
> prints `[+] ATTACK CONFIRMED`. None of the originals are
> modified.
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
>   is sent.
> - Promote N-2's `check_gpu` mismatch from `print` to `raise`.
> - Tighten `_tdx_status_ok` to `{"UpToDate"}` and require an
>   explicit opt-in flag listing the accepted advisories to
>   include `"OutOfDate"`.
> - Decode and verify Sigstore DSSE bundles (signer-identity,
>   transparency-log inclusion, observer timestamp), not just
>   HEAD-check the URL.
> - Replace the signed `text` format with a structured claims
>   object that includes `sampling_params_hash` (covering
>   `temperature`, `top_p`, `top_k`, `seed`, decoding strategy)
>   and require `chat_verifier.py` to pin it against a policy
>   value.
> - Extend the Intel TDX `report_data` (or add a sibling field
>   in the attestation) to include `sha256(nvidia_payload_bytes)`.
>   Have `check_attestation` require: NRAS signature ✓ AND
>   `sha256(payload) == cpu_report_data.nras_hash`.
> - Replace the `<field>:request_hash:response_hash` signed text with a
>   structured claims object that separately commits to
>   `user_messages_hash`, `system_context_hash`,
>   `retrieved_context_hash`, `tool_call_log_hash`, and
>   `prior_receipt_hash` (for multi-turn chain binding).
>
> We plan to release a blog post and an arXiv preprint on
> [DATE], 60 days from this email. Because NEAR AI Cloud is a
> live service, we are happy to share the PoCs, the full
> finding doc, and to walk an engineer through the reproduction.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAMES], [AFFILIATION]

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
> We are a research team at [AFFILIATION] working on a paper
> about soundness gaps in TEE-based AI attestation systems.
> EphemeralML's AIR v1 implementation is one of the systems we
> reviewed. We want to flag up front that EphemeralML's code is
> a positive example in several places — the closed CDDL claims
> map and `verify-before-parse` discipline avoid an entire
> class of code-level interpretation bugs. The findings below
> are about *defaults* and *schema completeness*, not about
> bytes-handling bugs in the verifier.
>
> **Affected** (against `github.com/cyntrisec/EphemeralML`,
> branch `main`, commit `44cb844e` of 2026-05-23):
>
> - Finding E-1 — `AirVerifyPolicy::default()` leaves every
>   `expected_*` field as `None`; `MHASH`, `MODEL`, `ADHASH`,
>   `NONCE`, `PLATFORM` are not in `is_critical_check_name`
>   (`common/src/air_verify.rs:283-301, 385-415`). The verifier
>   returns `verified = true` on `Skip` for every policy slot
>   that isn't critical, including the model-identity slots.
> - AIR v1 sampling unattested — The CDDL has no fields for
>   sampling parameters (`common/src/air_receipt.rs:82-108`);
>   it defines `model_id`, `model_version`, `model_hash`,
>   `request_hash`, `response_hash`, `policy_version`,
>   `security_mode` but no `temperature` / `top_p` / `top_k` /
>   `seed` / decoding-strategy slot. The operator can vary
>   sampling per request without any receipt claim becoming a
>   lie.
> - AIR v1 application-context unattested — The CDDL has no
>   fields for application-layer context bytes. The receipt
>   commits to `request_hash` over whatever entered the model's
>   input buffer, with no slot distinguishing user-typed bytes
>   from operator-mediated context (RAG documents, tool-call
>   outputs, conversation history, output-pipeline rewrites).
>   A PoC drives the real `air_verify.rs` against a RAG-injected
>   receipt that verifies cleanly.
> - Finding E-2 — `feature = "mock"` produces structurally
>   valid AIR receipts in non-TEE deployment.
> - Finding E-3 — `seen_cti: Option<SeenCtiFn>`; replay
>   detection only happens if the caller passes a callback.
> - Finding E-4 — The verifier does not check that the receipt-
>   signing pubkey was bound into the hardware attestation
>   `user_data` along the way to the caller. A PoC drives the
>   real `verify_air_v1_receipt` with an attacker-generated
>   Ed25519 key and shows the receipt verifies (signature ✓)
>   despite the key never appearing in any NSM document.
> - Finding E-5 — `model_hash_scheme` is `Option<String>`; when
>   absent from the claims, the verifier passes the
>   `MHASH_SCHEME` check (`common/src/air_verify.rs:673-684`).
>   An enclave that omits the scheme is indistinguishable from
>   one that asserts a known scheme, so a verifier comparing
>   `expected_model_hash` to `claims.model_hash` has no
>   guarantee both sides used the same hash function.
> - Finding E-6 — `expected_attestation_doc_hash` would close
>   the chain-of-custody between Nitro NSM attestation and the
>   receipt signature, but it is currently not present.
> - Finding E-9 — `expected_request_hash` /
>   `expected_response_hash` policy fields collapse to a
>   tautology when the response bytes aren't independently
>   committed (`common/src/air_verify.rs:258-260, 759-799`): a
>   server can return bytes B and sign a receipt with
>   `response_hash = sha256(B)`, and the verifier accepts. The
>   receipt authenticates *content*, not *delivery*. A
>   documentation gap worth flagging because the property is
>   easy to misread when integrating with a remote verifier.
>
> Four runnable proofs-of-concept under
> `ephemeralml_poc_dishonest_prover/`, all driving real
> EphemeralML crate functions unmodified:
>
> 1. Default policy: the default-policy verifier accepts a
>    forged-model receipt because `MHASH`, `MODEL`, `ADHASH`
>    are not in `is_critical_check_name`.
> 2. Sampling unattested: the receipt verifies cleanly across
>    `temperature=2.0` / `seed=42` swaps; no field in the
>    receipt records sampling.
> 3. RAG-injected context: the receipt verifies cleanly when
>    the operator silently prepends a RAG document to the user's
>    question; no field distinguishes user-supplied from
>    operator-mediated bytes.
> 4. Signing-key chain unbound: `verify_air_v1_receipt` accepts
>    a receipt signed by an attacker-generated key never bound
>    into any NSM document.
>
> **Suggested fixes:**
>
> - Promote `MHASH`, `MODEL`, `ADHASH`, `PLATFORM` to
>   `is_critical_check_name` so an unset policy field makes
>   verification fail closed.
> - Default `seen_cti` to `Some(<in-memory bounded LRU>)` when
>   no caller override; emit a `verify_warnings` entry when it
>   is left at `None`.
> - Add `temperature`, `top_p`, `top_k`, `seed`,
>   `presence_penalty`, `frequency_penalty`, `stop_tokens_hash`,
>   and `active_safety_classifier_id` to the AIR v1 CDDL as
>   required fields (bumped to AIR v2 to preserve backward
>   compatibility, or as optional-but-policy-pinnable in
>   AIR v1.1).
> - Add `expected_attestation_doc_hash` to the policy struct so
>   the verifier can require the receipt-signing pubkey trace
>   through the Nitro NSM document.
> - Have `feature = "mock"` produce receipts whose
>   `security_mode` is a sentinel that `default()` always
>   rejects.
> - Ship a chained verifier in the EphemeralML SDK that takes a
>   Nitro NSM attestation document as input, verifies it against
>   the AWS Nitro CA, extracts the receipt-signing pubkey from
>   `user_data`, and only then calls `verify_air_v1_receipt`.
>   Document `verify_air_v1_receipt(receipt, key, policy)` as
>   low-level — callers should use the chained variant by
>   default.
> - Add `prepended_context_hash`, `tool_call_log_hash`, and
>   `post_processing_pipeline_hash` to the AIR v1 CDDL so a
>   receipt can distinguish user-input bytes from operator-
>   mediated bytes. Have `AirVerifyPolicy` expose `expected_*`
>   fields for each. For multi-turn support, add
>   `prior_receipt_hash` for inter-receipt chain binding.
>
> We plan to release a blog post and an arXiv preprint on
> [DATE], 60 days from this email. EphemeralML is in early
> access, so we are happy to share the PoCs, the full finding
> doc, and to coordinate a joint blog post if Cyntrisec wants
> to publish the mitigation story alongside ours.
>
> Please confirm receipt and the channel you would prefer for
> further correspondence.
>
> Best,
> [NAMES], [AFFILIATION]

**Attachments to send on first reply:**
- `ephemeralml_soundness_finding.md`
- `ephemeralml_poc_dishonest_prover/`

---

## Operational notes for the discloser

- **Send each email separately.** Do not bcc multiple vendors
  on the same thread — disclosure conversations leak.
- **Use a researcher email at the affiliation,** not a personal
  account, so vendors can verify the affiliation.
- **Track each thread.** A spreadsheet with columns
  `vendor | T0 | last_contact | embargo_end | fix_status |
  PoC_shared` is sufficient.
- **Share only per-vendor material on first contact** — the
  per-vendor finding doc and the relevant PoC. Do not share
  cross-vendor analysis or other vendors' findings; the paper
  and blog post are where the cross-system picture appears.
- **CVE assignment.** For commercial deployments, request a
  CVE through the vendor (or via MITRE if the vendor declines).
  For the academic Laminator finding, an acknowledgement in
  the writeup is sufficient — no CVE needed.
- **If a vendor goes silent past T0+21d,** send one polite
  follow-up. If silent past T0+45d, send a final notice that
  the blog post and arXiv preprint are proceeding on T0+60d
  regardless. Do not extend embargoes without a stated reason
  from the vendor.
