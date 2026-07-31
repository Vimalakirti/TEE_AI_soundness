Title: Potential soundness issues in A3S / Power
To: [crate maintainer’s GitHub-public email: they don’t list any email]

CC: ddkang@g.illinois.edu, [MATS fellows]

Hi Zhixiao Lin,
We are a research team at UIUC and MATS studying soundness issues in TEE-based AI attestation systems. As part of this work, we reviewed A3S / Power, including the public Rust crate and EthCC demo. We selected Power because it is one of the few public Rust implementations of TEE-based AI runtime attestation with NVIDIA H100 confidential-computing support.
During our review, we identified several potential soundness gaps that we would like to disclose and discuss with you. The issues we believe are most important involve model-hash enforcement defaults, cached attestation state, optional hardware-signature verification, and the lack of an explicit cryptographic binding between the CPU TEE attestation and the GPU confidential-computing evidence.
Reviewed version: github.com/A3S-Lab/Power, branch main, commit 7bbaebee dated 2026-05-10.
The main issues we would like to report are:
Model-hash enforcement appears to be optional by default. In autoload.rs:152-165, model_hashes, model_signing_key, and hardware_verifier appear to be represented as Option<> values. In our current understanding, re-hashing on load happens only if the configuration maps the model. This may allow the model-integrity check to be skipped in some deployment configurations.
The attestation endpoint appears to return a registration-time model hash. In api/openai/attestation.rs:91-105, /v1/attestation appears to return a cached manifest.sha256 value rather than re-hashing the currently loaded model. Depending on the model-loading path and configuration, this may allow stale or registration-time state to stand in for runtime model state.
Model weights are not part of the launch measurement. Our understanding is that the SEV-SNP MEASUREMENT and TDX MRTD cover the VM image at boot, while model files are read from disk at runtime. This is not necessarily a bug by itself, but it means the post-boot model-hash chain needs to be complete and consistently enforced.
Encrypted-model hash semantics appear to vary across code paths. In api/autoload.rs:99-147, tee/encrypted_model.rs, and api/openai/attestation.rs:91-105, the meaning of “model hash” appears to differ across encrypted-model loading modes. In some paths, the load-time check appears to compare against decrypted bytes, while the attestation endpoint reports the encrypted artifact hash. This may make it difficult for a verifier to know exactly which bytes are being attested.
Hardware-signature verification appears to be optional. VerifyOptions.hardware_verifier appears to be an Option<&dyn HardwareVerifier>. In our current understanding, a caller can invoke the verifier without a hardware verifier and receive a result where the hardware evidence was not actually verified. This may be easy for integrators to misuse unless the default path fails closed.
Simulated attestation appears to be accepted unless policy rejects it. A3S_TEE_SIMULATE=1 appears to switch the attestation path to a synthetic mode in tee/attestation.rs:147-154. We did not find an automatic rejection of tee_type == "simulated" in the verification path. This may be safe for testing, but it seems risky if production callers do not explicitly reject simulated evidence.
The CPU and GPU attestation chain does not appear to be explicitly bound. In tee/attestation.rs:184-201, the CPU report_data layout appears to be [nonce(32) || model_hash(32)], with no slot for binding the NVIDIA NRAS verdict or GPU evidence to the specific CPU attestation. Our understanding is that the CPU TEE evidence and GPU confidential-computing evidence are checked as separate links, but the schema does not cryptographically bind them into one chain.
Chat-template and sampling behavior appear to be outside the attested claims. The GGUF chat-template path in backend/chat_template.rs:57-104 appears to allow operator-supplied templates to affect the prompt seen by the model, while OpenAI-compatible sampling parameters such as temperature, top_p, and seed appear to affect outputs without being echoed in the attestation payload. This may create a gap between “the model ran” and “the model ran under the verifier’s intended prompt and decoding policy.”
Some possible mitigations we are considering include:
Failing closed when tee_mode = true and model_hashes is empty.
Treating hardware_verifier: None as a runtime error in production verification paths.
Re-hashing the currently loaded model on each /v1/attestation call, or binding the attestation to the in-memory model buffer rather than registration-time state.
Clarifying and unifying hash semantics for encrypted and decrypted model artifacts.
Adding sha256(chat_template_string) as a first-class attestation claim that policy can pin.
Adding sampling parameters such as temperature, top_p, top_k, seed, presence_penalty, frequency_penalty, and stop_tokens_hash to the receipt or attestation schema.
Rejecting tee_type == "simulated" by default unless an explicit testing or development policy is enabled.
Binding the NVIDIA NRAS verdict bytes, or a hash of them, into the CPU TEE report_data so that the verifier can require the CPU and GPU evidence to refer to the same computation.
Our current plan is to release a blog post and arXiv preprint around August 6, 2026, which is 60 days from this email. We would like to coordinate responsibly, incorporate your feedback, and acknowledge your response in the writeup.
We would also appreciate any corrections if we have misunderstood Power’s intended threat model, deployment assumptions, model-loading workflow, or verifier API expectations.
Please confirm receipt and let us know which channel you would prefer for further correspondence.
Best,
Bing-Jyue
UIUC

Hi 
Bing-Jyue,

Thank you for the careful review and for disclosing this responsibly. I
confirm receipt.

We have started reviewing your findings against A3S-Lab/Power and can
confirm that several of the issues you identified are soundness-relevant.
In particular, the model-hash enforcement defaults, cached manifest hash
use in /v1/attestation, optional hardware verification, simulated
attestation policy, encrypted-model hash semantics, and the lack of an
explicit CPU/GPU evidence binding all deserve hardening.

One clarification on our intended direction: NVIDIA GPU support is an
important production target for A3S Power. We do intend to support
deployments where inference runs with NVIDIA GPU acceleration, including
confidential-computing-capable GPU environments. Your point is still valid:
the public implementation should make the CPU TEE evidence and GPU
confidential-computing evidence part of one explicitly bound attestation
chain, rather than treating them as separate checks.

Our current remediation plan is:

- fail closed in production/strict TEE mode when required model hashes or
signatures are missing;

- reject tee_type == "simulated" by default outside explicit development
policy;

- make hardware signature verification mandatory in production verifier
paths and clearer in the CLI;

- make /v1/attestation?model=... bind to a well-defined, freshly verified
model digest or fail closed;

- clarify and unify encrypted-model hash semantics, likely separating
plaintext and ciphertext digests;

- add explicit claims for chat-template and decoding-policy state where
applicable;

- add a unified CPU TEE + NVIDIA GPU confidential-computing attestation
chain, binding a hash of the GPU evidence or verdict into the CPU TEE
report data;

- update documentation so the guarantees of current releases are not
overstated while this work is in progress.

Please use this email thread for now. If useful, we can also open a private
GitHub Security Advisory and invite your team there for patch review and
coordinated disclosure.

Your planned August 2026 publication timeline is reasonable. We will aim to
share a concrete patch and documentation plan with you before then, and we
would appreciate the opportunity to review any technical descriptions
involving A3S Power before publication so we can correct misunderstandings
and acknowledge your findings accurately.

Thank you again for the responsible and technically precise report.

Best,
Zhixiao Lin
Shanghai AI Lab
