Title: Potential soundness issues in NEAR AI Cloud verifier
To: security@near.org
CC: ddkang@g.illinois.edu, erl015@ucsd.edu, stephanie.q.ding@gmail.com, hpmv118@gmail.com

Hi NEAR AI security team,
We are a research team at UIUC and MATS studying soundness issues in TEE-based AI attestation systems. As part of this work, we reviewed the NEAR AI Cloud verifier, including the public repository at github.com/nearai/nearai-cloud-verifier.
During our review, we identified several potential soundness gaps that we would like to disclose and discuss with you. The issues we believe are most important involve GPU attestation verification, model binding, TLS/channel binding, sampling-parameter binding, and the lack of an explicit cryptographic binding between the CPU TEE attestation and GPU confidential-computing evidence.
Reviewed version: github.com/nearai/nearai-cloud-verifier, branch main, commit 8b7830e9 dated 2026-05-06.
The main issues we would like to report are:
The NVIDIA NRAS JWT payload appears to be parsed before signature verification. In py/model_verifier.py:42-47, the verifier appears to call base64url_decode_jwt_payload and read the JWT payload without first verifying the JWT signature against NVIDIA’s JWKS. In our current understanding, this may allow unauthenticated or stale GPU evidence to influence the verifier’s result.
The TDX report_data layout does not appear to bind the model identity. In py/model_verifier.py:66-126, the CPU attestation evidence appears to bind the signing key and nonce, but does not appear to include a model_hash slot. This may allow the attestation to verify independently of the specific model weights used for inference.
TLS/channel binding appears to rely on an optional flow. In tls_verifier.py:80-82, CA verification is disabled while the verifier checks the attested TLS certificate fingerprint. This design can be sound if the caller pins the expected signing address and consistently invokes the TLS-binding path. However, our understanding is that --signing-address and --verify-tls are optional in some flows, which may make it easy for integrators to validate attestation evidence without actually binding it to the live TLS channel.
Sampling parameters appear to be outside the signed receipt. In chat_verifier.py:78-91, the signed text payload appears to commit to request_hash and response_hash, but not to decoding parameters such as temperature, top_p, top_k, seed, or the decoding strategy. This may allow the operator to vary generation behavior while still producing structurally valid receipts.
The CPU and GPU attestation chains do not appear to be explicitly bound. In model_verifier.py:129-184, the Intel TDX quote and NVIDIA NRAS verdict appear to be checked as separate pipelines. We did not find a field that binds the NRAS verdict or GPU evidence to the specific CPU TEE attestation. This may allow otherwise valid CPU and GPU evidence to be combined without proving that they refer to the same computation.
Application-level context appears to be collapsed into a single request hash. The signed receipt format appears to hash the request bytes seen by the model, but does not distinguish user-provided input from operator-mediated context such as system prompts, RAG documents, tool outputs, or conversation history. This may create a gap between “these bytes were signed” and “these were exactly the user-intended input bytes.”
Some verifier checks appear to warn or print rather than fail closed. For example, our current understanding is that some mismatch or status conditions are reported with print rather than causing verification failure. This may make verifier outcomes easy to misinterpret in downstream integrations.
Some possible mitigations we are considering include:
Verifying the NVIDIA NRAS JWT signature against NVIDIA’s JWKS before reading or trusting any payload fields.
Adding a model_hash, or model_hash_scheme plus hash, to the TDX report_data layout and requiring verifier policy to pin it.
Making TLS/channel binding mandatory in the SDK-level verification path, so the live TLS certificate SPKI is checked before any request body is sent.
Requiring --signing-address or an equivalent pinned identity in verification flows.
Promoting mismatch/status checks from print warnings to hard verification failures where appropriate.
Adding sampling parameters such as temperature, top_p, top_k, seed, and decoding strategy to a structured receipt claim.
Binding the NVIDIA NRAS verdict bytes, or a hash of them, into the CPU TEE attestation evidence.
Replacing the signed text format with a structured claims object that separately commits to user messages, system context, retrieved context, tool-call logs, and prior receipt hashes for multi-turn sessions.
Our current plan is to release a blog post and arXiv preprint around August 6, 2026. We would like to coordinate responsibly, incorporate your feedback, and acknowledge your response in the writeup.
We would also appreciate any corrections if we have misunderstood NEAR AI Cloud’s intended threat model, deployment assumptions, verifier workflow, or channel-binding design.
Please confirm receipt and let us know which channel you would prefer for further correspondence.
Best,
Bing-Jyue
UIUC



Hi Bing-Jyue and team,

Thanks for the detailed read. It's clear you spent real time in the code, and we went back through each point against the same commit you cited (8b7830e9).

One thing up front, because it changes how most of the items land: the scripts in nearai-cloud-verifier are illustrative clients. Their job is to show a user how to pull NEAR AI Cloud's attestation evidence and read what it contains. They aren't the trust boundary, and nothing in the request path depends on them. The security comes from what the TEE binds into the Intel TDX quote and the NVIDIA GPU attestation, plus the gateway's own enforcement. So for each point, the question we cared about is whether the evidence carries the property, not whether one example script asserts it.

Point by point:

(1) The NRAS verdict is fetched straight from nras.attestation.nvidia.com over CA-verified TLS, so its authenticity rests on that channel to NVIDIA, not on a client re-checking the JWT, and nobody sits in between who could swap it. A JWKS check is reasonable defense in depth for anyone writing their own verifier.

(2) Model identity is bound, just not in report_data. It lives in the TDX register mr_config_id = 01 || SHA256(app_compose), which the example checks, and the compose pins every image by @sha256 digest with Sigstore provenance. report_data is the right home for the runtime signing key and nonce; a static workload measurement belongs in the MR registers, and that's where it is.

(3) The TLS binding is in the quote too: with include_tls_fingerprint, report_data[0..32] = SHA256(signing_address || spki_hash), checked against the live certificate over a single connection. Whether a given run passes --verify-tls is an ergonomics choice in example code, and the domain path already does it by default.

(5) The TDX quote and the GPU evidence both answer the same fresh nonce and are produced inside the same compose measured by mr_config, so they're tied to one challenge and one workload. Coupling the two evidence blobs more tightly is a design dimension we think about, and a good one to talk through, though the current construction meets the guarantee we make.

(4) and (6) are about something a signature over inputs and outputs can't give you. Sampling parameters are already inside request_hash, which is a SHA256 of the exact request body; proving the server honored a parameter, or that a sampled decode is reproducible, isn't something such a signature can show. Request context is the same: the receipt commits to the exact bytes the model saw, and splitting user input from system or tool content is an application-layer choice a caller can make by hashing those parts itself.

(7) Printing each check instead of failing is deliberate. The scripts show a reader what gets verified, step by step. They're walkthroughs, not a verification library, and we'll keep tidying them for clarity.

So across the list, we don't see these as changing the platform's security properties for the reasons above. I'd be glad to walk you through the attestation design on a call, since one or two of these settle faster live than over email.

If it's useful, we'd also be glad to read the part of your write-up that covers NEAR AI Cloud before you publish, just to make sure the threat model and architecture come across accurately. Happy to be acknowledged for the exchange.

Best,

Pierre