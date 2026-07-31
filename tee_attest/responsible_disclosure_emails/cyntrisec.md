Title: Potential soundness issues in EphemeralML / AIR v1
To: contact@cyntrisec.com
CC: ddkang@g.illinois.edu, erl015@ucsd.edu, stephanie.q.ding@gmail.com, hpmv118@gmail.com

Hi Cyntrisec security team,
We are a research team at UIUC and MATS studying soundness issues in TEE-based AI attestation systems. As part of this work, we reviewed EphemeralML’s AIR v1 implementation.
We want to say up front that EphemeralML appears to make several careful design choices. In particular, the closed CDDL claims map and verify-before-parse discipline seem to avoid an important class of code-level interpretation bugs. The issues we would like to disclose are mainly about verification defaults, schema completeness, and how the receipt-signing key is chained back to hardware attestation evidence.
Reviewed version: github.com/cyntrisec/EphemeralML, branch main, commit 44cb844e dated 2026-05-23.
The main issues we would like to report are:
The default verification policy appears to skip several identity checks. In common/src/air_verify.rs:283-301, 385-415, AirVerifyPolicy::default() appears to leave several expected_* fields unset. In our current understanding, checks such as MHASH, MODEL, ADHASH, NONCE, and PLATFORM are not all treated as critical by default. This may allow a verifier using the default policy to receive a successful verification result while important model- or platform-identity claims were not pinned.
Sampling parameters do not appear to be represented as structured AIR claims. In common/src/air_receipt.rs:82-108, AIR v1 appears to include fields such as model_id, model_version, model_hash, request_hash, response_hash, policy_version, and security_mode, but not decoding parameters such as temperature, top_p, top_k, seed, or decoding strategy. This may make it difficult for a verifier to distinguish “this model produced this response” from “this model produced this response under the verifier’s intended decoding policy.”
Application-level context does not appear to be separately represented in the receipt schema. The receipt appears to commit to request_hash, but we did not find separate claims distinguishing user-provided input from operator-mediated context such as RAG documents, tool-call outputs, system prompts, conversation history, or output-pipeline rewrites. This may create ambiguity about which application-layer bytes the verifier intended to authorize.
Replay protection appears to be caller-provided. In our current understanding, replay detection depends on the caller providing seen_cti: Option<SeenCtiFn>. This may be safe for careful integrators, but it seems easy for downstream users to omit replay protection unless the SDK provides a fail-closed default or clear warning.
The receipt-signing key does not appear to be automatically chained to the Nitro NSM attestation document. The low-level verifier appears to verify an AIR receipt against a supplied signing key, but we did not find an automatic check that this signing key was bound into a hardware attestation document along the path to the caller. This may allow a structurally valid receipt signature to be mistaken for a full hardware-backed attestation chain if integrators call the low-level verifier directly.
The model-hash scheme appears to be optional. In common/src/air_verify.rs:673-684, model_hash_scheme appears to be optional. In our current understanding, if the scheme is absent, the verifier may pass the corresponding check. This may make it difficult for a verifier to know that both sides used the same hash function or model-hash convention.
Mock-mode receipts may need stronger production safeguards. Our understanding is that feature = "mock" can produce structurally valid AIR receipts in non-TEE deployment. This is useful for testing, but may be risky if production verification does not reject mock or sentinel security modes by default.
Some possible mitigations we are considering include:
Promoting model-, artifact-, platform-, and nonce-related checks such as MHASH, MODEL, ADHASH, PLATFORM, and NONCE to fail-closed behavior under the default verification policy.
Providing a default replay-protection mechanism, such as an in-memory bounded LRU, or emitting a clear verification warning when replay protection is not configured.
Adding sampling parameters such as temperature, top_p, top_k, seed, presence_penalty, frequency_penalty, stop_tokens_hash, and active safety-classifier identifiers to the AIR schema as required or policy-pinnable fields.
Adding structured context claims such as user_messages_hash, system_context_hash, retrieved_context_hash, tool_call_log_hash, post_processing_pipeline_hash, and prior_receipt_hash for multi-turn sessions.
Adding an expected_attestation_doc_hash or equivalent policy field so that the verifier can require the receipt-signing key to trace back to the Nitro NSM attestation document.
Having mock-mode receipts use a sentinel security_mode that the default verification policy rejects.
Providing a high-level chained verifier that verifies the Nitro NSM document against the AWS Nitro CA, extracts the receipt-signing key from user_data, and only then verifies the AIR receipt. The lower-level verify_air_v1_receipt(receipt, key, policy) API could then be documented as a building block rather than the recommended production entry point.
Our current plan is to release a blog post and arXiv preprint around August 6, 2026, which is 60 days from this email. We would like to coordinate responsibly, incorporate your feedback, and acknowledge your response in the writeup.
We would also appreciate any corrections if we have misunderstood EphemeralML’s intended threat model, deployment assumptions, AIR verification workflow, or recommended SDK integration path.
Please confirm receipt and let us know which channel you would prefer for further correspondence.
Best,
Bing-Jyue
UIUC


Hi Bing-Jyue,

Thank you for the careful report. I confirm receipt.

I’m Borys, founder of Cyntrisec. This address is monitored by me, and this email thread with the current recipients is a good channel for coordination.

I appreciate the responsible disclosure timeline and the precise framing, including the positive notes on the closed claims map and verify-before-parse design. I’m glad to coordinate toward your planned writeup and welcome acknowledgment of our response.

I’ll track this internally as the AIR v1 coordinated disclosure thread.

I’ll review each point against the current EphemeralML implementation and the prepared AIR draft-02 text, then follow up by Friday, June 12, 2026 with where I agree, where I think the intended threat model differs, and what I plan to change in code or docs.

Please let me know if you prefer a different secure channel for follow-up artifacts; otherwise email works for coordination.

Best,
Borys Tsyrulnikov
Founder, Cyntrisec

Hi Bing-Jyue and team,

As promised, here is my per-finding response. I reproduced each point against
the commit you reviewed (44cb844e) before answering. Numbering follows your
report.

One framing note first, because several findings touch it. AIR distinguishes
two verification levels: AIR-local verification (COSE structure, signature,
closed claims map, freshness, and policy match against whatever pins the
caller supplies) and end-to-end TEE provenance (AIR-local plus validation of
the platform attestation document, key binding, and measurement
reconciliation). The -02 working text in the tree you reviewed
(spec/v1/ietf/draft-tsyrulnikov-rats-attested-inference-receipt-02.md)
formalizes this: "Validator Behavior" makes the key-binding check and
measurement reconciliation a MUST for validators asserting TEE assurance and
says an AIR-local validator "MUST NOT claim TEE provenance from the receipt
alone"; "Trust Assumptions" (TA-1..TA-4) states that layers 1-4 prove only
TA-independent properties. Where your findings show the implementation makes
that distinction too easy to miss, I agree, and I'm changing the code rather
than pointing at the spec.

1. Default policy skips identity checks - agree. Your reading is correct:
AirVerifyPolicy::default() leaves all expected_* pins unset
(air_verify.rs:283-301) - it does enforce freshness (max age 3600s) and
rejects evaluation-mode receipts, but every unpinned identity check is
reported as Skip, and verified_from_checks() (385-394) lets non-critical
skips through; is_critical_check_name() (396-415) covers the structural,
cryptographic, and closed-set checks but not MHASH, MODEL, ADHASH, PLATFORM,
NONCE, or REPLAY. The design intent was that default() is the AIR-local
baseline - identity pins are deployment-specific, so there is no meaningful
universal default - and each skip is individually visible in result.checks.
But I agree the single top-level verified: bool invites exactly the misread
you describe. One thing your report did not mention, for completeness: the
report layer in the same commit already starts making the distinction
explicit - the ephemeralml-report tool emits assurance_level = "air_local" vs
"tee_provenance" (the latter only when an attestation document is supplied,
verified, attestation_doc_hash-bound, and signing-key-bound), plus an
explicit warning when no attestation sidecar is given
(common/src/verification_report.rs, client/src/bin/ephemeralml_report.rs).
That report path does not yet perform every Validator Behavior check I want
to require for end-to-end TEE provenance, especially measurement
reconciliation; the narrower point is that a higher-level artifact already
distinguishes receipt-local from attestation-backed reporting. The gap you
found is real at the layer you audited: the library result type does not
carry that distinction, and the higher-level semantics need to be made
consistent. Planned changes: (a) propagate and tighten the assurance-level
distinction into the library result (AIR-local vs chained TEE provenance,
including measurement reconciliation where provenance is claimed, with
skipped identity checks listed), (b) a strict policy constructor that
requires explicit values for model hash, model ID, attestation document hash,
and platform, and requires a nonce and a replay hook, (c) a rustdoc warning
on default().

2. Sampling parameters - agree this is a real gap for decoding-policy
assurance. It was a deliberate v1 scope cut (v1 commits to the
application-layer request/response bytes and defines no extension registry;
see Non-Goals), and I plan to handle it as profile claims rather than core
claims. One nuance worth reflecting in your writeup: claims like temperature,
top_p, or seed are workload-asserted values under our trust assumption TA-2 -
a verifier can policy-pin them (reject receipts asserting an unexpected
decoding configuration) but generally cannot recompute the response to
confirm the policy was actually applied, given nondeterministic accelerator
kernels. So they add policy-pinning value, not independent verifiability. The
-02 revision will add a "Future Profile Candidates" section naming
sampling/decoding parameters together with this trust-class analysis; your
proposed claim list is useful input to it.

3. Structured context claims - same category, and I agree on the ambiguity
you identify. request_hash deliberately commits to the full request bytes as
the workload saw them; v1 does not distinguish user input from
operator-mediated context. Multi-receipt chaining (prior_receipt_hash) was
explicitly deferred (Non-Goals lists pipeline chaining; sequence_number gives
only within-session monotonicity, with its limits documented under Replay
Protection). For context, nearby literature is cautious in the same way:
AEX (arXiv:2603.14283), a recent LLM API provenance proposal, binds a
client-visible request projection to a response/output lineage, and
explicitly says it does not prove absence of hidden prompts, hidden
retrieval, or hidden policy systems; visibility of every hidden intermediate
output; or semantic correctness of accepted output transforms. The
same Future Profile Candidates section will name structured context claims
(user / system / retrieved-context / tool-log hashes, prior receipt hash).
To be transparent: -02 reserves the design space and the trust analysis; I am
not committing to a delivery date for the profile itself.

4. Replay protection caller-provided - agree. seen_cti defaults to None and
require_nonce to false, so REPLAY and NONCE are Skip under the default
policy. The published -01 already frames replay as a shared responsibility
and says deployments requiring strong replay resistance MUST use at least one
of cti deduplication or eat_nonce; the -02 text adds a Freshness Boundary
subsection (a nonce proves freshness only to the party that issued it; iat is
workload-asserted; audit-time freshness and non-omission need an external
layer such as a countersigning transparency log, which AIR v1 deliberately
does not define). For the implementation I will do what you suggest, with one
honest caveat: I will ship a bounded-LRU seen-cti helper in the crate and
require a replay hook and nonce in the strict constructor, but an in-memory
cache only covers a single verifier process - durable cross-restart,
cross-instance deduplication is deployment infrastructure that a receipt
library cannot own. The verification level will therefore state explicitly
when no replay protection was configured, rather than leaving it as a Skip
line.

5. Receipt key chaining to the NSM document - the chained path exists, so let
me correct the record on specifics while agreeing with your conclusion about
API positioning. In the reviewed commit: extract_key_from_attestation()
(client/src/receipt_key.rs) verifies the NSM COSE_Sign1 signature and
certificate chain against the AWS Nitro root CA before trusting the embedded
user_data, and refuses plain-CBOR mock documents unless the caller explicitly
opts in via allow_mock. The policy field you propose already exists:
expected_attestation_doc_hash (air_verify.rs:801-818) binds the receipt to a
specific attestation document. The verifier CLI's --attestation flow does
exactly the chained sequence from your mitigation list: read the document,
verify it against the root CA, extract the key from user_data, automatically
set expected_attestation_doc_hash = SHA-256(document), then verify the
receipt (client/src/bin/ephemeralml_verify.rs:308-345); ephemeralml-report
then raises its report-layer assurance level only when those document-hash
and signing-key bindings hold. As noted above, I will tighten the meaning of
that level to include measurement reconciliation where TEE provenance is
claimed.
The published -01 also already states that AIR-local verification is
insufficient for TEE assurance and that verifiers requiring it MUST
independently obtain and verify the attestation document. What is missing is
exactly what you say: a single library-level chained entry point, and
documentation that positions verify_air_v1_receipt(receipt, key, policy) as a
building block rather than the recommended production entry point. Planned: a
one-call chained verifier in the client library (attestation document +
receipt + policy in, leveled result out), and rustdoc repositioning of the
low-level function. You may also find it relevant that there is closely
related individual Internet-Draft work in the RATS space on this failure
class - key substitution when attestation evidence and operational-key
proof-of-possession are validated independently - namely
draft-reddy-rats-key-binding-01 (an individual draft, not a WG item, posted
June 7). The -02 revision will reference it, since AIR's Nitro user_data
construction is analogous to the draft's combined-model shape: platform
attestation carries both platform state and the public key to bind, while the
AIR receipt signature supplies proof of possession for that key.

6. model_hash_scheme optional - agree. Confirmed behavior: an absent scheme
passes the MHASH_SCHEME check (air_verify.rs:673-684); a present-but-unknown
scheme fails closed. The spec defines absence semantics (model_hash treated
as opaque: comparable against a known-good value, not independently
reproducible), but you are right that a deployment which requires
reproducibility has no policy knob to demand the scheme. Planned: a
require_model_hash_scheme policy flag, set by the strict constructor.

7. Mock-mode receipts - agree, and this is the clearest bug of the set. Today
the only emission mapping is SecurityMode::GatewayOnly -> "production"
(air_receipt.rs:206), so a mock-feature build running outside any TEE emits
receipts labeled production. The rejection machinery for a sentinel already
exists and is fail-closed by default: "evaluation" receipts are rejected
unless the caller opts in (air_verify.rs:850-856), and the spec says
evaluation receipts MUST NOT be accepted for production trust decisions. The
planned fix is your sentinel mitigation, without widening the closed value
set: mock-feature builds will emit security_mode = "evaluation". That keeps
test receipts distinguishable from production evidence and makes the default
verifier fail closed.

Timeline and coordination:

- Code changes (findings 1, 4, the finding-5 ergonomics, 6, 7): targeted to
  land on main by 2026-06-30. I'll send you the commit hashes.
- Spec: AIR -01 is already on the IETF datatracker
  (draft-tsyrulnikov-rats-attested-inference-receipt-01); the -02 revision
  including the clarifications above goes up before the IETF 126 draft cutoff
  (2026-07-06). I'll send the link - it is probably the right citation target
  for your preprint.
- Your August 6 window works for me. Two requests: where the writeup
  describes current behavior, I'd appreciate it noting the reviewed commit
  (44cb844e) and, where applicable, the fixed state; and I'm happy to review
  the relevant sections for technical accuracy before publication - accuracy
  review only, not approval.
- If you built proof-of-concept artifacts (for example, a mock-emitted
  receipt passing a default-policy verify), I'm happy to receive them and
  will preserve them as regression tests, though our reproduction already
  matches your reading.

For your writeup, I am comfortable with you saying that we confirmed the
verifier-default, replay-signaling, model-hash-scheme-policy, mock-separation,
and chained-verifier-ergonomics concerns; that we distinguish AIR-local
receipt validity from end-to-end TEE provenance; and that we committed to
implementation and draft clarifications ahead of your publication.

Thank you for the quality of the report. The file:line anchors and the
explicit "our current understanding" framing made every item straightforward
to reproduce, and your mitigation list overlaps almost entirely with what I'm
implementing.

Best,
Borys

Hi Bing-Jyue and team,

Following up on my June 12 response: the code changes I committed to are now on
main (github.com/cyntrisec/EphemeralML). Commit hashes, mapped to your findings
and stated against the commit you reviewed (44cb844e):

- Finding 7 (mock-mode receipts labeled "production") — 53b3390. Builds compiled
  with the mock feature now emit security_mode = "evaluation", which the default
  verifier rejects; "production" and "evaluation" remain the only members of the
  closed value set, so nothing is widened.

- Finding 1 (default policy skips identity checks) — bfe856f. The verification
  result now carries a first-class assurance level (AirLocal vs TeeProvenance)
  and lists the identity checks left unpinned, so callers no longer have to
  infer hardware provenance from "verified: true" alone. I added a strict() policy
  constructor that pins model hash, model id, attestation-document hash, and
  platform and requires a nonce and a replay hook, and documented default() as
  the AIR-local baseline.

- Finding 4 (replay protection caller-provided) — b8f10f5. There is now a
  bounded in-memory seen-cti cache in the crate, required by strict(). The
  honest caveat from my last note stands: it covers a single verifier process;
  durable cross-restart, cross-instance deduplication is deployment
  infrastructure a receipt library cannot own.

- Finding 6 (model_hash_scheme optional) — 07658b5. A require_model_hash_scheme
  policy flag (set by strict()) now fails closed when the scheme is absent or
  unknown, for deployments that need the model hash to be reproducible.

- Finding 5 (receipt-key chaining ergonomics) — 0797de1. There is now a
  one-call chained verifier in the client library,
  verify_air_v1_receipt_chained(receipt, attestation, policy): it verifies the
  Nitro platform attestation document, derives the receipt-signing key from it,
  pins expected_attestation_doc_hash, reconciles measurements, and raises
  TeeProvenance only when all of that plus AIR-local verification pass. The
  low-level verify_air_v1_receipt is repositioned in its docs as a building
  block rather than the recommended production entry point.

One follow-up commit hardens the finding-5 work, 4bc6c34: PCR reconciliation is
now a single routine shared by the hosted verifier and the chained verifier (so
they cannot diverge), receipt-asserted PCRs beyond what the attestation exposes
fail closed, and TeeProvenance additionally requires a production-mode receipt.

All of this is non-breaking: the AIR v1 wire format and eat_profile are
unchanged and existing receipts remain valid. I also validated the verification
path on real hardware. On AWS Nitro the chained verifier reached TeeProvenance
against a live NSM attestation document, with measurement reconciliation
passing and the document-hash binding rejecting a receipt paired with a
different document. On GCP Confidential Space (Intel TDX) the end-to-end
emit-and-verify passed with a production-mode receipt and the platform-evidence
boot binding verified. The current main tip is a later commit (df44542) that
only reformats the touched Rust files and updates quinn-proto for a RustSec
advisory; it does not change the AIR verifier behavior described above.

On the spec: AIR -02 — including the clarifications from my last note (the
AIR-local vs TEE-provenance validator behavior, the freshness boundary, and the
future-profile candidates for sampling and structured-context claims) — goes up
on the IETF datatracker before the IETF 126 cutoff on July 6. I'll send the
link once it's posted; it is probably the right citation target for your
writeup.

Your August 6 window still works for me. The two requests from before stand:
where the writeup describes current behavior, I'd appreciate it noting the
reviewed commit (44cb844e) and, where applicable, the fixed state above; and
I'm glad to review the relevant sections for technical accuracy before
publication — accuracy review only, not approval.

Thank you again for the report. The file:line precision made every item
straightforward to reproduce and fix.

Best,
Borys

Hi Bing-Jyue and team,

Thanks — your proposed framing matches my understanding and is fair. AIR -02 is now posted:

- Datatracker: https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/
- This revision (-02): https://datatracker.ietf.org/doc/html/draft-tsyrulnikov-rats-attested-inference-receipt-02

draft-tsyrulnikov-rats-attested-inference-receipt-02 is the right citation
target — I'd pin "-02" explicitly (the doc page always resolves to the latest
revision).

Confirming your framing against the published text:
- distinguishing the reviewed commit (44cb844e) from the fixed state on main —
  yes;
- describing AIR-local verification separately from end-to-end TEE provenance —
  yes; -02 formalizes it in "Validator Behavior" (Section 7.3) and "Trust
  Assumptions" (Section 11.1, TA-1..TA-4);
- treating the sampling-parameter and structured-context points as
  schema/profile and policy-pinning gaps rather than implementation bugs — yes;
  -02 carries them in Section 10 "Future Profile Candidates" (Section 10.1
  decoding/sampling, Section 10.2 structured context) with the TA-2
  workload-asserted / policy-pinnable-not-recomputable analysis, not as
  completed v1 fields;
- citing -02 for the current spec text alongside the reviewed commit and the
  remediation commits from my June 30 note — that's exactly the structure I'd
  suggest.

The offer stands both ways: I'm glad to review the EphemeralML/AIR technical
sections for factual accuracy before publication — accuracy review only, not
approval — and can turn comments around quickly on your early-August window.
Send them whenever they're ready.

Thanks again for the rigor and the constructive coordination.

Best,
Borys