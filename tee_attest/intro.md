# 1. Introduction

<!-- Working title: "When the Prover Lies: Breaking Soundness in
TEE-Based AI Attestation". Target: IEEE S&P / NDSS (research paper,
double-blind). See drafting notes at the bottom of this file. -->

A new class of commercial service promises something that, until
recently, was impossible: *verifiable* AI inference. Providers such
as Tinfoil, NEAR AI Cloud, and others run large language models
inside hardware Trusted Execution Environments (TEEs) — Intel TDX,
AMD SEV-SNP, AWS Nitro, increasingly paired with confidential-compute
GPUs (NVIDIA H100 CC) — and hand the user a signed *attestation*: a
hardware-rooted certificate asserting that the user's prompt was
processed by a specific model, in a genuine enclave, with the user's
data kept private from the operator. Enterprises adopting these
services, and the regulators beginning to reference them, treat that
certificate as proof. The entire value proposition is that the user
no longer has to trust the provider's word — the hardware vouches for
it.

Trustworthiness here rests on *two* independent properties.
**Confidentiality**: the operator cannot read the user's prompts,
responses, or the model weights. **Soundness**: the claims carried by
the attestation are actually true — it really was the named model, run
under the stated configuration, on the hardware described, with the
data handled as promised. A decade of TEE-for-ML research has been
almost entirely about the first property \cite{mo2024, confidential-ml-survey}:
how to keep data secret from a curious or compromised host. The second
property has gone largely unexamined, even though it is the one the
attestation actually advertises, and even though the party producing
the attestation — the service operator — is also the party with the
strongest incentive and the most complete control to forge it.

The difficulty is structural. Hardware attestation signs a
*measurement*: a hash of the code that launched, plus an
operator-assembled payload. But the measurement is not the property.
"This is Llama-3-70B at temperature 0," "my prompt was not logged,"
"the H100 in the certificate is the GPU that actually ran the
matrix multiplies" — none of these is a hash the hardware computed.
Each must be *translated* from the raw measurement into a claim the
verifier checks, and that translation is software the operator writes.
The gap between a measurement and the property a relying party cares
about is the oldest open problem in attestation \cite{sadeghi2004,
coker2011}. Our question is empirical and adversarial: **in the TEE-AI
systems people are deploying today, does this translation survive a
provider who wants it to fail?**

It does not. We present the first systematic offensive analysis of
soundness in TEE-based AI attestation. We adopt a **malicious-prover**
threat model that, unlike the honest-but-curious host of the
confidentiality literature, matches the trust relationship these
services actually create: the operator runs genuine TEE hardware and
may even preserve confidentiality perfectly, but controls everything
*around* the enclave — launch configuration, the bytes on disk, the
model loader, the network edge, the receipt schema, and any external
evidence the verifier consults — and seeks to make the verifier accept
claims that are false. We instantiate this model against six systems
spanning the deployment spectrum: a published academic prototype, open
build-time tooling, and live commercial services with paying customers,
collectively exercising four CPU TEE technologies and confidential-GPU
attestation.

Across these systems, sound attestation fails pervasively, and it
fails in the same ways. A model the operator never loaded passes
verification because no field in the quote names the weights. A
randomly-initialized network is certified to 99% accuracy by a
genuine Intel-signed quote, because the audited code deserializes an
attacker-supplied checkpoint that rewrites the metric function. A
model is swapped *after* the attested hash is read. A CPU and a GPU
attestation, each individually valid and signed by their respective
hardware vendors, are accepted as a pair though nothing binds them to
the same computation. The vulnerabilities we find cluster into **nine
classes**; we demonstrate them with **19 proof-of-concept attacks**,
eight of which drive the systems' *original, unmodified* code and the
rest a small mock at an external trust boundary.

Five of the nine classes are modern incarnations of gaps long known to
property-attestation theory — unmeasured configuration, opt-in policy
checks, unauthenticated external evidence, trusted code that consumes
hostile input, and stale cached state. That they are simultaneously
live in six independently engineered systems, built by different teams
in different languages over a four-year span, is itself a finding: the
recurrence is structural, a consequence of there being no compiler from
"property" to "measurement," not of any one team's carelessness. The
remaining **three classes have no analog in two decades of attestation
work**, because the problem they describe did not exist before
generative models running on composed hardware:

- **Unattested sampling regime.** An LLM's output is a function not
  only of the prompt and weights but of `temperature`, `top_p`, `seed`,
  stop tokens, and the active safety classifiers. No surveyed receipt
  commits to any of these, so an operator can steer behavior
  arbitrarily without a single claim becoming a lie.
- **Unbound multi-root composition.** Production deployments now chain
  *several* hardware roots — a CPU TEE plus a confidential GPU. Each
  signs an honest attestation of itself, but nothing cryptographically
  binds "this GPU verdict" to "the GPU that ran this inference," so a
  cached or cross-tenant GPU attestation passes.
- **Unattested application context.** Real LLM applications wrap each
  inference in operator-mediated bytes — retrieved documents, tool
  outputs, conversation history, output filters. A receipt that hashes
  the user's request and the user's response is honest about its
  endpoints and blind to everything the operator injected in between.

We further identify a boundary that bounds what attestation can ever
deliver, and that the nine classes silently assume away: **measured is
not audited.** Attestation establishes code *identity* — this exact
hash ran in genuine hardware — never code *safety*. A verifier that
pins the hash of an opaque binary, or of a loader whose job is to fetch
and execute code the measurement never saw, has perfect soundness with
respect to identity and zero assurance about behavior. This is the seam
where attestation meets source audit, and it explains why hardening all
nine classes is necessary but not sufficient for a trustworthy service.

These results have immediate stakes: several of the affected systems
serve live user traffic today. We have undertaken coordinated
disclosure with every affected vendor (\S\ref{sec:disclosure}), and we
distill our findings into a set of design principles and per-class
mitigations — most of which already appear, correctly implemented, in
*some* surveyed system, demonstrating that each gap is closable without
new hardware or cryptography.

**Contributions.** In summary, this paper makes the following
contributions:

1. **A malicious-prover threat model for TEE-AI attestation**
   (\S\ref{sec:threat}). We articulate the soundness question —
   *are the claims a verifier accepts actually about what was
   computed?* — as distinct from the confidentiality question that
   dominates TEE-ML research, and we map the eight joints in a generic
   TEE-AI attestation workflow at which a malicious prover can subvert
   it.

2. **The first systematic offensive study of deployed TEE-AI
   attestation** (\S\ref{sec:attacks}). Across six systems and four
   TEE technologies, we discover nine classes of soundness
   vulnerability and demonstrate them with 19 proof-of-concept attacks
   (eight against unmodified system code), including exploitable flaws
   in commercial services with real users.

3. **Three soundness failure modes unique to the AI setting**
   (\S\ref{sec:novel}) — unattested sampling, unbound multi-root
   composition, and unattested application context — none of which has
   an analog in prior attestation literature, together with the
   *measured-≠-audited* boundary that delimits attestation's reach.

4. **Defenses** (\S\ref{sec:defenses}). We give a fail-closed design
   discipline and concrete, per-class mitigations, and show that every
   fix is already realized in at least one surveyed system.

The rest of the paper is organized as follows. \S\ref{sec:background}
reviews TEE attestation and the TEE-AI deployment pattern.
\S\ref{sec:threat} defines the threat model and workflow.
\S\ref{sec:attacks} presents the vulnerability classes and attacks;
\S\ref{sec:novel} treats the three AI-native classes in depth.
\S\ref{sec:defenses} develops defenses, \S\ref{sec:disclosure} covers
disclosure and ethics, and \S\ref{sec:related} situates the work.

---

<!--
DRAFTING NOTES (delete before submission)

Framing choice. This intro is written as an *attack/measurement*
research paper, not a SoK: the hero contribution is "we discovered and
demonstrated exploitable soundness failures in deployed TEE-AI
systems," with the nine-class taxonomy demoted to a *result* of that
analysis. This is the framing that survives the "isn't this just a
survey / isn't F1–F5 already known?" reviewer objection at S&P/NDSS.
If you'd rather lead with the *defense* (the design discipline /
checklist) or with the *novel-classes theory* (F7–F9 as the core
intellectual contribution), the paragraph order and contributions list
should be re-weighted — tell me and I'll re-cut.

Double-blind. S&P and NDSS are double-blind. I kept the *subject*
vendor names (Tinfoil, NEAR AI, etc.) since an attack paper must name
what it breaks, but removed any first-person reference to our own prior
artifacts. Verify the system names you're comfortable disclosing
pre-publication; some vendors may request anonymization until a fix
ships.

Open placeholders to fill:
- Exact PoC/finding counts if they change (currently 6 systems, 9
  classes, 19 PoCs, 8-on-unmodified-code).
- Disclosure status: the contributions claim "coordinated disclosure
  ... with every affected vendor." The master doc (§7.2) lists this as
  REQUIRED-before-publication. Make this sentence true before
  submitting, or soften to "are undertaking."
- \cite keys are placeholders: sadeghi2004 (property-based
  attestation), coker2011 (principles of remote attestation),
  kil2009 (dynamic properties), mo2024 + confidential-ml-survey
  (confidentiality-side TEE-ML), brundage2020 (verifiable claims).
- The four vivid attacks in ¶5 are, in order: NEAR AI no-model-binding
  (Attack 2), Laminator metric forgery (Attack 7), Power cache TOCTOU
  (Attack 3), Power/NEAR AI CPU↔GPU composition (Attacks 12/18). Swap
  in whichever land hardest with your audience; the random-init-99%
  one is the strongest hook and could even open the paper.
- Section \ref labels are guesses; align with the actual skeleton.

Length: ~1.1 pages in the IEEE 2-column template. Trim ¶6 or the
measured-≠-audited paragraph first if over budget.
-->
