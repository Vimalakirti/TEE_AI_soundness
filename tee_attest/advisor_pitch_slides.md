# Soundness Gaps in TEE-Based AI Attestation

### A promising research direction — early findings & roadmap

[Your Name] · [Date]

---

## The Promise

> "Your AI computation ran inside a hardware-protected enclave.
> No one — not even the cloud operator — can lie about what was computed."

This is what a growing set of TEE-AI services is selling today — including
the systems we'll discuss in this talk (**Tinfoil**, **NEAR AI Cloud**,
**EphemeralML / Cyntrisec**, **A3S / Power**), as well as a published
academic prototype (**Laminator**).

The promise rests on a single chain:

> hardware-signed measurement → enclave code → application output

---

## How TEE-Based AI Attestation Works

A **TEE (Trusted Execution Environment)** is a hardware-protected region
on the CPU. The cloud operator owns the machine, but:

- They **cannot see** into this region (memory is encrypted).
- They **cannot lie** about what code is loaded into it (the CPU signs a
  fingerprint of the loaded code with a vendor-held key — Intel, AMD, AWS, etc.).

### The chain of trust the user is supposed to get

1. The cloud operator boots the AI service **inside a TEE**.
   The CPU computes a "code fingerprint" and signs it with the vendor's key.
2. The user sends an AI request. The TEE runs the AI model and produces a
   signed per-request **receipt**: *"my code-fingerprint = X; I processed
   input Y; I produced output Z."*
3. The user receives the response + receipt + fingerprint, then:
   - checks the fingerprint matches the expected AI service, and
   - checks the receipt signature came from inside that same TEE.

### Who controls what

| Party | Controls | Cannot lie about |
|---|---|---|
| **Cloud operator** | The machine, network, model files on disk — everything *outside* the TEE | Anything *inside* the TEE — the CPU enforces it |
| **TEE hardware** | The signing key, the code fingerprint | Out of scope — assumed to work |
| **User (verifier)** | Which fingerprint they expect; which checks they perform | (The user is the party being protected) |

### The property we're stress-testing

> *"A malicious cloud operator cannot lie about which AI model ran,
> what input it received, or what output it produced."*

**Our research question:** does the chain of trust above actually deliver
this property, or does it have systematic gaps?

### Quick glossary

- **TEE** (Trusted Execution Environment) — a secure region on the CPU.
- **Enclave** — a running instance of code inside a TEE.
- **Attestation** — a signed statement from the CPU about what code is
  loaded into the enclave.
- **Receipt** — a signed statement *from inside the enclave* about a
  specific AI request and its output.
- **Verifier** — the party (the user, or software acting for them)
  checking the attestation and receipt.

---

## The Gap (one sentence)

Trusted hardware can only sign **a fingerprint of code**.
What users actually care about is **what that code did with their AI request**.

Between those two things sits a long bridge — model identity, configuration,
policy, channel, sampling — that has to be **wired by hand, in software, by
every implementer**.

**We are finding that this bridge is systematically broken.**

---

## Why This Matters Now

TEE-based AI attestation is the trust mechanism behind a growing class of
commercial services in **2025–2026**:

- YC-backed TEE-AI providers offering "verifiable inference."
- Live cloud chat services advertising hardware-rooted attestation.
- Early-access commercial verifiers with their own receipt formats.
- Open-source Rust crates and academic prototypes.

If the trust claim breaks → users believe lies about AI computation.

**No prior systematization-of-knowledge paper covers TEE-AI soundness gaps.**
The closest adjacent literature is about *confidentiality* (can the operator
see the prompt?), not about *soundness* (does the receipt mean what it says?).

---

## What We Did (Preliminary Work)

- Picked **3 representative TEE-AI attestation systems** and read their
  source code line by line.
- For each gap we found, built a **runnable proof-of-concept** — a small
  program that produces a forged attestation that the system's own
  verifier accepts as legitimate. None of these PoCs modify the original
  systems' source.
- Started to see the **same patterns recur across independent systems** —
  not isolated bugs, but a structural problem.

---

## The Systems We're Surveying

| System | Type | TEE Platform | Status |
|---|---|---|---|
| **Laminator** | Academic prototype (CODASPY '25) | Intel SGX | **Analyzed** |
| **NEAR AI Cloud** | Live cloud service | Intel TDX + NVIDIA H100 CC | **Analyzed** |
| **A3S / Power** | Open-source crate | TDX / SEV-SNP (+ H100 optional) | **Analyzed** |
| Tinfoil | YC-backed commercial | TDX + H100 CC | Listed; queued for analysis |
| Cyntrisec / EphemeralML | Early-access commercial | AWS Nitro Enclaves | Listed; queued for analysis |

*TEE platform names are the CPU vendor's brand for "secure region":*
*Intel SGX (older), Intel TDX (newer), AMD SEV-SNP, AWS Nitro Enclaves.*
*"H100 CC" means an NVIDIA H100 GPU running in confidential-compute mode —*
*a GPU equivalent to a CPU TEE.*

**3 analyzed today. 2 more queued.** More candidate systems exist in the
broader TEE-AI ecosystem (we can extend the survey beyond these 5 if the
direction is approved).

---

## What We're Looking For

A **soundness gap** is a place where a dishonest cloud operator can
produce an attestation that:
- looks legitimate (signatures all valid, verifier prints "verified ✓"),
- but **does not actually describe what the AI service did** for the user.

We grouped what we found so far into **4 common gap patterns**. Each is
shown below with a concrete demonstration.

> Note: these 4 are the clearest cases. We have additional candidate
> patterns we're still validating — we'll bring those next time once
> this direction is approved.

---

## Gap 1 — The Secure Box Reads the Attacker's "Code"

### The bug, in one sentence
The TEE's code is fixed at boot, but the AI model files it loads from
disk are **not** part of the measured code. If the file format secretly
allows embedded code (like Excel macros for Python — the `.pth` /
"pickle" format does), the TEE happily runs that code **inside its
trusted region**.

### Concrete demo: Laminator (academic, CODASPY '25)
- The TEE runs Python and loads a model file: `torch.load("model.pth")`.
- That call silently executes any Python code embedded in the `.pth`
  file (PyTorch's default behavior — known but enabled by default).
- A malicious model file patches the in-TEE accuracy-test function to
  **always return "99% accuracy"** regardless of what the real model
  would have scored.

### What the user sees
> A hardware-signed attestation that says: *"This Intel SGX TEE ran
> Laminator's auditing code and measured 99% accuracy."*
>
> The real model is a randomly-initialised network whose true accuracy
> is **~24%** (i.e., random guessing on a 4-class problem).

The hardware signature is genuine. The number it commits to is a lie.

---

## Gap 2 — Critical Checks Are Off by Default

### The bug, in one sentence
Every verifier library we surveyed comes with critical security checks
built in — *"is the hardware signature real?"*, *"did the right AI model
run?"* — but the **defaults turn those checks off**, and the API hides
that fact from the caller.

### Analogy
A car with airbags installed but switched off in the factory settings.
The capability exists; the default doesn't engage it.

### Concrete demo: A3S Power (open-source Rust crate)
- Power's verifier function has a parameter called `hardware_verifier`,
  declared as optional.
- The example code in Power's own documentation sets this parameter to
  **None** (skip the check).
- We hand the verifier a **completely fake attestation report** — no
  real hardware ever signed it.

### What the user sees
> The verifier returns **success**. The "did we actually check the
> hardware signature?" answer is buried in a boolean inside the return
> value that the caller has to remember to inspect separately.
>
> A caller that writes `if verify(...) { accept(); }` accepts the forgery.

We observed the **same shape** in two other systems:
- **EphemeralML**: model-identity check defaults to "skip."
- **NEAR AI**: live-channel binding is an opt-in flag (`--verify-tls`).

---

## Gap 3 — Receipts Don't Cover *How* the AI Answered (AI-specific)

### The bug, in one sentence
LLMs are non-deterministic. The same model, same question, with a
different **temperature** setting produces a different answer. The
receipt commits to *"this question came in, these bytes went out"* — but
**not** to the temperature (or other sampling settings) the operator
chose server-side. So the operator picks the answer by tuning a knob the
receipt never names.

### Concrete demo: NEAR AI Cloud (live service)

| Operator picks ... | Model's answer to *"Is this contract safe to sign?"* |
|---|---|
| `temperature = 0` (deterministic) | *"I need to see the actual contract first."* |
| `temperature = 1.5` (high randomness) | *"Yes, this contract looks safe to sign."* |

### What the user sees
> **Both** receipts verify cleanly. The hash of the input matches; the
> hash of the output matches; the signature checks out.
>
> **Nothing in the receipt format names temperature, top-p, seed, or
> any other sampling setting.** The verifier cannot tell which regime
> the operator chose.

This gap is **AI-specific** — it doesn't exist in classic
proof-of-computation work, because classic computations are
deterministic. It only arises when the workload is a non-deterministic
generative model.

---

## Gap 4 — CPU and GPU Don't Prove They Worked Together

### The bug, in one sentence
Modern AI inference runs on **CPU + GPU**. Each piece of hardware
produces its own attestation. **Nothing in the system cryptographically
proves that a particular CPU and a particular GPU worked together** on
this specific request — the operator can mix and match.

### Analogy
Two trusted witnesses (CPU + GPU) each sign their own affidavit. But the
affidavits don't reference each other. The operator can take Witness A's
affidavit from Monday's case and pair it with Witness B's from
Tuesday's. Both are real signatures. The pair is a lie.

### Concrete demo: NEAR AI Cloud
- Each AI request comes with two attestations:
  - one from the **CPU TEE** (Intel TDX)
  - one from the **GPU** (NVIDIA's attestation service for H100 GPUs in
    confidential-compute mode)
- The operator obtains **one** valid GPU attestation for GPU `GA`.
- The operator pairs it with **two different CPU attestations** —
  possibly from machines that don't even have GPU `GA`, or have a
  totally different GPU `GB`.

### What the user sees
> CPU signature ✓ and GPU signature ✓ for **both** pairings. The
> verifier accepts both as legitimate.
>
> **No field in the receipt asks: "is the GPU named in this GPU
> attestation actually the GPU that ran this CPU enclave's request?"**

Each link in the chain is honest. The chain itself is unbound.

---

## Cross-System Recurrence

| Gap | Laminator | NEAR AI Cloud | A3S Power |
|---|---|---|---|
| **1.** Enclave runs attacker code | ✓ **H** (pickle RCE) | — | ✓ M (Jinja template) |
| **2.** Defaults fail open | ✓ M | ✓ M | ✓ **H** |
| **3.** Sampling unattested | n/a (audit-time) | ✓ M | ✓ **H** |
| **4.** CPU↔GPU chain unbound | n/a (no GPU) | ✓ **H** | ✓ **H** |

- Multiple systems, multiple gap categories, multiple severities.
- Where a gap doesn't apply (Laminator has no GPU, no per-inference receipt),
  the cell is honestly **n/a** — not a missed finding.
- **Where the gap applies, we found it.**

This is the structural claim: these are **not isolated bugs**.

---

## Why This Is Promising Research

- **Empirical foundation**: live deployed systems, findings with exact
  file-and-line citations, runnable demos that work against the real
  source code (we never modify the systems themselves).
- **Novel framing**: existing work in this space asks *"can the cloud
  operator see what the user is doing?"* (confidentiality). Our work
  asks *"can the cloud operator lie about what they did?"* (soundness)
  — a much less-studied question.
- **Actionable**: each gap maps to a concrete code-level fix.
- **Timely**: real services are deploying this technology *now*, and
  marketing it as a trust guarantee.

**Suggested target venue**: a systematization-of-knowledge ("SoK") paper
at one of the top security conferences — **S&P 2027**, **USENIX Security
2026**, or **CCS 2026**.

---

## TODOs — How We Get to a Publishable Paper

### Short-term (next 4–6 weeks)

- [ ] **Extend in-depth analysis from 3 to 5 systems** (Tinfoil, EphemeralML
      are next in the queue).
- [ ] **Continue looking for common gap categories** beyond the 4 shown
      today — we suspect there are at least 2–3 more recurring patterns
      hiding in the systems we haven't deeply analyzed yet.
- [ ] Write up each gap as a per-system finding doc with file:line citations.

### Medium-term (next 2 months)

- [ ] Survey additional TEE-AI systems for taxonomy breadth — concrete
      candidates to discuss with you in our next meeting.
- [ ] Build the full cross-system matrix (gap × system × severity)
      as the paper's headline figure.
- [ ] Draft the SoK manuscript.

### Pre-publication

- [ ] **Responsible disclosure** to each affected vendor — 60–90 day
      embargo windows are standard.
- [ ] Coordinate with security contacts at Tinfoil, NEAR AI, EphemeralML.
- [ ] Submit by the venue's deadline.

---

## What I'm Asking For

1. **Approval** to invest the next 2–3 months in this research direction.
2. **Guidance** on venue selection — SoK at S&P vs. USENIX Security vs. CCS.
3. **Advice** on disclosure timing — start now or wait until manuscript draft?
4. Optional: introductions to anyone in your network working on TEE
   attestation, NVIDIA confidential compute, or AI safety / auditing.

---

## Summary

- TEEs promise *"no one can lie about what was computed."*
  In practice, the bridge from hardware measurement to AI-output meaning
  is broken in **recurring, structural ways**.
- We've demonstrated **4 common gaps** across **3 surveyed systems**,
  each with a runnable PoC against the real, unmodified source code.
- We have a clear roadmap to extend this to **5+ systems**, find
  **more recurring patterns**, and produce a **publishable SoK**.

**The question for today: should we keep going?**
