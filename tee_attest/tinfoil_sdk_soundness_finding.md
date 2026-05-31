# Tinfoil SDK: Soundness Findings

**Subject:** Tinfoil's open-source verifier SDK
(`github.com/tinfoilsh/tinfoil-go` and the Python/JS/Rust mirrors).
This is the client-side library every Tinfoil customer (or third
party verifying a Tinfoil-hosted enclave) is expected to use to
check attestations issued by `inference.tinfoil.sh` and the
`confidential-model-router` family of services.

**Scope:** Soundness of the *verifier-side* library. The library
itself is open source. The infrastructure it talks to
(`github-proxy.tinfoil.sh`, `inference.tinfoil.sh`, Sigstore TUF
repo, the customer-side CVM) is operated by Tinfoil and is not
within scope; we model it as the prover the SDK is verifying.

**Headline:** The Tinfoil SDK is genuinely the best-engineered
verifier surveyed alongside EphemeralML: it uses sigstore-go for
real DSSE verification (with SCT, transparency log, and observer
timestamp checks), it has an explicit `TLSBoundRoundTripper` that
makes TLS-key binding mandatory, and the Sigstore code-measurement
chain is wired correctly through `tinfoil-go/verifier/sigstore/sigstore.go`.
The remaining soundness gap is concentrated in one place: the
SDK routes **every** "what is the current release of repo X?"
query through a single Tinfoil-operated HTTPS host
(`github-proxy.tinfoil.sh`), and that host's responses are not
authenticated against the canonical GitHub Release API. The
Sigstore verification downstream catches *forgery* — the proxy
cannot mint new signatures — but it does not catch *rollback*: the
proxy can hand back any historically-valid (tag, digest, bundle)
triple, including stale releases.

Two additional, lower-severity observations are noted at the end
for completeness.

All findings refer to the repository state at the time of cloning
(`depth=1` snapshot of `tinfoilsh/tinfoil-go`).

A working proof of concept for **Tinfoil-1** lives at
[`tinfoil_poc_dishonest_prover/`](tinfoil_poc_dishonest_prover/).
Running `./run_poc.sh` spawns a mock implementing
`github-proxy.tinfoil.sh`'s URL grammar in two modes and shows the
SDK's resolution logic accepts whichever (tag, digest, bundle) the
proxy decides to return.

---

## Roles

- **Tinfoil (Operator)** — owns and runs the enclaves, the model
  files, the GitHub repos that hold release artefacts, and the
  intermediary `github-proxy.tinfoil.sh`.
- **End User / Verifier** — calls the SDK's `SecureClient` (Go) /
  `TinfoilAI` (Python) / equivalent. Wants to know "is the enclave
  I'm talking to running the code I expect, currently?"
- **Sigstore (third-party trust root)** — signs DSSE bundles
  produced by Tinfoil's GitHub Actions CI. Provides SCT,
  transparency log, and observer timestamp infrastructure.
- **GitHub (third-party host)** — the canonical source of
  Tinfoil's release tags, digests, and Sigstore attestation
  bundles. The SDK does not talk to GitHub directly.

---

## Trust-target overview

Per-Verify chain in `tinfoil-go/verifier/client/client.go:147-232`:

```text
SDK Verify()
├── github.FetchLatestDigest(repo)
│       ├── FetchLatestTag(repo)            ── via github-proxy.tinfoil.sh
│       └── FetchDigest(repo, latestTag)    ── via github-proxy.tinfoil.sh
├── github.FetchAttestationBundle(repo, digest)  ── via github-proxy.tinfoil.sh
├── sigstoreClient.VerifyAttestation(bundle, repo, digest)
│       └── sigstore-go: verify cert chain, SCT, Rekor inclusion, TSA
├── attestation.Fetch(enclave)              ── live HTTPS to inference.*
├── enclaveAttestation.Verify()             ── platform-specific verify
└── TLSBoundRoundTripper{ExpectedPublicKey: ...}
```

The Sigstore-verified `codeMeasurement` must equal
`enclaveVerification.Measurement` (`client.go:207-209`). The TLS
round-tripper pins the live cert's SPKI against the attested
fingerprint on every connection (`roundtrip.go:42-68`). Those
parts are correct and not flagged here.

What we flag is the *upstream* resolution: how the SDK knows
*which* `digest` and *which* `bundle` to verify against. That's
entirely the proxy's choice.

---

## Finding Tinfoil-1 — `github-proxy.tinfoil.sh` is the sole arbiter of "current release"

**Severity:** High. Allows silent rollback to any
historically-valid Tinfoil release.

**Taxonomy class:** **F3** (external evidence parsed without
authentication) — specifically the *currency* sub-flavor: the
evidence is authenticated *at signing time*, but its currency
relative to the verifier's request is not.

**Location:**

- `tinfoil-go/verifier/github/github.go:11`
  — `const githubProxy = "https://github-proxy.tinfoil.sh"`
- `tinfoil-go/verifier/github/github.go:14-30`  (`FetchLatestTag`)
- `tinfoil-go/verifier/github/github.go:33-41`  (`FetchDigest`)
- `tinfoil-go/verifier/github/github.go:44-54`  (`FetchLatestDigest`)
- `tinfoil-go/verifier/github/github.go:57-79`  (`FetchAttestationBundle`)
- `tinfoil-go/verifier/util/fetch_other.go:9-23` (`util.Get` — plain
  `http.Get`, no out-of-band verification)

**Mechanism.** Every call chain that asks "which release am I
checking against?" passes through `github-proxy.tinfoil.sh`:

```go
// github.go:14-30
func FetchLatestTag(repo string) (string, error) {
    url := githubProxy + "/repos/" + repo + "/releases/latest"
    releaseResponse, _, err := util.Get(url)
    ...
    var responseJSON struct {
        TagName string `json:"tag_name"`
        Body    string `json:"body"`
    }
    if err := json.Unmarshal(releaseResponse, &responseJSON); err != nil {
        return "", err
    }
    return responseJSON.TagName, nil
}
```

The proxy's HTTPS response is TLS-authenticated as
"a server holding the cert for `github-proxy.tinfoil.sh`" — and
that server is Tinfoil-operated. The response body itself is not
signed against an independent trust root. The SDK trusts the
proxy to return the same `tag_name` and `digest` that
`api.github.com/repos/<repo>/releases/latest` would return at the
same moment.

Downstream, `sigstoreClient.VerifyAttestation(bundle, repo,
digest)` does verify the bundle's signature against the Sigstore
TUF root, with SCT, transparency log, and observer timestamps
(`sigstore.go:74-79`). So the proxy cannot mint *new* signatures
without being a sigstore CI identity. But the proxy *can* return
any (tag, digest, bundle) triple that Tinfoil's CI has signed at
any point in the past — including stale releases.

**Attack.** Operator (= Tinfoil, or anyone who compromises the
proxy) wants the verifier to pin to release `v0.3.0` (which is
still a Tinfoil-signed release but happens to contain a known
soundness gap or bypass the operator wants to exploit). The
proxy:

1. On `GET /repos/<repo>/releases/latest`, returns
   `{"tag_name": "v0.3.0", ...}` instead of the actual latest tag.
2. On `GET /<repo>/releases/download/v0.3.0/tinfoil.hash`, returns
   the digest for v0.3.0 (which exists and is a real release).
3. On `GET /repos/<repo>/attestations/sha256:<v0.3.0 digest>`,
   returns the legitimate Sigstore bundle for that digest.

The verifier's chain:
- `FetchLatestDigest` returns `(v0.3.0, <digest>)`.
- `FetchAttestationBundle(repo, digest)` returns the real bundle.
- `sigstoreClient.VerifyAttestation(bundle, repo, digest)` passes
  — the bundle was honestly signed by Tinfoil's CI at the time
  v0.3.0 was released.
- The verifier extracts `codeMeasurement` and proceeds to compare
  it against the live enclave's measurement.

If the operator additionally runs an enclave instance whose
measurement matches v0.3.0, the verifier accepts it as the current
service.

**Status.** PoC at
[`tinfoil_poc_dishonest_prover/`](tinfoil_poc_dishonest_prover/)
spawns a mock that implements `github-proxy.tinfoil.sh`'s URL
grammar and shows the SDK's resolution logic accepting whatever
the proxy returns. Local-only; no Tinfoil infrastructure is
touched.

**Mitigation.**

- Have the SDK fetch tag+digest from a *separate* trust root than
  the proxy. Two-of-two: require agreement between the proxy and
  (e.g.) `api.github.com` or `npm`/`crates.io` for the same
  package.
- Reject Sigstore bundles whose observer timestamp is older than
  a freshness threshold. This requires the proxy to serve recent
  bundles, which the SDK can re-sign or have Tinfoil's CI
  re-attest at scheduled intervals.
- Add `min_tag`, `min_digest` policy fields callers can set to
  enforce a floor.
- Pin (repo, tag, digest) tuples via a separate signed manifest
  the caller obtains out of band.

---

## Finding Tinfoil-2 — Certificate identity regex permits any workflow file

**Severity:** Low / supply-chain framing. Not directly exploitable
without write access to the Tinfoil repo.

**Taxonomy class:** F1-flavored (the regex is a *config* the SDK
embeds; if Tinfoil ever ships a workflow change that produces a
broader SAN match, the SDK widens its trust silently).

**Location:** `tinfoil-go/verifier/sigstore/sigstore.go:84-93`

```go
certID, err := verify.NewShortCertificateIdentity(
    oidcIssuer,
    "",
    "",
    // TODO: Can we pin this to latest without fetching the latest release?
    "^https://github.com/"+repo+"/.github/workflows/.*@refs/tags/*",
)
```

The pattern allows:
- any workflow file (`.github/workflows/.*`),
- any tag ref (`@refs/tags/*` — `*` is regex quantifier on the
  trailing `/`).

The `.` in `.github` is a regex wildcard, not a literal dot —
matches `Xgithub` too, though `^https://github.com/` constrains
the prefix.

**Risk.** If a repo collaborator (or an attacker who compromises
a Tinfoil GitHub Actions secret) adds a malicious workflow file
that produces a DSSE bundle pointing at a different
`codeMeasurement`, the SDK would accept it because the SAN regex
matches any workflow in the repo. Standard supply-chain concern;
the TODO comment in the source acknowledges the tension between
tightness and operability.

**Mitigation.** Pin the SAN regex to a specific workflow file
(e.g., `release.yml`), and the tag-ref portion to a specific
naming convention (e.g., `@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$`).

---

## Finding Tinfoil-3 — `LatestHardwareMeasurements` is operator-pinned

**Severity:** Acknowledged-by-design.

**Taxonomy class:** F1 (which "trusted hardware measurements" are
expected is operator-configured) + F3-currency (the
`tinfoilsh/hardware-measurements` repo's "latest" is resolved via
the same proxy).

**Location:** `tinfoil-go/verifier/sigstore/sigstore.go:236-244`

```go
func (c *Client) LatestHardwareMeasurements() ([]*attestation.HardwareMeasurement, error) {
    const repo = "tinfoilsh/hardware-measurements"
    digest, err := github.FetchLatestDigest(repo)
    ...
    return c.FetchHardwareMeasurements(repo, digest)
}
```

The expected MRTD + RTMR0 set for TDX hardware verification is
fetched from a Tinfoil-controlled repo via the same proxy as
Tinfoil-1. Two consequences:

1. **Tinfoil chooses which hardware platforms count as "good."**
   This is reasonable — they have visibility into Intel TCB
   advisories — but it means the trust root for TDX hardware
   identity is operationally Tinfoil, not Intel.
2. **The Tinfoil-1 rollback attack also rolls back hardware
   measurements.** If `tinfoilsh/hardware-measurements` ever
   shipped a measurement set that included a since-revoked TCB
   level, the proxy can roll the SDK back to accept it.

**Mitigation.** Same as Tinfoil-1, applied to the
`hardware-measurements` repo. Alternatively, fetch the canonical
list directly from Intel PCS in addition to (or instead of) the
proxy.

---

## What the Tinfoil SDK does well

- **Real Sigstore verification.** `VerifyBundle` uses
  `sigstore-go/pkg/verify`'s `NewSignedEntityVerifier` with `SCT(1)`,
  `TransparencyLog(1)`, and `ObserverTimestamps(1)` — i.e., the
  Sigstore consensus checks are all on
  (`sigstore.go:74-79`).
- **Mandatory TLS-key binding** via `TLSBoundRoundTripper`. Every
  request through `secureClient.HTTPClient()` is pinned to the
  attested SPKI before the first byte of HTTP body is sent
  (`roundtrip.go:42-68`). Re-verification on cert-rotation errors
  via `tinfoil_client.go:reVerifyingTransport`. This is the
  reference-quality F6 fix.
- **Embedded trusted root** as a fallback when the TUF fetch
  fails (`client.go:22-23` and `:403-419`). The fallback is
  conservative — it uses the most-recently-vetted root rather
  than refusing to verify.
- **Cert chain re-verification on every request.** Unlike many
  SDKs that pin the cert once and trust the keep-alive, Tinfoil's
  `reVerifyingTransport` triggers a fresh Verify() on certificate
  errors (`tinfoil_client.go:25-66`).
- **`measurement.Equals` is `slices.Equal` over register strings**
  (`attestation.go:182-191`) — no string normalization, no
  fall-through, fails closed on type mismatch.

---

## Summary table

| # | Title | Severity | Class | One-line fix |
|---|---|---|---|---|
| Tinfoil-1 | github-proxy is sole arbiter of "current" | High | F3 (currency) | Two-source resolution; freshness floor; signed (tag, digest) manifest |
| Tinfoil-2 | SAN regex too permissive | Low | F1-flavored | Pin to specific workflow file + version regex |
| Tinfoil-3 | Hardware measurements pinned via same proxy | Acknowledged | F1 + F3 | Same as Tinfoil-1, or fetch Intel PCS directly |

## Suggested headline framing

> *Tinfoil's verifier SDK is one of two best-engineered in the
> survey (the other being EphemeralML). The Sigstore-side
> verification is correct, the TLS-key binding is mandatory, and
> the trust chain from hardware attestation through code
> measurement to live channel is wired correctly. The remaining
> soundness gap is at the entry point: every "which release is
> current?" query flows through a single Tinfoil-operated HTTPS
> intermediary whose responses are not authenticated against a
> second trust root. The Sigstore verification downstream catches
> forgery but not rollback. A malicious or compromised proxy can
> silently pin verifiers to any historically-signed Tinfoil
> release.*

## Responsible disclosure

`tinfoilsh/tinfoil-go` is in active use by Tinfoil customers as
the canonical verifier. Before publishing this finding alongside
a paper, coordinate disclosure with Tinfoil and give the standard
60–90-day fix window.
