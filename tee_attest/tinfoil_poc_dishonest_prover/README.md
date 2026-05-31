# Tinfoil SDK Dishonest-Prover PoC

Standalone proof of concept for **Finding Tinfoil-1** from
`../tinfoil_sdk_soundness_finding.md` (the
`github-proxy.tinfoil.sh` intermediary can roll the verifier back
to any historically-valid Tinfoil release).

The Tinfoil source tree under `../tinfoil/` is **not** modified.
The PoC implements the proxy's URL grammar in Python and ports the
SDK's resolution logic faithfully from
`verifier/github/github.go`.

## Threat model

- The "prover" is Tinfoil itself (or anyone who has compromised
  the `github-proxy.tinfoil.sh` host). The proxy mediates every
  GitHub Release API call the SDK makes.
- The verifier is the end user running `tinfoil-go`'s
  `SecureClient` (or its Python/JS/Rust mirror).
- Sigstore TUF, the embedded trust root, and the downstream
  bundle signature verification are all trusted and operating
  correctly. The PoC does not break any cryptographic
  primitive.

**Goal:** show that the SDK's resolution of "current release of
repo X" is dictated entirely by what the proxy returns, and that
the proxy can switch between historically-valid releases without
the SDK noticing.

## How the gap works

`tinfoil-go/verifier/github/github.go:11` declares:

```go
const githubProxy = "https://github-proxy.tinfoil.sh"
```

Every release-resolution call in the SDK hits this hostname:

- `FetchLatestTag(repo)` (`github.go:14-30`) — JSON, single
  string field, no signature.
- `FetchDigest(repo, tag)` (`github.go:33-41`) — plain text, no
  signature.
- `FetchAttestationBundle(repo, digest)` (`github.go:57-79`) —
  JSON; the bundle inside *is* Sigstore-signed (verified
  downstream).

`util.Get` (`verifier/util/fetch_other.go:9-23`) is just
`http.Get` plus an HTTP-status check. TLS validates the proxy
hostname; nothing validates the response body's content against
GitHub's canonical Release API.

Downstream, `sigstoreClient.VerifyAttestation` checks the
Sigstore bundle properly (cert chain, SCT, transparency log,
observer timestamp). What it cannot tell is whether the bundle
the proxy chose is the *current* bundle or a historical one.

## Files

| File | Purpose |
|---|---|
| `mock_github_proxy.py` | Stdlib HTTP server that implements the same URL grammar as `github-proxy.tinfoil.sh` for the endpoints `github.go` consumes. Two switchable modes: `current` and `rolled-back`. |
| `demo_proxy_rollback.py` | Faithful Python ports of `FetchLatestTag`, `FetchDigest`, `FetchLatestDigest`, and `FetchAttestationBundle` from `tinfoil-go/verifier/github/github.go`. Spawns the mock, resolves `tinfoilsh/confidential-model-router` against it in both modes, and shows the SDK's resolution logic happily accepts whichever (tag, digest, bundle) the proxy returned. |
| `run_poc.sh` | Convenience driver. |

## How to run

```bash
cd tinfoil_poc_dishonest_prover
./run_poc.sh
```

If you hit a shell-quirk SIGURG (exit 144) when piping through
backgrounded subprocesses, run the demo directly:

```bash
timeout 30 python3 demo_proxy_rollback.py
```

## Expected output

```text
Stage 1 — proxy in `current` mode
    SDK resolves repo=tinfoilsh/confidential-model-router to:
        latest tag    = v0.5.2
        latest digest = 1234abcd...
        bundle        = {'_note': 'current-release-bundle-bytes'}

Stage 2 — proxy operator flips to `rolled-back` mode
    Same SDK call against the same proxy host now returns:
        latest tag    = v0.3.0   (was v0.5.2)
        latest digest = 9999dead...
        bundle        = {'_note': 'older-release-bundle-bytes-(simulated)'}

What the verifier sees as 'current'
    digest changed between calls: True
    tag changed between calls:    True
    bundle changed:               True

[+] ATTACK CONFIRMED (F3 — rollback variant)
```

## Caveats

- The bundle bodies are placeholders. A faithful end-to-end demo
  would have to construct two distinct valid Sigstore bundles
  (one for the current release, one for an older release) and
  call `sigstoreClient.VerifyAttestation` against each. This
  requires real Sigstore signing identities and historical
  bundles, which are Tinfoil-internal. The structural claim — that
  the SDK's logic accepts whatever (tag, digest, bundle) the
  proxy returns, with the downstream Sigstore verification
  succeeding so long as Tinfoil's CI ever signed *some* bundle
  matching the digest — does not require us to mint real
  signatures.
- The exit-144 / SIGURG behaviour observed when running the demo
  through certain shell pipe configurations is a runner-side
  artifact, not a PoC failure. The demo's `[+] ATTACK CONFIRMED`
  line appears in stdout regardless.

## Mitigations

- Resolve `(tag, digest)` from a *second* trust root in addition
  to the proxy. Require agreement.
- Reject Sigstore bundles whose `observer_timestamp` is older
  than a configurable freshness window.
- Expose `min_tag` / `min_digest` policy fields the caller can
  pin against a known floor.
- Pin `(repo, tag, digest)` tuples via a separately-signed
  manifest the caller obtains out of band.

## Responsible disclosure

`tinfoilsh/tinfoil-go` is in active use by Tinfoil customers.
Before publishing this finding alongside a paper, coordinate
disclosure with Tinfoil and give the standard 60–90-day fix
window.
