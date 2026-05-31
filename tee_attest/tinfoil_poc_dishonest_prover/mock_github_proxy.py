#!/usr/bin/env python3
"""
Mock of `github-proxy.tinfoil.sh` — the single HTTPS intermediary
that every `tinfoil-go` SDK call passes through when resolving
"what is the current release of this Tinfoil-owned repo?"

The real proxy is operated by Tinfoil. The SDK has the URL hard-coded
in `verifier/github/github.go:11` (`githubProxy = "https://github-proxy.tinfoil.sh"`)
and uses `util.Get()` (`verifier/util/fetch_other.go:9-23`), which is
just `http.Get` with no out-of-band content authentication. The
proxy can therefore choose:

  - which tag of a repo is "latest"      (FetchLatestTag)
  - which digest is the "current" release (FetchDigest)
  - which Sigstore bundle to return       (FetchAttestationBundle)

The bundle itself is Sigstore-verified downstream, so the proxy
cannot mint *new* signatures. But it can return any
*historically-valid* (digest, bundle) pair, including stale
releases the operator wants the verifier to pin to.

This mock implements the three endpoints with two switchable modes:

  * `mode=current`  — returns the (fake) "current" release of a repo
  * `mode=rolled-back` — returns an older release for the same repo

Tinfoil's source tree is not modified; the mock just speaks the
same URL grammar the SDK's `github.go` builds, against the same
JSON shape `github.go` decodes.
"""

import argparse
import json
import os
import socketserver
import sys
import threading
import urllib.parse
import http.server


_STATE = {"mode": "current"}

# (tag, digest, bundle_blob) per repo per mode.
_RELEASES = {
    "tinfoilsh/confidential-model-router": {
        "current":     ("v0.5.2", "1234abcd" * 8,
                        b'{"_note":"current-release-bundle-bytes"}'),
        "rolled-back": ("v0.3.0", "9999dead" * 8,
                        b'{"_note":"older-release-bundle-bytes-(simulated)"}'),
    },
    "tinfoilsh/hardware-measurements": {
        "current":     ("hw1",     "aaaaeeee" * 8,
                        b'{"_note":"current-hardware-bundle"}'),
        "rolled-back": ("hw1-old", "1111bbbb" * 8,
                        b'{"_note":"older-hardware-bundle"}'),
    },
}


def _release_for(repo: str) -> tuple[str, str, bytes]:
    mode = _STATE["mode"]
    if repo not in _RELEASES:
        return ("missing", "0" * 64, b"")
    return _RELEASES[repo][mode]


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"[proxy] {format % args}\n")

    def _serve(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        parts = url.path.strip("/").split("/")

        # /repos/<org>/<repo>/releases/latest        -> FetchLatestTag
        if (
            len(parts) == 5
            and parts[0] == "repos"
            and parts[3] == "releases"
            and parts[4] == "latest"
        ):
            repo = f"{parts[1]}/{parts[2]}"
            tag, _, _ = _release_for(repo)
            self._serve(200, json.dumps({
                "tag_name": tag,
                "body":     f"Release {tag} of {repo} (proxy mode={_STATE['mode']})",
            }).encode())
            return

        # /<org>/<repo>/releases/download/<tag>/tinfoil.hash  -> FetchDigest
        if (
            len(parts) == 6
            and parts[2] == "releases"
            and parts[3] == "download"
            and parts[5] == "tinfoil.hash"
        ):
            repo = f"{parts[0]}/{parts[1]}"
            tag = parts[4]
            tag_now, digest_now, _ = _release_for(repo)
            if tag == tag_now:
                # honest match between requested tag and current-mode digest
                body = digest_now.encode() + b"\n"
            else:
                body = digest_now.encode() + b"\n"  # proxy serves whatever it likes
            self._serve(200, body, "text/plain")
            return

        # /repos/<org>/<repo>/attestations/sha256:<digest> -> FetchAttestationBundle
        if (
            len(parts) == 5
            and parts[0] == "repos"
            and parts[3] == "attestations"
            and parts[4].startswith("sha256:")
        ):
            repo = f"{parts[1]}/{parts[2]}"
            _, _, bundle_blob = _release_for(repo)
            self._serve(200, json.dumps({
                "attestations": [{"bundle": json.loads(bundle_blob.decode())}]
            }).encode())
            return

        # /admin/mode?set=<mode>
        if url.path == "/admin/mode":
            params = urllib.parse.parse_qs(url.query)
            new_mode = params.get("set", [None])[0]
            if new_mode in {"current", "rolled-back"}:
                _STATE["mode"] = new_mode
                self._serve(200, json.dumps({"mode": _STATE["mode"]}).encode())
            else:
                self._serve(400, json.dumps({"error": "bad mode"}).encode())
            return

        if url.path == "/admin/state":
            self._serve(200, json.dumps({"mode": _STATE["mode"]}).encode())
            return

        self._serve(404, json.dumps({"error": f"unknown path {url.path}"}).encode())


class _ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str, port: int) -> None:
    with _ReuseTCPServer((host, port), _Handler) as srv:
        sys.stderr.write(f"[proxy] listening on http://{host}:{port}\n")
        srv.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19500)
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
