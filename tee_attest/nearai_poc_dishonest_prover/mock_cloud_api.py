#!/usr/bin/env python3
"""
A tiny mock of `cloud-api.near.ai` that exposes just enough of the
attestation + chat surface to drive nearai-cloud-verifier's
`model_verifier.py` and `chat_verifier.py`.

The mock is **not** a TDX implementation. It returns hex-encoded
synthetic bytes in place of real Intel quotes. The point of the mock
is to demonstrate two properties of the real verifier surface:

  1. Nothing in the attestation response identifies the *model
     weights* the inference server is serving. The mock toggles
     between "good" and "evil" backends; the attestation bytes are
     byte-identical except for the nonce slot.

  2. The verifier reads NVIDIA NRAS JWTs without verifying their
     signature. The mock's `nvidia_payload` includes a JWT-shaped
     string whose header and signature are empty.

Endpoints:

  GET  /v1/attestation/report?model=...&nonce=...&include_tls_fingerprint=...
       Returns gateway_attestation + (optionally) model_attestations.
  POST /v1/chat/completions
       Returns a streaming-or-non-streaming chat response based on
       the current backend toggle.
  GET  /admin/swap
       Toggles the backend between "good" and "evil".
  GET  /admin/state
       Returns the current backend name (for the demo's logging).

Run:
    python3 mock_cloud_api.py --port 17172
"""

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import socketserver
import sys
import threading
import urllib.parse


# Module-level mutable state shared across handler instances.
_BACKEND = {"active": "good"}

# A constant Docker compose pretending to host an inference container.
_COMPOSE = {
    "docker_compose_file":
        "version: '3'\n"
        "services:\n"
        "  inference:\n"
        "    image: nearaidev/cloud-api@sha256:" + ("a" * 64) + "\n"
        "    ports: ['8000:8000']\n"
}
_COMPOSE_JSON = json.dumps(_COMPOSE)
_COMPOSE_HASH = hashlib.sha256(_COMPOSE_JSON.encode()).hexdigest()

# Constant signing address (would be derived from a real key in production).
_SIGNING_ADDRESS = "0x" + "ab" * 20

# Constant TLS SPKI fingerprint (the mock fronts no TLS).
_TLS_FP = "cd" * 32


def _build_quote(report_data_hex: str, mr_config_hex: str) -> str:
    """Construct a fake TDX quote string.

    The real model_verifier.py passes these bytes to
    dcap_qvl.get_collateral_and_verify(). The demos run against the
    mock either by skipping that call or by monkey-patching it. The
    bytes here are structured so that the verifier's `check_report_data`
    and `show_compose` code paths can extract the right fields.
    """
    # 256-byte buffer; report_data at the offset model_verifier uses.
    buf = bytearray(b"\x00" * 1024)
    rd = bytes.fromhex(report_data_hex)
    buf[0:len(rd)] = rd
    mc = bytes.fromhex(mr_config_hex)
    # mr_config_id slot — model_verifier.py reads from the parsed
    # `mrconfig` field, which is hex of the slot. We don't try to
    # match TDX's exact layout here; the demo doesn't run dcap_qvl.
    return buf.hex()


def _build_attestation_body(
    nonce_hex: str,
    include_tls: bool,
    signing_address: str,
) -> dict:
    """Construct the JSON body cloud-api returns for /v1/attestation/report."""
    # Layout: report_data[0..32] = padded signing_address OR
    # SHA256(signing_address || tls_fp). [32..64] = nonce.
    addr_bytes = bytes.fromhex(signing_address.removeprefix("0x")).ljust(32, b"\x00")
    nonce_bytes = bytes.fromhex(nonce_hex)
    if include_tls:
        first32 = hashlib.sha256(
            bytes.fromhex(signing_address.removeprefix("0x"))
            + bytes.fromhex(_TLS_FP)
        ).digest()
    else:
        first32 = addr_bytes[:32]
    report_data = (first32 + nonce_bytes[:32]).hex()
    mr_config = "01" + _COMPOSE_HASH  # exactly what show_compose expects

    # A "JWT" with an empty signature. The verifier's
    # base64url_decode_jwt_payload only reads the middle segment.
    payload = {
        "x-nvidia-overall-att-result": "MATCH",
        "x-nvidia-attestation-detailed-result": {"x-nvidia-gpu-arch-check": "MATCH"},
        "nonce": nonce_hex,
    }
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")
    fake_jwt = f"{header_b64}.{payload_b64}."  # empty signature

    nvidia_payload = {
        "nonce": nonce_hex,
        "arch": "HOPPER",
        "evidence_list": ["<synthetic GPU evidence>"],
    }

    gateway = {
        "signing_address": signing_address,
        "signing_algo": "ecdsa",
        "intel_quote": _build_quote(report_data, mr_config),
        "info": {"tcb_info": json.dumps({"app_compose": _COMPOSE_JSON})},
        "nvidia_payload": json.dumps(nvidia_payload),
        "model_attestations_jwt_hint": fake_jwt,  # what the verifier would forward to NRAS
    }
    if include_tls:
        gateway["tls_cert_fingerprint"] = _TLS_FP

    body = {
        "gateway_attestation": gateway,
        "model_attestations": [gateway],  # same content for the demo
    }
    if include_tls:
        body["tls_certificate"] = "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"
    return body


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quiet logs to keep demo output readable.
        sys.stderr.write(f"[mock] {self.address_string()} - {format % args}\n")

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)
        if url.path == "/v1/attestation/report":
            model = params.get("model", [""])[0]
            nonce = params.get("nonce", [""])[0]
            include_tls = (params.get("include_tls_fingerprint", ["false"])[0].lower()
                           in ("1", "true", "yes"))
            signing_address = params.get("signing_address", [_SIGNING_ADDRESS])[0]
            body = _build_attestation_body(nonce, include_tls, signing_address)
            self._json(200, body)
            return
        if url.path == "/admin/swap":
            _BACKEND["active"] = "evil" if _BACKEND["active"] == "good" else "good"
            self._json(200, {"active": _BACKEND["active"]})
            return
        if url.path == "/admin/state":
            self._json(200, {"active": _BACKEND["active"]})
            return
        if url.path == "/v1/signature/" or url.path.startswith("/v1/signature/"):
            # Minimal signature endpoint stub; not used by the model-binding demo.
            chat_id = url.path.rsplit("/", 1)[-1]
            self._json(200, {
                "signing_address": _SIGNING_ADDRESS,
                "text": f"{chat_id}:00aa:00bb",
                "signature": "0x" + "00" * 65,
            })
            return
        self._json(404, {"error": f"unknown path {url.path}"})

    def do_POST(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except Exception:
            req = {}

        if url.path == "/v1/chat/completions":
            active = _BACKEND["active"]
            if active == "good":
                content = (
                    "The capital of France is Paris. This response was produced "
                    "by an honestly-served model."
                )
            else:
                content = (
                    "The capital of France is Berlin. This response was produced "
                    "by an attacker-substituted model."
                )
            chat_id = "chatcmpl-" + secrets.token_hex(8)
            if req.get("stream"):
                # Minimal SSE-shaped reply.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                evt = json.dumps({
                    "id": chat_id, "object": "chat.completion.chunk",
                    "choices": [{"delta": {"content": content},
                                 "finish_reason": "stop"}],
                })
                self.wfile.write(f"data: {evt}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self._json(200, {
                    "id": chat_id,
                    "object": "chat.completion",
                    "model": req.get("model", "unspecified"),
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                })
            return
        self._json(404, {"error": f"unknown path {url.path}"})


class _ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str, port: int) -> None:
    with _ReuseTCPServer((host, port), _Handler) as srv:
        sys.stderr.write(f"[mock] listening on http://{host}:{port}\n")
        srv.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=17172)
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
