#!/usr/bin/env python3
"""
Demonstrate that the nearai-cloud-verifier attestation surface has no
field that identifies the model weights. Toggle the mock server's
backend between "good" and "evil" and show that every field a
verifier sees (other than the nonce, which by design varies) is
byte-identical across the swap.

Reference: see "5. nearai-cloud-verifier" in
../model_switching.md and Finding N-1 in
../nearai_cloud_verifier_soundness_finding.md.
"""

import argparse
import json
import secrets
import subprocess
import sys
import time
import urllib.request


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post_chat(base: str) -> str:
    body = json.dumps({
        "model": "deepseek-ai/DeepSeek-V3.1",
        "messages": [{"role": "user", "content": "What is the capital of France?"}],
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{base}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer fake"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read())
    return payload["choices"][0]["message"]["content"]


def _attestation_field_diff(a: dict, b: dict) -> list[str]:
    """Walk two attestation bundles and return paths that differ."""
    diffs: list[str] = []

    def walk(prefix, x, y):
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y)):
                walk(f"{prefix}.{k}" if prefix else k, x.get(k), y.get(k))
        elif isinstance(x, list) and isinstance(y, list):
            n = max(len(x), len(y))
            for i in range(n):
                walk(f"{prefix}[{i}]", x[i] if i < len(x) else None,
                     y[i] if i < len(y) else None)
        elif x != y:
            diffs.append(prefix)

    walk("", a, b)
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=17172)
    args = parser.parse_args()

    # Start the mock as a subprocess.
    proc = subprocess.Popen(
        [sys.executable, "mock_cloud_api.py", "--port", str(args.port)],
        cwd=".",
    )
    base = f"http://127.0.0.1:{args.port}"
    try:
        # Wait for the mock to listen.
        for _ in range(50):
            try:
                _get_json(f"{base}/admin/state")
                break
            except Exception:
                time.sleep(0.05)
        else:
            print("error: mock did not start", file=sys.stderr)
            return 1

        nonce1 = secrets.token_hex(32)
        nonce2 = secrets.token_hex(32)

        print("=" * 72)
        print("Stage 1 — backend toggled to 'good'")
        print("=" * 72)
        assert _get_json(f"{base}/admin/state")["active"] == "good"
        attestation_good = _get_json(
            f"{base}/v1/attestation/report?model=deepseek-ai/DeepSeek-V3.1"
            f"&nonce={nonce1}&signing_algo=ecdsa"
        )
        chat_good = _post_chat(base)
        print(f"    nonce sent:        {nonce1}")
        print(f"    chat response:     {chat_good}")
        print(f"    signing_address:   {attestation_good['gateway_attestation']['signing_address']}")
        print(f"    intel_quote[:64]:  {attestation_good['gateway_attestation']['intel_quote'][:64]}...")
        print()

        print("=" * 72)
        print("Stage 2 — operator runs /admin/swap")
        print("=" * 72)
        swap = _get_json(f"{base}/admin/swap")
        print(f"    backend now: {swap['active']}")
        print()

        print("=" * 72)
        print("Stage 3 — backend toggled to 'evil'")
        print("=" * 72)
        assert _get_json(f"{base}/admin/state")["active"] == "evil"
        attestation_evil = _get_json(
            f"{base}/v1/attestation/report?model=deepseek-ai/DeepSeek-V3.1"
            f"&nonce={nonce2}&signing_algo=ecdsa"
        )
        chat_evil = _post_chat(base)
        print(f"    nonce sent:        {nonce2}")
        print(f"    chat response:     {chat_evil}")
        print(f"    signing_address:   {attestation_evil['gateway_attestation']['signing_address']}")
        print(f"    intel_quote[:64]:  {attestation_evil['gateway_attestation']['intel_quote'][:64]}...")
        print()

        print("=" * 72)
        print("Stage 4 — field-by-field diff between the two attestations")
        print("=" * 72)
        diffs = _attestation_field_diff(attestation_good, attestation_evil)
        # Fields that legitimately carry nonce bytes:
        #   - intel_quote: report_data[32..64] = nonce
        #   - nvidia_payload: contains the GPU-evidence nonce
        #   - model_attestations_jwt_hint: NRAS-style JWT echoes the nonce
        nonce_explained = [
            d for d in diffs
            if d in {
                "gateway_attestation.intel_quote",
                "gateway_attestation.nvidia_payload",
                "gateway_attestation.model_attestations_jwt_hint",
                "model_attestations[0].intel_quote",
                "model_attestations[0].nvidia_payload",
                "model_attestations[0].model_attestations_jwt_hint",
            }
        ]
        unexplained = [d for d in diffs if d not in nonce_explained]

        print(f"    Total fields differing: {len(diffs)}")
        print(f"    Differences explained by the changed nonce alone: "
              f"{len(nonce_explained)}")
        print("    nonce-explained diffs:")
        for path in nonce_explained:
            print(f"        - {path}")
        if unexplained:
            print(f"    !! UNEXPLAINED diffs (would identify the model):")
            for path in unexplained:
                print(f"        - {path}")
        else:
            print("    Unexplained diffs: NONE")
        print()

        print("=" * 72)
        print("Result")
        print("=" * 72)
        print(f"    chat response BEFORE swap: {chat_good!r}")
        print(f"    chat response AFTER  swap: {chat_evil!r}")
        print()
        if chat_good != chat_evil and not unexplained:
            print("[+] ATTACK CONFIRMED")
            print("    The model the operator chose to serve produced different")
            print("    output. Yet every attestation field — signing_address,")
            print("    mr_config_id (via intel_quote), app_compose, tls_cert_fingerprint,")
            print("    nvidia_payload's verdict — is unchanged across the swap.")
            print("    No field of the attestation chain identifies the model")
            print("    weights, so the verifier cannot distinguish the two states.")
            return 0
        if chat_good == chat_evil:
            print("[!] mock did not actually swap behaviour")
            return 2
        print("[!] unexplained diffs found; mock leaks model state into attestation")
        return 2
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
