#!/usr/bin/env python3
"""
Crypto workload generator.

Repeatedly calls every demo API endpoint so that the eBPF runtime agent
has enough crypto activity to observe during automated testing.

Usage:
    python scripts/generate_crypto_workload.py [--iterations N] [--base-url URL]

Defaults:
    --iterations 10
    --base-url   http://localhost:8080

NOTE: The legacy_crypto scenario (Scenario B — Static Only) is intentionally
excluded from this workload.  It must not be exercised at runtime so that the
comparison between static and runtime detection remains valid.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_ITERATIONS = 10


def post(base_url: str, path: str, body: dict) -> dict:
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def run_one_iteration(base_url: str, iteration: int) -> None:
    print(f"\n── Iteration {iteration} ─────────────────────────────────────────")

    # ── RSA ──────────────────────────────────────────────────────────────
    print("  [RSA] Generating key...")
    post(base_url, "/api/rsa/generate", {})

    print("  [RSA] Encrypting...")
    enc = post(base_url, "/api/rsa/encrypt", {"plaintext": f"workload-iteration-{iteration}"})
    ct = enc.get("result", {}).get("ciphertext", "")

    print("  [RSA] Decrypting...")
    post(base_url, "/api/rsa/decrypt", {"ciphertext": ct})

    print("  [RSA] Signing...")
    signed = post(base_url, "/api/rsa/sign", {"message": f"iteration-{iteration}"})
    sig = signed.get("result", {}).get("signature", "")

    print("  [RSA] Verifying...")
    post(base_url, "/api/rsa/verify", {"message": f"iteration-{iteration}", "signature": sig})

    # ── ECDSA ─────────────────────────────────────────────────────────────
    print("  [ECDSA] Generating key...")
    post(base_url, "/api/ecdsa/generate", {})

    print("  [ECDSA] Signing...")
    esigned = post(base_url, "/api/ecdsa/sign", {"message": f"ecdsa-{iteration}"})
    esig = esigned.get("result", {}).get("signature", "")

    print("  [ECDSA] Verifying...")
    post(base_url, "/api/ecdsa/verify", {"message": f"ecdsa-{iteration}", "signature": esig})

    # ── ECDH ──────────────────────────────────────────────────────────────
    print("  [ECDH] Key exchange...")
    post(base_url, "/api/ecdh/exchange", {})

    # ── DH ────────────────────────────────────────────────────────────────
    print("  [DH] Key exchange...")
    post(base_url, "/api/dh/exchange", {})

    # ── AES ───────────────────────────────────────────────────────────────
    print("  [AES] Encrypting...")
    aenc = post(base_url, "/api/aes/encrypt", {"plaintext": f"aes-workload-{iteration}", "aad": "demo"})
    act  = aenc.get("result", {}).get("ciphertext", "")
    anonce = aenc.get("result", {}).get("nonce", "")

    print("  [AES] Decrypting...")
    post(base_url, "/api/aes/decrypt", {"ciphertext": act, "nonce": anonce, "aad": "demo"})

    # ── Hashing ───────────────────────────────────────────────────────────
    print("  [SHA-256] Hashing...")
    post(base_url, "/api/hash/sha256", {"text": f"sha256-workload-{iteration}"})

    print("  [SHA-512] Hashing...")
    post(base_url, "/api/hash/sha512", {"text": f"sha512-workload-{iteration}"})

    # ── TLS ───────────────────────────────────────────────────────────────
    print("  [TLS] HTTPS request...")
    post(base_url, "/api/tls/request", {"url": ""})

    print(f"  ✓ Iteration {iteration} complete")


def wait_for_app(base_url: str, timeout: int = 30) -> None:
    url = base_url.rstrip("/") + "/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status == 200:
                    print(f"Application is up at {base_url}")
                    return
        except Exception:
            pass
        print(f"  Waiting for application at {base_url} ...")
        time.sleep(2)
    print(f"ERROR: Application did not start within {timeout}s", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="PQC demo crypto workload generator")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help=f"Number of iterations (default: {DEFAULT_ITERATIONS})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"Application base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to pause between iterations (default: 0.5)")
    args = parser.parse_args()

    print(f"PQC Demo Crypto Workload Generator")
    print(f"  Target:     {args.base_url}")
    print(f"  Iterations: {args.iterations}")
    print(f"  Delay:      {args.delay}s")

    wait_for_app(args.base_url)

    errors = 0
    for i in range(1, args.iterations + 1):
        try:
            run_one_iteration(args.base_url, i)
        except Exception as exc:
            print(f"  ERROR in iteration {i}: {exc}", file=sys.stderr)
            errors += 1
        if args.delay > 0 and i < args.iterations:
            time.sleep(args.delay)

    print(f"\n{'─'*60}")
    print(f"Workload complete: {args.iterations - errors}/{args.iterations} iterations succeeded")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
