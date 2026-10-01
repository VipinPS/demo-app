# Crypto Demo Application

A containerised realistic cryptographic workload designed as a **target application** for PQC (Post-Quantum Cryptography) scanner demonstrations.

This application is **not** a scanner.  
Its purpose is to be **scanned and monitored** by the separate `pqc-scanner` project.

```
demo-app source code
        │
        ├──── Static scan ────► pqc-scanner  (detects crypto in source)
        │
        ▼
   Running container
        │
        └──── Runtime ────────► eBPF agent   (detects crypto at runtime)
```

---

## Contents

- [Build](#build)
- [Run](#run)
- [Web UI](#web-ui)
- [Generate Crypto Activity](#generate-crypto-activity)
- [Expected Scanner Coverage](#expected-scanner-coverage)
- [Detection Scenarios](#detection-scenarios)
- [Source Layout](#source-layout)
- [Tests](#tests)

---

## Build

```bash
docker build -t pqc-demo-app .
```

Or with Podman:

```bash
podman build -t pqc-demo-app .
```

---

## Run

```bash
docker run --rm -p 8080:8080 pqc-demo-app
```

Or with Compose:

```bash
docker compose up --build
```

The application is available at **<http://localhost:8080>**.

---

## Web UI

Open `http://localhost:8080` in a browser.

The dashboard contains one card per cryptographic operation:

| Card | Buttons | Notes |
|---|---|---|
| **RSA Operations** | Generate RSA Key · Encrypt · Decrypt · Sign · Verify | RSA-2048, OAEP/SHA-256 encryption, PSS/SHA-256 signatures |
| **ECDSA** | Generate Key · Sign · Verify | P-256 (secp256r1), ECDSA/SHA-256 |
| **ECDH** | Perform Key Exchange | P-256, HKDF-SHA-256 key derivation |
| **Diffie–Hellman** | Perform DH Key Exchange | RFC 3526 MODP-2048 group |
| **AES** | AES Encrypt · AES Decrypt | AES-256-GCM authenticated encryption |
| **Hashing** | SHA-256 · SHA-512 | Cryptography library via OpenSSL |
| **TLS / HTTPS Client** | Make HTTPS Request | Scenario C: TLS through dependency |

For RSA and ECDSA, the UI preserves the ciphertext/signature from the most
recent Encrypt/Sign operation so that Decrypt/Verify work immediately.

---

## Generate Crypto Activity

### Python script (cross-platform)

```bash
python scripts/generate_crypto_workload.py
```

Options:

```
--iterations N     Number of full crypto cycles (default: 10)
--base-url URL     Application base URL (default: http://localhost:8080)
--delay D          Pause between iterations in seconds (default: 0.5)
```

Example — 20 iterations:

```bash
python scripts/generate_crypto_workload.py --iterations 20
```

### Shell wrapper

```bash
./scripts/generate-workload.sh --iterations 20
```

### What the workload executes (per iteration)

1. RSA key generation
2. RSA encrypt
3. RSA decrypt
4. RSA sign
5. RSA verify
6. ECDSA key generation
7. ECDSA sign
8. ECDSA verify
9. ECDH key exchange
10. DH key exchange
11. AES-256-GCM encrypt
12. AES-256-GCM decrypt
13. SHA-256 hash
14. SHA-512 hash
15. HTTPS request (TLS through dependency)

> **Note:** `legacy_crypto.py` (Scenario B) is intentionally excluded from the
> workload so that the static-only scenario remains demonstrable.

---

## Expected Scanner Coverage

| Demo operation | Static scan | Runtime (eBPF) | Scenario |
|---|---|---|---|
| RSA-2048 key generation | ✅ Yes | ✅ Yes | A |
| RSA encryption (OAEP) | ✅ Yes | ✅ Yes | A |
| RSA decryption | ✅ Yes | ✅ Yes | A |
| RSA signing (PSS) | ✅ Yes | ✅ Yes | A |
| RSA signature verification | ✅ Yes | ✅ Yes | A |
| ECDSA key generation (P-256) | ✅ Yes | ✅ Yes | A |
| ECDSA sign / verify | ✅ Yes | ✅ Yes | A |
| ECDH key exchange | ✅ Yes | ✅ Yes | A |
| DH key exchange (MODP-2048) | ✅ Yes | ✅ Yes | A |
| AES-256-GCM encrypt / decrypt | ✅ Yes | ✅ Yes | A |
| SHA-256 | ✅ Yes | ✅ Yes | A |
| SHA-512 | ✅ Yes | ✅ Yes | A |
| Legacy RSA-1024 (`legacy_crypto.py`) | ✅ Yes | ❌ Normally No | B |
| Legacy RSA PKCS#1v15 (`legacy_crypto.py`) | ✅ Yes | ❌ Normally No | B |
| Legacy DH small group (`legacy_crypto.py`) | ✅ Yes | ❌ Normally No | B |
| Legacy AES-128-CBC (`legacy_crypto.py`) | ✅ Yes | ❌ Normally No | B |
| TLS through dependency (`https_client.py`) | ⚠️ Limited | ✅ Yes | C |

---

## Detection Scenarios

### Scenario A — Static + Dynamic

Crypto operations in `app/crypto/` are explicit in source code **and** are
exercised at runtime by the UI or workload generator.  
Both a static scanner and an eBPF agent should detect these.

### Scenario B — Static Only

`app/crypto/legacy_crypto.py` contains valid cryptographic code that is
**never imported or called** from the main application.  
A static scanner will discover:
- RSA-1024 key generation
- RSA PKCS#1 v1.5 encryption
- DH with a non-standard small group
- AES-128-CBC (unauthenticated)

An eBPF agent monitoring a normal demo run will **not** see these paths
executed, which is the point of the demonstration.

### Scenario C — Runtime Through Dependency

`app/tls/https_client.py` performs an HTTPS GET using Python's `ssl` module
backed by OpenSSL.  The source contains **no explicit RSA/ECDSA/AES calls** —
yet at runtime the TLS handshake causes libssl/libcrypto to perform a full
set of asymmetric and symmetric crypto operations.  
An eBPF agent will observe rich crypto activity while the static scanner
sees only `urllib.request.urlopen(...)`.

---

## Source Layout

```
demo-app/
├── app/
│   ├── main.py                    # Flask application & routes
│   ├── __init__.py
│   ├── crypto/
│   │   ├── rsa_operations.py      # RSA-2048 (Scenario A)
│   │   ├── ecdsa_operations.py    # ECDSA P-256 (Scenario A)
│   │   ├── ecdh_operations.py     # ECDH P-256 (Scenario A)
│   │   ├── dh_operations.py       # DH MODP-2048 (Scenario A)
│   │   ├── aes_operations.py      # AES-256-GCM (Scenario A)
│   │   ├── hash_operations.py     # SHA-256 / SHA-512 (Scenario A)
│   │   └── legacy_crypto.py       # Legacy paths (Scenario B — static only)
│   ├── tls/
│   │   └── https_client.py        # TLS client (Scenario C — runtime)
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── style.css
│       └── app.js
├── tests/
│   └── test_crypto.py
├── scripts/
│   ├── generate_crypto_workload.py
│   └── generate-workload.sh
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Tests

Install dependencies:

```bash
pip install -r requirements.txt
pip install pytest
```

Run:

```bash
pytest tests/ -v
```

Tests cover:
- RSA encrypt → decrypt round-trip
- RSA sign → verify round-trip
- ECDSA sign → verify round-trip
- ECDH: both sides derive the same secret
- DH: both sides derive the same secret
- AES-256-GCM encrypt → decrypt round-trip
- SHA-256 known-vector digest
- SHA-512 known-vector digest
- Flask API integration tests for all endpoints

---

## eBPF Considerations

- The `cryptography` Python package is built against the system OpenSSL
  (`libcrypto.so`, `libssl.so`), so all cryptographic primitives are executed
  through the native library.
- The application logs each high-level operation with a `[DEMO]` prefix so
  that demo actions can be correlated with external scanner/eBPF observations.
- The application PID is logged on first request for eBPF process targeting.
- No static linking of crypto libraries occurs.

---

## Important Boundaries

This repository contains **only** the target demo application.  
It does **not** implement:

- PQC scanning or vulnerability detection
- Static AST analysis
- eBPF agents or probes
- Scanner dashboards

Those components belong to the separate `pqc-scanner` project.
