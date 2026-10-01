"""
Crypto Demo Application — main entry point.

This application is a realistic target workload for PQC scanner demonstrations.
It intentionally exposes multiple cryptographic patterns so that both a static
source-code scanner and a runtime eBPF agent can observe meaningful crypto activity.

It does NOT implement any scanner, eBPF agent, or vulnerability detector.
"""

import logging
import os
import sys

from flask import Flask, jsonify, render_template, request

# Crypto modules — Scenario A (Static + Dynamic)
from app.crypto.aes_operations import aes_decrypt, aes_encrypt
from app.crypto.dh_operations import perform_dh
from app.crypto.ecdh_operations import perform_ecdh
from app.crypto.ecdsa_operations import ecdsa_sign, ecdsa_verify, generate_ecdsa_key
from app.crypto.hash_operations import sha256_hash, sha512_hash
from app.crypto.rsa_operations import (
    generate_rsa_key,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
)

# TLS module — Scenario C (Runtime Through Dependency)
from app.tls.https_client import make_https_request

# NOTE: app.crypto.legacy_crypto is NOT imported here — Scenario B (Static Only).
# The module exists in the repository for static scanning purposes but is never
# called from normal application flow.

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")


@app.before_request
def _log_pid_once():
    """Log the process PID on the very first request for eBPF correlation."""
    if not getattr(app, "_pid_logged", False):
        logger.info("[DEMO] Application PID: %d", os.getpid())
        app._pid_logged = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# UI route
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok", "pid": os.getpid()})


# ---------------------------------------------------------------------------
# RSA routes
# ---------------------------------------------------------------------------

@app.route("/api/rsa/generate", methods=["POST"])
def api_rsa_generate():
    try:
        result = generate_rsa_key()
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("RSA key generation failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/rsa/encrypt", methods=["POST"])
def api_rsa_encrypt():
    data = request.get_json(silent=True) or {}
    plaintext = data.get("plaintext", "")
    if not plaintext:
        return jsonify({"ok": False, "error": "plaintext is required"}), 400
    try:
        result = rsa_encrypt(plaintext)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("RSA encryption failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/rsa/decrypt", methods=["POST"])
def api_rsa_decrypt():
    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext", "")
    if not ciphertext:
        return jsonify({"ok": False, "error": "ciphertext is required"}), 400
    try:
        result = rsa_decrypt(ciphertext)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("RSA decryption failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/rsa/sign", methods=["POST"])
def api_rsa_sign():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"ok": False, "error": "message is required"}), 400
    try:
        result = rsa_sign(message)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("RSA sign failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/rsa/verify", methods=["POST"])
def api_rsa_verify():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    signature = data.get("signature", "")
    if not message or not signature:
        return jsonify({"ok": False, "error": "message and signature are required"}), 400
    try:
        result = rsa_verify(message, signature)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("RSA verify failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# ECDSA routes
# ---------------------------------------------------------------------------

@app.route("/api/ecdsa/generate", methods=["POST"])
def api_ecdsa_generate():
    try:
        result = generate_ecdsa_key()
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("ECDSA key generation failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/ecdsa/sign", methods=["POST"])
def api_ecdsa_sign():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"ok": False, "error": "message is required"}), 400
    try:
        result = ecdsa_sign(message)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("ECDSA sign failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/ecdsa/verify", methods=["POST"])
def api_ecdsa_verify():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    signature = data.get("signature", "")
    if not message or not signature:
        return jsonify({"ok": False, "error": "message and signature are required"}), 400
    try:
        result = ecdsa_verify(message, signature)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("ECDSA verify failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# ECDH route
# ---------------------------------------------------------------------------

@app.route("/api/ecdh/exchange", methods=["POST"])
def api_ecdh_exchange():
    try:
        result = perform_ecdh()
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("ECDH exchange failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# DH route
# ---------------------------------------------------------------------------

@app.route("/api/dh/exchange", methods=["POST"])
def api_dh_exchange():
    try:
        result = perform_dh()
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("DH exchange failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# AES routes
# ---------------------------------------------------------------------------

@app.route("/api/aes/encrypt", methods=["POST"])
def api_aes_encrypt():
    data = request.get_json(silent=True) or {}
    plaintext = data.get("plaintext", "")
    aad = data.get("aad", "")
    if not plaintext:
        return jsonify({"ok": False, "error": "plaintext is required"}), 400
    try:
        result = aes_encrypt(plaintext, aad)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("AES encryption failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/aes/decrypt", methods=["POST"])
def api_aes_decrypt():
    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext", "")
    nonce = data.get("nonce", "")
    aad = data.get("aad", "")
    if not ciphertext or not nonce:
        return jsonify({"ok": False, "error": "ciphertext and nonce are required"}), 400
    try:
        result = aes_decrypt(ciphertext, nonce, aad)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("AES decryption failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Hash routes
# ---------------------------------------------------------------------------

@app.route("/api/hash/sha256", methods=["POST"])
def api_sha256():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400
    try:
        result = sha256_hash(text)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("SHA-256 hash failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/hash/sha512", methods=["POST"])
def api_sha512():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400
    try:
        result = sha512_hash(text)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("SHA-512 hash failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# TLS route
# ---------------------------------------------------------------------------

@app.route("/api/tls/request", methods=["POST"])
def api_tls_request():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    certfile = os.environ.get("DEMO_CERT_FILE", "certs/demo.crt")
    keyfile = os.environ.get("DEMO_KEY_FILE", "certs/demo.key")
    try:
        result = make_https_request(url=url, certfile=certfile, keyfile=keyfile)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        logger.exception("HTTPS request failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    logger.info("[DEMO] Starting Crypto Demo Application on port %d (PID %d)", port, os.getpid())
    app.run(host="127.0.0.1", port=port, debug=False)
