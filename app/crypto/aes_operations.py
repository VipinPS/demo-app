"""
AES-256-GCM symmetric encryption/decryption operations.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
"""

import base64
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Demo session key (rotated on each server start; not persisted)
_aes_key: bytes | None = None


def _get_or_create_key() -> bytes:
    global _aes_key
    if _aes_key is None:
        _aes_key = os.urandom(32)  # 256-bit key
    return _aes_key


def aes_encrypt(plaintext: str, associated_data: str = "") -> dict:
    """Encrypt plaintext with AES-256-GCM."""
    logger.info("[DEMO] AES-256-GCM encryption executed")

    key = _get_or_create_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aad = associated_data.encode() if associated_data else None

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "aad": associated_data,
        "key_preview": base64.b64encode(key).decode()[:16] + "...",
    }


def aes_decrypt(ciphertext_b64: str, nonce_b64: str, associated_data: str = "") -> dict:
    """Decrypt AES-256-GCM ciphertext."""
    if _aes_key is None:
        raise ValueError("No AES key available. Encrypt a message first.")

    logger.info("[DEMO] AES-256-GCM decryption executed")

    key = _aes_key
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aad = associated_data.encode() if associated_data else None

    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return {"plaintext": plaintext.decode()}
