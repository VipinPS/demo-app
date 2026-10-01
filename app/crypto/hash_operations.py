"""
Hash operations: SHA-256 and SHA-512.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
"""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def sha256_hash(data: str) -> dict:
    """Compute the SHA-256 digest of the supplied string."""
    logger.info("[DEMO] SHA-256 hash executed")

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    result = digest.finalize()

    return {
        "algorithm": "SHA-256",
        "input_length": len(data),
        "digest_hex": result.hex(),
        "digest_b64": __import__("base64").b64encode(result).decode(),
    }


def sha512_hash(data: str) -> dict:
    """Compute the SHA-512 digest of the supplied string."""
    logger.info("[DEMO] SHA-512 hash executed")

    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(data.encode())
    result = digest.finalize()

    return {
        "algorithm": "SHA-512",
        "input_length": len(data),
        "digest_hex": result.hex(),
        "digest_b64": __import__("base64").b64encode(result).decode(),
    }
