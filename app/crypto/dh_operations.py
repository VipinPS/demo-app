"""
Finite-field Diffie-Hellman key exchange operations.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
Uses the RFC 3526 MODP-2048 group.
"""

import base64
import logging

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers

logger = logging.getLogger(__name__)

# RFC 3526 — MODP Group 14 (2048-bit prime)
_MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_MODP_2048_G = 2

_dh_params = None


def _get_params():
    global _dh_params
    if _dh_params is None:
        pn = DHParameterNumbers(_MODP_2048_P, _MODP_2048_G)
        _dh_params = pn.parameters()
    return _dh_params


def perform_dh() -> dict:
    """
    Simulate a full finite-field DH exchange between two parties (A and B).
    Both parties share the same pre-agreed RFC 3526 MODP-2048 parameters.
    """
    logger.info("[DEMO] DH (finite-field) key exchange executed")

    params = _get_params()

    # Party A
    private_key_a = params.generate_private_key()
    public_key_a = private_key_a.public_key()

    # Party B
    private_key_b = params.generate_private_key()
    public_key_b = private_key_b.public_key()

    # Key agreement
    shared_secret_a = private_key_a.exchange(public_key_b)
    shared_secret_b = private_key_b.exchange(public_key_a)

    secrets_match = shared_secret_a == shared_secret_b

    logger.info("[DEMO] DH key exchange complete — secrets_match=%s", secrets_match)

    return {
        "group": "RFC 3526 MODP-2048",
        "shared_secret_a_preview": base64.b64encode(shared_secret_a).decode()[:32] + "...",
        "shared_secret_b_preview": base64.b64encode(shared_secret_b).decode()[:32] + "...",
        "secrets_match": secrets_match,
    }
