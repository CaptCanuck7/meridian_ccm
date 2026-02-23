"""
OTVP-compliant Ed25519 signing — replaces the former HMAC-SHA256 module.

The KeyPair singleton is initialised once by main.py at agent startup and
injected wherever signing is needed.  This module retains a thin
module-level API (sign / verify) for any legacy call-sites, delegating to
the active KeyPair.
"""

from __future__ import annotations

from crypto.keys import KeyPair

# Module-level singleton — set by main.py after key loading
_keypair: KeyPair | None = None


def init(keypair: KeyPair) -> None:
    """Register the active KeyPair. Called once at agent startup."""
    global _keypair
    _keypair = keypair


def sign(payload: dict) -> str:
    """Return base64url Ed25519 signature of the canonical JSON payload."""
    if _keypair is None:
        raise RuntimeError("signer.init() must be called before signer.sign()")
    return _keypair.sign(payload)


def verify(payload: dict, signature: str) -> bool:
    """Return True if signature is a valid Ed25519 signature of payload."""
    if _keypair is None:
        raise RuntimeError("signer.init() must be called before signer.verify()")
    return _keypair.verify(payload, signature)
