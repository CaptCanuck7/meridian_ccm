"""
Ed25519 asymmetric signing for OTVP-compliant evidence signing.

KeyPair is generated on first startup and persisted to disk so that the
same keypair is reused across agent restarts. Verification uses only the
public key; the private key never leaves the agent process.

Canonical JSON: sort_keys=True, no extra whitespace, UTF-8 encoded.
Signature encoding: base64url (URL-safe, no padding).
"""

from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

log = logging.getLogger(__name__)

_DEFAULT_KEY_DIR = os.getenv("KEY_DIR", "/keys")
PRIVATE_KEY_PATH = os.path.join(_DEFAULT_KEY_DIR, "signing_key.pem")
PUBLIC_KEY_PATH  = os.path.join(_DEFAULT_KEY_DIR, "signing_key.pub.pem")


def _canonical(payload: dict) -> bytes:
    """Return canonical UTF-8 JSON bytes (sorted keys, no extra whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class KeyPair:
    """Ed25519 keypair for signing and verification."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public: Ed25519PublicKey = private_key.public_key()

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_generate(
        cls,
        private_path: str = PRIVATE_KEY_PATH,
        public_path: str = PUBLIC_KEY_PATH,
    ) -> "KeyPair":
        """Load keypair from disk, or generate and persist a new one."""
        if os.path.exists(private_path):
            log.info("Loading Ed25519 key from %s", private_path)
            with open(private_path, "rb") as fh:
                private_key = load_pem_private_key(fh.read(), password=None)
            kp = cls(private_key)  # type: ignore[arg-type]
        else:
            log.info("Generating new Ed25519 keypair → %s", private_path)
            kp = cls.generate()
            os.makedirs(os.path.dirname(private_path), exist_ok=True)
            with open(private_path, "wb") as fh:
                fh.write(
                    kp._private.private_bytes(
                        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                    )
                )
            with open(public_path, "wb") as fh:
                fh.write(
                    kp._public.public_bytes(
                        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                    )
                )

        log.info("Public key (hex): %s", kp.public_key_hex)
        return kp

    # ── Signing / verification ────────────────────────────────────────────────

    def sign(self, payload: dict) -> str:
        """Return base64url Ed25519 signature of the canonical JSON payload."""
        raw_sig = self._private.sign(_canonical(payload))
        return base64.urlsafe_b64encode(raw_sig).decode("ascii")

    def verify(self, payload: dict, signature: str) -> bool:
        """Return True if signature is a valid Ed25519 signature of payload."""
        try:
            sig_bytes = base64.urlsafe_b64decode(signature.encode("ascii") + b"==")
            self._public.verify(sig_bytes, _canonical(payload))
            return True
        except Exception:
            return False

    # ── Key export ───────────────────────────────────────────────────────────

    @property
    def public_key_pem(self) -> str:
        return self._public.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    @property
    def public_key_hex(self) -> str:
        raw = self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()
