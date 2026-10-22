"""Ed25519 signing keys for the audit service.

The signer is the audit service, never the agent. In production this key
lives in a KMS/HSM and rotation means a new ``signer_key_id`` with old keys
retained for verification; here a local key file stands in, and the key id
is derived from the public key so verification bundles are self-describing.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "audit-signer-" + hashlib.sha256(raw).hexdigest()[:12]


class Signer:
    """Loads (or creates) the audit service's Ed25519 key."""

    def __init__(self, key_path: str | Path):
        self.key_path = Path(key_path)
        if self.key_path.exists():
            self._private = Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(self.key_path.read_text().strip())
            )
        else:
            self._private = Ed25519PrivateKey.generate()
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            raw = self._private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            self.key_path.write_text(_b64(raw))
            os.chmod(self.key_path, 0o600)
        self.public_key = self._private.public_key()
        self.key_id = key_id_for(self.public_key)

    def sign(self, data: bytes) -> str:
        return _b64(self._private.sign(data))

    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _b64(raw)


def verify_signature(public_key_b64: str, signature_b64: str, data: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except Exception:
        return False
