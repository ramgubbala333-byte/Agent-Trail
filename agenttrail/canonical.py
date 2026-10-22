"""Canonical JSON (RFC 8785) and hashing helpers.

Hashing non-canonical JSON is the classic audit-trail bug: two serializers
produce different bytes for the same logical event and verification becomes
flaky across languages. Every byte that enters the hash chain in AgentTrail
is canonicalized with RFC 8785 (JSON Canonicalization Scheme) first.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

import jcs


def canonical_bytes(obj) -> bytes:
    """Serialize *obj* to RFC 8785 canonical JSON bytes."""
    return jcs.canonicalize(obj)


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_object(obj) -> str:
    """SHA-256 over the canonical form of *obj*, as ``sha256:<hex>``."""
    return sha256_hex(canonical_bytes(obj))


def hmac_hex(key: bytes, value: str) -> str:
    """HMAC-SHA-256 of *value* — for correlating identifiers without storing
    the raw (low-entropy, dictionary-attackable) value itself."""
    return "hmac:" + _hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
