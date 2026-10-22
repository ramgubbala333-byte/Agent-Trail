"""Redaction — applied in the interceptor, before anything is persisted.

Two nets, in order:
1. Schema-driven: fields a tool declares ``sensitive`` are always removed and
   replaced by an HMAC of the value (correlatable, not readable).
2. Pattern-based: secrets and personal data detectors sweep everything else
   (connection strings, API keys, card numbers, emails).

The ledger records *which* fields were redacted (``sensitive_fields``) so a
reviewer knows evidence was withheld, without seeing it.
"""

from __future__ import annotations

import re
from typing import Any

from .canonical import hmac_hex

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("connection_string", re.compile(r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s\"']+")),
    ("api_key", re.compile(r"(?i)(sk-[a-z0-9_\-]{10,}|api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\s\"',}]+)")),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("email", re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    ("password_assignment", re.compile(r"(?i)password[\"']?\s*[:=]\s*[\"']?[^\s\"',}]+")),
]

REDACTED = "[REDACTED]"
HASHED = "[HASHED]"


def _sweep(value: Any, found: list[str], label: str) -> Any:
    if isinstance(value, str):
        out = value
        for name, pat in _PATTERNS:
            if pat.search(out):
                found.append(f"{label}:{name}")
                out = pat.sub(REDACTED, out)
        return out
    if isinstance(value, dict):
        return {k: _sweep(v, found, f"{label}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_sweep(v, found, label) for v in value]
    return value


def redact_payload(
    payload: dict[str, Any],
    sensitive_fields: set[str],
    hmac_key: bytes,
) -> tuple[dict[str, Any], list[str]]:
    """Return (redacted_copy, sensitive_field_names).

    Fields named in *sensitive_fields* are HMAC-hashed (kept correlatable);
    everything else passes the pattern sweep. The input is not mutated.
    """
    found: list[str] = []
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key in sensitive_fields and value is not None:
            result[key] = HASHED
            found.append(key)
            result[f"{key}_hmac"] = hmac_hex(hmac_key, str(value))
        else:
            result[key] = _sweep(value, found, key)
    return result, sorted(set(found))
