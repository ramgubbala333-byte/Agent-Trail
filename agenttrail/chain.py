"""The audit writer and verifier — the heart of AgentTrail.

Sealing an event:
  1. allocate the next per-session ``sequence_no`` from the chain head,
  2. ``prev_hash`` = the previous event's hash (or the genesis hash),
  3. ``event_hash = SHA-256(prev_hash_bytes || RFC 8785 canonical event)``,
  4. sign ``event_hash`` with the audit service's Ed25519 key,
  5. append atomically (event row + advanced chain head, one transaction).

Verification recomputes every step from the stored payloads alone, so a
trail can be checked offline from an exported bundle. A signature proves
*attribution, integrity and ordering* — not that the recorded action was
correct. That distinction is the project's honesty line.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from .canonical import canonical_bytes, sha256_hex
from .events import AuditEvent, Integrity, now_utc
from .keys import Signer, verify_signature
from .store import AuditStore


class AuditWriteError(RuntimeError):
    """Raised when an event cannot be sealed/persisted. Callers that perform
    consequential actions must fail closed on this — never swallow it."""


def genesis_hash(session_id: str) -> str:
    return sha256_hex(b"agenttrail:genesis:" + session_id.encode("utf-8"))


def _hash_with_prev(prev_hash: str, canonical: bytes) -> str:
    prev_bytes = bytes.fromhex(prev_hash.split(":", 1)[1])
    return sha256_hex(prev_bytes + canonical)


class AuditWriter:
    def __init__(self, store: AuditStore, signer: Signer):
        self.store = store
        self.signer = signer
        self.store.register_signer(signer.key_id, signer.public_key_b64())

    def append(self, event: AuditEvent) -> AuditEvent:
        """Seal *event* into its session chain and persist it. Returns the
        sealed event (integrity block filled)."""
        try:
            head = self.store.chain_head(event.session_id)
            if head is None:
                sequence_no, prev_hash = 0, genesis_hash(event.session_id)
            else:
                sequence_no, prev_hash = head[0] + 1, head[1]

            event.sequence_no = sequence_no
            event.ingested_at_utc = now_utc()

            unsigned = event.unsigned_dict()
            event_hash = _hash_with_prev(prev_hash, canonical_bytes(unsigned))
            signature = self.signer.sign(bytes.fromhex(event_hash.split(":", 1)[1]))
            event.integrity = Integrity(
                prev_hash=prev_hash,
                event_hash=event_hash,
                signer_key_id=self.signer.key_id,
                signature=signature,
            )
            payload_json = canonical_bytes(
                event.model_dump(exclude_none=True)
            ).decode("utf-8")
            self.store.append_sealed(
                session_id=event.session_id,
                sequence_no=sequence_no,
                payload_json=payload_json,
                event_id=event.event_id,
                event_type=event.event_type,
                event_time_utc=event.event_time_utc,
                prev_hash=prev_hash,
                event_hash=event_hash,
                signer_key_id=self.signer.key_id,
                signature=signature,
            )
            return event
        except AuditWriteError:
            raise
        except Exception as exc:  # persistence failure — callers fail closed
            raise AuditWriteError(str(exc)) from exc


def merkle_root(hash_list: list[str]) -> str:
    """Merkle root over ``sha256:<hex>`` digests (odd level duplicates last)."""
    if not hash_list:
        return sha256_hex(b"agenttrail:empty")
    level = [bytes.fromhex(h.split(":", 1)[1]) for h in hash_list]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(a + b).digest())
        level = nxt
    return "sha256:" + level[0].hex()


def seal_session(store: AuditStore, signer: Signer, session_id: str) -> dict[str, Any]:
    """Seal a session: Merkle root over its event hashes + count + head hash,
    signed by the audit service. An unsealed session is OPEN — possibly still
    being written; a sealed one is a closed body of evidence. Events appended
    after sealing (e.g. audit-access notes) are reported, not hidden."""
    events = store.session_events(session_id)
    if not events:
        raise AuditWriteError(f"cannot seal empty session {session_id}")
    hashes = [ev["integrity"]["event_hash"] for ev in events]
    root = merkle_root(hashes)
    signature = signer.sign(bytes.fromhex(root.split(":", 1)[1]))
    seal = {
        "session_id": session_id,
        "event_count": len(events),
        "head_hash": hashes[-1],
        "merkle_root": root,
        "signer_key_id": signer.key_id,
        "signature": signature,
        "sealed_at": now_utc(),
    }
    store.save_seal(seal)
    return seal


def verify_events(events: list[dict[str, Any]], session_id: str,
                  public_keys: dict[str, str]) -> dict[str, Any]:
    """Recompute a session chain from stored payload dicts.

    Returns {valid, events_checked, failed_at_sequence, reason}.
    """
    expected_prev = genesis_hash(session_id)
    for idx, ev in enumerate(events):
        seq = ev.get("sequence_no")
        if seq != idx:
            return {"valid": False, "events_checked": idx,
                    "failed_at_sequence": seq,
                    "reason": f"sequence gap: expected {idx}, found {seq}"}
        integrity = ev.get("integrity") or {}
        if integrity.get("prev_hash") != expected_prev:
            return {"valid": False, "events_checked": idx,
                    "failed_at_sequence": seq,
                    "reason": "prev_hash does not match previous event_hash"}
        unsigned = {k: v for k, v in ev.items() if k != "integrity"}
        recomputed = _hash_with_prev(expected_prev, canonical_bytes(unsigned))
        if recomputed != integrity.get("event_hash"):
            return {"valid": False, "events_checked": idx,
                    "failed_at_sequence": seq,
                    "reason": "event_hash mismatch — payload was modified after sealing"}
        key_id = integrity.get("signer_key_id")
        pub = public_keys.get(key_id)
        if not pub:
            return {"valid": False, "events_checked": idx,
                    "failed_at_sequence": seq,
                    "reason": f"unknown signer key {key_id}"}
        digest = bytes.fromhex(integrity["event_hash"].split(":", 1)[1])
        if not verify_signature(pub, integrity.get("signature", ""), digest):
            return {"valid": False, "events_checked": idx,
                    "failed_at_sequence": seq,
                    "reason": "signature verification failed"}
        expected_prev = integrity["event_hash"]
    return {"valid": True, "events_checked": len(events),
            "failed_at_sequence": None, "reason": None}


def verify_session(store: AuditStore, session_id: str) -> dict[str, Any]:
    events = store.session_events(session_id)
    if not events:
        return {"valid": False, "events_checked": 0, "failed_at_sequence": None,
                "reason": "session not found or empty"}
    key_ids = {ev["integrity"]["signer_key_id"] for ev in events if ev.get("integrity")}
    public_keys = {}
    for kid in key_ids:
        pub = store.signer_public_key(kid)
        if pub:
            public_keys[kid] = pub
    result = verify_events(events, session_id, public_keys)
    result["session_id"] = session_id
    result["head_hash"] = events[-1]["integrity"]["event_hash"] if events else None

    seal = store.get_seal(session_id)
    if seal is None:
        result["seal"] = {"status": "open"}  # not yet sealed — still admissible, not final
    else:
        sealed_events = events[: seal["event_count"]]
        root = merkle_root([ev["integrity"]["event_hash"] for ev in sealed_events])
        pub = public_keys.get(seal["signer_key_id"]) or store.signer_public_key(
            seal["signer_key_id"])
        sig_ok = bool(pub) and verify_signature(
            pub, seal["signature"],
            bytes.fromhex(seal["merkle_root"].split(":", 1)[1]))
        seal_ok = (root == seal["merkle_root"]
                   and sealed_events
                   and sealed_events[-1]["integrity"]["event_hash"] == seal["head_hash"]
                   and sig_ok)
        result["seal"] = {
            "status": "sealed" if seal_ok else "seal_invalid",
            "event_count": seal["event_count"],
            "events_after_seal": len(events) - seal["event_count"],
            "merkle_root": seal["merkle_root"],
            "sealed_at": seal["sealed_at"],
        }
        if not seal_ok:
            result["valid"] = False
            result["reason"] = (result["reason"] or
                                 "session seal does not match the sealed events")
    return result
