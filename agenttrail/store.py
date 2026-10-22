"""Append-only audit store (SQLite reference implementation).

The production mapping is Postgres with an INSERT/SELECT-only role for the
writer and no UPDATE/DELETE grants for anyone (see ``schema/postgres.sql``).
The shape here is identical: one ``audit_events`` row per event, a per-session
chain head updated inside the same transaction that appends, and signer
public keys kept with the trail so bundles verify offline.

Operational state (approvals, kill-switch flags) lives in separate tables —
it is *not* part of the sealed trail; the trail records events about it.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional


class AuditStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS signers (
                key_id TEXT PRIMARY KEY,
                public_key_b64 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                session_id TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                event_time_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                signer_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (session_id, sequence_no)
            );
            CREATE TABLE IF NOT EXISTS session_heads (
                session_id TEXT PRIMARY KEY,
                last_sequence INTEGER NOT NULL,
                last_hash TEXT NOT NULL
            );
            -- operational state (not sealed evidence)
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                action_version INTEGER NOT NULL,
                action_digest TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                args_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                approver TEXT,
                created_at TEXT NOT NULL,
                decided_at TEXT,
                expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS session_seals (
                session_id TEXT PRIMARY KEY,
                event_count INTEGER NOT NULL,
                head_hash TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                signer_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                sealed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control_flags (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    # -- signers ---------------------------------------------------------
    def register_signer(self, key_id: str, public_key_b64: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO signers (key_id, public_key_b64) VALUES (?, ?)",
                (key_id, public_key_b64),
            )
            self._conn.commit()

    def signer_public_key(self, key_id: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT public_key_b64 FROM signers WHERE key_id = ?", (key_id,)
        ).fetchone()
        return row["public_key_b64"] if row else None

    # -- chain head / append (called only by AuditWriter) -----------------
    def chain_head(self, session_id: str) -> Optional[tuple[int, str]]:
        row = self._conn.execute(
            "SELECT last_sequence, last_hash FROM session_heads WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return (row["last_sequence"], row["last_hash"]) if row else None

    def append_sealed(self, session_id: str, sequence_no: int, payload_json: str,
                      event_id: str, event_type: str, event_time_utc: str,
                      prev_hash: str, event_hash: str, signer_key_id: str,
                      signature: str) -> None:
        """Insert one sealed event and advance the chain head, atomically."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO audit_events (session_id, sequence_no, event_id,"
                    " event_type, event_time_utc, payload_json, prev_hash, event_hash,"
                    " signer_key_id, signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (session_id, sequence_no, event_id, event_type, event_time_utc,
                     payload_json, prev_hash, event_hash, signer_key_id, signature),
                )
                self._conn.execute(
                    "INSERT INTO session_heads (session_id, last_sequence, last_hash)"
                    " VALUES (?, ?, ?)"
                    " ON CONFLICT(session_id) DO UPDATE SET"
                    " last_sequence = excluded.last_sequence,"
                    " last_hash = excluded.last_hash",
                    (session_id, sequence_no, event_hash),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # -- reads -------------------------------------------------------------
    def list_sessions(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT session_id, last_sequence, last_hash FROM session_heads"
            " ORDER BY session_id"
        ).fetchall()
        return [dict(r) for r in rows]

    def session_events(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload_json FROM audit_events WHERE session_id = ?"
            " ORDER BY sequence_no",
            (session_id,),
        ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    def raw_event_rows(self, session_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM audit_events WHERE session_id = ? ORDER BY sequence_no",
            (session_id,),
        ).fetchall()

    # -- operational state ---------------------------------------------------
    def save_approval(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals (approval_id, session_id, action_id,"
                " action_version, action_digest, tool_name, args_json, status,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (record["approval_id"], record["session_id"], record["action_id"],
                 record["action_version"], record["action_digest"], record["tool_name"],
                 json.dumps(record["args"]), record["created_at"], record.get("expires_at")),
            )
            self._conn.commit()

    def get_approval(self, approval_id: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["args"] = json.loads(d.pop("args_json"))
        return d

    def decide_approval(self, approval_id: str, status: str, approver: str,
                        decided_at: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE approvals SET status = ?, approver = ?, decided_at = ?"
                " WHERE approval_id = ?",
                (status, approver, decided_at, approval_id),
            )
            self._conn.commit()

    # -- session seals -------------------------------------------------------
    def save_seal(self, seal: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO session_seals (session_id, event_count,"
                " head_hash, merkle_root, signer_key_id, signature, sealed_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seal["session_id"], seal["event_count"], seal["head_hash"],
                 seal["merkle_root"], seal["signer_key_id"], seal["signature"],
                 seal["sealed_at"]),
            )
            self._conn.commit()

    def get_seal(self, session_id: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM session_seals WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def set_flag(self, key: str, value: str, updated_at: str, updated_by: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO control_flags (key, value, updated_at, updated_by)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                (key, value, updated_at, updated_by),
            )
            self._conn.commit()

    def get_flag(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM control_flags WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None
