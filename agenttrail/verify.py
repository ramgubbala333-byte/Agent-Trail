"""Offline chain verification CLI.

    python -m agenttrail.verify --db data/audit.db [--session sess_x]

Recomputes every hash and signature from the stored payloads alone — no
server, no agent, no trust in the application. Exit code 0 iff every checked
session is intact.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .chain import verify_session
from .store import AuditStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrail-verify")
    parser.add_argument("--db", help="path to the audit database")
    parser.add_argument("--session", help="verify only this session id")
    parser.add_argument("--bundle", help="verify an exported evidence bundle (.zip) offline")
    args = parser.parse_args(argv)

    if args.bundle:
        from .bundle import verify_bundle_bytes
        result = verify_bundle_bytes(Path(args.bundle).read_bytes())
        if result["valid"]:
            print(f"✓ bundle {args.bundle}: VALID — {result['events_checked']} "
                  f"events, session {result['session_id']}")
            return 0
        print(f"✗ bundle {args.bundle}: INVALID at sequence "
              f"{result['failed_at_sequence']} — {result['reason']}")
        return 1

    if not args.db:
        parser.error("--db is required unless --bundle is given")
    if not Path(args.db).exists():
        print(f"database not found: {args.db}")
        return 2
    store = AuditStore(args.db)
    if args.session:
        session_ids = [args.session]
    else:
        session_ids = [s["session_id"] for s in store.list_sessions()]

    all_valid = True
    for session_id in session_ids:
        result = verify_session(store, session_id)
        if result["valid"]:
            print(f"✓ {session_id}: VALID — {result['events_checked']} events, "
                  f"head {result['head_hash'][:19]}…")
        else:
            all_valid = False
            print(f"✗ {session_id}: INVALID at sequence "
                  f"{result['failed_at_sequence']} — {result['reason']}")
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())
