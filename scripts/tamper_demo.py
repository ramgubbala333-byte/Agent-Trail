"""Tamper demo: rewrite history in a *copy* of the audit DB and watch
verification fail at exactly the edited sequence number.

    python scripts/tamper_demo.py data/audit.db <session_id>
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agenttrail.chain import verify_session  # noqa: E402
from agenttrail.store import AuditStore  # noqa: E402


def main() -> int:
    db_path, session_id = sys.argv[1], sys.argv[2]
    print("Original trail:")
    store = AuditStore(db_path)
    result = verify_session(store, session_id)
    print(f"  valid={result['valid']}  events={result['events_checked']}")

    tmp = Path(tempfile.mkdtemp()) / "tampered.db"
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(tmp)
    src.backup(dst)  # WAL-safe copy (a raw file copy would miss the -wal)
    src.close()
    dst.close()
    raw = sqlite3.connect(tmp)
    row = raw.execute(
        "SELECT sequence_no, payload_json FROM audit_events"
        " WHERE session_id = ? AND event_type = 'tool_executed' LIMIT 1",
        (session_id,)).fetchone()
    if not row:
        print("No executed tool call to tamper with — run the demo first.")
        return 2
    seq, payload = row
    forged = payload.replace('"completed"', '"forged"', 1)
    if forged == payload:
        forged = payload.replace("RF-", "RF-9", 1)
    raw.execute("UPDATE audit_events SET payload_json = ?"
                " WHERE session_id = ? AND sequence_no = ?",
                (forged, session_id, seq))
    raw.commit()
    raw.close()

    print(f"\nTampered copy (edited the tool_executed event at sequence {seq}):")
    result = verify_session(AuditStore(tmp), session_id)
    print(f"  valid={result['valid']}  failed_at_sequence="
          f"{result['failed_at_sequence']}  reason={result['reason']}")
    return 0 if not result["valid"] and result["failed_at_sequence"] == seq else 1


if __name__ == "__main__":
    sys.exit(main())
