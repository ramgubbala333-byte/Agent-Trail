"""Hash-chain integrity: a valid trail verifies; a tampered one fails at
exactly the sequence number that was edited."""

import sqlite3

from agenttrail.chain import verify_session


def _run_flow(stack):
    ctx = stack.session()
    stack.loop.handle_message(ctx, "Find customer Priya and check order 8841")
    stack.loop.handle_message(ctx, "refund order 8841 $10")
    return ctx


def test_chain_verifies(stack):
    _run_flow(stack)
    result = verify_session(stack.store, "sess_test")
    assert result["valid"], result
    assert result["events_checked"] >= 8  # session, requests, proposals, executions…


def test_tamper_detected_at_exact_sequence(stack):
    _run_flow(stack)
    events = stack.store.session_events("sess_test")
    target = next(e for e in events if e["event_type"] == "tool_executed"
                  and e["tool"]["tool_name"] == "issue_refund")
    seq = target["sequence_no"]

    # An admin (or attacker) with raw DB access rewrites history: the refund
    # receipt in the sealed payload is altered after the fact.
    raw = sqlite3.connect(stack.store.db_path)
    row = raw.execute(
        "SELECT payload_json FROM audit_events WHERE session_id = ? AND sequence_no = ?",
        ("sess_test", seq)).fetchone()
    tampered = row[0].replace("RF-1001", "RF-9999")
    assert tampered != row[0]
    raw.execute(
        "UPDATE audit_events SET payload_json = ? WHERE session_id = ? AND sequence_no = ?",
        (tampered, "sess_test", seq))
    raw.commit()
    raw.close()

    result = verify_session(stack.store, "sess_test")
    assert not result["valid"]
    assert result["failed_at_sequence"] == seq
    assert "modified" in result["reason"]


def test_genesis_and_sequence_continuity(stack):
    _run_flow(stack)
    events = stack.store.session_events("sess_test")
    assert events[0]["event_type"] == "session_started"
    assert [e["sequence_no"] for e in events] == list(range(len(events)))
    for prev, cur in zip(events, events[1:]):
        assert cur["integrity"]["prev_hash"] == prev["integrity"]["event_hash"]
