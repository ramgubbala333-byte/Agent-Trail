"""End-to-end over HTTP: the full story an auditor later replays."""

import os
import tempfile

os.environ["AGENTTRAIL_DATA_DIR"] = tempfile.mkdtemp(prefix="agenttrail-api-")

from fastapi.testclient import TestClient  # noqa: E402

from agenttrail.app import app  # noqa: E402

client = TestClient(app)


def test_full_story():
    r = client.post("/sessions", json={"user_id": "u_demo_221",
                                       "role": "support_agent"})
    assert r.status_code == 200
    sid = r.json()["session_id"]

    r = client.post(f"/sessions/{sid}/messages",
                    json={"text": "Find customer Priya and check order 8841"})
    assert r.status_code == 200
    statuses = {x["tool"]: x["status"] for x in r.json()["results"]}
    assert statuses == {"search_customers": "executed", "get_order": "executed"}

    r = client.post(f"/sessions/{sid}/messages",
                    json={"text": "refund order 8841 $42"})
    result = r.json()["results"][0]
    assert result["status"] == "pending_approval"
    approval_id = result["approval_id"]

    r = client.post(f"/approvals/{approval_id}/decision",
                    json={"approver": "j.ribeiro@example.com",
                          "decision": "granted"})
    assert r.json()["status"] == "executed"

    r = client.get(f"/audit/sessions/{sid}")
    events = r.json()["events"]
    types = [e["event_type"] for e in events]
    for expected in ("session_started", "tool_proposed", "policy_evaluated",
                     "approval_requested", "approval_granted", "tool_executed"):
        assert expected in types, types
    # Reading the trail is itself audited: the access event is sealed after
    # the read it records, so it appears from the *next* read onwards.
    r = client.get(f"/audit/sessions/{sid}")
    assert "audit_accessed" in [e["event_type"] for e in r.json()["events"]]
    executed = next(e for e in events if e["event_type"] == "tool_executed"
                    and e["tool"]["tool_name"] == "issue_refund")
    assert executed["outcome"]["downstream_receipt"] == "RF-1001"
    assert executed["approval"]["approved_action_digest"]

    r = client.get(f"/audit/sessions/{sid}/verify")
    assert r.json()["valid"] is True

    r = client.get(f"/audit/sessions/{sid}/export")
    bundle = r.json()
    assert bundle["verification"]["valid"] is True
    assert bundle["signers"]  # offline verification material is in the bundle
