"""v0.2 product-pattern features: policy-as-code presets, session sealing,
self-approval block, evidence bundles, stats/registry/UI surface."""

import io
import json
import os
import tempfile
import zipfile

os.environ.setdefault("AGENTTRAIL_DATA_DIR", tempfile.mkdtemp(prefix="agenttrail-v2-"))

from agenttrail.bundle import build_bundle, verify_bundle_bytes
from agenttrail.chain import verify_session
from agenttrail.policy import PolicyConfig, PolicyEngine, load_policy_config


def test_strict_preset_requires_approval_for_any_refund(stack):
    strict = PolicyEngine(stack.store, load_policy_config_from_preset("strict"))
    ctx = stack.session()
    from agenttrail.gateway import Gateway
    gw = Gateway(stack.writer, stack.store, strict, stack.bizdb,
                 stack.gateway.hmac_key)
    res = gw.propose(ctx, "issue_refund", {"order_id": 8841, "amount_cents": 500})
    assert res.status == "pending_approval"  # even $5 needs a human when strict


def load_policy_config_from_preset(name):
    cfg = PolicyConfig()
    from agenttrail.policy import PRESETS
    for k, v in PRESETS[{"strict": "strict_enterprise"}.get(name, name)].items():
        setattr(cfg, k, v)
    cfg.preset = name
    return cfg


def test_policy_file_overrides_preset(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"preset": "balanced",
                             "refund_approval_threshold_cents": 900}))
    cfg = load_policy_config(p)
    assert cfg.refund_approval_threshold_cents == 900
    assert cfg.preset == "balanced"


def test_policy_hot_reload_is_audited(stack, tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"preset": "dev_sandbox", "version": "support-policy-v9"}))
    cfg = stack.gateway.reload_policy("ops-admin", str(p))
    assert cfg["version"] == "support-policy-v9"
    assert stack.policy.config.preset == "dev_sandbox"
    system_events = stack.store.session_events("system")
    assert any(e["event_type"] == "policy_reloaded" for e in system_events)
    assert verify_session(stack.store, "system")["valid"]


def test_session_seal_and_post_seal_access(stack):
    ctx = stack.session()
    stack.loop.handle_message(ctx, "check order 8841")
    seal = stack.gateway.close_session(ctx)
    assert seal["event_count"] >= 5
    result = verify_session(stack.store, "sess_test")
    assert result["valid"] and result["seal"]["status"] == "sealed"
    # Reads after sealing are appended and reported — never hidden.
    stack.gateway.emit(ctx, "audit_accessed", data={"auditor": "a@x", "access": "replay"})
    result2 = verify_session(stack.store, "sess_test")
    assert result2["valid"] and result2["seal"]["events_after_seal"] == 1


def test_self_approval_is_blocked(stack):
    ctx = stack.session(user="u_requester")
    res = stack.gateway.propose(ctx, "issue_refund",
                                {"order_id": 8841, "amount_cents": 4200})
    assert res.status == "pending_approval"
    blocked = stack.gateway.decide(res.approval_id, "u_requester", "granted")
    assert blocked.status == "denied" and "SELF_APPROVAL" in blocked.reason
    assert stack.store.get_approval(res.approval_id)["status"] == "pending"
    ok = stack.gateway.decide(res.approval_id, "lead@example.com", "granted")
    assert ok.status == "executed"


def test_evidence_bundle_verifies_offline(stack):
    ctx = stack.session()
    stack.loop.handle_message(ctx, "Find customer Priya and check order 8841")
    stack.gateway.close_session(ctx)
    verification = verify_session(stack.store, "sess_test")
    data = build_bundle(stack.store, "sess_test", verification,
                        stack.policy.config.as_dict())
    names = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
    assert {"events.jsonl", "manifest.json", "policy_snapshot.json",
            "report.md", "verify_bundle.py", "signer_public_key.b64"} <= names
    result = verify_bundle_bytes(data)
    assert result["valid"], result

    # Tamper inside the bundle -> the offline verifier must catch it too.
    z = zipfile.ZipFile(io.BytesIO(data))
    items = {n: z.read(n) for n in z.namelist()}
    items["events.jsonl"] = items["events.jsonl"].replace(b"Priya", b"ZZZZZ")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for n, b in items.items():
            out.writestr(n, b)
    assert not verify_bundle_bytes(buf.getvalue())["valid"]


def test_api_surface_v2():
    from fastapi.testclient import TestClient
    from agenttrail.app import app
    client = TestClient(app)
    r = client.post("/sessions", json={"user_id": "u_v2", "role": "support_agent"})
    sid = r.json()["session_id"]
    client.post(f"/sessions/{sid}/messages", json={"text": "check order 8841"})
    r = client.post(f"/sessions/{sid}/close")
    assert r.json()["seal"]["merkle_root"].startswith("sha256:")
    r = client.get(f"/audit/sessions/{sid}/verify")
    assert r.json()["valid"] and r.json()["seal"]["status"] == "sealed"
    r = client.get("/audit/stats")
    assert r.json()["sessions"] >= 1 and r.json()["events"] >= 5
    r = client.get("/registry/agents")
    assert r.json()["agents"][0]["agent_id"] == "support-agent"
    r = client.get("/ui")
    assert r.status_code == 200 and "AgentTrail Auditor" in r.text
    r = client.get(f"/audit/sessions/{sid}/export.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert verify_bundle_bytes(r.content)["valid"]
