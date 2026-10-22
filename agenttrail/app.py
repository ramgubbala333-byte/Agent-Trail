"""AgentTrail API.

Agent surface:  sessions, messages, approvals, kill switch.
Auditor surface (read-only + verification): session list, replay, verify,
evidence-bundle export. Reading the trail is itself audited — replay and
export append an ``audit_accessed`` event naming the auditor.

Run:  uvicorn agenttrail.app:app --port 8000
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from pathlib import Path

from fastapi.responses import HTMLResponse, Response

from . import __version__
from .agent import AgentLoop, make_planner
from .bizdb import BusinessDB
from .bundle import build_bundle
from .canonical import hash_object
from .chain import AuditWriteError, AuditWriter, verify_session
from .events import Actor, Config
from .gateway import Gateway, SessionContext
from .keys import Signer
from .policy import PolicyEngine, load_policy_config
from .store import AuditStore
from .tools import TOOLS

DATA_DIR = os.environ.get("AGENTTRAIL_DATA_DIR", "data")
store = AuditStore(os.path.join(DATA_DIR, "audit.db"))
signer = Signer(os.path.join(DATA_DIR, "signer.key"))
writer = AuditWriter(store, signer)
bizdb = BusinessDB(os.path.join(DATA_DIR, "biz.db"))
policy = PolicyEngine(store, load_policy_config())
gateway = Gateway(writer, store, policy, bizdb,
                  hmac_key=hashlib.sha256(
                      os.environ.get("AGENTTRAIL_HMAC_KEY", "dev-hmac-key").encode()
                  ).digest())
planner = make_planner()
loop = AgentLoop(gateway, planner, gateway.hmac_key)

SYSTEM_PROMPT = "You are a support operations agent. Use tools; never invent receipts."
SYSTEM_PROMPT_HASH = hash_object({"prompt": SYSTEM_PROMPT})

app = FastAPI(title="AgentTrail", version=__version__,
              description="Tamper-evident audit trails for AI agents.")


class SessionIn(BaseModel):
    user_id: str = "u_demo_221"
    role: str = "support_agent"
    tenant_id: str = "acme-demo"


class MessageIn(BaseModel):
    text: str


class DecisionIn(BaseModel):
    approver: str
    decision: str  # granted | denied


class KillIn(BaseModel):
    scope: str  # global | session | tool
    active: bool = True
    by_user: str = "ops-admin"
    session_id: Optional[str] = None
    tool_name: Optional[str] = None


class PolicyReloadIn(BaseModel):
    by_user: str = "ops-admin"
    path: Optional[str] = None


@app.get("/")
def root():
    return {"service": "agenttrail", "version": __version__,
            "planner": planner.model_id, "signer_key_id": signer.key_id,
            "policy_version": policy.config.version,
            "policy_preset": policy.config.preset}


@app.post("/sessions")
def create_session(body: SessionIn):
    session_id = "sess_" + uuid.uuid4().hex[:12]
    ctx = SessionContext(
        session_id=session_id,
        actor=Actor(user_id=body.user_id, role=body.role,
                    tenant_id=body.tenant_id,
                    delegated_scope=sorted(
                        policy.config.role_tools.get(body.role, set()))),
        config=Config(model_provider=planner.model_provider,
                      model_id=planner.model_id,
                      system_prompt_hash=SYSTEM_PROMPT_HASH,
                      policy_version=policy.config.version),
        budget_usd=policy.config.session_budget_usd,
        max_steps=policy.config.max_steps,
    )
    try:
        gateway.start_session(ctx)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed — session not opened: {exc}")
    return {"session_id": session_id, "role": body.role}


@app.post("/sessions/{session_id}/messages")
def post_message(session_id: str, body: MessageIn):
    ctx = gateway.contexts.get(session_id)
    if ctx is None:
        raise HTTPException(404, "unknown session")
    try:
        return loop.handle_message(ctx, body.text)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed — action not executed: {exc}")


@app.post("/sessions/{session_id}/close")
def close_session(session_id: str):
    ctx = gateway.contexts.get(session_id)
    if ctx is None:
        raise HTTPException(404, "unknown session")
    try:
        seal = gateway.close_session(ctx)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed: {exc}")
    return {"session_id": session_id, "closed": True, "seal": seal}


@app.post("/admin/policy/reload")
def policy_reload(body: PolicyReloadIn):
    try:
        config = gateway.reload_policy(body.by_user, body.path)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed: {exc}")
    except Exception as exc:
        raise HTTPException(422, f"policy reload failed: {exc}")
    return {"policy": config}


@app.get("/registry/agents")
def agent_registry():
    """Agent Cards: the registered agents, their tools and governing policy —
    the governance layer's inventory, in the open."""
    return {"agents": [{
        "agent_id": "support-agent",
        "agent_version": __version__,
        "purpose": "Customer-support operations over the demo CRM",
        "workload_identity": "svc-agenttrail",
        "policy_id": policy.config.policy_id,
        "policy_version": policy.config.version,
        "tools": [{"name": name, "write": spec.write,
                   "sensitive_fields": sorted(spec.sensitive_fields)}
                  for name, spec in sorted(TOOLS.items())],
        "roles": {role: sorted(tools) for role, tools
                  in policy.config.role_tools.items()},
    }]}


@app.post("/approvals/{approval_id}/decision")
def decide(approval_id: str, body: DecisionIn):
    if body.decision not in {"granted", "denied"}:
        raise HTTPException(422, "decision must be granted or denied")
    try:
        res = gateway.decide(approval_id, body.approver, body.decision)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed — action not executed: {exc}")
    return {"approval_id": approval_id, "status": res.status,
            "action_id": res.action_id, "reason": res.reason}


@app.post("/admin/kill")
def kill(body: KillIn):
    try:
        key = gateway.set_kill(body.scope, body.active, body.by_user,
                               session_id=body.session_id, tool_name=body.tool_name)
    except AuditWriteError as exc:
        raise HTTPException(503, f"audit write failed: {exc}")
    return {"flag": key, "active": body.active}


# -- auditor surface ---------------------------------------------------------

def _log_access(session_id: str, auditor: str, what: str) -> None:
    """Reading the trail is itself an auditable act."""
    ctx = gateway.contexts.get(session_id)
    if ctx is None:
        return
    try:
        gateway.emit(ctx, "audit_accessed",
                     decision_summary=f"Auditor {auditor} accessed the trail ({what}).",
                     data={"auditor": auditor, "access": what})
    except AuditWriteError:
        pass  # reads must not fail because the access note could not be sealed


@app.get("/audit/sessions")
def audit_sessions():
    return {"sessions": store.list_sessions(),
            "signer_key_id": signer.key_id,
            "public_key": signer.public_key_b64()}


@app.get("/audit/sessions/{session_id}")
def audit_replay(session_id: str, x_auditor_id: str = Header("auditor")):
    events = store.session_events(session_id)
    if not events:
        raise HTTPException(404, "session not found")
    _log_access(session_id, x_auditor_id, "replay")
    return {"session_id": session_id, "events": events}


@app.get("/audit/sessions/{session_id}/verify")
def audit_verify(session_id: str):
    result = verify_session(store, session_id)
    if result.get("reason") == "session not found or empty":
        raise HTTPException(404, "session not found")
    return result


@app.get("/audit/sessions/{session_id}/export")
def audit_export(session_id: str, x_auditor_id: str = Header("auditor")):
    events = store.session_events(session_id)
    if not events:
        raise HTTPException(404, "session not found")
    key_ids = {ev["integrity"]["signer_key_id"] for ev in events}
    bundle = {
        "session_id": session_id,
        "signers": {kid: store.signer_public_key(kid) for kid in key_ids},
        "events": events,
        "verification": verify_session(store, session_id),
    }
    _log_access(session_id, x_auditor_id, "export")
    return bundle


@app.get("/audit/sessions/{session_id}/export.zip")
def audit_export_zip(session_id: str, x_auditor_id: str = Header("auditor")):
    events = store.session_events(session_id)
    if not events:
        raise HTTPException(404, "session not found")
    verification = verify_session(store, session_id)
    data = build_bundle(store, session_id, verification, policy.config.as_dict())
    _log_access(session_id, x_auditor_id, "export.zip")
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition":
                             f'attachment; filename="agenttrail-{session_id}.zip"'})


@app.get("/audit/stats")
def audit_stats():
    """Dashboard aggregates computed from the trails themselves — cost,
    policy decisions, tool latency, errors. If it isn't in the trail, it
    isn't on the dashboard."""
    sessions = store.list_sessions()
    by_type: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    durations: list[int] = []
    total_cost = 0.0
    total_tokens = 0
    errors = 0
    for s in sessions:
        for ev in store.session_events(s["session_id"]):
            by_type[ev["event_type"]] = by_type.get(ev["event_type"], 0) + 1
            if ev.get("policy"):
                v = ev["policy"]["verdict"]
                verdicts[v] = verdicts.get(v, 0) + 1
            if ev["event_type"] == "tool_executed" and ev.get("outcome"):
                if ev["outcome"].get("duration_ms") is not None:
                    durations.append(ev["outcome"]["duration_ms"])
            if ev["event_type"] == "tool_failed":
                errors += 1
            if ev.get("usage"):
                total_cost += ev["usage"].get("cost_usd", 0.0)
                total_tokens += (ev["usage"].get("input_tokens", 0)
                                 + ev["usage"].get("output_tokens", 0))
    durations.sort()

    def pct(p: float):
        if not durations:
            return None
        return durations[min(len(durations) - 1, int(p * len(durations)))]

    return {
        "sessions": len(sessions),
        "events": sum(by_type.values()),
        "events_by_type": by_type,
        "policy_verdicts": verdicts,
        "tool_errors": errors,
        "total_cost_usd": round(total_cost, 4),
        "total_tokens": total_tokens,
        "tool_latency_ms": {"p50": pct(0.50), "p95": pct(0.95)},
    }


@app.get("/ui", response_class=HTMLResponse)
def auditor_ui():
    html = (Path(__file__).parent / "static" / "auditor.html").read_text()
    return HTMLResponse(html)
