"""The policy gateway / audit interceptor.

Every tool call the agent wants to make passes through here:

    propose → policy_evaluated → (deny | approval flow | execute) → outcome

The gateway is deterministic and sits *outside* the agent: the agent never
holds the credentials that perform writes, and it cannot write its own audit
records — the suspect does not keep the diary. If an audit write fails, the
gateway fails closed: no silent audit loss for consequential actions.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .bizdb import BusinessDB
from .canonical import hash_object
from .chain import AuditWriter
from .events import Actor, Approval, AuditEvent, Config, Outcome, Policy, ToolCall, now_utc
from .policy import PolicyEngine
from .redact import redact_payload
from .store import AuditStore
from .tools import TOOLS, ToolError, summarize_result

APPROVAL_TTL_MINUTES = 15


@dataclass
class SessionContext:
    session_id: str
    actor: Actor
    config: Config
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    session_cost_usd: float = 0.0
    steps: int = 0
    budget_usd: float = 0.50
    max_steps: int = 25
    action_counter: int = 0
    last_event_id: Optional[str] = None

    def next_action_id(self) -> str:
        self.action_counter += 1
        return f"A-{self.action_counter}"


@dataclass
class GatewayResult:
    status: str  # executed | denied | pending_approval | failed
    output: Any = None
    approval_id: Optional[str] = None
    action_id: Optional[str] = None
    reason: str = ""


class Gateway:
    def __init__(self, writer: AuditWriter, store: AuditStore,
                 policy: PolicyEngine, bizdb: BusinessDB, hmac_key: bytes):
        self.writer = writer
        self.store = store
        self.policy = policy
        self.bizdb = bizdb
        self.hmac_key = hmac_key
        self.contexts: dict[str, SessionContext] = {}

    # -- event plumbing ------------------------------------------------------
    def emit(self, ctx: SessionContext, event_type: str, **kw) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            session_id=ctx.session_id,
            trace_id=ctx.trace_id,
            parent_event_id=ctx.last_event_id,
            actor=ctx.actor,
            config=ctx.config,
            **kw,
        )
        sealed = self.writer.append(event)  # raises AuditWriteError → fail closed
        ctx.last_event_id = sealed.event_id
        return sealed

    def start_session(self, ctx: SessionContext) -> AuditEvent:
        self.contexts[ctx.session_id] = ctx
        return self.emit(
            ctx, "session_started",
            decision_summary="Session opened; principal, scope and configuration sealed as the chain genesis.",
            data={"delegated_scope": ctx.actor.delegated_scope,
                  "budget_usd": ctx.budget_usd, "max_steps": ctx.max_steps},
        )

    def _tool_block(self, spec, tool_call_id: str, args: dict,
                    action_id: str | None, action_version: int | None) -> ToolCall:
        redacted, sensitive = redact_payload(args, spec.sensitive_fields, self.hmac_key)
        target = spec.target_template.format(**{k: args.get(k, "") for k in
                                                args}) if spec.target_template else None
        return ToolCall(
            tool_name=spec.name, tool_call_id=tool_call_id,
            action_id=action_id, action_version=action_version,
            target=target, write=spec.write,
            args_redacted=redacted, args_hash=hash_object(args),
            sensitive_fields=sensitive,
        )

    # -- the interceptor -------------------------------------------------------
    def propose(self, ctx: SessionContext, tool_name: str, args: dict,
                decision_summary: str = "") -> GatewayResult:
        if tool_name not in TOOLS:
            return GatewayResult("denied", reason=f"unknown tool {tool_name}")
        spec = TOOLS[tool_name]
        tool_call_id = "call_" + uuid.uuid4().hex[:12]
        action_id = ctx.next_action_id() if spec.write else None
        action_version = 1 if spec.write else None
        tool_block = self._tool_block(spec, tool_call_id, args, action_id, action_version)

        self.emit(ctx, "tool_proposed", tool=tool_block,
                  decision_summary=decision_summary or f"Agent proposes {tool_name}.")
        ctx.steps += 1

        decision = self.policy.evaluate(
            role=ctx.actor.role, session_id=ctx.session_id, tool_name=tool_name,
            args=args, write=spec.write, session_cost_usd=ctx.session_cost_usd,
            budget_usd=ctx.budget_usd, steps=ctx.steps, max_steps=ctx.max_steps)
        self.emit(ctx, "policy_evaluated", tool=tool_block,
                  policy=Policy(verdict=decision.verdict,
                                reason_code=decision.reason_code,
                                detail=decision.detail))

        if decision.verdict == "deny":
            if decision.reason_code == "BUDGET_EXCEEDED":
                self.emit(ctx, "budget_exceeded", tool=tool_block,
                          decision_summary=decision.detail)
            return GatewayResult("denied", action_id=action_id,
                                 reason=f"{decision.reason_code}: {decision.detail}")

        if decision.verdict == "require_approval":
            digest = hash_object({"tool": tool_name, "args": args,
                                  "target": tool_block.target})
            approval_id = "AP-" + uuid.uuid4().hex[:8].upper()
            expires = (datetime.now(timezone.utc)
                       + timedelta(minutes=APPROVAL_TTL_MINUTES))
            self.store.save_approval({
                "approval_id": approval_id, "session_id": ctx.session_id,
                "action_id": action_id, "action_version": action_version,
                "action_digest": digest, "tool_name": tool_name, "args": args,
                "created_at": now_utc(),
                "expires_at": expires.isoformat().replace("+00:00", "Z"),
            })
            self.emit(ctx, "approval_requested", tool=tool_block,
                      approval=Approval(approval_id=approval_id,
                                        approved_action_digest=digest,
                                        expires_at=expires.isoformat().replace("+00:00", "Z")),
                      decision_summary=f"Human approval required: {decision.detail}")
            return GatewayResult("pending_approval", approval_id=approval_id,
                                 action_id=action_id, reason=decision.detail)

        return self._execute(ctx, spec, args, tool_block, tool_call_id,
                             action_id, approval=None)

    def _execute(self, ctx: SessionContext, spec, args: dict, tool_block: ToolCall,
                 tool_call_id: str, action_id: str | None,
                 approval: Approval | None) -> GatewayResult:
        idem = f"{ctx.session_id}:{action_id or tool_call_id}"
        started = time.monotonic()
        try:
            result = spec.handler(self.bizdb, args, idem)
        except ToolError as exc:
            self.emit(ctx, "tool_failed", tool=tool_block, approval=approval,
                      outcome=Outcome(status="failed", error=str(exc),
                                      duration_ms=int((time.monotonic() - started) * 1000)))
            return GatewayResult("failed", action_id=action_id, reason=str(exc))
        duration = int((time.monotonic() - started) * 1000)
        summary, swept = redact_payload(summarize_result(spec.name, result),
                                        set(), self.hmac_key)
        self.emit(ctx, "tool_executed", tool=tool_block, approval=approval,
                  outcome=Outcome(status="completed",
                                  downstream_receipt=result.get("receipt"),
                                  duration_ms=duration),
                  data={"result_summary": summary,
                        "result_sensitive_fields": swept})
        return GatewayResult("executed", output=result, action_id=action_id)

    # -- human decision ----------------------------------------------------------
    def decide(self, approval_id: str, approver: str, decision: str) -> GatewayResult:
        record = self.store.get_approval(approval_id)
        if not record:
            return GatewayResult("failed", reason=f"unknown approval {approval_id}")
        if record["status"] != "pending":
            return GatewayResult("failed", approval_id=approval_id,
                                 reason=f"approval already {record['status']}")
        ctx = self.contexts.get(record["session_id"])
        if ctx is None:
            return GatewayResult("failed", approval_id=approval_id,
                                 reason="session context unavailable")
        if approver == ctx.actor.user_id:
            # Separation of duties: the principal who requested an action can
            # never approve it — not even with a support_lead hat on.
            spec0 = TOOLS[record["tool_name"]]
            self.emit(ctx, "policy_evaluated",
                      tool=self._tool_block(spec0, "call_" + uuid.uuid4().hex[:12],
                                            record["args"], record["action_id"],
                                            record["action_version"]),
                      policy=Policy(verdict="deny", reason_code="SELF_APPROVAL",
                                    detail="approver is the requesting principal"))
            return GatewayResult("denied", approval_id=approval_id,
                                 action_id=record["action_id"],
                                 reason="SELF_APPROVAL: the requester cannot approve their own action")
        spec = TOOLS[record["tool_name"]]
        tool_block = self._tool_block(spec, "call_" + uuid.uuid4().hex[:12],
                                      record["args"], record["action_id"],
                                      record["action_version"])
        approval_block = Approval(approval_id=approval_id, approver=approver,
                                  decision=decision,
                                  approved_action_digest=record["action_digest"],
                                  expires_at=record["expires_at"])
        if decision != "granted":
            self.store.decide_approval(approval_id, "denied", approver, now_utc())
            self.emit(ctx, "approval_denied", tool=tool_block, approval=approval_block,
                      decision_summary=f"{approver} denied the proposed action.")
            return GatewayResult("denied", approval_id=approval_id,
                                 action_id=record["action_id"], reason="denied by approver")
        if record["expires_at"] and record["expires_at"] < now_utc():
            self.store.decide_approval(approval_id, "expired", approver, now_utc())
            self.emit(ctx, "approval_expired", tool=tool_block, approval=approval_block)
            return GatewayResult("failed", approval_id=approval_id,
                                 reason="approval expired")
        # Binding check: the stored digest must still match the stored action —
        # execution below uses the stored args, never fresh agent input, so an
        # approval can never be ridden by a modified amount or target.
        digest = hash_object({"tool": record["tool_name"], "args": record["args"],
                              "target": tool_block.target})
        if digest != record["action_digest"]:
            return GatewayResult("failed", approval_id=approval_id,
                                 reason="action digest mismatch — approval does not cover this action")
        self.store.decide_approval(approval_id, "granted", approver, now_utc())
        self.emit(ctx, "approval_granted", tool=tool_block, approval=approval_block,
                  decision_summary=f"{approver} approved action {record['action_id']} v{record['action_version']} exactly as proposed.")
        killed = self.policy.kill_state(ctx.session_id, record["tool_name"])
        if killed:
            self.emit(ctx, "policy_evaluated", tool=tool_block,
                      policy=Policy(verdict="deny",
                                    reason_code=f"KILL_SWITCH_{killed.upper()}",
                                    detail="kill switch engaged between approval and execution"))
            return GatewayResult("denied", approval_id=approval_id,
                                 reason="kill switch engaged before execution")
        return self._execute(ctx, spec, record["args"], tool_block,
                             tool_block.tool_call_id, record["action_id"],
                             approval=approval_block)

    # -- session close + seal ---------------------------------------------------------
    def close_session(self, ctx: SessionContext) -> dict:
        from .chain import seal_session
        self.emit(ctx, "session_completed",
                  decision_summary="Session closed; sealing the trail.")
        return seal_session(self.store, self.writer.signer, ctx.session_id)

    def reload_policy(self, by_user: str, path: str | None = None) -> dict:
        config = self.policy.reload(path)
        ctx = self._system_ctx(by_user)
        self.emit(ctx, "policy_reloaded",
                  decision_summary=f"Policy hot-reloaded by {by_user}: {config.version} (preset: {config.preset}).",
                  data={"policy": config.as_dict()})
        return config.as_dict()

    # -- kill switch ----------------------------------------------------------------
    def set_kill(self, scope: str, active: bool, by_user: str,
                 session_id: str | None = None, tool_name: str | None = None) -> str:
        if scope == "session":
            key, ctx = f"kill:session:{session_id}", self.contexts.get(session_id or "")
        elif scope == "tool":
            key, ctx = f"kill:tool:{tool_name}", None
        else:
            key, ctx = "kill:global", None
        self.store.set_flag(key, "on" if active else "off", now_utc(), by_user)
        event_ctx = ctx or self._system_ctx(by_user)
        self.emit(event_ctx,
                  "kill_switch_activated" if active else "kill_switch_deactivated",
                  decision_summary=f"Kill switch ({scope}) {'engaged' if active else 'released'} by {by_user}.",
                  data={"scope": scope, "session_id": session_id,
                        "tool_name": tool_name})
        return key

    def _system_ctx(self, user: str) -> SessionContext:
        if "system" not in self.contexts:
            self.contexts["system"] = SessionContext(
                session_id="system",
                actor=Actor(user_id=user, role="admin"),
                config=Config(model_provider="none", model_id="none",
                              system_prompt_hash="sha256:system",
                              policy_version=self.policy.config.version))
        return self.contexts["system"]
