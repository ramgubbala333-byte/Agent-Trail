"""The audit event model — one schema shared by producer, store and auditor.

Design rule: start from the questions a reviewer must answer — *identity,
authority, action, outcome* — for a specific business operation, then extend
with agent-specific configuration and workflow evidence. Recommendation,
policy decision, human review and downstream result are separate records: a
model saying "this was approved" is not evidence of approval.

The ``integrity`` block is added by the audit layer only. Nothing in the
agent process can set it.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from . import SCHEMA_VERSION


def uuid7() -> str:
    """Time-ordered UUID (v7 layout) — sortable event ids without a library."""
    ms = int(time.time() * 1000)
    rand = uuid.uuid4().int
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76  # version
    value |= (rand >> 4) & ((1 << 12) - 1)
    value |= 0b10 << 62  # variant
    value |= rand & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Actor(BaseModel):
    user_id: str  # human principal (pseudonymized upstream if required)
    tenant_id: str = "default"
    role: str
    agent_id: str = "support-agent"
    agent_version: str = "0.1.0"
    workload_identity: str = "svc-agenttrail"  # identity the process runs as
    delegated_scope: list[str] = Field(default_factory=list)


class Config(BaseModel):
    model_provider: str
    model_id: str  # exact revision, never a floating alias where avoidable
    temperature: float = 0.0
    system_prompt_hash: str
    prompt_version: str = "support-v1"
    tool_registry_version: str = "tools-2026-10-21"
    policy_id: str = "support-policy"
    policy_version: str


class ToolCall(BaseModel):
    mcp_server: str = "crm-mcp@0.1.0"
    tool_name: str
    tool_call_id: str
    action_id: Optional[str] = None  # proposal id for writes, e.g. "A-3"
    action_version: Optional[int] = None
    target: Optional[str] = None  # e.g. "crm://orders/8841"
    write: bool = False
    args_redacted: dict[str, Any] = Field(default_factory=dict)
    args_hash: Optional[str] = None
    sensitive_fields: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    verdict: str  # allow | deny | require_approval
    reason_code: str
    detail: Optional[str] = None


class Approval(BaseModel):
    approval_id: str
    approver: Optional[str] = None
    decision: Optional[str] = None  # granted | denied
    approved_action_digest: Optional[str] = None
    expires_at: Optional[str] = None


class Outcome(BaseModel):
    status: str  # completed | rejected | uncertain | failed
    downstream_receipt: Optional[str] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    session_cost_usd: float = 0.0
    pricing_version: str = "demo-pricing-v1"


class Integrity(BaseModel):
    prev_hash: str
    event_hash: str
    signer_key_id: str
    signature: str


class AuditEvent(BaseModel):
    """One ledger record. ``integrity`` is None until the audit writer seals it."""

    event_id: str = Field(default_factory=uuid7)
    schema_version: str = SCHEMA_VERSION
    event_type: str
    event_time_utc: str = Field(default_factory=now_utc)
    ingested_at_utc: Optional[str] = None  # set by the audit writer
    sequence_no: Optional[int] = None  # per-session, set by the audit writer
    session_id: str
    trace_id: str
    parent_event_id: Optional[str] = None

    actor: Optional[Actor] = None
    config: Optional[Config] = None
    decision_summary: Optional[str] = None  # reviewer-facing, never raw CoT
    tool: Optional[ToolCall] = None
    policy: Optional[Policy] = None
    approval: Optional[Approval] = None
    outcome: Optional[Outcome] = None
    usage: Optional[Usage] = None
    data: dict[str, Any] = Field(default_factory=dict)  # event-type-specific evidence

    integrity: Optional[Integrity] = None

    def unsigned_dict(self) -> dict[str, Any]:
        """The event exactly as it enters the hash chain (no integrity block)."""
        d = self.model_dump(exclude_none=True)
        d.pop("integrity", None)
        return d
