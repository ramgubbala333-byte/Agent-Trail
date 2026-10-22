"""Deterministic policy — now policy-as-code.

The working products converged on declarative, versioned policy that lives
outside the model and outside the code: Galileo Agent Control ships JSON
rules hot-reloaded fleet-wide; InALign ships presets (STRICT_ENTERPRISE /
BALANCED / DEV_SANDBOX). AgentTrail does the same: a JSON policy file
(``AGENTTRAIL_POLICY_FILE``) over a named preset, stamped into every event
as ``policy_version`` so a policy change is itself visible in the trail.

All enforcement stays in plain deterministic functions. The model cannot
choose its own approval path.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

READ_TOOLS = {"search_customers", "get_order"}
WRITE_TOOLS = {"issue_refund", "update_ticket_priority", "create_internal_note"}

PRESETS: dict[str, dict] = {
    "strict_enterprise": {
        "refund_approval_threshold_cents": 0,      # every refund needs a human
        "session_budget_usd": 0.25,
        "max_steps": 15,
    },
    "balanced": {
        "refund_approval_threshold_cents": 2500,   # > $25.00 needs a human
        "session_budget_usd": 0.50,
        "max_steps": 25,
    },
    "dev_sandbox": {
        "refund_approval_threshold_cents": 100_000,
        "session_budget_usd": 5.00,
        "max_steps": 100,
    },
}

DEFAULT_ROLE_TOOLS: dict[str, set[str]] = {
    "support_agent": READ_TOOLS | WRITE_TOOLS,
    "support_lead": READ_TOOLS | WRITE_TOOLS,
    "viewer": set(),  # can look, cannot act — every proposal is denied + logged
}


@dataclass
class PolicyConfig:
    policy_id: str = "support-policy"
    version: str = "support-policy-v4"
    preset: str = "balanced"
    refund_approval_threshold_cents: int = 2500
    session_budget_usd: float = 0.50
    max_steps: int = 25
    role_tools: dict[str, set[str]] = field(
        default_factory=lambda: {k: set(v) for k, v in DEFAULT_ROLE_TOOLS.items()})

    def as_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "preset": self.preset,
            "refund_approval_threshold_cents": self.refund_approval_threshold_cents,
            "session_budget_usd": self.session_budget_usd,
            "max_steps": self.max_steps,
            "role_tools": {k: sorted(v) for k, v in self.role_tools.items()},
        }


def load_policy_config(path: str | Path | None = None) -> PolicyConfig:
    """Preset first, then file keys override. Unknown presets are rejected —
    a typo must fail loudly at startup, never silently loosen policy."""
    cfg = PolicyConfig()
    file_path = path or os.environ.get("AGENTTRAIL_POLICY_FILE")
    data: dict = {}
    if file_path:
        data = json.loads(Path(file_path).read_text())
    preset_name = data.get("preset", cfg.preset)
    if preset_name not in PRESETS:
        raise ValueError(f"unknown policy preset: {preset_name}")
    for key, value in PRESETS[preset_name].items():
        setattr(cfg, key, value)
    cfg.preset = preset_name
    for key in ("policy_id", "version", "refund_approval_threshold_cents",
                "session_budget_usd", "max_steps"):
        if key in data:
            setattr(cfg, key, data[key])
    if "role_tools" in data:
        cfg.role_tools = {k: set(v) for k, v in data["role_tools"].items()}
    return cfg


# Backwards-compatible exports (default/balanced view of the world).
DEFAULT_CONFIG = PolicyConfig()
POLICY_ID = DEFAULT_CONFIG.policy_id
POLICY_VERSION = DEFAULT_CONFIG.version
ROLE_TOOLS = DEFAULT_CONFIG.role_tools
REFUND_APPROVAL_THRESHOLD_CENTS = DEFAULT_CONFIG.refund_approval_threshold_cents
DEFAULT_SESSION_BUDGET_USD = DEFAULT_CONFIG.session_budget_usd
DEFAULT_MAX_STEPS = DEFAULT_CONFIG.max_steps


@dataclass
class PolicyDecision:
    verdict: str  # allow | deny | require_approval
    reason_code: str
    detail: str = ""


class PolicyEngine:
    def __init__(self, store, config: PolicyConfig | None = None):
        self.store = store  # for kill-switch flags
        self.config = config or PolicyConfig()

    def reload(self, path: str | Path | None = None) -> PolicyConfig:
        """Hot-reload policy from file — no redeploy, and the caller seals a
        policy_reloaded event so the change is part of the record."""
        self.config = load_policy_config(path)
        return self.config

    # -- kill switch -------------------------------------------------------
    def kill_state(self, session_id: str, tool_name: str) -> str | None:
        if self.store.get_flag("kill:global") == "on":
            return "global"
        if self.store.get_flag(f"kill:session:{session_id}") == "on":
            return "session"
        if self.store.get_flag(f"kill:tool:{tool_name}") == "on":
            return "tool"
        return None

    # -- main evaluation -----------------------------------------------------
    def evaluate(self, *, role: str, session_id: str, tool_name: str,
                 args: dict, write: bool, session_cost_usd: float,
                 budget_usd: float | None = None,
                 steps: int = 0, max_steps: int | None = None) -> PolicyDecision:
        cfg = self.config
        budget_usd = cfg.session_budget_usd if budget_usd is None else budget_usd
        max_steps = cfg.max_steps if max_steps is None else max_steps
        killed = self.kill_state(session_id, tool_name)
        if killed:
            return PolicyDecision("deny", f"KILL_SWITCH_{killed.upper()}",
                                  f"kill switch active at {killed} scope")
        if steps >= max_steps:
            return PolicyDecision("deny", "MAX_STEPS_EXCEEDED",
                                  f"session reached {max_steps} steps")
        if session_cost_usd >= budget_usd:
            return PolicyDecision("deny", "BUDGET_EXCEEDED",
                                  f"session cost ${session_cost_usd:.4f} >= budget ${budget_usd:.2f}")
        allowed = cfg.role_tools.get(role, set())
        if tool_name not in allowed:
            return PolicyDecision("deny", "NOT_ENTITLED",
                                  f"role {role} may not call {tool_name}")
        if (tool_name == "issue_refund"
                and int(args.get("amount_cents", 0)) > cfg.refund_approval_threshold_cents):
            return PolicyDecision(
                "require_approval", "WRITE_OVER_THRESHOLD",
                f"refund ${int(args.get('amount_cents', 0)) / 100:.2f} exceeds "
                f"${cfg.refund_approval_threshold_cents / 100:.2f} auto-approval "
                f"threshold (preset: {cfg.preset})")
        return PolicyDecision("allow", "OK",
                              "within entitlement, thresholds and budget")
