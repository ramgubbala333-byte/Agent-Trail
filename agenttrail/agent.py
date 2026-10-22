"""The agent loop — deliberately simple and hand-written.

The point of this project is the interceptor boundary, so the loop is kept
boring: a planner proposes tool calls, the gateway disposes. Two planners:

- ``ScriptedPlanner`` — deterministic intent parser for the demo domain.
  Its events honestly record ``model_id: scripted-planner-v1``; it stands in
  for an LLM so the full audit story runs with no API key.
- ``LLMPlanner`` — an OpenAI-compatible tool-calling planner, used when
  ``AGENTTRAIL_LLM_API_KEY`` is set. Real model id and token usage are
  recorded per call.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

import httpx

from .canonical import hash_object
from .events import Usage
from .gateway import Gateway, GatewayResult, SessionContext
from .redact import redact_payload

# Demo pricing table (PRICING_VERSION in events.Usage) — illustrative rates.
PRICE_IN_PER_1K = 0.003
PRICE_OUT_PER_1K = 0.015


@dataclass
class PlannedCall:
    tool_name: str
    args: dict
    summary: str


class ScriptedPlanner:
    model_provider = "agenttrail-demo"
    model_id = "scripted-planner-v1"

    def plan(self, message: str) -> list[PlannedCall]:
        m = message.lower()
        calls: list[PlannedCall] = []
        s = re.search(r"(?:find|search|look up)(?: for)?\s+(?:customer\s+)?([a-z][a-z\s.'@-]{1,40})", m)
        if s and "ticket" not in s.group(1):
            q = re.split(r"\s+and\s+", s.group(1))[0].strip().rstrip(".,")
            calls.append(PlannedCall("search_customers", {"query": q},
                                     f"Look up customer matching '{q}'."))
        r = re.search(r"refund\s+(?:order\s+)?#?(\d+)\s+\$?(\d+(?:\.\d{1,2})?)", m)
        o = re.search(r"(?:check|show|get|look up)?\s*order\s+#?(\d+)", m)
        if o and not r:
            calls.append(PlannedCall("get_order", {"order_id": int(o.group(1))},
                                     f"Fetch order {o.group(1)}."))
        n = re.search(r"note on ticket\s+(\d+):\s*(.+)", message, re.IGNORECASE)
        if n:
            calls.append(PlannedCall("create_internal_note",
                                     {"ticket_id": int(n.group(1)),
                                      "body": n.group(2).strip()},
                                     f"Add internal note to ticket {n.group(1)}."))
        p = re.search(r"ticket\s+(\d+)\s+(?:priority\s+)?(?:to\s+)?(low|normal|high|urgent)", m)
        if p:
            calls.append(PlannedCall("update_ticket_priority",
                                     {"ticket_id": int(p.group(1)),
                                      "priority": p.group(2)},
                                     f"Set ticket {p.group(1)} priority to {p.group(2)}."))
        if r:
            cents = int(round(float(r.group(2)) * 100))
            calls.append(PlannedCall("issue_refund",
                                     {"order_id": int(r.group(1)),
                                      "amount_cents": cents},
                                     f"Refund ${cents / 100:.2f} on order {r.group(1)}."))
        return calls

    def usage_for(self, message: str, calls: list[PlannedCall]) -> Usage:
        in_tok = 600 + len(message) // 4
        out_tok = 90 + 40 * len(calls)
        cost = in_tok / 1000 * PRICE_IN_PER_1K + out_tok / 1000 * PRICE_OUT_PER_1K
        return Usage(input_tokens=in_tok, output_tokens=out_tok, cost_usd=round(cost, 6))


class LLMPlanner:
    """OpenAI-compatible chat-completions planner with tool calling."""

    def __init__(self):
        self.base = os.environ.get("AGENTTRAIL_LLM_BASE_URL", "https://api.openai.com/v1")
        self.key = os.environ["AGENTTRAIL_LLM_API_KEY"]
        self.model_id = os.environ.get("AGENTTRAIL_LLM_MODEL", "gpt-5-mini")
        self.model_provider = "openai-compatible"
        self._last_usage = Usage()

    def plan(self, message: str) -> list[PlannedCall]:
        from .tools import TOOLS
        tools = [{
            "type": "function",
            "function": {"name": name,
                         "description": f"{'Write' if spec.write else 'Read'} tool {name}",
                         "parameters": {"type": "object", "properties": {}, "required": []}},
        } for name, spec in TOOLS.items()]
        resp = httpx.post(
            f"{self.base}/chat/completions",
            headers={"Authorization": f"Bearer {self.key}"},
            json={"model": self.model_id, "temperature": 0,
                  "messages": [{"role": "user", "content": message}],
                  "tools": tools},
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()
        u = body.get("usage", {})
        in_tok, out_tok = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        self._last_usage = Usage(
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=round(in_tok / 1000 * PRICE_IN_PER_1K
                           + out_tok / 1000 * PRICE_OUT_PER_1K, 6))
        calls = []
        for tc in body["choices"][0]["message"].get("tool_calls") or []:
            fn = tc["function"]
            calls.append(PlannedCall(fn["name"], json.loads(fn["arguments"] or "{}"),
                                     f"Model selected {fn['name']}."))
        return calls

    def usage_for(self, message: str, calls: list[PlannedCall]) -> Usage:
        return self._last_usage


def make_planner():
    if os.environ.get("AGENTTRAIL_LLM_API_KEY"):
        return LLMPlanner()
    return ScriptedPlanner()


class AgentLoop:
    def __init__(self, gateway: Gateway, planner, hmac_key: bytes):
        self.gateway = gateway
        self.planner = planner
        self.hmac_key = hmac_key

    def handle_message(self, ctx: SessionContext, message: str) -> dict:
        swept, _ = redact_payload({"message": message}, set(), self.hmac_key)
        self.gateway.emit(ctx, "request_received",
                          decision_summary="User request received.",
                          data={"message_redacted": swept["message"],
                                "message_hash": hash_object({"m": message})})
        calls = self.planner.plan(message)
        if not calls:
            reply = ("I can look up customers and orders, issue refunds, set ticket "
                     "priority, and add ticket notes — try: 'Find customer Priya, "
                     "check order 8841 and refund order 8841 $42'.")
            self.gateway.emit(ctx, "output_delivered",
                              decision_summary="No tool call required.",
                              data={"output_hash": hash_object({"o": reply})})
            return {"reply": reply, "results": []}

        usage = self.planner.usage_for(message, calls)
        ctx.session_cost_usd = round(ctx.session_cost_usd + usage.cost_usd, 6)
        usage.session_cost_usd = ctx.session_cost_usd
        self.gateway.emit(ctx, "model_invoked", usage=usage,
                          decision_summary=f"Planner proposed {len(calls)} tool call(s): "
                                           + "; ".join(c.summary for c in calls))

        results: list[dict] = []
        lines: list[str] = []
        for call in calls:
            res: GatewayResult = self.gateway.propose(ctx, call.tool_name, call.args,
                                                      call.summary)
            entry = {"tool": call.tool_name, "status": res.status,
                     "action_id": res.action_id, "approval_id": res.approval_id,
                     "reason": res.reason}
            if res.status == "executed":
                entry["output"] = res.output
                receipt = (res.output or {}).get("receipt")
                lines.append(f"✓ {call.tool_name} completed"
                             + (f" (receipt {receipt})" if receipt else "")
                             + f" — {json.dumps(res.output, default=str)[:220]}")
            elif res.status == "pending_approval":
                lines.append(f"⏸ {call.tool_name} needs human approval "
                             f"({res.approval_id}): {res.reason}")
                entry["output"] = None
            elif res.status == "denied":
                lines.append(f"⛔ {call.tool_name} denied by policy — {res.reason}")
                entry["output"] = None
            else:
                lines.append(f"✗ {call.tool_name} failed — {res.reason}")
                entry["output"] = None
            results.append(entry)
            if res.status in {"pending_approval", "denied"}:
                break  # stop the run: later steps may depend on this one

        reply = "\n".join(lines)
        self.gateway.emit(ctx, "output_delivered",
                          decision_summary="Reply composed from verified tool outcomes.",
                          data={"output_hash": hash_object({"o": reply})})
        return {"reply": reply, "results": results}
