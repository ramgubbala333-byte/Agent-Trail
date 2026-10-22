"""The demo tool set — thin, least-privilege, MCP-style tools over the CRM.

Each tool declares: whether it writes, which argument fields are sensitive
(always redacted from the ledger), and a target template for the audit
record. Handlers return structured results plus a downstream receipt id for
writes — the receipt, not the agent's intent, is what the trail records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .bizdb import BusinessDB


class ToolError(Exception):
    pass


@dataclass
class ToolSpec:
    name: str
    write: bool
    handler: Callable[[BusinessDB, dict, str], dict]
    sensitive_fields: set[str] = field(default_factory=set)
    target_template: str = ""  # e.g. "crm://orders/{order_id}"


def _search_customers(db: BusinessDB, args: dict, _idem: str) -> dict:
    rows = db.search_customers(str(args.get("query", "")))
    return {"matches": rows, "count": len(rows)}


def _get_order(db: BusinessDB, args: dict, _idem: str) -> dict:
    order = db.get_order(int(args["order_id"]))
    if not order:
        raise ToolError(f"order {args['order_id']} not found")
    return {"order": order}


def _issue_refund(db: BusinessDB, args: dict, idem: str) -> dict:
    order = db.get_order(int(args["order_id"]))
    if not order:
        raise ToolError(f"order {args['order_id']} not found")
    amount = int(args["amount_cents"])
    if amount <= 0 or amount > order["amount_cents"]:
        raise ToolError(
            f"refund {amount} invalid for order total {order['amount_cents']}")
    receipt = db.record_refund(order["id"], amount, idem)
    return {"receipt": receipt, "order_id": order["id"], "amount_cents": amount}


def _update_ticket_priority(db: BusinessDB, args: dict, _idem: str) -> dict:
    ticket = db.get_ticket(int(args["ticket_id"]))
    if not ticket:
        raise ToolError(f"ticket {args['ticket_id']} not found")
    level = str(args["priority"]).lower()
    if level not in {"low", "normal", "high", "urgent"}:
        raise ToolError(f"invalid priority {level}")
    db.set_ticket_priority(ticket["id"], level)
    return {"receipt": f"TKT-{ticket['id']}", "ticket_id": ticket["id"],
            "priority": level}


def _create_internal_note(db: BusinessDB, args: dict, _idem: str) -> dict:
    ticket = db.get_ticket(int(args["ticket_id"]))
    if not ticket:
        raise ToolError(f"ticket {args['ticket_id']} not found")
    receipt = db.record_note(ticket["id"], str(args["body"]))
    return {"receipt": receipt, "ticket_id": ticket["id"]}


TOOLS: dict[str, ToolSpec] = {
    "search_customers": ToolSpec(
        "search_customers", write=False, handler=_search_customers,
        sensitive_fields={"query"}, target_template="crm://customers"),
    "get_order": ToolSpec(
        "get_order", write=False, handler=_get_order,
        target_template="crm://orders/{order_id}"),
    "issue_refund": ToolSpec(
        "issue_refund", write=True, handler=_issue_refund,
        sensitive_fields={"customer_id"},
        target_template="crm://orders/{order_id}"),
    "update_ticket_priority": ToolSpec(
        "update_ticket_priority", write=True, handler=_update_ticket_priority,
        target_template="crm://tickets/{ticket_id}"),
    "create_internal_note": ToolSpec(
        "create_internal_note", write=True, handler=_create_internal_note,
        target_template="crm://tickets/{ticket_id}"),
}


def summarize_result(tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Ledger-safe summary of a tool result — counts and ids, not raw bodies.
    Full payloads belong in a restricted evidence store, not the ledger."""
    if tool_name == "search_customers":
        return {"count": result["count"],
                "customer_ids": [m["id"] for m in result["matches"]]}
    if tool_name == "get_order":
        o = result["order"]
        return {"order_id": o["id"], "status": o["status"],
                "amount_cents": o["amount_cents"]}
    return {k: v for k, v in result.items() if k != "body"}
