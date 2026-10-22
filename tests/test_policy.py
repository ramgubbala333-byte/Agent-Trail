"""Policy gateway: entitlements, approval binding, kill switch, budgets.
Denials are evidence too — every one of them must land in the trail."""

from agenttrail.chain import verify_session


def _types(stack):
    return [e["event_type"] for e in stack.store.session_events("sess_test")]


def test_viewer_is_denied_and_denial_is_logged(stack):
    ctx = stack.session(role="viewer")
    res = stack.gateway.propose(ctx, "get_order", {"order_id": 8841})
    assert res.status == "denied"
    assert "NOT_ENTITLED" in res.reason
    assert "tool_executed" not in _types(stack)
    evaluated = [e for e in stack.store.session_events("sess_test")
                 if e["event_type"] == "policy_evaluated"]
    assert evaluated[-1]["policy"]["verdict"] == "deny"


def test_small_refund_auto_executes(stack):
    ctx = stack.session()
    res = stack.gateway.propose(ctx, "issue_refund",
                                {"order_id": 8841, "amount_cents": 1000})
    assert res.status == "executed"
    assert res.output["receipt"] == "RF-1001"


def test_large_refund_requires_approval_then_executes_exactly(stack):
    ctx = stack.session()
    res = stack.gateway.propose(ctx, "issue_refund",
                                {"order_id": 8841, "amount_cents": 4200})
    assert res.status == "pending_approval"
    # Nothing executed yet — the money has not moved.
    assert stack.bizdb._conn.execute("SELECT COUNT(*) c FROM refunds").fetchone()["c"] == 0

    done = stack.gateway.decide(res.approval_id, "j.ribeiro@example.com", "granted")
    assert done.status == "executed"
    assert done.action_id == res.action_id
    row = stack.bizdb._conn.execute("SELECT * FROM refunds").fetchone()
    assert row["amount_cents"] == 4200  # exactly the approved amount

    types = _types(stack)
    assert "approval_requested" in types and "approval_granted" in types
    assert verify_session(stack.store, "sess_test")["valid"]


def test_approval_cannot_be_reused_or_ridden_by_a_new_amount(stack):
    ctx = stack.session()
    first = stack.gateway.propose(ctx, "issue_refund",
                                  {"order_id": 8841, "amount_cents": 4200})
    second = stack.gateway.propose(ctx, "issue_refund",
                                   {"order_id": 8841, "amount_cents": 9900})
    assert first.approval_id != second.approval_id

    granted = stack.gateway.decide(first.approval_id, "lead@example.com", "granted")
    assert granted.status == "executed"
    amounts = [r["amount_cents"] for r in
               stack.bizdb._conn.execute("SELECT amount_cents FROM refunds").fetchall()]
    assert amounts == [4200]  # the $99 action did not ride the $42 approval

    again = stack.gateway.decide(first.approval_id, "lead@example.com", "granted")
    assert again.status == "failed"  # an approval executes once, never twice


def test_denied_approval_executes_nothing(stack):
    ctx = stack.session()
    res = stack.gateway.propose(ctx, "issue_refund",
                                {"order_id": 8842, "amount_cents": 5000})
    done = stack.gateway.decide(res.approval_id, "lead@example.com", "denied")
    assert done.status == "denied"
    assert stack.bizdb._conn.execute("SELECT COUNT(*) c FROM refunds").fetchone()["c"] == 0
    assert "approval_denied" in _types(stack)


def test_kill_switch_halts_session_and_is_audited(stack):
    ctx = stack.session()
    stack.gateway.set_kill("session", True, "ops-admin", session_id="sess_test")
    res = stack.gateway.propose(ctx, "get_order", {"order_id": 8841})
    assert res.status == "denied"
    assert "KILL_SWITCH_SESSION" in res.reason
    stack.gateway.set_kill("session", False, "ops-admin", session_id="sess_test")
    res2 = stack.gateway.propose(ctx, "get_order", {"order_id": 8841})
    assert res2.status == "executed"
    assert "kill_switch_activated" in _types(stack)


def test_budget_cap_denies_and_logs(stack):
    ctx = stack.session()
    ctx.session_cost_usd = 999.0
    res = stack.gateway.propose(ctx, "get_order", {"order_id": 8841})
    assert res.status == "denied"
    assert "BUDGET_EXCEEDED" in res.reason
    assert "budget_exceeded" in _types(stack)
