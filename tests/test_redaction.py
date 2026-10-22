"""Secrets and PII must never reach the sealed trail — redaction happens in
the interceptor, before persistence, and the trail records *that* fields
were redacted without revealing them."""

import json


def _all_payloads(stack):
    return json.dumps(stack.store.session_events("sess_test"))


def test_sensitive_arg_is_hashed_not_stored(stack):
    ctx = stack.session()
    res = stack.gateway.propose(ctx, "search_customers",
                                {"query": "priya.nair@example.com"})
    assert res.status == "executed"
    payloads = _all_payloads(stack)
    assert "priya.nair@example.com" not in payloads
    proposed = next(e for e in stack.store.session_events("sess_test")
                    if e["event_type"] == "tool_proposed")
    assert proposed["tool"]["args_redacted"]["query"] == "[HASHED]"
    assert "query" in proposed["tool"]["sensitive_fields"]
    assert proposed["tool"]["args_redacted"]["query_hmac"].startswith("hmac:")


def test_connection_string_in_tool_args_is_swept(stack):
    ctx = stack.session()
    secret = "postgres://admin:hunter2@db.internal:5432/crm"
    res = stack.gateway.propose(
        ctx, "create_internal_note",
        {"ticket_id": 501, "body": f"creds for repro: {secret}"})
    assert res.status == "executed"
    payloads = _all_payloads(stack)
    assert "hunter2" not in payloads
    assert "postgres://" not in payloads
    assert "[REDACTED]" in payloads


def test_card_number_in_message_is_swept(stack):
    ctx = stack.session()
    stack.loop.handle_message(ctx, "note on ticket 501: card 4242 4242 4242 4242 declined")
    assert "4242 4242" not in _all_payloads(stack)
