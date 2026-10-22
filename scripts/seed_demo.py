"""Seed a demo database with the full story — reads, a DENIED attempt, an
approved refund, a kill-switch halt — then seal one session and verify all.

    python scripts/seed_demo.py [data_dir]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agenttrail.agent import AgentLoop, ScriptedPlanner  # noqa: E402
from agenttrail.bizdb import BusinessDB  # noqa: E402
from agenttrail.canonical import hash_object  # noqa: E402
from agenttrail.chain import AuditWriter, verify_session  # noqa: E402
from agenttrail.events import Actor, Config  # noqa: E402
from agenttrail.gateway import Gateway, SessionContext  # noqa: E402
from agenttrail.keys import Signer  # noqa: E402
from agenttrail.policy import PolicyEngine, load_policy_config  # noqa: E402
from agenttrail.store import AuditStore  # noqa: E402
import hashlib  # noqa: E402

HMAC = hashlib.sha256(b"dev-hmac-key").digest()


def make_ctx(gateway, sid, role, user):
    cfg = load_policy_config()
    ctx = SessionContext(
        session_id=sid,
        actor=Actor(user_id=user, role=role,
                    delegated_scope=sorted(cfg.role_tools.get(role, set()))),
        config=Config(model_provider="agenttrail-demo",
                      model_id="scripted-planner-v1",
                      system_prompt_hash=hash_object({"prompt": "seed"}),
                      policy_version=cfg.version),
        budget_usd=cfg.session_budget_usd, max_steps=cfg.max_steps)
    gateway.start_session(ctx)
    return ctx


def main() -> int:
    data = Path(sys.argv[1] if len(sys.argv) > 1 else "data")
    data.mkdir(parents=True, exist_ok=True)
    store = AuditStore(data / "audit.db")
    writer = AuditWriter(store, Signer(data / "signer.key"))
    gateway = Gateway(writer, store, PolicyEngine(store, load_policy_config()),
                      BusinessDB(data / "biz.db"), HMAC)
    loop = AgentLoop(gateway, ScriptedPlanner(), HMAC)

    main_ctx = make_ctx(gateway, "sess_demo_main", "support_agent", "u_demo_221")
    loop.handle_message(main_ctx, "Find customer Priya and check order 8841")
    pending = loop.handle_message(main_ctx, "refund order 8841 $42")
    approval_id = pending["results"][0]["approval_id"]
    gateway.decide(approval_id, "j.ribeiro@example.com", "granted")
    seal = gateway.close_session(main_ctx)
    print(f"sess_demo_main: approved refund executed, sealed "
          f"({seal['event_count']} events, root {seal['merkle_root'][:19]}…)")

    viewer = make_ctx(gateway, "sess_demo_denied", "viewer", "u_demo_309")
    res = loop.handle_message(viewer, "check order 8842")
    print(f"sess_demo_denied: viewer attempt -> {res['results'][0]['status']} "
          f"({res['results'][0]['reason'][:60]}…)")

    killed = make_ctx(gateway, "sess_demo_killed", "support_agent", "u_demo_221")
    gateway.set_kill("session", True, "ops-admin", session_id="sess_demo_killed")
    res = gateway.propose(killed, "get_order", {"order_id": 8841})
    print(f"sess_demo_killed: propose under kill switch -> {res.status} ({res.reason})")

    ok = True
    for s in store.list_sessions():
        r = verify_session(store, s["session_id"])
        print(f"  verify {s['session_id']}: valid={r['valid']} "
              f"seal={(r.get('seal') or {}).get('status')}")
        ok = ok and r["valid"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
