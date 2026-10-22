import hashlib

import pytest

from agenttrail.agent import AgentLoop, ScriptedPlanner
from agenttrail.bizdb import BusinessDB
from agenttrail.canonical import hash_object
from agenttrail.chain import AuditWriter
from agenttrail.events import Actor, Config
from agenttrail.gateway import Gateway, SessionContext
from agenttrail.keys import Signer
from agenttrail.policy import POLICY_VERSION, PolicyEngine, ROLE_TOOLS
from agenttrail.store import AuditStore

HMAC_KEY = hashlib.sha256(b"test-hmac-key").digest()
PROMPT_HASH = hash_object({"prompt": "test"})


class Stack:
    def __init__(self, tmp_path):
        self.store = AuditStore(tmp_path / "audit.db")
        self.signer = Signer(tmp_path / "signer.key")
        self.writer = AuditWriter(self.store, self.signer)
        self.bizdb = BusinessDB(tmp_path / "biz.db")
        self.policy = PolicyEngine(self.store)
        self.gateway = Gateway(self.writer, self.store, self.policy,
                               self.bizdb, HMAC_KEY)
        self.loop = AgentLoop(self.gateway, ScriptedPlanner(), HMAC_KEY)

    def session(self, role="support_agent", user="u_test_1") -> SessionContext:
        ctx = SessionContext(
            session_id="sess_test",
            actor=Actor(user_id=user, role=role,
                        delegated_scope=sorted(ROLE_TOOLS.get(role, set()))),
            config=Config(model_provider="agenttrail-demo",
                          model_id="scripted-planner-v1",
                          system_prompt_hash=PROMPT_HASH,
                          policy_version=POLICY_VERSION),
        )
        self.gateway.start_session(ctx)
        return ctx


@pytest.fixture()
def stack(tmp_path):
    return Stack(tmp_path)
