"""AgentTrail — tamper-evident audit trails for AI agents.

An MCP-style agent where every action produces a signed, hash-chained,
replayable audit record. The audit layer lives outside the agent: the agent
proposes, a deterministic policy gateway decides, and only the audit service
can write the trail.
"""

__version__ = "0.2.0"
SCHEMA_VERSION = "1.0"
