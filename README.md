# AgentTrail

**Tamper-evident audit trails for AI agents.** Every action an agent takes — every tool it proposes, every policy decision, every human approval, every execution and its downstream receipt — is written into a signed, hash-chained, replayable record that the agent itself cannot write, edit, or quietly skip.

> The MCP specification requires no audit logging at all. Observability tools give you sampled, mutable traces that expire in weeks. When an agent refunds the wrong customer at 3 a.m., neither one answers the only question that matters: *who asked for this, under what authority, with what inputs, what policy allowed it, who approved it — and how do you know the record wasn't edited afterwards?* AgentTrail is built to answer exactly that.

![status](https://img.shields.io/badge/status-0.2.0-blue) ![python](https://img.shields.io/badge/python-3.11%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## What it proves — and what it doesn't

A verified AgentTrail record proves **attribution, integrity and ordering**: this principal, under this delegated scope, with this exact model revision, prompt version and policy version, proposed this exact action; this deterministic policy verdict followed; this named human approved this exact action digest; the downstream system returned this receipt — and no event in the chain has been altered, reordered, inserted or deleted since it was sealed.

It does **not** prove the action was *correct*, the model's reasoning was sound, or the organization is compliant with any regulation. Signatures prove the record is authentic, not that the decision was right. AgentTrail implements Article 12-style automatic, tamper-evident record-keeping patterns (EU AI Act); compliance is an organizational determination, not a library feature.

## How it works

```
                ┌──────────────────────── Agent process ────────────────────────┐
                │  Planner (LLM or scripted)  ── proposes tool calls ──┐        │
                └──────────────────────────────────────────────────────┼────────┘
                                                                       ▼
   ┌────────────────────── Policy gateway (deterministic, outside the agent) ───────────────┐
   │  1. tool_proposed        — arguments redacted, then sealed                            │
   │  2. policy_evaluated     — entitlement · threshold · budget · kill switch             │
   │  3a. deny                — nothing executes; the denial is evidence                   │
   │  3b. require_approval    — proposal frozen as action A-n v1 + digest; a named human   │
   │                            approves *that exact digest*; any change = new proposal    │
   │  3c. allow → execute     — execute-once, idempotency key, downstream receipt recorded │
   └──────────────────────────────────────┬───────────────────────────────────────────────┘
                                          ▼
   ┌────────────────────── Audit service (separate identity) ──────────────────────────────┐
   │  redact → RFC 8785 canonical JSON → SHA-256 hash chain (per session) → Ed25519 sign → │
   │  append-only store. The agent's credentials are denied write access to the trail.     │
   └──────────────────────────────────────┬───────────────────────────────────────────────┘
                                          ▼
        Auditor API: replay any session · verify the chain · export an evidence
        bundle that verifies offline. Reading the trail is itself audited.
```

**Fail closed.** If an audit write fails, the action does not execute. There is no `try: audit(); except: pass` anywhere in the consequential path — silent audit loss is treated as a system failure, not a logging inconvenience.

## The demo story (2 minutes)

A support-ops agent works over a seeded CRM (customers, orders, tickets):

| Tool | Type | Policy |
|---|---|---|
| `search_customers` | read | entitled roles |
| `get_order` | read | entitled roles |
| `create_internal_note` | write | auto-allowed |
| `update_ticket_priority` | write | auto-allowed |
| `issue_refund` | write | **human approval required above $25** |

```bash
pip install -e ".[dev]"
uvicorn agenttrail.app:app --port 8000
./scripts/demo.sh        # in a second terminal
```

The script opens a session, runs reads, requests a **$42 refund** (it pauses — nothing executes), a named human approves the exact action, the refund executes with receipt `RF-1001`, the session is replayed and verified. Then it copies the database, edits one sealed event, and verification **fails at exactly that sequence number**:

```bash
python scripts/tamper_demo.py data/audit.db <session_id>
# Original trail:   valid=True   events=17
# Tampered copy:    valid=False  failed_at_sequence=11
#                   reason=event_hash mismatch — payload was modified after sealing
```

## Event schema

One Pydantic model shared by producer, store and auditor (`agenttrail/events.py`). Sixteen event types — `session_started`, `request_received`, `model_invoked`, `retrieval_performed`, `tool_proposed`, `policy_evaluated`, `approval_requested`, `approval_granted` / `approval_denied` / `approval_expired`, `tool_executed`, `tool_failed`, `data_accessed`, `guardrail_evaluated`, `output_delivered`, `budget_exceeded` / `kill_switch_activated`, `session_completed`, `audit_accessed` — each carrying, as applicable:

- **Envelope** — time-ordered `event_id` (UUIDv7 layout), per-session `sequence_no`, `trace_id`, `parent_event_id`, both event time and ingestion time (server-side UTC; the agent's clock is never trusted).
- **Actor** — human principal, tenant, role, delegated scope, agent id/version, and the workload identity the process actually ran as.
- **Configuration provenance** — exact model revision (never a floating alias), prompt hash + version, tool-registry version, **policy id + version**.
- **Tool call** — validated arguments in redacted form + `args_hash`, action id + immutable action version, target resource, read/write flag, idempotency key.
- **Policy & approval** — verdict + reason code; approver identity and the exact action digest approved.
- **Outcome** — status (`completed` / `rejected` / `uncertain` / `failed`), downstream receipt id, duration. A timeout is recorded `uncertain` and reconciled — never blind-retried.
- **Usage** — tokens, computed cost, cumulative session cost against the budget.
- **Integrity** — `prev_hash`, `event_hash`, signer key id, Ed25519 signature. Added by the audit layer only.

**Never logged:** raw chain-of-thought (a short reviewer-facing decision summary instead), passwords, tokens, connection strings, card data, raw PII/PHI. Redaction runs in the interceptor *before* persistence — schema-declared sensitive fields are HMAC-hashed (correlatable, not readable), and pattern detectors sweep everything else. The trail records *which* fields were redacted. Tests seed synthetic secrets and assert they never appear anywhere in the trail.

## Design decisions worth arguing about

- **Per-session hash chains + checkpoints**, not one global chain. A global chain serializes every writer through one lock and forks under concurrency; per-session chains match how auditors actually replay, and a daily Merkle checkpoint over session roots restores global ordering evidence (schema in `schema/postgres.sql`, anchoring on the roadmap).
- **Canonical JSON before hashing (RFC 8785).** Hashing whatever your serializer emits is the classic self-own: verification becomes flaky across languages and library versions.
- **Approvals bind to digests, not intentions.** Approving "a refund" is meaningless; approving action `A-3` v1 with digest `sha256:…` over tool + arguments + target is evidence. Change the amount and you have a new proposal, not an edited approval. Execution uses the *stored* approved arguments — never fresh agent input.
- **Propose, don't execute.** The gateway re-checks entitlement, budget and kill-switch state at execution time — including between approval and execution.
- **The kill switch is infrastructure, not a prompt.** Three scopes (session / tool / global), checked before every execution, flippable at 3 a.m. without a deploy, and itself audited. A prompt that says "please stop" is not a kill switch.
- **Replay ≠ re-run.** The auditor view reconstructs what happened from sealed records; it never re-executes the agent and never promises the same answer.
- **Two pipelines, on purpose.** Sampled observability traces (OpenTelemetry GenAI conventions → Langfuse/Phoenix) are for debugging and evals. The audit stream is unsampled, separately stored, and retained for years. Treating traces as an audit trail is mistake #11 in every postmortem.

## API

| Endpoint | Purpose |
|---|---|
| `POST /sessions` | Open a session (seals the genesis event) |
| `POST /sessions/{id}/messages` | Send a user message; agent acts through the gateway |
| `POST /approvals/{id}/decision` | Named human grants/denies the exact proposed action |
| `POST /admin/kill` | Engage/release the kill switch (session, tool, or global) |
| `POST /sessions/{id}/close` | Close a session and **seal** its trail (Merkle root + signature) |
| `POST /admin/policy/reload` | Hot-reload policy-as-code; the reload itself is a sealed event |
| `GET /registry/agents` | Agent Cards: registered agents, their tools, roles and governing policy |
| `GET /audit/stats` | Dashboard aggregates computed from the trails (cost, verdicts, latency, errors) |
| `GET /audit/sessions/{id}/export.zip` | **Evidence bundle** — verifies offline, no server needed |
| `GET /ui` | Auditor web UI: session list, replay timeline, verify + seal status, bundle export |
| `GET /audit/sessions` | List sessions + signer public key |
| `GET /audit/sessions/{id}` | Replay: the full ordered trail (access is audited) |
| `GET /audit/sessions/{id}/verify` | Recompute chain + signatures |
| `GET /audit/sessions/{id}/export` | Evidence bundle — verifies fully offline |

## Policy as code

Policy is a versioned JSON file, not constants buried in code — the pattern production gateways (Galileo Agent Control, Permit) converged on. Start from a preset — `strict_enterprise` (every refund needs a human), `balanced` (approval above $25), `dev_sandbox` — override any key, and hot-reload without a restart; the reload is itself sealed into the system trail with the new `policy_version`, so *"which policy allowed this?"* is always answerable for any historical event.

```bash
AGENTTRAIL_POLICY_FILE=policy.json uvicorn agenttrail.app:app --port 8000
curl -X POST localhost:8000/admin/policy/reload -d '{"by_user":"ops-admin"}'
```

## Session sealing

Closing a session **seals** it: a Merkle root over the session's event hashes, plus the event count and head hash, signed by the audit service. Verification now distinguishes three states — chain valid + **sealed** (a closed body of evidence), chain valid + **OPEN** (unsealed; still admissible, not final), and **seal invalid**. Events appended after sealing (audit-access notes) are counted and reported, never hidden. A bare hash chain is rewritable by whoever holds the file; the signature + seal is what turns it into evidence.

## Evidence bundles

`GET /audit/sessions/{id}/export.zip` produces what an auditor actually receives: `events.jsonl`, a `manifest.json` (head hash, seal, verification result, the exact chain construction), the `policy_snapshot.json` that governed the session, the signer's public key, a human-readable `report.md`, and a **standalone `verify_bundle.py`** that re-checks the whole chain with no AgentTrail server and no trust in the producer:

```bash
python verify_bundle.py agenttrail-sess_….zip
# OK: 19 events verified for session sess_…; head sha256:…

agenttrail-verify --bundle agenttrail-sess_….zip   # same check, from the CLI
```

## Auditor UI

`GET /ui` — session list with chain heads, a replay timeline (chronological trajectory with per-event detail and tool-latency bars), one-click chain verification with seal status, bundle export, and a stats header (sessions, events, cost, tokens, policy verdicts, tool p95) computed from the trails themselves.

Offline verification, no server required:

```bash
agenttrail-verify --db data/audit.db            # every session
agenttrail-verify --db data/audit.db --session sess_ab12cd34ef56
```

## Planners

The audit boundary is the project, so the agent loop is deliberately simple and hand-written (no framework checkpointing masquerading as an audit trail). With no configuration it runs a deterministic scripted planner — the events honestly record `model_id: scripted-planner-v1` — so the entire story runs with no API key. Set `AGENTTRAIL_LLM_API_KEY` (and optionally `AGENTTRAIL_LLM_BASE_URL`, `AGENTTRAIL_LLM_MODEL`) to drive it with a real OpenAI-compatible model; real model revision and token usage are recorded per call.

## Production layout

`docker-compose.yml` stands up the production-shaped stack — Postgres audit store (schema + grant model in `schema/postgres.sql`: writer role is INSERT/SELECT-only on the sealed tables; immutability comes from permissions *and* the hash chain *and* external anchoring, never from good intentions), Kafka (audit topic: `cleanup.policy=delete`, never compacted), and MinIO with Object Lock standing in for S3 Object Lock Compliance mode as the WORM archive. The SQLite reference implementation in this repo keeps development and tests dependency-free with identical event and chain semantics.

## Roadmap

- Kafka producer via transactional outbox (design in place; SQLite dev path first)
- Daily Merkle checkpointing across sessions with external anchoring (signed git commit / OpenTimestamps) and inclusion proofs
- WORM archive export with verify-from-archive-alone test
- OpenTelemetry GenAI sidecar → Langfuse/Phoenix dashboard (sampled traces, deliberately separate)
- Policy simulation: replay a candidate policy against historical proposals before shipping it
- Scanner hooks (LLM input/output, tool pre/post) for prompt-injection and secret detection
- KMS/HSM signer with key rotation

## Tests

```bash
pytest
```

21 tests: chain verification, tamper detection at the exact sequence, redaction (synthetic secrets/PII never persist), entitlement denials, approval binding and single-use, **self-approval block**, kill switch, budget caps, policy presets + file overrides + audited hot-reload, session sealing (incl. post-seal access accounting), evidence-bundle export with offline verification (and bundle tampering), and a full HTTP end-to-end of the demo story. `scripts/seed_demo.py` seeds a database containing an approved-and-sealed session, a denied viewer attempt, and a kill-switch halt.

## License

MIT © Venkat Ram Kumar Gubbala
