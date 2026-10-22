-- AgentTrail audit store — Postgres production schema.
--
-- The load-bearing property is not the table shape, it is the GRANTS:
-- the writer role can INSERT and SELECT, and nobody — not the agent, not
-- the application role — can UPDATE or DELETE the sealed trail. Integrity
-- then comes from permissions + hash chain + external anchoring together,
-- never from "the app code doesn't update rows".

CREATE TABLE IF NOT EXISTS signers (
    key_id          TEXT PRIMARY KEY,
    public_key_b64  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    session_id      TEXT        NOT NULL,
    sequence_no     INTEGER     NOT NULL,
    event_id        TEXT        NOT NULL UNIQUE,
    event_type      TEXT        NOT NULL,
    event_time_utc  TIMESTAMPTZ NOT NULL,
    payload_json    JSONB       NOT NULL,
    prev_hash       TEXT        NOT NULL,
    event_hash      TEXT        NOT NULL,
    signer_key_id   TEXT        NOT NULL REFERENCES signers(key_id),
    signature       TEXT        NOT NULL,
    PRIMARY KEY (session_id, sequence_no)
);
CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events (event_time_utc);

CREATE TABLE IF NOT EXISTS session_heads (
    session_id    TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL,
    last_hash     TEXT NOT NULL
);

-- Daily Merkle checkpoints: one chain over session roots, anchored
-- externally (signed git commit / RFC 3161 timestamp / OpenTimestamps).
CREATE TABLE IF NOT EXISTS merkle_checkpoints (
    checkpoint_date DATE PRIMARY KEY,
    merkle_root     TEXT NOT NULL,
    prev_root       TEXT,
    anchor_ref      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Operational state (mutable by design; NOT sealed evidence).
CREATE TABLE IF NOT EXISTS approvals (
    approval_id    TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    action_id      TEXT NOT NULL,
    action_version INTEGER NOT NULL,
    action_digest  TEXT NOT NULL,
    tool_name      TEXT NOT NULL,
    args_json      JSONB NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    approver       TEXT,
    created_at     TIMESTAMPTZ NOT NULL,
    decided_at     TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS control_flags (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL
);

-- Roles: run the application as agenttrail_writer.
-- CREATE ROLE agenttrail_writer LOGIN PASSWORD '...';
-- GRANT SELECT, INSERT ON audit_events, session_heads, signers TO agenttrail_writer;
-- GRANT SELECT, INSERT, UPDATE ON approvals, control_flags TO agenttrail_writer;
-- REVOKE UPDATE, DELETE ON audit_events FROM agenttrail_writer;  -- the point
