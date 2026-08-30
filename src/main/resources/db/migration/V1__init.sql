-- Tamper-evident audit log — initial schema.
-- Flyway owns the schema; Hibernate runs with ddl-auto=none.

-- The append-only hash chain. One row per recorded event, ordered by `seq`.
CREATE TABLE audit_event (
    -- Assigned by the application under the chain_head lock (not a DB identity) so the
    -- value is known before the row's hashes are computed.
    seq                  BIGINT        NOT NULL PRIMARY KEY,
    event_id             UUID          NOT NULL,
    event_type           VARCHAR(200)  NOT NULL,
    actor_id             VARCHAR(200)  NOT NULL,
    resource_type        VARCHAR(200)  NOT NULL,
    resource_id          VARCHAR(200)  NOT NULL,
    -- Payload as stored/returned. After a redaction the affected leaves are replaced
    -- by a marker object; NULL only when the whole row has been archived (tombstone).
    payload_json         CLOB,
    -- JSON Pointer -> random per-leaf salt (hex). NULL after archival.
    leaf_salts_json      CLOB,
    -- JSON Pointer -> salted leaf commitment (hex). Never NULL; survives archival so the
    -- chain math still closes over an archived row.
    leaf_commitments_json CLOB         NOT NULL,
    -- Caller-supplied "when it happened" (defaults to recorded_at when omitted).
    event_timestamp      TIMESTAMP(9)  NOT NULL,
    -- Server-assigned; authoritative for ordering and retention.
    recorded_at          TIMESTAMP(9)  NOT NULL,
    content_hash         CHAR(64)      NOT NULL,
    prev_hash            CHAR(64)      NOT NULL,
    record_hash          CHAR(64)      NOT NULL,
    archived_at          TIMESTAMP(9)
);

CREATE UNIQUE INDEX ux_audit_event_event_id ON audit_event (event_id);
CREATE INDEX ix_audit_event_actor        ON audit_event (actor_id);
CREATE INDEX ix_audit_event_resource     ON audit_event (resource_type, resource_id);
CREATE INDEX ix_audit_event_type         ON audit_event (event_type);
CREATE INDEX ix_audit_event_recorded_at  ON audit_event (recorded_at);
CREATE INDEX ix_audit_event_event_ts     ON audit_event (event_timestamp);

-- Single-row table used to serialize chain appends (SELECT ... FOR UPDATE) and to hold
-- the current chain head so a new append never has to scan the tail.
CREATE TABLE chain_head (
    id                SMALLINT      NOT NULL PRIMARY KEY,
    last_seq          BIGINT        NOT NULL,
    last_record_hash  CHAR(64)      NOT NULL,
    updated_at        TIMESTAMP(9)  NOT NULL
);

-- Seed: last_seq = 0, last_record_hash = genesis value
-- (SHA-256("tamper-evident-audit-log::genesis::v1")).
INSERT INTO chain_head (id, last_seq, last_record_hash, updated_at)
VALUES (1, 0, 'cdb3681748c47491bb74d81d0c8fb45444a52577331ee03b951cb2b9775fe0fa', CURRENT_TIMESTAMP);

-- Full copies of archived rows, kept for deep verification. In production this is a
-- candidate for separate WORM / cold storage.
CREATE TABLE archived_audit_event (
    seq                  BIGINT        NOT NULL PRIMARY KEY,
    event_id             UUID          NOT NULL,
    event_type           VARCHAR(200)  NOT NULL,
    actor_id             VARCHAR(200)  NOT NULL,
    resource_type        VARCHAR(200)  NOT NULL,
    resource_id          VARCHAR(200)  NOT NULL,
    payload_json         CLOB,
    leaf_salts_json      CLOB,
    leaf_commitments_json CLOB         NOT NULL,
    event_timestamp      TIMESTAMP(9)  NOT NULL,
    recorded_at          TIMESTAMP(9)  NOT NULL,
    content_hash         CHAR(64)      NOT NULL,
    prev_hash            CHAR(64)      NOT NULL,
    record_hash          CHAR(64)      NOT NULL,
    archived_at          TIMESTAMP(9)  NOT NULL
);

-- One row per redacted payload leaf. The commitment is copied here so a redaction can be
-- audited and (if the salt was retained) a later-disclosed value can be checked.
CREATE TABLE redaction (
    redaction_id      UUID          NOT NULL PRIMARY KEY,
    event_seq         BIGINT        NOT NULL REFERENCES audit_event (seq),
    field_path        VARCHAR(1000) NOT NULL,
    field_commitment  CHAR(64)      NOT NULL,
    field_salt        VARCHAR(64),
    salt_retained     BOOLEAN       NOT NULL,
    reason            VARCHAR(2000) NOT NULL,
    redacted_by       VARCHAR(200)  NOT NULL,
    redacted_at       TIMESTAMP(9)  NOT NULL
);

CREATE INDEX ix_redaction_event_seq ON redaction (event_seq);
CREATE UNIQUE INDEX ux_redaction_seq_path ON redaction (event_seq, field_path);
