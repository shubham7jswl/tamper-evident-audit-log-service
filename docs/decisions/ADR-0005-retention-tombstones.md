# ADR-0005: Retention via tombstones

**Status:** Accepted

## Context

Scenario B: records older than a configurable window must be archivable/soft-deletable, and chain
verification must not report a false break for legitimately archived records.

## Decision

Archival copies the full row to `archived_audit_event`, then converts the live row to a
**tombstone**: `payload_json` and `leaf_salts_json` set to `NULL`, `archived_at` set, and **every
hash column retained** (`content_hash`, `prev_hash`, `record_hash`, `leaf_commitments_json`). The
row is never deleted.

Because the row stays:

- `seq` remains gap-free → no `SEQUENCE_GAP` false positive.
- `content_hash` is still bound into `record_hash` → tampering with a tombstone's hashes is still
  detected.
- Shallow verification (default) checks the chain math using the retained `content_hash`.
- `deep=true` verification (ADMIN) additionally recomputes `content_hash` from the
  `archived_audit_event` copy, catching tampering *inside* the archive.

`VerificationReport` lists the `archivedSegments` (contiguous tombstone ranges) it saw.

## Alternatives considered

| Option | Why not |
|---|---|
| Hard-delete archived rows | Creates a real `seq` gap; verification can't distinguish it from a malicious deletion without extra trusted state. |
| Move rows out and store per-segment "bridge" hashes | Equivalent security to tombstones but more moving parts and a new data structure to protect. |
| Keep everything forever | Doesn't satisfy the retention requirement; unbounded PII exposure. |

## Consequences

- Storage for a tombstone is small (hashes + metadata) but non-zero; the archive holds the bulk.
- The archive table is the integrity-sensitive part for archived data — in production it belongs
  in WORM / append-only cold storage. Deep verification is the check that it hasn't been altered.
- Retention runs are manual (`POST /audit/retention/run`, ADMIN) or scheduled
  (`audit.retention.scheduled=true`). A retention run does not itself write to the chain (it only
  tombstones); the operational log records it.
