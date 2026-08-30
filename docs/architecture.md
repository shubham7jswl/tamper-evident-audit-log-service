# Architecture Overview

## 1. Purpose and shape

A single Spring Boot service exposing a small REST API over an append-only `audit_event` table.
Records form a SHA-256 hash chain; a verification endpoint walks the chain and reports the first
inconsistency. The service is deliberately monolithic and synchronous — an audit log's value is
correctness and auditability, not throughput.

```
             ┌──────────────────────────── HTTP (X-Api-Key) ────────────────────────────┐
             │                                                                          │
   POST /audit/events        GET /audit/events        GET /audit/verify        GET /audit/export
   POST .../redactions       GET .../{eventId}        GET /audit/compliance/access-report
   POST /audit/retention/run
             │
   ┌─────────▼──────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌───────────────┐
   │   ChainAppender    │   │ AuditQuery   │   │ ChainVerifier │   │ Redaction /  │   │ BundleExporter│
   │ (single writer,    │   │ Service      │   │               │   │ Retention    │   │ /Verifier     │
   │  chain_head lock)  │   │              │   │               │   │ Service      │   │               │
   └─────────┬──────────┘   └──────┬───────┘   └───────┬───────┘   └──────┬───────┘   └───────┬───────┘
             │                     │                   │                  │                   │
             └──────────────── AuditHasher / CanonicalJson / PayloadCommitments ──────────────┘
                                                   │
                                        H2 (file) + Flyway schema
```

### Components (`src/main/java/com/sj/audit/`)

| Package | Responsibility |
|---|---|
| `hash` | `CanonicalJson` (deterministic serialization), `Hashing` (SHA-256 + HMAC + domain separation), `PayloadCommitments` (per-leaf salted commitments), `AuditHasher` (content + record hash), `JsonPointers`, `Instants` |
| `domain` | JPA entities (`AuditEvent`, `ChainHead`, `ArchivedAuditEvent`, `Redaction`) and repositories |
| `chain` | `ChainAppender` (the only writer), `ChainVerifier`, `VerificationReport`, `ViolationType` |
| `query` | dynamic filtered query (JPA Criteria) + pagination |
| `redaction` | `RedactionService` — leaf redaction + meta-audit event |
| `retention` | `RetentionService` — archival to tombstones + scheduled job |
| `export` | `BundleExporter` (service) and `BundleVerifier` (standalone, Spring-free) |
| `compliance` | `ComplianceReportService` — Scenario C |
| `security` | `ApiKeyAuthFilter`, `ScopeInterceptor`, `@RequireScope`, `ApiPrincipal` |
| `api` | controllers, request/response DTOs, `GlobalExceptionHandler` |
| `config` | `AuditProperties`, `JsonSupport`, `Clock` bean, error model |

## 2. Data model

`audit_event` — the chain (see `src/main/resources/db/migration/V1__init.sql`):

| Column | Notes |
|---|---|
| `seq` (PK, BIGINT) | Chain order. Assigned by the application under the `chain_head` lock — **not** a DB identity — so it is known before hashing. Gap-free by construction. |
| `event_id` (UUID, unique) | External identifier returned to callers. |
| `event_type`, `actor_id`, `resource_type`, `resource_id` | The event's "who/what". |
| `payload_json` (CLOB) | Canonicalized payload as stored/returned. Redacted leaves become a `"__REDACTED__:<id>"` sentinel. `NULL` once archived. |
| `leaf_salts_json` (CLOB) | JSON Pointer → 128-bit hex salt, one per payload leaf. Entry removed on redaction; whole column `NULL` once archived. |
| `leaf_commitments_json` (CLOB) | JSON Pointer → salted commitment. **Never mutated** (`updatable=false`), never null — this is what keeps an archived/redacted row verifiable. |
| `event_timestamp` | Caller-supplied "when it happened"; defaults to `recorded_at`. Trusted-but-recorded. |
| `recorded_at` | Server clock. Authoritative for ordering and retention. |
| `content_hash`, `prev_hash`, `record_hash` | The chain. See §3. |
| `archived_at` | Set when the row becomes a tombstone. |

Supporting tables: `chain_head` (single row, lock target + head cache), `archived_audit_event`
(full copies for deep verification), `redaction` (one row per redacted leaf: path, commitment,
optional retained salt, reason, actor, time).

### Timestamp choice

Both are stored. `recorded_at` is **server-assigned** and authoritative — callers cannot backdate
their position in the chain. `event_timestamp` is **caller-supplied** (optional) because only the
caller knows when the real-world event occurred; it is covered by the hash so it cannot be altered
later, but the service makes no claim it is accurate. Query time-range filtering is on
`event_timestamp`.

## 3. Hash chain design

### Algorithm: SHA-256

FIPS 180-4, universally available and hardware-accelerated, ~128-bit collision resistance.
Rejected alternatives and full rationale: `docs/decisions/ADR-0001-hash-algorithm.md`.

### Canonicalization

Every hash pre-image is produced by `CanonicalJson`: object keys sorted by Unicode code point, no
insignificant whitespace, normalized numbers, minimal string escaping. Instants are formatted to a
fixed 9-fractional-digit `...Z` form so datastore precision cannot change the hash. Multi-part
hash inputs use a domain-separation prefix (`"REC1"`, `"LEAF1"`) and a `0x1F` delimiter between
parts, each part being a fixed-length hex string or short tag — unambiguous, no length-extension
exposure.

### What is hashed

1. **Per-leaf commitments.** For each payload leaf (any JSON value, plus a marker for empty
   objects/arrays), `commitment = SHA-256("LEAF1" | saltHex | typeTag+canonicalValue)` with a
   fresh random 128-bit salt per leaf. Stored as `leaf_commitments_json`.
2. **Content hash.** `content_hash = SHA-256(CanonicalJson(hashableView))` where `hashableView`
   is `{ v, seq, eventId, eventType, actorId, resourceType, resourceId, eventTimestamp,
   recordedAt, payloadLeafHashes }` and `payloadLeafHashes` is the pointer→commitment map. The
   payload's *values* never enter the content hash directly — only their commitments do. This is
   the property that makes redaction possible (ADR-0004).
3. **Record hash.** `record_hash = SHA-256("REC1" | prev_hash | content_hash)`, where `prev_hash`
   is the previous record's `record_hash`, or the genesis constant
   `SHA-256("tamper-evident-audit-log::genesis::v1")` for `seq = 1`.

### Verification (`ChainVerifier`)

Walks `seq` ascending in pages, holding the running previous `record_hash`. Per record:

| Check | Violation if it fails |
|---|---|
| `seq` is the next expected value | `SEQUENCE_GAP` (a deletion — archival leaves a tombstone, not a gap) |
| `seq == 1 ⇒ prev_hash == genesis` | `GENESIS_MISMATCH` |
| `prev_hash == previous record's record_hash` | `PREV_HASH_MISMATCH` |
| non-redacted leaves: recomputed commitment == stored | `LEAF_COMMITMENT_MISMATCH` (payload value changed / field added or removed) |
| recomputed `content_hash` == stored | `CONTENT_HASH_MISMATCH` (core field or commitment map changed) |
| recomputed `record_hash` == stored | `RECORD_HASH_MISMATCH` |

Stops at and reports the first inconsistency: `{ seq, eventId, violationType, detail }`. Archived
rows: their `content_hash` is still bound into `record_hash`, so the chain math still closes;
`deep=true` additionally re-derives it from the archive copy. `fromSeq/toSeq` allow verifying a
sub-range (seeded from the predecessor's `record_hash`).

### Concurrency & append-only enforcement

- **Single writer.** `ChainAppender.append` runs in one transaction that first does
  `SELECT ... FOR UPDATE` on the `chain_head` row. This serializes all appends and guarantees a
  gap-free `seq` even across multiple service instances on one database. Trade-off: throughput is
  bound by a single writer — acceptable for an audit log; the scale path is per-stream chains
  (ADR-0003).
- **No mutation API.** There is no `PUT`/`PATCH`/`DELETE` route for events. The entity exposes no
  generic setters — only the two audited domain operations `applyRedaction` and
  `archiveAsTombstone`, both of which preserve every hash column.
- **Database hardening (documented, not enforced on H2).** In production: `REVOKE UPDATE, DELETE`
  from the app role and add a rule/trigger that blocks them; keep `archived_audit_event` in WORM
  storage. The verify endpoint is the ultimate backstop regardless.

## 4. API design

REST/JSON, one resource tree under `/audit`. Errors use a single `ApiError` shape
`{ timestamp, status, error, message, path }` (framework 4xx keep their status via
`ResponseEntityExceptionHandler`). Pagination uses a stable `PageResponse` envelope
(`content`, `page`, `size`, `totalElements`, `totalPages`, `hasNext`); results are ordered by
`seq`. Offset pagination is used for simplicity; keyset pagination on `seq` is the documented
improvement for very large result sets.

### AuthN / AuthZ

`X-Api-Key` header checked by a servlet filter against a configured key list; each key carries a
set of scopes (`READ`, `WRITE`, `ADMIN`). Controller methods declare `@RequireScope(...)`,
enforced by an interceptor. High-impact operations (redaction, retention, deep verify) require
`ADMIN` — this is the "human sign-off for high-impact changes" control. Deliberately minimal: no
rotation, no rate limiting, no mTLS — see §6.

## 5. Key trade-offs

| Decision | Benefit | Cost / limitation |
|---|---|---|
| H2 file database | zero-install, trivial tamper demo | single node; not load-tested; app-level append-only only |
| Per-leaf salted commitments in the content hash | redaction without breaking the chain; low-entropy values not brute-forceable after redaction | more complex hashing; core (non-payload) fields are not redactable |
| Single-writer append via row lock | correct, gap-free `seq`, multi-instance safe | throughput ceiling |
| Full-scan verification | simple, no extra state to trust | O(n); no checkpointing |
| Static API keys | simple, testable, no external IdP | no rotation/rate-limiting; keys in config |
| Custom near-canonical JSON | no dependency, good enough for structured audit payloads | not byte-identical to RFC 8785 for exotic floats |
| No external anchoring | self-contained | chain is only as trustworthy as the operator retaining the head hash |

## 6. Production readiness gaps (known, documented)

Auth hardening (rotation, rate limiting, mTLS, per-key audit); Postgres with revoked DML grants +
triggers + WORM archive storage; verification checkpoints for O(1) incremental verification;
external anchoring of the chain head (RFC-3161 timestamps or a transparency log) for
non-repudiation against a malicious operator; horizontal scale via sharded per-stream chains;
observability (metrics on append latency, verification results, redaction counts); backpressure /
async ingestion if write volume demands it.
