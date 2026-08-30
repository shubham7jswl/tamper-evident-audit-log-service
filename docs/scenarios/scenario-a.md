# Scenario A — Core Audit Log Service

## Requirement understanding

> Append-only event history; write API; query API with filtering + pagination; each record carries
> a hash of its own content and of the previous record; a `GET /audit/verify` endpoint that walks
> the chain and reports whether it is intact and, if not, the first inconsistency.

**Normalized problem statement.** Build a service where (1) events can only be added, never
modified or removed through the API; (2) events are queryable by actor / resource / type / time
with pagination; (3) every event is cryptographically linked to its predecessor so that any
out-of-band modification or deletion is detectable; (4) an endpoint performs that detection and
localizes the first fault.

### Ambiguities identified and how they were resolved

| Ambiguity | Resolution (documented assumption) |
|---|---|
| `timestamp` caller-supplied or server-assigned? | **Both.** `recorded_at` = server clock, authoritative for ordering/retention. `event_timestamp` = optional caller value, hashed but not trusted for accuracy. Query filters on `event_timestamp`. |
| What exactly does "content" cover in the content hash? | `seq`, `eventId`, all four core fields, both timestamps, and per-leaf payload commitments. Explicit `hashableView` (ADR-0002). |
| Genesis value for the first record? | Fixed constant `SHA-256("tamper-evident-audit-log::genesis::v1")`. |
| Pagination style? | Offset (`page`/`size`, max 200), ordered by `seq`. Keyset noted as the scale improvement. |
| Is verification allowed to be O(n)? | Yes at this scope; checkpointing noted as future work. |
| Should verify stop at the first fault or list all? | Reports the **first** inconsistency (matches the requirement wording) and how many records it checked. |
| Auth? | Not in the brief; added a minimal API-key + scopes model so "write" vs "read" is enforced and high-impact ops are gated. |

## Task decomposition (with dependencies)

```
1. Project setup: deps (web, data-jpa, validation, flyway, h2), profiles, quality profile
2. Hashing core  ──depends on 1
   2a. CanonicalJson (deterministic serialization)
   2b. Hashing (SHA-256, HMAC, domain separation)
   2c. PayloadCommitments (per-leaf salted commitments)
   2d. AuditHasher (content hash + record hash)
3. Schema + entities ──depends on 1
   3a. V1__init.sql (audit_event, chain_head seed, archive, redaction)
   3b. JPA entities + repositories
4. ChainAppender ──depends on 2, 3   (locked append, genesis handling)
5. Write API ──depends on 4
6. Query API ──depends on 3   (Criteria spec + pagination)
7. Verify API ──depends on 2, 3   (ChainVerifier)
8. Security ──depends on 1   (filter + scope interceptor)  ──gates 5,6,7
9. Validation: MockMvc + full-stack IT + direct-DB tamper tests + tamper-demo doc
```

Sequencing rationale: the hashing core (2) is the riskiest and most reusable piece, so it was
built and unit-tested first, in isolation from Spring. The chain writer (4) and verifier (7) both
depend on it. The API and security layers are thin and came last.

## Execution notes

- `ChainAppender.append` takes `SELECT ... FOR UPDATE` on `chain_head`, computes
  `seq = last_seq + 1`, hashes, inserts, advances the head — all in one transaction (ADR-0003).
- `seq` is application-assigned, not a DB identity, because the hash needs it before insert.
- The entity has no setters; only `applyRedaction` / `archiveAsTombstone`. There is no update or
  delete controller method — confirmed by a test that `PUT /audit/events/{id}` returns 405.
- `ChainVerifier` pages through the chain (500 rows at a time) rather than loading it all.

## Validation

Automated (`src/test/java/com/sj/audit/chain/ChainVerifierIT.java` and `api/AuditApiIT.java`):

| Test | Asserts |
|---|---|
| `intactChainVerifies` | 3 appends → `intact:true`, `recordsChecked:3` |
| `emptyChainVerifies` | empty chain is intact |
| `detectsCoreFieldTamperAtRightSeq` | `UPDATE ... SET actor_id` on seq 2 → `CONTENT_HASH_MISMATCH` at seq 2 |
| `detectsPayloadLeafTamper` | `UPDATE ... SET payload_json` on seq 2 → `LEAF_COMMITMENT_MISMATCH` at seq 2 |
| `detectsDeletedRecordAsSequenceGap` | `DELETE ... WHERE seq=2` → `SEQUENCE_GAP` |
| `detectsRecordHashTamper` | zeroed `record_hash` → `RECORD_HASH_MISMATCH` / `PREV_HASH_MISMATCH` |
| `rejectsMissingApiKey` / `rejectsInsufficientScope` | 401 / 403 |
| `writesAndReadsBackAnEvent`, `filtersOutNonMatchingActors`, `paginates` | write + query + pagination |
| `hasNoUpdateRoute` | `PUT` → 405 |

Manual (the assignment's own acceptance path) — `scripts/tamper-demo.md`: write events → verify
`intact:true` → modify a row via the H2 shell → verify `intact:false` with `firstInconsistency`.
Run and confirmed during development.

## What was scoped out

External consumers, event schemas per `eventType`, verification checkpoints, keyset pagination,
soft rate limiting. All noted in `docs/architecture.md` §6.
