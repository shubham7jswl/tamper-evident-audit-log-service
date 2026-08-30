# Testing approach, coverage, limitations, trade-offs

## How to run

```bash
./mvnw verify                 # unit tests (surefire) + *IT integration tests (failsafe)
./mvnw verify -Pquality       # + Spotless, SpotBugs, JaCoCo 70% line gate   (run on JDK <= 25)
./mvnw verify -Psecurity      # + OWASP dependency-check (slow; downloads NVD)
```

## Test inventory

| Layer | Test | What it proves |
|---|---|---|
| Unit | `CanonicalJsonTest` (6) | deterministic serialization: key sorting, whitespace, number normalization, escaping, unicode, input-order independence |
| Unit | `PayloadCommitmentsTest` (3) | leaf enumeration + JSON Pointer paths + escaping; commitment varies with salt and value; is stable |
| IT | `ChainVerifierIT` (6) | intact chain verifies; **direct-DB tamper** of a core field / payload leaf / record hash is detected at the right `seq` with the right `ViolationType`; a deleted row is a `SEQUENCE_GAP` |
| IT | `RedactionServiceIT` (4) | redacted chain still verifies; value is gone; sibling fields still integrity-checked; meta-audit event written; bad path rejected |
| IT | `RetentionServiceIT` (2) | archived tombstones don't cause a false break; `archivedSegments` reported; deep verify catches tamper inside the archive |
| IT | `BundleExportIT` (3) | exported bundle verifies offline (incl. non-contiguous seqs); tampering a record or the bundle hash fails verification |
| IT | `AuditApiIT` (8) | 401 without key, 403 wrong scope, create + query + filter + pagination, `verify` endpoint, **no `PUT` route (405)**, non-object payload rejected |
| IT | `ComplianceReportIT` (2) | access report returns only configured access events for the account; embeds a verifiable bundle; is itself audited; rejects non-client-data resource types |
| Smoke | `TamperEvidentAuditLogServiceApplicationTests` | full Spring context + Flyway schema loads |

~35 tests. Manual acceptance (`scripts/tamper-demo.md`) was run against a live instance during
development: write → `verify intact` → H2-shell `UPDATE` → `verify` reports
`CONTENT_HASH_MISMATCH` at the tampered `seq`.

## What is deliberately covered

- The **security-critical path**: every documented tamper class has a test that modifies the
  datastore directly (not via the API) and asserts detection + localization.
- The **redaction invariant**: "redaction must not break the chain" is asserted, not just claimed.
- The **export invariant**: verification works from the bundle alone, with a Spring-free verifier.
- API **authz** and the **absence** of mutation routes.

## What is not covered, and why

| Gap | Why not | Risk |
|---|---|---|
| Concurrency / load test of `ChainAppender` | Correctness rests on a DB row lock (well-understood); a meaningful load test needs Postgres + a harness | Low — single-writer semantics are simple; throughput is a known limitation, not a correctness risk |
| Multi-instance verification | Requires orchestrating two app processes on one DB | Low — the lock is DB-side |
| Property-based / fuzz testing of `CanonicalJson` | Time; the RFC-8785 divergence is already documented | Medium — exotic float payloads could serialize inconsistently across languages |
| Postgres parity | H2 chosen for zero-install; SQL is standard, `columnDefinition` avoided | Medium — `TIMESTAMP(9)` / `FOR UPDATE` behaviour differs subtly |
| Performance of O(n) verification on large chains | No large dataset generated | Medium — verification cost grows linearly; checkpointing is the mitigation, noted as future work |
| Key rotation, rate limiting, mTLS | Auth is intentionally minimal | Medium — not production-grade auth |
| Archive in real WORM storage | H2 table stands in for it | Medium — archive integrity depends on that store; deep verify is the check |
| `BundleVerifier` cross-language | Only the Java verifier exists | Low–Medium — algorithm is documented in `scenario-b.md` |

## Trade-offs in the test strategy

- **Integration-heavy over mock-heavy.** The valuable assertions here are end-to-end ("tamper the
  row, does verify catch it?"). Mocking the repository would test the mock. The cost is slower
  tests (~15s) and a real H2 per context.
- **DB reset via `DELETE` in `@BeforeEach`**, not `@Transactional` rollback, because the
  pessimistic lock + MockMvc requests interact badly with a wrapping test transaction.
- **`*IT` on failsafe, not surefire**, so `./mvnw test` is fast and `./mvnw verify` is complete —
  standard Maven split.
- **JaCoCo in the `quality` profile only**: 0.8.12 cannot instrument JDK 26 bytecode, and the
  default build must work on the JDK the reviewer has. Coverage still runs on JDK ≤ 25.
