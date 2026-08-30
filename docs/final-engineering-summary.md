# Final Engineering Summary

## 1. Plan & rationale

Build a tamper-evident audit log as a single synchronous Spring Boot service over an append-only
table, with a SHA-256 hash chain and a verification endpoint (Scenario A); then extend it with
retention, redaction, and verifiable export (Scenario B); then take an under-specified compliance
requirement through clarification → design → a focused partial implementation (Scenario C).

Sequencing was driven by risk: the hashing/canonicalization core is the part most likely to be
subtly wrong and is depended on by everything else, so it was built and unit-tested in isolation
first. The chain writer and verifier came next, then the thin API and auth layers, then the
extensions, then documentation. Every AI-drafted change was compiled, tested, and — for the
security-critical paths — validated by modifying the datastore directly and confirming detection.

Key technology decisions (with the engineer's reasoning) are in `docs/ai-usage-log.md §1` and the
five ADRs under `docs/decisions/`.

## 2. Artifacts

| Artifact | Location |
|---|---|
| Runnable service | `./mvnw spring-boot:run -Dspring-boot.run.profiles=dev` (port 8080) |
| Schema | `src/main/resources/db/migration/V1__init.sql` (Flyway) |
| Hash chain core | `src/main/java/com/sj/audit/hash/`, `.../chain/` |
| REST API | `src/main/java/com/sj/audit/api/` (8 endpoints, table in `README.md`) |
| OpenAPI / Swagger UI | `/v3/api-docs`, `/swagger-ui.html` (springdoc; `config/OpenApiConfig.java`) |
| Standalone bundle verifier | `src/main/java/com/sj/audit/export/BundleVerifier.java` |
| Tests | `src/test/...` — ~35 tests, `./mvnw verify` |
| Architecture & data model | `docs/architecture.md` |
| Decision records | `docs/decisions/ADR-0001..0005` |
| Scenario write-ups | `docs/scenarios/scenario-a|b|c.md` |
| Testing approach | `docs/testing.md` |
| AI usage log | `docs/ai-usage-log.md` |
| Tamper demo script | `scripts/tamper-demo.md` |
| Attestation | `ATTESTATION.md` |

## 3. Risks, trade-offs, and validation

| Risk | Mitigation / current state | Residual |
|---|---|---|
| A subtle bug in canonicalization or hashing would silently weaken tamper evidence | Isolated unit tests; same serializer on write and verify paths; direct-DB tamper tests for every violation type | RFC-8785 divergence on exotic floats — documented, mitigate by sending sensitive numbers as strings |
| A malicious operator could rewrite the entire forward chain | Inherent to any hash chain without an external anchor; verification detects any *partial* tamper | No external timestamp/transparency-log anchoring — noted as future work |
| Redaction could be used to quietly alter data | Redaction never recomputes hashes; a `AUDIT_RECORD_REDACTED` meta event is chained; pre-redaction value tampering is caught by the leaf-commitment check | Post-redaction, a field's integrity rests on its commitment (by design) |
| Archived data could be tampered in cold storage | `deep=true` verification re-hashes from the archive copy | Archive store is a plain table here; production needs WORM |
| Single-writer append limits throughput | Acceptable for an audit log; correct across instances via DB row lock | Not load-tested; scale path is per-stream chains |
| Minimal API-key auth | Scopes enforce read/write/admin separation | No rotation, rate limiting, or mTLS |
| H2 vs production DB parity | Standard SQL, `columnDefinition` avoided, `ddl-auto=none` | `TIMESTAMP(9)` / `FOR UPDATE` nuances differ on Postgres |

Validation performed: `./mvnw verify` green (~35 tests); manual end-to-end tamper demo run against
a live instance (write → verify intact → H2-shell `UPDATE` → verify reports
`CONTENT_HASH_MISMATCH` at the right `seq`); redaction, retention, export, and compliance flows
exercised via `curl` against the running service.

## 4. Assumptions

- Callers are trusted to emit events; the log attests to what was *recorded*, not to what
  *happened* (stated in the Scenario C disclaimer).
- One logical chain for the whole service (not per-tenant) at this scope.
- `event_timestamp` is caller-supplied and not verified for accuracy; `recorded_at` is
  authoritative.
- "Access" event types and "client account data" resource types are configuration, owned by
  compliance, not code.
- Redaction targets leaf fields; whole-subtree redaction is done leaf by leaf.
- The reviewer runs JDK 21+ (built on 26); network is available for the first Maven build.

## 5. Limitations

- No external anchoring of the chain head → no protection against a fully malicious operator.
- O(n) verification, no checkpoints.
- Single node, single writer, not load-tested.
- Auth is minimal (static keys, scopes; no rotation/rate-limiting/mTLS).
- Canonical JSON is near-RFC-8785, not identical.
- Export bundle signing is HMAC (shared secret), not asymmetric.
- Compliance report: no regulator portal, no scheduled delivery, no document rendering, no
  actor-identity resolution (all explicitly scoped out in `scenario-c.md`).
- H2 file datastore; app-level append-only enforcement (DB-level DML revocation documented, not
  applied).

## 6. If this went to production next

1. Postgres; revoke `UPDATE`/`DELETE` from the app role; trigger to block them; `archived_audit_event` in WORM/object-lock storage.
2. External anchoring: periodically publish the head `record_hash` to an RFC-3161 TSA or a transparency log.
3. Verification checkpoints (every N records store a signed running hash) → O(1) incremental verification.
4. Real auth: OIDC/JWT for humans, mTLS or signed requests for services; key rotation; per-key rate limits and audit.
5. Per-stream chains for horizontal write scale.
6. Observability: append latency, verification outcomes, redaction/retention counters, alerting on any `intact:false`.
7. Asymmetric signing of export bundles with a published verification key.
