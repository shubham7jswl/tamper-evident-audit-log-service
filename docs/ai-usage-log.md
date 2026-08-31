# AI Usage Log / Traceability Notes

**Tool:** Claude Code (Sonnet). **Model of use:** engineer-led. The engineer set the scenario,
made the binding technology decisions, reviewed every diff before commit, ran the build and the
manual tamper demo, and owns correctness, maintainability and production-readiness. The AI
accelerated implementation, wrote first drafts of code and docs, and surfaced framework issues.

Legend: **A** accepted as-is · **M** accepted with modification · **R** rejected.

---

## 1. Requirement interpretation & planning

| Item | AI contribution | Engineer action | Rationale |
|---|---|---|---|
| Scenario decomposition & task graph | AI proposed the A→B→C breakdown, dependency ordering, and a risk list | **M** | Engineer confirmed the ordering (hashing core first, as the riskiest reusable piece) and the A+B-full / C-partial scope split. |
| Datastore choice | AI recommended Postgres+Testcontainers; offered H2 and SQLite | **R → chose H2 file** | Engineer prioritized zero-install setup and a trivial "tamper directly in the datastore" demo over production parity. Parity gap documented in `testing.md`. |
| Auth model | AI offered "no auth / API key / JWT" | **chose static API key + scopes** | Enough to enforce read/write separation and gate high-impact ops; not an auth product. |
| Timestamp semantics | AI proposed storing both caller and server time | **A** | Matches the brief's "document your choice"; server time authoritative for ordering. |

## 2. Hashing & chain core (`com.sj.audit.hash`, `com.sj.audit.chain`)

| Item | AI contribution | Engineer action | Rationale |
|---|---|---|---|
| SHA-256 vs SHA-3/BLAKE3/SHA-512 | AI drafted the comparison | **A**, captured as ADR-0001 | Standard, ubiquitous, auditor-friendly. |
| `CanonicalJson` | AI wrote the serializer | **M** | Engineer required proper **Unicode code-point** key ordering (AI's first draft used Java `String` natural order) and an explicit zero-handling branch in number normalization. RFC-8785 divergence documented rather than fixed. |
| Per-leaf salted commitments (the redaction-enabling design) | AI proposed hashing the raw payload; engineer pushed back that this makes redaction impossible; AI then designed the pointer→commitment scheme | **M**, captured as ADR-0002 / ADR-0004 | This is the core design decision of Scenario B. Engineer added the synthetic marker for empty containers so structural deletion is also caught. |
| Redaction marker as an object `{"redacted": id}` | AI's first approach | **R** | It changed the leaf's JSON Pointer path set, complicating the verifier. Replaced with a **string sentinel** `"__REDACTED__:<id>"` that keeps paths stable; the `redaction` table (not the string) drives verifier skipping. |
| `ChainVerifier` "added leaf" / "missing leaf" checks | AI added on request | **A** | Without them, adding a payload field after the fact could go undetected in edge cases. |
| Single-writer append via `chain_head` `SELECT FOR UPDATE` | AI proposed an app-level `ReentrantLock`; engineer required multi-instance correctness | **M**, captured as ADR-0003 | Row lock works across instances; `ReentrantLock` doesn't. |
| `seq` as application-assigned vs DB identity | AI initially used `AUTO_INCREMENT` | **R** | The hash needs `seq` before insert; mixing explicit + identity inserts desyncs H2's sequence. Switched to a plain PK assigned under the lock. |

## 3. Framework / build issues surfaced during execution

The target stack is **Spring Boot 4.1.1 + Jackson 3** — newer than common training data. The AI's
first drafts assumed Boot 3 / Jackson 2 conventions; each was corrected against the actual
classpath:

| Symptom | Fix | How found |
|---|---|---|
| `com.fasterxml.jackson.databind.*` not resolvable | Jackson 3 uses `tools.jackson.databind.*` (annotations stay `com.fasterxml`) | compile error → `dependency:tree` |
| `ObjectNode.fieldNames()` gone | use `properties()` | compile error |
| `TextNode` gone | renamed `StringNode` | compile error → jar inspection |
| Flyway never ran; "database is empty" | Boot 4 split migration auto-config into `org.springframework.boot:spring-boot-flyway` | no "Migrating" log line → autoconfigure imports inspection |
| `@AutoConfigureMockMvc` not on classpath | Boot 4 removed it from `starter-test`; built `MockMvc` from `WebApplicationContext` + explicit filter instead | compile error |
| App won't boot: `Feature not supported: AUTO_SERVER=TRUE && DB_CLOSE_ON_EXIT=FALSE` | H2 2.4 forbids that flag combo; dropped `DB_CLOSE_ON_EXIT` | runtime stack trace in `spring-boot:run` log |
| `PUT /audit/events/{id}` returned 500 not 405 | catch-all `@ExceptionHandler(Exception)` swallowed `HttpRequestMethodNotSupportedException`; made the handler extend `ResponseEntityExceptionHandler` | failing test `hasNoUpdateRoute` |
| JaCoCo can't instrument JDK 26 bytecode (major 70) | moved JaCoCo to the `quality` profile | test run stack trace |

Every one of these was caught by **compiling / running / testing**, not by review alone — which
is the point of keeping the engineer's build loop tight around AI output.

## 4. Tests

| Item | AI contribution | Engineer action | Rationale |
|---|---|---|---|
| Test plan | AI proposed the matrix in `testing.md` | **A** | Covers every documented tamper class via direct-DB modification. |
| DB reset strategy | AI first used `@Transactional` rollback | **M** | Broke with pessimistic locking + MockMvc; switched to `DELETE` in `@BeforeEach`. |
| `TRUNCATE TABLE` in reset | AI's first version | **R** | H2 blocks `TRUNCATE` on FK-referenced tables even with referential integrity off; used ordered `DELETE`. |
| All assertions | AI wrote | reviewed | Engineer spot-checked that failing-path tests fail for the stated reason (e.g. `LEAF_COMMITMENT_MISMATCH`, not a generic mismatch). |

## 5. OpenAPI / Swagger (added after initial submission draft)

| Item | AI contribution | Engineer action | Rationale |
|---|---|---|---|
| Dependency choice | AI checked the local repo and Maven for a springdoc build that targets Spring Boot 4 | **M** — pinned `springdoc-openapi-starter-webmvc-ui:3.0.0` explicitly (not in the Boot BOM); confirmed its parent is `spring-boot-starter-parent:4.0.0` and it boots against 4.1.1 | springdoc 2.x is Boot 3 / Jackson 2 only and would not start on Spring 7. |
| Jackson 2 pulled transitively by swagger-core | AI noted swagger-core brings `com.fasterxml.jackson:2.21.5` alongside Jackson 3 | **A** — left as-is | Different package coordinates (`com.fasterxml.*` vs `tools.jackson.*`); they coexist, swagger uses its copy only for spec model serialization. |
| `OpenApiConfig` — global `X-Api-Key` security scheme | AI wrote | **A** | So Swagger UI "Authorize" sends the key on every call. |
| `@Tag` / `@Operation` on the six controllers | AI drafted concise summaries incl. the required scope | reviewed | springdoc does not read Javadoc without a build plugin; explicit annotations keep the spec useful. |
| springdoc endpoints and auth | AI confirmed `/swagger-ui/**` and `/v3/api-docs/**` are outside `/audit/*`, so the API-key filter already doesn't touch them | **A**, documented in README | Dev-tooling endpoints intentionally open; noted. |

Validated: `./mvnw verify` green (36 tests); booted and confirmed `/v3/api-docs` returns an
OpenAPI 3.1 document with all six tags and per-operation summaries, and `/swagger-ui.html` loads.

## 6. Documentation

`README.md`, `docs/architecture.md`, the five ADRs, the three scenario docs, `docs/testing.md`,
this log, and `docs/final-engineering-summary.md` were drafted by the AI from the implemented
code and the decisions above, then reviewed and adjusted by the engineer. `ATTESTATION.md` is a
template for the engineer to complete with the exact wording from the assignment's §0.

## 7. Readability refactor (rename-only pass)

| Item | AI contribution | Engineer action | Rationale |
|---|---|---|---|
| Scope | AI offered three levels (docs-only / locals-only / full pass) | **chose full pass** | Wanted the code to read the way the docs describe it. |
| Renames | AI renamed cryptic identifiers — `HashInputs`→`ContentHashInput`, `PayloadCommitments.commit`→`computeLeafCommitment`, `leafForms`→`canonicalLeavesByPointer`, `ChainVerifier.inc`→`inconsistencyAt`, `PAGE`→`SCAN_PAGE_SIZE`, `cursor`→`nextSeqToScan`, `e`→`event`, `json`→`jsonCodec`, repo fields→`auditEvents`/`chainAppender`, `rows`→`matchedEvents`, … | reviewed | Names now match the domain vocabulary in the ADRs. |
| Frozen strings | AI flagged that the string literals in the hash pre-image (`"v"`, `"REC1"`, `"LEAF1"`, `"payloadLeafHashes"`, …) must not change | **A** | Renaming them would silently break every existing chain; only Java identifiers were touched. |
| `package-info.java` | AI wrote one per package with a short glossary | reviewed | Biggest comprehension win; zero runtime risk. |

Validated: behaviour-preserving — `./mvnw verify` still green (36 tests), and a booted instance
still produces identical hashes for the same input (write → verify intact → redact → verify intact
→ export).

## 8. Secure-AI-usage notes

- No secrets, credentials, or proprietary data were provided to the AI. The API keys in config
  are obvious development placeholders overridden by env vars.
- No AI-generated code was accepted without compiling and running it.
- Dependencies were not added on the AI's say-so alone — each was checked in `dependency:tree`
  and the build.
- The AI has no write access to any remote; all commits were made explicitly by the engineer's
  session.
