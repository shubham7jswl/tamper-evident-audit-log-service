# CLAUDE.md

Guidance for working in this repository.

## What this is

A tamper-evident, append-only audit log service (take-home exercise). Spring Boot 4.1 / Java 21,
**Jackson 3** (`tools.jackson.*`), H2 file DB + Flyway. See `docs/architecture.md` and the ADRs in
`docs/decisions/`.

## Build & run

```bash
./mvnw verify                                        # unit (surefire) + *IT (failsafe) — ~35 tests
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev # http://localhost:8080, H2 console at /h2-console
./mvnw verify -Pquality                              # SpotBugs + JaCoCo — run on JDK 21 only
```

Dev API keys (header `X-Api-Key`): `dev-reader-key` (READ), `dev-writer-key` (WRITE+READ),
`dev-admin-key` (+ADMIN).

## Layout

Layered: `com.sj.audit.api` (thin controllers + `GlobalExceptionHandler`) · `.service` (all
business logic — `ChainAppender` single writer, `ChainVerifier`, `AuditQueryService`,
`RedactionService`, `RetentionService`, `BundleExporter`, `ComplianceReportService`) ·
`.repository` (Spring Data) · `.domain` (JPA entities + DTOs; `.domain.chain` `VerificationReport`,
`.domain.query` `AuditQueryFilter`, `.domain.export` `ExportBundle`) · `.enums` (`Scope`,
`ViolationType`) · `.utils.hash` (canonical JSON, SHA-256, per-leaf commitments — Spring-free) ·
`.utils` (`BundleVerifier`, Spring-free) · `.config` (+ `.config.security` — API-key filter,
scope interceptor, `@RequireScope`).

## Conventions & gotchas

- **Jackson 3**: `tools.jackson.databind.*`; `ObjectNode.properties()` not `fieldNames()`;
  `StringNode` not `TextNode`; annotations stay `com.fasterxml.jackson.annotation`.
- **Flyway** auto-config comes from `spring-boot-flyway` (Boot 4 split it out). Schema is
  authoritative; `ddl-auto=none`.
- `seq` is app-assigned under the `chain_head` `SELECT FOR UPDATE`, not a DB identity.
- `content_hash` covers per-leaf **commitments**, never raw payload values — this is what makes
  redaction possible without breaking the chain (ADR-0004).
- Never add an update/delete route for events. The entity has no setters beyond `applyRedaction`
  / `archiveAsTombstone`.
- Integration tests end in `*IT`, extend `AbstractIntegrationTest` (resets the DB per test).
- Tests + `scripts/tamper-demo.md` are the source of truth for tamper-detection behavior.

## When changing hashing

Any change to `CanonicalJson`, `AuditHasher`, `PayloadCommitments`, or the hashable view is a
breaking change to existing chains. Bump the `"v"` in the hashable view and update `BundleVerifier`
in lockstep.
