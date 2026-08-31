# Tamper-Evident Audit Log Service

An append-only audit log with a **SHA-256 hash chain**: every stored record commits to its own
content and to the previous record, so any later modification or deletion of a past record is
detectable by a verification endpoint. Extended with retention/archival, structured payload
redaction that does not break the chain, verifiable bulk export, and a compliance access report.

- **Scenario A** — core service (write / query / hash chain / verify): `docs/scenarios/scenario-a.md`
- **Scenario B** — retention + redaction + verifiable export: `docs/scenarios/scenario-b.md`
- **Scenario C** — ambiguous compliance requirement (clarification → design → partial build): `docs/scenarios/scenario-c.md`
- **Architecture & key decisions**: `docs/architecture.md` and `docs/decisions/`
- **Testing approach, limits, trade-offs**: `docs/testing.md`
- **AI usage log**: `docs/ai-usage-log.md`
- **Final engineering summary**: `docs/final-engineering-summary.md`
- **Post-review remediation**: `docs/eval-remediation.md`
- **Attestation & reviewed revision**: `ATTESTATION.md`, `SUBMISSION.md`

## Prerequisites

- JDK 21+ (built and tested on JDK 26; source level is 21)
- No database to install — embedded **H2** file database, created on first run under `./data/`
- Maven wrapper is included (`./mvnw`); network access is needed on first build to download deps

## Run it

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

The service listens on `http://localhost:8080`.

- **Swagger UI:** `http://localhost:8080/swagger-ui.html` — click **Authorize** and paste an API
  key (e.g. `dev-admin-key`) to call every endpoint from the browser.
- **OpenAPI spec:** `http://localhost:8080/v3/api-docs`
- The `dev` profile also enables the **H2 web console** at `http://localhost:8080/h2-console`
  (JDBC URL `jdbc:h2:file:./data/auditdb`, user `sa`, no password) — used for the tamper demo below.

The `/swagger-ui/**`, `/v3/api-docs/**`, and `/actuator/health` paths are open; all `/audit/**`
endpoints require `X-Api-Key`.

### API keys

The **`dev` profile** ships three well-known keys for local use:

| Key (header `X-Api-Key`) | Scopes | Env var |
|---|---|---|
| `dev-reader-key` | READ | `AUDIT_READER_KEY` |
| `dev-writer-key` | WRITE, READ | `AUDIT_WRITER_KEY` |
| `dev-admin-key`  | WRITE, READ, ADMIN | `AUDIT_ADMIN_KEY` |

Outside `dev` (and `test`), **no keys are shipped**: set `AUDIT_READER_KEY` / `AUDIT_WRITER_KEY` /
`AUDIT_ADMIN_KEY` to high-entropy secrets. `ApiKeyConfigValidator` fails startup if a key is
missing, a known placeholder, or shorter than 16 characters — so a deployment that forgot to set
them cannot silently come up with default credentials.

## Build & test

```bash
./mvnw verify                 # compile + unit tests + *IT integration tests
./mvnw verify -Pquality       # + Spotless (format), SpotBugs, JaCoCo 70% line gate  (use JDK <= 25)
./mvnw verify -Psecurity      # + OWASP dependency-check (downloads the NVD feed; slow)
```

## API summary

| Method & path | Scope | Purpose |
|---|---|---|
| `POST /audit/events` | WRITE | Append an event. No update/delete route exists. |
| `GET /audit/events` | READ | Query with `actorId`, `resourceType`, `resourceId`, `eventType`, `from`, `to`, `page`, `size`. |
| `GET /audit/events/{eventId}` | READ | Fetch one record. |
| `GET /audit/verify` | READ | Walk the chain; `?fromSeq=&toSeq=` sub-range; `?deep=true` (ADMIN) re-hashes archived rows. |
| `POST /audit/events/{eventId}/redactions` | ADMIN | Redact payload leaves. |
| `POST /audit/retention/run` | ADMIN | Archive records older than the retention window. |
| `GET /audit/export?resourceId=` or `?actorId=` | READ | Self-contained, independently verifiable bundle. |
| `GET /audit/compliance/access-report?resourceType=&resourceId=&from=&to=` | READ | Scenario C report. |

### Quickstart

```bash
BASE=http://localhost:8080
WRITER='X-Api-Key: dev-writer-key'
ADMIN='X-Api-Key: dev-admin-key'

# write
curl -s -X POST $BASE/audit/events -H "$WRITER" -H 'Content-Type: application/json' -d '{
  "eventType":"ACCOUNT_VIEWED","actorId":"clerk-7","resourceType":"CLIENT_ACCOUNT",
  "resourceId":"acct-1","payload":{"accountNumber":"4444333322221111","channel":"web"}}'

# query
curl -s "$BASE/audit/events?actorId=clerk-7&page=0&size=20" -H "$WRITER"

# verify
curl -s "$BASE/audit/verify" -H "$WRITER"

# redact a sensitive field (chain stays valid)
curl -s -X POST "$BASE/audit/events/<eventId>/redactions" -H "$ADMIN" -H 'Content-Type: application/json' \
  -d '{"fieldPaths":["/accountNumber"],"reason":"PCI DSS","redactedBy":"officer-1"}'

# export + verify offline
curl -s "$BASE/audit/export?resourceId=acct-1" -H "$WRITER" > bundle.json
```

## Tamper demo (end-to-end proof)

See `scripts/tamper-demo.md` for a copy-paste walkthrough: write events → `verify` reports
`intact:true` → modify a row directly in H2 → `verify` reports `intact:false` with the first
inconsistent `seq` and the violation type.
