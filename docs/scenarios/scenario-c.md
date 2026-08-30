# Scenario C — Compliance Reporting (ambiguous requirement)

> Product says: *"Regulators need to be able to audit access to client account data."*

## 1. How I clarified and normalized the requirement

This sentence hides at least eight decisions. Below is what I would ask product/compliance, the
assumption I made to proceed, and why.

| # | Ambiguity | Question I would ask | Assumption made to proceed | Why |
|---|---|---|---|---|
| 1 | Who is the consumer? | Is this an external regulator with their own portal login, or an internal compliance officer producing evidence *for* a regulator? | **Internal compliance officer / investigator** produces an on-demand report; external delivery is out of scope. | Building a regulator-facing authenticated portal is a separate product; the audit data and its integrity proof are the hard part and are reusable either way. |
| 2 | What is "access"? | Read-only views? Also exports, searches, permission grants? Failed attempts? | A **configurable set of event types** (`audit.compliance.access-event-types`, default `ACCOUNT_VIEWED, ACCOUNT_STATEMENT_DOWNLOADED, ACCOUNT_SEARCHED, ACCOUNT_EXPORTED`). | "Access" is a policy definition, not an engineering one — make it configuration, not code. |
| 3 | What is "client account data"? | Which resource types count — the account, its statements, KYC documents, transactions? | A **configurable set of resource types** (`audit.compliance.client-data-resource-types`, default `CLIENT_ACCOUNT, CLIENT_ACCOUNT_STATEMENT`). Report is requested for one `resourceId`. | Same reason as #2 — data classification is owned by compliance. |
| 4 | Time scope | How far back? Must it cover archived/retained periods? | Caller supplies `from`/`to`. Archived records are included (they remain in the chain as tombstones; access events themselves are unlikely to be archived within a regulatory window, but the report does not silently drop them). | Regulators define retention; the API shouldn't. |
| 5 | Output format & delivery | PDF? CSV? Signed JSON? Emailed quarterly? | **On-demand JSON** (a machine-readable report object) that embeds a verifiable export bundle. CSV/PDF rendering and scheduled delivery are out of scope. | The integrity-bearing artifact is the bundle; presentation is a thin, low-risk layer to add later. |
| 6 | Completeness / non-repudiation | How does the regulator trust the report is complete and unaltered? | Report embeds (a) a full-chain `verify` result and (b) a `completeness` block (seq range covered, matched count). The embedded bundle is independently verifiable. | This is where the hash chain pays off — the report can *prove* it wasn't trimmed. |
| 7 | Actor identity | `actorId` is an opaque id — regulators want human identities. | **Out of scope.** Report exposes `actorId` as recorded; identity resolution is a join against an external directory. | Identity mapping is a separate system with its own privacy controls. |
| 8 | Is running the report itself sensitive? | Should generating a compliance report be audited? | **Yes** — every report generation appends a `COMPLIANCE_REPORT_GENERATED` event (requester, filter, result hash, bundle hash). | Access to compliance tooling is itself auditable activity. |

## 2. Clarified requirement statement (what I built from)

> Provide an **on-demand Compliance Access Report API**. Given a client-account resource
> (`resourceType` in the configured client-data set, plus a `resourceId`) and a time range
> `[from, to)`, return a tamper-evident report of every recorded event whose type is in the
> configured "access" set for that account — including actor, event time, event type, and a
> redaction-aware indication of which payload fields are present/redacted. The report includes a
> chain-verification result and a completeness statement (seq range, count), and embeds a
> self-contained verifiable export bundle of exactly those records. Generating the report is
> itself recorded as an audit event. Regulator authentication, scheduled delivery, document
> rendering, and actor-identity resolution are out of scope.

## 3. Design produced from the clarified requirement

- Config: `AuditProperties.Compliance { accessEventTypes, clientDataResourceTypes }`.
- `GET /audit/compliance/access-report?resourceType=&resourceId=&from=&to=` (scope `READ`).
- `ComplianceReportService`:
  1. Reject `resourceType` not in the client-data set (400) — enforces the data-classification
     boundary.
  2. Query `audit_event` by `resourceType + resourceId`, `event_timestamp` in `[from, to)`,
     ordered by `seq`; keep only events whose type is in `accessEventTypes`.
  3. Build `entries[]` (seq, eventId, eventType, actorId, timestamps, redactedPaths).
  4. Build an embedded `ExportBundle` for exactly those seqs (reuses Scenario B — `exportForSeqs`).
  5. Run a full-chain `verify`.
  6. Compute `completeness { chainRangeFromSeq, chainRangeToSeq, matchedCount, chainIntact }`.
  7. Compute `reportHash` over the request + bundle hash + count.
  8. Append `COMPLIANCE_REPORT_GENERATED` to the chain.
- Response also carries a plain-language `disclaimer` about what the report does and does not
  attest to (it covers only configured access events and only what is in the chain).

## 4. What I implemented vs. scoped out

**Implemented:** the endpoint, config-driven classification, the report object with embedded
verifiable bundle + chain verification + completeness, the meta-audit event, and the
data-classification guard. Tested in `compliance/ComplianceReportIT.java`
(`reportsAccessEventsForAnAccountAndIsItselfAudited`,
`rejectsResourceTypeThatIsNotClientAccountData`).

**Scoped out, with reason:**

| Not built | Why | Rough effort to add |
|---|---|---|
| Regulator authentication portal | Separate product; different threat model | large |
| CSV / PDF rendering | Presentation layer; no integrity value | small–medium |
| Scheduled / pushed delivery (e.g. quarterly) | Ops concern; needs a delivery channel + retry semantics | medium |
| Actor identity resolution | External directory join; own privacy controls | medium |
| Cross-account / portfolio reports | Needs an account-grouping concept the domain doesn't have yet | medium |
| External timestamp anchoring (RFC-3161 / transparency log) | Protects against a malicious operator; valuable but orthogonal to this requirement | medium |
| Legal-hold / retention exemption interaction | Needs a legal-hold feature first | medium |

## 5. Scope boundary (explicit)

The report is only as complete as the events that were emitted into the log by upstream systems —
it attests that *recorded* access events are present and unaltered, not that every real-world
access was recorded. This is stated in the response `disclaimer` and is the honest limit of an
audit log that trusts its producers.
