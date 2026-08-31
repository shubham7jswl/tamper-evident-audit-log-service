# Scenario B — Retention and Redaction

Three extensions to the Scenario A service: retention/archival, structured redaction, and
verifiable bulk export.

---

## B1. Retention policy

### Requirement understanding

Records older than a configurable window become archivable/soft-deletable; chain verification must
not report a false break for legitimately archived records.

### Decomposition

1. Config: `audit.retention.window` (Duration), `enabled`, `scheduled`, `scheduled-cron`.
2. `archived_audit_event` table (full copies).
3. `RetentionService.run()`: find live rows with `recorded_at < now - window`, copy to archive,
   convert live row to a tombstone (payload + salts nulled, hashes kept, `archived_at` set).
4. `ChainVerifier`: recognise tombstones; verify chain math from the retained `content_hash`;
   `deep=true` re-hashes from the archive copy; report `archivedSegments`.
5. `POST /audit/retention/run` (ADMIN) + optional `@Scheduled` job.

### Design & rationale

Tombstones, not deletes — see `docs/decisions/ADR-0005-retention-tombstones.md`. The key insight:
a retained `content_hash` is still bound into `record_hash`, so the chain still closes over an
archived row and tampering with the tombstone's hashes is still caught. Deep verification is what
protects the *archive contents*.

### Validation (`retention/RetentionServiceIT.java`)

- `archivedRecordsDoNotBreakVerification`: window `PT0S`, 3 events archived → shallow verify
  `intact:true`, `archivedSegments = [{1,3}]`; deep verify also `intact:true`.
- `deepVerificationDetectsTamperInsideAnArchivedRow`: mutate `archived_audit_event.payload_json`
  → shallow still `true` (can't see it), deep `false`.

### Limitations

Archive integrity depends on the archive store; in production it belongs in WORM storage.
Retention is all-or-nothing per age; no legal-hold exemption mechanism (noted as future work).

---

## B2. Structured redaction

### Requirement understanding

Sensitive fields inside a record's payload must be redactable for privacy, without breaking the
hash chain — "the original hash covers the original value, so simply removing the value would
invalidate the hash."

### The engineering problem, stated precisely

We need a scheme where, after redaction: (a) the redacted plaintext is gone from the datastore;
(b) `GET /audit/verify` still returns `intact:true`; (c) verification still detects tampering with
the *non-redacted* parts of the record; (d) the redaction is itself auditable.

### Design — pre-committed leaves

Full rationale and alternatives: `docs/decisions/ADR-0004-redaction-by-commitment.md`. Summary:

- `content_hash` is computed over **per-leaf salted commitments**, decided at write time — never
  over the raw payload values. `commitment = SHA-256("LEAF1" | salt | typeTag+value)`,
  fresh 128-bit salt per leaf.
- Redaction removes the plaintext (replaced by a `"__REDACTED__:<id>"` sentinel) and the salt,
  and records a `redaction` row with the commitment. **No hash is recomputed.** Chain stays valid.
- A `AUDIT_RECORD_REDACTED` meta event is appended to the chain.
- Verification skips plaintext recomputation for redacted paths (driven by the `redaction` table,
  not the sentinel string) and trusts the stored commitment, which is chained into `record_hash`.

### Trade-offs considered

| Choice | Trade-off |
|---|---|
| Salt retained (default) | Enables later "does this disclosed value match the commitment?" proof. |
| Salt destroyed (`retainSalt=false`) | Stronger erasure; loses the disclosure proof. |
| Leaf-level granularity | Redact one field, keep the rest — but can't redact whole subtrees in one call (redact each leaf). |
| Core fields not redactable | `actorId` etc. are hashed directly; move them into payload if they must be redactable. |

### Limitations

Verification cannot re-derive redacted plaintext (by design). Tampering with a value *before* it
is redacted is caught by the leaf-commitment check; after redaction, that field's integrity rests
on the commitment. No un-redact.

### Validation (`redaction/RedactionServiceIT.java`)

- `redactedChainStillVerifiesAndHidesTheValue`: redact `/accountNumber` → `verify` still
  `intact:true`; stored payload contains the sentinel, not the number; sibling field intact.
- `writesAMetaAuditEvent`: an `AUDIT_RECORD_REDACTED` event is appended.
- `tamperingANonRedactedLeafIsStillDetected`: change a sibling field in the DB →
  `LEAF_COMMITMENT_MISMATCH`.
- `rejectsUnknownFieldPath`: redacting a non-existent pointer → 400.

---

## B3. Bulk verifiable export

### Requirement understanding

Export all records for a given `resourceId` or `actorId` as a self-contained bundle that a
recipient can independently verify were not altered since export.

### Design

`GET /audit/export?resourceId=` (or `?actorId=`) → `ExportBundle`:

- `records[]` — each with all fields, `payload` (redaction-aware), `leafSalts`,
  `leafCommitments`, `redactedPaths`, `contentHash`, `prevHash`, `recordHash`, `archived`.
- `segments[]` — for each contiguous run of selected `seq` values, the `priorRecordHash` (the
  `record_hash` of the record just before the run, or genesis).
- `bundleHash` = `SHA-256` of the canonical bundle JSON with `bundleHash`/`hmac` nulled;
  `hmac` = `HMAC-SHA-256(secret, bundleHash)` when `audit.export.hmac-secret` is set.

**Subset verification insight:** a filter by `resourceId` yields a *non-contiguous* set of `seq`
values. Each record still carries its own `prevHash` and `recordHash`, so a recipient can verify,
per record, that `contentHash` recomputes from fields + commitments **and**
`recordHash == SHA-256("REC1" | prevHash | contentHash)` — proving each record is individually
unaltered and correctly linked to its predecessor, even without the neighbours. `segments`
provide the anchor to walk full linkage within each run.

`BundleVerifier` (`com.sj.audit.utils`) is a standalone class (no Spring) so a recipient can run it
with just the `com.sj.audit.utils.hash` package + Jackson.

### Validation (`export/BundleExportIT.java`)

- `exportedBundleVerifiesIndependently`: export `acct-1` (non-contiguous seq 1 & 3) →
  `BundleVerifier.verify` valid; 2 segments.
- `tamperingABundleRecordFailsVerification`: mutate a payload value in the bundle → invalid.
- `tamperingTheBundleHashFailsVerification`: forge `bundleHash` → invalid.

### Limitations

The bundle format is `v1` and self-described but not a published standard. HMAC proves it came
from a holder of the shared secret, not a public-key signature (a real deployment would sign with
an asymmetric key the recipient trusts).
