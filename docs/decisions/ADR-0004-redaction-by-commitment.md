# ADR-0004: Redaction by pre-committed leaves

**Status:** Accepted

## Context

Scenario B: sensitive values inside a record's payload (account numbers, personal identifiers)
must be redactable to satisfy privacy law, **without breaking the hash chain**. The naive approach
— delete the value — invalidates `content_hash` and every subsequent `record_hash`.

## Decision

Make the content hash depend on payload values only *through per-leaf salted commitments*, decided
at write time:

- At append: for every payload leaf, generate a random 128-bit salt and compute
  `commitment = SHA-256("LEAF1" | saltHex | typeTag+canonicalValue)`. Store the pointer→salt map
  (`leaf_salts_json`) and the pointer→commitment map (`leaf_commitments_json`). `content_hash`
  covers the commitment map, never the raw values.
- To redact a leaf: remove its plaintext from `payload_json` (replace with a
  `"__REDACTED__:<redactionId>"` sentinel), remove its salt from `leaf_salts_json`, and write a
  `redaction` row recording `{ path, commitment, retained-salt?, reason, redactedBy, time }`.
  **No hash is recomputed** — `content_hash` and `record_hash` are untouched, so the chain stays
  valid.
- The redaction action itself is appended to the chain as an `AUDIT_RECORD_REDACTED` event
  (meta-audit).
- Verification skips plaintext recomputation for redacted paths and uses the stored commitment
  (which is still bound into `record_hash`).

### Salt retention trade-off

- **Retain the salt** (default): a party who is later lawfully disclosed the original value can
  prove it matches — `SHA-256("LEAF1" | salt | value) == commitment`.
- **Destroy the salt** (`retainSalt=false`): stronger erasure (the commitment then reveals
  nothing computationally useful even against a guessed value), at the cost of that disclosure
  proof.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep an encrypted copy of the original and re-derive the hash on verify | Not real erasure; the plaintext still exists under a key. |
| Recompute `content_hash`/`record_hash` on redaction and re-link forward | Rewrites history; indistinguishable from tampering; breaks any previously exported bundle. |
| Unsalted per-leaf hash `SHA-256(value)` | Low-entropy values (16-digit account numbers, SSNs) are brute-forceable from the hash after redaction. |
| Redact whole records only | Too coarse for "redact the account number, keep the rest". |

## Consequences and limitations

- Verification proves the **non-redacted** fields and the record structure are intact and that a
  redaction is recorded — it cannot re-derive the redacted plaintext (by design).
- While plaintext is present, changing it is caught by the leaf-commitment check. Once redacted,
  integrity of that field rests on the commitment being chained into `record_hash`.
- **Core fields** (`eventType`, `actorId`, `resourceType`, `resourceId`, timestamps) are hashed
  directly and are **not redactable**. If a deployment needs redactable actor identifiers, move
  them into the payload.
- Redaction is irreversible with respect to the plaintext; there is no "un-redact".
