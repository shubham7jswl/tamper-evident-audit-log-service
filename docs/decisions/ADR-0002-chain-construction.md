# ADR-0002: Chain construction — content hash, record hash, genesis

**Status:** Accepted

## Context

We must define exactly what each record commits to, and how records link, such that any
modification to a past record invalidates its own hash and every subsequent hash.

## Decision

Two hashes per record:

- `content_hash = SHA-256(CanonicalJson(hashableView))` where
  `hashableView = { v:1, seq, eventId, eventType, actorId, resourceType, resourceId,
  eventTimestamp, recordedAt, payloadLeafHashes }`.
  `payloadLeafHashes` is a map of JSON Pointer → per-leaf salted commitment (see ADR-0004); the
  payload's actual values are **not** in the content hash.
- `record_hash = SHA-256("REC1" | prev_hash | content_hash)`.
  `prev_hash` = previous record's `record_hash`, or, for `seq = 1`, the genesis constant
  `SHA-256("tamper-evident-audit-log::genesis::v1")` =
  `cdb3681748c47491bb74d81d0c8fb45444a52577331ee03b951cb2b9775fe0fa`.

`seq` is included in the content hash and is assigned by the application (not the DB) so that
reordering or renumbering is detectable and the value is known before hashing.

### Canonicalization

`CanonicalJson`: keys sorted by Unicode code point, no whitespace, integers without a decimal
point, decimals via `BigDecimal.toPlainString()` with trailing zeros stripped, only mandatory JSON
string escapes, UTF-8 output. **Known limitation:** not byte-identical to RFC 8785 (JCS) for
exotic floating-point values (it does not reproduce ECMAScript `Number.toString`). Mitigation:
send sensitive numeric payload data as strings or integers. This is acceptable because audit
payloads are structured domain data, not arbitrary floats, and the same serializer is used on
both the write and verify paths.

## Alternatives considered

- **Hash the raw canonical payload blob into `content_hash`.** Simpler, but redaction then
  necessarily invalidates the hash — the whole point of Scenario B. Rejected.
- **Merkle tree per record instead of a flat pointer→commitment map.** Enables O(log n) inclusion
  proofs for individual fields. Deferred — the flat map already gives per-field redaction and the
  map's key set already commits structure; a Merkle upgrade is compatible via a `v:2` hashable
  view.
- **Single hash (`record_hash` only).** Loses the ability to talk about "the record's content" vs
  "the record's position", and complicates redaction and export. Rejected.

## Consequences

- Adding/removing/reordering a payload leaf changes the pointer set in `payloadLeafHashes` →
  changes `content_hash` → detected.
- Empty objects/arrays are committed via a synthetic marker leaf so their removal is also
  detected.
- Verification recomputes `content_hash` from stored fields + stored commitments, and (for live
  rows) additionally recomputes each non-redacted leaf commitment from the live payload value.
