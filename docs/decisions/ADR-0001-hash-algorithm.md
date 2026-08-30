# ADR-0001: Hash algorithm — SHA-256

**Status:** Accepted

## Context

The chain needs a cryptographic hash for content commitments and record links. Requirements:
second-preimage and collision resistance for the foreseeable life of the data; ubiquitous library
support (recipients must be able to independently verify exports); acceptable performance for
full-chain scans; and a good story for compliance reviewers.

## Decision

Use **SHA-256** (FIPS 180-4) everywhere. HMAC-SHA-256 for the optional export-bundle signature.

## Alternatives considered

| Option | Why not |
|---|---|
| SHA-512 | ~Same security margin for our purposes; wider output inflates storage; marginal speed win on 64-bit not worth the asymmetry with tooling defaults. |
| SHA-3 / SHA3-256 | No practical security advantage here; slower in software; less pervasive in client libraries a bundle recipient might use. |
| BLAKE3 | Fast, but not FIPS/NIST-standardized; weaker "explain it to an auditor" story; fewer drop-in implementations across languages. |
| Non-cryptographic (CRC, xxHash) | No preimage resistance — an attacker could recompute forward. Disqualified. |

## Consequences

- 32-byte / 64-hex-char hashes stored in three columns per row.
- Domain separation: every multi-input hash is prefixed (`"REC1"`, `"LEAF1"`) and delimited
  (`0x1F`); each part is a fixed-length hex string or short tag, so concatenation is unambiguous
  and length-extension is a non-issue.
- Migrating algorithms later means a `content_hash` version bump (the hashable view already
  carries `"v"`), re-hashing forward from a checkpoint, and publishing both old and new head
  hashes during transition.
