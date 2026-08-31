package com.sj.audit.enums;

/** Classifies the first inconsistency found while walking the hash chain. */
public enum ViolationType {

  /** The first record's {@code prev_hash} is not the configured genesis value. */
  GENESIS_MISMATCH,

  /** A {@code seq} is missing — a record was deleted (archival leaves a tombstone, not a gap). */
  SEQUENCE_GAP,

  /** Recomputed content hash != stored {@code content_hash} (a core field or the commitment map changed). */
  CONTENT_HASH_MISMATCH,

  /** A non-redacted payload leaf no longer matches its stored salted commitment. */
  LEAF_COMMITMENT_MISMATCH,

  /** Recomputed {@code SHA-256("REC1" | prev_hash | content_hash)} != stored {@code record_hash}. */
  RECORD_HASH_MISMATCH,

  /** A record's {@code prev_hash} does not equal the previous record's {@code record_hash}. */
  PREV_HASH_MISMATCH,

  /** A verifiable (live, non-redacted) leaf has no stored salt — datastore corruption. */
  MISSING_SALT
}
