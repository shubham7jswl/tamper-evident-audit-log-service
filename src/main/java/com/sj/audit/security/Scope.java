package com.sj.audit.security;

/** Coarse-grained capabilities carried by an API key. */
public enum Scope {
  /** Append new audit events. */
  WRITE,
  /** Read / query events, run chain verification, export bundles, run compliance reports. */
  READ,
  /** High-impact operations: redaction and retention runs. */
  ADMIN
}
