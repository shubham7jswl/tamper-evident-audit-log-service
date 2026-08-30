package com.sj.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Single-row bookkeeping table (id = 1). Serves two purposes:
 *
 * <ul>
 *   <li>a lock target — appends take a {@code PESSIMISTIC_WRITE} lock on this row so the chain has
 *       exactly one writer at a time, even across multiple app instances on a shared DB;
 *   <li>a cache of the current head so an append never has to scan the tail of {@code audit_event}.
 * </ul>
 */
@Entity
@Table(name = "chain_head")
public class ChainHead {

  public static final short SINGLETON_ID = 1;

  @Id
  @Column(name = "id")
  private Short id;

  @Column(name = "last_seq", nullable = false)
  private long lastSeq;

  @Column(name = "last_record_hash", nullable = false, length = 64)
  private String lastRecordHash;

  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  protected ChainHead() {}

  public void advance(long newSeq, String newRecordHash, Instant when) {
    this.lastSeq = newSeq;
    this.lastRecordHash = newRecordHash;
    this.updatedAt = when;
  }

  public long getLastSeq() {
    return lastSeq;
  }

  public String getLastRecordHash() {
    return lastRecordHash;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }
}
