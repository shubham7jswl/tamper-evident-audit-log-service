package com.sj.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** One redacted payload leaf. Immutable audit trail of a redaction action. */
@Entity
@Table(name = "redaction")
public class Redaction {

  @Id
  @Column(name = "redaction_id", updatable = false)
  private UUID redactionId;

  @Column(name = "event_seq", updatable = false, nullable = false)
  private long eventSeq;

  @Column(name = "field_path", updatable = false, nullable = false)
  private String fieldPath;

  @Column(name = "field_commitment", updatable = false, nullable = false, length = 64)
  private String fieldCommitment;

  /** Hex salt for the redacted leaf; null when the salt was destroyed for stronger erasure. */
  @Column(name = "field_salt", updatable = false)
  private String fieldSalt;

  @Column(name = "salt_retained", updatable = false, nullable = false)
  private boolean saltRetained;

  @Column(name = "reason", updatable = false, nullable = false)
  private String reason;

  @Column(name = "redacted_by", updatable = false, nullable = false)
  private String redactedBy;

  @Column(name = "redacted_at", updatable = false, nullable = false)
  private Instant redactedAt;

  protected Redaction() {}

  public Redaction(
      UUID redactionId,
      long eventSeq,
      String fieldPath,
      String fieldCommitment,
      String fieldSalt,
      boolean saltRetained,
      String reason,
      String redactedBy,
      Instant redactedAt) {
    this.redactionId = redactionId;
    this.eventSeq = eventSeq;
    this.fieldPath = fieldPath;
    this.fieldCommitment = fieldCommitment;
    this.fieldSalt = fieldSalt;
    this.saltRetained = saltRetained;
    this.reason = reason;
    this.redactedBy = redactedBy;
    this.redactedAt = redactedAt;
  }

  public UUID getRedactionId() {
    return redactionId;
  }

  public long getEventSeq() {
    return eventSeq;
  }

  public String getFieldPath() {
    return fieldPath;
  }

  public String getFieldCommitment() {
    return fieldCommitment;
  }

  public String getFieldSalt() {
    return fieldSalt;
  }

  public boolean isSaltRetained() {
    return saltRetained;
  }

  public String getReason() {
    return reason;
  }

  public String getRedactedBy() {
    return redactedBy;
  }

  public Instant getRedactedAt() {
    return redactedAt;
  }
}
