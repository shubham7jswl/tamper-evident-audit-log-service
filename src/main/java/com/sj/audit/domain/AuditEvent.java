package com.sj.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One immutable record in the append-only hash chain.
 *
 * <p>There are deliberately no generic setters. The only post-insert mutations allowed are the two
 * audited domain operations {@link #applyRedaction} and {@link #archiveAsTombstone}; both preserve
 * every hash column so chain verification still closes over the row.
 */
@Entity
@Table(name = "audit_event")
public class AuditEvent {

  @Id
  @Column(name = "seq", updatable = false)
  private Long seq;

  @Column(name = "event_id", updatable = false, nullable = false)
  private UUID eventId;

  @Column(name = "event_type", updatable = false, nullable = false)
  private String eventType;

  @Column(name = "actor_id", updatable = false, nullable = false)
  private String actorId;

  @Column(name = "resource_type", updatable = false, nullable = false)
  private String resourceType;

  @Column(name = "resource_id", updatable = false, nullable = false)
  private String resourceId;

  /** Canonical JSON of the payload as stored/returned; null once archived. */
  @Column(name = "payload_json")
  private String payloadJson;

  /** JSON object: JSON Pointer -> hex salt; entries removed on redaction; null once archived. */
  @Column(name = "leaf_salts_json")
  private String leafSaltsJson;

  /** JSON object: JSON Pointer -> hex commitment; never mutated, never null. */
  @Column(name = "leaf_commitments_json", updatable = false, nullable = false)
  private String leafCommitmentsJson;

  @Column(name = "event_timestamp", updatable = false, nullable = false)
  private Instant eventTimestamp;

  @Column(name = "recorded_at", updatable = false, nullable = false)
  private Instant recordedAt;

  @Column(name = "content_hash", updatable = false, nullable = false, length = 64)
  private String contentHash;

  @Column(name = "prev_hash", updatable = false, nullable = false, length = 64)
  private String prevHash;

  @Column(name = "record_hash", updatable = false, nullable = false, length = 64)
  private String recordHash;

  @Column(name = "archived_at")
  private Instant archivedAt;

  protected AuditEvent() {
    // for Hibernate
  }

  public AuditEvent(
      long seq,
      UUID eventId,
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      String payloadJson,
      String leafSaltsJson,
      String leafCommitmentsJson,
      Instant eventTimestamp,
      Instant recordedAt,
      String contentHash,
      String prevHash,
      String recordHash) {
    this.seq = seq;
    this.eventId = eventId;
    this.eventType = eventType;
    this.actorId = actorId;
    this.resourceType = resourceType;
    this.resourceId = resourceId;
    this.payloadJson = payloadJson;
    this.leafSaltsJson = leafSaltsJson;
    this.leafCommitmentsJson = leafCommitmentsJson;
    this.eventTimestamp = eventTimestamp;
    this.recordedAt = recordedAt;
    this.contentHash = contentHash;
    this.prevHash = prevHash;
    this.recordHash = recordHash;
  }

  /** Replace the stored payload / salt map after redacting one or more leaves. */
  public void applyRedaction(String newPayloadJson, String newLeafSaltsJson) {
    if (isArchived()) {
      throw new IllegalStateException("cannot redact an archived record: seq=" + seq);
    }
    this.payloadJson = newPayloadJson;
    this.leafSaltsJson = newLeafSaltsJson;
  }

  /** Drop payload + salts, keep all hashes: the row becomes a chain-linking tombstone. */
  public void archiveAsTombstone(Instant when) {
    this.payloadJson = null;
    this.leafSaltsJson = null;
    this.archivedAt = when;
  }

  public boolean isArchived() {
    return archivedAt != null;
  }

  public Long getSeq() {
    return seq;
  }

  public UUID getEventId() {
    return eventId;
  }

  public String getEventType() {
    return eventType;
  }

  public String getActorId() {
    return actorId;
  }

  public String getResourceType() {
    return resourceType;
  }

  public String getResourceId() {
    return resourceId;
  }

  public String getPayloadJson() {
    return payloadJson;
  }

  public String getLeafSaltsJson() {
    return leafSaltsJson;
  }

  public String getLeafCommitmentsJson() {
    return leafCommitmentsJson;
  }

  public Instant getEventTimestamp() {
    return eventTimestamp;
  }

  public Instant getRecordedAt() {
    return recordedAt;
  }

  public String getContentHash() {
    return contentHash;
  }

  public String getPrevHash() {
    return prevHash;
  }

  public String getRecordHash() {
    return recordHash;
  }

  public Instant getArchivedAt() {
    return archivedAt;
  }
}
