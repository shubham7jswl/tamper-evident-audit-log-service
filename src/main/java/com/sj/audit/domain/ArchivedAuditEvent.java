package com.sj.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Full, immutable copy of a record taken at archival time. Kept so deep verification can still
 * recompute an archived row's content hash from its original fields. In production this table is a
 * candidate for separate WORM / cold storage.
 */
@Entity
@Table(name = "archived_audit_event")
public class ArchivedAuditEvent {

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

  @Column(name = "payload_json")
  private String payloadJson;

  @Column(name = "leaf_salts_json")
  private String leafSaltsJson;

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

  @Column(name = "archived_at", updatable = false, nullable = false)
  private Instant archivedAt;

  protected ArchivedAuditEvent() {}

  public static ArchivedAuditEvent copyOf(AuditEvent e, Instant archivedAt) {
    ArchivedAuditEvent a = new ArchivedAuditEvent();
    a.seq = e.getSeq();
    a.eventId = e.getEventId();
    a.eventType = e.getEventType();
    a.actorId = e.getActorId();
    a.resourceType = e.getResourceType();
    a.resourceId = e.getResourceId();
    a.payloadJson = e.getPayloadJson();
    a.leafSaltsJson = e.getLeafSaltsJson();
    a.leafCommitmentsJson = e.getLeafCommitmentsJson();
    a.eventTimestamp = e.getEventTimestamp();
    a.recordedAt = e.getRecordedAt();
    a.contentHash = e.getContentHash();
    a.prevHash = e.getPrevHash();
    a.recordHash = e.getRecordHash();
    a.archivedAt = archivedAt;
    return a;
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
