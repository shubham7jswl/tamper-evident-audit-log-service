package com.sj.audit.api;

import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.hash.Instants;
import java.util.List;
import tools.jackson.databind.JsonNode;

/** Read model for a single audit record. */
public record AuditEventResponse(
    long seq,
    String eventId,
    String eventType,
    String actorId,
    String resourceType,
    String resourceId,
    JsonNode payload,
    List<String> redactedPaths,
    String eventTimestamp,
    String recordedAt,
    String contentHash,
    String prevHash,
    String recordHash,
    boolean archived) {

  public static AuditEventResponse from(
      AuditEvent e, JsonSupport json, List<String> redactedPaths) {
    return new AuditEventResponse(
        e.getSeq(),
        e.getEventId().toString(),
        e.getEventType(),
        e.getActorId(),
        e.getResourceType(),
        e.getResourceId(),
        e.getPayloadJson() == null ? null : json.parse(e.getPayloadJson()),
        redactedPaths,
        Instants.canonical(e.getEventTimestamp()),
        Instants.canonical(e.getRecordedAt()),
        e.getContentHash(),
        e.getPrevHash(),
        e.getRecordHash(),
        e.isArchived());
  }
}
