package com.sj.audit.service;

import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.repository.AuditEventRepository;
import com.sj.audit.domain.ChainHead;
import com.sj.audit.repository.ChainHeadRepository;
import com.sj.audit.utils.hash.AuditHasher;
import com.sj.audit.utils.hash.CanonicalJson;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;

/**
 * The single writer of the hash chain: turns a {@link NewEvent} into a fully-hashed, persisted
 * {@link AuditEvent} and advances the chain head.
 *
 * <p>Every append runs in one transaction that first takes a {@code PESSIMISTIC_WRITE} lock on the
 * {@code chain_head} row. That lock is what guarantees a total order on appends and a gap-free
 * {@code seq}, even with multiple service instances against one database. Throughput is therefore
 * bounded by a single writer — an acceptable trade-off for an audit log (see
 * {@code docs/decisions/ADR-0003-single-writer-append.md}).
 */
@Service
public class ChainAppender {

  private final ChainHeadRepository chainHeadRepository;
  private final AuditEventRepository auditEvents;
  private final AuditHasher auditHasher;
  private final JsonSupport jsonCodec;
  private final Clock clock;

  public ChainAppender(
      ChainHeadRepository chainHeadRepository,
      AuditEventRepository auditEvents,
      AuditHasher auditHasher,
      JsonSupport jsonCodec,
      Clock clock) {
    this.chainHeadRepository = chainHeadRepository;
    this.auditEvents = auditEvents;
    this.auditHasher = auditHasher;
    this.jsonCodec = jsonCodec;
    this.clock = clock;
  }

  /** Everything a caller supplies for a new event; the server fills in the rest. */
  public record NewEvent(
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      JsonNode payload,
      Instant callerEventTimestamp) {}

  @Transactional
  public AuditEvent append(NewEvent newEvent) {
    ChainHead chainHead = chainHeadRepository.lockHead();
    long nextSeq = chainHead.getLastSeq() + 1;
    String previousRecordHash = chainHead.getLastRecordHash();

    Instant recordedAt = clock.instant();
    Instant eventTimestamp =
        newEvent.callerEventTimestamp() != null ? newEvent.callerEventTimestamp() : recordedAt;
    UUID eventId = UUID.randomUUID();

    JsonNode payload = newEvent.payload();
    String canonicalPayload = CanonicalJson.canonicalize(payload);
    Map<String, String> saltByPointer = auditHasher.newSaltPerLeaf(payload);
    Map<String, String> commitmentByPointer =
        auditHasher.computeLeafCommitments(payload, saltByPointer);

    String contentHash =
        auditHasher.contentHash(
            new AuditHasher.ContentHashInput(
                nextSeq,
                eventId,
                newEvent.eventType(),
                newEvent.actorId(),
                newEvent.resourceType(),
                newEvent.resourceId(),
                eventTimestamp,
                recordedAt,
                commitmentByPointer));
    String recordHash = auditHasher.recordHash(previousRecordHash, contentHash);

    AuditEvent event =
        new AuditEvent(
            nextSeq,
            eventId,
            newEvent.eventType(),
            newEvent.actorId(),
            newEvent.resourceType(),
            newEvent.resourceId(),
            canonicalPayload,
            jsonCodec.writeStringMap(saltByPointer),
            jsonCodec.writeStringMap(commitmentByPointer),
            eventTimestamp,
            recordedAt,
            contentHash,
            previousRecordHash,
            recordHash);
    auditEvents.save(event);

    chainHead.advance(nextSeq, recordHash, recordedAt);
    return event;
  }
}
