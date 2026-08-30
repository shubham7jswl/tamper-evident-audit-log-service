package com.sj.audit.chain;

import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.domain.ChainHead;
import com.sj.audit.domain.ChainHeadRepository;
import com.sj.audit.hash.AuditHasher;
import com.sj.audit.hash.CanonicalJson;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;

/**
 * The single writer of the hash chain.
 *
 * <p>Every append runs in one transaction that first takes a {@code PESSIMISTIC_WRITE} lock on the
 * {@code chain_head} row. That lock is what guarantees a total order on appends and a gap-free
 * {@code seq}, even with multiple service instances against one database. Throughput is therefore
 * bounded by a single writer — an acceptable trade-off for an audit log (see
 * {@code docs/decisions/ADR-0003-single-writer-append.md}).
 */
@Service
public class ChainAppender {

  private final ChainHeadRepository chainHead;
  private final AuditEventRepository events;
  private final AuditHasher hasher;
  private final JsonSupport json;
  private final Clock clock;

  public ChainAppender(
      ChainHeadRepository chainHead,
      AuditEventRepository events,
      AuditHasher hasher,
      JsonSupport json,
      Clock clock) {
    this.chainHead = chainHead;
    this.events = events;
    this.hasher = hasher;
    this.json = json;
    this.clock = clock;
  }

  public record NewEvent(
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      JsonNode payload,
      Instant eventTimestamp) {}

  @Transactional
  public AuditEvent append(NewEvent cmd) {
    ChainHead head = chainHead.lockHead();
    long seq = head.getLastSeq() + 1;
    String prevHash = head.getLastRecordHash();

    Instant recordedAt = clock.instant();
    Instant eventTimestamp = cmd.eventTimestamp() != null ? cmd.eventTimestamp() : recordedAt;
    UUID eventId = UUID.randomUUID();

    JsonNode payload = cmd.payload();
    String canonicalPayload = CanonicalJson.canonicalize(payload);
    Map<String, String> salts = hasher.freshSalts(payload);
    Map<String, String> commitments = hasher.commitmentsFor(payload, salts);

    String contentHash =
        hasher.contentHash(
            new AuditHasher.HashInputs(
                seq,
                eventId,
                cmd.eventType(),
                cmd.actorId(),
                cmd.resourceType(),
                cmd.resourceId(),
                eventTimestamp,
                recordedAt,
                commitments));
    String recordHash = hasher.recordHash(prevHash, contentHash);

    AuditEvent event =
        new AuditEvent(
            seq,
            eventId,
            cmd.eventType(),
            cmd.actorId(),
            cmd.resourceType(),
            cmd.resourceId(),
            canonicalPayload,
            json.writeStringMap(salts),
            json.writeStringMap(commitments),
            eventTimestamp,
            recordedAt,
            contentHash,
            prevHash,
            recordHash);
    events.save(event);

    head.advance(seq, recordHash, recordedAt);
    return event;
  }
}
