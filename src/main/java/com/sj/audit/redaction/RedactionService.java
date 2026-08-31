package com.sj.audit.redaction;

import com.sj.audit.chain.ChainAppender;
import com.sj.audit.config.AuditProperties;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.domain.Redaction;
import com.sj.audit.domain.RedactionRepository;
import com.sj.audit.hash.CanonicalJson;
import com.sj.audit.hash.JsonPointers;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Structured redaction of individual payload leaves.
 *
 * <p>Because {@code content_hash} was computed over per-leaf <em>salted commitments</em> (never the
 * raw payload), we can delete a leaf's plaintext without recomputing any hash: the chain stays
 * valid and verification still passes. The removed value is replaced in {@code payload_json} by a
 * {@code "__REDACTED__:<id>"} sentinel; the commitment is copied into the {@code redaction} table
 * for auditing and (optionally) later disclosure proof. Every redaction also writes a
 * {@code AUDIT_RECORD_REDACTED} meta event to the chain.
 *
 * <p>Trade-off: retaining the salt lets someone later prove a disclosed value matches the
 * commitment; destroying it ({@code retainSalt=false}) is a stronger erasure but forecloses that
 * proof. See {@code docs/scenarios/scenario-b.md}.
 */
@Service
public class RedactionService {

  public static final String REDACTION_SENTINEL_PREFIX = "__REDACTED__:";
  public static final String REDACTION_META_EVENT_TYPE = "AUDIT_RECORD_REDACTED";

  private final AuditEventRepository auditEvents;
  private final RedactionRepository redactions;
  private final ChainAppender chainAppender;
  private final JsonSupport jsonCodec;
  private final AuditProperties properties;
  private final Clock clock;

  public RedactionService(
      AuditEventRepository auditEvents,
      RedactionRepository redactions,
      ChainAppender chainAppender,
      JsonSupport jsonCodec,
      AuditProperties properties,
      Clock clock) {
    this.auditEvents = auditEvents;
    this.redactions = redactions;
    this.chainAppender = chainAppender;
    this.jsonCodec = jsonCodec;
    this.properties = properties;
    this.clock = clock;
  }

  public record RedactRequest(
      UUID eventId,
      List<String> fieldPaths,
      String reason,
      String redactedBy,
      Boolean retainSalt) {}

  public record RedactedField(String fieldPath, UUID redactionId, String commitment) {}

  public record RedactionResult(
      UUID eventId, long seq, List<RedactedField> redactedFields, UUID metaEventId) {}

  @Transactional
  public RedactionResult redact(RedactRequest request) {
    AuditEvent event =
        auditEvents
            .findByEventId(request.eventId())
            .orElseThrow(() -> new NoSuchElementException("no audit event " + request.eventId()));
    if (event.isArchived()) {
      throw new IllegalStateException("cannot redact archived record seq=" + event.getSeq());
    }
    if (request.fieldPaths() == null || request.fieldPaths().isEmpty()) {
      throw new IllegalArgumentException("fieldPaths must not be empty");
    }

    JsonNode payload = jsonCodec.parse(event.getPayloadJson());
    Map<String, String> saltByPointer = jsonCodec.readStringMap(event.getLeafSaltsJson());
    Map<String, String> commitmentByPointer =
        jsonCodec.readStringMap(event.getLeafCommitmentsJson());
    boolean retainSalt =
        request.retainSalt() != null
            ? request.retainSalt()
            : properties.redaction().retainSaltByDefault();

    List<RedactedField> redactedFields = new ArrayList<>();
    for (String pointer : request.fieldPaths()) {
      if (!commitmentByPointer.containsKey(pointer)) {
        throw new IllegalArgumentException("payload has no leaf at " + pointer);
      }
      if (redactions.existsByEventSeqAndFieldPath(event.getSeq(), pointer)) {
        throw new IllegalStateException(pointer + " is already redacted on seq " + event.getSeq());
      }
      String commitment = commitmentByPointer.get(pointer);
      String salt = saltByPointer.remove(pointer);
      UUID redactionId = UUID.randomUUID();

      JsonPointers.setStringLeaf(payload, pointer, REDACTION_SENTINEL_PREFIX + redactionId);
      redactions.save(
          new Redaction(
              redactionId,
              event.getSeq(),
              pointer,
              commitment,
              retainSalt ? salt : null,
              retainSalt && salt != null,
              request.reason(),
              request.redactedBy(),
              clock.instant()));
      redactedFields.add(new RedactedField(pointer, redactionId, commitment));
    }

    event.applyRedaction(
        CanonicalJson.canonicalize(payload), jsonCodec.writeStringMap(saltByPointer));

    ObjectNode metaEventPayload = jsonCodec.newObject();
    metaEventPayload.put("targetEventId", event.getEventId().toString());
    metaEventPayload.put("targetSeq", event.getSeq());
    metaEventPayload.put("reason", request.reason());
    metaEventPayload.put("redactedBy", request.redactedBy());
    metaEventPayload.put("saltRetained", retainSalt);
    var redactedPointers = metaEventPayload.putArray("fieldPaths");
    redactedFields.forEach(field -> redactedPointers.add(field.fieldPath()));

    AuditEvent metaEvent =
        chainAppender.append(
            new ChainAppender.NewEvent(
                REDACTION_META_EVENT_TYPE,
                request.redactedBy(),
                "AUDIT_EVENT",
                event.getEventId().toString(),
                metaEventPayload,
                null));

    return new RedactionResult(
        event.getEventId(), event.getSeq(), redactedFields, metaEvent.getEventId());
  }
}
