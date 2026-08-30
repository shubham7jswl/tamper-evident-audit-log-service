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

  public static final String SENTINEL_PREFIX = "__REDACTED__:";
  public static final String META_EVENT_TYPE = "AUDIT_RECORD_REDACTED";

  private final AuditEventRepository events;
  private final RedactionRepository redactions;
  private final ChainAppender appender;
  private final JsonSupport json;
  private final AuditProperties properties;
  private final Clock clock;

  public RedactionService(
      AuditEventRepository events,
      RedactionRepository redactions,
      ChainAppender appender,
      JsonSupport json,
      AuditProperties properties,
      Clock clock) {
    this.events = events;
    this.redactions = redactions;
    this.appender = appender;
    this.json = json;
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
        events
            .findByEventId(request.eventId())
            .orElseThrow(
                () -> new NoSuchElementException("no audit event " + request.eventId()));
    if (event.isArchived()) {
      throw new IllegalStateException("cannot redact archived record seq=" + event.getSeq());
    }
    if (request.fieldPaths() == null || request.fieldPaths().isEmpty()) {
      throw new IllegalArgumentException("fieldPaths must not be empty");
    }

    JsonNode payload = json.parse(event.getPayloadJson());
    Map<String, String> salts = json.readStringMap(event.getLeafSaltsJson());
    Map<String, String> commitments = json.readStringMap(event.getLeafCommitmentsJson());
    boolean retainSalt =
        request.retainSalt() != null
            ? request.retainSalt()
            : properties.redaction().retainSaltByDefault();

    List<RedactedField> redacted = new ArrayList<>();
    for (String path : request.fieldPaths()) {
      if (!commitments.containsKey(path)) {
        throw new IllegalArgumentException("payload has no leaf at " + path);
      }
      if (redactions.existsByEventSeqAndFieldPath(event.getSeq(), path)) {
        throw new IllegalStateException(path + " is already redacted on seq " + event.getSeq());
      }
      String commitment = commitments.get(path);
      String salt = salts.remove(path);
      UUID redactionId = UUID.randomUUID();

      JsonPointers.setStringLeaf(payload, path, SENTINEL_PREFIX + redactionId);
      redactions.save(
          new Redaction(
              redactionId,
              event.getSeq(),
              path,
              commitment,
              retainSalt ? salt : null,
              retainSalt && salt != null,
              request.reason(),
              request.redactedBy(),
              clock.instant()));
      redacted.add(new RedactedField(path, redactionId, commitment));
    }

    event.applyRedaction(CanonicalJson.canonicalize(payload), json.writeStringMap(salts));

    ObjectNode metaPayload = json.newObject();
    metaPayload.put("targetEventId", event.getEventId().toString());
    metaPayload.put("targetSeq", event.getSeq());
    metaPayload.put("reason", request.reason());
    metaPayload.put("redactedBy", request.redactedBy());
    metaPayload.put("saltRetained", retainSalt);
    var paths = metaPayload.putArray("fieldPaths");
    redacted.forEach(f -> paths.add(f.fieldPath()));

    AuditEvent meta =
        appender.append(
            new ChainAppender.NewEvent(
                META_EVENT_TYPE,
                request.redactedBy(),
                "AUDIT_EVENT",
                event.getEventId().toString(),
                metaPayload,
                null));

    return new RedactionResult(event.getEventId(), event.getSeq(), redacted, meta.getEventId());
  }
}
