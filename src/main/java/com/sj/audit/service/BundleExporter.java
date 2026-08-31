package com.sj.audit.service;

import com.sj.audit.config.AuditProperties;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.export.ExportBundle;
import com.sj.audit.repository.AuditEventRepository;
import com.sj.audit.domain.Redaction;
import com.sj.audit.repository.RedactionRepository;
import com.sj.audit.utils.hash.CanonicalJson;
import com.sj.audit.utils.hash.Hashing;
import com.sj.audit.utils.hash.Instants;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** Builds {@link ExportBundle}s for a {@code resourceId}, an {@code actorId}, or an explicit seq set. */
@Service
public class BundleExporter {

  private final AuditEventRepository auditEvents;
  private final RedactionRepository redactions;
  private final JsonSupport jsonCodec;
  private final AuditProperties properties;
  private final Clock clock;

  public BundleExporter(
      AuditEventRepository auditEvents,
      RedactionRepository redactions,
      JsonSupport jsonCodec,
      AuditProperties properties,
      Clock clock) {
    this.auditEvents = auditEvents;
    this.redactions = redactions;
    this.jsonCodec = jsonCodec;
    this.properties = properties;
    this.clock = clock;
  }

  @Transactional(readOnly = true)
  public ExportBundle exportByResourceId(String resourceId) {
    return build(
        new ExportBundle.Filter("resourceId", resourceId),
        auditEvents.findByResourceIdOrderBySeqAsc(resourceId));
  }

  @Transactional(readOnly = true)
  public ExportBundle exportByActorId(String actorId) {
    return build(
        new ExportBundle.Filter("actorId", actorId), auditEvents.findByActorIdOrderBySeqAsc(actorId));
  }

  @Transactional(readOnly = true)
  public ExportBundle exportForSeqs(ExportBundle.Filter filter, List<Long> seqs) {
    return build(filter, auditEvents.findBySeqInOrderBySeqAsc(seqs));
  }

  private ExportBundle build(ExportBundle.Filter filter, List<AuditEvent> matchedEvents) {
    List<Long> matchedSeqs = matchedEvents.stream().map(AuditEvent::getSeq).toList();
    Map<Long, List<String>> redactedBySeq =
        redactions.findByEventSeqInOrderByEventSeqAscFieldPathAsc(matchedSeqs).stream()
            .collect(
                Collectors.groupingBy(
                    Redaction::getEventSeq,
                    Collectors.mapping(Redaction::getFieldPath, Collectors.toList())));

    List<ExportBundle.Record> records =
        matchedEvents.stream()
            .map(event -> toRecord(event, redactedBySeq.getOrDefault(event.getSeq(), List.of())))
            .toList();

    ExportBundle unsignedBundle =
        new ExportBundle(
            "1",
            Instants.canonical(clock.instant()),
            filter,
            properties.genesisHash(),
            records,
            segments(matchedEvents),
            null,
            null);

    String bundleHash = bundleHash(unsignedBundle);
    String secret = properties.export().hmacSecret();
    String hmac =
        secret == null || secret.isEmpty()
            ? null
            : Hashing.hmacSha256Hex(secret, bundleHash.getBytes(StandardCharsets.UTF_8));
    return unsignedBundle.withIntegrity(bundleHash, hmac);
  }

  private ExportBundle.Record toRecord(AuditEvent event, List<String> redactedPaths) {
    JsonNode payload = event.getPayloadJson() == null ? null : jsonCodec.parse(event.getPayloadJson());
    return new ExportBundle.Record(
        event.getSeq(),
        event.getEventId().toString(),
        event.getEventType(),
        event.getActorId(),
        event.getResourceType(),
        event.getResourceId(),
        payload,
        jsonCodec.readStringMap(event.getLeafSaltsJson()),
        jsonCodec.readStringMap(event.getLeafCommitmentsJson()),
        redactedPaths,
        Instants.canonical(event.getEventTimestamp()),
        Instants.canonical(event.getRecordedAt()),
        event.getContentHash(),
        event.getPrevHash(),
        event.getRecordHash(),
        event.isArchived());
  }

  private List<ExportBundle.Segment> segments(List<AuditEvent> matchedEvents) {
    List<ExportBundle.Segment> segments = new ArrayList<>();
    long runStartSeq = -1;
    long previousSeq = -1;
    for (AuditEvent event : matchedEvents) {
      long seq = event.getSeq();
      if (runStartSeq < 0) {
        runStartSeq = seq;
      } else if (seq != previousSeq + 1) {
        segments.add(new ExportBundle.Segment(runStartSeq, previousSeq, priorRecordHash(runStartSeq)));
        runStartSeq = seq;
      }
      previousSeq = seq;
    }
    if (runStartSeq >= 0) {
      segments.add(new ExportBundle.Segment(runStartSeq, previousSeq, priorRecordHash(runStartSeq)));
    }
    return segments;
  }

  private String priorRecordHash(long runStartSeq) {
    if (runStartSeq <= 1) {
      return properties.genesisHash();
    }
    return auditEvents
        .findById(runStartSeq - 1)
        .map(AuditEvent::getRecordHash)
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "predecessor of seq " + runStartSeq + " missing; cannot build segment proof"));
  }

  private String bundleHash(ExportBundle unsignedBundle) {
    ObjectNode bundleTree = (ObjectNode) jsonCodec.toTree(unsignedBundle);
    bundleTree.remove("bundleHash");
    bundleTree.remove("hmac");
    return Hashing.sha256Hex(CanonicalJson.canonicalize(bundleTree));
  }
}
