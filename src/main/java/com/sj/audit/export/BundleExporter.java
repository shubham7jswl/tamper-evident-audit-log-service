package com.sj.audit.export;

import com.sj.audit.config.AuditProperties;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.domain.Redaction;
import com.sj.audit.domain.RedactionRepository;
import com.sj.audit.hash.CanonicalJson;
import com.sj.audit.hash.Hashing;
import com.sj.audit.hash.Instants;
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

  private final AuditEventRepository events;
  private final RedactionRepository redactions;
  private final JsonSupport json;
  private final AuditProperties properties;
  private final Clock clock;

  public BundleExporter(
      AuditEventRepository events,
      RedactionRepository redactions,
      JsonSupport json,
      AuditProperties properties,
      Clock clock) {
    this.events = events;
    this.redactions = redactions;
    this.json = json;
    this.properties = properties;
    this.clock = clock;
  }

  @Transactional(readOnly = true)
  public ExportBundle exportByResourceId(String resourceId) {
    return build(
        new ExportBundle.Filter("resourceId", resourceId),
        events.findByResourceIdOrderBySeqAsc(resourceId));
  }

  @Transactional(readOnly = true)
  public ExportBundle exportByActorId(String actorId) {
    return build(
        new ExportBundle.Filter("actorId", actorId), events.findByActorIdOrderBySeqAsc(actorId));
  }

  @Transactional(readOnly = true)
  public ExportBundle exportForSeqs(ExportBundle.Filter filter, List<Long> seqs) {
    return build(filter, events.findBySeqInOrderBySeqAsc(seqs));
  }

  private ExportBundle build(ExportBundle.Filter filter, List<AuditEvent> rows) {
    List<Long> seqs = rows.stream().map(AuditEvent::getSeq).toList();
    Map<Long, List<String>> redactedBySeq =
        redactions.findByEventSeqInOrderByEventSeqAscFieldPathAsc(seqs).stream()
            .collect(
                Collectors.groupingBy(
                    Redaction::getEventSeq,
                    Collectors.mapping(Redaction::getFieldPath, Collectors.toList())));

    List<ExportBundle.Record> records =
        rows.stream()
            .map(e -> toRecord(e, redactedBySeq.getOrDefault(e.getSeq(), List.of())))
            .toList();

    ExportBundle unsigned =
        new ExportBundle(
            "1",
            Instants.canonical(clock.instant()),
            filter,
            properties.genesisHash(),
            records,
            segments(rows),
            null,
            null);

    String bundleHash = bundleHash(unsigned);
    String secret = properties.export().hmacSecret();
    String hmac =
        secret == null || secret.isEmpty()
            ? null
            : Hashing.hmacSha256Hex(secret, bundleHash.getBytes(StandardCharsets.UTF_8));
    return unsigned.withIntegrity(bundleHash, hmac);
  }

  private ExportBundle.Record toRecord(AuditEvent e, List<String> redactedPaths) {
    JsonNode payload = e.getPayloadJson() == null ? null : json.parse(e.getPayloadJson());
    return new ExportBundle.Record(
        e.getSeq(),
        e.getEventId().toString(),
        e.getEventType(),
        e.getActorId(),
        e.getResourceType(),
        e.getResourceId(),
        payload,
        json.readStringMap(e.getLeafSaltsJson()),
        json.readStringMap(e.getLeafCommitmentsJson()),
        redactedPaths,
        Instants.canonical(e.getEventTimestamp()),
        Instants.canonical(e.getRecordedAt()),
        e.getContentHash(),
        e.getPrevHash(),
        e.getRecordHash(),
        e.isArchived());
  }

  private List<ExportBundle.Segment> segments(List<AuditEvent> rows) {
    List<ExportBundle.Segment> segments = new ArrayList<>();
    long runStart = -1;
    long prevSeq = -1;
    for (AuditEvent e : rows) {
      long seq = e.getSeq();
      if (runStart < 0) {
        runStart = seq;
      } else if (seq != prevSeq + 1) {
        segments.add(new ExportBundle.Segment(runStart, prevSeq, priorRecordHash(runStart)));
        runStart = seq;
      }
      prevSeq = seq;
    }
    if (runStart >= 0) {
      segments.add(new ExportBundle.Segment(runStart, prevSeq, priorRecordHash(runStart)));
    }
    return segments;
  }

  private String priorRecordHash(long runStartSeq) {
    if (runStartSeq <= 1) {
      return properties.genesisHash();
    }
    return events
        .findById(runStartSeq - 1)
        .map(AuditEvent::getRecordHash)
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "predecessor of seq " + runStartSeq + " missing; cannot build segment proof"));
  }

  private String bundleHash(ExportBundle unsigned) {
    ObjectNode tree = (ObjectNode) json.toTree(unsigned);
    tree.remove("bundleHash");
    tree.remove("hmac");
    return Hashing.sha256Hex(CanonicalJson.canonicalize(tree));
  }
}
