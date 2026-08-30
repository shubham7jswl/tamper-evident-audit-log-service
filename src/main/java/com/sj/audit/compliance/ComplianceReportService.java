package com.sj.audit.compliance;

import com.sj.audit.chain.ChainAppender;
import com.sj.audit.chain.ChainVerifier;
import com.sj.audit.chain.VerificationReport;
import com.sj.audit.config.AuditProperties;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.export.BundleExporter;
import com.sj.audit.export.ExportBundle;
import com.sj.audit.hash.Hashing;
import com.sj.audit.hash.Instants;
import com.sj.audit.query.AuditQueryFilter;
import com.sj.audit.query.AuditQueryService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.node.ObjectNode;

/**
 * Scenario C — Compliance Access Report.
 *
 * <p>Clarified requirement (see {@code docs/scenarios/scenario-c.md}): given a client-account
 * resource and a time window, return a tamper-evident report of every recorded <em>access</em>
 * event (a configurable set of event types) against that account — actor, time, type, and a
 * redaction-aware payload view — together with a chain-verification result and a completeness
 * statement. Generating the report is itself written to the audit chain.
 */
@Service
public class ComplianceReportService {

  public static final String REPORT_EVENT_TYPE = "COMPLIANCE_REPORT_GENERATED";

  private final AuditQueryService queryService;
  private final BundleExporter bundleExporter;
  private final ChainVerifier chainVerifier;
  private final ChainAppender appender;
  private final AuditProperties properties;
  private final JsonSupport json;

  public ComplianceReportService(
      AuditQueryService queryService,
      BundleExporter bundleExporter,
      ChainVerifier chainVerifier,
      ChainAppender appender,
      AuditProperties properties,
      JsonSupport json) {
    this.queryService = queryService;
    this.bundleExporter = bundleExporter;
    this.chainVerifier = chainVerifier;
    this.appender = appender;
    this.properties = properties;
    this.json = json;
  }

  public record AccessReportRequest(
      String resourceType, String resourceId, Instant from, Instant to, String requestedBy) {}

  public record AccessEntry(
      long seq,
      String eventId,
      String eventType,
      String actorId,
      String eventTimestamp,
      String recordedAt,
      List<String> redactedPaths) {}

  public record Completeness(
      long chainRangeFromSeq, long chainRangeToSeq, int matchedCount, boolean chainIntact) {}

  public record AccessReport(
      String reportVersion,
      String generatedAt,
      AccessReportRequest request,
      List<String> accessEventTypes,
      List<AccessEntry> entries,
      Completeness completeness,
      VerificationReport chainVerification,
      ExportBundle bundle,
      String reportHash,
      UUID metaEventId,
      String disclaimer) {}

  @Transactional
  public AccessReport accessReport(AccessReportRequest request) {
    if (!properties.compliance().clientDataResourceTypes().contains(request.resourceType())) {
      throw new IllegalArgumentException(
          "resourceType '"
              + request.resourceType()
              + "' is not classified as client account data; allowed: "
              + properties.compliance().clientDataResourceTypes());
    }
    List<String> accessTypes = List.copyOf(properties.compliance().accessEventTypes());

    List<AuditEvent> matched =
        queryService
            .query(
                new AuditQueryFilter(
                    null,
                    request.resourceType(),
                    request.resourceId(),
                    null,
                    request.from(),
                    request.to()),
                PageRequest.of(0, 10_000, Sort.by("seq").ascending()))
            .getContent()
            .stream()
            .filter(e -> accessTypes.contains(e.getEventType()))
            .toList();

    List<Long> seqs = matched.stream().map(AuditEvent::getSeq).toList();
    ExportBundle bundle =
        bundleExporter.exportForSeqs(
            new ExportBundle.Filter("complianceAccessReport", request.resourceId()), seqs);

    List<AccessEntry> entries =
        bundle.records().stream()
            .map(
                r ->
                    new AccessEntry(
                        r.seq(),
                        r.eventId(),
                        r.eventType(),
                        r.actorId(),
                        r.eventTimestamp(),
                        r.recordedAt(),
                        r.redactedPaths()))
            .toList();

    VerificationReport verification = chainVerifier.verify(null, null, false);

    long fromSeq = seqs.isEmpty() ? 0 : seqs.get(0);
    long toSeq = seqs.isEmpty() ? 0 : seqs.get(seqs.size() - 1);
    Completeness completeness =
        new Completeness(fromSeq, toSeq, matched.size(), verification.intact());

    String reportHash =
        Hashing.sha256Hex(
            String.join(
                "",
                request.resourceType(),
                request.resourceId(),
                String.valueOf(request.from()),
                String.valueOf(request.to()),
                bundle.bundleHash(),
                Integer.toString(matched.size())));

    ObjectNode metaPayload = json.newObject();
    metaPayload.put("resourceType", request.resourceType());
    metaPayload.put("resourceId", request.resourceId());
    metaPayload.put("from", String.valueOf(request.from()));
    metaPayload.put("to", String.valueOf(request.to()));
    metaPayload.put("requestedBy", request.requestedBy());
    metaPayload.put("matchedCount", matched.size());
    metaPayload.put("reportHash", reportHash);
    metaPayload.put("bundleHash", bundle.bundleHash());

    AuditEvent meta =
        appender.append(
            new ChainAppender.NewEvent(
                REPORT_EVENT_TYPE,
                request.requestedBy(),
                request.resourceType(),
                request.resourceId(),
                metaPayload,
                null));

    return new AccessReport(
        "1",
        Instants.canonical(Instant.now()),
        request,
        accessTypes,
        entries,
        completeness,
        verification,
        bundle,
        reportHash,
        meta.getEventId(),
        "Covers only event types configured as 'access' events and only records present in the "
            + "audit chain when generated. Verify the embedded bundle independently with "
            + "BundleVerifier. Absence of an event here is not proof it did not occur upstream.");
  }
}
