package com.sj.audit.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.export.BundleVerifier;
import com.sj.audit.support.AbstractIntegrationTest;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ComplianceReportIT extends AbstractIntegrationTest {

  @Autowired ComplianceReportService reportService;
  @Autowired AuditEventRepository events;

  @Test
  void reportsAccessEventsForAnAccountAndIsItselfAudited() {
    appender.append(event("ACCOUNT_VIEWED", "clerk-1", "acct-1", "{\"channel\":\"web\"}"));
    appender.append(event("ACCOUNT_STATEMENT_DOWNLOADED", "clerk-2", "acct-1", "{\"month\":\"2026-01\"}"));
    appender.append(event("USER_LOGIN", "clerk-1", "acct-1", "{\"ip\":\"1.2.3.4\"}")); // not an access event
    appender.append(event("ACCOUNT_VIEWED", "clerk-3", "acct-2", "{\"channel\":\"api\"}")); // other account

    ComplianceReportService.AccessReport report =
        reportService.accessReport(
            new ComplianceReportService.AccessReportRequest(
                "CLIENT_ACCOUNT",
                "acct-1",
                Instant.parse("2025-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"),
                "regulator-x"));

    assertThat(report.entries()).hasSize(2);
    assertThat(report.entries())
        .extracting(ComplianceReportService.AccessEntry::eventType)
        .containsExactly("ACCOUNT_VIEWED", "ACCOUNT_STATEMENT_DOWNLOADED");
    assertThat(report.completeness().matchedCount()).isEqualTo(2);
    assertThat(report.chainVerification().intact()).isTrue();

    assertThat(BundleVerifier.verify(report.bundle(), properties.export().hmacSecret()).valid())
        .isTrue();

    assertThat(events.findAll())
        .anySatisfy(
            e -> assertThat(e.getEventType()).isEqualTo("COMPLIANCE_REPORT_GENERATED"));
  }

  @Test
  void rejectsResourceTypeThatIsNotClientAccountData() {
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () ->
            reportService.accessReport(
                new ComplianceReportService.AccessReportRequest(
                    "SERVER_CONFIG", "x", Instant.EPOCH, Instant.now(), "y")));
  }
}
