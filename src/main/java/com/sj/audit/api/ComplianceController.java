package com.sj.audit.api;

import com.sj.audit.compliance.ComplianceReportService;
import com.sj.audit.security.ApiPrincipal;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Scenario C — regulator-facing compliance access report. */
@RestController
@Tag(name = "Compliance", description = "Scenario C — tamper-evident access report for a client account")
public class ComplianceController {

  private final ComplianceReportService reportService;

  public ComplianceController(ComplianceReportService reportService) {
    this.reportService = reportService;
  }

  @GetMapping("/audit/compliance/access-report")
  @RequireScope(Scope.READ)
  @Operation(
      summary = "Compliance access report for a client account (scope: READ)",
      description =
          "resourceType must be a configured client-data type. Returns matched access events, a "
              + "completeness statement, a full chain-verification result and an embedded "
              + "verifiable bundle. Generating the report is itself audited.")
  public ComplianceReportService.AccessReport accessReport(
      ApiPrincipal principal,
      @RequestParam String resourceType,
      @RequestParam String resourceId,
      @RequestParam String from,
      @RequestParam String to) {
    Instant fromInstant = parse(from, "from");
    Instant toInstant = parse(to, "to");
    return reportService.accessReport(
        new ComplianceReportService.AccessReportRequest(
            resourceType, resourceId, fromInstant, toInstant, principal.name()));
  }

  private static Instant parse(String value, String field) {
    try {
      return Instant.parse(value);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(field + " must be an ISO-8601 instant");
    }
  }
}
