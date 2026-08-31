/**
 * Compliance access report (Scenario C — the ambiguous requirement "regulators need to audit
 * access to client account data").
 *
 * <p>{@link ComplianceReportService} answers, for one client account and a
 * time window: which <i>access</i> events (a configurable set of event types) touched it, is the
 * chain intact, and is the coverage complete. It returns those entries plus an embedded verifiable
 * {@link ExportBundle}, and appends a {@code COMPLIANCE_REPORT_GENERATED} event
 * so running the report is itself audited.
 *
 * <p>What was clarified, assumed, and scoped out is written up in
 * {@code docs/scenarios/scenario-c.md}.
 */
package com.sj.audit.compliance;

import com.sj.audit.domain.export.ExportBundle;
import com.sj.audit.service.ComplianceReportService;