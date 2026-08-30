package com.sj.audit.retention;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.chain.ChainVerifier;
import com.sj.audit.chain.VerificationReport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.redaction.RedactionService;
import com.sj.audit.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

@TestPropertySource(properties = "audit.retention.window=PT0S")
class RetentionServiceIT extends AbstractIntegrationTest {

  @Autowired RetentionService retentionService;
  @Autowired ChainVerifier verifier;
  @Autowired AuditEventRepository events;
  @Autowired RedactionService redactionService;

  @Test
  void archivedRecordsDoNotBreakVerification() {
    appender.append(event("A", "u", "acct-1", "{\"k\":1}"));
    appender.append(event("B", "u", "acct-1", "{\"k\":2}"));
    appender.append(event("C", "u", "acct-2", "{\"k\":3}"));

    RetentionService.RetentionResult result = retentionService.run();
    assertThat(result.archivedCount()).isEqualTo(3);

    assertThat(events.findAll()).allSatisfy(e -> assertThat(e.isArchived()).isTrue());
    assertThat(events.findAll()).allSatisfy(e -> assertThat(e.getPayloadJson()).isNull());

    VerificationReport shallow = verifier.verify(null, null, false);
    assertThat(shallow.intact()).isTrue();
    assertThat(shallow.archivedSegments()).containsExactly(new VerificationReport.ArchivedSegment(1, 3));

    assertThat(verifier.verify(null, null, true).intact()).isTrue();
  }

  @Test
  void deepVerificationDetectsTamperInsideAnArchivedRow() {
    appender.append(event("A", "u", "acct-1", "{\"k\":1}"));
    retentionService.run();

    jdbc.update("UPDATE archived_audit_event SET payload_json = '{\"k\":999}' WHERE seq = 1");

    assertThat(verifier.verify(null, null, false).intact()).isTrue(); // shallow can't see it
    assertThat(verifier.verify(null, null, true).intact()).isFalse(); // deep re-hashes and catches it
  }

  @Test
  void aRecordRedactedThenArchivedStillVerifiesEvenOnDeep() {
    AuditEvent e =
        appender.append(event("ACCOUNT_VIEWED", "u", "acct-1", "{\"ssn\":\"111-22-3333\",\"ok\":1}"));
    redactionService.redact(
        new RedactionService.RedactRequest(
            e.getEventId(), List.of("/ssn"), "privacy", "officer", null));
    retentionService.run();

    assertThat(verifier.verify(null, null, false).intact()).isTrue();
    assertThat(verifier.verify(null, null, true).intact()).isTrue();
  }
}
