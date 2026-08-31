package com.sj.audit.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.domain.AuditEvent;
import com.sj.audit.enums.ViolationType;
import com.sj.audit.repository.AuditEventRepository;
import com.sj.audit.support.AbstractIntegrationTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class RedactionServiceIT extends AbstractIntegrationTest {

  @Autowired
  RedactionService redactionService;
  @Autowired ChainVerifier verifier;
  @Autowired AuditEventRepository events;

  private UUID seedWithSensitivePayload() {
    AuditEvent e =
        appender.append(
            event(
                "ACCOUNT_VIEWED",
                "clerk-9",
                "acct-1",
                "{\"accountNumber\":\"4444333322221111\",\"note\":\"routine check\"}"));
    return e.getEventId();
  }

  @Test
  void redactedChainStillVerifiesAndHidesTheValue() {
    UUID eventId = seedWithSensitivePayload();

    RedactionService.RedactionResult result =
        redactionService.redact(
            new RedactionService.RedactRequest(
                eventId, List.of("/accountNumber"), "PCI", "officer-1", null));

    assertThat(result.redactedFields()).hasSize(1);
    assertThat(verifier.verify(null, null, false).intact()).isTrue();

    AuditEvent reloaded = events.findByEventId(eventId).orElseThrow();
    assertThat(reloaded.getPayloadJson()).contains("__REDACTED__:").doesNotContain("4444333322221111");
    assertThat(reloaded.getPayloadJson()).contains("routine check");
  }

  @Test
  void writesAMetaAuditEvent() {
    UUID eventId = seedWithSensitivePayload();
    redactionService.redact(
        new RedactionService.RedactRequest(
            eventId, List.of("/accountNumber"), "PCI", "officer-1", null));

    List<AuditEvent> all = events.findAll();
    assertThat(all).anySatisfy(e -> assertThat(e.getEventType()).isEqualTo("AUDIT_RECORD_REDACTED"));
  }

  @Test
  void tamperingANonRedactedLeafIsStillDetected() {
    UUID eventId = seedWithSensitivePayload();
    redactionService.redact(
        new RedactionService.RedactRequest(
            eventId, List.of("/accountNumber"), "PCI", "officer-1", null));

    long seq = events.findByEventId(eventId).orElseThrow().getSeq();
    jdbc.update(
        "UPDATE audit_event SET payload_json = "
            + "'{\"accountNumber\":\"__REDACTED__:x\",\"note\":\"tampered\"}' WHERE seq = ?",
        seq);

    var report = verifier.verify(null, null, false);
    assertThat(report.intact()).isFalse();
    assertThat(report.firstInconsistency().violationType())
        .isEqualTo(ViolationType.LEAF_COMMITMENT_MISMATCH);
  }

  @Test
  void rejectsUnknownFieldPath() {
    UUID eventId = seedWithSensitivePayload();
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () ->
            redactionService.redact(
                new RedactionService.RedactRequest(
                    eventId, List.of("/doesNotExist"), "x", "y", null)));
  }
}
