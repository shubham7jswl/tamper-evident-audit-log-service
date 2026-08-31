package com.sj.audit.chain;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.domain.chain.VerificationReport;
import com.sj.audit.enums.ViolationType;
import com.sj.audit.service.ChainVerifier;
import com.sj.audit.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ChainVerifierIT extends AbstractIntegrationTest {

  @Autowired
  ChainVerifier verifier;

  private void seedThreeEvents() {
    appender.append(event("USER_LOGIN", "alice", "acct-1", "{\"ip\":\"10.0.0.1\"}"));
    appender.append(event("ACCOUNT_VIEWED", "alice", "acct-1", "{\"ssn\":\"111-22-3333\"}"));
    appender.append(event("RECORD_UPDATED", "bob", "acct-2", "{\"field\":\"email\",\"to\":\"x@y.z\"}"));
  }

  @Test
  void intactChainVerifies() {
    seedThreeEvents();
    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).isTrue();
    assertThat(report.recordsChecked()).isEqualTo(3);
  }

  @Test
  void emptyChainVerifies() {
    assertThat(verifier.verify(null, null, false).intact()).isTrue();
  }

  @Test
  void detectsCoreFieldTamperAtRightSeq() {
    seedThreeEvents();
    jdbc.update("UPDATE audit_event SET actor_id = 'mallory' WHERE seq = 2");

    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).isFalse();
    assertThat(report.firstInconsistency().seq()).isEqualTo(2);
    assertThat(report.firstInconsistency().violationType())
        .isEqualTo(ViolationType.CONTENT_HASH_MISMATCH);
  }

  @Test
  void detectsPayloadLeafTamper() {
    seedThreeEvents();
    jdbc.update(
        "UPDATE audit_event SET payload_json = '{\"ssn\":\"999-99-9999\"}' WHERE seq = 2");

    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).isFalse();
    assertThat(report.firstInconsistency().seq()).isEqualTo(2);
    assertThat(report.firstInconsistency().violationType())
        .isEqualTo(ViolationType.LEAF_COMMITMENT_MISMATCH);
  }

  @Test
  void detectsDeletedRecordAsSequenceGap() {
    seedThreeEvents();
    jdbc.update("DELETE FROM audit_event WHERE seq = 2");

    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).isFalse();
    assertThat(report.firstInconsistency().violationType()).isEqualTo(ViolationType.SEQUENCE_GAP);
  }

  @Test
  void detectsRecordHashTamper() {
    seedThreeEvents();
    jdbc.update("UPDATE audit_event SET record_hash = repeat('0', 64) WHERE seq = 2");

    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).isFalse();
    assertThat(report.firstInconsistency().seq()).isEqualTo(2);
    // the broken record_hash is first seen as a link break at seq 3, or a record-hash mismatch at 2
    assertThat(report.firstInconsistency().violationType())
        .isIn(ViolationType.RECORD_HASH_MISMATCH, ViolationType.PREV_HASH_MISMATCH);
  }
}
