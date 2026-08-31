package com.sj.audit.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.domain.export.ExportBundle;
import com.sj.audit.support.AbstractIntegrationTest;
import com.sj.audit.utils.BundleVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.ObjectNode;

class BundleExportIT extends AbstractIntegrationTest {

  @Autowired
  BundleExporter exporter;

  private void seed() {
    appender.append(event("A", "u1", "acct-1", "{\"k\":1}"));
    appender.append(event("B", "u2", "acct-2", "{\"k\":2}")); // gap in the acct-1 selection
    appender.append(event("C", "u1", "acct-1", "{\"k\":3}"));
  }

  @Test
  void exportedBundleVerifiesIndependently() {
    seed();
    ExportBundle bundle = exporter.exportByResourceId("acct-1");

    assertThat(bundle.records()).hasSize(2);
    assertThat(bundle.segments()).hasSize(2); // seq 1 and seq 3 are non-contiguous

    BundleVerifier.Result result = BundleVerifier.verify(bundle, properties.export().hmacSecret());
    assertThat(result.valid()).as("%s", result.problems()).isTrue();
  }

  @Test
  void tamperingABundleRecordFailsVerification() {
    seed();
    ExportBundle bundle = exporter.exportByResourceId("acct-1");

    ExportBundle.Record original = bundle.records().get(0);
    ((ObjectNode) original.payload()).put("k", 999);

    BundleVerifier.Result result = BundleVerifier.verify(bundle, properties.export().hmacSecret());
    assertThat(result.valid()).isFalse();
  }

  @Test
  void tamperingTheBundleHashFailsVerification() {
    seed();
    ExportBundle bundle = exporter.exportByActorId("u1");
    ExportBundle forged = bundle.withIntegrity("0".repeat(64), bundle.hmac());

    assertThat(BundleVerifier.verify(forged, properties.export().hmacSecret()).valid()).isFalse();
  }
}
