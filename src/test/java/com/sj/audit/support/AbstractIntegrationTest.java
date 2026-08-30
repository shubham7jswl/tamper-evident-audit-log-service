package com.sj.audit.support;

import com.sj.audit.chain.ChainAppender;
import com.sj.audit.config.AuditProperties;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Shared base for integration tests: full context on in-memory H2, DB reset before each test. */
@SpringBootTest
public abstract class AbstractIntegrationTest {

  protected static final JsonMapper JSON = JsonMapper.builder().build();

  @Autowired protected ChainAppender appender;
  @Autowired protected JdbcTemplate jdbc;
  @Autowired protected AuditProperties properties;

  @BeforeEach
  void resetDatabase() {
    jdbc.execute("DELETE FROM redaction");
    jdbc.execute("DELETE FROM archived_audit_event");
    jdbc.execute("DELETE FROM audit_event");
    jdbc.update(
        "UPDATE chain_head SET last_seq = 0, last_record_hash = ?, updated_at = CURRENT_TIMESTAMP",
        properties.genesisHash());
  }

  protected ChainAppender.NewEvent event(String type, String actor, String resourceId, String payloadJson) {
    return new ChainAppender.NewEvent(
        type, actor, "CLIENT_ACCOUNT", resourceId, JSON.readTree(payloadJson), Instant.parse("2026-01-01T00:00:00Z"));
  }
}
