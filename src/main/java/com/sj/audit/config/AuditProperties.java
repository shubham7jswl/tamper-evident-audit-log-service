package com.sj.audit.config;

import com.sj.audit.enums.Scope;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Strongly-typed configuration for the audit log service, bound from the {@code audit.*} tree.
 *
 * <p>Records give us immutable, constructor-bound config with no accidental runtime mutation.
 */
@ConfigurationProperties(prefix = "audit")
public record AuditProperties(
    /** Hex SHA-256 used as {@code prev_hash} of the very first record. */
    String genesisHash,
    List<ApiKey> apiKeys,
    Retention retention,
    Redaction redaction,
    Export export,
    Compliance compliance) {

  public record ApiKey(String key, String principal, Set<Scope> scopes) {}

  public record Retention(
      @DefaultValue("true") boolean enabled,
      @DefaultValue("P365D") Duration window,
      @DefaultValue("false") boolean scheduled,
      @DefaultValue("0 0 3 * * *") String scheduledCron) {}

  public record Redaction(@DefaultValue("true") boolean retainSaltByDefault) {}

  /** Optional HMAC signing of export bundles. Empty secret => bundles are left unsigned. */
  public record Export(@DefaultValue("") String hmacSecret) {}

  public record Compliance(
      Set<String> accessEventTypes, Set<String> clientDataResourceTypes) {}
}
