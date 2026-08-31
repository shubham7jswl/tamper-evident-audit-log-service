package com.sj.audit.config.security;

import com.sj.audit.config.AuditProperties;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Fails application startup when the configured {@code X-Api-Key} values look like the built-in
 * development placeholders (or are missing / too short) and no relaxed profile is active.
 *
 * <p>The point is to make an unsafe deployment loud instead of silent: a service that ships to a
 * real environment without {@code AUDIT_READER_KEY} / {@code AUDIT_WRITER_KEY} /
 * {@code AUDIT_ADMIN_KEY} set would otherwise come up with well-known credentials. Under the
 * {@code dev} or {@code test} profile the check is skipped so local runs and the test suite can
 * use fixed keys.
 */
@Component
public class ApiKeyConfigValidator {

  /** Profiles under which well-known / weak keys are tolerated. */
  static final Set<String> RELAXED_PROFILES = Set.of("dev", "test");

  /** Keys that appear in the repo, docs, or common tutorials — never valid in a real environment. */
  static final Set<String> KNOWN_PLACEHOLDERS =
      Set.of(
          "dev-reader-key",
          "dev-writer-key",
          "dev-admin-key",
          "test-reader-key",
          "test-writer-key",
          "test-admin-key",
          "changeme",
          "change-me",
          "changeit",
          "password",
          "secret");

  static final int MIN_KEY_LENGTH = 16;

  public ApiKeyConfigValidator(AuditProperties properties, Environment environment) {
    validate(properties.apiKeys(), environment.getActiveProfiles());
  }

  /**
   * @throws IllegalStateException if, with no relaxed profile active, any key is missing, a
   *     well-known placeholder, or shorter than {@link #MIN_KEY_LENGTH}.
   */
  static void validate(List<AuditProperties.ApiKey> keys, String[] activeProfiles) {
    for (String profile : activeProfiles) {
      if (RELAXED_PROFILES.contains(profile)) {
        return;
      }
    }
    if (keys == null || keys.isEmpty()) {
      throw new IllegalStateException(
          "No audit.api-keys configured. Set AUDIT_READER_KEY / AUDIT_WRITER_KEY / "
              + "AUDIT_ADMIN_KEY, or run with the 'dev' profile for local development.");
    }
    for (AuditProperties.ApiKey key : keys) {
      String value = key.key() == null ? "" : key.key().strip();
      String who = "audit.api-keys entry for principal '" + key.principal() + "'";
      if (value.isEmpty()) {
        throw new IllegalStateException(
            who + " has no value — provide it via its AUDIT_*_KEY environment variable.");
      }
      if (KNOWN_PLACEHOLDERS.contains(value.toLowerCase(Locale.ROOT))) {
        throw new IllegalStateException(
            who
                + " is set to the well-known placeholder \""
                + value
                + "\". Use a real secret, or run with the 'dev' profile.");
      }
      if (value.length() < MIN_KEY_LENGTH) {
        throw new IllegalStateException(
            who
                + " is only "
                + value.length()
                + " characters; require at least "
                + MIN_KEY_LENGTH
                + " for adequate entropy.");
      }
    }
  }
}
