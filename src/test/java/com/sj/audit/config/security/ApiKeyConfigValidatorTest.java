package com.sj.audit.config.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sj.audit.config.AuditProperties;
import com.sj.audit.enums.Scope;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ApiKeyConfigValidatorTest {

  private static final String[] NO_PROFILE = new String[0];
  private static final String[] PROD = {"prod"};
  private static final String[] DEV = {"dev"};

  private static AuditProperties.ApiKey key(String value, Scope... scopes) {
    return new AuditProperties.ApiKey(value, "principal-for-" + value, Set.of(scopes));
  }

  @Test
  void acceptsStrongDistinctKeysOutsideRelaxedProfiles() {
    List<AuditProperties.ApiKey> keys =
        List.of(
            key("R3ader-9f2c1a8b7e6d5c4b", Scope.READ),
            key("Wr1ter-1122334455667788", Scope.WRITE, Scope.READ),
            key("Adm1n-aabbccddeeff00112233", Scope.WRITE, Scope.READ, Scope.ADMIN));

    assertThatCode(() -> ApiKeyConfigValidator.validate(keys, PROD)).doesNotThrowAnyException();
  }

  @Test
  void rejectsWellKnownDevPlaceholderOutsideRelaxedProfiles() {
    List<AuditProperties.ApiKey> keys = List.of(key("dev-admin-key", Scope.ADMIN));

    assertThatThrownBy(() -> ApiKeyConfigValidator.validate(keys, PROD))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("placeholder")
        .hasMessageContaining("dev-admin-key");
  }

  @Test
  void rejectsMissingKeyValueOutsideRelaxedProfiles() {
    List<AuditProperties.ApiKey> keys = List.of(key("  ", Scope.READ));

    assertThatThrownBy(() -> ApiKeyConfigValidator.validate(keys, NO_PROFILE))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("no value");
  }

  @Test
  void rejectsShortKeyOutsideRelaxedProfiles() {
    List<AuditProperties.ApiKey> keys = List.of(key("short-key", Scope.READ));

    assertThatThrownBy(() -> ApiKeyConfigValidator.validate(keys, PROD))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("at least " + ApiKeyConfigValidator.MIN_KEY_LENGTH);
  }

  @Test
  void rejectsEmptyKeyListOutsideRelaxedProfiles() {
    assertThatThrownBy(() -> ApiKeyConfigValidator.validate(List.of(), PROD))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("No audit.api-keys configured");
  }

  @Test
  void skipsAllChecksUnderDevProfile() {
    List<AuditProperties.ApiKey> weak = List.of(key("dev-admin-key", Scope.ADMIN));

    assertThatCode(() -> ApiKeyConfigValidator.validate(weak, DEV)).doesNotThrowAnyException();
    assertThatCode(() -> ApiKeyConfigValidator.validate(null, DEV)).doesNotThrowAnyException();
  }

  @Test
  void skipsAllChecksUnderTestProfile() {
    List<AuditProperties.ApiKey> weak = List.of(key("test-writer-key", Scope.WRITE));

    assertThatCode(() -> ApiKeyConfigValidator.validate(weak, new String[] {"test"}))
        .doesNotThrowAnyException();
  }
}
