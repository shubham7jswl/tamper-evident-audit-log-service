package com.sj.audit.config.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.config.AuditProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/** Proves the validator actually fails (or allows) application startup, not just the static method. */
class ApiKeyConfigValidatorContextTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              org.springframework.boot.autoconfigure.AutoConfigurations.of(
                  ConfigurationPropertiesAutoConfiguration.class))
          .withUserConfiguration(TestConfig.class);

  @Test
  void startupFailsOnPlaceholderKeyWithNoRelaxedProfile() {
    runner
        .withPropertyValues(
            "audit.api-keys[0].key=dev-admin-key",
            "audit.api-keys[0].principal=admin",
            "audit.api-keys[0].scopes=ADMIN,WRITE,READ")
        .run(
            context ->
                assertThat(context)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("placeholder"));
  }

  @Test
  void startupSucceedsOnStrongKeys() {
    runner
        .withPropertyValues(
            "audit.api-keys[0].key=reader-3f2c1a8b7e6d5c4b",
            "audit.api-keys[0].principal=reader",
            "audit.api-keys[0].scopes=READ")
        .run(context -> assertThat(context).hasNotFailed().hasSingleBean(ApiKeyConfigValidator.class));
  }

  @Test
  void startupSucceedsWithPlaceholderKeyUnderDevProfile() {
    runner
        .withPropertyValues(
            "audit.api-keys[0].key=dev-admin-key",
            "audit.api-keys[0].principal=admin",
            "audit.api-keys[0].scopes=ADMIN,WRITE,READ")
        .withInitializer(
            ctx -> ctx.getEnvironment().setActiveProfiles("dev"))
        .run(context -> assertThat(context).hasNotFailed());
  }

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties(AuditProperties.class)
  @Import(ApiKeyConfigValidator.class)
  static class TestConfig {}
}
