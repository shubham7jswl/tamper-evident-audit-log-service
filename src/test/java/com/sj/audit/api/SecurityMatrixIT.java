package com.sj.audit.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sj.audit.config.security.ApiKeyAuthFilter;
import com.sj.audit.support.AbstractIntegrationTest;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * The endpoint × credential authorization matrix: what each scope may and may not do, and how
 * bad credentials are rejected. Complements {@link AuditApiIT}, which covers the happy paths.
 *
 * <p>Test keys (from {@code src/test/resources/application.yml}): {@code test-reader-key} = READ,
 * {@code test-writeonly-key} = WRITE, {@code test-writer-key} = WRITE+READ,
 * {@code test-admin-key} = WRITE+READ+ADMIN.
 */
class SecurityMatrixIT extends AbstractIntegrationTest {

  @Autowired WebApplicationContext context;
  MockMvc mvc;

  private static final String EVENT_BODY =
      """
      {"eventType":"USER_LOGIN","actorId":"alice","resourceType":"CLIENT_ACCOUNT",
       "resourceId":"acct-1","payload":{"ip":"10.0.0.1"}}
      """;
  private static final String REDACT_BODY = """
      {"fieldPaths":["/ip"],"reason":"test"}
      """;

  @BeforeEach
  void setUpMvc() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context)
            .addFilters(new ApiKeyAuthFilter(properties, JSON))
            .build();
  }

  // ---- authentication: bad or missing credentials -> 401 -------------------------------------

  @ParameterizedTest(name = "auth header [{0}] -> 401")
  @ValueSource(strings = {"<none>", "", "totally-unknown-key", "test-reader-key-WRONG"})
  void rejectsBadCredentialsWith401(String header) throws Exception {
    MockHttpServletRequestBuilder request = get("/audit/events");
    if (!"<none>".equals(header)) {
      request = request.header("X-Api-Key", header);
    }
    mvc.perform(request).andExpect(status().isUnauthorized());
  }

  // ---- authorization: valid key, insufficient scope -> 403 ----------------------------------

  static Stream<Arguments> endpointsAndUnderscopedKeys() {
    UUID id = UUID.randomUUID();
    return Stream.of(
        // POST /audit/events requires WRITE
        Arguments.of("POST", "/audit/events", EVENT_BODY, "test-reader-key"),
        // read endpoints require READ; test-writeonly-key has WRITE but not READ
        Arguments.of("GET", "/audit/events", null, "test-writeonly-key"),
        Arguments.of("GET", "/audit/events/" + id, null, "test-writeonly-key"),
        Arguments.of("GET", "/audit/verify", null, "test-writeonly-key"),
        Arguments.of("GET", "/audit/export?resourceId=acct-1", null, "test-writeonly-key"),
        Arguments.of(
            "GET",
            "/audit/compliance/access-report?resourceType=CLIENT_ACCOUNT&resourceId=acct-1"
                + "&from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z",
            null,
            "test-writeonly-key"),
        // ADMIN-only endpoints, hit with WRITE+READ (no ADMIN)
        Arguments.of("POST", "/audit/events/" + id + "/redactions", REDACT_BODY, "test-writer-key"),
        Arguments.of("POST", "/audit/retention/run", null, "test-writer-key"),
        Arguments.of("POST", "/audit/events/" + id + "/redactions", REDACT_BODY, "test-reader-key"),
        Arguments.of("POST", "/audit/retention/run", null, "test-reader-key"));
  }

  @ParameterizedTest(name = "{3} on {0} {1} -> 403")
  @MethodSource("endpointsAndUnderscopedKeys")
  void deniesInsufficientScopeWith403(String method, String path, String body, String apiKey)
      throws Exception {
    mvc.perform(build(method, path, body).header("X-Api-Key", apiKey))
        .andExpect(status().isForbidden());
  }

  // ---- deep verification is an explicit ADMIN gate inside the controller --------------------

  @Test
  void deepVerifyRequiresAdmin() throws Exception {
    mvc.perform(get("/audit/verify").param("deep", "true").header("X-Api-Key", "test-reader-key"))
        .andExpect(status().isForbidden());
    mvc.perform(get("/audit/verify").param("deep", "true").header("X-Api-Key", "test-admin-key"))
        .andExpect(status().isOk());
    mvc.perform(get("/audit/verify").param("deep", "false").header("X-Api-Key", "test-reader-key"))
        .andExpect(status().isOk());
  }

  // ---- positive control: the right scope is never an auth failure --------------------------

  @ParameterizedTest(name = "admin on {0} {1} -> not 401/403")
  @MethodSource("everyProtectedEndpoint")
  void adminScopePassesAuthOnEveryEndpoint(String method, String path, String body)
      throws Exception {
    int statusCode =
        mvc.perform(build(method, path, body).header("X-Api-Key", "test-admin-key"))
            .andReturn()
            .getResponse()
            .getStatus();
    assertThat(statusCode)
        .as("admin must never be blocked by auth on %s %s", method, path)
        .isNotIn(401, 403);
  }

  static Stream<Arguments> everyProtectedEndpoint() {
    UUID id = UUID.randomUUID();
    return Stream.of(
        Arguments.of("POST", "/audit/events", EVENT_BODY),
        Arguments.of("GET", "/audit/events", null),
        Arguments.of("GET", "/audit/events/" + id, null),
        Arguments.of("GET", "/audit/verify", null),
        Arguments.of("GET", "/audit/verify?deep=true", null),
        Arguments.of("GET", "/audit/export?resourceId=acct-1", null),
        Arguments.of(
            "GET",
            "/audit/compliance/access-report?resourceType=CLIENT_ACCOUNT&resourceId=acct-1"
                + "&from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z",
            null),
        Arguments.of("POST", "/audit/retention/run", null));
  }

  private static MockHttpServletRequestBuilder build(String method, String path, String body) {
    MockHttpServletRequestBuilder request =
        HttpMethod.POST.name().equals(method) ? post(path) : get(path);
    if (body != null) {
      request = request.contentType(MediaType.APPLICATION_JSON).content(body);
    }
    return request;
  }
}
