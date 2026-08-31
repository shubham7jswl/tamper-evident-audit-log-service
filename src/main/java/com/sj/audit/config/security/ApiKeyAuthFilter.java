package com.sj.audit.config.security;

import com.sj.audit.config.ApiError;
import com.sj.audit.config.AuditProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Authenticates every API request against the static {@code X-Api-Key} list. Unauthenticated
 * requests get {@code 401} before any handler runs; authorization (scope checks) is a separate
 * concern handled by {@link ScopeInterceptor}.
 *
 * <p>This is deliberately minimal (no rotation, no per-key rate limiting, no mTLS). See
 * {@code docs/architecture.md} "Security" for the production hardening list.
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

  static final String HEADER = "X-Api-Key";

  private final Map<String, ApiPrincipal> principalsByKey = new HashMap<>();
  private final ObjectMapper objectMapper;

  public ApiKeyAuthFilter(AuditProperties properties, ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
    if (properties.apiKeys() != null) {
      for (AuditProperties.ApiKey k : properties.apiKeys()) {
        // Skip blank keys: an unset AUDIT_*_KEY binds to "" and must never authenticate a request
        // that omits the header. ApiKeyConfigValidator already fails startup for this outside dev.
        if (k.key() == null || k.key().isBlank()) {
          continue;
        }
        principalsByKey.put(k.key(), new ApiPrincipal(k.principal(), Set.copyOf(k.scopes())));
      }
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return path.startsWith("/actuator/health")
        || path.startsWith("/actuator/info")
        || path.startsWith("/h2-console")
        || path.equals("/error");
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    String presented = request.getHeader(HEADER);
    ApiPrincipal principal = (presented == null || presented.isBlank()) ? null : lookup(presented);
    if (principal == null) {
      writeUnauthorized(request, response);
      return;
    }
    request.setAttribute(ApiPrincipal.ATTRIBUTE, principal);
    chain.doFilter(request, response);
  }

  private ApiPrincipal lookup(String presented) {
    // Constant-time-ish: compare against every configured key so a wrong key of the right
    // length does not leak timing information about which prefix matched.
    ApiPrincipal match = null;
    byte[] presentedBytes = presented.getBytes(StandardCharsets.UTF_8);
    for (Map.Entry<String, ApiPrincipal> e : principalsByKey.entrySet()) {
      if (MessageDigest.isEqual(presentedBytes, e.getKey().getBytes(StandardCharsets.UTF_8))) {
        match = e.getValue();
      }
    }
    return match;
  }

  private void writeUnauthorized(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    ApiError body =
        ApiError.of(
            HttpStatus.UNAUTHORIZED.value(),
            "Unauthorized",
            "missing or invalid " + HEADER + " header",
            request.getRequestURI());
    response.getWriter().write(objectMapper.writeValueAsString(body));
  }
}
