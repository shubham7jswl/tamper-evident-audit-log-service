package com.sj.audit.config.security;

import com.sj.audit.config.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import tools.jackson.databind.ObjectMapper;

/** Enforces {@link RequireScope} on controller methods after authentication has run. */
@Component
public class ScopeInterceptor implements HandlerInterceptor {

  private final ObjectMapper objectMapper;

  public ScopeInterceptor(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    if (!(handler instanceof HandlerMethod method)) {
      return true;
    }
    RequireScope required = method.getMethodAnnotation(RequireScope.class);
    if (required == null) {
      return true;
    }
    ApiPrincipal principal = (ApiPrincipal) request.getAttribute(ApiPrincipal.ATTRIBUTE);
    if (principal == null) {
      return deny(request, response, HttpStatus.UNAUTHORIZED, "authentication required");
    }
    if (!principal.hasScope(required.value())) {
      return deny(
          request,
          response,
          HttpStatus.FORBIDDEN,
          "principal '" + principal.name() + "' lacks required scope " + required.value());
    }
    return true;
  }

  private boolean deny(
      HttpServletRequest request, HttpServletResponse response, HttpStatus status, String message)
      throws Exception {
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response
        .getWriter()
        .write(
            objectMapper.writeValueAsString(
                ApiError.of(
                    status.value(), status.getReasonPhrase(), message, request.getRequestURI())));
    return false;
  }
}
