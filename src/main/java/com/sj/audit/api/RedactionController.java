package com.sj.audit.api;

import com.sj.audit.redaction.RedactionService;
import com.sj.audit.security.ApiPrincipal;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Structured redaction. ADMIN-scoped — this is the "human sign-off for high-impact changes" gate.
 */
@RestController
public class RedactionController {

  private final RedactionService redactionService;

  public RedactionController(RedactionService redactionService) {
    this.redactionService = redactionService;
  }

  public record RedactionRequestBody(
      @NotNull @NotEmpty List<String> fieldPaths,
      @NotNull String reason,
      String redactedBy,
      Boolean retainSalt) {}

  @PostMapping("/audit/events/{eventId}/redactions")
  @RequireScope(Scope.ADMIN)
  public RedactionService.RedactionResult redact(
      ApiPrincipal principal,
      @PathVariable String eventId,
      @RequestBody RedactionRequestBody body) {
    String redactedBy = body.redactedBy() != null ? body.redactedBy() : principal.name();
    return redactionService.redact(
        new RedactionService.RedactRequest(
            UUID.fromString(eventId),
            body.fieldPaths(),
            body.reason(),
            redactedBy,
            body.retainSalt()));
  }
}
