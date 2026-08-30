package com.sj.audit.api;

import com.sj.audit.retention.RetentionService;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Manual trigger for a retention/archival pass. ADMIN-scoped. */
@RestController
@Tag(name = "Retention", description = "Archive records older than the retention window")
public class RetentionController {

  private final RetentionService retentionService;

  public RetentionController(RetentionService retentionService) {
    this.retentionService = retentionService;
  }

  @PostMapping("/audit/retention/run")
  @RequireScope(Scope.ADMIN)
  @Operation(
      summary = "Run a retention pass (scope: ADMIN)",
      description =
          "Copies rows older than audit.retention.window to the archive and converts the live "
              + "rows to tombstones (hashes kept). Verification still passes for archived ranges.")
  public RetentionService.RetentionResult run() {
    return retentionService.run();
  }
}
