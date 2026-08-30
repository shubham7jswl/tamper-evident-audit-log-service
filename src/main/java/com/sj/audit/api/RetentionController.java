package com.sj.audit.api;

import com.sj.audit.retention.RetentionService;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Manual trigger for a retention/archival pass. ADMIN-scoped. */
@RestController
public class RetentionController {

  private final RetentionService retentionService;

  public RetentionController(RetentionService retentionService) {
    this.retentionService = retentionService;
  }

  @PostMapping("/audit/retention/run")
  @RequireScope(Scope.ADMIN)
  public RetentionService.RetentionResult run() {
    return retentionService.run();
  }
}
