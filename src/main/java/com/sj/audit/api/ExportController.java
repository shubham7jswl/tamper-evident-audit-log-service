package com.sj.audit.api;

import com.sj.audit.export.BundleExporter;
import com.sj.audit.export.ExportBundle;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Bulk verifiable export for a single {@code resourceId} or {@code actorId}. */
@RestController
public class ExportController {

  private final BundleExporter exporter;

  public ExportController(BundleExporter exporter) {
    this.exporter = exporter;
  }

  @GetMapping("/audit/export")
  @RequireScope(Scope.READ)
  public ExportBundle export(
      @RequestParam(required = false) String resourceId,
      @RequestParam(required = false) String actorId) {
    boolean hasResource = resourceId != null && !resourceId.isBlank();
    boolean hasActor = actorId != null && !actorId.isBlank();
    if (hasResource == hasActor) {
      throw new IllegalArgumentException("exactly one of resourceId or actorId is required");
    }
    return hasResource
        ? exporter.exportByResourceId(resourceId)
        : exporter.exportByActorId(actorId);
  }
}
