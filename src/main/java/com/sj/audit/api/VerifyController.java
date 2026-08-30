package com.sj.audit.api;

import com.sj.audit.chain.ChainVerifier;
import com.sj.audit.chain.VerificationReport;
import com.sj.audit.config.ForbiddenException;
import com.sj.audit.security.ApiPrincipal;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Chain verification endpoint. */
@RestController
@Tag(name = "Verification", description = "Walk the hash chain and detect tampering")
public class VerifyController {

  private final ChainVerifier verifier;

  public VerifyController(ChainVerifier verifier) {
    this.verifier = verifier;
  }

  /**
   * Walks the chain (optionally a {@code [fromSeq, toSeq]} sub-range) and reports whether it is
   * intact; if not, the first inconsistent record and the violation type. {@code deep=true}
   * additionally re-hashes archived rows from the archive copy and requires the ADMIN scope.
   */
  @GetMapping("/audit/verify")
  @RequireScope(Scope.READ)
  @Operation(
      summary = "Verify the chain (scope: READ; deep=true needs ADMIN)",
      description =
          "Returns {intact, recordsChecked, archivedSegments, firstInconsistency}. Optional "
              + "fromSeq/toSeq verify a sub-range. deep=true re-hashes archived rows from the "
              + "archive copy.")
  public VerificationReport verify(
      ApiPrincipal principal,
      @RequestParam(required = false) Long fromSeq,
      @RequestParam(required = false) Long toSeq,
      @RequestParam(defaultValue = "false") boolean deep) {
    if (deep && !principal.hasScope(Scope.ADMIN)) {
      throw new ForbiddenException("deep verification requires the ADMIN scope");
    }
    return verifier.verify(fromSeq, toSeq, deep);
  }
}
