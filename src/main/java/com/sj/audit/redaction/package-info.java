/**
 * Structured redaction (Scenario B): remove a sensitive payload field without breaking the chain.
 *
 * <p>Because the content hash only ever covered per-leaf <i>commitments</i>, not raw values,
 * {@link RedactionService} can delete a leaf's plaintext (replacing it with
 * a {@code "__REDACTED__:<id>"} sentinel), drop its salt, and record a
 * {@link com.sj.audit.domain.Redaction} row — <b>without recomputing any hash</b>. Verification
 * still passes; the {@code redaction} table (not the sentinel string) tells the verifier which
 * leaves to skip. Each redaction also appends an {@code AUDIT_RECORD_REDACTED} meta event.
 *
 * <p>See {@code docs/decisions/ADR-0004-redaction-by-commitment.md}.
 */
package com.sj.audit.redaction;

import com.sj.audit.service.RedactionService;