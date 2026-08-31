/**
 * All business logic sits here; controllers in {@code com.sj.audit.api} call exactly one of these
 * services and map the result.
 *
 * <ul>
 *   <li>{@link com.sj.audit.service.ChainAppender} — the <b>single writer</b>. Locks the
 *       {@code chain_head} row, assigns the next {@code seq}, computes the hashes, saves the row,
 *       advances the head. The only place a record is created. (Vocabulary: see
 *       {@code com.sj.audit.domain.chain}.)
 *   <li>{@link com.sj.audit.service.ChainVerifier} — walks {@code seq} in order, recomputes each
 *       record's hashes and checks the links, and returns a
 *       {@link com.sj.audit.domain.chain.VerificationReport} naming the first
 *       {@link com.sj.audit.enums.ViolationType} it finds (or {@code intact}).
 *   <li>{@link com.sj.audit.service.AuditQueryService} — the read side: turns a
 *       {@link com.sj.audit.domain.query.AuditQueryFilter} into a JPA {@code Specification},
 *       always ordered by {@code seq}, time range matched on {@code event_timestamp}.
 *   <li>{@link com.sj.audit.service.RedactionService} — structured redaction (Scenario B). Because
 *       the content hash only ever covered per-leaf <i>commitments</i>, not raw values, it can
 *       delete a leaf's plaintext (replacing it with a {@code "__REDACTED__:<id>"} sentinel), drop
 *       its salt, and record a {@link com.sj.audit.domain.Redaction} row <b>without recomputing
 *       any hash</b>. The {@code redaction} table (not the sentinel string) tells the verifier
 *       which leaves to skip. Each redaction also appends an {@code AUDIT_RECORD_REDACTED} meta
 *       event. See {@code docs/decisions/ADR-0004-redaction-by-commitment.md}.
 *   <li>{@link com.sj.audit.service.RetentionService} — retention (Scenario B). Copies records
 *       older than {@code audit.retention.window} into
 *       {@link com.sj.audit.domain.ArchivedAuditEvent} and turns the live row into a
 *       <b>tombstone</b> — payload and salts nulled, every hash column kept, {@code archived_at}
 *       set. The row is never deleted, so {@code seq} stays gap-free and the retained
 *       {@code content_hash} is still chained into {@code record_hash}. Deep verification re-checks
 *       the archive copy. See {@code docs/decisions/ADR-0005-retention-tombstones.md}.
 *   <li>{@link com.sj.audit.service.BundleExporter} — builds an offline-verifiable
 *       {@link com.sj.audit.domain.export.ExportBundle} for a {@code resourceId} or
 *       {@code actorId}. A recipient checks it with {@link com.sj.audit.utils.BundleVerifier}.
 *   <li>{@link com.sj.audit.service.ComplianceReportService} — compliance access report
 *       (Scenario C, the ambiguous requirement). For one client account and a time window: which
 *       <i>access</i> events touched it, is the chain intact, is coverage complete. Returns those
 *       entries plus an embedded verifiable {@link com.sj.audit.domain.export.ExportBundle}, and
 *       appends a {@code COMPLIANCE_REPORT_GENERATED} event so running the report is itself
 *       audited. See {@code docs/scenarios/scenario-c.md}.
 * </ul>
 */
package com.sj.audit.service;
