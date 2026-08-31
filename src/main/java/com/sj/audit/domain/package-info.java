/**
 * Persistence: JPA entities and their Spring Data repositories.
 *
 * <ul>
 *   <li>{@link com.sj.audit.domain.AuditEvent} — one row in the append-only chain. No generic
 *       setters; the only post-insert changes are the audited operations {@code applyRedaction}
 *       and {@code archiveAsTombstone}, both of which keep every hash column.
 *   <li>{@link com.sj.audit.domain.ChainHead} — the single-row lock target + head cache.
 *   <li>{@link com.sj.audit.domain.ArchivedAuditEvent} — a full, immutable copy taken at archival
 *       time, used for deep verification.
 *   <li>{@link com.sj.audit.domain.Redaction} — one row per redacted payload leaf: which pointer,
 *       its commitment, whether the salt was kept, why, by whom, when.
 * </ul>
 *
 * <p>The schema is owned by Flyway ({@code src/main/resources/db/migration}); Hibernate runs with
 * {@code ddl-auto=none}.
 */
package com.sj.audit.domain;
