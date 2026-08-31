/**
 * Retention (Scenario B): age out old records without creating a false chain break.
 *
 * <p>{@link com.sj.audit.retention.RetentionService} copies records older than
 * {@code audit.retention.window} into {@link com.sj.audit.domain.ArchivedAuditEvent} and turns the
 * live row into a <b>tombstone</b> — payload and salts nulled, every hash column kept,
 * {@code archived_at} set. The row is never deleted, so {@code seq} stays gap-free and the retained
 * {@code content_hash} is still chained into {@code record_hash}. Deep verification re-checks the
 * archive copy.
 *
 * <p>See {@code docs/decisions/ADR-0005-retention-tombstones.md}.
 */
package com.sj.audit.retention;
