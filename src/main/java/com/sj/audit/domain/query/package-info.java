/**
 * The read side: filtered, paginated queries over the audit log.
 *
 * <p>{@link AuditQueryFilter} carries the optional criteria (actor / resource /
 * type / time range); {@link AuditQueryService} turns them into a JPA
 * {@code Specification}, always ordered by {@code seq}. The time range is matched against
 * {@code event_timestamp} (when the event happened), not {@code recorded_at}.
 */
package com.sj.audit.domain.query;

import com.sj.audit.service.AuditQueryService;