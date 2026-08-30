package com.sj.audit.query;

import java.time.Instant;

/**
 * Query criteria for the read API. Any combination may be supplied; null fields are ignored. The
 * time range is matched against {@code event_timestamp} (when the event occurred), half-open
 * {@code [from, to)}.
 */
public record AuditQueryFilter(
    String actorId,
    String resourceType,
    String resourceId,
    String eventType,
    Instant from,
    Instant to) {}
