package com.sj.audit.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import tools.jackson.databind.JsonNode;

/**
 * Write-API request body.
 *
 * <p>{@code timestamp} is optional and caller-supplied ("when it happened"); when omitted the
 * server uses its own clock. The server <em>always</em> additionally records its own
 * {@code recordedAt}, which is authoritative for ordering and retention.
 */
public record CreateEventRequest(
    @NotBlank @Size(max = 200) String eventType,
    @NotBlank @Size(max = 200) String actorId,
    @NotBlank @Size(max = 200) String resourceType,
    @NotBlank @Size(max = 200) String resourceId,
    @NotNull JsonNode payload,
    Instant timestamp) {}
