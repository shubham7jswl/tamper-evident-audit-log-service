package com.sj.audit.api;

import com.sj.audit.chain.ChainAppender;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.Redaction;
import com.sj.audit.domain.RedactionRepository;
import com.sj.audit.query.AuditQueryFilter;
import com.sj.audit.query.AuditQueryService;
import com.sj.audit.security.RequireScope;
import com.sj.audit.security.Scope;
import jakarta.validation.Valid;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Write and query APIs. There is deliberately no update or delete route. */
@RestController
@RequestMapping("/audit/events")
public class AuditEventController {

  private static final int MAX_PAGE_SIZE = 200;

  private final ChainAppender appender;
  private final AuditQueryService queryService;
  private final RedactionRepository redactions;
  private final JsonSupport json;

  public AuditEventController(
      ChainAppender appender,
      AuditQueryService queryService,
      RedactionRepository redactions,
      JsonSupport json) {
    this.appender = appender;
    this.queryService = queryService;
    this.redactions = redactions;
    this.json = json;
  }

  @PostMapping
  @RequireScope(Scope.WRITE)
  public ResponseEntity<AuditEventResponse> create(@Valid @RequestBody CreateEventRequest request) {
    if (!request.payload().isObject()) {
      throw new IllegalArgumentException("payload must be a JSON object");
    }
    AuditEvent saved =
        appender.append(
            new ChainAppender.NewEvent(
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                request.payload(),
                request.timestamp()));
    return ResponseEntity.created(URI.create("/audit/events/" + saved.getEventId()))
        .body(AuditEventResponse.from(saved, json, List.of()));
  }

  @GetMapping("/{eventId}")
  @RequireScope(Scope.READ)
  public AuditEventResponse get(@PathVariable String eventId) {
    AuditEvent event =
        queryService
            .findByEventId(parseUuid(eventId))
            .orElseThrow(() -> new NoSuchElementException("no audit event " + eventId));
    List<String> redactedPaths =
        redactions.findByEventSeqOrderByFieldPathAsc(event.getSeq()).stream()
            .map(Redaction::getFieldPath)
            .toList();
    return AuditEventResponse.from(event, json, redactedPaths);
  }

  @GetMapping
  @RequireScope(Scope.READ)
  public PageResponse<AuditEventResponse> query(
      @RequestParam(required = false) String actorId,
      @RequestParam(required = false) String resourceType,
      @RequestParam(required = false) String resourceId,
      @RequestParam(required = false) String eventType,
      @RequestParam(required = false) String from,
      @RequestParam(required = false) String to,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size) {

    int effectiveSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
    AuditQueryFilter filter =
        new AuditQueryFilter(
            actorId, resourceType, resourceId, eventType, parseInstant(from, "from"), parseInstant(to, "to"));

    Page<AuditEvent> result =
        queryService.query(
            filter, PageRequest.of(Math.max(page, 0), effectiveSize, Sort.by("seq").ascending()));

    Map<Long, List<String>> redactedBySeq =
        redactions
            .findByEventSeqInOrderByEventSeqAscFieldPathAsc(
                result.getContent().stream().map(AuditEvent::getSeq).toList())
            .stream()
            .collect(
                Collectors.groupingBy(
                    Redaction::getEventSeq,
                    Collectors.mapping(Redaction::getFieldPath, Collectors.toList())));

    List<AuditEventResponse> content =
        result.getContent().stream()
            .map(
                e ->
                    AuditEventResponse.from(
                        e, json, redactedBySeq.getOrDefault(e.getSeq(), List.of())))
            .toList();
    return PageResponse.of(result, content);
  }

  private static java.util.UUID parseUuid(String value) {
    try {
      return java.util.UUID.fromString(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("not a valid event id: " + value);
    }
  }

  private static Instant parseInstant(String value, String field) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(field + " must be an ISO-8601 instant, e.g. 2026-08-29T12:00:00Z");
    }
  }
}
