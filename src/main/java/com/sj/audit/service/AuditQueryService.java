package com.sj.audit.service;

import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.query.AuditQueryFilter;
import com.sj.audit.repository.AuditEventRepository;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Read-side of the audit log: filtered, paginated queries ordered by chain position ({@code seq}). */
@Service
public class AuditQueryService {

  private final AuditEventRepository auditEvents;

  public AuditQueryService(AuditEventRepository auditEvents) {
    this.auditEvents = auditEvents;
  }

  @Transactional(readOnly = true)
  public Page<AuditEvent> query(AuditQueryFilter filter, Pageable pageable) {
    return auditEvents.findAll(matching(filter), pageable);
  }

  @Transactional(readOnly = true)
  public Optional<AuditEvent> findByEventId(UUID eventId) {
    return auditEvents.findByEventId(eventId);
  }

  /** Builds a JPA {@code WHERE} from the non-null criteria; time range is on {@code eventTimestamp}. */
  static Specification<AuditEvent> matching(AuditQueryFilter filter) {
    return (root, query, criteriaBuilder) -> {
      List<Predicate> conditions = new ArrayList<>();
      if (filter.actorId() != null) {
        conditions.add(criteriaBuilder.equal(root.get("actorId"), filter.actorId()));
      }
      if (filter.resourceType() != null) {
        conditions.add(criteriaBuilder.equal(root.get("resourceType"), filter.resourceType()));
      }
      if (filter.resourceId() != null) {
        conditions.add(criteriaBuilder.equal(root.get("resourceId"), filter.resourceId()));
      }
      if (filter.eventType() != null) {
        conditions.add(criteriaBuilder.equal(root.get("eventType"), filter.eventType()));
      }
      if (filter.from() != null) {
        conditions.add(
            criteriaBuilder.greaterThanOrEqualTo(root.get("eventTimestamp"), filter.from()));
      }
      if (filter.to() != null) {
        conditions.add(criteriaBuilder.lessThan(root.get("eventTimestamp"), filter.to()));
      }
      return criteriaBuilder.and(conditions.toArray(new Predicate[0]));
    };
  }
}
