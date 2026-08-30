package com.sj.audit.query;

import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Read-side of the audit log: filtered, paginated queries ordered by chain position ({@code seq}). */
@Service
public class AuditQueryService {

  private final AuditEventRepository events;

  public AuditQueryService(AuditEventRepository events) {
    this.events = events;
  }

  @Transactional(readOnly = true)
  public Page<AuditEvent> query(AuditQueryFilter filter, Pageable pageable) {
    return events.findAll(toSpecification(filter), pageable);
  }

  @Transactional(readOnly = true)
  public java.util.Optional<AuditEvent> findByEventId(java.util.UUID eventId) {
    return events.findByEventId(eventId);
  }

  static Specification<AuditEvent> toSpecification(AuditQueryFilter f) {
    return (root, cq, cb) -> {
      List<Predicate> predicates = new ArrayList<>();
      if (f.actorId() != null) {
        predicates.add(cb.equal(root.get("actorId"), f.actorId()));
      }
      if (f.resourceType() != null) {
        predicates.add(cb.equal(root.get("resourceType"), f.resourceType()));
      }
      if (f.resourceId() != null) {
        predicates.add(cb.equal(root.get("resourceId"), f.resourceId()));
      }
      if (f.eventType() != null) {
        predicates.add(cb.equal(root.get("eventType"), f.eventType()));
      }
      if (f.from() != null) {
        predicates.add(cb.greaterThanOrEqualTo(root.get("eventTimestamp"), f.from()));
      }
      if (f.to() != null) {
        predicates.add(cb.lessThan(root.get("eventTimestamp"), f.to()));
      }
      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }
}
