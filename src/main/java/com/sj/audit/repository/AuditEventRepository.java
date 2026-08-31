package com.sj.audit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.sj.audit.domain.AuditEvent;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

public interface AuditEventRepository
    extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {

  Optional<AuditEvent> findByEventId(UUID eventId);

  /** Ascending page of the chain starting at {@code fromSeqInclusive}; used by verification. */
  List<AuditEvent> findBySeqGreaterThanEqualOrderBySeqAsc(long fromSeqInclusive, Limit limit);

  @Query("select coalesce(max(e.seq), 0) from AuditEvent e")
  long maxSeq();

  @Query("select coalesce(min(e.seq), 0) from AuditEvent e")
  long minSeq();

  List<AuditEvent> findByResourceIdOrderBySeqAsc(String resourceId);

  List<AuditEvent> findByActorIdOrderBySeqAsc(String actorId);

  List<AuditEvent> findBySeqInOrderBySeqAsc(Collection<Long> seqs);

  List<AuditEvent> findByArchivedAtIsNullAndRecordedAtLessThanOrderBySeqAsc(Instant cutoff);
}
