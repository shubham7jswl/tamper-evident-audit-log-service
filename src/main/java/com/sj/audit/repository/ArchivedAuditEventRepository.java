package com.sj.audit.repository;

import java.util.Optional;

import com.sj.audit.domain.ArchivedAuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ArchivedAuditEventRepository extends JpaRepository<ArchivedAuditEvent, Long> {

  Optional<ArchivedAuditEvent> findBySeq(long seq);
}
