package com.sj.audit.domain;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ArchivedAuditEventRepository extends JpaRepository<ArchivedAuditEvent, Long> {

  Optional<ArchivedAuditEvent> findBySeq(long seq);
}
