package com.sj.audit.domain;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RedactionRepository extends JpaRepository<Redaction, java.util.UUID> {

  List<Redaction> findByEventSeqOrderByFieldPathAsc(long eventSeq);

  List<Redaction> findByEventSeqInOrderByEventSeqAscFieldPathAsc(Collection<Long> eventSeqs);

  boolean existsByEventSeqAndFieldPath(long eventSeq, String fieldPath);
}
