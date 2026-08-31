package com.sj.audit.repository;

import java.util.Collection;
import java.util.List;

import com.sj.audit.domain.Redaction;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RedactionRepository extends JpaRepository<Redaction, java.util.UUID> {

  List<Redaction> findByEventSeqOrderByFieldPathAsc(long eventSeq);

  List<Redaction> findByEventSeqInOrderByEventSeqAscFieldPathAsc(Collection<Long> eventSeqs);

  boolean existsByEventSeqAndFieldPath(long eventSeq, String fieldPath);
}
