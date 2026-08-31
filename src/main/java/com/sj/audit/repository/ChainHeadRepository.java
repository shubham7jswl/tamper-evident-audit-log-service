package com.sj.audit.repository;

import com.sj.audit.domain.ChainHead;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

public interface ChainHeadRepository extends JpaRepository<ChainHead, Short> {

  /**
   * Load the singleton head row with a write lock ({@code SELECT ... FOR UPDATE}). Every append
   * calls this first, which serializes chain writers across all instances sharing the database.
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select h from ChainHead h where h.id = 1")
  ChainHead lockHead();
}
