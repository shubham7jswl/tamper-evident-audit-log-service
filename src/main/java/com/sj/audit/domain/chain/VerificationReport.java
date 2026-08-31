package com.sj.audit.domain.chain;

import com.sj.audit.enums.ViolationType;

import java.util.List;
import java.util.UUID;

/**
 * Result of a chain verification pass.
 *
 * @param intact true iff no inconsistency was found in the inspected range
 * @param recordsChecked number of records inspected before stopping
 * @param fromSeq first seq inspected
 * @param toSeq last seq inspected (0 when the range was empty)
 * @param deep whether archived rows were re-hashed from the archive copy
 * @param archivedSegments contiguous runs of archived (tombstoned) records seen in the range
 * @param firstInconsistency the first problem found, or null when {@code intact}
 */
public record VerificationReport(
    boolean intact,
    long recordsChecked,
    long fromSeq,
    long toSeq,
    boolean deep,
    List<ArchivedSegment> archivedSegments,
    Inconsistency firstInconsistency) {

  public record ArchivedSegment(long fromSeq, long toSeq) {}

  public record Inconsistency(long seq, UUID eventId, ViolationType violationType, String detail) {}

  public static VerificationReport intact(
      long recordsChecked, long fromSeq, long toSeq, boolean deep, List<ArchivedSegment> archived) {
    return new VerificationReport(true, recordsChecked, fromSeq, toSeq, deep, archived, null);
  }

  public static VerificationReport broken(
      long recordsChecked,
      long fromSeq,
      long toSeq,
      boolean deep,
      List<ArchivedSegment> archived,
      Inconsistency inconsistency) {
    return new VerificationReport(
        false, recordsChecked, fromSeq, toSeq, deep, archived, inconsistency);
  }
}
