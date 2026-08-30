package com.sj.audit.chain;

import com.sj.audit.config.AuditProperties;
import com.sj.audit.config.JsonSupport;
import com.sj.audit.domain.ArchivedAuditEvent;
import com.sj.audit.domain.ArchivedAuditEventRepository;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import com.sj.audit.domain.Redaction;
import com.sj.audit.domain.RedactionRepository;
import com.sj.audit.hash.AuditHasher;
import com.sj.audit.hash.PayloadCommitments;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;

/**
 * Walks the hash chain and reports whether it is intact, stopping at (and identifying) the first
 * inconsistency.
 *
 * <p>Handles two legitimate states that must NOT be reported as tampering:
 *
 * <ul>
 *   <li><b>archived tombstones</b> — payload/salts gone, hashes retained. Their {@code content_hash}
 *       is still bound into {@code record_hash}, so the chain math still closes; we just cannot
 *       re-derive it from fields unless {@code deep} verification is requested (which reads the
 *       archive copy).
 *   <li><b>redacted leaves</b> — plaintext gone; the stored per-leaf commitment (unchanged since
 *       write, and covered by {@code content_hash}) is used in its place.
 * </ul>
 */
@Service
public class ChainVerifier {

  private static final int PAGE = 500;

  private final AuditEventRepository events;
  private final ArchivedAuditEventRepository archived;
  private final RedactionRepository redactions;
  private final AuditHasher hasher;
  private final JsonSupport json;
  private final String genesisHash;

  public ChainVerifier(
      AuditEventRepository events,
      ArchivedAuditEventRepository archived,
      RedactionRepository redactions,
      AuditHasher hasher,
      JsonSupport json,
      AuditProperties properties) {
    this.events = events;
    this.archived = archived;
    this.redactions = redactions;
    this.hasher = hasher;
    this.json = json;
    this.genesisHash = properties.genesisHash();
  }

  @Transactional(readOnly = true)
  public VerificationReport verify(Long fromSeqOrNull, Long toSeqOrNull, boolean deep) {
    long minSeq = events.minSeq();
    long maxSeq = events.maxSeq();
    if (maxSeq == 0) {
      return VerificationReport.intact(0, 0, 0, deep, List.of());
    }
    long fromSeq = fromSeqOrNull != null ? Math.max(fromSeqOrNull, 1) : minSeq;
    long toSeq = toSeqOrNull != null ? Math.min(toSeqOrNull, maxSeq) : maxSeq;
    if (fromSeq > toSeq) {
      return VerificationReport.intact(0, fromSeq, 0, deep, List.of());
    }

    String prevRecordHash = seedPrevHash(fromSeq);
    long expectedSeq = fromSeq;
    long checked = 0;
    List<VerificationReport.ArchivedSegment> archivedSegments = new ArrayList<>();
    Long archiveRunStart = null;
    Long archiveRunEnd = null;

    long cursor = fromSeq;
    while (cursor <= toSeq) {
      List<AuditEvent> page =
          events.findBySeqGreaterThanEqualOrderBySeqAsc(cursor, Limit.of(PAGE));
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent e : page) {
        if (e.getSeq() > toSeq) {
          break;
        }
        checked++;

        if (e.getSeq() != expectedSeq) {
          flushRun(archivedSegments, archiveRunStart, archiveRunEnd);
          return VerificationReport.broken(
              checked,
              fromSeq,
              e.getSeq(),
              deep,
              archivedSegments,
              new VerificationReport.Inconsistency(
                  expectedSeq,
                  null,
                  ViolationType.SEQUENCE_GAP,
                  "expected seq " + expectedSeq + " but next present record is " + e.getSeq()));
        }

        // 1. genesis / linkage
        if (e.getSeq() == 1 && !e.getPrevHash().equals(genesisHash)) {
          return VerificationReport.broken(
              checked, fromSeq, e.getSeq(), deep, archivedSegments,
              inc(e, ViolationType.GENESIS_MISMATCH, "prev_hash != configured genesis value"));
        }
        if (!e.getPrevHash().equals(prevRecordHash)) {
          return VerificationReport.broken(
              checked, fromSeq, e.getSeq(), deep, archivedSegments,
              inc(
                  e,
                  ViolationType.PREV_HASH_MISMATCH,
                  "prev_hash does not match the previous record's record_hash"));
        }

        // 2. content hash (and, where possible, per-leaf commitments)
        VerificationReport.Inconsistency contentProblem = checkContent(e, deep);
        if (contentProblem != null) {
          return VerificationReport.broken(
              checked, fromSeq, e.getSeq(), deep, archivedSegments, contentProblem);
        }

        // 3. record hash
        String expectedRecordHash = hasher.recordHash(e.getPrevHash(), e.getContentHash());
        if (!expectedRecordHash.equals(e.getRecordHash())) {
          return VerificationReport.broken(
              checked, fromSeq, e.getSeq(), deep, archivedSegments,
              inc(e, ViolationType.RECORD_HASH_MISMATCH, "recomputed record_hash != stored"));
        }

        // archived-run bookkeeping
        if (e.isArchived()) {
          if (archiveRunStart == null) {
            archiveRunStart = e.getSeq();
          }
          archiveRunEnd = e.getSeq();
        } else if (archiveRunStart != null) {
          archivedSegments.add(
              new VerificationReport.ArchivedSegment(archiveRunStart, archiveRunEnd));
          archiveRunStart = null;
          archiveRunEnd = null;
        }

        prevRecordHash = e.getRecordHash();
        expectedSeq++;
      }
      cursor = page.get(page.size() - 1).getSeq() + 1;
    }

    if (expectedSeq <= toSeq) {
      flushRun(archivedSegments, archiveRunStart, archiveRunEnd);
      return VerificationReport.broken(
          checked, fromSeq, expectedSeq - 1, deep, archivedSegments,
          new VerificationReport.Inconsistency(
              expectedSeq, null, ViolationType.SEQUENCE_GAP,
              "records end at seq " + (expectedSeq - 1) + " but chain head is " + toSeq));
    }

    flushRun(archivedSegments, archiveRunStart, archiveRunEnd);
    return VerificationReport.intact(checked, fromSeq, toSeq, deep, archivedSegments);
  }

  private VerificationReport.Inconsistency checkContent(AuditEvent e, boolean deep) {
    Map<String, String> storedCommitments = json.readStringMap(e.getLeafCommitmentsJson());
    Set<String> redactedPaths =
        redactions.findByEventSeqOrderByFieldPathAsc(e.getSeq()).stream()
            .map(Redaction::getFieldPath)
            .collect(Collectors.toSet());

    if (e.isArchived()) {
      if (deep) {
        ArchivedAuditEvent copy = archived.findBySeq(e.getSeq()).orElse(null);
        if (copy == null) {
          return inc(e, ViolationType.CONTENT_HASH_MISMATCH, "archived row has no archive copy");
        }
        VerificationReport.Inconsistency leafProblem =
            recomputeLeaves(
                e, copy.getPayloadJson(), copy.getLeafSaltsJson(), storedCommitments, redactedPaths);
        if (leafProblem != null) {
          return leafProblem;
        }
      }
      // shallow: trust storedCommitments (still chained into record_hash) and just recompute
      // the content hash from the stored core fields + commitment map.
      return contentHashMatches(e, storedCommitments)
          ? null
          : inc(e, ViolationType.CONTENT_HASH_MISMATCH, "recomputed content_hash != stored (archived)");
    }

    VerificationReport.Inconsistency leafProblem =
        recomputeLeaves(
            e, e.getPayloadJson(), e.getLeafSaltsJson(), storedCommitments, redactedPaths);
    if (leafProblem != null) {
      return leafProblem;
    }
    return contentHashMatches(e, storedCommitments)
        ? null
        : inc(e, ViolationType.CONTENT_HASH_MISMATCH, "recomputed content_hash != stored");
  }

  /** Recompute every non-redacted leaf commitment from plaintext + salt and compare to stored. */
  private VerificationReport.Inconsistency recomputeLeaves(
      AuditEvent e,
      String payloadJson,
      String saltsJson,
      Map<String, String> storedCommitments,
      Set<String> redactedPaths) {
    JsonNode payload = json.parse(payloadJson);
    Map<String, String> salts = json.readStringMap(saltsJson);
    Map<String, String> currentForms = PayloadCommitments.leafForms(payload);

    for (Map.Entry<String, String> entry : storedCommitments.entrySet()) {
      String path = entry.getKey();
      if (redactedPaths.contains(path)) {
        continue;
      }
      String form = currentForms.get(path);
      if (form == null) {
        return inc(
            e,
            ViolationType.LEAF_COMMITMENT_MISMATCH,
            "payload leaf " + path + " is missing (structure changed)");
      }
      String salt = salts.get(path);
      if (salt == null) {
        return inc(e, ViolationType.MISSING_SALT, "no salt for payload leaf " + path);
      }
      if (!PayloadCommitments.commit(salt, form).equals(entry.getValue())) {
        return inc(
            e, ViolationType.LEAF_COMMITMENT_MISMATCH, "payload leaf " + path + " was modified");
      }
    }
    // any leaf present now but not in the stored commitment set => field was added
    for (String path : currentForms.keySet()) {
      if (!storedCommitments.containsKey(path)) {
        return inc(
            e,
            ViolationType.LEAF_COMMITMENT_MISMATCH,
            "payload leaf " + path + " was added after the record was written");
      }
    }
    return null;
  }

  private boolean contentHashMatches(AuditEvent e, Map<String, String> commitments) {
    String recomputed =
        hasher.contentHash(
            new AuditHasher.HashInputs(
                e.getSeq(),
                e.getEventId(),
                e.getEventType(),
                e.getActorId(),
                e.getResourceType(),
                e.getResourceId(),
                e.getEventTimestamp(),
                e.getRecordedAt(),
                commitments));
    return recomputed.equals(e.getContentHash());
  }

  private String seedPrevHash(long fromSeq) {
    if (fromSeq <= 1) {
      return genesisHash;
    }
    return events
        .findById(fromSeq - 1)
        .map(AuditEvent::getRecordHash)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "cannot start verification at seq " + fromSeq + ": predecessor is missing"));
  }

  private static void flushRun(
      List<VerificationReport.ArchivedSegment> segments, Long start, Long end) {
    if (start != null) {
      segments.add(new VerificationReport.ArchivedSegment(start, end));
    }
  }

  private static VerificationReport.Inconsistency inc(
      AuditEvent e, ViolationType type, String detail) {
    return new VerificationReport.Inconsistency(e.getSeq(), e.getEventId(), type, detail);
  }
}
