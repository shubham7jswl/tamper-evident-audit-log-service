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

  private static final int SCAN_PAGE_SIZE = 500;

  private final AuditEventRepository auditEvents;
  private final ArchivedAuditEventRepository archive;
  private final RedactionRepository redactions;
  private final AuditHasher auditHasher;
  private final JsonSupport jsonCodec;
  private final String genesisHash;

  public ChainVerifier(
      AuditEventRepository auditEvents,
      ArchivedAuditEventRepository archive,
      RedactionRepository redactions,
      AuditHasher auditHasher,
      JsonSupport jsonCodec,
      AuditProperties properties) {
    this.auditEvents = auditEvents;
    this.archive = archive;
    this.redactions = redactions;
    this.auditHasher = auditHasher;
    this.jsonCodec = jsonCodec;
    this.genesisHash = properties.genesisHash();
  }

  @Transactional(readOnly = true)
  public VerificationReport verify(Long requestedFromSeq, Long requestedToSeq, boolean deep) {
    long firstSeqInChain = auditEvents.minSeq();
    long lastSeqInChain = auditEvents.maxSeq();
    if (lastSeqInChain == 0) {
      return VerificationReport.intact(0, 0, 0, deep, List.of());
    }
    long fromSeq = requestedFromSeq != null ? Math.max(requestedFromSeq, 1) : firstSeqInChain;
    long toSeq = requestedToSeq != null ? Math.min(requestedToSeq, lastSeqInChain) : lastSeqInChain;
    if (fromSeq > toSeq) {
      return VerificationReport.intact(0, fromSeq, 0, deep, List.of());
    }

    String previousRecordHash = recordHashBefore(fromSeq);
    long expectedSeq = fromSeq;
    long recordsChecked = 0;
    List<VerificationReport.ArchivedSegment> archivedSegments = new ArrayList<>();
    Long openArchivedRunStartSeq = null;
    Long openArchivedRunEndSeq = null;

    long nextSeqToScan = fromSeq;
    while (nextSeqToScan <= toSeq) {
      List<AuditEvent> page =
          auditEvents.findBySeqGreaterThanEqualOrderBySeqAsc(nextSeqToScan, Limit.of(SCAN_PAGE_SIZE));
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent event : page) {
        if (event.getSeq() > toSeq) {
          break;
        }
        recordsChecked++;

        if (event.getSeq() != expectedSeq) {
          closeArchivedRun(archivedSegments, openArchivedRunStartSeq, openArchivedRunEndSeq);
          return VerificationReport.broken(
              recordsChecked,
              fromSeq,
              event.getSeq(),
              deep,
              archivedSegments,
              new VerificationReport.Inconsistency(
                  expectedSeq,
                  null,
                  ViolationType.SEQUENCE_GAP,
                  "expected seq " + expectedSeq + " but next present record is " + event.getSeq()));
        }

        // 1. genesis / linkage
        if (event.getSeq() == 1 && !event.getPrevHash().equals(genesisHash)) {
          return VerificationReport.broken(
              recordsChecked, fromSeq, event.getSeq(), deep, archivedSegments,
              inconsistencyAt(
                  event, ViolationType.GENESIS_MISMATCH, "prev_hash != configured genesis value"));
        }
        if (!event.getPrevHash().equals(previousRecordHash)) {
          return VerificationReport.broken(
              recordsChecked, fromSeq, event.getSeq(), deep, archivedSegments,
              inconsistencyAt(
                  event,
                  ViolationType.PREV_HASH_MISMATCH,
                  "prev_hash does not match the previous record's record_hash"));
        }

        // 2. content hash (and, where possible, per-leaf commitments)
        VerificationReport.Inconsistency contentInconsistency = checkContentHash(event, deep);
        if (contentInconsistency != null) {
          return VerificationReport.broken(
              recordsChecked, fromSeq, event.getSeq(), deep, archivedSegments, contentInconsistency);
        }

        // 3. record hash
        String expectedRecordHash =
            auditHasher.recordHash(event.getPrevHash(), event.getContentHash());
        if (!expectedRecordHash.equals(event.getRecordHash())) {
          return VerificationReport.broken(
              recordsChecked, fromSeq, event.getSeq(), deep, archivedSegments,
              inconsistencyAt(
                  event, ViolationType.RECORD_HASH_MISMATCH, "recomputed record_hash != stored"));
        }

        // track contiguous runs of archived tombstones so the report can list them
        if (event.isArchived()) {
          if (openArchivedRunStartSeq == null) {
            openArchivedRunStartSeq = event.getSeq();
          }
          openArchivedRunEndSeq = event.getSeq();
        } else if (openArchivedRunStartSeq != null) {
          archivedSegments.add(
              new VerificationReport.ArchivedSegment(
                  openArchivedRunStartSeq, openArchivedRunEndSeq));
          openArchivedRunStartSeq = null;
          openArchivedRunEndSeq = null;
        }

        previousRecordHash = event.getRecordHash();
        expectedSeq++;
      }
      nextSeqToScan = page.get(page.size() - 1).getSeq() + 1;
    }

    if (expectedSeq <= toSeq) {
      closeArchivedRun(archivedSegments, openArchivedRunStartSeq, openArchivedRunEndSeq);
      return VerificationReport.broken(
          recordsChecked, fromSeq, expectedSeq - 1, deep, archivedSegments,
          new VerificationReport.Inconsistency(
              expectedSeq, null, ViolationType.SEQUENCE_GAP,
              "records end at seq " + (expectedSeq - 1) + " but chain head is " + toSeq));
    }

    closeArchivedRun(archivedSegments, openArchivedRunStartSeq, openArchivedRunEndSeq);
    return VerificationReport.intact(recordsChecked, fromSeq, toSeq, deep, archivedSegments);
  }

  private VerificationReport.Inconsistency checkContentHash(AuditEvent event, boolean deep) {
    Map<String, String> storedCommitmentByPointer =
        jsonCodec.readStringMap(event.getLeafCommitmentsJson());
    Set<String> redactedPointers =
        redactions.findByEventSeqOrderByFieldPathAsc(event.getSeq()).stream()
            .map(Redaction::getFieldPath)
            .collect(Collectors.toSet());

    if (event.isArchived()) {
      if (deep) {
        ArchivedAuditEvent archivedCopy = archive.findBySeq(event.getSeq()).orElse(null);
        if (archivedCopy == null) {
          return inconsistencyAt(
              event, ViolationType.CONTENT_HASH_MISMATCH, "archived row has no archive copy");
        }
        VerificationReport.Inconsistency leafInconsistency =
            checkLeafCommitments(
                event,
                archivedCopy.getPayloadJson(),
                archivedCopy.getLeafSaltsJson(),
                storedCommitmentByPointer,
                redactedPointers);
        if (leafInconsistency != null) {
          return leafInconsistency;
        }
      }
      // shallow: trust the stored commitments (still chained into record_hash) and just recompute
      // the content hash from the stored core fields + commitment map.
      return contentHashMatches(event, storedCommitmentByPointer)
          ? null
          : inconsistencyAt(
              event,
              ViolationType.CONTENT_HASH_MISMATCH,
              "recomputed content_hash != stored (archived)");
    }

    VerificationReport.Inconsistency leafInconsistency =
        checkLeafCommitments(
            event,
            event.getPayloadJson(),
            event.getLeafSaltsJson(),
            storedCommitmentByPointer,
            redactedPointers);
    if (leafInconsistency != null) {
      return leafInconsistency;
    }
    return contentHashMatches(event, storedCommitmentByPointer)
        ? null
        : inconsistencyAt(
            event, ViolationType.CONTENT_HASH_MISMATCH, "recomputed content_hash != stored");
  }

  /**
   * For every non-redacted leaf, recompute its commitment from the current plaintext + salt and
   * compare it to the stored commitment. Also catches leaves that were added or removed.
   */
  private VerificationReport.Inconsistency checkLeafCommitments(
      AuditEvent event,
      String payloadJson,
      String saltsJson,
      Map<String, String> storedCommitmentByPointer,
      Set<String> redactedPointers) {
    JsonNode payload = jsonCodec.parse(payloadJson);
    Map<String, String> saltByPointer = jsonCodec.readStringMap(saltsJson);
    Map<String, String> currentLeafByPointer = PayloadCommitments.canonicalLeavesByPointer(payload);

    for (Map.Entry<String, String> stored : storedCommitmentByPointer.entrySet()) {
      String pointer = stored.getKey();
      if (redactedPointers.contains(pointer)) {
        continue;
      }
      String currentLeaf = currentLeafByPointer.get(pointer);
      if (currentLeaf == null) {
        return inconsistencyAt(
            event,
            ViolationType.LEAF_COMMITMENT_MISMATCH,
            "payload leaf " + pointer + " is missing (structure changed)");
      }
      String salt = saltByPointer.get(pointer);
      if (salt == null) {
        return inconsistencyAt(
            event, ViolationType.MISSING_SALT, "no salt for payload leaf " + pointer);
      }
      if (!PayloadCommitments.computeLeafCommitment(salt, currentLeaf).equals(stored.getValue())) {
        return inconsistencyAt(
            event,
            ViolationType.LEAF_COMMITMENT_MISMATCH,
            "payload leaf " + pointer + " was modified");
      }
    }
    // any leaf present now but not in the stored commitment set => a field was added
    for (String pointer : currentLeafByPointer.keySet()) {
      if (!storedCommitmentByPointer.containsKey(pointer)) {
        return inconsistencyAt(
            event,
            ViolationType.LEAF_COMMITMENT_MISMATCH,
            "payload leaf " + pointer + " was added after the record was written");
      }
    }
    return null;
  }

  private boolean contentHashMatches(AuditEvent event, Map<String, String> commitmentByPointer) {
    String recomputedContentHash =
        auditHasher.contentHash(
            new AuditHasher.ContentHashInput(
                event.getSeq(),
                event.getEventId(),
                event.getEventType(),
                event.getActorId(),
                event.getResourceType(),
                event.getResourceId(),
                event.getEventTimestamp(),
                event.getRecordedAt(),
                commitmentByPointer));
    return recomputedContentHash.equals(event.getContentHash());
  }

  /** The record hash the verifier must see on the record just before {@code fromSeq}. */
  private String recordHashBefore(long fromSeq) {
    if (fromSeq <= 1) {
      return genesisHash;
    }
    return auditEvents
        .findById(fromSeq - 1)
        .map(AuditEvent::getRecordHash)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "cannot start verification at seq " + fromSeq + ": predecessor is missing"));
  }

  private static void closeArchivedRun(
      List<VerificationReport.ArchivedSegment> segments, Long runStartSeq, Long runEndSeq) {
    if (runStartSeq != null) {
      segments.add(new VerificationReport.ArchivedSegment(runStartSeq, runEndSeq));
    }
  }

  private static VerificationReport.Inconsistency inconsistencyAt(
      AuditEvent event, ViolationType type, String detail) {
    return new VerificationReport.Inconsistency(event.getSeq(), event.getEventId(), type, detail);
  }
}
