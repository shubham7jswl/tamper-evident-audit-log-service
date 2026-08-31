package com.sj.audit.utils;

import com.sj.audit.domain.export.ExportBundle;
import com.sj.audit.utils.hash.AuditHasher;
import com.sj.audit.utils.hash.CanonicalJson;
import com.sj.audit.utils.hash.Hashing;
import com.sj.audit.utils.hash.Instants;
import com.sj.audit.utils.hash.PayloadCommitments;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Standalone verification of an {@link ExportBundle}. Deliberately free of Spring so a recipient can
 * run it with only this class, the {@code com.sj.audit.hash} package and Jackson on the classpath.
 *
 * <p>Checks, in order: bundle hash, optional HMAC, then per record — non-redacted leaf commitments,
 * content hash, record hash — then per segment the {@code prevHash -> recordHash} linkage.
 */
public final class BundleVerifier {

  private BundleVerifier() {}

  public record Result(boolean valid, List<String> problems) {}

  public static Result verify(ExportBundle bundle, String hmacSecretOrNull) {
    ObjectMapper objectMapper = JsonMapper.builder().build();
    AuditHasher auditHasher = new AuditHasher(objectMapper);
    List<String> problems = new ArrayList<>();

    ObjectNode bundleWithoutIntegrity = (ObjectNode) objectMapper.valueToTree(bundle);
    bundleWithoutIntegrity.remove("bundleHash");
    bundleWithoutIntegrity.remove("hmac");
    String recomputedBundleHash =
        Hashing.sha256Hex(CanonicalJson.canonicalize(bundleWithoutIntegrity));
    if (!recomputedBundleHash.equals(bundle.bundleHash())) {
      problems.add("bundle hash mismatch");
    }
    if (bundle.hmac() != null && hmacSecretOrNull != null) {
      String expectedHmac =
          Hashing.hmacSha256Hex(
              hmacSecretOrNull, bundle.bundleHash().getBytes(StandardCharsets.UTF_8));
      if (!expectedHmac.equals(bundle.hmac())) {
        problems.add("hmac mismatch");
      }
    }

    Map<Long, ExportBundle.Record> recordBySeq = new HashMap<>();
    for (ExportBundle.Record record : bundle.records()) {
      recordBySeq.put(record.seq(), record);
      verifyRecord(auditHasher, record, problems);
    }

    for (ExportBundle.Segment segment : bundle.segments()) {
      String previousRecordHash = segment.priorRecordHash();
      for (long seq = segment.fromSeq(); seq <= segment.toSeq(); seq++) {
        ExportBundle.Record record = recordBySeq.get(seq);
        if (record == null) {
          problems.add("segment record missing: seq " + seq);
          break;
        }
        if (!record.prevHash().equals(previousRecordHash)) {
          problems.add("broken chain link at seq " + seq);
        }
        previousRecordHash = record.recordHash();
      }
    }
    return new Result(problems.isEmpty(), List.copyOf(problems));
  }

  private static void verifyRecord(
      AuditHasher auditHasher, ExportBundle.Record record, List<String> problems) {
    Map<String, String> storedCommitmentByPointer = record.leafCommitments();

    if (record.payload() != null) {
      Map<String, String> currentLeafByPointer =
          PayloadCommitments.canonicalLeavesByPointer(record.payload());
      for (Map.Entry<String, String> stored : storedCommitmentByPointer.entrySet()) {
        String pointer = stored.getKey();
        if (record.redactedPaths().contains(pointer)) {
          continue;
        }
        String currentLeaf = currentLeafByPointer.get(pointer);
        String salt = record.leafSalts().get(pointer);
        if (currentLeaf == null || salt == null) {
          problems.add("cannot verify leaf " + pointer + " at seq " + record.seq());
          continue;
        }
        if (!PayloadCommitments.computeLeafCommitment(salt, currentLeaf).equals(stored.getValue())) {
          problems.add("leaf " + pointer + " modified at seq " + record.seq());
        }
      }
    }

    String recomputedContentHash =
        auditHasher.contentHash(
            new AuditHasher.ContentHashInput(
                record.seq(),
                UUID.fromString(record.eventId()),
                record.eventType(),
                record.actorId(),
                record.resourceType(),
                record.resourceId(),
                Instants.parse(record.eventTimestamp()),
                Instants.parse(record.recordedAt()),
                storedCommitmentByPointer));
    if (!recomputedContentHash.equals(record.contentHash())) {
      problems.add("content hash mismatch at seq " + record.seq());
    }
    if (!auditHasher.recordHash(record.prevHash(), record.contentHash()).equals(record.recordHash())) {
      problems.add("record hash mismatch at seq " + record.seq());
    }
  }

  /** Convenience for callers holding raw JSON. */
  public static Result verifyJson(String bundleJson, String hmacSecretOrNull) {
    ExportBundle bundle = JsonMapper.builder().build().readValue(bundleJson, ExportBundle.class);
    return verify(bundle, hmacSecretOrNull);
  }
}
