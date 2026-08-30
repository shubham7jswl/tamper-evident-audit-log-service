package com.sj.audit.export;

import com.sj.audit.hash.AuditHasher;
import com.sj.audit.hash.CanonicalJson;
import com.sj.audit.hash.Hashing;
import com.sj.audit.hash.Instants;
import com.sj.audit.hash.PayloadCommitments;
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
    ObjectMapper mapper = JsonMapper.builder().build();
    AuditHasher hasher = new AuditHasher(mapper);
    List<String> problems = new ArrayList<>();

    ObjectNode tree = (ObjectNode) mapper.valueToTree(bundle);
    tree.remove("bundleHash");
    tree.remove("hmac");
    String recomputedBundleHash = Hashing.sha256Hex(CanonicalJson.canonicalize(tree));
    if (!recomputedBundleHash.equals(bundle.bundleHash())) {
      problems.add("bundle hash mismatch");
    }
    if (bundle.hmac() != null && hmacSecretOrNull != null) {
      String expected =
          Hashing.hmacSha256Hex(
              hmacSecretOrNull, bundle.bundleHash().getBytes(StandardCharsets.UTF_8));
      if (!expected.equals(bundle.hmac())) {
        problems.add("hmac mismatch");
      }
    }

    Map<Long, ExportBundle.Record> bySeq = new HashMap<>();
    for (ExportBundle.Record r : bundle.records()) {
      bySeq.put(r.seq(), r);
      verifyRecord(hasher, r, problems);
    }

    for (ExportBundle.Segment segment : bundle.segments()) {
      String prev = segment.priorRecordHash();
      for (long seq = segment.fromSeq(); seq <= segment.toSeq(); seq++) {
        ExportBundle.Record r = bySeq.get(seq);
        if (r == null) {
          problems.add("segment record missing: seq " + seq);
          break;
        }
        if (!r.prevHash().equals(prev)) {
          problems.add("broken chain link at seq " + seq);
        }
        prev = r.recordHash();
      }
    }
    return new Result(problems.isEmpty(), List.copyOf(problems));
  }

  private static void verifyRecord(
      AuditHasher hasher, ExportBundle.Record r, List<String> problems) {
    Map<String, String> commitments = r.leafCommitments();

    if (r.payload() != null) {
      Map<String, String> forms = PayloadCommitments.leafForms(r.payload());
      for (Map.Entry<String, String> entry : commitments.entrySet()) {
        String path = entry.getKey();
        if (r.redactedPaths().contains(path)) {
          continue;
        }
        String form = forms.get(path);
        String salt = r.leafSalts().get(path);
        if (form == null || salt == null) {
          problems.add("cannot verify leaf " + path + " at seq " + r.seq());
          continue;
        }
        if (!PayloadCommitments.commit(salt, form).equals(entry.getValue())) {
          problems.add("leaf " + path + " modified at seq " + r.seq());
        }
      }
    }

    String contentHash =
        hasher.contentHash(
            new AuditHasher.HashInputs(
                r.seq(),
                UUID.fromString(r.eventId()),
                r.eventType(),
                r.actorId(),
                r.resourceType(),
                r.resourceId(),
                Instants.parse(r.eventTimestamp()),
                Instants.parse(r.recordedAt()),
                commitments));
    if (!contentHash.equals(r.contentHash())) {
      problems.add("content hash mismatch at seq " + r.seq());
    }
    if (!hasher.recordHash(r.prevHash(), r.contentHash()).equals(r.recordHash())) {
      problems.add("record hash mismatch at seq " + r.seq());
    }
  }

  /** Convenience for callers holding raw JSON. */
  public static Result verifyJson(String bundleJson, String hmacSecretOrNull) {
    ExportBundle bundle = JsonMapper.builder().build().readValue(bundleJson, ExportBundle.class);
    return verify(bundle, hmacSecretOrNull);
  }
}
