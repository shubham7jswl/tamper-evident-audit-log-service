package com.sj.audit.hash;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Computes the two hashes that make a record tamper-evident:
 *
 * <ul>
 *   <li><b>content hash</b> — SHA-256 over the canonical JSON "hashable view" of the record: its
 *       core fields plus the map of per-leaf payload commitments;
 *   <li><b>record hash</b> — {@code SHA-256("REC1" | prevRecordHash | contentHash)}, the link that
 *       chains this record to its predecessor.
 * </ul>
 */
@Component
public class AuditHasher {

  static final int CONTENT_HASH_VERSION = 1;
  static final String RECORD_DOMAIN = "REC1";

  private final ObjectMapper mapper;
  private final SecureRandom random = new SecureRandom();

  public AuditHasher(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  public record HashInputs(
      long seq,
      UUID eventId,
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      Instant eventTimestamp,
      Instant recordedAt,
      Map<String, String> leafCommitments) {}

  public String contentHash(HashInputs in) {
    ObjectNode view = mapper.createObjectNode();
    view.put("v", CONTENT_HASH_VERSION);
    view.put("seq", in.seq());
    view.put("eventId", in.eventId().toString());
    view.put("eventType", in.eventType());
    view.put("actorId", in.actorId());
    view.put("resourceType", in.resourceType());
    view.put("resourceId", in.resourceId());
    view.put("eventTimestamp", Instants.canonical(in.eventTimestamp()));
    view.put("recordedAt", Instants.canonical(in.recordedAt()));
    ObjectNode commits = view.putObject("payloadLeafHashes");
    in.leafCommitments().forEach(commits::put);
    return Hashing.sha256Hex(CanonicalJson.canonicalize(view));
  }

  public String recordHash(String prevRecordHash, String contentHash) {
    return Hashing.domainHashHex(RECORD_DOMAIN, prevRecordHash, contentHash);
  }

  /** Fresh 128-bit hex salt per payload leaf, keyed by JSON Pointer. */
  public Map<String, String> freshSalts(JsonNode payload) {
    Map<String, String> salts = new LinkedHashMap<>();
    for (String pointer : PayloadCommitments.leafForms(payload).keySet()) {
      byte[] b = new byte[16];
      random.nextBytes(b);
      salts.put(pointer, Hex.encode(b));
    }
    return salts;
  }

  /**
   * Recompute every leaf commitment from a payload and its salt map. Throws if a leaf has no salt
   * (which would indicate corruption of the stored salt map).
   */
  public Map<String, String> commitmentsFor(JsonNode payload, Map<String, String> saltsByPointer) {
    Map<String, String> out = new LinkedHashMap<>();
    PayloadCommitments.leafForms(payload)
        .forEach(
            (pointer, form) -> {
              String salt = saltsByPointer.get(pointer);
              if (salt == null) {
                throw new IllegalArgumentException("no salt for payload leaf " + pointer);
              }
              out.put(pointer, PayloadCommitments.commit(salt, form));
            });
    return out;
  }
}
