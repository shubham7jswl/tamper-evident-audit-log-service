package com.sj.audit.hash;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Computes the two hashes that make an audit record tamper-evident.
 *
 * <ul>
 *   <li><b>content hash</b> — {@code SHA-256} over the canonical JSON <i>hashable view</i> of a
 *       record: its core fields plus the map of per-leaf payload commitments. It fingerprints
 *       <i>what the record says</i>.
 *   <li><b>record hash</b> — {@code SHA-256("REC1" | previousRecordHash | contentHash)}. It is the
 *       link that chains a record to its predecessor; changing any earlier record changes every
 *       record hash after it.
 * </ul>
 *
 * <p>The string literals used to build the pre-image ({@code "v"}, {@code "seq"},
 * {@code "payloadLeafHashes"}, {@code "REC1"}, …) are a wire format frozen by
 * {@code CONTENT_HASH_VERSION} — never rename them without bumping the version.
 */
@Component
public class AuditHasher {

  static final int CONTENT_HASH_VERSION = 1;
  static final String RECORD_HASH_DOMAIN = "REC1";

  private final ObjectMapper objectMapper;
  private final SecureRandom secureRandom = new SecureRandom();

  public AuditHasher(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  /** The fields of a record that are fed into its content hash. */
  public record ContentHashInput(
      long seq,
      UUID eventId,
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      Instant eventTimestamp,
      Instant recordedAt,
      Map<String, String> leafCommitmentsByPointer) {}

  public String contentHash(ContentHashInput input) {
    ObjectNode hashableView = objectMapper.createObjectNode();
    hashableView.put("v", CONTENT_HASH_VERSION);
    hashableView.put("seq", input.seq());
    hashableView.put("eventId", input.eventId().toString());
    hashableView.put("eventType", input.eventType());
    hashableView.put("actorId", input.actorId());
    hashableView.put("resourceType", input.resourceType());
    hashableView.put("resourceId", input.resourceId());
    hashableView.put("eventTimestamp", Instants.canonical(input.eventTimestamp()));
    hashableView.put("recordedAt", Instants.canonical(input.recordedAt()));
    ObjectNode payloadLeafHashes = hashableView.putObject("payloadLeafHashes");
    input.leafCommitmentsByPointer().forEach(payloadLeafHashes::put);
    return Hashing.sha256Hex(CanonicalJson.canonicalize(hashableView));
  }

  public String recordHash(String previousRecordHash, String contentHash) {
    return Hashing.domainHashHex(RECORD_HASH_DOMAIN, previousRecordHash, contentHash);
  }

  /** A fresh random 128-bit hex salt for every payload leaf, keyed by its JSON Pointer. */
  public Map<String, String> newSaltPerLeaf(JsonNode payload) {
    Map<String, String> saltByPointer = new LinkedHashMap<>();
    for (String pointer : PayloadCommitments.canonicalLeavesByPointer(payload).keySet()) {
      byte[] saltBytes = new byte[16];
      secureRandom.nextBytes(saltBytes);
      saltByPointer.put(pointer, Hex.encode(saltBytes));
    }
    return saltByPointer;
  }

  /**
   * Compute the commitment for every payload leaf from the payload and its salt map. Throws if a
   * leaf has no salt — that would mean the stored salt map has been corrupted.
   */
  public Map<String, String> computeLeafCommitments(
      JsonNode payload, Map<String, String> saltByPointer) {
    Map<String, String> commitmentByPointer = new LinkedHashMap<>();
    PayloadCommitments.canonicalLeavesByPointer(payload)
        .forEach(
            (pointer, canonicalLeaf) -> {
              String salt = saltByPointer.get(pointer);
              if (salt == null) {
                throw new IllegalArgumentException("no salt for payload leaf " + pointer);
              }
              commitmentByPointer.put(
                  pointer, PayloadCommitments.computeLeafCommitment(salt, canonicalLeaf));
            });
    return commitmentByPointer;
  }
}
