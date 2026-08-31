package com.sj.audit.hash;

import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * Turns an event payload into a map of <b>per-leaf salted commitments</b> — the mechanism that lets
 * us redact individual payload fields later without invalidating the hash chain.
 *
 * <p>A <i>leaf</i> is any JSON value (string / number / boolean / null) and, so that structure is
 * also committed, any <em>empty</em> object or array. Non-empty containers are represented
 * implicitly by the set of leaf pointers beneath them: adding, removing or reordering payload
 * elements changes that set, and therefore the content hash.
 *
 * <p>Each leaf is first turned into a short deterministic string — its <i>canonical leaf</i> — of
 * the form {@code typeTag + canonicalValue} (e.g. {@code "S4111"}, {@code "N10.5"}, {@code "Btrue"},
 * {@code "Z"} for null, {@code "E{}"} for an empty object). The commitment is then
 *
 * <pre>commitment = SHA-256("LEAF1" | saltHex | canonicalLeaf)</pre>
 *
 * The random per-leaf salt makes commitments over low-entropy values (account numbers, SSNs)
 * resistant to brute-force/dictionary recovery once the plaintext has been redacted.
 */
public final class PayloadCommitments {

  private static final String LEAF_COMMITMENT_DOMAIN = "LEAF1";

  private PayloadCommitments() {}

  /** Ordered map of JSON Pointer -&gt; canonical leaf, one entry per leaf in {@code payload}. */
  public static Map<String, String> canonicalLeavesByPointer(JsonNode payload) {
    Map<String, String> canonicalLeafByPointer = new LinkedHashMap<>();
    collectLeaves("", payload, canonicalLeafByPointer);
    return canonicalLeafByPointer;
  }

  /** The salted commitment for a single leaf, given its hex salt and its canonical-leaf string. */
  public static String computeLeafCommitment(String saltHex, String canonicalLeaf) {
    return Hashing.domainHashHex(LEAF_COMMITMENT_DOMAIN, saltHex, canonicalLeaf);
  }

  private static void collectLeaves(
      String pointer, JsonNode node, Map<String, String> canonicalLeafByPointer) {
    switch (node.getNodeType()) {
      case OBJECT -> {
        if (node.isEmpty()) {
          canonicalLeafByPointer.put(pointer, "E{}");
          return;
        }
        node.properties()
            .forEach(
                field ->
                    collectLeaves(
                        pointer + "/" + escapeToken(field.getKey()),
                        field.getValue(),
                        canonicalLeafByPointer));
      }
      case ARRAY -> {
        if (node.isEmpty()) {
          canonicalLeafByPointer.put(pointer, "E[]");
          return;
        }
        for (int index = 0; index < node.size(); index++) {
          collectLeaves(pointer + "/" + index, node.get(index), canonicalLeafByPointer);
        }
      }
      case STRING -> canonicalLeafByPointer.put(pointer, "S" + node.textValue());
      case NUMBER -> canonicalLeafByPointer.put(pointer, "N" + CanonicalJson.canonicalNumber(node));
      case BOOLEAN ->
          canonicalLeafByPointer.put(pointer, "B" + (node.booleanValue() ? "true" : "false"));
      case NULL -> canonicalLeafByPointer.put(pointer, "Z");
      default ->
          throw new IllegalArgumentException("unsupported payload node: " + node.getNodeType());
    }
  }

  /** RFC 6901 reference-token escaping ({@code ~} -&gt; {@code ~0}, {@code /} -&gt; {@code ~1}). */
  private static String escapeToken(String token) {
    return token.replace("~", "~0").replace("/", "~1");
  }
}
