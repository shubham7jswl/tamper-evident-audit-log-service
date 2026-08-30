package com.sj.audit.hash;

import tools.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns an event payload into a map of <b>per-leaf salted commitments</b> — the mechanism that lets
 * us redact individual payload fields later without invalidating the hash chain.
 *
 * <p>A "leaf" is any JSON value (string / number / boolean / null) and, so that structure is also
 * committed, any <em>empty</em> object or array. Non-empty containers are represented implicitly by
 * the set of leaf pointers beneath them: adding, removing or reordering payload elements changes
 * that set and therefore the content hash.
 *
 * <p>Commitment formula (see {@link Hashing#domainHashHex}):
 *
 * <pre>commitment = SHA-256("LEAF1" | saltHex | leafTag+canonicalValue)</pre>
 *
 * The random per-leaf salt makes commitments over low-entropy values (account numbers, SSNs)
 * resistant to brute-force/dictionary recovery once the plaintext is redacted.
 */
public final class PayloadCommitments {

  private static final String DOMAIN = "LEAF1";

  private PayloadCommitments() {}

  /** Ordered map of JSON Pointer -> canonical leaf form ({@code tag + value}). */
  public static Map<String, String> leafForms(JsonNode payload) {
    Map<String, String> out = new LinkedHashMap<>();
    walk("", payload, out);
    return out;
  }

  /** Compute the commitment for one leaf given its hex salt and canonical leaf form. */
  public static String commit(String saltHex, String leafForm) {
    return Hashing.domainHashHex(DOMAIN, saltHex, leafForm);
  }

  private static void walk(String pointer, JsonNode node, Map<String, String> out) {
    switch (node.getNodeType()) {
      case OBJECT -> {
        if (node.isEmpty()) {
          out.put(pointer, "E{}");
          return;
        }
        node.properties()
            .forEach(e -> walk(pointer + "/" + escape(e.getKey()), e.getValue(), out));
      }
      case ARRAY -> {
        if (node.isEmpty()) {
          out.put(pointer, "E[]");
          return;
        }
        for (int i = 0; i < node.size(); i++) {
          walk(pointer + "/" + i, node.get(i), out);
        }
      }
      case STRING -> out.put(pointer, "S" + node.textValue());
      case NUMBER -> out.put(pointer, "N" + CanonicalJson.canonicalNumber(node));
      case BOOLEAN -> out.put(pointer, "B" + (node.booleanValue() ? "true" : "false"));
      case NULL -> out.put(pointer, "Z");
      default -> throw new IllegalArgumentException("unsupported payload node: " + node.getNodeType());
    }
  }

  /** RFC 6901 reference-token escaping. */
  private static String escape(String token) {
    return token.replace("~", "~0").replace("/", "~1");
  }
}
