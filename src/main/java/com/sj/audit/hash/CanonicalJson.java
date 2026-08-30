package com.sj.audit.hash;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic ("canonical") JSON serialization used as the pre-image for every hash in the
 * service. Two structurally-equal JSON values always serialize to the exact same bytes.
 *
 * <p>Rules:
 *
 * <ul>
 *   <li>object member names sorted by Unicode code point, no whitespace;
 *   <li>numbers normalized (integers without a decimal point/exponent; decimals via {@link
 *       BigDecimal#toPlainString()} with trailing zeros stripped);
 *   <li>strings emitted as UTF-8 with only the mandatory JSON escapes.
 * </ul>
 *
 * <p>Known limitation: this is close to but not RFC 8785 (JCS) — in particular it does not
 * reproduce ECMAScript {@code Number.prototype.toString} for exotic floating-point values. Callers
 * that need exact reproducibility of sensitive numeric data should send it as a string or an
 * integer. Documented in {@code docs/decisions/ADR-0002-chain-construction.md}.
 */
public final class CanonicalJson {

  private CanonicalJson() {}

  public static String canonicalize(JsonNode node) {
    StringBuilder sb = new StringBuilder();
    write(node, sb);
    return sb.toString();
  }

  private static void write(JsonNode node, StringBuilder sb) {
    if (node == null || node.isNull() || node.isMissingNode()) {
      sb.append("null");
      return;
    }
    switch (node.getNodeType()) {
      case OBJECT -> writeObject((ObjectNode) node, sb);
      case ARRAY -> {
        sb.append('[');
        for (int i = 0; i < node.size(); i++) {
          if (i > 0) {
            sb.append(',');
          }
          write(node.get(i), sb);
        }
        sb.append(']');
      }
      case STRING -> writeString(node.textValue(), sb);
      case NUMBER -> sb.append(canonicalNumber(node));
      case BOOLEAN -> sb.append(node.booleanValue() ? "true" : "false");
      default -> throw new IllegalArgumentException("unsupported JSON node type: " + node.getNodeType());
    }
  }

  private static void writeObject(ObjectNode obj, StringBuilder sb) {
    List<String> names = new ArrayList<>();
    obj.properties().forEach(e -> names.add(e.getKey()));
    names.sort(CanonicalJson::compareByCodePoint);
    sb.append('{');
    for (int i = 0; i < names.size(); i++) {
      if (i > 0) {
        sb.append(',');
      }
      writeString(names.get(i), sb);
      sb.append(':');
      write(obj.get(names.get(i)), sb);
    }
    sb.append('}');
  }

  static String canonicalNumber(JsonNode n) {
    if (n.isIntegralNumber()) {
      return n.bigIntegerValue().toString();
    }
    BigDecimal d = n.decimalValue();
    if (d.signum() == 0) {
      return "0";
    }
    d = d.stripTrailingZeros();
    if (d.scale() < 0) {
      d = d.setScale(0);
    }
    return d.toPlainString();
  }

  static void writeString(String s, StringBuilder sb) {
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\b' -> sb.append("\\b");
        case '\f' -> sb.append("\\f");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    sb.append('"');
  }

  static int compareByCodePoint(String a, String b) {
    int i = 0;
    int j = 0;
    while (i < a.length() && j < b.length()) {
      int ca = a.codePointAt(i);
      int cb = b.codePointAt(j);
      if (ca != cb) {
        return Integer.compare(ca, cb);
      }
      i += Character.charCount(ca);
      j += Character.charCount(cb);
    }
    return Integer.compare(a.length() - i, b.length() - j);
  }
}
