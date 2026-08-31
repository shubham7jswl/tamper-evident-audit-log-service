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
    StringBuilder out = new StringBuilder();
    write(node, out);
    return out.toString();
  }

  private static void write(JsonNode node, StringBuilder out) {
    if (node == null || node.isNull() || node.isMissingNode()) {
      out.append("null");
      return;
    }
    switch (node.getNodeType()) {
      case OBJECT -> writeObject((ObjectNode) node, out);
      case ARRAY -> {
        out.append('[');
        for (int i = 0; i < node.size(); i++) {
          if (i > 0) {
            out.append(',');
          }
          write(node.get(i), out);
        }
        out.append(']');
      }
      case STRING -> writeString(node.textValue(), out);
      case NUMBER -> out.append(canonicalNumber(node));
      case BOOLEAN -> out.append(node.booleanValue() ? "true" : "false");
      default -> throw new IllegalArgumentException("unsupported JSON node type: " + node.getNodeType());
    }
  }

  private static void writeObject(ObjectNode object, StringBuilder out) {
    List<String> names = new ArrayList<>();
    object.properties().forEach(e -> names.add(e.getKey()));
    names.sort(CanonicalJson::compareByCodePoint);
    out.append('{');
    for (int i = 0; i < names.size(); i++) {
      if (i > 0) {
        out.append(',');
      }
      writeString(names.get(i), out);
      out.append(':');
      write(object.get(names.get(i)), out);
    }
    out.append('}');
  }

  static String canonicalNumber(JsonNode node) {
    if (node.isIntegralNumber()) {
      return node.bigIntegerValue().toString();
    }
    BigDecimal decimal = node.decimalValue();
    if (decimal.signum() == 0) {
      return "0";
    }
    decimal = decimal.stripTrailingZeros();
    if (decimal.scale() < 0) {
      decimal = decimal.setScale(0);
    }
    return decimal.toPlainString();
  }

  static void writeString(String text, StringBuilder out) {
    out.append('"');
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
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
