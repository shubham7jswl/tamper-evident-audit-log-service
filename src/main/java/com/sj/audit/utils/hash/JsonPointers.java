package com.sj.audit.utils.hash;

import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

/** Minimal RFC 6901 JSON Pointer helpers for navigating/mutating payload trees. */
public final class JsonPointers {

  private JsonPointers() {}

  public static List<String> tokens(String pointer) {
    List<String> out = new ArrayList<>();
    if (pointer == null || pointer.isEmpty()) {
      return out;
    }
    if (pointer.charAt(0) != '/') {
      throw new IllegalArgumentException("not a JSON Pointer: " + pointer);
    }
    for (String raw : pointer.substring(1).split("/", -1)) {
      out.add(raw.replace("~1", "/").replace("~0", "~"));
    }
    return out;
  }

  /** True if the pointer resolves to an existing value node in {@code root}. */
  public static boolean resolves(JsonNode root, String pointer) {
    JsonNode node = root;
    for (String token : tokens(pointer)) {
      if (node instanceof ObjectNode obj) {
        node = obj.get(token);
      } else if (node instanceof ArrayNode arr) {
        node = arr.get(parseIndex(token));
      } else {
        return false;
      }
      if (node == null) {
        return false;
      }
    }
    return true;
  }

  /** Replace the leaf at {@code pointer} with a string value. Throws if the path does not resolve. */
  public static void setStringLeaf(JsonNode root, String pointer, String value) {
    List<String> tokens = tokens(pointer);
    if (tokens.isEmpty()) {
      throw new IllegalArgumentException("cannot replace the document root");
    }
    JsonNode parent = root;
    for (int i = 0; i < tokens.size() - 1; i++) {
      String token = tokens.get(i);
      parent =
          parent instanceof ArrayNode arr
              ? arr.get(parseIndex(token))
              : ((ObjectNode) parent).get(token);
      if (parent == null) {
        throw new IllegalArgumentException("JSON Pointer does not resolve: " + pointer);
      }
    }
    String last = tokens.get(tokens.size() - 1);
    if (parent instanceof ObjectNode obj) {
      if (!obj.has(last)) {
        throw new IllegalArgumentException("JSON Pointer does not resolve: " + pointer);
      }
      obj.set(last, StringNode.valueOf(value));
    } else if (parent instanceof ArrayNode arr) {
      int idx = parseIndex(last);
      if (idx < 0 || idx >= arr.size()) {
        throw new IllegalArgumentException("JSON Pointer index out of range: " + pointer);
      }
      arr.set(idx, StringNode.valueOf(value));
    } else {
      throw new IllegalArgumentException("JSON Pointer parent is not a container: " + pointer);
    }
  }

  private static int parseIndex(String token) {
    try {
      return Integer.parseInt(token);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("expected array index, got '" + token + "'");
    }
  }
}
