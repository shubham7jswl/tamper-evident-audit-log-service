package com.sj.audit.config;

import tools.jackson.core.type.TypeReference;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Thin helper around the shared {@link ObjectMapper} for the JSON-in-a-column fields. */
@Component
public class JsonSupport {

  private static final TypeReference<LinkedHashMap<String, String>> STRING_MAP =
      new TypeReference<>() {};

  private final ObjectMapper mapper;

  public JsonSupport(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  public JsonNode parse(String json) {
    return mapper.readTree(json);
  }

  public String write(Object value) {
    return mapper.writeValueAsString(value);
  }

  public ObjectNode newObject() {
    return mapper.createObjectNode();
  }

  public JsonNode toTree(Object value) {
    return mapper.valueToTree(value);
  }

  public Map<String, String> readStringMap(String json) {
    if (json == null) {
      return new LinkedHashMap<>();
    }
    return mapper.readValue(json, STRING_MAP);
  }

  public String writeStringMap(Map<String, String> map) {
    return mapper.writeValueAsString(map);
  }
}
