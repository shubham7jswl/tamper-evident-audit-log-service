package com.sj.audit.hash;

import static org.assertj.core.api.Assertions.assertThat;

import com.sj.audit.utils.hash.CanonicalJson;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class CanonicalJsonTest {

  private final JsonMapper mapper = JsonMapper.builder().build();

  private String canon(String json) {
    return CanonicalJson.canonicalize(mapper.readTree(json));
  }

  @Test
  void sortsObjectKeysAndDropsWhitespace() {
    assertThat(canon("{ \"b\": 1, \"a\": 2 }")).isEqualTo("{\"a\":2,\"b\":1}");
  }

  @Test
  void isStableRegardlessOfInputKeyOrder() {
    assertThat(canon("{\"z\":{\"y\":1,\"x\":2},\"a\":[3,2,1]}"))
        .isEqualTo(canon("{\"a\":[3,2,1],\"z\":{\"x\":2,\"y\":1}}"));
  }

  @Test
  void preservesArrayOrder() {
    assertThat(canon("[3,1,2]")).isEqualTo("[3,1,2]");
  }

  @Test
  void normalizesNumbers() {
    assertThat(canon("{\"a\":1.50,\"b\":10,\"c\":0.0,\"d\":-2.000}"))
        .isEqualTo("{\"a\":1.5,\"b\":10,\"c\":0,\"d\":-2}");
  }

  @Test
  void escapesControlCharactersAndQuotes() {
    assertThat(canon("{\"k\":\"a\\\"b\\nc\"}")).isEqualTo("{\"k\":\"a\\\"b\\nc\"}");
  }

  @Test
  void keepsUnicodeLiteral() {
    assertThat(canon("{\"k\":\"café\"}")).isEqualTo("{\"k\":\"café\"}");
  }
}
