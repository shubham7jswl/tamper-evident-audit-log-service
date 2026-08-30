package com.sj.audit.hash;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class PayloadCommitmentsTest {

  private final JsonMapper mapper = JsonMapper.builder().build();

  @Test
  void enumeratesLeavesWithJsonPointerPaths() {
    Map<String, String> forms =
        PayloadCommitments.leafForms(
            mapper.readTree(
                "{\"amount\":10,\"account\":{\"number\":\"123\"},\"tags\":[\"a\",\"b\"],\"empty\":{}}"));

    assertThat(forms)
        .containsEntry("/amount", "N10")
        .containsEntry("/account/number", "S123")
        .containsEntry("/tags/0", "Sa")
        .containsEntry("/tags/1", "Sb")
        .containsEntry("/empty", "E{}");
  }

  @Test
  void commitmentChangesWithSaltAndValue() {
    String form = "S123456789";
    String c1 = PayloadCommitments.commit("aa", form);
    String c2 = PayloadCommitments.commit("bb", form);
    String c3 = PayloadCommitments.commit("aa", "S987654321");

    assertThat(c1).hasSize(64).isNotEqualTo(c2).isNotEqualTo(c3);
    assertThat(PayloadCommitments.commit("aa", form)).isEqualTo(c1);
  }

  @Test
  void escapesSlashAndTildeInKeys() {
    Map<String, String> forms =
        PayloadCommitments.leafForms(mapper.readTree("{\"a/b\":1,\"c~d\":2}"));
    assertThat(forms).containsKeys("/a~1b", "/c~0d");
  }
}
