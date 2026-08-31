package com.sj.audit.hash;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class PayloadCommitmentsTest {

  private final JsonMapper mapper = JsonMapper.builder().build();

  @Test
  void enumeratesLeavesWithJsonPointerPaths() {
    Map<String, String> canonicalLeafByPointer =
        PayloadCommitments.canonicalLeavesByPointer(
            mapper.readTree(
                "{\"amount\":10,\"account\":{\"number\":\"123\"},\"tags\":[\"a\",\"b\"],\"empty\":{}}"));

    assertThat(canonicalLeafByPointer)
        .containsEntry("/amount", "N10")
        .containsEntry("/account/number", "S123")
        .containsEntry("/tags/0", "Sa")
        .containsEntry("/tags/1", "Sb")
        .containsEntry("/empty", "E{}");
  }

  @Test
  void commitmentChangesWithSaltAndValue() {
    String canonicalLeaf = "S123456789";
    String commitment = PayloadCommitments.computeLeafCommitment("aa", canonicalLeaf);
    String differentSalt = PayloadCommitments.computeLeafCommitment("bb", canonicalLeaf);
    String differentValue = PayloadCommitments.computeLeafCommitment("aa", "S987654321");

    assertThat(commitment).hasSize(64).isNotEqualTo(differentSalt).isNotEqualTo(differentValue);
    assertThat(PayloadCommitments.computeLeafCommitment("aa", canonicalLeaf)).isEqualTo(commitment);
  }

  @Test
  void escapesSlashAndTildeInKeys() {
    Map<String, String> canonicalLeafByPointer =
        PayloadCommitments.canonicalLeavesByPointer(mapper.readTree("{\"a/b\":1,\"c~d\":2}"));
    assertThat(canonicalLeafByPointer).containsKeys("/a~1b", "/c~0d");
  }
}
