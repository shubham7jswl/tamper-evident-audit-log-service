package com.sj.audit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.chain.VerificationReport;
import com.sj.audit.repository.AuditEventRepository;
import com.sj.audit.support.AbstractIntegrationTest;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Exercises the {@code chain_head} single-writer lock (ADR-0003) under real thread contention:
 * many threads append at once and the chain must stay totally ordered, gap-free and verifiable.
 *
 * <p>Thread count is kept at/under the HikariCP default pool size so each concurrent
 * {@code @Transactional} append can hold its own connection.
 */
class ChainAppenderConcurrencyIT extends AbstractIntegrationTest {

  private static final int THREADS = 8;
  private static final int APPENDS_PER_THREAD = 8;
  private static final int TOTAL = THREADS * APPENDS_PER_THREAD;

  @Autowired ChainVerifier verifier;
  @Autowired AuditEventRepository auditEvents;

  @Test
  void concurrentAppendsProduceAGapFreeVerifiableChain() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    CountDownLatch startGate = new CountDownLatch(1);
    try {
      List<Future<Object>> futures =
          IntStream.range(0, THREADS)
              .mapToObj(
                  threadIndex ->
                      pool.submit(
                          () -> {
                            startGate.await();
                            for (int i = 0; i < APPENDS_PER_THREAD; i++) {
                              appender.append(
                                  event(
                                      "CONCURRENT_APPEND",
                                      "writer-" + threadIndex,
                                      "acct-" + threadIndex,
                                      "{\"i\":" + i + "}"));
                            }
                            return null;
                          }))
              .toList();

      startGate.countDown();
      for (Future<Object> future : futures) {
        // Surfaces any exception thrown inside a worker (lock timeout, deadlock, constraint).
        assertThatCode(() -> future.get(30, TimeUnit.SECONDS)).doesNotThrowAnyException();
      }
    } finally {
      pool.shutdownNow();
    }

    List<Long> seqs = auditEvents.findAll().stream().map(AuditEvent::getSeq).sorted().toList();
    assertThat(seqs)
        .as("every append persisted exactly one row with a unique, gap-free seq")
        .containsExactlyElementsOf(LongStream.rangeClosed(1, TOTAL).boxed().toList());

    Long headSeq = jdbc.queryForObject("SELECT last_seq FROM chain_head", Long.class);
    assertThat(headSeq).as("chain head advanced to the last append").isEqualTo((long) TOTAL);

    VerificationReport report = verifier.verify(null, null, false);
    assertThat(report.intact()).as("hash links hold across all concurrent appends").isTrue();
    assertThat(report.recordsChecked()).isEqualTo(TOTAL);
  }
}
