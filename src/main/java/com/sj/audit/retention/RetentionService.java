package com.sj.audit.retention;

import com.sj.audit.config.AuditProperties;
import com.sj.audit.domain.ArchivedAuditEvent;
import com.sj.audit.domain.ArchivedAuditEventRepository;
import com.sj.audit.domain.AuditEvent;
import com.sj.audit.domain.AuditEventRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Retention: records older than {@code audit.retention.window} are moved to
 * {@code archived_audit_event} and the live row becomes a <b>tombstone</b> — payload and salts
 * dropped, every hash column kept. The row is never deleted, so {@code seq} stays gap-free and
 * chain verification does not see a false break; the retained {@code content_hash} is still bound
 * into {@code record_hash}.
 */
@Service
public class RetentionService {

  private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

  private final AuditEventRepository events;
  private final ArchivedAuditEventRepository archive;
  private final AuditProperties properties;
  private final Clock clock;

  public RetentionService(
      AuditEventRepository events,
      ArchivedAuditEventRepository archive,
      AuditProperties properties,
      Clock clock) {
    this.events = events;
    this.archive = archive;
    this.properties = properties;
    this.clock = clock;
  }

  public record RetentionResult(int archivedCount, long throughSeq, Instant cutoff) {}

  @Transactional
  public RetentionResult run() {
    if (!properties.retention().enabled()) {
      throw new IllegalStateException("retention is disabled (audit.retention.enabled=false)");
    }
    Instant now = clock.instant();
    Instant cutoff = now.minus(properties.retention().window());
    List<AuditEvent> due =
        events.findByArchivedAtIsNullAndRecordedAtLessThanOrderBySeqAsc(cutoff);

    long throughSeq = 0;
    for (AuditEvent event : due) {
      archive.save(ArchivedAuditEvent.copyOf(event, now));
      event.archiveAsTombstone(now);
      throughSeq = event.getSeq();
    }
    log.info("retention run archived {} records (cutoff {})", due.size(), cutoff);
    return new RetentionResult(due.size(), throughSeq, cutoff);
  }

  /** Registered unconditionally; only acts when {@code audit.retention.scheduled=true}. */
  @Scheduled(cron = "${audit.retention.scheduled-cron:0 0 3 * * *}")
  public void scheduledRun() {
    if (properties.retention().enabled() && properties.retention().scheduled()) {
      run();
    }
  }
}
