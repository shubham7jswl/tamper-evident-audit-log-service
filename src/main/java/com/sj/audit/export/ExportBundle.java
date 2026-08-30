package com.sj.audit.export;

import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * A self-contained, independently verifiable export of a subset of the chain.
 *
 * <p>Each {@link Record} carries its own {@code prevHash} and {@code recordHash}, so a recipient can
 * confirm — per record — that (a) the content hash recomputes from the fields + commitments and
 * (b) {@code recordHash == SHA-256("REC1" | prevHash | contentHash)}. That proves each record is
 * unaltered and correctly positioned relative to its predecessor even when the filter selects a
 * non-contiguous set of {@code seq} values. {@link Segment} entries give the predecessor
 * {@code recordHash} at the start of every contiguous run so full linkage can be walked.
 *
 * <p>{@code bundleHash} is {@code SHA-256} of the canonical JSON of this object with
 * {@code bundleHash} and {@code hmac} set to null. {@code hmac} (optional) is
 * {@code HMAC-SHA-256(secret, bundleHash)}.
 */
public record ExportBundle(
    String bundleVersion,
    String exportedAt,
    Filter filter,
    String genesisHash,
    List<Record> records,
    List<Segment> segments,
    String bundleHash,
    String hmac) {

  public record Filter(String type, String value) {}

  public record Record(
      long seq,
      String eventId,
      String eventType,
      String actorId,
      String resourceType,
      String resourceId,
      JsonNode payload,
      Map<String, String> leafSalts,
      Map<String, String> leafCommitments,
      List<String> redactedPaths,
      String eventTimestamp,
      String recordedAt,
      String contentHash,
      String prevHash,
      String recordHash,
      boolean archived) {}

  public record Segment(long fromSeq, long toSeq, String priorRecordHash) {}

  public ExportBundle withIntegrity(String bundleHash, String hmac) {
    return new ExportBundle(
        bundleVersion, exportedAt, filter, genesisHash, records, segments, bundleHash, hmac);
  }
}
