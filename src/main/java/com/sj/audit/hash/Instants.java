package com.sj.audit.hash;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Canonical, fixed-width instant formatting for hashing.
 *
 * <p>{@link Instant#toString()} varies its fractional-second width (0/3/6/9 digits). We always emit
 * exactly 9 fractional digits and a {@code Z} suffix so the hashed representation is stable no
 * matter what precision the datastore round-trips.
 */
public final class Instants {

  private static final DateTimeFormatter CANONICAL =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'").withZone(ZoneOffset.UTC);

  private Instants() {}

  public static String canonical(Instant instant) {
    return CANONICAL.format(instant.atOffset(ZoneOffset.UTC));
  }

  public static Instant parse(String canonical) {
    return OffsetDateTime.parse(canonical).toInstant();
  }
}
