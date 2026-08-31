package com.sj.audit.utils.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Low-level hashing primitives.
 *
 * <p>Algorithm choice: <b>SHA-256</b> (FIPS 180-4). Ubiquitous, hardware-accelerated on all target
 * platforms, 128-bit collision resistance — sufficient for tamper evidence and friendly to
 * compliance reviewers. See {@code docs/decisions/ADR-0001-hash-algorithm.md}.
 *
 * <p>All multi-part inputs are combined with an explicit domain-separation prefix and a
 * {@code 0x1F} (ASCII unit separator) delimiter between parts. Every part we concatenate is a
 * fixed-length hex string or a short ASCII tag, so the encoding is unambiguous and not vulnerable
 * to length-extension confusion.
 */
public final class Hashing {

  /** ASCII unit separator placed between the parts of a domain-separated hash pre-image. */
  private static final byte PART_SEPARATOR = 0x1F;

  private Hashing() {}

  public static byte[] sha256(byte[] input) {
    return newDigest().digest(input);
  }

  public static String sha256Hex(byte[] input) {
    return Hex.encode(sha256(input));
  }

  public static String sha256Hex(String utf8Input) {
    return sha256Hex(utf8Input.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Domain-separated digest of an ordered list of parts: {@code SHA-256(prefix || 0x1F || p0 || 0x1F
   * || p1 || ...)}. Parts are treated as UTF-8 text.
   */
  public static String domainHashHex(String domainPrefix, String... parts) {
    MessageDigest digest = newDigest();
    digest.update(domainPrefix.getBytes(StandardCharsets.US_ASCII));
    for (String part : parts) {
      digest.update(PART_SEPARATOR);
      digest.update(part.getBytes(StandardCharsets.UTF_8));
    }
    return Hex.encode(digest.digest());
  }

  /** HMAC-SHA-256, hex-encoded. Used for optional export-bundle signing. */
  public static String hmacSha256Hex(String secret, byte[] message) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return Hex.encode(mac.doFinal(message));
    } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
      throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
    }
  }

  private static MessageDigest newDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
