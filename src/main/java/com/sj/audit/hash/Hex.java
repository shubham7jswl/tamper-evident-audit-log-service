package com.sj.audit.hash;

/** Lowercase hex encode/decode. */
public final class Hex {

  private static final char[] DIGITS = "0123456789abcdef".toCharArray();

  private Hex() {}

  public static String encode(byte[] bytes) {
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      out[i * 2] = DIGITS[v >>> 4];
      out[i * 2 + 1] = DIGITS[v & 0x0F];
    }
    return new String(out);
  }

  public static byte[] decode(String hex) {
    int len = hex.length();
    if ((len & 1) == 1) {
      throw new IllegalArgumentException("hex string has odd length");
    }
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      int hi = Character.digit(hex.charAt(i), 16);
      int lo = Character.digit(hex.charAt(i + 1), 16);
      if (hi < 0 || lo < 0) {
        throw new IllegalArgumentException("invalid hex character");
      }
      out[i / 2] = (byte) ((hi << 4) | lo);
    }
    return out;
  }
}
