/**
 * Cryptographic building blocks for the tamper-evident chain. Nothing here talks to Spring or the
 * database — it is pure functions over bytes and JSON, reused by both the write path
 * ({@code chain.ChainAppender}) and every verify path ({@code chain.ChainVerifier},
 * {@code export.BundleVerifier}).
 *
 * <h2>Vocabulary</h2>
 *
 * <ul>
 *   <li><b>canonical JSON</b> ({@link CanonicalJson}) — one and only one byte
 *       string for a given JSON value (sorted keys, normalized numbers, no whitespace). Every hash
 *       pre-image goes through it so the write side and the verify side agree.
 *   <li><b>leaf</b> — a single JSON value inside a payload (string / number / boolean / null), plus
 *       a marker for an empty object/array. Identified by its <b>JSON Pointer</b> (e.g.
 *       {@code /account/number}).
 *   <li><b>canonical leaf</b> — a leaf rendered as {@code typeTag + value} (e.g. {@code "S4111"}).
 *   <li><b>leaf commitment</b> ({@link PayloadCommitments}) —
 *       {@code SHA-256("LEAF1" | salt | canonicalLeaf)}. The content hash covers these, never the
 *       raw values, which is what makes redaction possible.
 *   <li><b>salt</b> — a random 128-bit value per leaf, so a commitment over a low-entropy value
 *       (an account number) cannot be brute-forced once the plaintext is gone.
 *   <li><b>content hash</b> / <b>record hash</b> ({@link AuditHasher}) — see that
 *       class. Content hash = "what the record says"; record hash = "the link to the record
 *       before".
 *   <li><b>domain separation</b> ({@link Hashing}) — every multi-part hash input
 *       starts with a constant tag ({@code "REC1"}, {@code "LEAF1"}) and puts {@code 0x1F} between
 *       parts, so two different structures can never share a pre-image.
 * </ul>
 */
package com.sj.audit.utils.hash;

