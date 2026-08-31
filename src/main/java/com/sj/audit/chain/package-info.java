/**
 * The hash chain itself: how records are appended to it and how it is verified.
 *
 * <ul>
 *   <li>{@link com.sj.audit.chain.ChainAppender} — the <b>single writer</b>. Locks the
 *       {@code chain_head} row, assigns the next {@code seq}, computes the hashes, saves the row,
 *       advances the head. This is the only place a record is created.
 *   <li>{@link com.sj.audit.chain.ChainVerifier} — walks {@code seq} in order, recomputing each
 *       record's hashes and checking the links, and returns a {@link
 *       com.sj.audit.chain.VerificationReport} naming the first {@link
 *       com.sj.audit.chain.ViolationType} it finds (or {@code intact}).
 * </ul>
 *
 * <h2>Vocabulary</h2>
 *
 * <ul>
 *   <li><b>seq</b> — the record's position in the chain. Application-assigned (not a DB identity)
 *       so it is known before hashing, and gap-free because appends are serialized.
 *   <li><b>genesis hash</b> — the fixed value used as {@code prev_hash} of {@code seq 1}.
 *   <li><b>chain head</b> — the running {@code (last seq, last record hash)}, cached in the
 *       {@code chain_head} table so an append never scans the tail.
 *   <li><b>tombstone</b> — an archived record: payload + salts dropped, all hashes kept. The
 *       verifier must treat it as legitimate, not a break.
 *   <li><b>archived segment</b> — a contiguous run of tombstones, reported so the caller can see
 *       what retention removed.
 * </ul>
 */
package com.sj.audit.chain;
