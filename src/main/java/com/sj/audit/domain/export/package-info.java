/**
 * Verifiable bulk export (Scenario B): hand someone a subset of the chain they can check offline.
 *
 * <ul>
 *   <li>{@link BundleExporter} — builds an {@link
 *       ExportBundle} for a {@code resourceId} or {@code actorId}.
 *   <li>{@link ExportBundle} — the wire format: every record with its hashes,
 *       salts and commitments, plus <b>segments</b> (the record hash just before each contiguous
 *       run of selected {@code seq}s) and an overall {@code bundleHash} / optional {@code hmac}.
 *   <li>{@link BundleVerifier} — Spring-free; re-derives every hash and walks
 *       the links. A recipient needs only this class, {@code com.sj.audit.hash} and Jackson.
 * </ul>
 *
 * <p>Key idea: each record carries its own {@code prevHash} and {@code recordHash}, so a
 * non-contiguous selection is still verifiable record-by-record.
 */
package com.sj.audit.domain.export;

import com.sj.audit.service.BundleExporter;
import com.sj.audit.utils.BundleVerifier;