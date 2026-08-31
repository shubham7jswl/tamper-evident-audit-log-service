/**
 * Cross-cutting wiring: {@link com.sj.audit.config.AuditProperties} (the {@code audit.*} config
 * tree — genesis hash, API keys, retention window, redaction/export/compliance settings), the
 * {@link java.time.Clock} bean, the OpenAPI document, JSON helpers ({@link
 * com.sj.audit.config.JsonSupport}), and the shared error model ({@link
 * com.sj.audit.config.ApiError}, {@link com.sj.audit.config.ForbiddenException}).
 */
package com.sj.audit.config;
