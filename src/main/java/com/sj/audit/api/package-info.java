/**
 * The REST layer: controllers, request/response DTOs, and the shared error handler. Controllers
 * stay thin — validate input, call one service, map the result. All business logic lives in
 * {@code chain}, {@code query}, {@code redaction}, {@code retention}, {@code export} and
 * {@code compliance}.
 *
 * <p>Endpoint summary in {@code README.md}; an OpenAPI 3 document is served at {@code /v3/api-docs} with
 * Swagger UI at {@code /swagger-ui.html}. Every non-2xx response is a {@link
 * com.sj.audit.config.ApiError}.
 */
package com.sj.audit.api;
