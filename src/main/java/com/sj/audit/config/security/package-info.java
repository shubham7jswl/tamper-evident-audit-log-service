/**
 * Minimal request security: a static {@code X-Api-Key} header mapped to a set of {@link
 * Scope}s.
 *
 * <ul>
 *   <li>{@link ApiKeyAuthFilter} — authenticates (401 if the key is missing
 *       or unknown) and attaches an {@link ApiPrincipal} to the request.
 *   <li>{@link ScopeInterceptor} + {@link
 *       RequireScope} — authorizes (403 if the principal lacks the scope the
 *       handler method requires). {@code WRITE} to append, {@code READ} to query/verify/export,
 *       {@code ADMIN} for the high-impact operations (redaction, retention, deep verify).
 * </ul>
 *
 * <p>Deliberately not production auth — no rotation, rate limiting or mTLS. See
 * {@code docs/architecture.md} §6.
 */
package com.sj.audit.config.security;

import com.sj.audit.enums.Scope;