package com.sj.audit.api;

import com.sj.audit.config.ApiError;
import com.sj.audit.config.ForbiddenException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Uniform {@link ApiError} responses for the whole API. */
@RestControllerAdvice
public class GlobalExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiError> onValidation(
      MethodArgumentNotValidException ex, HttpServletRequest request) {
    String message =
        ex.getBindingResult().getFieldErrors().stream()
            .map(f -> f.getField() + " " + f.getDefaultMessage())
            .collect(Collectors.joining("; "));
    return build(HttpStatus.BAD_REQUEST, message.isEmpty() ? "validation failed" : message, request);
  }

  @ExceptionHandler({IllegalArgumentException.class})
  public ResponseEntity<ApiError> onBadRequest(IllegalArgumentException ex, HttpServletRequest request) {
    return build(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
  }

  @ExceptionHandler(NoSuchElementException.class)
  public ResponseEntity<ApiError> onNotFound(NoSuchElementException ex, HttpServletRequest request) {
    return build(HttpStatus.NOT_FOUND, ex.getMessage(), request);
  }

  @ExceptionHandler(IllegalStateException.class)
  public ResponseEntity<ApiError> onConflict(IllegalStateException ex, HttpServletRequest request) {
    return build(HttpStatus.CONFLICT, ex.getMessage(), request);
  }

  @ExceptionHandler(ForbiddenException.class)
  public ResponseEntity<ApiError> onForbidden(ForbiddenException ex, HttpServletRequest request) {
    return build(HttpStatus.FORBIDDEN, ex.getMessage(), request);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiError> onUnexpected(Exception ex, HttpServletRequest request) {
    log.error("unhandled exception on {} {}", request.getMethod(), request.getRequestURI(), ex);
    return build(HttpStatus.INTERNAL_SERVER_ERROR, "internal error", request);
  }

  private ResponseEntity<ApiError> build(HttpStatus status, String message, HttpServletRequest request) {
    ApiError body =
        ApiError.of(status.value(), status.getReasonPhrase(), message, request.getRequestURI());
    return ResponseEntity.status(status).body(body);
  }
}
