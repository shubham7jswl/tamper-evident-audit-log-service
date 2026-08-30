package com.sj.audit.config;

/** Thrown when an authenticated principal lacks the authority for a specific operation. */
public class ForbiddenException extends RuntimeException {
  public ForbiddenException(String message) {
    super(message);
  }
}
