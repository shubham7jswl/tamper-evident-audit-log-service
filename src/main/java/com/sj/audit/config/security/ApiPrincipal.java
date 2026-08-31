package com.sj.audit.config.security;

import com.sj.audit.enums.Scope;

import java.util.Set;

/** The authenticated caller, derived from a valid {@code X-Api-Key}. */
public record ApiPrincipal(String name, Set<Scope> scopes) {

  /** Request attribute key under which the filter stores the resolved principal. */
  public static final String ATTRIBUTE = ApiPrincipal.class.getName();

  public boolean hasScope(Scope scope) {
    return scopes.contains(scope);
  }
}
