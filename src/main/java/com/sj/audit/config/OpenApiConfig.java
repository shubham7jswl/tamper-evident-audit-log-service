package com.sj.audit.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI document for the audit API. Every endpoint is secured by the {@code X-Api-Key} header;
 * that is declared once here as a global API-key security scheme so "Authorize" in Swagger UI sends
 * it on every request.
 */
@Configuration
public class OpenApiConfig {

  static final String API_KEY_SCHEME = "ApiKeyAuth";

  @Bean
  public OpenAPI auditOpenApi() {
    return new OpenAPI()
        .info(
            new Info()
                .title("Tamper-Evident Audit Log Service")
                .version("0.0.1")
                .description(
                    "Append-only audit log with a SHA-256 hash chain, chain verification, "
                        + "structured redaction, retention, verifiable export, and a compliance "
                        + "access report. Send a valid key in the `X-Api-Key` header "
                        + "(dev keys: dev-reader-key / dev-writer-key / dev-admin-key).")
                .license(new License().name("Proprietary — take-home exercise")))
        .components(
            new Components()
                .addSecuritySchemes(
                    API_KEY_SCHEME,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER)
                        .name("X-Api-Key")
                        .description("Static API key; scopes: READ, WRITE, ADMIN")))
        .addSecurityItem(new SecurityRequirement().addList(API_KEY_SCHEME));
  }
}
