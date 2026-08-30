package com.sj.audit.security;

import com.sj.audit.config.AuditProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.List;
import org.springframework.core.Ordered;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import tools.jackson.databind.ObjectMapper;

/** Wires the API-key filter and the scope interceptor into the MVC stack. */
@Configuration
public class SecurityConfig implements WebMvcConfigurer {

  private final ScopeInterceptor scopeInterceptor;
  private final ApiPrincipalArgumentResolver apiPrincipalArgumentResolver;

  public SecurityConfig(
      ScopeInterceptor scopeInterceptor,
      ApiPrincipalArgumentResolver apiPrincipalArgumentResolver) {
    this.scopeInterceptor = scopeInterceptor;
    this.apiPrincipalArgumentResolver = apiPrincipalArgumentResolver;
  }

  @Override
  public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
    resolvers.add(apiPrincipalArgumentResolver);
  }

  @Bean
  public FilterRegistrationBean<ApiKeyAuthFilter> apiKeyAuthFilter(
      AuditProperties properties, ObjectMapper objectMapper) {
    FilterRegistrationBean<ApiKeyAuthFilter> registration = new FilterRegistrationBean<>();
    registration.setFilter(new ApiKeyAuthFilter(properties, objectMapper));
    registration.addUrlPatterns("/audit/*");
    registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
    return registration;
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(scopeInterceptor).addPathPatterns("/audit/**");
  }
}
