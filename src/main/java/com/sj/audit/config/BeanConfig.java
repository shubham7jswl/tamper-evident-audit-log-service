package com.sj.audit.config;

import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BeanConfig {

  /** Injectable clock so tests can control {@code recorded_at}. */
  @Bean
  @ConditionalOnMissingBean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
