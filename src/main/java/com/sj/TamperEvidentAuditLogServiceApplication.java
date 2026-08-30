package com.sj;

import com.sj.audit.config.AuditProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableConfigurationProperties(AuditProperties.class)
@EnableScheduling
public class TamperEvidentAuditLogServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(TamperEvidentAuditLogServiceApplication.class, args);
  }
}
