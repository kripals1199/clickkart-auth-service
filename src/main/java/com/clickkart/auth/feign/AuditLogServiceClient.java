// src/main/java/com/clickkart/auth/feign/AuditLogServiceClient.java
package com.clickkart.auth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Real Eureka-discovered client for the Audit Log Service (build order item #13, not yet
 * built). Wrapped with a Resilience4j circuit breaker (see
 * clickkart-auth-service-*.properties: resilience4j.circuitbreaker.instances.clickkart-audit-log-service.*)
 * and {@link AuditLogServiceClientFallbackFactory}, per Rule 9 - a genuine typed client
 * against the real future route, never an inline mock.
 */
@FeignClient(name = AuditLogServiceClient.SERVICE_NAME, fallbackFactory = AuditLogServiceClientFallbackFactory.class)
public interface AuditLogServiceClient {

    String SERVICE_NAME = "clickkart-audit-log-service";
    String EVENTS_PATH = "/api/v1/audit-log/events";
    String CORRELATION_ID_HEADER = "X-Correlation-Id";

    @PostMapping(path = EVENTS_PATH, consumes = MediaType.APPLICATION_JSON_VALUE)
    void logEvent(@RequestHeader(CORRELATION_ID_HEADER) String correlationId, @RequestBody AuditEventRequest request);
}
