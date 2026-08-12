// src/main/java/com/clickkart/auth/feign/CaptchaServiceClient.java
package com.clickkart.auth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Real Eureka-discovered client for Captcha Service's internal, server-to-server-only {@code
 * /verify} endpoint (not Gateway-routed - see {@code CaptchaController}'s Javadoc). Wrapped with
 * a Resilience4j circuit breaker (config key {@code
 * resilience4j.circuitbreaker.instances.clickkart-captcha-service.*}) and {@link
 * CaptchaServiceClientFallbackFactory}, per Rule 9 - a genuine typed client, never an inline
 * mock.
 */
@FeignClient(name = CaptchaServiceClient.SERVICE_NAME, fallbackFactory = CaptchaServiceClientFallbackFactory.class)
public interface CaptchaServiceClient {

    String SERVICE_NAME = "clickkart-captcha-service";
    String VERIFY_PATH = "/api/v1/captcha/verify";
    String CORRELATION_ID_HEADER = "X-Correlation-Id";

    @PostMapping(path = VERIFY_PATH, consumes = MediaType.APPLICATION_JSON_VALUE)
    CaptchaVerifyApiResponse verify(@RequestHeader(CORRELATION_ID_HEADER) String correlationId, @RequestBody VerifyCaptchaRequest request);
}
