// src/main/java/com/clickkart/auth/feign/NotificationServiceClient.java
package com.clickkart.auth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Real Eureka-discovered client for the Notification Service (not yet built, same situation as
 * {@link AuditLogServiceClient} was when it was written). Wrapped with a Resilience4j circuit
 * breaker (config key {@code resilience4j.circuitbreaker.instances.clickkart-notification-service.*},
 * sourced from clickkart-config-repository like every other environment-specific property) and
 * {@link NotificationServiceClientFallbackFactory}, per Rule 9 - a genuine typed client against
 * the real future route, never an inline mock.
 */
@FeignClient(name = NotificationServiceClient.SERVICE_NAME, fallbackFactory = NotificationServiceClientFallbackFactory.class)
public interface NotificationServiceClient {

    String SERVICE_NAME = "clickkart-notification-service";
    String PASSWORD_RESET_PATH = "/api/v1/notifications/password-reset";
    String OTP_PATH = "/api/v1/notifications/otp";
    String CORRELATION_ID_HEADER = "X-Correlation-Id";

    @PostMapping(path = PASSWORD_RESET_PATH, consumes = MediaType.APPLICATION_JSON_VALUE)
    void sendPasswordResetNotification(
            @RequestHeader(CORRELATION_ID_HEADER) String correlationId, @RequestBody PasswordResetNotificationRequest request);

    /** One endpoint for both channels - {@code request.channel()} tells the receiving service which dispatch path to use. */
    @PostMapping(path = OTP_PATH, consumes = MediaType.APPLICATION_JSON_VALUE)
    void sendOtp(@RequestHeader(CORRELATION_ID_HEADER) String correlationId, @RequestBody OtpNotificationRequest request);
}
