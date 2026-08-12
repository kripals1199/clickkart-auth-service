// src/main/java/com/clickkart/auth/exception/DownstreamServiceUnavailableException.java
package com.clickkart.auth.exception;

/**
 * A required integrated dependency (Redis, the Audit Log Service, the Notification Service)
 * could not be reached. Deliberately fails the whole request rather than degrading silently -
 * see {@code AuthFailureRecorder}, {@code AuditLogServiceClientFallbackFactory}, {@code
 * NotificationServiceClientFallbackFactory}, {@code RateLimitFilter}, and {@code
 * JwtAuthenticationFilter} for the call sites that throw this, and {@code GlobalExceptionHandler}
 * for the resulting 503 response.
 */
public class DownstreamServiceUnavailableException extends RuntimeException {

    public DownstreamServiceUnavailableException(String serviceName, Throwable cause) {
        super(serviceName + " is currently unavailable - please try again shortly", cause);
    }
}
