// src/main/java/com/clickkart/auth/feign/CaptchaServiceClientFallbackFactory.java
package com.clickkart.auth.feign;

import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * Captcha Service is a required dependency for the endpoints that call it - bot-detection on
 * register/forgot-password must not become optional the moment the service is slow or down
 * (fail closed, same posture as {@code RateLimitFilter}'s Redis outage handling). On
 * open-circuit/error this logs at WARN (never {@code request.answer()}, which is meaningless
 * outside its own challenge but still avoided as a matter of habit - see other fallback
 * factories' Javadoc on never logging raw secrets) and throws {@link
 * DownstreamServiceUnavailableException}, which Feign's fallback-invocation mechanism propagates
 * to the caller exactly as if the underlying call had thrown it directly.
 */
@Slf4j
@Component
public class CaptchaServiceClientFallbackFactory implements FallbackFactory<CaptchaServiceClient> {

    private static final String SERVICE_NAME = "Captcha Service";

    @Override
    public CaptchaServiceClient create(Throwable cause) {
        return (correlationId, request) -> {
            log.warn(
                    "CAPTCHA_VERIFY_DISPATCH_FAILED correlationId={} challengeId={} - captcha-service unreachable, cause={}",
                    correlationId,
                    request.challengeId(),
                    cause.toString());
            throw new DownstreamServiceUnavailableException(SERVICE_NAME, cause);
        };
    }
}
