// src/main/java/com/clickkart/auth/feign/NotificationServiceClientFallbackFactory.java
package com.clickkart.auth.feign;

import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * The Notification Service is a required dependency - a request that promises to email/SMS a
 * reset link or a code must not report success if that dispatch never actually happened. On
 * open-circuit/error, this logs at WARN (never {@code rawResetToken}/{@code rawOtp} itself,
 * which would defeat the entire point of only ever persisting their hash - see {@code
 * PasswordResetTokenEntity}, {@code LoginOtpEntity}, {@code VerificationCodeEntity}) and then
 * throws {@link DownstreamServiceUnavailableException}, which Feign's fallback-invocation
 * mechanism propagates to the caller exactly as if the underlying call had thrown it directly.
 *
 * <p><b>Known trade-off:</b> {@code AuthServiceImpl.forgotPassword}/{@code requestOtp} otherwise
 * respond identically whether or not the identifier resolves to an account, specifically so a
 * caller can never learn account existence from the response. Making this dependency required
 * reopens that channel while it's down: an unknown identifier still returns 200 immediately, but
 * a known identifier now returns 503 instead of 200 - the two cases become distinguishable for
 * as long as the outage lasts.
 */
@Slf4j
@Component
public class NotificationServiceClientFallbackFactory implements FallbackFactory<NotificationServiceClient> {

    private static final String SERVICE_NAME = "Notification Service";

    @Override
    public NotificationServiceClient create(Throwable cause) {
        return new NotificationServiceClient() {
            @Override
            public void sendPasswordResetNotification(String correlationId, PasswordResetNotificationRequest request) {
                log.warn(
                        "PASSWORD_RESET_NOTIFICATION_DISPATCH_FAILED correlationId={} recipient={} expiresAt={} - "
                                + "notification-service unreachable, cause={}",
                        correlationId,
                        request.recipientEmail(),
                        request.expiresAt(),
                        cause.toString());
                throw new DownstreamServiceUnavailableException(SERVICE_NAME, cause);
            }

            @Override
            public void sendOtp(String correlationId, OtpNotificationRequest request) {
                log.warn(
                        "OTP_NOTIFICATION_DISPATCH_FAILED correlationId={} channel={} expiresAt={} - "
                                + "notification-service unreachable, cause={}",
                        correlationId,
                        request.channel(),
                        request.expiresAt(),
                        cause.toString());
                throw new DownstreamServiceUnavailableException(SERVICE_NAME, cause);
            }
        };
    }
}
