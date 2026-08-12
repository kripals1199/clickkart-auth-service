// src/main/java/com/clickkart/auth/feign/PasswordResetNotificationRequest.java
package com.clickkart.auth.feign;

import java.time.Instant;

/**
 * What the (future) Notification Service needs to email a reset link: the raw token, not its
 * hash - this Feign call is the one and only place the raw value travels anywhere after being
 * minted (see {@code PasswordResetService.issue}), exactly as a real "reset your password" email
 * always must carry the raw, usable token. Never logged - see
 * {@link NotificationServiceClientFallbackFactory}.
 */
public record PasswordResetNotificationRequest(String recipientEmail, String rawResetToken, Instant expiresAt) {

    public static PasswordResetNotificationRequest of(String recipientEmail, String rawResetToken, Instant expiresAt) {
        return new PasswordResetNotificationRequest(recipientEmail, rawResetToken, expiresAt);
    }
}
