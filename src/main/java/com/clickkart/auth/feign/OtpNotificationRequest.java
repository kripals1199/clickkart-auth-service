// src/main/java/com/clickkart/auth/feign/OtpNotificationRequest.java
package com.clickkart.auth.feign;

import com.clickkart.auth.enums.OtpChannel;
import java.time.Instant;

/**
 * What the (future) Notification Service needs to deliver a login OTP: the raw code, not its
 * hash - this Feign call is the one and only place the raw value travels anywhere after being
 * minted (see {@code OtpService.issue}). {@code channel} tells the receiving service which
 * dispatch path to use; exactly one of {@code recipientEmail}/{@code recipientMobileNumber} is
 * populated, matching {@code channel}. Never logged - see {@link NotificationServiceClientFallbackFactory}.
 */
public record OtpNotificationRequest(
        OtpChannel channel, String recipientEmail, String recipientMobileNumber, String rawOtp, Instant expiresAt) {

    public static OtpNotificationRequest of(
            OtpChannel channel, String recipientEmail, String recipientMobileNumber, String rawOtp, Instant expiresAt) {
        return new OtpNotificationRequest(channel, recipientEmail, recipientMobileNumber, rawOtp, expiresAt);
    }
}
