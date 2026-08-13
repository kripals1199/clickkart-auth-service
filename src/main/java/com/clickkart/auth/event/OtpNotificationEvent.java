// src/main/java/com/clickkart/auth/event/OtpNotificationEvent.java
package com.clickkart.auth.event;

import com.clickkart.auth.feign.OtpNotificationRequest;

/**
 * Published inside the transaction that issues a login OTP or a contact-verification code;
 * dispatched only after that transaction commits - see {@link NotificationDispatchListener}.
 *
 * <p>Both flows share this event because they send the same payload through the same downstream
 * endpoint; only the originating use case differs, which the audit trail already records.
 */
public record OtpNotificationEvent(String correlationId, OtpNotificationRequest request) {}
