// src/main/java/com/clickkart/auth/event/PasswordResetNotificationEvent.java
package com.clickkart.auth.event;

import com.clickkart.auth.feign.PasswordResetNotificationRequest;

/**
 * Published inside the transaction that issues a password-reset token; dispatched only after that
 * transaction commits - see {@link NotificationDispatchListener}.
 *
 * <p>Carries the raw token, because that is what the recipient needs and it exists nowhere else
 * (only its hash is persisted). It is never logged.
 */
public record PasswordResetNotificationEvent(String correlationId, PasswordResetNotificationRequest request) {}
