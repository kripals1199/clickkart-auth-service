// src/main/java/com/clickkart/auth/event/NotificationDispatchListener.java
package com.clickkart.auth.event;

import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.feign.NotificationServiceClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Dispatches outbound notifications <b>after</b> the issuing transaction commits.
 *
 * <h2>Why this exists</h2>
 * The notification call used to happen inline, inside the same transaction that persisted the
 * token. Anything that failed <i>after</i> the send - a downstream timeout, an audit-log outage,
 * a constraint violation - rolled the token back while the email was already in the user's inbox.
 * The result was a reset link that could never be redeemed, delivered to a user who had just been
 * told the request failed. This was observed twice in real runs, not hypothesised.
 *
 * <p>Binding dispatch to {@link TransactionPhase#AFTER_COMMIT} makes the ordering correct: a
 * message is only ever sent once the credential it carries is durably stored. The worst remaining
 * failure is "token exists, email did not arrive", which the user resolves by requesting another -
 * strictly better than a token that cannot work.
 *
 * <h2>Why failures are swallowed here</h2>
 * Deliberate, and a real change from the previous behaviour. After commit there is nothing left
 * to roll back, so rethrowing could not undo the token and would only turn a successful request
 * into a confusing 500. Failures are logged at ERROR and remain visible downstream:
 * notification-service records its own FAILED row for the attempt.
 *
 * <p>This also restores a property the previous design had quietly broken. {@code forgotPassword}
 * is meant to respond identically whether or not the identifier exists, so an attacker cannot use
 * it to enumerate accounts. Making the notification call a hard, in-band dependency reopened that
 * channel: an unknown identifier returned 200 immediately while a known one returned 503 whenever
 * the notification path was unhealthy. Dispatching after commit removes that difference.
 */
@Slf4j(topic = LoggerNames.SECURITY)
@Component
@RequiredArgsConstructor
public class NotificationDispatchListener {

    private final NotificationServiceClient notificationServiceClient;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordResetRequested(PasswordResetNotificationEvent event) {
        try {
            notificationServiceClient.sendPasswordResetNotification(event.correlationId(), event.request());
        } catch (RuntimeException e) {
            // Never the raw token - it is the one secret this whole flow exists to protect.
            log.error(
                    "PASSWORD_RESET_NOTIFICATION_DISPATCH_FAILED_AFTER_COMMIT correlationId={} recipient={} cause={} "
                            + "- the reset token IS valid and stored; the user simply did not receive it and can request another",
                    event.correlationId(), event.request().recipientEmail(), e.toString());
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onOtpRequested(OtpNotificationEvent event) {
        try {
            notificationServiceClient.sendOtp(event.correlationId(), event.request());
        } catch (RuntimeException e) {
            log.error(
                    "OTP_NOTIFICATION_DISPATCH_FAILED_AFTER_COMMIT correlationId={} channel={} cause={} "
                            + "- the code IS valid and stored; the user simply did not receive it and can request another",
                    event.correlationId(), event.request().channel(), e.toString());
        }
    }
}
