// src/main/java/com/clickkart/auth/service/AuthFailureRecorder.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.LoginFailureReason;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;

/**
 * Persists the durable side effects of an authentication failure - lockout counter, {@code
 * LoginAuditEntity}, tamper-evident {@code AuditLogEntryEntity}, refresh-token-family revocation,
 * an OTP's own attempt counter - in their own independent transaction ({@code
 * Propagation.REQUIRES_NEW}), separate from the caller's.
 *
 * <p>This exists specifically because the caller ({@code AuthServiceImpl.login}/{@code
 * verifyOtp}, {@code RefreshTokenServiceImpl.rotate}, {@code OtpServiceImpl.verify}) is about to
 * throw the very exception the failure represents, from inside its own {@code
 * @Transactional(rollbackFor = Exception.class)} method. Without this separate transaction,
 * Spring's default rollback-on-unchecked-exception behavior would silently undo every one of
 * these writes the instant that exception propagates - the lockout counter would never actually
 * persist, the failed-login audit trail would have no record of the rejection, a detected
 * stolen-refresh-token replay would never actually get revoked, and an OTP's wrong-guess attempt
 * counter would never advance (letting it be guessed indefinitely). All of this was confirmed
 * non-functional in practice before this fix (Mockito-based unit tests don't catch it, since they
 * never engage real transaction/rollback semantics).
 *
 * <p>Every implementation here also calls {@code AuditTrailService.record(...)}, and the Audit
 * Log Service it dispatches to is a required dependency (see {@code
 * AuditLogServiceClientFallbackFactory} - it throws {@code DownstreamServiceUnavailableException}
 * on failure rather than swallowing it). A dispatch failure therefore rolls back this method's
 * own REQUIRES_NEW transaction too, undoing the lockout counter/audit-record writes alongside it,
 * and that exception (not the original login/OTP failure) is what ultimately reaches the caller
 * as a 503. This is intentional: an authentication failure this service cannot durably record is
 * not something it should pretend to have handled.
 */
public interface AuthFailureRecorder {

    /**
     * {@code clickKartUser} may be {@code null} (unknown identifier - nothing to persist on the
     * account) or an already-in-memory-mutated entity (e.g. after {@code
     * increaseFailedAttempts()}/{@code lock()}) that this method re-attaches and saves.
     */
    void recordLoginFailure(
            ClickKartUserEntity clickKartUser,
            String attemptedIdentifier,
            LoginFailureReason failureReason,
            AuditAction auditAction,
            String correlationId,
            RequestMetadata requestMetadata,
            String auditDetails);

    /**
     * Revokes the entire refresh-token family sharing {@code correlationId} and records the
     * reuse detection, atomically.
     *
     * @return how many tokens were revoked, so the caller can still log it without needing its own persistence step
     */
    int revokeRefreshTokenFamilyAndRecordReuse(String correlationId, String actor, Instant now, RequestMetadata requestMetadata);

    /**
     * Persists an OTP's state after a wrong-guess (already mutated in-memory by the caller -
     * {@code increaseAttempts()}, and {@code markUsed()} too if that guess just crossed {@code
     * auth.otp-max-verify-attempts}) - same REQUIRES_NEW reasoning as {@link #recordLoginFailure},
     * since the caller is about to throw {@code InvalidOtpException}.
     */
    void recordOtpVerifyFailure(LoginOtpEntity otp);

    /**
     * Persists a verification code's state after a wrong-guess (already mutated in-memory by the
     * caller - {@code increaseAttempts()}, and {@code markUsed()} too if that guess just crossed
     * {@code auth.verification-code-max-verify-attempts}) and records the audit-trail failure
     * entry, both in the same {@code REQUIRES_NEW} transaction - same reasoning as {@link
     * #recordLoginFailure}, since the caller is about to throw {@code
     * InvalidVerificationCodeException}. Unlike {@link #recordOtpVerifyFailure}, this also writes
     * the audit entry directly (rather than leaving that to a separate account-lockout recorder
     * call downstream) because contact-verification failures have no account-lockout bookkeeping
     * of their own to piggyback on.
     */
    void recordVerificationCodeFailure(
            VerificationCodeEntity code,
            AuditAction auditAction,
            String correlationId,
            String actor,
            RequestMetadata requestMetadata,
            String auditDetails);
}
