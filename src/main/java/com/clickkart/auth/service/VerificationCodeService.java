// src/main/java/com/clickkart/auth/service/VerificationCodeService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.exception.InvalidVerificationCodeException;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;

/** Owns issuance and one-time consumption of {@link VerificationCodeEntity}s. */
public interface VerificationCodeService {

    record IssuedVerificationCode(VerificationCodeEntity entity, String rawValue) {}

    /**
     * Invalidates any still-outstanding code for this account and channel before issuing a new
     * one - only the most recently requested code is ever honored.
     */
    IssuedVerificationCode issue(ClickKartUserEntity clickKartUser, OtpChannel channel, String correlationId, Instant now);

    /**
     * Validates the presented raw code for this account and channel, marking it used on success.
     * A wrong guess increments the code's own attempt counter and, once {@code
     * auth.verification-code-max-verify-attempts} is reached, burns it outright - and, since the
     * caller ({@code AuthServiceImpl.confirmContactVerification}) is about to throw from inside
     * its own {@code @Transactional} method, persists that attempt (and the audit-trail failure
     * record) via {@code AuthFailureRecorder} in an independent {@code REQUIRES_NEW} transaction
     * before throwing, so neither is lost to rollback.
     *
     * @throws InvalidVerificationCodeException for every rejection case - no outstanding code,
     *     wrong code, expired, already used, or too many wrong guesses.
     */
    VerificationCodeEntity verify(
            ClickKartUserEntity clickKartUser,
            OtpChannel channel,
            String rawCode,
            Instant now,
            String correlationId,
            RequestMetadata requestMetadata);
}
