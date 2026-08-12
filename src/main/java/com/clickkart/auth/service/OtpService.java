// src/main/java/com/clickkart/auth/service/OtpService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.exception.InvalidOtpException;
import java.time.Instant;

/** Owns issuance and one-time consumption of {@link LoginOtpEntity}s. */
public interface OtpService {

    record IssuedOtp(LoginOtpEntity entity, String rawValue) {}

    /**
     * Invalidates any still-outstanding OTP from an earlier request before issuing a new one -
     * only the most recently requested code is ever honored.
     */
    IssuedOtp issue(ClickKartUserEntity clickKartUser, OtpChannel channel, String correlationId, Instant now);

    /**
     * Validates the presented raw OTP for this account in one locked step, marking it used on
     * success. A wrong guess increments the OTP's own attempt counter and, once {@code
     * auth.otp-max-verify-attempts} is reached, burns the OTP outright (marks it used) so no
     * further guesses against it are possible even if the correct code is later found.
     *
     * @throws InvalidOtpException for every rejection case - no outstanding OTP, wrong code,
     *     expired, already used, or too many wrong guesses - a caller has no legitimate reason to
     *     distinguish them (mirrors password login's InvalidCredentialsException).
     */
    LoginOtpEntity verify(ClickKartUserEntity clickKartUser, String rawOtp, Instant now);
}
