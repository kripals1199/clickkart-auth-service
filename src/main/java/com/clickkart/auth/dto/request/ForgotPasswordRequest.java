// src/main/java/com/clickkart/auth/dto/request/ForgotPasswordRequest.java
package com.clickkart.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * {@code identifier} may be the account's email, mobile number, or public id - same as {@link LoginRequest}.
 * {@code captchaChallengeId}/{@code captchaAnswer} come from a prior {@code POST
 * /api/v1/captcha/challenge} - bot-detection on this endpoint (email-bombing an arbitrary
 * address, per the flagged production gap this closes).
 */
public record ForgotPasswordRequest(
        @NotBlank String identifier, @NotBlank String captchaChallengeId, @NotBlank String captchaAnswer) {}
