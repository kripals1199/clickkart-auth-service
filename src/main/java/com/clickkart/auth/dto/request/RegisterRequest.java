// src/main/java/com/clickkart/auth/dto/request/RegisterRequest.java
package com.clickkart.auth.dto.request;

import com.clickkart.auth.dto.PasswordPolicy;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Public self-registration always creates a {@code ROLE_CUSTOMER} account -
 * there is no role selection here. {@code captchaChallengeId}/{@code captchaAnswer} come from a
 * prior {@code POST /api/v1/captcha/challenge} - bot-detection on account creation, per the
 * flagged production gap this closes.
 */
public record RegisterRequest(
		@NotBlank
		@Email
		@Size(max = 254) String email,

		@NotBlank
		@Pattern(regexp = "^[6-9]\\d{9}$", message = "Mobile number must be a valid 10-digit Indian number starting with 6, 7, 8, or 9")
        String mobileNumber,

		@NotBlank
		@Size(min = PasswordPolicy.MIN_LENGTH, max = PasswordPolicy.MAX_LENGTH)
        @Pattern(regexp = PasswordPolicy.REGEX, message = PasswordPolicy.MESSAGE)
        String password,

		@NotBlank String captchaChallengeId,

		@NotBlank String captchaAnswer) {
}
