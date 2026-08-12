// src/main/java/com/clickkart/auth/dto/request/ResetPasswordRequest.java
package com.clickkart.auth.dto.request;

import com.clickkart.auth.dto.PasswordPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** {@code token} is the raw, opaque value from the reset link - never the hash stored server-side. */
public record ResetPasswordRequest(
        @NotBlank String token,
        @NotBlank
                @Size(min = PasswordPolicy.MIN_LENGTH, max = PasswordPolicy.MAX_LENGTH)
                @Pattern(regexp = PasswordPolicy.REGEX, message = PasswordPolicy.MESSAGE)
                String newPassword) {}
