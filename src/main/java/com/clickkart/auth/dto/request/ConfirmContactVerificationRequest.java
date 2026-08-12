// src/main/java/com/clickkart/auth/dto/request/ConfirmContactVerificationRequest.java
package com.clickkart.auth.dto.request;

import com.clickkart.auth.enums.OtpChannel;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ConfirmContactVerificationRequest(@NotNull OtpChannel channel, @NotBlank String code) {}
