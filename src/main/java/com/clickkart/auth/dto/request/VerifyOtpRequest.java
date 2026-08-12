// src/main/java/com/clickkart/auth/dto/request/VerifyOtpRequest.java
package com.clickkart.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/** {@code identifier} may be the account's email, mobile number, or public id - same as {@link LoginRequest}. */
public record VerifyOtpRequest(@NotBlank String identifier, @NotBlank String otp) {}
