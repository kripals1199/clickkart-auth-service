// src/main/java/com/clickkart/auth/dto/request/RequestOtpRequest.java
package com.clickkart.auth.dto.request;

import com.clickkart.auth.enums.OtpChannel;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** {@code identifier} may be the account's email, mobile number, or public id - same as {@link LoginRequest}. */
public record RequestOtpRequest(@NotBlank String identifier, @NotNull OtpChannel channel) {}
