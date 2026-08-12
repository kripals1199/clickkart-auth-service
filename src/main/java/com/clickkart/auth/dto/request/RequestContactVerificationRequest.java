// src/main/java/com/clickkart/auth/dto/request/RequestContactVerificationRequest.java
package com.clickkart.auth.dto.request;

import com.clickkart.auth.enums.OtpChannel;
import jakarta.validation.constraints.NotNull;

/** {@code channel} doubles as which attribute to verify - EMAIL verifies the account's email, SMS verifies its mobile number. */
public record RequestContactVerificationRequest(@NotNull OtpChannel channel) {}
