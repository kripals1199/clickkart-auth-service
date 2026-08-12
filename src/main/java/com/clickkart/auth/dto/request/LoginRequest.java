// src/main/java/com/clickkart/auth/dto/request/LoginRequest.java
package com.clickkart.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/** {@code identifier} may be the account's email, mobile number, or public id (e.g. "USR-..."). */
public record LoginRequest(@NotBlank String identifier, @NotBlank String password) {}
