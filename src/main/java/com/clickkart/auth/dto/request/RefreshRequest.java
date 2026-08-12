// src/main/java/com/clickkart/auth/dto/request/RefreshRequest.java
package com.clickkart.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RefreshRequest(@NotBlank String refreshToken) {}
