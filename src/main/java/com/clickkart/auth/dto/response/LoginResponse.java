// src/main/java/com/clickkart/auth/dto/response/LoginResponse.java
package com.clickkart.auth.dto.response;

/**
 * Login (and registration, which auto-logs-in) response: the JWT/refresh token pair <b>plus</b>
 * the account's own profile summary, so a UI integrator doesn't need a follow-up "who am I" call
 * right after signing in or signing up. {@code /refresh} deliberately returns the plain
 * {@link AuthTokenResponse} instead - resending the full user profile on every silent token
 * refresh would be wasted payload for something that essentially never changes between refreshes.
 */
public record LoginResponse(AuthTokenResponse tokens, ClickKartUserSummaryResponse user) {}
