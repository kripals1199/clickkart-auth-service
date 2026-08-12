// src/main/java/com/clickkart/auth/dto/request/LogoutRequest.java
package com.clickkart.auth.dto.request;

/**
 * Optional body. When {@code refreshToken} is present, only that session's refresh token is
 * revoked; when absent, every active refresh token owned by the authenticated account is
 * revoked (logout-everywhere), since the client may not have retained its own reference.
 */
public record LogoutRequest(String refreshToken) {}
