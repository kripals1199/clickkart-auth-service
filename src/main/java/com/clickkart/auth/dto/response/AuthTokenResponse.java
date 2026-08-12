// src/main/java/com/clickkart/auth/dto/response/AuthTokenResponse.java
package com.clickkart.auth.dto.response;

public record AuthTokenResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {

    public static AuthTokenResponse bearer(String accessToken, String refreshToken, long expiresInSeconds) {
        return new AuthTokenResponse(accessToken, refreshToken, "Bearer", expiresInSeconds);
    }
}
