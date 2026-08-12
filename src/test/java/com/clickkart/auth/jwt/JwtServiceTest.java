// src/test/java/com/clickkart/auth/jwt/JwtServiceTest.java
package com.clickkart.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.clickkart.auth.config.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.SignatureException;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        AuthProperties properties = new AuthProperties();
        properties.setJwtSecret("test-only-secret-key-must-be-at-least-32-bytes-long");
        properties.setAccessTokenTtlSeconds(900);
        properties.setRefreshTokenBytes(64);
        jwtService = new JwtService(properties);
    }

    @Test
    void mintAccessTokenEmbedsRolesAndCorrelationIdAndIsParseable() {
        String publicId = "USR-" + UUID.randomUUID();
        String correlationId = UUID.randomUUID().toString();

        JwtService.MintedAccessToken minted = jwtService.mintAccessToken(publicId, Set.of("ROLE_CUSTOMER", "ROLE_SELLER"), correlationId);

        Claims claims = jwtService.parseAndValidate(minted.token());
        assertThat(claims.getSubject()).isEqualTo(publicId);
        assertThat(claims.getId()).isEqualTo(minted.jti());
        assertThat(claims.get(JwtClaimNames.CORRELATION_ID, String.class)).isEqualTo(correlationId);
        String rolesClaim = claims.get(JwtClaimNames.ROLES, String.class);
        assertThat(rolesClaim.split(",")).containsExactlyInAnyOrder("ROLE_CUSTOMER", "ROLE_SELLER");
    }

    @Test
    void parseAndValidateRejectsTokenSignedWithADifferentKey() {
        AuthProperties otherProperties = new AuthProperties();
        otherProperties.setJwtSecret("a-completely-different-test-secret-key-of-32-bytes+");
        JwtService otherService = new JwtService(otherProperties);

        String token = otherService.mintAccessToken("USR-" + UUID.randomUUID(), Set.of("ROLE_CUSTOMER"), "cid").token();

        assertThrows(SignatureException.class, () -> jwtService.parseAndValidate(token));
    }

    @Test
    void hashTokenIsDeterministicAndSha256HexLength() {
        String raw = "some-opaque-refresh-token-value";
        String hash1 = jwtService.hashToken(raw);
        String hash2 = jwtService.hashToken(raw);

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64); // SHA-256 -> 32 bytes -> 64 hex chars
    }

    @Test
    void generateOpaqueRefreshTokenProducesDistinctHighEntropyValues() {
        String first = jwtService.generateOpaqueRefreshToken();
        String second = jwtService.generateOpaqueRefreshToken();

        assertThat(first).isNotEqualTo(second);
        assertThat(first.length()).isGreaterThan(40);
    }
}
