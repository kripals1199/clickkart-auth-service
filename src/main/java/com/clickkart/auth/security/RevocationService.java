// src/main/java/com/clickkart/auth/security/RevocationService.java
package com.clickkart.auth.security;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import java.time.Duration;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Reads/writes the same {@code revoked:jti:<jti>} Redis keyspace the Gateway's
 * JwtAuthenticationGlobalFilter checks on every request - this is what makes logout invalidate
 * an access token immediately instead of leaving it valid until its natural expiry.
 *
 * <p>Redis is a required dependency here, not optional: {@link #revoke} translates a Redis
 * failure into {@link DownstreamServiceUnavailableException} (503 via {@code
 * GlobalExceptionHandler}) rather than letting logout silently succeed without actually revoking
 * anything, or letting a raw {@code DataAccessException} leak through as a generic 500.
 * {@link #isRevoked} does not need the same treatment - its one caller, {@code
 * JwtAuthenticationFilter}, already wraps that call itself, since it also needs to log the jti
 * and request path on failure.
 */
@Service
@RequiredArgsConstructor
public class RevocationService {

    private static final String SERVICE_NAME = "Token revocation (Redis)";

    private final StringRedisTemplate redisTemplate;
    private final AuthProperties authProperties;

    /** TTLs the revocation marker to exactly the token's remaining lifetime - no reason to keep it in Redis after the token would have expired anyway. */
    public void revoke(String jti, Instant tokenExpiresAt) {
        Duration ttl = Duration.between(Instant.now(), tokenExpiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }
        try {
            redisTemplate.opsForValue().set(key(jti), "1", ttl);
        } catch (DataAccessException e) {
            throw new DownstreamServiceUnavailableException(SERVICE_NAME, e);
        }
    }

    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate.hasKey(key(jti)));
    }

    private String key(String jti) {
        return authProperties.getRevocationKeyPrefix() + jti;
    }
}
