// src/main/java/com/clickkart/auth/service/RefreshTokenService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.RefreshTokenEntity;
import com.clickkart.auth.exception.InvalidRefreshTokenException;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;

/**
 * Owns issuance, rotation, and reuse-detection for {@link RefreshTokenEntity}s.
 *
 * <p><b>Rotation:</b> every {@code /refresh} call revokes the presented token and issues a brand
 * new one under the same {@code correlationId} (Rule 13 - one id per session, not per token).
 *
 * <p><b>Reuse detection:</b> see {@link RefreshTokenServiceImpl#rotate} for the pessimistic-lock
 * mechanics - if the presented token is found already revoked <i>and</i> {@code
 * replacedByTokenHash} is set (meaning it was legitimately rotated away, not just expired), that
 * is the signature of a stolen refresh token being replayed after the real client already moved
 * past it, and the entire session family sharing its {@code correlationId} is revoked immediately.
 */
public interface RefreshTokenService {

    record IssuedRefreshToken(RefreshTokenEntity entity, String rawValue) {}

    /** Mints and persists a brand new refresh token for a fresh login - no prior token to rotate away. */
    IssuedRefreshToken issue(ClickKartUserEntity clickKartUser, String correlationId, Instant now);

    /**
     * Validates the presented raw refresh token and, if it's genuinely usable, revokes it and
     * issues its successor under the same correlationId.
     *
     * @throws InvalidRefreshTokenException for every rejection case, including reuse - the caller
     *     doesn't need to distinguish reuse from ordinary invalidity to decide what to tell the
     *     client (always a 401, "log in again"); the security log (and, for reuse specifically,
     *     the tamper-evident audit trail) carries that distinction for operators.
     */
    IssuedRefreshToken rotate(String rawIncomingToken, Instant now, RequestMetadata requestMetadata);
}
