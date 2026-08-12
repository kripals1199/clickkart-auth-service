// src/main/java/com/clickkart/auth/serviceImpl/RefreshTokenServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.RefreshTokenEntity;
import com.clickkart.auth.exception.InvalidRefreshTokenException;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.repository.RefreshTokenRepository;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.service.RefreshTokenService;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j(topic = LoggerNames.SECURITY)
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final AuthProperties authProperties;
    private final AuthFailureRecorder authFailureRecorder;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public IssuedRefreshToken issue(ClickKartUserEntity clickKartUser, String correlationId, Instant now) {
        String rawValue = jwtService.generateOpaqueRefreshToken();
        RefreshTokenEntity entity = new RefreshTokenEntity(
                clickKartUser, jwtService.hashToken(rawValue), correlationId, now, now.plusSeconds(authProperties.getRefreshTokenTtlSeconds()));
        return new IssuedRefreshToken(refreshTokenRepository.save(entity), rawValue);
    }

    /**
     * {@link RefreshTokenRepository#findByTokenHashForUpdate} takes a pessimistic write lock so
     * two concurrent rotations of the exact same still-valid refresh token can't race past each
     * other - see that method's Javadoc for why a {@code @Version}-driven optimistic check alone
     * isn't enough here.
     *
     * <p>{@code noRollbackFor = InvalidRefreshTokenException.class}: the ineligible-account branch
     * below mutates {@code existing} (marks it revoked) and then throws that exact exception - a
     * plain {@code rollbackFor} would silently undo the revoke the instant it propagates, the same
     * class of bug already fixed for login/OTP failure bookkeeping via {@code AuthFailureRecorder}
     * (REQUIRES_NEW). REQUIRES_NEW isn't an option here though: {@code existing} is already
     * pessimistic-write-locked by *this* transaction, so a REQUIRES_NEW transaction trying to
     * update that same row would block on a lock only this same, still-open call could release -
     * a guaranteed self-deadlock. {@code noRollbackFor} sidesteps that entirely by letting this
     * transaction commit (preserving the revoke) despite still throwing to reject the caller.
     * Harmless for this method's other two throw sites (reuse-detected, expired/already-used) -
     * neither mutates anything in this transaction before throwing, so commit vs. rollback makes
     * no observable difference for them.
     *
     * <p>This annotation alone is not sufficient - {@code AuthServiceImpl.refresh()} (the only
     * caller, and the actual outer transaction boundary whenever this method is invoked as
     * intended) must carry the identical {@code noRollbackFor} for this same exception, since
     * Spring's rollback-only flag is a one-way latch: if that outer interceptor's own rules don't
     * also exclude this exception, it will mark the shared transaction rollback-only regardless of
     * what this inner boundary decided. Keep both in sync.
     */
    @Override
    @Transactional(rollbackFor = Exception.class, noRollbackFor = InvalidRefreshTokenException.class)
    public IssuedRefreshToken rotate(String rawIncomingToken, Instant now, RequestMetadata requestMetadata) {
        String incomingHash = jwtService.hashToken(rawIncomingToken);
        RefreshTokenEntity existing = refreshTokenRepository
                .findByTokenHashForUpdate(incomingHash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token is invalid or unknown"));

        if (existing.wasReplayedAfterRotation()) {
            String actor = existing.getClickKartUser().getPublicId();
            // Revocation + audit record run in authFailureRecorder's own REQUIRES_NEW
            // transaction, not here - this method is about to throw, and the resulting rollback
            // would otherwise silently undo the revocation itself, leaving the compromised
            // session family still valid.
            int revokedCount = authFailureRecorder.revokeRefreshTokenFamilyAndRecordReuse(
                    existing.getCorrelationId(), actor, now, requestMetadata);
            log.warn(
                    "REFRESH_TOKEN_REUSE_DETECTED correlationId={} userId={} familyTokensRevoked={}",
                    existing.getCorrelationId(),
                    actor,
                    revokedCount);
            throw new InvalidRefreshTokenException("Refresh token reuse detected - session revoked, please log in again");
        }

        if (!existing.isUsable(now)) {
            throw new InvalidRefreshTokenException("Refresh token has expired or already been used");
        }

        ClickKartUserEntity clickKartUser = existing.getClickKartUser();
        if (!clickKartUser.isEnabled() || !clickKartUser.isAccountNonLocked()) {
            existing.revoke(now);
            throw new InvalidRefreshTokenException("Account is no longer eligible to refresh a session");
        }

        IssuedRefreshToken issued = issue(clickKartUser, existing.getCorrelationId(), now);
        existing.revokeAsRotated(now, issued.entity().getTokenHash());
        return issued;
    }
}
