// src/main/java/com/clickkart/auth/security/TokenRevocationLogoutHandler.java
package com.clickkart.auth.security;

import com.clickkart.auth.dto.request.LogoutRequest;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.RefreshTokenEntity;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.repository.ClickKartUserRepository;
import com.clickkart.auth.repository.RefreshTokenRepository;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * All the actual token-invalidation work behind {@code POST /api/v1/auth/logout}, extracted out
 * of {@code AuthServiceImpl} into its own component - not wired through Spring Security's own
 * {@code LogoutHandler}/{@code LogoutFilter} URL-based DSL, since that machinery is built around
 * session/cookie invalidation and doesn't fit a stateless JWT API cleanly (there's no session to
 * invalidate, and the "handler" needs the parsed request body's optional refresh token, which
 * Spring Security's {@code LogoutHandler.logout(request, response, authentication)} signature
 * has no clean way to supply). {@code AuthServiceImpl.logout} calls this directly, then records
 * the audit trail entry itself - this class's only responsibility is revocation.
 */
@Component
@RequiredArgsConstructor
public class TokenRevocationLogoutHandler {

    private final RevocationService revocationService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ClickKartUserRepository clickKartUserRepository;
    private final JwtService jwtService;

    @Transactional(rollbackFor = Exception.class)
    public void handle(AuthenticatedPrincipal principal, LogoutRequest request) {
        revocationService.revoke(principal.jti(), principal.expiresAt());

        if (request != null && request.refreshToken() != null && !request.refreshToken().isBlank()) {
            revokeSpecificToken(principal, request.refreshToken());
        } else {
            revokeAllActiveTokensForAccount(principal);
        }
    }

    private void revokeSpecificToken(AuthenticatedPrincipal principal, String rawRefreshToken) {
        String hash = jwtService.hashToken(rawRefreshToken);
        refreshTokenRepository.findByTokenHash(hash).ifPresent(token -> {
            // isRevoked() checked first, deliberately - it's a plain column read, unlike
            // getClickKartUser(), which lazily resolves the owning account and would throw if that
            // account has since been soft-deleted (ClickKartUserEntity's @SQLRestriction excludes
            // it from the lookup Hibernate issues to initialize the association). An already-revoked
            // token (e.g. swept by AuthServiceImpl.lockAccount/deleteAccount) has nothing left to do
            // here anyway, so short-circuiting on that first avoids ever touching the association -
            // logout must never 500 just because the token it was handed happens to be stale.
            if (!token.isRevoked() && token.getClickKartUser().getPublicId().equals(principal.userId())) {
                token.revoke(Instant.now());
                refreshTokenRepository.save(token);
            }
        });
    }

    private void revokeAllActiveTokensForAccount(AuthenticatedPrincipal principal) {
        ClickKartUserEntity userRef = clickKartUserRepository
                .findByPublicId(principal.userId())
                .orElseThrow(() -> new IllegalStateException("Authenticated account no longer exists: " + principal.userId()));
        revokeAllActiveTokensForAccount(userRef);
    }

    /**
     * Public overload for callers that already hold the target {@link ClickKartUserEntity} - e.g.
     * {@code AuthServiceImpl.deleteAccount}, where an ADMIN is revoking a different account's
     * sessions, not their own. Only revokes refresh tokens: an already-issued, unexpired access
     * token for the target account has no known {@code jti} to add to the revocation blocklist
     * (that's only ever available for the *currently authenticated* principal's own token, via
     * {@code principal.jti()}), so it remains valid until its natural TTL expiry either way - the
     * same pre-existing limitation {@code lockAccount} already has today.
     */
    @Transactional(rollbackFor = Exception.class)
    public void revokeAllActiveTokensForAccount(ClickKartUserEntity clickKartUser) {
        List<RefreshTokenEntity> active = refreshTokenRepository.findAllByClickKartUserAndRevokedFalse(clickKartUser);
        Instant now = Instant.now();
        active.forEach(token -> token.revoke(now));
        refreshTokenRepository.saveAll(active);
    }
}
