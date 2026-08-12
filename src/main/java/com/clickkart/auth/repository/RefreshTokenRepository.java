// src/main/java/com/clickkart/auth/repository/RefreshTokenRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.RefreshTokenEntity;
import com.clickkart.auth.entity.ClickKartUserEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /**
     * Locking variant of {@link #findByTokenHash} for the rotate-on-refresh critical section
     * (Part 5/6): two requests racing to rotate the exact same still-valid refresh token is
     * precisely the reuse-detection scenario this service exists to catch, and the row already
     * carries a {@code @Version} (inherited from {@code BaseEntity}) that would also catch it
     * via {@code OptimisticLockException} on the loser's save - but that only surfaces as a
     * failure *after* both requests have already done the read-then-decide work. This pessimistic
     * lock makes the second request wait at the read instead, so only one rotation is ever
     * actually attempted per token, and the loser sees the already-rotated (revoked) state
     * directly rather than an exception to interpret.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select rt from RefreshTokenEntity rt where rt.tokenHash = :tokenHash")
    Optional<RefreshTokenEntity> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    List<RefreshTokenEntity> findAllByClickKartUserAndRevokedFalse(ClickKartUserEntity clickKartUser);

    /** Every token ever issued in one login session (Rule 13: correlationId is the session/family identifier). */
    List<RefreshTokenEntity> findAllByCorrelationId(String correlationId);

    /**
     * Revokes an entire session family in one statement - what reuse-detection calls once a
     * replayed, already-rotated token is confirmed (the standard response: don't just reject the
     * one request, invalidate every token descended from that session, since the whole chain is
     * now considered compromised). A single {@code UPDATE} instead of loading N rows into Java
     * just to call {@code revoke()} on each and save them individually.
     */
    @Modifying
    @Query(
            "update RefreshTokenEntity rt set rt.revoked = true, rt.revokedAt = :now "
                    + "where rt.correlationId = :correlationId and rt.revoked = false")
    int revokeAllByCorrelationId(@Param("correlationId") String correlationId, @Param("now") Instant now);
}
