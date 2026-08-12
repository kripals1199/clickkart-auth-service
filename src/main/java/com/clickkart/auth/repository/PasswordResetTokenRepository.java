// src/main/java/com/clickkart/auth/repository/PasswordResetTokenRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.PasswordResetTokenEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetTokenEntity, Long> {

    /** Pessimistic lock for the consume-on-reset critical section - same reasoning as {@code RefreshTokenRepository.findByTokenHashForUpdate}. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from PasswordResetTokenEntity t where t.tokenHash = :tokenHash")
    Optional<PasswordResetTokenEntity> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    /**
     * Invalidates every outstanding (unused) token for this account - called whenever a new
     * reset is requested, so only the most recently issued token is ever honored and an older,
     * possibly-leaked token from an earlier request stops working.
     */
    @Modifying
    @Query("update PasswordResetTokenEntity t set t.used = true, t.usedAt = :now where t.clickKartUser = :clickKartUser and t.used = false")
    int invalidateAllOutstandingForUser(@Param("clickKartUser") ClickKartUserEntity clickKartUser, @Param("now") Instant now);
}
