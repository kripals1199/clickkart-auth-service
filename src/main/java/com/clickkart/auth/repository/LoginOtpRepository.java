// src/main/java/com/clickkart/auth/repository/LoginOtpRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginOtpRepository extends JpaRepository<LoginOtpEntity, Long> {

    /**
     * Deliberately NOT pessimistic-locked, unlike {@code PasswordResetTokenRepository
     * .findByTokenHashForUpdate} / {@code RefreshTokenRepository.findByTokenHashForUpdate} - a
     * wrong-guess path here calls {@code AuthFailureRecorder.recordOtpVerifyFailure} in its own
     * {@code REQUIRES_NEW} transaction (see that method's Javadoc for why) to persist the attempt
     * count before {@code OtpServiceImpl.verify} throws, and that independent transaction updates
     * this exact same row on a different connection. Holding a {@code SELECT ... FOR UPDATE} lock
     * on it here would make that update block forever waiting on a lock only this same,
     * still-open call could release - a guaranteed self-deadlock, not just a rare race. The
     * inherited {@code @Version} column (from {@code BaseEntity}) still catches genuine concurrent
     * modification of the same OTP the ordinary optimistic-locking way.
     */
    @Query("select o from LoginOtpEntity o where o.clickKartUser = :clickKartUser and o.used = false")
    Optional<LoginOtpEntity> findOutstanding(@Param("clickKartUser") ClickKartUserEntity clickKartUser);

    /**
     * Invalidates every outstanding (unused) OTP for this account - called whenever a new one is
     * requested, so only the most recently issued code is ever honored and an older, possibly
     * intercepted code stops working.
     */
    @Modifying
    @Query("update LoginOtpEntity o set o.used = true, o.usedAt = :now where o.clickKartUser = :clickKartUser and o.used = false")
    int invalidateAllOutstandingForUser(@Param("clickKartUser") ClickKartUserEntity clickKartUser, @Param("now") Instant now);
}
