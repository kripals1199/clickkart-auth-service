// src/main/java/com/clickkart/auth/repository/VerificationCodeRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.OtpChannel;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCodeEntity, Long> {

    /**
     * Deliberately NOT pessimistic-locked - same reasoning as {@code LoginOtpRepository
     * .findOutstanding}: a wrong-guess path calls {@code AuthFailureRecorder
     * .recordVerificationCodeFailure} in its own {@code REQUIRES_NEW} transaction to persist the
     * attempt count before {@code VerificationCodeServiceImpl.verify} throws, and holding a
     * {@code SELECT ... FOR UPDATE} lock here would make that independent update block forever on
     * a lock only this same, still-open call could release - a guaranteed self-deadlock. The
     * inherited {@code @Version} column still catches genuine concurrent modification.
     */
    @Query("select v from VerificationCodeEntity v where v.clickKartUser = :clickKartUser and v.channel = :channel and v.used = false")
    Optional<VerificationCodeEntity> findOutstanding(
            @Param("clickKartUser") ClickKartUserEntity clickKartUser, @Param("channel") OtpChannel channel);

    /**
     * Scoped to {@code (user, channel)}, not just {@code user} - unlike a login OTP, a single
     * account may legitimately have an outstanding EMAIL verification code and an outstanding SMS
     * verification code at the same time; requesting a new one for one channel must not silently
     * burn an unrelated outstanding code for the other.
     */
    @Modifying
    @Query(
            "update VerificationCodeEntity v set v.used = true, v.usedAt = :now "
                    + "where v.clickKartUser = :clickKartUser and v.channel = :channel and v.used = false")
    int invalidateAllOutstandingForUser(
            @Param("clickKartUser") ClickKartUserEntity clickKartUser,
            @Param("channel") OtpChannel channel,
            @Param("now") Instant now);
}
