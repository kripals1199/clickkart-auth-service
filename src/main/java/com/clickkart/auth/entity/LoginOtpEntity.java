// src/main/java/com/clickkart/auth/entity/LoginOtpEntity.java
package com.clickkart.auth.entity;

import com.clickkart.auth.enums.OtpChannel;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A one-time login code - unlike {@link PasswordResetTokenEntity} (a long, cryptographically
 * unique opaque string, safely looked up globally by hash), a short numeric OTP has real
 * collision odds across concurrently-issued codes, so lookup is always scoped to a specific
 * {@link ClickKartUserEntity} (see {@code LoginOtpRepository}), never global-by-hash.
 * {@code attemptCount} caps how many wrong guesses a single issued OTP tolerates before it burns
 * itself out (see {@link #isUsable}) - independent of, and in addition to, the account-level
 * lockout {@code ClickKartUserEntity} already enforces for password login.
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "login_otps",
        indexes = @Index(name = "idx_login_otps_user_id", columnList = "user_id"))
public class LoginOtpEntity extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private ClickKartUserEntity clickKartUser;

    @Column(name = "otp_hash", nullable = false, length = 64)
    private String otpHash;

    // See AuditLogEntryEntity.action's comment for why JdbcTypeCode(VARCHAR) is paired with
    // @Enumerated(STRING) here - prevents Hibernate from auto-generating a CHECK constraint that
    // would freeze this column's valid values at whatever OtpChannel has today, with no migration
    // tool to widen it if the enum ever grows (e.g. a future WHATSAPP channel).
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "channel", nullable = false, length = 10)
    private OtpChannel channel;

    @Column(name = "correlation_id", nullable = false, length = 36)
    private String correlationId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount = 0;

    @Column(name = "used", nullable = false)
    private boolean used = false;

    @Column(name = "used_at")
    private Instant usedAt;

    public LoginOtpEntity(
            ClickKartUserEntity clickKartUser, String otpHash, OtpChannel channel, String correlationId, Instant expiresAt) {
        this.clickKartUser = clickKartUser;
        this.otpHash = otpHash;
        this.channel = channel;
        this.correlationId = correlationId;
        this.expiresAt = expiresAt;
    }

    public boolean isUsable(Instant now) {
        return !used && expiresAt.isAfter(now);
    }

    public void markUsed(Instant now) {
        this.used = true;
        this.usedAt = now;
    }

    /** @return the new attempt count, so the caller can decide whether it just crossed the max-attempts threshold */
    public int increaseAttempts() {
        return ++this.attemptCount;
    }
}
