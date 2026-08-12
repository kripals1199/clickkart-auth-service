// src/main/java/com/clickkart/auth/entity/VerificationCodeEntity.java
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
 * A short-lived numeric code proving an authenticated account owns a claimed email/mobile number -
 * structurally close to {@link LoginOtpEntity} (same hash/expiry/attempt-count shape) but a
 * deliberately separate entity, not a shared "purpose"-discriminated table: this is a self-service
 * account-attribute proof, not a login credential, and conflating the two would mean a wrong
 * verification-code guess could plausibly ever influence login-lockout state (or vice versa),
 * which is not a security coupling this project wants. {@code channel} doubles as which attribute
 * is being verified - {@code EMAIL} delivers to/verifies the account's email, {@code SMS} delivers
 * to/verifies its mobile number - so a single account may have one outstanding EMAIL code and one
 * outstanding SMS code at the same time (see {@code VerificationCodeRepository}, scoped by
 * {@code (user, channel)}, unlike {@code LoginOtpRepository}'s user-only scope).
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "verification_codes",
        indexes = @Index(name = "idx_verification_codes_user_id", columnList = "user_id"))
public class VerificationCodeEntity extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private ClickKartUserEntity clickKartUser;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    // See AuditLogEntryEntity.action's comment for why JdbcTypeCode(VARCHAR) is paired with
    // @Enumerated(STRING) here - prevents Hibernate from auto-generating a CHECK constraint that
    // would freeze this column's valid values at whatever OtpChannel has today.
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

    public VerificationCodeEntity(
            ClickKartUserEntity clickKartUser, String codeHash, OtpChannel channel, String correlationId, Instant expiresAt) {
        this.clickKartUser = clickKartUser;
        this.codeHash = codeHash;
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
