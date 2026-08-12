// src/main/java/com/clickkart/auth/entity/PasswordResetTokenEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "password_reset_tokens",
        uniqueConstraints = @UniqueConstraint(name = "uk_password_reset_tokens_token_hash", columnNames = "token_hash"),
        indexes = {
            @Index(name = "idx_password_reset_tokens_user_id", columnList = "user_id"),
            @Index(name = "idx_password_reset_tokens_token_hash", columnList = "token_hash")
        })
public class PasswordResetTokenEntity extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private ClickKartUserEntity clickKartUser;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(name = "correlation_id", nullable = false, length = 36)
    private String correlationId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used", nullable = false)
    private boolean used = false;

    @Column(name = "used_at")
    private Instant usedAt;

    public PasswordResetTokenEntity(ClickKartUserEntity clickKartUser, String tokenHash, String correlationId, Instant expiresAt) {
        this.clickKartUser = clickKartUser;
        this.tokenHash = tokenHash;
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
}
