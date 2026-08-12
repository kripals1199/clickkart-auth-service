// src/main/java/com/clickkart/auth/entity/LoginAuditEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "login_audits",
        indexes = {
            @Index(name = "idx_login_audits_user_id", columnList = "user_id"),
            @Index(name = "idx_login_audits_attempted_identifier", columnList = "attempted_identifier"),
            @Index(name = "idx_login_audits_occurred_at", columnList = "occurred_at"),
            @Index(name = "idx_login_audits_ip_occurred", columnList = "ip_address, occurred_at"),
            @Index(name = "idx_login_audits_ip_address", columnList = "ip_address")
        })
public class LoginAuditEntity extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", updatable = false)
    private ClickKartUserEntity clickKartUser;

    /** What the caller typed as the login identifier - kept even on success, for "which identifier did I log in with" history. */
    @Column(name = "attempted_identifier", nullable = false, updatable = false, length = 254)
    private String attemptedIdentifier;

    @Column(name = "successful", nullable = false, updatable = false)
    private boolean successful;

    /** e.g. {@code BAD_PASSWORD}, {@code ACCOUNT_LOCKED}, {@code ACCOUNT_DISABLED}, {@code UNKNOWN_IDENTIFIER} - null when {@code successful}. */
    @Column(name = "failure_reason", updatable = false, length = 40)
    private String failureReason;

    @Column(name = "ip_address", nullable = false, updatable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", updatable = false, length = 512)
    private String userAgent;

    @Column(name = "correlation_id", nullable = false, updatable = false, length = 36)
    private String correlationId;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    private LoginAuditEntity(
            ClickKartUserEntity clickKartUser,
            String attemptedIdentifier,
            boolean successful,
            String failureReason,
            String ipAddress,
            String userAgent,
            String correlationId,
            Instant occurredAt) {
        this.clickKartUser = clickKartUser;
        this.attemptedIdentifier = attemptedIdentifier;
        this.successful = successful;
        this.failureReason = failureReason;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.correlationId = correlationId;
        this.occurredAt = occurredAt;
    }

    public static LoginAuditEntity success(
            ClickKartUserEntity clickKartUser, String attemptedIdentifier, String ipAddress, String userAgent, String correlationId) {
        return new LoginAuditEntity(clickKartUser, attemptedIdentifier, true, null, ipAddress, userAgent, correlationId, Instant.now());
    }

    public static LoginAuditEntity failure(
            ClickKartUserEntity clickKartUser,
            String attemptedIdentifier,
            String failureReason,
            String ipAddress,
            String userAgent,
            String correlationId) {
        return new LoginAuditEntity(
                clickKartUser, attemptedIdentifier, false, failureReason, ipAddress, userAgent, correlationId, Instant.now());
    }
}
