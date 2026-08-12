// src/main/java/com/clickkart/auth/entity/AuditLogEntryEntity.java
package com.clickkart.auth.entity;

import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.util.Sha256;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "audit_log_entries",
        indexes = {
            @Index(name = "idx_audit_log_entries_actor", columnList = "actor"),
            @Index(name = "idx_audit_log_entries_correlation_id", columnList = "correlation_id"),
            @Index(name = "idx_audit_log_entries_occurred_at", columnList = "occurred_at")
        })
public class AuditLogEntryEntity extends BaseEntity {

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(name = "correlation_id", nullable = false, updatable = false, length = 36)
    private String correlationId;

    /** {@code ClickKartUserEntity.publicId}, or {@code "system"} for unauthenticated flows - never a raw email/mobile number. */
    @Column(name = "actor", nullable = false, updatable = false, length = 64)
    private String actor;

    // JdbcTypeCode(VARCHAR) alongside @Enumerated(STRING) is deliberate, not redundant: plain
    // @Enumerated(STRING) alone makes Hibernate 6+ auto-generate a CHECK constraint listing every
    // current AuditAction value at table-creation time. With no migration tool in this project
    // (ddl-auto=update never widens an existing constraint), every later addition to this enum -
    // which has already happened repeatedly - would get silently rejected by that stale
    // constraint in any environment where the table already exists, until someone manually drops
    // it. Forcing the plain VARCHAR JDBC type sidesteps Hibernate's enum-aware DDL generation
    // entirely, so no such constraint is ever created.
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "action", nullable = false, updatable = false, length = 30)
    private AuditAction action;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "outcome", nullable = false, updatable = false, length = 10)
    private AuditOutcome outcome;

    @Column(name = "ip_address", nullable = false, updatable = false, length = 45)
    private String ipAddress;

    /** Free text - deliberately never populated with email/mobile/password/token values (see class Javadoc). */
    @Column(name = "user_agent", updatable = false, length = 512)
    private String userAgent;

    @Column(name = "details", updatable = false, length = 1000)
    private String details;

    @Column(name = "previous_entry_hash", nullable = false, updatable = false, length = 64)
    private String previousEntryHash;

    @Column(name = "entry_hash", nullable = false, updatable = false, length = 64)
    private String entryHash;

    private AuditLogEntryEntity(
            Instant occurredAt,
            String correlationId,
            String actor,
            AuditAction action,
            AuditOutcome outcome,
            String ipAddress,
            String userAgent,
            String details,
            String previousEntryHash,
            String entryHash) {
        this.occurredAt = occurredAt;
        this.correlationId = correlationId;
        this.actor = actor;
        this.action = action;
        this.outcome = outcome;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.details = details;
        this.previousEntryHash = previousEntryHash;
        this.entryHash = entryHash;
    }

    /**
     * Builds a new entry linked to {@code previousEntryHash}, computing this entry's own hash
     * over its canonical field representation (see {@link #canonicalPayload}). The caller
     * ({@code AuditTrailService}) is responsible for supplying the correct, current chain-head
     * hash under a lock - this factory only computes the digest, it does not read or update any
     * shared state itself.
     */
    public static AuditLogEntryEntity create(
            Instant occurredAt,
            String correlationId,
            String actor,
            AuditAction action,
            AuditOutcome outcome,
            String ipAddress,
            String userAgent,
            String details,
            String previousEntryHash) {
        String payload = canonicalPayload(
                occurredAt, correlationId, actor, action, outcome, ipAddress, userAgent, details, previousEntryHash);
        String entryHash = Sha256.hex(payload);
        return new AuditLogEntryEntity(
                occurredAt, correlationId, actor, action, outcome, ipAddress, userAgent, details, previousEntryHash, entryHash);
    }

    /**
     * Recomputes what this row's {@code entryHash} should be, from its own persisted fields -
     * used by {@code AuditTrailService.verifyChainIntegrity()} to detect tampering. Field order
     * and separators here must never change without a documented migration plan for the whole
     * chain, since it would invalidate every previously-computed hash.
     */
    public String recomputeHash() {
        String payload = canonicalPayload(
                occurredAt, correlationId, actor, action, outcome, ipAddress, userAgent, details, previousEntryHash);
        return Sha256.hex(payload);
    }

    private static String canonicalPayload(
            Instant occurredAt,
            String correlationId,
            String actor,
            AuditAction action,
            AuditOutcome outcome,
            String ipAddress,
            String userAgent,
            String details,
            String previousEntryHash) {
        return String.join(
                "|",
                previousEntryHash,
                occurredAt.toString(),
                correlationId,
                actor,
                action.name(),
                outcome.name(),
                ipAddress,
                userAgent == null ? "" : userAgent,
                details == null ? "" : details);
    }
}
