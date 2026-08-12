// src/main/java/com/clickkart/auth/dto/response/AuditLogEntryResponse.java
package com.clickkart.auth.dto.response;

import com.clickkart.auth.entity.AuditLogEntryEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import java.time.Instant;

/**
 * API-facing view of an {@link AuditLogEntryEntity} - never return the JPA entity itself from a
 * controller. {@code entryHash}/{@code previousEntryHash} are included deliberately: an external
 * auditor/compliance tool can independently recompute and cross-check them (same canonical field
 * order documented on {@link AuditLogEntryEntity}) without needing direct database access.
 */
public record AuditLogEntryResponse(
        Long id,
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

    public static AuditLogEntryResponse from(AuditLogEntryEntity entry) {
        return new AuditLogEntryResponse(
                entry.getId(),
                entry.getOccurredAt(),
                entry.getCorrelationId(),
                entry.getActor(),
                entry.getAction(),
                entry.getOutcome(),
                entry.getIpAddress(),
                entry.getUserAgent(),
                entry.getDetails(),
                entry.getPreviousEntryHash(),
                entry.getEntryHash());
    }
}
