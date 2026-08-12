// src/main/java/com/clickkart/auth/feign/AuditEventRequest.java
package com.clickkart.auth.feign;

import com.clickkart.auth.enums.AuditAction;
import java.time.Instant;

/**
 * Every write endpoint reports these 5 fields to the Audit Log Service (Section 3 compliance
 * rule): correlation id, IP address, actor, action, timestamp.
 */
public record AuditEventRequest(
        String correlationId, String actor, AuditAction action, String ipAddress, Instant timestamp, String details) {

    public static AuditEventRequest of(
            String correlationId, String actor, AuditAction action, String ipAddress, String details) {
        return new AuditEventRequest(correlationId, actor, action, ipAddress, Instant.now(), details);
    }
}
