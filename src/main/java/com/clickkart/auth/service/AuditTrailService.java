// src/main/java/com/clickkart/auth/service/AuditTrailService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.AuditLogEntryEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.web.RequestMetadata;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Banking-grade audit trail: every call to {@link #record} must durably persist an {@link
 * AuditLogEntryEntity} inside the caller's own {@code @Transactional} method (see {@code
 * AuthServiceImpl}) - if that database write fails, the whole enclosing transaction rolls back,
 * so a login/register/logout can never silently "succeed" without leaving an audit trace (the
 * banking "audit-or-abort" guarantee). The local table is the system of record; a best-effort
 * Feign call to the future Audit Log Service afterward is for centralized cross-service
 * aggregation only (see {@link AuditTrailServiceImpl} for that detail).
 */
public interface AuditTrailService {

    /** Hash a genesis (non-existent) predecessor is chained from - the first real entry links to this, never to another entry's hash. */
    String GENESIS_HASH = "0".repeat(64);

    void record(
            String correlationId,
            String actor,
            AuditAction action,
            AuditOutcome outcome,
            RequestMetadata requestMetadata,
            String details);

    /**
     * Recomputes every entry's hash from its own stored fields and checks it against both the
     * stored {@code entryHash} and the chain link to the previous entry - any mismatch means a
     * row was altered (or deleted/reordered) after being written.
     */
    ChainIntegrityReport verifyChainIntegrity();

    Page<AuditLogEntryEntity> browse(Pageable pageable);
}
