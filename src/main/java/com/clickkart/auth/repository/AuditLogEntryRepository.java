// src/main/java/com/clickkart/auth/repository/AuditLogEntryRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.AuditLogEntryEntity;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

/**
 * Deliberately extends the bare Spring Data {@code Repository} marker, not {@code JpaRepository}
 * - an audit trail is append-only by design (see {@link AuditLogEntryEntity}'s class Javadoc), so this
 * interface exposes no {@code deleteById}/{@code deleteAll}/{@code delete(...)} at all. There is
 * no supported way to remove an audit record through this repository, full stop.
 */
@Repository
public interface AuditLogEntryRepository extends org.springframework.data.repository.Repository<AuditLogEntryEntity, Long> {

    AuditLogEntryEntity save(AuditLogEntryEntity entry);

    long count();

    Page<AuditLogEntryEntity> findAllByOrderByIdAsc(Pageable pageable);

    /**
     * Full-table read in chain order, for {@code AuditTrailService.verifyChainIntegrity()}.
     * Loads the entire table into memory - fine for an on-demand admin integrity check at
     * current scale; a checkpoint-based incremental verification (verify only entries added
     * since the last verified id) is the natural next step once the table is large enough that
     * a full scan becomes expensive.
     */
    List<AuditLogEntryEntity> findAllByOrderByIdAsc();
}
