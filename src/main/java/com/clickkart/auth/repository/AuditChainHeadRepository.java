// src/main/java/com/clickkart/auth/repository/AuditChainHeadRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.AuditChainHeadEntity;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Deliberately extends the bare Spring Data {@code Repository} marker (not {@code JpaRepository})
 * - this singleton bookkeeping row has exactly two legitimate operations, save and lock-and-read,
 * and no business ever needs to delete it or list "all" of them.
 */
@Repository
public interface AuditChainHeadRepository extends org.springframework.data.repository.Repository<AuditChainHeadEntity, Long> {

    AuditChainHeadEntity save(AuditChainHeadEntity head);

    Optional<AuditChainHeadEntity> findById(Long id);

    /**
     * Locks the singleton row for the duration of the caller's transaction, serializing every
     * concurrent audit-chain append onto this one row - see the class Javadoc on
     * {@link AuditChainHeadEntity} for why this lock is what actually keeps the chain a single
     * unbroken sequence rather than letting concurrent writers fork it.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from AuditChainHeadEntity h where h.id = :id")
    Optional<AuditChainHeadEntity> lockForUpdate(@Param("id") Long id);
}
