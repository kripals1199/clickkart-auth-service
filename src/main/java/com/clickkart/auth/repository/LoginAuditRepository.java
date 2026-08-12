// src/main/java/com/clickkart/auth/repository/LoginAuditRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginAuditEntity;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * {@link LoginAuditEntity} is append-only (see that entity's Javadoc) but, unlike {@code
 * AuditLogEntryRepository}/{@code AuditChainHeadRepository}, this one extends the full {@code
 * JpaRepository} rather than the bare {@code Repository} marker - the hash-chained compliance
 * trail (a legal/audit record) warrants that hard API-level guarantee against deletion; this
 * table is an operational security-monitoring aid, where a documented retention/purge job
 * (deleting rows older than N days) is a legitimate, expected operation rather than a red flag.
 */
@Repository
public interface LoginAuditRepository extends JpaRepository<LoginAuditEntity, Long>, JpaSpecificationExecutor<LoginAuditEntity> {

    /** "Show me my last N logins" - account-scoped, newest first. */
    Page<LoginAuditEntity> findAllByClickKartUserOrderByOccurredAtDesc(ClickKartUserEntity clickKartUser, Pageable pageable);

    /** Simple brute-force signal: too many failed attempts against one identifier from one IP. */
    long countByIpAddressAndSuccessfulFalseAndOccurredAtAfter(String ipAddress, Instant since);

    /**
     * Credential-stuffing/enumeration signal distinct from the above: not "many failures against
     * one account", but "many *different* identifiers attempted from one IP" - a single
     * compromised-account brute-forcer looks like the derived query above, but a credential-
     * stuffing bot trying a list of stolen email/password pairs looks like this one. Expressed as
     * explicit JPQL rather than a derived name since "count distinct" isn't something Spring
     * Data's method-name derivation can express.
     */
    @Query(
            "select count(distinct la.attemptedIdentifier) from LoginAuditEntity la "
                    + "where la.ipAddress = :ipAddress and la.occurredAt >= :since")
    long countDistinctIdentifiersAttemptedFromIp(@Param("ipAddress") String ipAddress, @Param("since") Instant since);
}
