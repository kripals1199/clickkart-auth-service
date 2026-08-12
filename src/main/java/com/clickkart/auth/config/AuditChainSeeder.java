// src/main/java/com/clickkart/auth/config/AuditChainSeeder.java
package com.clickkart.auth.config;

import com.clickkart.auth.entity.AuditChainHeadEntity;
import com.clickkart.auth.repository.AuditChainHeadRepository;
import com.clickkart.auth.service.AuditTrailService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ensures the singleton {@link AuditChainHeadEntity} row exists before any request can try to append
 * to the audit hash chain - same idempotent startup-seeding pattern as {@code RoleSeeder}, for
 * the same reason (no Flyway/Liquibase migration in this project). Keeping this out of the
 * request-handling hot path ({@code AuditTrailService.record}) means that method can assume the
 * row is already there rather than having to create-if-missing under its own lock.
 */
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class AuditChainSeeder implements ApplicationRunner {

    private final AuditChainHeadRepository auditChainHeadRepository;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void run(ApplicationArguments args) {
        if (auditChainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).isEmpty()) {
            auditChainHeadRepository.save(new AuditChainHeadEntity(AuditTrailService.GENESIS_HASH));
        }
    }
}
