// src/main/java/com/clickkart/auth/config/RoleSeeder.java
package com.clickkart.auth.config;

import com.clickkart.auth.entity.RoleEntity;
import com.clickkart.auth.enums.RoleType;
import com.clickkart.auth.repository.RoleRepository;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ensures the 4 baseline {@link RoleType} rows exist in the {@code roles} table on every
 * startup. Idempotent by design (checked via {@code existsByName} before each insert) so it is
 * safe to run on every boot across every replica - this is this project's substitute for a
 * Flyway/Liquibase seed migration, since the project uses neither (Rule: no migration tooling).
 * Runs before any request can be served (ApplicationRunner, ordered first) so registration/login
 * never race a missing role row.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RoleSeeder implements ApplicationRunner {

    private static final Map<RoleType, String> BASELINE_ROLE_DESCRIPTIONS = Map.of(
            RoleType.ROLE_ADMIN, "Full administrative access to the ClickKart platform",
            RoleType.ROLE_CUSTOMER, "Standard shopper account - browse, purchase, and track orders",
            RoleType.ROLE_SELLER, "Merchant account - list and manage products for sale",
            RoleType.ROLE_DELIVERY_AGENT, "Delivery personnel account - fulfill and track order deliveries");

    private final RoleRepository roleRepository;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void run(ApplicationArguments args) {
        for (RoleType roleType : RoleType.values()) {
            if (!roleRepository.existsByName(roleType.name())) {
                roleRepository.save(new RoleEntity(roleType.name(), BASELINE_ROLE_DESCRIPTIONS.get(roleType)));
                log.info("Seeded baseline role {}", roleType.name());
            }
        }
    }
}
