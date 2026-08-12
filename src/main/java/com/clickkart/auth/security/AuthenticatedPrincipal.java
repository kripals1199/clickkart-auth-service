// src/main/java/com/clickkart/auth/security/AuthenticatedPrincipal.java
package com.clickkart.auth.security;

import java.time.Instant;
import java.util.Set;

/**
 * What {@link JwtAuthenticationFilter} extracts from a validated access token and places on
 * the {@code SecurityContext}. Controllers/services read this instead of trusting any
 * X-User-Id/X-User-Roles header, since a request reaching this service directly (bypassing the
 * Gateway) must be authorized on the token's own merits, not on headers an attacker could set.
 *
 * <p>{@code userId} holds the JWT subject, which is {@code ClickKartUserEntity.publicId} - the
 * external-facing identifier - never the internal auto-generated {@code Long} primary key.
 * {@code roles} are plain role-name strings (e.g. {@code "ROLE_ADMIN"}) taken verbatim from the
 * JWT claim - not re-parsed into the {@code RoleType} enum, since roles are now a persisted,
 * admin-manageable table ({@code RoleEntity}) and a future custom role wouldn't have a matching enum
 * constant.
 */
public record AuthenticatedPrincipal(
        String userId, Set<String> roles, String correlationId, String jti, Instant expiresAt) {}
