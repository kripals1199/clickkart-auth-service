// src/main/java/com/clickkart/auth/enums/RoleType.java
package com.clickkart.auth.enums;

/**
 * The 4 platform roles (Rule 1) - constants are ROLE_-prefixed so they match Spring Security's
 * own convention (its {@code hasRole(...)} checks look for a {@code ROLE_} prefix). RBAC source
 * of truth lives here - every other service trusts the roleTypes claim minted into the JWT at
 * login rather than maintaining its own copy.
 */
public enum RoleType {
    ROLE_ADMIN,
    ROLE_CUSTOMER,
    ROLE_SELLER,
    ROLE_DELIVERY_AGENT;

    /**
     * {@code ROLE_ADMIN.name()} as a compile-time constant, for use in annotation values (e.g.
     * {@code @PreAuthorize}) where only a constant expression is allowed - a method call like
     * {@code RoleType.ROLE_ADMIN.name()} cannot appear there. Kept as a named field rather than
     * a raw string literal at each call site so there is exactly one place this value lives.
     */
    public static final String ADMIN_AUTHORITY = "ROLE_ADMIN";
}
