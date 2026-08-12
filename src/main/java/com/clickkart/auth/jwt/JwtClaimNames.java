// src/main/java/com/clickkart/auth/jwt/JwtClaimNames.java
package com.clickkart.auth.jwt;

/**
 * Custom (non-registered) claim keys minted into every access token by {@link JwtService}.
 * No shared library exists between services (Rule 4),
 * so the Gateway's {@code com.clickkart.gateway.filter.JwtClaimNames} is a deliberate local
 * copy of these same literal values - if either side's copy drifts, claim extraction silently
 * breaks and needs a manual cross-check.
 */
public final class JwtClaimNames {

    private JwtClaimNames() {}

    public static final String ROLES = "roleTypes";
    public static final String CORRELATION_ID = "correlationId";
}
