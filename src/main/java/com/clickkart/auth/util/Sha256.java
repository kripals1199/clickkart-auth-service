// src/main/java/com/clickkart/auth/util/Sha256.java
package com.clickkart.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Single shared SHA-256 implementation - used both for refresh-token hashing ({@code JwtService})
 * and audit-log hash-chain links ({@code AuditLogEntryEntity}), so the same well-tested digest logic
 * isn't duplicated across two unrelated classes.
 */
public final class Sha256 {

    private static final String ALGORITHM = "SHA-256";

    private Sha256() {}

    /** @return the lowercase hex-encoded SHA-256 digest of {@code input} (64 characters) */
    public static String hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " algorithm unavailable", e);
        }
    }
}
