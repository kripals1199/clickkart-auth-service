// src/main/java/com/clickkart/auth/dto/PasswordPolicy.java
package com.clickkart.auth.dto;

/**
 * Single source of truth for the password complexity rule enforced on every DTO that carries a
 * new plaintext password ({@link RegisterRequest}, {@link ResetPasswordRequest}, {@link
 * ChangePasswordRequest}) - a bean-validation annotation attribute must be a compile-time
 * constant, so this exists as a constants holder rather than a validator instance shared via DI.
 */
public final class PasswordPolicy {

    private PasswordPolicy() {}

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 100;

    public static final String REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\da-zA-Z]).{8,}$";
    public static final String MESSAGE =
            "must contain at least one uppercase letter, one lowercase letter, one digit, and one special character";
}
