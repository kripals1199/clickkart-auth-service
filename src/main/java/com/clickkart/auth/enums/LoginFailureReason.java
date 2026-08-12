// src/main/java/com/clickkart/auth/enums/LoginFailureReason.java
package com.clickkart.auth.enums;

/** Closed vocabulary for {@code LoginAuditEntity.failureReason} - see that entity's Javadoc. */
public enum LoginFailureReason {
    UNKNOWN_IDENTIFIER,
    BAD_PASSWORD,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    INVALID_OTP
}
