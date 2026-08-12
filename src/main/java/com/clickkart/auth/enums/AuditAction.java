// src/main/java/com/clickkart/auth/enums/AuditAction.java
package com.clickkart.auth.enums;

/**
 * Closed vocabulary of audit event types this service can emit to the Audit Log Service
 * (Section 3 compliance rule) - an enum instead of ad-hoc string literals at each call site, so
 * every action name is typo-proof and this list is the one place to see everything this service
 * audits. Serialized to JSON as its plain name (e.g. {@code "LOGIN_SUCCESS"}) via Jackson's
 * default enum handling - no custom serializer needed.
 */
public enum AuditAction {
    REGISTER,
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    TOKEN_REFRESHED,
    LOGOUT,
    ACCOUNTS_LISTED,
    FORGOT_PASSWORD_REQUESTED,
    PASSWORD_RESET_COMPLETED,
    PASSWORD_CHANGED,
    ACCOUNT_LOCKED_BY_ADMIN,
    ACCOUNT_UNLOCKED_BY_ADMIN,
    REFRESH_TOKEN_REUSE_DETECTED,
    REVOKED_TOKEN_REUSE_DETECTED,
    RATE_LIMIT_EXCEEDED,
    ACCESS_DENIED,
    OTP_REQUESTED,
    OTP_LOGIN_SUCCESS,
    OTP_LOGIN_FAILED,
    AUDIT_TRAIL_VIEWED,
    AUDIT_INTEGRITY_VERIFIED,
    CONTACT_VERIFY_REQUESTED,
    CONTACT_VERIFIED,
    CONTACT_VERIFY_FAILED,
    ACCOUNT_DELETED_BY_ADMIN
}
