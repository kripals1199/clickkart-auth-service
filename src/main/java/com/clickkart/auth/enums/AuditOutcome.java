// src/main/java/com/clickkart/auth/enums/AuditOutcome.java
package com.clickkart.auth.enums;

/** Whether the audited action succeeded or failed - kept distinct from {@link AuditAction} (what happened) so both are queryable independently. */
public enum AuditOutcome {
    SUCCESS,
    FAILURE
}
