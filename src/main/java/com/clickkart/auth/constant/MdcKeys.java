// src/main/java/com/clickkart/auth/constant/MdcKeys.java
package com.clickkart.auth.constant;

/**
 * SLF4J MDC key names used consistently across filters/services/exception handling, so the same
 * literal isn't retyped (and risking drift) in every class that reads or writes the correlation
 * id via MDC.
 */
public final class MdcKeys {

    private MdcKeys() {}

    public static final String CORRELATION_ID = "correlationId";
}
