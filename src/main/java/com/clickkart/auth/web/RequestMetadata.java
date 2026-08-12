// src/main/java/com/clickkart/auth/web/RequestMetadata.java
package com.clickkart.auth.web;

/**
 * HTTP-request-derived context threaded from {@code AuthController} through the service layer
 * into the audit trail - bundled into one record instead of a growing list of {@code String}
 * parameters on every {@code AuthService} method.
 */
public record RequestMetadata(String ipAddress, String userAgent) {}
