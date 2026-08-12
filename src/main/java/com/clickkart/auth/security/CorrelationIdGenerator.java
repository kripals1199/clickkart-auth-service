// src/main/java/com/clickkart/auth/security/CorrelationIdGenerator.java
package com.clickkart.auth.security;

import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Single place that mints a new correlation id (Rule 13: the Auth Service is the only source of
 * a correlation id, minted at login). A dedicated component rather than an inline
 * {@code UUID.randomUUID().toString()} at each call site - trivial today, but gives {@code
 * AuthServiceImpl} exactly one thing to mock in a test that needs a deterministic id, and one
 * place to change the generation strategy later (e.g. a prefixed/sortable id) without touching
 * every call site.
 */
@Component
public class CorrelationIdGenerator {

    public String generate() {
        return UUID.randomUUID().toString();
    }
}
