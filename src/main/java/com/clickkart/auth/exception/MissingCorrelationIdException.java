// src/main/java/com/clickkart/auth/exception/MissingCorrelationIdException.java
package com.clickkart.auth.exception;

/**
 * Thrown when a request reaches any endpoint other than register/login/refresh without a
 * valid correlationId claim in its (already signature/expiry/revocation-validated) JWT
 * (Rule 13). Auth Service never invents a substitute - it either has the value it minted at
 * login, or it rejects the request.
 */
public class MissingCorrelationIdException extends RuntimeException {

    public MissingCorrelationIdException(String message) {
        super(message);
    }
}
