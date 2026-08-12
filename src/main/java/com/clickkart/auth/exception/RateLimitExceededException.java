// src/main/java/com/clickkart/auth/exception/RateLimitExceededException.java
package com.clickkart.auth.exception;

public class RateLimitExceededException extends RuntimeException {

    public RateLimitExceededException(String message) {
        super(message);
    }
}
