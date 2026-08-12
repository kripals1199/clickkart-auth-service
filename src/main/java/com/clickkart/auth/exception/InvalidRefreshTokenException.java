// src/main/java/com/clickkart/auth/exception/InvalidRefreshTokenException.java
package com.clickkart.auth.exception;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
