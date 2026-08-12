// src/main/java/com/clickkart/auth/exception/InvalidPasswordResetTokenException.java
package com.clickkart.auth.exception;

public class InvalidPasswordResetTokenException extends RuntimeException {

    public InvalidPasswordResetTokenException(String message) {
        super(message);
    }
}
