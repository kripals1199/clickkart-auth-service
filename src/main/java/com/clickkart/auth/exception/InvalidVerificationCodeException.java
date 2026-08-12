// src/main/java/com/clickkart/auth/exception/InvalidVerificationCodeException.java
package com.clickkart.auth.exception;

public class InvalidVerificationCodeException extends RuntimeException {

    public InvalidVerificationCodeException(String message) {
        super(message);
    }
}
