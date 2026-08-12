// src/main/java/com/clickkart/auth/exception/InvalidCredentialsException.java
package com.clickkart.auth.exception;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
