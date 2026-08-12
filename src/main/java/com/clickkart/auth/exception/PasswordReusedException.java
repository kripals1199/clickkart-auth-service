// src/main/java/com/clickkart/auth/exception/PasswordReusedException.java
package com.clickkart.auth.exception;

public class PasswordReusedException extends RuntimeException {

    public PasswordReusedException(String message) {
        super(message);
    }
}
