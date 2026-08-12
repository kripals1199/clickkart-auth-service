// src/main/java/com/clickkart/auth/exception/InvalidCurrentPasswordException.java
package com.clickkart.auth.exception;

public class InvalidCurrentPasswordException extends RuntimeException {

    public InvalidCurrentPasswordException(String message) {
        super(message);
    }
}
