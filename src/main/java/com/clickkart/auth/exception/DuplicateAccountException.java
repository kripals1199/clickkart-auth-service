// src/main/java/com/clickkart/auth/exception/DuplicateAccountException.java
package com.clickkart.auth.exception;

public class DuplicateAccountException extends RuntimeException {

    public DuplicateAccountException(String message) {
        super(message);
    }
}
