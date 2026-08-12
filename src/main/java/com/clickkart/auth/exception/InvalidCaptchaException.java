// src/main/java/com/clickkart/auth/exception/InvalidCaptchaException.java
package com.clickkart.auth.exception;

/** Thrown when Captcha Service reports a missing, wrong, or expired/already-used challenge answer. */
public class InvalidCaptchaException extends RuntimeException {

    public InvalidCaptchaException(String message) {
        super(message);
    }
}
