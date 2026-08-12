// src/main/java/com/clickkart/auth/exception/AccountLockedException.java
package com.clickkart.auth.exception;

import java.time.Instant;
import lombok.Getter;

@Getter
public class AccountLockedException extends RuntimeException {

    private final Instant lockedUntil;

    public AccountLockedException(String message, Instant lockedUntil) {
        super(message);
        this.lockedUntil = lockedUntil;
    }
}
