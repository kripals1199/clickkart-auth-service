// src/main/java/com/clickkart/auth/service/PasswordResetService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.PasswordResetTokenEntity;
import com.clickkart.auth.exception.InvalidPasswordResetTokenException;
import java.time.Instant;

/** Owns issuance and one-time consumption of {@link PasswordResetTokenEntity}s. */
public interface PasswordResetService {

    record IssuedPasswordResetToken(PasswordResetTokenEntity entity, String rawValue) {}

    /**
     * Invalidates any still-outstanding token from an earlier request before issuing a new one -
     * only the most recently requested reset link is ever honored.
     */
    IssuedPasswordResetToken issue(ClickKartUserEntity clickKartUser, String correlationId, Instant now);

    /**
     * Validates and marks the presented raw token used in one locked step, returning the entity
     * (which carries the target {@code ClickKartUserEntity} and the original {@code correlationId} to
     * audit under).
     *
     * @throws InvalidPasswordResetTokenException for every rejection case - unknown, already
     *     used, or expired - a UI integrator has no legitimate reason to distinguish them.
     */
    PasswordResetTokenEntity consume(String rawToken, Instant now);
}
