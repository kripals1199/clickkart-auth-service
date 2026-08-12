// src/main/java/com/clickkart/auth/service/PasswordPolicyService.java
package com.clickkart.auth.service;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.exception.PasswordReusedException;

/**
 * The "cannot reuse your last N passwords" policy (Part 6) - a real bank/enterprise requirement.
 * {@code AuthServiceImpl.register()} also calls {@link #record} for the initial password, so
 * every later change/reset has a real history to compare against, including rejecting an
 * immediate change back to the current password.
 */
public interface PasswordPolicyService {

    /** @throws PasswordReusedException if {@code rawNewPassword} matches any of the account's last N password hashes. */
    void assertNotReused(ClickKartUserEntity clickKartUser, String rawNewPassword);

    void record(ClickKartUserEntity clickKartUser, String passwordHash);
}
