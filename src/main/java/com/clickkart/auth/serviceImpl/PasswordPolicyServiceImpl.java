// src/main/java/com/clickkart/auth/serviceImpl/PasswordPolicyServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.PasswordHistoryEntity;
import com.clickkart.auth.exception.PasswordReusedException;
import com.clickkart.auth.repository.PasswordHistoryRepository;
import com.clickkart.auth.service.PasswordPolicyService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class PasswordPolicyServiceImpl implements PasswordPolicyService {

    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties authProperties;

    @Override
    @Transactional(readOnly = true, rollbackFor = Exception.class)
    public void assertNotReused(ClickKartUserEntity clickKartUser, String rawNewPassword) {
        List<PasswordHistoryEntity> recent = passwordHistoryRepository.findRecentByUserId(
                clickKartUser.getId(), authProperties.getPasswordHistoryLimit());

        boolean reused = recent.stream().anyMatch(history -> passwordEncoder.matches(rawNewPassword, history.getPasswordHash()));
        if (reused) {
            throw new PasswordReusedException(
                    "New password must not match any of your last " + authProperties.getPasswordHistoryLimit() + " passwords");
        }
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void record(ClickKartUserEntity clickKartUser, String passwordHash) {
        passwordHistoryRepository.save(new PasswordHistoryEntity(clickKartUser, passwordHash));
    }
}
