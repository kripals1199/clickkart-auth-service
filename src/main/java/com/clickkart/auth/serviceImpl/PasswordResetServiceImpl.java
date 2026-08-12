// src/main/java/com/clickkart/auth/serviceImpl/PasswordResetServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.PasswordResetTokenEntity;
import com.clickkart.auth.exception.InvalidPasswordResetTokenException;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.repository.PasswordResetTokenRepository;
import com.clickkart.auth.service.PasswordResetService;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class PasswordResetServiceImpl implements PasswordResetService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final JwtService jwtService;
    private final AuthProperties authProperties;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public IssuedPasswordResetToken issue(ClickKartUserEntity clickKartUser, String correlationId, Instant now) {
        passwordResetTokenRepository.invalidateAllOutstandingForUser(clickKartUser, now);

        String rawValue = jwtService.generateOpaqueToken(authProperties.getPasswordResetTokenBytes());
        PasswordResetTokenEntity entity = new PasswordResetTokenEntity(
                clickKartUser,
                jwtService.hashToken(rawValue),
                correlationId,
                now.plusSeconds(authProperties.getPasswordResetTokenTtlSeconds()));
        return new IssuedPasswordResetToken(passwordResetTokenRepository.save(entity), rawValue);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public PasswordResetTokenEntity consume(String rawToken, Instant now) {
        String tokenHash = jwtService.hashToken(rawToken);
        PasswordResetTokenEntity token = passwordResetTokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new InvalidPasswordResetTokenException("Password reset token is invalid or unknown"));

        if (!token.isUsable(now)) {
            throw new InvalidPasswordResetTokenException("Password reset token has expired or already been used");
        }

        token.markUsed(now);
        return token;
    }
}
