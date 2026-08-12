// src/main/java/com/clickkart/auth/serviceImpl/VerificationCodeServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.exception.InvalidVerificationCodeException;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.repository.VerificationCodeRepository;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.service.VerificationCodeService;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class VerificationCodeServiceImpl implements VerificationCodeService {

    private static final String GENERIC_REJECTION_MESSAGE = "Verification code is invalid, expired, or was never requested";

    private final VerificationCodeRepository verificationCodeRepository;
    private final JwtService jwtService;
    private final AuthProperties authProperties;
    private final AuthFailureRecorder authFailureRecorder;

    @Override
    public IssuedVerificationCode issue(ClickKartUserEntity clickKartUser, OtpChannel channel, String correlationId, Instant now) {
        verificationCodeRepository.invalidateAllOutstandingForUser(clickKartUser, channel, now);
        String rawValue = jwtService.generateNumericOtp(authProperties.getOtpLength());
        VerificationCodeEntity entity = new VerificationCodeEntity(
                clickKartUser,
                jwtService.hashToken(rawValue),
                channel,
                correlationId,
                now.plusSeconds(authProperties.getVerificationCodeTtlSeconds()));
        return new IssuedVerificationCode(verificationCodeRepository.save(entity), rawValue);
    }

    @Override
    public VerificationCodeEntity verify(
            ClickKartUserEntity clickKartUser,
            OtpChannel channel,
            String rawCode,
            Instant now,
            String correlationId,
            RequestMetadata requestMetadata) {
        VerificationCodeEntity code = verificationCodeRepository
                .findOutstanding(clickKartUser, channel)
                .orElseThrow(() -> new InvalidVerificationCodeException(GENERIC_REJECTION_MESSAGE));

        if (!code.isUsable(now)) {
            throw new InvalidVerificationCodeException(GENERIC_REJECTION_MESSAGE);
        }

        if (!code.getCodeHash().equals(jwtService.hashToken(rawCode))) {
            int attempts = code.increaseAttempts();
            if (attempts >= authProperties.getVerificationCodeMaxVerifyAttempts()) {
                code.markUsed(now);
            }
            authFailureRecorder.recordVerificationCodeFailure(
                    code,
                    AuditAction.CONTACT_VERIFY_FAILED,
                    correlationId,
                    clickKartUser.getPublicId(),
                    requestMetadata,
                    "channel=" + channel + " attempts=" + attempts);
            throw new InvalidVerificationCodeException(GENERIC_REJECTION_MESSAGE);
        }

        code.markUsed(now);
        return code;
    }
}
