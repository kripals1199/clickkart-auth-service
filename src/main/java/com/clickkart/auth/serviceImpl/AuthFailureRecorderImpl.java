// src/main/java/com/clickkart/auth/serviceImpl/AuthFailureRecorderImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginAuditEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.enums.LoginFailureReason;
import com.clickkart.auth.repository.ClickKartUserRepository;
import com.clickkart.auth.repository.LoginAuditRepository;
import com.clickkart.auth.repository.LoginOtpRepository;
import com.clickkart.auth.repository.RefreshTokenRepository;
import com.clickkart.auth.repository.VerificationCodeRepository;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthFailureRecorderImpl implements AuthFailureRecorder {

    /** {@code AuditLogEntryEntity.actor} convention for flows with no resolvable {@code ClickKartUserEntity}. */
    private static final String SYSTEM_ACTOR = "system";

    private final ClickKartUserRepository clickKartUserRepository;
    private final LoginAuditRepository loginAuditRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginOtpRepository loginOtpRepository;
    private final VerificationCodeRepository verificationCodeRepository;
    private final AuditTrailService auditTrailService;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
    public void recordLoginFailure(
            ClickKartUserEntity clickKartUser,
            String attemptedIdentifier,
            LoginFailureReason failureReason,
            AuditAction auditAction,
            String correlationId,
            RequestMetadata requestMetadata,
            String auditDetails) {
        if (clickKartUser != null) {
            clickKartUserRepository.save(clickKartUser);
        }

        loginAuditRepository.save(LoginAuditEntity.failure(
                clickKartUser,
                attemptedIdentifier,
                failureReason.name(),
                requestMetadata.ipAddress(),
                requestMetadata.userAgent(),
                correlationId));

        String actor = clickKartUser != null ? clickKartUser.getPublicId() : SYSTEM_ACTOR;
        auditTrailService.record(correlationId, actor, auditAction, AuditOutcome.FAILURE, requestMetadata, auditDetails);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
    public int revokeRefreshTokenFamilyAndRecordReuse(
            String correlationId, String actor, Instant now, RequestMetadata requestMetadata) {
        int revokedCount = refreshTokenRepository.revokeAllByCorrelationId(correlationId, now);
        auditTrailService.record(
                correlationId,
                actor,
                AuditAction.REFRESH_TOKEN_REUSE_DETECTED,
                AuditOutcome.FAILURE,
                requestMetadata,
                "familyTokensRevoked=" + revokedCount);
        return revokedCount;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
    public void recordOtpVerifyFailure(LoginOtpEntity otp) {
        loginOtpRepository.save(otp);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
    public void recordVerificationCodeFailure(
            VerificationCodeEntity code,
            AuditAction auditAction,
            String correlationId,
            String actor,
            RequestMetadata requestMetadata,
            String auditDetails) {
        verificationCodeRepository.save(code);
        auditTrailService.record(correlationId, actor, auditAction, AuditOutcome.FAILURE, requestMetadata, auditDetails);
    }
}
