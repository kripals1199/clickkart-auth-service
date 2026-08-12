// src/main/java/com/clickkart/auth/service/AuthService.java
package com.clickkart.auth.service;

import com.clickkart.auth.dto.request.ChangePasswordRequest;
import com.clickkart.auth.dto.request.ConfirmContactVerificationRequest;
import com.clickkart.auth.dto.request.ForgotPasswordRequest;
import com.clickkart.auth.dto.request.LoginRequest;
import com.clickkart.auth.dto.request.LogoutRequest;
import com.clickkart.auth.dto.request.RefreshRequest;
import com.clickkart.auth.dto.request.RegisterRequest;
import com.clickkart.auth.dto.request.RequestContactVerificationRequest;
import com.clickkart.auth.dto.request.RequestOtpRequest;
import com.clickkart.auth.dto.request.ResetPasswordRequest;
import com.clickkart.auth.dto.request.VerifyOtpRequest;
import com.clickkart.auth.dto.response.AuthTokenResponse;
import com.clickkart.auth.dto.response.LoginResponse;
import com.clickkart.auth.dto.response.ClickKartUserSummaryResponse;
import com.clickkart.auth.enums.RoleType;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.web.RequestMetadata;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuthService {

    /** Registration also establishes a session - the response carries the same access/refresh pair {@link #login} would. */
    LoginResponse register(RegisterRequest request, RequestMetadata requestMetadata);

    LoginResponse login(LoginRequest request, RequestMetadata requestMetadata);

    AuthTokenResponse refresh(RefreshRequest request, RequestMetadata requestMetadata);

    void logout(AuthenticatedPrincipal principal, LogoutRequest request, RequestMetadata requestMetadata);

    Page<ClickKartUserSummaryResponse> listAccounts(
            RoleType roleType,
            Boolean locked,
            String emailContains,
            Pageable pageable,
            AuthenticatedPrincipal admin,
            RequestMetadata requestMetadata);

    /**
     * Always completes normally whether or not {@code request.identifier()} resolves to an
     * account - the caller must respond identically either way so as not to reveal account
     * existence (Rule: never leak identifier existence through timing or response shape).
     */
    void forgotPassword(ForgotPasswordRequest request, RequestMetadata requestMetadata);

    void resetPassword(ResetPasswordRequest request, RequestMetadata requestMetadata);

    /**
     * Always completes normally whether or not {@code request.identifier()} resolves to an
     * account - same non-revealing contract as {@link #forgotPassword}.
     */
    void requestOtp(RequestOtpRequest request, RequestMetadata requestMetadata);

    /** Alternative to password login (Rule: OTP is a parallel path, not a second factor) - mints the same tokens {@link #login} would. */
    LoginResponse verifyOtp(VerifyOtpRequest request, RequestMetadata requestMetadata);

    void changePassword(AuthenticatedPrincipal principal, ChangePasswordRequest request, RequestMetadata requestMetadata);

    ClickKartUserSummaryResponse lockAccount(String publicId, AuthenticatedPrincipal admin, RequestMetadata requestMetadata);

    ClickKartUserSummaryResponse unlockAccount(String publicId, AuthenticatedPrincipal admin, RequestMetadata requestMetadata);

    /** Authenticated self-service - issues a verification code for the caller's own email or mobile number, per {@code request.channel()}. */
    void requestContactVerification(
            AuthenticatedPrincipal principal, RequestContactVerificationRequest request, RequestMetadata requestMetadata);

    /** Marks the caller's own email or mobile number verified once the presented code checks out. */
    void confirmContactVerification(
            AuthenticatedPrincipal principal, ConfirmContactVerificationRequest request, RequestMetadata requestMetadata);

    /**
     * ADMIN-only soft delete (Rule: {@code ClickKartUserEntity} is never hard-deleted) - also
     * revokes every active refresh token for the account, so it can no longer refresh its way to
     * a new access token even though its current one remains valid until natural expiry (see
     * {@code TokenRevocationLogoutHandler.revokeAllActiveTokensForAccount(ClickKartUserEntity)}).
     */
    ClickKartUserSummaryResponse deleteAccount(String publicId, AuthenticatedPrincipal admin, RequestMetadata requestMetadata);
}
