// src/test/java/com/clickkart/auth/serviceimpl/AuthServiceImplTest.java
package com.clickkart.auth.serviceimpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.dto.request.ChangePasswordRequest;
import com.clickkart.auth.dto.request.ConfirmContactVerificationRequest;
import com.clickkart.auth.dto.request.ForgotPasswordRequest;
import com.clickkart.auth.dto.request.LoginRequest;
import com.clickkart.auth.dto.response.LoginResponse;
import com.clickkart.auth.dto.request.RegisterRequest;
import com.clickkart.auth.dto.request.RequestContactVerificationRequest;
import com.clickkart.auth.dto.request.RequestOtpRequest;
import com.clickkart.auth.dto.request.ResetPasswordRequest;
import com.clickkart.auth.dto.request.VerifyOtpRequest;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import com.clickkart.auth.entity.PasswordResetTokenEntity;
import com.clickkart.auth.entity.RefreshTokenEntity;
import com.clickkart.auth.entity.RoleEntity;
import com.clickkart.auth.entity.VerificationCodeEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.enums.RoleType;
import com.clickkart.auth.exception.AccountLockedException;
import com.clickkart.auth.exception.AccountNotFoundException;
import com.clickkart.auth.exception.DuplicateAccountException;
import com.clickkart.auth.exception.InvalidCredentialsException;
import com.clickkart.auth.exception.InvalidCurrentPasswordException;
import com.clickkart.auth.exception.InvalidOtpException;
import com.clickkart.auth.exception.InvalidVerificationCodeException;
import com.clickkart.auth.exception.PasswordReusedException;
import com.clickkart.auth.feign.CaptchaServiceClient;
import com.clickkart.auth.feign.CaptchaVerificationResult;
import com.clickkart.auth.feign.CaptchaVerifyApiResponse;
import com.clickkart.auth.repository.ClickKartUserRepository;
import com.clickkart.auth.repository.LoginAuditRepository;
import com.clickkart.auth.repository.RoleRepository;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.security.CorrelationIdGenerator;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.security.TokenRevocationLogoutHandler;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.service.OtpService;
import com.clickkart.auth.enums.LoginFailureReason;
import com.clickkart.auth.service.PasswordPolicyService;
import com.clickkart.auth.service.PasswordResetService;
import com.clickkart.auth.service.PasswordResetService.IssuedPasswordResetToken;
import com.clickkart.auth.service.RefreshTokenService;
import com.clickkart.auth.service.RefreshTokenService.IssuedRefreshToken;
import com.clickkart.auth.service.VerificationCodeService;
import com.clickkart.auth.serviceImpl.AuthServiceImpl;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final RequestMetadata REQUEST_METADATA = new RequestMetadata("127.0.0.1", "JUnit-Test-Agent");

    @Mock
    private ClickKartUserRepository clickKartUserRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private TokenRevocationLogoutHandler tokenRevocationLogoutHandler;

    @Mock
    private CorrelationIdGenerator correlationIdGenerator;

    @Mock
    private AuditTrailService auditTrailService;

    @Mock
    private LoginAuditRepository loginAuditRepository;

    @Mock
    private PasswordResetService passwordResetService;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private org.springframework.context.ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private CaptchaServiceClient captchaServiceClient;

    @Mock
    private AuthFailureRecorder authFailureRecorder;

    @Mock
    private OtpService otpService;

    @Mock
    private VerificationCodeService verificationCodeService;

    private AuthProperties authProperties;
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();
        authProperties.setMaxFailedLoginAttempts(3);
        authProperties.setLockoutDurationMinutes(15);
        authProperties.setAccessTokenTtlSeconds(900);
        authProperties.setRefreshTokenTtlSeconds(604800);
        authProperties.setPasswordHistoryLimit(5);

        // Every code path mints/reuses a correlation id; stubbed leniently here so individual
        // tests only need to override it when the value itself matters.
        lenient().when(correlationIdGenerator.generate()).thenReturn("correlation-id-1");
        // register()/forgotPassword() both gate on this; stubbed leniently to "valid" so tests
        // not focused on captcha behavior itself don't each need their own stub.
        lenient().when(captchaServiceClient.verify(anyString(), any()))
                .thenReturn(new CaptchaVerifyApiResponse(new CaptchaVerificationResult(true)));

        authService = new AuthServiceImpl(
                clickKartUserRepository,
                roleRepository,
                passwordEncoder,
                authenticationManager,
                jwtService,
                refreshTokenService,
                tokenRevocationLogoutHandler,
                correlationIdGenerator,
                authProperties,
                auditTrailService,
                loginAuditRepository,
                passwordResetService,
                passwordPolicyService,
                captchaServiceClient,
                applicationEventPublisher,
                authFailureRecorder,
                otpService,
                verificationCodeService);
    }

    private RoleEntity role(RoleType roleType) {
        RoleEntity role = new RoleEntity(roleType.name(), "test role");
        ReflectionTestUtils.setField(role, "id", 1L);
        return role;
    }

    private ClickKartUserEntity newUser(RoleType roleType) {
        ClickKartUserEntity clickKartUser =
                new ClickKartUserEntity("user@example.com", "9845550100", "hashed-password", Set.of(role(roleType)));
        ReflectionTestUtils.setField(clickKartUser, "id", 1L);
        return clickKartUser;
    }

    private IssuedRefreshToken issuedRefreshToken(ClickKartUserEntity clickKartUser, String correlationId) {
        RefreshTokenEntity entity = new RefreshTokenEntity(
                clickKartUser, "hashed-refresh-token-value", correlationId, Instant.now(), Instant.now().plusSeconds(604800));
        return new IssuedRefreshToken(entity, "raw-refresh-token-value");
    }

    private PasswordResetTokenEntity resetToken(ClickKartUserEntity clickKartUser, String correlationId) {
        PasswordResetTokenEntity token =
                new PasswordResetTokenEntity(clickKartUser, "hashed-reset-token-value", correlationId, Instant.now().plusSeconds(1800));
        ReflectionTestUtils.setField(token, "id", 1L);
        return token;
    }

    private LoginOtpEntity loginOtp(ClickKartUserEntity clickKartUser, String correlationId) {
        LoginOtpEntity otp = new LoginOtpEntity(
                clickKartUser, "hashed-otp-value", OtpChannel.SMS, correlationId, Instant.now().plusSeconds(300));
        ReflectionTestUtils.setField(otp, "id", 1L);
        return otp;
    }

    private VerificationCodeEntity verificationCode(ClickKartUserEntity clickKartUser, OtpChannel channel, String correlationId) {
        VerificationCodeEntity code = new VerificationCodeEntity(
                clickKartUser, "hashed-verification-code-value", channel, correlationId, Instant.now().plusSeconds(86400));
        ReflectionTestUtils.setField(code, "id", 1L);
        return code;
    }

    private AuthenticatedPrincipal principal(ClickKartUserEntity clickKartUser, String correlationId) {
        return new AuthenticatedPrincipal(
                clickKartUser.getPublicId(), Set.of("ROLE_CUSTOMER"), correlationId, "jti-123", Instant.now().plusSeconds(900));
    }

    @Test
    void registerRejectsDuplicateEmail() {
        when(clickKartUserRepository.existsByEmail("dup@example.com")).thenReturn(true);
        RegisterRequest request =
                new RegisterRequest("dup@example.com", "9845550111", "Str0ng!Passw0rd", "challenge-id-1", "ABC123");

        assertThrows(DuplicateAccountException.class, () -> authService.register(request, REQUEST_METADATA));
    }

    @Test
    void registerResolvesSeededRoleAndPersistsAccountAndRecordsAudit() {
        when(clickKartUserRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(clickKartUserRepository.existsByMobileNumber("9845550111")).thenReturn(false);
        when(roleRepository.findByName("ROLE_CUSTOMER")).thenReturn(Optional.of(role(RoleType.ROLE_CUSTOMER)));
        when(passwordEncoder.encode("Str0ng!Passw0rd")).thenReturn("hashed-password");
        when(clickKartUserRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtService.mintAccessToken(any(), any(), any()))
                .thenReturn(new JwtService.MintedAccessToken("access-token-value", "jti-123", Instant.now().plusSeconds(900)));
        when(refreshTokenService.issue(any(), anyString(), any()))
                .thenAnswer(invocation -> issuedRefreshToken(invocation.getArgument(0), invocation.getArgument(1)));

        RegisterRequest request =
                new RegisterRequest("new@example.com", "9845550111", "Str0ng!Passw0rd", "challenge-id-1", "ABC123");
        LoginResponse response = authService.register(request, REQUEST_METADATA);

        assertThat(response.user().email()).isEqualTo("new@example.com");
        assertThat(response.user().roles()).containsExactly("ROLE_CUSTOMER");
        assertThat(response.tokens().accessToken()).isEqualTo("access-token-value");
        assertThat(response.tokens().refreshToken()).isEqualTo("raw-refresh-token-value");
        verify(passwordPolicyService).record(any(), eq("hashed-password"));
        verify(auditTrailService)
                .record(anyString(), anyString(), eq(AuditAction.REGISTER), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void loginFailsWithInvalidCredentialsAndIncrementsFailedAttemptsOnWrongPassword() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad credentials"));

        LoginRequest request = new LoginRequest("user@example.com", "wrong-password");

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, REQUEST_METADATA));

        assertThat(clickKartUser.getFailedLoginAttempts()).isEqualTo(1);
        // Persisted via authFailureRecorder (its own REQUIRES_NEW transaction), not directly -
        // see AuthFailureRecorder's Javadoc for why.
        verify(authFailureRecorder)
                .recordLoginFailure(eq(clickKartUser), anyString(), eq(LoginFailureReason.BAD_PASSWORD),
                        eq(AuditAction.LOGIN_FAILED), anyString(), eq(REQUEST_METADATA), anyString());
    }

    @Test
    void loginLocksAccountAfterMaxFailedAttempts() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        // Simulate 2 prior failures; the 3rd (max) should trip the lock.
        clickKartUser.increaseFailedAttempts();
        clickKartUser.increaseFailedAttempts();
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad credentials"));

        LoginRequest request = new LoginRequest("user@example.com", "still-wrong");
        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, REQUEST_METADATA));

        assertThat(clickKartUser.isAccountNonLocked()).isFalse();
    }

    @Test
    void loginRejectsAlreadyLockedAccountWithoutCheckingPassword() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        clickKartUser.lock();
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));

        LoginRequest request = new LoginRequest("user@example.com", "irrelevant");

        assertThrows(AccountLockedException.class, () -> authService.login(request, REQUEST_METADATA));
        verify(authFailureRecorder)
                .recordLoginFailure(eq(clickKartUser), anyString(), eq(LoginFailureReason.ACCOUNT_LOCKED),
                        eq(AuditAction.LOGIN_FAILED), anyString(), eq(REQUEST_METADATA), anyString());
    }

    @Test
    void loginRejectsUnknownIdentifierAndRecordsLoginAuditAndAuditTrail() {
        when(clickKartUserRepository.findByPublicId("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByMobileNumber("nobody@example.com")).thenReturn(Optional.empty());

        LoginRequest request = new LoginRequest("nobody@example.com", "irrelevant");

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, REQUEST_METADATA));
        verify(authFailureRecorder)
                .recordLoginFailure(isNull(), anyString(), eq(LoginFailureReason.UNKNOWN_IDENTIFIER),
                        eq(AuditAction.LOGIN_FAILED), anyString(), eq(REQUEST_METADATA), anyString());
    }

    @Test
    void loginAutoUnlocksAndSucceedsOnceLockoutWindowHasElapsed() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        clickKartUser.lock();
        // Backdate the lock past the 15-minute lockout window configured in setUp().
        ReflectionTestUtils.setField(clickKartUser, "lockTime", Instant.now().minusSeconds(20 * 60));

        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenReturn(null);
        when(jwtService.mintAccessToken(any(), any(), any()))
                .thenReturn(new JwtService.MintedAccessToken("access-token-value", "jti-123", Instant.now().plusSeconds(900)));
        when(refreshTokenService.issue(eq(clickKartUser), anyString(), any()))
                .thenAnswer(invocation -> issuedRefreshToken(clickKartUser, invocation.getArgument(1)));

        LoginRequest request = new LoginRequest("user@example.com", "correct-password");
        LoginResponse response = authService.login(request, REQUEST_METADATA);

        assertThat(response.tokens().accessToken()).isEqualTo("access-token-value");
        assertThat(response.user().email()).isEqualTo("user@example.com");
        assertThat(clickKartUser.isAccountNonLocked()).isTrue();
    }

    @Test
    void loginSucceedsMintsTokensAndResetsFailedAttempts() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        // Simulate one prior failed attempt (below the max(3) threshold, so not locked).
        ReflectionTestUtils.setField(clickKartUser, "failedLoginAttempts", 1);

        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenReturn(null);
        when(jwtService.mintAccessToken(any(), any(), any()))
                .thenReturn(new JwtService.MintedAccessToken("access-token-value", "jti-123", Instant.now().plusSeconds(900)));
        when(refreshTokenService.issue(eq(clickKartUser), anyString(), any()))
                .thenAnswer(invocation -> issuedRefreshToken(clickKartUser, invocation.getArgument(1)));

        LoginRequest request = new LoginRequest("user@example.com", "correct-password");
        LoginResponse response = authService.login(request, REQUEST_METADATA);

        assertThat(response.tokens().accessToken()).isEqualTo("access-token-value");
        assertThat(response.tokens().refreshToken()).isEqualTo("raw-refresh-token-value");
        assertThat(response.tokens().tokenType()).isEqualTo("Bearer");
        assertThat(response.user().publicId()).isEqualTo(clickKartUser.getPublicId());
        assertThat(clickKartUser.getFailedLoginAttempts()).isZero();
        verify(refreshTokenService).issue(eq(clickKartUser), anyString(), any());
        verify(loginAuditRepository).save(any());
        verify(auditTrailService)
                .record(anyString(), eq(clickKartUser.getPublicId()), eq(AuditAction.LOGIN_SUCCESS), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void forgotPasswordDoesNothingObservableWhenIdentifierIsUnknown() {
        when(clickKartUserRepository.findByPublicId("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByMobileNumber("nobody@example.com")).thenReturn(Optional.empty());

        authService.forgotPassword(
                new ForgotPasswordRequest("nobody@example.com", "challenge-id-1", "ABC123"), REQUEST_METADATA);

        verifyNoInteractions(passwordResetService, applicationEventPublisher, auditTrailService);
    }

    @Test
    void forgotPasswordIssuesTokenAndDispatchesNotificationWhenIdentifierResolves() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(passwordResetService.issue(eq(clickKartUser), anyString(), any())).thenAnswer(invocation -> {
            PasswordResetTokenEntity token = resetToken(clickKartUser, invocation.getArgument(1));
            return new IssuedPasswordResetToken(token, "raw-reset-token-value");
        });

        authService.forgotPassword(
                new ForgotPasswordRequest("user@example.com", "challenge-id-1", "ABC123"), REQUEST_METADATA);

        // Published, not sent inline - dispatch is bound to AFTER_COMMIT so the token is durably
        // stored before the email carrying it leaves. See NotificationDispatchListener.
        verify(applicationEventPublisher).publishEvent(argThat((Object e) ->
                e instanceof com.clickkart.auth.event.PasswordResetNotificationEvent ev
                        && ev.request().rawResetToken().equals("raw-reset-token-value")));
        verify(auditTrailService)
                .record(anyString(), eq(clickKartUser.getPublicId()), eq(AuditAction.FORGOT_PASSWORD_REQUESTED), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void resetPasswordAppliesNewPasswordAndUnlocksAccount() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        clickKartUser.lock();
        PasswordResetTokenEntity token = resetToken(clickKartUser, "correlation-id-1");
        when(passwordResetService.consume(eq("raw-reset-token-value"), any())).thenReturn(token);
        when(passwordEncoder.encode("N3wStr0ng!Passw0rd")).thenReturn("new-hashed-password");

        authService.resetPassword(new ResetPasswordRequest("raw-reset-token-value", "N3wStr0ng!Passw0rd"), REQUEST_METADATA);

        assertThat(clickKartUser.getPasswordHash()).isEqualTo("new-hashed-password");
        assertThat(clickKartUser.isAccountNonLocked()).isTrue();
        verify(passwordPolicyService).assertNotReused(clickKartUser, "N3wStr0ng!Passw0rd");
        verify(passwordPolicyService).record(clickKartUser, "new-hashed-password");
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(clickKartUser.getPublicId()), eq(AuditAction.PASSWORD_RESET_COMPLETED), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void resetPasswordPropagatesReusedPasswordRejection() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        PasswordResetTokenEntity token = resetToken(clickKartUser, "correlation-id-1");
        when(passwordResetService.consume(eq("raw-reset-token-value"), any())).thenReturn(token);
        org.mockito.Mockito.doThrow(new PasswordReusedException("reused"))
                .when(passwordPolicyService)
                .assertNotReused(eq(clickKartUser), anyString());

        assertThrows(
                PasswordReusedException.class,
                () -> authService.resetPassword(new ResetPasswordRequest("raw-reset-token-value", "OldStr0ng!Passw0rd"), REQUEST_METADATA));

        verify(clickKartUserRepository, never()).save(any());
    }

    @Test
    void requestOtpDoesNothingObservableWhenIdentifierIsUnknown() {
        when(clickKartUserRepository.findByPublicId("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());
        when(clickKartUserRepository.findByMobileNumber("nobody@example.com")).thenReturn(Optional.empty());

        authService.requestOtp(new RequestOtpRequest("nobody@example.com", OtpChannel.SMS), REQUEST_METADATA);

        verifyNoInteractions(otpService, applicationEventPublisher, auditTrailService);
    }

    @Test
    void requestOtpIssuesCodeAndDispatchesSmsWhenIdentifierResolves() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(otpService.issue(eq(clickKartUser), eq(OtpChannel.SMS), anyString(), any())).thenAnswer(invocation -> {
            LoginOtpEntity otp = loginOtp(clickKartUser, invocation.getArgument(2));
            return new OtpService.IssuedOtp(otp, "042817");
        });

        authService.requestOtp(new RequestOtpRequest("user@example.com", OtpChannel.SMS), REQUEST_METADATA);

        verify(applicationEventPublisher).publishEvent(argThat((Object e) ->
                e instanceof com.clickkart.auth.event.OtpNotificationEvent ev
                        && ev.request().rawOtp().equals("042817") && ev.request().channel() == OtpChannel.SMS));
        verify(auditTrailService)
                .record(anyString(), eq(clickKartUser.getPublicId()), eq(AuditAction.OTP_REQUESTED), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void verifyOtpSucceedsMintsTokensAndResetsFailedAttempts() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        ReflectionTestUtils.setField(clickKartUser, "failedLoginAttempts", 1);
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(otpService.verify(eq(clickKartUser), eq("042817"), any())).thenReturn(loginOtp(clickKartUser, "correlation-id-1"));
        when(jwtService.mintAccessToken(any(), any(), any()))
                .thenReturn(new JwtService.MintedAccessToken("access-token-value", "jti-123", Instant.now().plusSeconds(900)));
        when(refreshTokenService.issue(eq(clickKartUser), anyString(), any()))
                .thenAnswer(invocation -> issuedRefreshToken(clickKartUser, invocation.getArgument(1)));

        LoginResponse response = authService.verifyOtp(new VerifyOtpRequest("user@example.com", "042817"), REQUEST_METADATA);

        assertThat(response.tokens().accessToken()).isEqualTo("access-token-value");
        assertThat(clickKartUser.getFailedLoginAttempts()).isZero();
        verify(auditTrailService)
                .record(anyString(), eq(clickKartUser.getPublicId()), eq(AuditAction.OTP_LOGIN_SUCCESS), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void verifyOtpFailsWithInvalidCredentialsAndIncrementsFailedAttemptsOnWrongCode() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        when(clickKartUserRepository.findByEmail("user@example.com")).thenReturn(Optional.of(clickKartUser));
        when(otpService.verify(eq(clickKartUser), eq("999999"), any())).thenThrow(new InvalidOtpException("wrong"));

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.verifyOtp(new VerifyOtpRequest("user@example.com", "999999"), REQUEST_METADATA));

        assertThat(clickKartUser.getFailedLoginAttempts()).isEqualTo(1);
        verify(authFailureRecorder)
                .recordLoginFailure(eq(clickKartUser), anyString(), eq(LoginFailureReason.INVALID_OTP),
                        eq(AuditAction.OTP_LOGIN_FAILED), anyString(), eq(REQUEST_METADATA), anyString());
    }

    @Test
    void changePasswordRejectsWrongCurrentPassword() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        AuthenticatedPrincipal principal = principal(clickKartUser, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad credentials"));

        ChangePasswordRequest request = new ChangePasswordRequest("wrong-current", "N3wStr0ng!Passw0rd");

        assertThrows(InvalidCurrentPasswordException.class, () -> authService.changePassword(principal, request, REQUEST_METADATA));
        verify(clickKartUserRepository, never()).save(any());
    }

    @Test
    void changePasswordSucceedsAndRecordsHistory() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        AuthenticatedPrincipal principal = principal(clickKartUser, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));
        when(authenticationManager.authenticate(any())).thenReturn(null);
        when(passwordEncoder.encode("N3wStr0ng!Passw0rd")).thenReturn("new-hashed-password");

        ChangePasswordRequest request = new ChangePasswordRequest("correct-current", "N3wStr0ng!Passw0rd");
        authService.changePassword(principal, request, REQUEST_METADATA);

        assertThat(clickKartUser.getPasswordHash()).isEqualTo("new-hashed-password");
        verify(passwordPolicyService).record(clickKartUser, "new-hashed-password");
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(clickKartUser.getPublicId()), eq(AuditAction.PASSWORD_CHANGED), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void lockAccountThrowsWhenAccountNotFound() {
        when(clickKartUserRepository.findByPublicId("USR-missing")).thenReturn(Optional.empty());
        ClickKartUserEntity admin = newUser(RoleType.ROLE_ADMIN);
        AuthenticatedPrincipal adminPrincipal = principal(admin, "correlation-id-1");

        assertThrows(
                AccountNotFoundException.class, () -> authService.lockAccount("USR-missing", adminPrincipal, REQUEST_METADATA));
    }

    @Test
    void lockAccountLocksAndReturnsUpdatedSummary() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        ClickKartUserEntity admin = newUser(RoleType.ROLE_ADMIN);
        AuthenticatedPrincipal adminPrincipal = principal(admin, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));

        var response = authService.lockAccount(clickKartUser.getPublicId(), adminPrincipal, REQUEST_METADATA);

        assertThat(response.locked()).isTrue();
        // Locking must actually end existing sessions, not just block new ones - see
        // TokenRevocationLogoutHandler.revokeAllActiveTokensForAccount's Javadoc.
        verify(tokenRevocationLogoutHandler).revokeAllActiveTokensForAccount(clickKartUser);
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(admin.getPublicId()), eq(AuditAction.ACCOUNT_LOCKED_BY_ADMIN), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void unlockAccountUnlocksAndReturnsUpdatedSummary() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        clickKartUser.lock();
        ClickKartUserEntity admin = newUser(RoleType.ROLE_ADMIN);
        AuthenticatedPrincipal adminPrincipal = principal(admin, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));

        var response = authService.unlockAccount(clickKartUser.getPublicId(), adminPrincipal, REQUEST_METADATA);

        assertThat(response.locked()).isFalse();
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(admin.getPublicId()), eq(AuditAction.ACCOUNT_UNLOCKED_BY_ADMIN), eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void requestContactVerificationIssuesCodeAndDispatchesEmailNotification() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        AuthenticatedPrincipal principal = principal(clickKartUser, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));
        when(verificationCodeService.issue(eq(clickKartUser), eq(OtpChannel.EMAIL), eq("correlation-id-1"), any()))
                .thenAnswer(invocation -> new VerificationCodeService.IssuedVerificationCode(
                        verificationCode(clickKartUser, OtpChannel.EMAIL, "correlation-id-1"), "042817"));

        authService.requestContactVerification(
                principal, new RequestContactVerificationRequest(OtpChannel.EMAIL), REQUEST_METADATA);

        verify(applicationEventPublisher).publishEvent(argThat((Object e) ->
                e instanceof com.clickkart.auth.event.OtpNotificationEvent ev
                        && ev.correlationId().equals("correlation-id-1")
                        && ev.request().rawOtp().equals("042817") && ev.request().channel() == OtpChannel.EMAIL));
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(clickKartUser.getPublicId()), eq(AuditAction.CONTACT_VERIFY_REQUESTED),
                        eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void confirmContactVerificationMarksEmailVerifiedOnSuccess() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        AuthenticatedPrincipal principal = principal(clickKartUser, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));
        when(verificationCodeService.verify(eq(clickKartUser), eq(OtpChannel.EMAIL), eq("042817"), any(), eq("correlation-id-1"), eq(REQUEST_METADATA)))
                .thenReturn(verificationCode(clickKartUser, OtpChannel.EMAIL, "correlation-id-1"));

        authService.confirmContactVerification(
                principal, new ConfirmContactVerificationRequest(OtpChannel.EMAIL, "042817"), REQUEST_METADATA);

        assertThat(clickKartUser.isEmailVerified()).isTrue();
        assertThat(clickKartUser.isMobileVerified()).isFalse();
        verify(clickKartUserRepository).save(clickKartUser);
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(clickKartUser.getPublicId()), eq(AuditAction.CONTACT_VERIFIED),
                        eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }

    @Test
    void confirmContactVerificationPropagatesInvalidCodeWithoutMarkingVerified() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        AuthenticatedPrincipal principal = principal(clickKartUser, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));
        when(verificationCodeService.verify(eq(clickKartUser), eq(OtpChannel.SMS), eq("999999"), any(), eq("correlation-id-1"), eq(REQUEST_METADATA)))
                .thenThrow(new InvalidVerificationCodeException("wrong"));

        assertThrows(
                InvalidVerificationCodeException.class,
                () -> authService.confirmContactVerification(
                        principal, new ConfirmContactVerificationRequest(OtpChannel.SMS, "999999"), REQUEST_METADATA));

        assertThat(clickKartUser.isMobileVerified()).isFalse();
        verify(clickKartUserRepository, never()).save(any());
    }

    @Test
    void deleteAccountThrowsWhenAccountNotFound() {
        when(clickKartUserRepository.findByPublicId("USR-missing")).thenReturn(Optional.empty());
        ClickKartUserEntity admin = newUser(RoleType.ROLE_ADMIN);
        AuthenticatedPrincipal adminPrincipal = principal(admin, "correlation-id-1");

        assertThrows(
                AccountNotFoundException.class, () -> authService.deleteAccount("USR-missing", adminPrincipal, REQUEST_METADATA));
    }

    @Test
    void deleteAccountSoftDeletesRevokesTokensAndReturnsUpdatedSummary() {
        ClickKartUserEntity clickKartUser = newUser(RoleType.ROLE_CUSTOMER);
        ClickKartUserEntity admin = newUser(RoleType.ROLE_ADMIN);
        AuthenticatedPrincipal adminPrincipal = principal(admin, "correlation-id-1");
        when(clickKartUserRepository.findByPublicId(clickKartUser.getPublicId())).thenReturn(Optional.of(clickKartUser));

        var response = authService.deleteAccount(clickKartUser.getPublicId(), adminPrincipal, REQUEST_METADATA);

        assertThat(clickKartUser.isDeleted()).isTrue();
        assertThat(clickKartUser.isEnabled()).isFalse();
        assertThat(response.publicId()).isEqualTo(clickKartUser.getPublicId());
        verify(tokenRevocationLogoutHandler).revokeAllActiveTokensForAccount(clickKartUser);
        verify(auditTrailService)
                .record(eq("correlation-id-1"), eq(admin.getPublicId()), eq(AuditAction.ACCOUNT_DELETED_BY_ADMIN),
                        eq(AuditOutcome.SUCCESS), eq(REQUEST_METADATA), any());
    }
}
