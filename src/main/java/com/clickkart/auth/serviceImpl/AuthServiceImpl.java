// src/main/java/com/clickkart/auth/serviceImpl/AuthServiceImpl.java
package com.clickkart.auth.serviceImpl;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.constant.MdcKeys;
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
import com.clickkart.auth.dto.response.ClickKartUserSummaryResponse;
import com.clickkart.auth.dto.response.LoginResponse;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginAuditEntity;
import com.clickkart.auth.entity.PasswordResetTokenEntity;
import com.clickkart.auth.entity.RoleEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.enums.LoginFailureReason;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.enums.RoleType;
import com.clickkart.auth.exception.AccountLockedException;
import com.clickkart.auth.exception.AccountNotFoundException;
import com.clickkart.auth.exception.DuplicateAccountException;
import com.clickkart.auth.exception.InvalidCredentialsException;
import com.clickkart.auth.exception.InvalidCaptchaException;
import com.clickkart.auth.exception.InvalidCurrentPasswordException;
import com.clickkart.auth.exception.InvalidOtpException;
import com.clickkart.auth.exception.InvalidRefreshTokenException;
import com.clickkart.auth.feign.CaptchaServiceClient;
import com.clickkart.auth.feign.NotificationServiceClient;
import com.clickkart.auth.feign.OtpNotificationRequest;
import com.clickkart.auth.feign.PasswordResetNotificationRequest;
import com.clickkart.auth.feign.VerifyCaptchaRequest;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.jwt.JwtService.MintedAccessToken;
import com.clickkart.auth.repository.ClickKartUserRepository;
import com.clickkart.auth.repository.ClickKartUserSpecifications;
import com.clickkart.auth.repository.LoginAuditRepository;
import com.clickkart.auth.repository.RoleRepository;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.security.CorrelationIdGenerator;
import com.clickkart.auth.security.TokenRevocationLogoutHandler;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.service.AuthService;
import com.clickkart.auth.service.OtpService;
import com.clickkart.auth.service.OtpService.IssuedOtp;
import com.clickkart.auth.service.PasswordPolicyService;
import com.clickkart.auth.service.PasswordResetService;
import com.clickkart.auth.service.PasswordResetService.IssuedPasswordResetToken;
import com.clickkart.auth.service.RefreshTokenService;
import com.clickkart.auth.service.RefreshTokenService.IssuedRefreshToken;
import com.clickkart.auth.service.VerificationCodeService;
import com.clickkart.auth.service.VerificationCodeService.IssuedVerificationCode;
import com.clickkart.auth.web.RequestMetadata;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j(topic = LoggerNames.SECURITY)
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class AuthServiceImpl implements AuthService {

	private final ClickKartUserRepository clickKartUserRepository;
	private final RoleRepository roleRepository;
	private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService;
	private final TokenRevocationLogoutHandler tokenRevocationLogoutHandler;
	private final CorrelationIdGenerator correlationIdGenerator;
	private final AuthProperties authProperties;
	private final AuditTrailService auditTrailService;
	private final LoginAuditRepository loginAuditRepository;
	private final PasswordResetService passwordResetService;
	private final PasswordPolicyService passwordPolicyService;
	private final NotificationServiceClient notificationServiceClient;
	private final CaptchaServiceClient captchaServiceClient;
	private final AuthFailureRecorder authFailureRecorder;
	private final OtpService otpService;
	private final VerificationCodeService verificationCodeService;

	@Override
	@Transactional(rollbackFor = Exception.class)
	public LoginResponse register(RegisterRequest request, RequestMetadata requestMetadata) {
		String correlationId = mintCorrelationId();
		verifyCaptcha(correlationId, request.captchaChallengeId(), request.captchaAnswer());

		String email = request.email().toLowerCase().trim();
		String mobileNumber = request.mobileNumber().trim();
		if (clickKartUserRepository.existsByEmail(email)) {
			throw new DuplicateAccountException("An account already exists for this email address");
		}
		if (clickKartUserRepository.existsByMobileNumber(mobileNumber)) {
			throw new DuplicateAccountException("An account already exists for this mobile number");
		}

		// Baseline roles are seeded at startup (RoleSeeder) - a missing row here means
		// the
		// seeder didn't run, a real config/deployment problem, not a normal user-facing
		// error.
		RoleEntity role = roleRepository.findByName(RoleType.ROLE_CUSTOMER.name()).orElseThrow(
				() -> new IllegalStateException("Baseline role not seeded: " + RoleType.ROLE_CUSTOMER.name()));

		String passwordHash = passwordEncoder.encode(request.password());
		ClickKartUserEntity clickKartUser = new ClickKartUserEntity(email, mobileNumber, passwordHash, Set.of(role));
		clickKartUser = clickKartUserRepository.save(clickKartUser);
		passwordPolicyService.record(clickKartUser, passwordHash);

		Instant now = Instant.now();
		auditTrailService.record(correlationId, clickKartUser.getPublicId(), AuditAction.REGISTER, AuditOutcome.SUCCESS,requestMetadata, null);

		// New requirement: registration also establishes a session, same as login -
		// mint the
		// same access/refresh pair under the same correlationId so the client doesn't
		// need a
		// separate /login call right after signing up.
		Set<String> roleNames = roleNamesOf(clickKartUser);
		MintedAccessToken accessToken = jwtService.mintAccessToken(clickKartUser.getPublicId(), roleNames,correlationId);
		IssuedRefreshToken refreshToken = refreshTokenService.issue(clickKartUser, correlationId, now);

		AuthTokenResponse tokens = AuthTokenResponse.bearer(accessToken.token(), refreshToken.rawValue(),authProperties.getAccessTokenTtlSeconds());
		return new LoginResponse(tokens, ClickKartUserSummaryResponse.from(clickKartUser));
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public LoginResponse login(LoginRequest request, RequestMetadata requestMetadata) {
		String identifier=request.identifier();
		Instant now = Instant.now();
		String correlationId = mintCorrelationId();
		Optional<ClickKartUserEntity> maybeUser = resolveIdentifier(identifier);

		if (maybeUser.isEmpty()) {
			log.warn("LOGIN_REJECTED_UNKNOWN_IDENTIFIER ipAddress={} correlationId={}", requestMetadata.ipAddress(),correlationId);
			// Recorded via authFailureRecorder (its own REQUIRES_NEW transaction), not directly
			// here - this method is about to throw, and the resulting rollback would otherwise
			// silently undo the LoginAuditEntity/AuditLogEntryEntity writes along with it.
			authFailureRecorder.recordLoginFailure(
					null, identifier, LoginFailureReason.UNKNOWN_IDENTIFIER, AuditAction.LOGIN_FAILED,
					correlationId, requestMetadata, "reason=" + LoginFailureReason.UNKNOWN_IDENTIFIER);
			throw new InvalidCredentialsException("Invalid credentials");
		}

		ClickKartUserEntity clickKartUser = maybeUser.get();
		assertNotLocked(clickKartUser, now, identifier, AuditAction.LOGIN_FAILED, correlationId, requestMetadata);

		if (!clickKartUser.isEnabled() || !passwordMatches(clickKartUser, request.password())) {
			LoginFailureReason failureReason = !clickKartUser.isEnabled() ? LoginFailureReason.ACCOUNT_DISABLED: LoginFailureReason.BAD_PASSWORD;
			recordFailedLoginAttempt(clickKartUser, identifier, failureReason, AuditAction.LOGIN_FAILED, correlationId, requestMetadata);
			throw new InvalidCredentialsException("Invalid credentials");
		}

		return completeSuccessfulLogin(clickKartUser, identifier, correlationId, now, requestMetadata, AuditAction.LOGIN_SUCCESS);
	}

	/**
	 * Full alternative to password login (not a second factor) - identifier + a valid OTP mints
	 * the same tokens {@link #login} would. Reuses the exact same account-lockout/failed-attempt
	 * machinery as password login, so a wrong-OTP guess counts toward, and is subject to, the
	 * same account-level lockout a wrong password would trigger.
	 */
	@Override
	@Transactional(rollbackFor = Exception.class)
	public LoginResponse verifyOtp(VerifyOtpRequest request, RequestMetadata requestMetadata) {
		String identifier = request.identifier();
		Instant now = Instant.now();
		String correlationId = mintCorrelationId();
		Optional<ClickKartUserEntity> maybeUser = resolveIdentifier(identifier);

		if (maybeUser.isEmpty()) {
			log.warn("OTP_LOGIN_REJECTED_UNKNOWN_IDENTIFIER ipAddress={} correlationId={}", requestMetadata.ipAddress(), correlationId);
			authFailureRecorder.recordLoginFailure(
					null, identifier, LoginFailureReason.UNKNOWN_IDENTIFIER, AuditAction.OTP_LOGIN_FAILED,
					correlationId, requestMetadata, "reason=" + LoginFailureReason.UNKNOWN_IDENTIFIER);
			throw new InvalidCredentialsException("Invalid credentials");
		}

		ClickKartUserEntity clickKartUser = maybeUser.get();
		assertNotLocked(clickKartUser, now, identifier, AuditAction.OTP_LOGIN_FAILED, correlationId, requestMetadata);

		LoginFailureReason failureReason = null;
		if (!clickKartUser.isEnabled()) {
			failureReason = LoginFailureReason.ACCOUNT_DISABLED;
		} else {
			try {
				otpService.verify(clickKartUser, request.otp(), now);
			} catch (InvalidOtpException e) {
				failureReason = LoginFailureReason.INVALID_OTP;
			}
		}

		if (failureReason != null) {
			recordFailedLoginAttempt(clickKartUser, identifier, failureReason, AuditAction.OTP_LOGIN_FAILED, correlationId, requestMetadata);
			throw new InvalidCredentialsException("Invalid credentials");
		}

		return completeSuccessfulLogin(clickKartUser, identifier, correlationId, now, requestMetadata, AuditAction.OTP_LOGIN_SUCCESS);
	}

	/** Rejects with {@link AccountLockedException} (after recording it) if still within the lockout window; auto-unlocks and returns normally once it has elapsed. */
	private void assertNotLocked(ClickKartUserEntity clickKartUser, Instant now, String identifier,
			AuditAction failureAuditAction, String correlationId, RequestMetadata requestMetadata) {
		if (clickKartUser.isAccountNonLocked()) {
			return;
		}

		Duration lockoutDuration = Duration.ofMinutes(authProperties.getLockoutDurationMinutes());
		if (clickKartUser.isLockExpired(now, lockoutDuration)) {
			clickKartUser.unlock();
			clickKartUserRepository.save(clickKartUser);
			return;
		}

		Instant lockedUntil = clickKartUser.getLockTime().plus(lockoutDuration);
		log.warn("LOGIN_REJECTED_LOCKED publicId={} ipAddress={} lockedUntil={}", clickKartUser.getPublicId(), requestMetadata.ipAddress(), lockedUntil);
		authFailureRecorder.recordLoginFailure(
				clickKartUser, identifier, LoginFailureReason.ACCOUNT_LOCKED, failureAuditAction,
				correlationId, requestMetadata, "reason=" + LoginFailureReason.ACCOUNT_LOCKED);
		throw new AccountLockedException("Account is temporarily locked due to repeated failed login attempts", lockedUntil);
	}

	/**
	 * Increments the failed-attempt counter (locking the account if {@code
	 * auth.max-failed-login-attempts} is crossed) and persists that plus the
	 * LoginAuditEntity/AuditLogEntryEntity writes via {@code authFailureRecorder} - the caller
	 * throws {@code InvalidCredentialsException} immediately after this returns.
	 */
	private void recordFailedLoginAttempt(ClickKartUserEntity clickKartUser, String identifier, LoginFailureReason failureReason,
			AuditAction failureAuditAction, String correlationId, RequestMetadata requestMetadata) {
		clickKartUser.increaseFailedAttempts();
		boolean nowLocked = clickKartUser.getFailedLoginAttempts() >= authProperties.getMaxFailedLoginAttempts();
		if (nowLocked) {
			clickKartUser.lock();
		}

		log.warn("LOGIN_FAILED publicId={} ipAddress={} reason={} failedAttempts={} nowLocked={}",clickKartUser.getPublicId(), requestMetadata.ipAddress(), failureReason,clickKartUser.getFailedLoginAttempts(), nowLocked);
		authFailureRecorder.recordLoginFailure(
				clickKartUser, identifier, failureReason, failureAuditAction, correlationId, requestMetadata,
				"reason=" + failureReason + " failedAttempts=" + clickKartUser.getFailedLoginAttempts());
	}

	/** Shared success tail for {@link #login} and {@link #verifyOtp} - resets lockout state, mints tokens, records success. */
	private LoginResponse completeSuccessfulLogin(ClickKartUserEntity clickKartUser, String identifier, String correlationId,
			Instant now, RequestMetadata requestMetadata, AuditAction successAuditAction) {
		clickKartUser.resetFailedAttempts();
		clickKartUser.recordSuccessfulLogin();
		clickKartUserRepository.save(clickKartUser);

		loginAuditRepository.save(LoginAuditEntity.success(clickKartUser, identifier,
				requestMetadata.ipAddress(), requestMetadata.userAgent(), correlationId));

		Set<String> roleNames = roleNamesOf(clickKartUser);
		MintedAccessToken accessToken = jwtService.mintAccessToken(clickKartUser.getPublicId(), roleNames,
				correlationId);
		IssuedRefreshToken refreshToken = refreshTokenService.issue(clickKartUser, correlationId, now);

		auditTrailService.record(correlationId, clickKartUser.getPublicId(), successAuditAction,
				AuditOutcome.SUCCESS, requestMetadata, null);

		AuthTokenResponse tokens = AuthTokenResponse.bearer(accessToken.token(), refreshToken.rawValue(),
				authProperties.getAccessTokenTtlSeconds());
		return new LoginResponse(tokens, ClickKartUserSummaryResponse.from(clickKartUser));
	}

	/**
	 * Routes the password check through the real Spring Security
	 * {@link AuthenticationManager} (see
	 * {@code SecurityConfig.daoAuthenticationProvider}) instead of calling {@code
	 * passwordEncoder.matches(...)} directly - {@code BadCredentialsException}
	 * (including the user-not-found case, which {@code DaoAuthenticationProvider}
	 * converts to the same exception by default so as not to leak which failed) is
	 * the only outcome this method interprets; enabled/locked state is -
	 * deliberately - this method's caller's responsibility, not the provider's (see
	 * that bean's Javadoc for why).
	 */
	private boolean passwordMatches(ClickKartUserEntity clickKartUser, String rawPassword) {
		try {
			authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(clickKartUser.getPublicId(), rawPassword));
			return true;
		} catch (BadCredentialsException e) {
			return false;
		}
	}

	// noRollbackFor = InvalidRefreshTokenException.class must match RefreshTokenServiceImpl.rotate's
	// own annotation exactly - see that method's Javadoc. Spring's rollback-only flag is a one-way
	// latch set by whichever @Transactional interceptor the exception passes through first; since
	// rotate() is normally called from within this method's own transaction (default REQUIRED
	// propagation just joins it), both layers must agree or the outer one here would still mark
	// the shared transaction rollback-only and silently undo rotate()'s ineligible-account revoke.
	@Override
	@Transactional(rollbackFor = Exception.class, noRollbackFor = InvalidRefreshTokenException.class)
	public AuthTokenResponse refresh(RefreshRequest request, RequestMetadata requestMetadata) {
		Instant now = Instant.now();
		IssuedRefreshToken rotated = refreshTokenService.rotate(request.refreshToken(), now, requestMetadata);
		ClickKartUserEntity clickKartUser = rotated.entity().getClickKartUser();
		String correlationId = rotated.entity().getCorrelationId();
		MDC.put(MdcKeys.CORRELATION_ID, correlationId);

		Set<String> roleNames = roleNamesOf(clickKartUser);
		MintedAccessToken accessToken = jwtService.mintAccessToken(clickKartUser.getPublicId(), roleNames,
				correlationId);

		auditTrailService.record(correlationId, clickKartUser.getPublicId(), AuditAction.TOKEN_REFRESHED,
				AuditOutcome.SUCCESS, requestMetadata, null);

		return AuthTokenResponse.bearer(accessToken.token(), rotated.rawValue(),
				authProperties.getAccessTokenTtlSeconds());
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void logout(AuthenticatedPrincipal principal, LogoutRequest request, RequestMetadata requestMetadata) {
		tokenRevocationLogoutHandler.handle(principal, request);

		auditTrailService.record(principal.correlationId(), principal.userId(), AuditAction.LOGOUT,
				AuditOutcome.SUCCESS, requestMetadata, null);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public Page<ClickKartUserSummaryResponse> listAccounts(RoleType roleType, Boolean locked, String emailContains,
			Pageable pageable, AuthenticatedPrincipal admin, RequestMetadata requestMetadata) {
		Page<ClickKartUserSummaryResponse> page = clickKartUserRepository
				.findAll(ClickKartUserSpecifications.withFilters(roleType, locked, emailContains), pageable)
				.map(ClickKartUserSummaryResponse::from);

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.ACCOUNTS_LISTED,
				AuditOutcome.SUCCESS, requestMetadata, null);

		return page;
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void forgotPassword(ForgotPasswordRequest request, RequestMetadata requestMetadata) {
		String correlationId = mintCorrelationId();
		verifyCaptcha(correlationId, request.captchaChallengeId(), request.captchaAnswer());

		Optional<ClickKartUserEntity> maybeUser = resolveIdentifier(request.identifier());
		if (maybeUser.isEmpty()) {
			// Do not reveal whether the identifier exists - the caller responds identically
			// either way.
			return;
		}

		ClickKartUserEntity clickKartUser = maybeUser.get();
		Instant now = Instant.now();

		IssuedPasswordResetToken issued = passwordResetService.issue(clickKartUser, correlationId, now);
		notificationServiceClient.sendPasswordResetNotification(correlationId, PasswordResetNotificationRequest.of(clickKartUser.getEmail(), issued.rawValue(), issued.entity().getExpiresAt()));

		auditTrailService.record(correlationId, clickKartUser.getPublicId(), AuditAction.FORGOT_PASSWORD_REQUESTED,
				AuditOutcome.SUCCESS, requestMetadata, null);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void resetPassword(ResetPasswordRequest request, RequestMetadata requestMetadata) {
		Instant now = Instant.now();
		PasswordResetTokenEntity token = passwordResetService.consume(request.token(), now);
		ClickKartUserEntity clickKartUser = token.getClickKartUser();

		passwordPolicyService.assertNotReused(clickKartUser, request.newPassword());

		String newPasswordHash = passwordEncoder.encode(request.newPassword());
		clickKartUser.changePassword(newPasswordHash);
		// Proving identity via a reset token is a stronger check than the lockout it's
		// meant to
		// recover from - clear it so a legitimate account owner isn't stuck locked out.
		if (!clickKartUser.isAccountNonLocked()) {
			clickKartUser.unlock();
		}
		clickKartUserRepository.save(clickKartUser);
		passwordPolicyService.record(clickKartUser, newPasswordHash);

		MDC.put(MdcKeys.CORRELATION_ID, token.getCorrelationId());
		auditTrailService.record(token.getCorrelationId(), clickKartUser.getPublicId(),
				AuditAction.PASSWORD_RESET_COMPLETED, AuditOutcome.SUCCESS, requestMetadata, null);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void requestOtp(RequestOtpRequest request, RequestMetadata requestMetadata) {
		Optional<ClickKartUserEntity> maybeUser = resolveIdentifier(request.identifier());
		if (maybeUser.isEmpty()) {
			// Do not reveal whether the identifier exists - the caller responds identically
			// either way.
			return;
		}

		ClickKartUserEntity clickKartUser = maybeUser.get();
		Instant now = Instant.now();
		String correlationId = mintCorrelationId();

		IssuedOtp issued = otpService.issue(clickKartUser, request.channel(), correlationId, now);
		OtpNotificationRequest notification = request.channel() == OtpChannel.SMS
				? OtpNotificationRequest.of(OtpChannel.SMS, null, clickKartUser.getMobileNumber(), issued.rawValue(), issued.entity().getExpiresAt())
				: OtpNotificationRequest.of(OtpChannel.EMAIL, clickKartUser.getEmail(), null, issued.rawValue(), issued.entity().getExpiresAt());
		notificationServiceClient.sendOtp(correlationId, notification);

		auditTrailService.record(correlationId, clickKartUser.getPublicId(), AuditAction.OTP_REQUESTED,
				AuditOutcome.SUCCESS, requestMetadata, "channel=" + request.channel());
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void changePassword(AuthenticatedPrincipal principal, ChangePasswordRequest request,
			RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = clickKartUserRepository.findByPublicId(principal.userId()).orElseThrow(
				() -> new IllegalStateException("Authenticated account no longer exists: " + principal.userId()));

		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(clickKartUser.getPublicId(), request.currentPassword()));
		} catch (BadCredentialsException e) {
			throw new InvalidCurrentPasswordException("Current password is incorrect");
		}

		passwordPolicyService.assertNotReused(clickKartUser, request.newPassword());

		String newPasswordHash = passwordEncoder.encode(request.newPassword());
		clickKartUser.changePassword(newPasswordHash);
		clickKartUserRepository.save(clickKartUser);
		passwordPolicyService.record(clickKartUser, newPasswordHash);

		auditTrailService.record(principal.correlationId(), principal.userId(), AuditAction.PASSWORD_CHANGED,
				AuditOutcome.SUCCESS, requestMetadata, null);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public ClickKartUserSummaryResponse lockAccount(String publicId, AuthenticatedPrincipal admin,
			RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = findAccountOrThrow(publicId);
		clickKartUser.lock();
		clickKartUserRepository.save(clickKartUser);
		// Locking must actually end existing sessions, not just block new ones - without this a
		// refresh token issued before the lock stays fully usable (RefreshTokenServiceImpl.rotate
		// only rejects it reactively, on presentation, and even that rejection previously failed
		// to persist - see that class's ineligible-account branch).
		tokenRevocationLogoutHandler.revokeAllActiveTokensForAccount(clickKartUser);

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.ACCOUNT_LOCKED_BY_ADMIN,
				AuditOutcome.SUCCESS, requestMetadata, "targetAccount=" + publicId);

		return ClickKartUserSummaryResponse.from(clickKartUser);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public ClickKartUserSummaryResponse unlockAccount(String publicId, AuthenticatedPrincipal admin,
			RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = findAccountOrThrow(publicId);
		clickKartUser.unlock();
		clickKartUserRepository.save(clickKartUser);

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.ACCOUNT_UNLOCKED_BY_ADMIN,
				AuditOutcome.SUCCESS, requestMetadata, "targetAccount=" + publicId);

		return ClickKartUserSummaryResponse.from(clickKartUser);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void requestContactVerification(AuthenticatedPrincipal principal, RequestContactVerificationRequest request,
			RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = clickKartUserRepository.findByPublicId(principal.userId()).orElseThrow(
				() -> new IllegalStateException("Authenticated account no longer exists: " + principal.userId()));

		IssuedVerificationCode issued = verificationCodeService.issue(clickKartUser, request.channel(), principal.correlationId(), Instant.now());
		OtpNotificationRequest notification = request.channel() == OtpChannel.SMS
				? OtpNotificationRequest.of(OtpChannel.SMS, null, clickKartUser.getMobileNumber(), issued.rawValue(), issued.entity().getExpiresAt())
				: OtpNotificationRequest.of(OtpChannel.EMAIL, clickKartUser.getEmail(), null, issued.rawValue(), issued.entity().getExpiresAt());
		notificationServiceClient.sendOtp(principal.correlationId(), notification);

		auditTrailService.record(principal.correlationId(), clickKartUser.getPublicId(), AuditAction.CONTACT_VERIFY_REQUESTED,
				AuditOutcome.SUCCESS, requestMetadata, "channel=" + request.channel());
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void confirmContactVerification(AuthenticatedPrincipal principal, ConfirmContactVerificationRequest request,
			RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = clickKartUserRepository.findByPublicId(principal.userId()).orElseThrow(
				() -> new IllegalStateException("Authenticated account no longer exists: " + principal.userId()));

		// verify() itself persists a wrong-guess attempt and its audit-trail entry via
		// authFailureRecorder (REQUIRES_NEW) before throwing, so this method's own
		// rollback-on-exception can't undo either - same reasoning as OtpServiceImpl.verify.
		verificationCodeService.verify(clickKartUser, request.channel(), request.code(), Instant.now(),
				principal.correlationId(), requestMetadata);

		if (request.channel() == OtpChannel.EMAIL) {
			clickKartUser.markEmailVerified();
		} else {
			clickKartUser.markMobileVerified();
		}
		clickKartUserRepository.save(clickKartUser);

		auditTrailService.record(principal.correlationId(), clickKartUser.getPublicId(), AuditAction.CONTACT_VERIFIED,
				AuditOutcome.SUCCESS, requestMetadata, "channel=" + request.channel());
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public ClickKartUserSummaryResponse deleteAccount(String publicId, AuthenticatedPrincipal admin, RequestMetadata requestMetadata) {
		ClickKartUserEntity clickKartUser = findAccountOrThrow(publicId);
		clickKartUser.softDelete();
		clickKartUserRepository.save(clickKartUser);
		tokenRevocationLogoutHandler.revokeAllActiveTokensForAccount(clickKartUser);

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.ACCOUNT_DELETED_BY_ADMIN,
				AuditOutcome.SUCCESS, requestMetadata, "targetAccount=" + publicId);

		return ClickKartUserSummaryResponse.from(clickKartUser);
	}

	private ClickKartUserEntity findAccountOrThrow(String publicId) {
		return clickKartUserRepository.findByPublicId(publicId)
				.orElseThrow(() -> new AccountNotFoundException("No account found for publicId: " + publicId));
	}

	private Set<String> roleNamesOf(ClickKartUserEntity clickKartUser) {
		return clickKartUser.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet());
	}

	private Optional<ClickKartUserEntity> resolveIdentifier(String identifier) {
		Optional<ClickKartUserEntity> byPublicId = clickKartUserRepository.findByPublicId(identifier);
		if (byPublicId.isPresent()) {
			return byPublicId;
		}

		Optional<ClickKartUserEntity> byEmail = clickKartUserRepository.findByEmail(identifier);
		if (byEmail.isPresent()) {
			return byEmail;
		}
		return clickKartUserRepository.findByMobileNumber(identifier);
	}

	private String mintCorrelationId() {
		String correlationId = correlationIdGenerator.generate();
		MDC.put(MdcKeys.CORRELATION_ID, correlationId);
		return correlationId;
	}

	/**
	 * Bot-detection gate for register/forgot-password (Rule: no CAPTCHA on public endpoints was a
	 * flagged production gap - this closes it). Required dependency, fails closed via {@link
	 * com.clickkart.auth.feign.CaptchaServiceClientFallbackFactory} on a Captcha Service outage,
	 * same posture as the Notification/Audit Log Service clients.
	 */
	private void verifyCaptcha(String correlationId, String captchaChallengeId, String captchaAnswer) {
		boolean valid = captchaServiceClient.verify(correlationId, new VerifyCaptchaRequest(captchaChallengeId, captchaAnswer))
				.data()
				.valid();
		if (!valid) {
			throw new InvalidCaptchaException("Captcha verification failed");
		}
	}
}
