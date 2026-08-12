// src/main/java/com/clickkart/auth/controller/AuthController.java
package com.clickkart.auth.controller;

import com.clickkart.auth.constant.ApiPaths;
import com.clickkart.auth.constant.MdcKeys;
import com.clickkart.auth.dto.ApiResponse;
import com.clickkart.auth.dto.PageResponse;
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
import com.clickkart.auth.service.AuthService;
import com.clickkart.auth.web.ClientIpResolver;
import com.clickkart.auth.web.RequestMetadata;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

/**
 * Registration, login (email/mobile/publicId), JWT/refresh issuance,
 * logout/revocation, forgot/reset/change password, and admin account management
 * - all under {@code /api/v1/auth} per the platform-wide API contract (Rule
 * 12).
 *
 * <p>
 * Every endpoint - success or error - returns the single {@link ApiResponse}
 * envelope, built explicitly here for the success side (see
 * {@link #envelope(int, Object, HttpServletRequest)}) and by
 * {@link com.clickkart.auth.exception.GlobalExceptionHandler} for the error side.
 * A UI integrator therefore only ever has one contract to parse, regardless of
 * endpoint or outcome:
 * {@code {"timestamp":"...","status":201,"success":true,"data":{...},"path":"...",
 * "correlationId":"..."}} on success, the same shape with {@code success:false}
 * and {@code error}/{@code message} populated (and {@code data} absent) on
 * failure.
 */
@Tag(name = "Auth", description = "Registration, session lifecycle, password management, and admin account operations")
@RestController
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;
	private final ClientIpResolver clientIpResolver;

	/**
	 * 201 Created, {@code data}:
	 * {"tokens":{"accessToken":"eyJ...","refreshToken":"c3RyaW5n...",
	 * "tokenType":"Bearer","expiresInSeconds":900},"user":{"publicId":"USR-...","email":"a@b.com",
	 * "mobileNumber":"9845550100","roles":["ROLE_CUSTOMER"],"enabled":true,"locked":false,
	 * "emailVerified":false,"mobileVerified":false,"lastLoginAt":null,
	 * "createdDate":"2026-08-02T10:00:00Z"}} - registration also establishes a
	 * session, so the caller doesn't need a separate {@code /login} call right
	 * after signing up. 409 Conflict if the email or mobile number is already
	 * registered.
	 */
	@Operation(summary = "Register a new customer account", description = "Public. Always creates a account and logs it in immediately.")
	@PostMapping(ApiPaths.REGISTER)
	public ResponseEntity<ApiResponse<LoginResponse>> register(@Valid @RequestBody RegisterRequest request,HttpServletRequest httpRequest) {
		LoginResponse response = authService.register(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.CREATED.value(), response, httpRequest);
	}

	/**
	 * 200 OK, {@code data}:
	 * {"tokens":{"accessToken":"eyJ...","refreshToken":"c3RyaW5n...",
	 * "tokenType":"Bearer","expiresInSeconds":900},"user":{"publicId":"USR-...",...}}
	 * 401 Unauthorized on a wrong identifier/password; 423 Locked if the account is
	 * locked out.
	 */
	@Operation(summary = "Log in", description = "Public. identifier may be email, mobile number, or publicId.")
	@PostMapping(ApiPaths.LOGIN)
	public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request,
			HttpServletRequest httpRequest) {
		LoginResponse response = authService.login(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * 200 OK, same {@code data} shape as login. 401 Unauthorized if the refresh
	 * token is invalid, expired, already rotated, or revoked.
	 */
	@Operation(summary = "Rotate a refresh token for a new access/refresh pair", description = "Public.")
	@PostMapping(ApiPaths.REFRESH)
	public ResponseEntity<ApiResponse<AuthTokenResponse>> refresh(@Valid @RequestBody RefreshRequest request,
			HttpServletRequest httpRequest) {
		AuthTokenResponse response = authService.refresh(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null} - logout has nothing to return, but still rides
	 * the same envelope (Rule 12: one shape for every response, no
	 * endpoint-specific exception) rather than a bare 204. Requires a valid,
	 * non-revoked access token (enforced by JwtAuthenticationFilter).
	 */
	@Operation(summary = "Log out", description = "Revokes the current access token, plus one or all refresh tokens.")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.LOGOUT)
	public ResponseEntity<ApiResponse<Void>> logout(@AuthenticationPrincipal AuthenticatedPrincipal principal,
			@Valid @RequestBody(required = false) LogoutRequest request, HttpServletRequest httpRequest) {
		authService.logout(principal, request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null} always, whether or not {@code identifier} resolves
	 * to an account (Rule: never reveal identifier existence). Sample body:
	 * {"identifier":"jane@example.com"}
	 */
	@Operation(summary = "Request a password reset", description = "Public. Always responds identically regardless of whether the identifier exists.")
	@PostMapping(ApiPaths.FORGOT_PASSWORD)
	public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
			HttpServletRequest httpRequest) {
		authService.forgotPassword(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null}. 401 Unauthorized if the token is invalid,
	 * expired, or already used. Sample body:
	 * {"token":"raw-reset-token-from-the-emailed-link","newPassword":"N3wStr0ng!Passw0rd"}
	 */
	@Operation(summary = "Complete a password reset using the token issued by forgot-password", description = "Public.")
	@PostMapping(ApiPaths.RESET_PASSWORD)
	public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request,
			HttpServletRequest httpRequest) {
		authService.resetPassword(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null} always, whether or not {@code identifier} resolves
	 * to an account (Rule: never reveal identifier existence). Sample body:
	 * {"identifier":"jane@example.com","channel":"SMS"}
	 */
	@Operation(summary = "Request a login OTP", description = "Public. Always responds identically regardless of whether the identifier exists.")
	@PostMapping(ApiPaths.OTP_REQUEST)
	public ResponseEntity<ApiResponse<Void>> requestOtp(@Valid @RequestBody RequestOtpRequest request,
			HttpServletRequest httpRequest) {
		authService.requestOtp(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, same {@code data} shape as login - an alternative to password login,
	 * not a second factor. 401 Unauthorized on a wrong/expired/already-used code;
	 * 423 Locked if the account is locked out (shared lockout state with password
	 * login).
	 */
	@Operation(summary = "Log in using a previously requested OTP", description = "Public.")
	@PostMapping(ApiPaths.OTP_VERIFY)
	public ResponseEntity<ApiResponse<LoginResponse>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request,
			HttpServletRequest httpRequest) {
		LoginResponse response = authService.verifyOtp(request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null}. 401 Unauthorized if {@code currentPassword} is
	 * wrong. Requires a valid access token.
	 */
	@Operation(summary = "Change the authenticated account's own password")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.CHANGE_PASSWORD)
	public ResponseEntity<ApiResponse<Void>> changePassword(@AuthenticationPrincipal AuthenticatedPrincipal principal,
			@Valid @RequestBody ChangePasswordRequest request, HttpServletRequest httpRequest) {
		authService.changePassword(principal, request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null}. Authenticated self-service - issues a
	 * verification code for the caller's own email or mobile number, per
	 * {@code channel}. Sample body: {"channel":"EMAIL"}.
	 */
	@Operation(summary = "Request a verification code for the authenticated account's own email or mobile number")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.VERIFY_CONTACT_REQUEST)
	public ResponseEntity<ApiResponse<Void>> requestContactVerification(
			@AuthenticationPrincipal AuthenticatedPrincipal principal,
			@Valid @RequestBody RequestContactVerificationRequest request, HttpServletRequest httpRequest) {
		authService.requestContactVerification(principal, request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * 200 OK, {@code data: null}. 401 Unauthorized on a wrong/expired/already-used
	 * code. Sample body: {"channel":"EMAIL","code":"042817"}.
	 */
	@Operation(summary = "Confirm a previously requested email/mobile verification code")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.VERIFY_CONTACT_CONFIRM)
	public ResponseEntity<ApiResponse<Void>> confirmContactVerification(
			@AuthenticationPrincipal AuthenticatedPrincipal principal,
			@Valid @RequestBody ConfirmContactVerificationRequest request, HttpServletRequest httpRequest) {
		authService.confirmContactVerification(principal, request, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), null, httpRequest);
	}

	/**
	 * ADMIN-only, real Pageable/Specification-backed listing (Rule 12) -
	 * {@code ?page=0&size=20
	 * &sort=createdDate,desc&roleType=ROLE_CUSTOMER&locked=false&email=example.com}.
	 * 403 Forbidden for a non-ADMIN caller.
	 */
	@Operation(summary = "List accounts (ADMIN only)", description = "Filterable/paginated account listing.")
	@SecurityRequirement(name = "bearerAuth")
	@GetMapping(ApiPaths.ACCOUNTS)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<PageResponse<ClickKartUserSummaryResponse>>> listAccounts(
			@RequestParam(required = false) RoleType roleType, @RequestParam(required = false) Boolean locked,
			@RequestParam(required = false) String email, Pageable pageable,
			@AuthenticationPrincipal AuthenticatedPrincipal principal, HttpServletRequest httpRequest) {
		Page<ClickKartUserSummaryResponse> page = authService.listAccounts(roleType, locked, email, pageable, principal,
				requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), PageResponse.from(page), httpRequest);
	}

	/**
	 * 200 OK, {@code data}: the account's updated
	 * {@code ClickKartUserSummaryResponse} ({@code locked:true}). 404 Not Found for
	 * an unknown {@code publicId}. 403 Forbidden for a non-ADMIN caller.
	 */
	@Operation(summary = "Lock an account (ADMIN only)")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.ACCOUNT_LOCK)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<ClickKartUserSummaryResponse>> lockAccount(@PathVariable String publicId,
			@AuthenticationPrincipal AuthenticatedPrincipal admin, HttpServletRequest httpRequest) {
		ClickKartUserSummaryResponse response = authService.lockAccount(publicId, admin, requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * 200 OK, {@code data}: the account's updated
	 * {@code ClickKartUserSummaryResponse} ({@code locked:false}, failed-attempt
	 * counter reset). 404 Not Found for an unknown {@code publicId}. 403 Forbidden
	 * for a non-ADMIN caller.
	 */
	@Operation(summary = "Unlock an account (ADMIN only)")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.ACCOUNT_UNLOCK)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<ClickKartUserSummaryResponse>> unlockAccount(@PathVariable String publicId,
			@AuthenticationPrincipal AuthenticatedPrincipal admin, HttpServletRequest httpRequest) {
		ClickKartUserSummaryResponse response = authService.unlockAccount(publicId, admin,
				requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * 200 OK, {@code data}: the account's final
	 * {@code ClickKartUserSummaryResponse} before it drops out of every normal
	 * query (soft delete - {@code ClickKartUserEntity} carries
	 * {@code @SQLRestriction("deleted = false")}). Also revokes every active
	 * refresh token for the account. 404 Not Found for an unknown {@code publicId}.
	 * 403 Forbidden for a non-ADMIN caller.
	 */
	@Operation(summary = "Soft-delete an account (ADMIN only)")
	@SecurityRequirement(name = "bearerAuth")
	@PostMapping(ApiPaths.ACCOUNT_DELETE)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<ClickKartUserSummaryResponse>> deleteAccount(@PathVariable String publicId,
			@AuthenticationPrincipal AuthenticatedPrincipal admin, HttpServletRequest httpRequest) {
		ClickKartUserSummaryResponse response = authService.deleteAccount(publicId, admin,
				requestMetadata(httpRequest));
		return envelope(HttpStatus.OK.value(), response, httpRequest);
	}

	/**
	 * Every success response goes through here - the one place that builds
	 * {@link ApiResponse} for the happy path.
	 */
	private <T> ResponseEntity<ApiResponse<T>> envelope(int status, T data, HttpServletRequest request) {
		String correlationId = MDC.get(MdcKeys.CORRELATION_ID);
		ApiResponse<T> body = ApiResponse.success(status, data, request.getRequestURI(), correlationId);
		return ResponseEntity.status(status).body(body);
	}

	private RequestMetadata requestMetadata(HttpServletRequest request) {
		return new RequestMetadata(clientIpResolver.resolve(request), request.getHeader(HttpHeaders.USER_AGENT));
	}
}
