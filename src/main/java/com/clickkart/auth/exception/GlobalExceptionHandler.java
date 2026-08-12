// src/main/java/com/clickkart/auth/exception/GlobalExceptionHandler.java
package com.clickkart.auth.exception;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.constant.MdcKeys;
import com.clickkart.auth.dto.ApiResponse;
import com.clickkart.auth.dto.ErrorDetail;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.web.ClientIpResolver;
import com.clickkart.auth.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Central mapping to the standard {@link ApiResponse} envelope (Rule 12),
 * including filter-level authentication failures delegated here via
 * {@code HandlerExceptionResolver} from
 * {@link com.clickkart.auth.jwt.JwtAuthenticationFilter}. Every handler returns
 * the exact {@code success=false} shape that {@code AuthController} builds
 * explicitly for {@code success=true} responses, so a UI integrator handles one
 * contract for both.
 *
 * <p>
 * Convention followed throughout: {@code message} is always a short,
 * display-ready string (safe to show directly in a toast/banner) and may be
 * reworded without notice; {@code error} is a typed {@link ErrorDetail} whose
 * {@code code} is the stable, machine-readable identifier a UI integrator
 * should actually branch on (e.g. {@code switch (error.code)}), never the
 * message text.
 */
@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

	private static final String LOCKED_UNTIL_METADATA_KEY = "lockedUntil";
	private static final String DEFAULT_FIELD_ERROR_MESSAGE = "invalid value";

	private final AuthProperties authProperties;
	private final AuditTrailService auditTrailService;
	private final ClientIpResolver clientIpResolver;

	@ExceptionHandler(DuplicateAccountException.class)
	public ResponseEntity<ApiResponse<Void>> handleDuplicateAccount(DuplicateAccountException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.CONFLICT, ErrorCode.DUPLICATE_ACCOUNT, ex.getMessage(), request);
	}

	/**
	 * Safety net for the genuine TOCTOU race {@code AuthServiceImpl.register}'s
	 * pre-check ({@code existsByEmail}/{@code existsByMobileNumber}) can't close on
	 * its own: two concurrent registrations for the same email/mobile can both pass
	 * that check before either commits, and the loser's insert then hits the
	 * DB-level unique constraint instead of the friendlier
	 * {@link DuplicateAccountException} path. Without this handler that surfaced as
	 * a raw 500 instead of the same 409 a normal duplicate registration gets.
	 */
	@ExceptionHandler(DataIntegrityViolationException.class)
	public ResponseEntity<ApiResponse<Void>> handleDataIntegrityViolation(DataIntegrityViolationException ex,
			HttpServletRequest request) {
		log.warn("DATA_INTEGRITY_VIOLATION path={} cause={}", request.getRequestURI(),
				ex.getMostSpecificCause().toString());
		return respond(HttpStatus.CONFLICT, ErrorCode.DUPLICATE_ACCOUNT, "This value is already in use", request);
	}

	@ExceptionHandler(InvalidCredentialsException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(InvalidCredentialsException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, ex.getMessage(), request);
	}

	@ExceptionHandler(InvalidCaptchaException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidCaptcha(InvalidCaptchaException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_CAPTCHA, ex.getMessage(), request);
	}

	@ExceptionHandler(AccountLockedException.class)
	public ResponseEntity<ApiResponse<Void>> handleAccountLocked(AccountLockedException ex,
			HttpServletRequest request) {
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put(LOCKED_UNTIL_METADATA_KEY, ex.getLockedUntil());
		ErrorDetail errorDetail = ErrorDetail.withMetadata(ErrorCode.ACCOUNT_LOCKED, metadata);
		return respond(HttpStatus.LOCKED, errorDetail, ex.getMessage(), request);
	}

	@ExceptionHandler(InvalidRefreshTokenException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidRefreshToken(InvalidRefreshTokenException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_REFRESH_TOKEN, ex.getMessage(), request);
	}

	@ExceptionHandler(InvalidPasswordResetTokenException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidPasswordResetToken(InvalidPasswordResetTokenException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_PASSWORD_RESET_TOKEN, ex.getMessage(), request);
	}

	@ExceptionHandler(InvalidCurrentPasswordException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidCurrentPassword(InvalidCurrentPasswordException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CURRENT_PASSWORD, ex.getMessage(), request);
	}

	/**
	 * Safety net only - {@code AuthServiceImpl.verifyOtp} always catches this
	 * itself and rethrows the generic {@link InvalidCredentialsException} (same
	 * "don't reveal which check failed" rule password login already follows), so
	 * this normally never fires. Kept for the same reason
	 * {@code RestAuthenticationEntryPoint}/{@code RestAccessDeniedHandler} are - if
	 * a future call site ever lets it escape uncaught, it still maps to 401, not
	 * the generic 500 {@link #handleUnexpected} would otherwise produce.
	 */
	@ExceptionHandler(InvalidOtpException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidOtp(InvalidOtpException ex, HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_OTP, ex.getMessage(), request);
	}

	/**
	 * Same rejection shape as {@link #handleInvalidOtp} -
	 * wrong/expired/already-used/never-requested all collapse to one generic 401.
	 */
	@ExceptionHandler(InvalidVerificationCodeException.class)
	public ResponseEntity<ApiResponse<Void>> handleInvalidVerificationCode(InvalidVerificationCodeException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_VERIFICATION_CODE, ex.getMessage(), request);
	}

	@ExceptionHandler(PasswordReusedException.class)
	public ResponseEntity<ApiResponse<Void>> handlePasswordReused(PasswordReusedException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.BAD_REQUEST, ErrorCode.PASSWORD_REUSED, ex.getMessage(), request);
	}

	@ExceptionHandler(AccountNotFoundException.class)
	public ResponseEntity<ApiResponse<Void>> handleAccountNotFound(AccountNotFoundException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.NOT_FOUND, ErrorCode.ACCOUNT_NOT_FOUND, ex.getMessage(), request);
	}

	@ExceptionHandler(MissingCorrelationIdException.class)
	public ResponseEntity<ApiResponse<Void>> handleMissingCorrelationId(MissingCorrelationIdException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.BAD_REQUEST, ErrorCode.MISSING_CORRELATION_ID, ex.getMessage(), request);
	}

	@ExceptionHandler({ BadCredentialsException.class, AuthenticationCredentialsNotFoundException.class })
	public ResponseEntity<ApiResponse<Void>> handleAuthenticationFailure(RuntimeException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.UNAUTHORIZED, ErrorCode.AUTHENTICATION_FAILED, ex.getMessage(), request);
	}

	/**
	 * An authenticated principal hitting an endpoint their role doesn't permit - a
	 * privilege-escalation signal worth the tamper-evident chain.
	 */
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiResponse<Void>> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
		Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
				.map(authentication -> authentication.getPrincipal()).filter(AuthenticatedPrincipal.class::isInstance)
				.map(AuthenticatedPrincipal.class::cast).ifPresent(
						principal -> auditTrailService
								.record(principal.correlationId(), principal.userId(), AuditAction.ACCESS_DENIED,
										AuditOutcome.FAILURE,
										new RequestMetadata(clientIpResolver.resolve(request),
												request.getHeader(HttpHeaders.USER_AGENT)),
										"path=" + request.getRequestURI()));
		return respond(HttpStatus.FORBIDDEN, ErrorCode.ACCESS_DENIED,
				"You do not have permission to perform this action", request);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException ex,
			HttpServletRequest request) {
		Map<String, String> fieldErrors = new LinkedHashMap<>();
		ex.getBindingResult().getFieldErrors().forEach(fieldError -> fieldErrors.put(fieldError.getField(),
				fieldError.getDefaultMessage() == null ? DEFAULT_FIELD_ERROR_MESSAGE : fieldError.getDefaultMessage()));
		ErrorDetail errorDetail = ErrorDetail.withFieldErrors(ErrorCode.VALIDATION_FAILED, fieldErrors);
		return respond(HttpStatus.BAD_REQUEST, errorDetail, "One or more fields failed validation", request);
	}

	/**
	 * e.g. {@code ?roleType=BOGUS} against the {@code RoleType} enum - a client
	 * error, not the 500 it would otherwise fall through to.
	 */
	@ExceptionHandler(MethodArgumentTypeMismatchException.class)
	public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(MethodArgumentTypeMismatchException ex,
			HttpServletRequest request) {
		Map<String, String> fieldErrors = new LinkedHashMap<>();
		fieldErrors.put(ex.getName(), DEFAULT_FIELD_ERROR_MESSAGE);
		ErrorDetail errorDetail = ErrorDetail.withFieldErrors(ErrorCode.VALIDATION_FAILED, fieldErrors);
		return respond(HttpStatus.BAD_REQUEST, errorDetail, "One or more fields failed validation", request);
	}

	/**
	 * Malformed/unparseable JSON request body - a client error, not the 500 it
	 * would otherwise fall through to.
	 */
	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ApiResponse<Void>> handleMalformedRequestBody(HttpMessageNotReadableException ex,
			HttpServletRequest request) {
		return respond(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED, "Request body is missing or malformed",
				request);
	}

	/**
	 * A required integrated dependency (Redis, Audit Log Service, Notification
	 * Service) could not be reached - see
	 * {@link DownstreamServiceUnavailableException}'s Javadoc for the call sites.
	 * 503, not 500: this is a known, transient upstream condition, not an internal
	 * defect.
	 */
	@ExceptionHandler(DownstreamServiceUnavailableException.class)
	public ResponseEntity<ApiResponse<Void>> handleDownstreamServiceUnavailable(
			DownstreamServiceUnavailableException ex, HttpServletRequest request) {
		log.warn("DOWNSTREAM_SERVICE_UNAVAILABLE path={} cause={}", request.getRequestURI(), ex.getMessage());
		return respond(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SERVICE_UNAVAILABLE, ex.getMessage(), request);
	}

	@ExceptionHandler(RateLimitExceededException.class)
	public ResponseEntity<ApiResponse<Void>> handleRateLimitExceeded(RateLimitExceededException ex,
			HttpServletRequest request) {
		String correlationId = MDC.get(MdcKeys.CORRELATION_ID);
		ApiResponse<Void> body = ApiResponse.error(HttpStatus.TOO_MANY_REQUESTS.value(),
				ErrorDetail.of(ErrorCode.RATE_LIMIT_EXCEEDED), ex.getMessage(), request.getRequestURI(), correlationId);
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
				.header(HttpHeaders.RETRY_AFTER, String.valueOf(authProperties.getRateLimitWindowSeconds())).body(body);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiResponse<Void>> handleUnexpected(Exception ex, HttpServletRequest request) {
		// Never leak internal exception details/stack traces to the client (Rule 14) -
		// full
		// detail goes to the ERROR log appender instead, keyed by the same correlation
		// id.
		log.error("Unhandled exception on {} {}", request.getMethod(), request.getRequestURI(), ex);
		return respond(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "An unexpected error occurred",
				request);
	}

	/** Simple case: {@code error.code} only, no field errors/metadata. */
	private ResponseEntity<ApiResponse<Void>> respond(HttpStatus status, String code, String message,
			HttpServletRequest request) {
		return respond(status, ErrorDetail.of(code), message, request);
	}

	private ResponseEntity<ApiResponse<Void>> respond(HttpStatus status, ErrorDetail errorDetail, String message,
			HttpServletRequest request) {
		String correlationId = MDC.get(MdcKeys.CORRELATION_ID);
		ApiResponse<Void> body = ApiResponse.error(status.value(), errorDetail, message, request.getRequestURI(),
				correlationId);
		return ResponseEntity.status(status).body(body);
	}

	/**
	 * Stable, machine-readable codes a UI integrator branches on - see the class
	 * Javadoc.
	 */
	private static final class ErrorCode {
		private ErrorCode() {
		}

		static final String DUPLICATE_ACCOUNT = "DUPLICATE_ACCOUNT";
		static final String INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
		static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
		static final String INVALID_REFRESH_TOKEN = "INVALID_REFRESH_TOKEN";
		static final String INVALID_PASSWORD_RESET_TOKEN = "INVALID_PASSWORD_RESET_TOKEN";
		static final String INVALID_CURRENT_PASSWORD = "INVALID_CURRENT_PASSWORD";
		static final String INVALID_OTP = "INVALID_OTP";
		static final String INVALID_VERIFICATION_CODE = "INVALID_VERIFICATION_CODE";
		static final String PASSWORD_REUSED = "PASSWORD_REUSED";
		static final String ACCOUNT_NOT_FOUND = "ACCOUNT_NOT_FOUND";
		static final String MISSING_CORRELATION_ID = "MISSING_CORRELATION_ID";
		static final String AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
		static final String ACCESS_DENIED = "ACCESS_DENIED";
		static final String VALIDATION_FAILED = "VALIDATION_FAILED";
		static final String INTERNAL_ERROR = "INTERNAL_ERROR";
		static final String RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED";
		static final String SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE";
		static final String INVALID_CAPTCHA = "INVALID_CAPTCHA";
	}
}
