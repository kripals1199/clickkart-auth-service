// src/main/java/com/clickkart/auth/controller/AuditController.java
package com.clickkart.auth.controller;

import com.clickkart.auth.constant.ApiPaths;
import com.clickkart.auth.constant.MdcKeys;
import com.clickkart.auth.dto.ApiResponse;
import com.clickkart.auth.dto.PageResponse;
import com.clickkart.auth.dto.response.AuditLogEntryResponse;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.enums.RoleType;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.ChainIntegrityReport;
import com.clickkart.auth.web.ClientIpResolver;
import com.clickkart.auth.web.RequestMetadata;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * ADMIN-only read access to the banking-grade audit trail (see
 * {@link AuditTrailService}) - browse the chain and independently verify it
 * hasn't been tampered with. Both endpoints return the same {@link ApiResponse}
 * envelope every other endpoint in this service uses.
 *
 * <p>
 * Both reads are themselves recorded into the trail (Rule: log every activity,
 * not just writes) - same reasoning {@code AuthController.listAccounts} already
 * follows: an ADMIN reading sensitive/compliance-relevant data is itself worth
 * a durable trace, distinct from the ordinary {@code AccessLogFilter} line
 * every request already gets.
 */
@Tag(name = "Audit", description = "ADMIN-only read access to the tamper-evident audit trail")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequiredArgsConstructor
public class AuditController {

	private final AuditTrailService auditTrailService;
	private final ClientIpResolver clientIpResolver;

	/**
	 * 200 OK, {@code data}: a page of audit entries in chain order (oldest first),
	 * each including its {@code entryHash}/{@code previousEntryHash} for
	 * independent verification. 403 Forbidden for a non-ADMIN caller.
	 */
	@Operation(summary = "Browse the audit trail (ADMIN only)")
	@GetMapping(ApiPaths.AUDIT)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<PageResponse<AuditLogEntryResponse>>> browse(Pageable pageable,@AuthenticationPrincipal AuthenticatedPrincipal admin, HttpServletRequest httpRequest) {
		Page<AuditLogEntryResponse> page = auditTrailService.browse(pageable).map(AuditLogEntryResponse::from);

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.AUDIT_TRAIL_VIEWED,AuditOutcome.SUCCESS, requestMetadata(httpRequest), "page=" + pageable.getPageNumber());

		return envelope(HttpStatus.OK.value(), PageResponse.from(page), httpRequest);
	}

	/**
	 * 200 OK, {@code data}:
	 * {"intact":true,"entriesChecked":42,"brokenAtEntryId":null, "reason":null}
	 * when the whole chain still checks out, or {@code intact:false} with the id of
	 * the first entry whose recomputed hash - or chain link - no longer matches
	 * what was recorded, if the trail has been tampered with.
	 */
	@Operation(summary = "Independently verify the audit hash chain hasn't been tampered with (ADMIN only)")
	@GetMapping(ApiPaths.AUDIT_VERIFY)
	@PreAuthorize("hasAuthority('" + RoleType.ADMIN_AUTHORITY + "')")
	public ResponseEntity<ApiResponse<ChainIntegrityReport>> verify(@AuthenticationPrincipal AuthenticatedPrincipal admin, HttpServletRequest httpRequest) {
		ChainIntegrityReport report = auditTrailService.verifyChainIntegrity();

		auditTrailService.record(admin.correlationId(), admin.userId(), AuditAction.AUDIT_INTEGRITY_VERIFIED,report.intact() ? AuditOutcome.SUCCESS : AuditOutcome.FAILURE, requestMetadata(httpRequest),"intact=" + report.intact());

		return envelope(HttpStatus.OK.value(), report, httpRequest);
	}

	private <T> ResponseEntity<ApiResponse<T>> envelope(int status, T data, HttpServletRequest request) {
		String correlationId = MDC.get(MdcKeys.CORRELATION_ID);
		ApiResponse<T> body = ApiResponse.success(status, data, request.getRequestURI(), correlationId);
		return ResponseEntity.status(status).body(body);
	}

	private RequestMetadata requestMetadata(HttpServletRequest request) {
		return new RequestMetadata(clientIpResolver.resolve(request), request.getHeader(HttpHeaders.USER_AGENT));
	}
}
