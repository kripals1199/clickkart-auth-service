// src/main/java/com/clickkart/auth/jwt/JwtAuthenticationFilter.java
package com.clickkart.auth.jwt;

import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.constant.MdcKeys;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import com.clickkart.auth.exception.MissingCorrelationIdException;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.security.RevocationService;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.web.ClientIpResolver;
import com.clickkart.auth.web.RequestMetadata;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.MDC;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j(topic = LoggerNames.SECURITY)
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final RevocationService revocationService;
    private final AuditTrailService auditTrailService;
    private final HandlerExceptionResolver handlerExceptionResolver;
    private final ClientIpResolver clientIpResolver;
    private final List<String> publicPaths;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (isPublicPath(request.getServletPath())) {
            chain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            handlerExceptionResolver.resolveException(
                    request, response, null, new BadCredentialsException("Missing or malformed Authorization header"));
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        Claims claims;
        try {
            claims = jwtService.parseAndValidate(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT_REJECTED reason=invalid-or-expired path={} remoteAddr={} cause={}",
                    request.getRequestURI(), request.getRemoteAddr(), e.toString());
            handlerExceptionResolver.resolveException(
                    request, response, null, new BadCredentialsException("Invalid or expired token"));
            return;
        }

        String jti = claims.getId();
        boolean revoked;
        try {
            revoked = revocationService.isRevoked(jti);
        } catch (DataAccessException e) {
            // Redis is required here, not best-effort - without it there is no way to honor a
            // prior logout/revocation, so every access token would effectively become
            // un-revocable until it naturally expires. Fail the request rather than silently
            // treat it as "not revoked".
            log.warn("REVOCATION_CHECK_UNAVAILABLE jti={} path={} remoteAddr={} cause={}",
                    jti, request.getRequestURI(), request.getRemoteAddr(), e.toString());
            handlerExceptionResolver.resolveException(
                    request, response, null, new DownstreamServiceUnavailableException("Token revocation check (Redis)", e));
            return;
        }

        if (revoked) {
            log.warn("JWT_REJECTED reason=revoked jti={} path={} remoteAddr={}",
                    jti, request.getRequestURI(), request.getRemoteAddr());
            // A revoked (logged-out) access token being replayed is a genuine security event,
            // not routine expiry - worth the tamper-evident chain, unlike the ordinary
            // invalid/expired rejections below, which are far too high-volume (any client with a
            // stale token) to burn a chain-head lock on.
            String tokenCorrelationId = claims.get(JwtClaimNames.CORRELATION_ID, String.class);
            if (tokenCorrelationId != null && !tokenCorrelationId.isBlank()) {
                RequestMetadata requestMetadata =
                        new RequestMetadata(clientIpResolver.resolve(request), request.getHeader(HttpHeaders.USER_AGENT));
                auditTrailService.record(
                        tokenCorrelationId,
                        claims.getSubject(),
                        AuditAction.REVOKED_TOKEN_REUSE_DETECTED,
                        AuditOutcome.FAILURE,
                        requestMetadata,
                        "jti=" + jti);
            }
            handlerExceptionResolver.resolveException(
                    request, response, null, new BadCredentialsException("Token has been revoked"));
            return;
        }

        String tokenCorrelationId = claims.get(JwtClaimNames.CORRELATION_ID, String.class);
        if (tokenCorrelationId == null || tokenCorrelationId.isBlank()) {
            handlerExceptionResolver.resolveException(
                    request,
                    response,
                    null,
                    new MissingCorrelationIdException("Token is missing the required correlationId claim"));
            return;
        }

        // CorrelationIdFilter has already seeded the MDC from the X-Correlation-Id header, which the
        // Gateway derives from this very claim, so on any real request path the two agree. Keeping the
        // MDC value authoritative is what makes the access log, this filter, and the id handed to
        // downstream services one id. Overwriting it here split a single request into two traces:
        // REQUEST_START logged one id while every outgoing call carried another.
        String correlationId = MDC.get(MdcKeys.CORRELATION_ID);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = tokenCorrelationId;
            MDC.put(MdcKeys.CORRELATION_ID, correlationId);
        }

        Set<String> roles = parseRoles(claims.get(JwtClaimNames.ROLES, String.class));
        AuthenticatedPrincipal principal = new AuthenticatedPrincipal(
                claims.getSubject(), roles, correlationId, jti, claims.getExpiration().toInstant());

        // RoleEntity names in the claim are already ROLE_-prefixed (e.g. ROLE_ADMIN, seeded from
        // RoleType) so Spring Security's hasRole('ADMIN') (which itself prepends "ROLE_" when
        // checking) matches correctly - prefixing again here would produce "ROLE_ROLE_ADMIN"
        // and silently break every @PreAuthorize("hasRole(...)") check.
        var authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        try {
            chain.doFilter(request, response);
        } finally {
            // The correlation id is deliberately left in place. CorrelationIdFilter owns it, and
            // AccessLogFilter - which wraps this filter - still needs it to log REQUEST_END; removing
            // it here is why every REQUEST_END line recorded correlationId=null. MdcCleanupFilter runs
            // outermost and clears the whole MDC, so nothing leaks onto the next pooled request.
            SecurityContextHolder.clearContext();
        }
    }

    private Set<String> parseRoles(String rolesClaim) {
        if (rolesClaim == null || rolesClaim.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(rolesClaim.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private boolean isPublicPath(String path) {
        for (String pattern : publicPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }
}
