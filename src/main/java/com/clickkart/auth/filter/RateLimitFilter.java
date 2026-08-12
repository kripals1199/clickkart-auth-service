// src/main/java/com/clickkart/auth/filter/RateLimitFilter.java
package com.clickkart.auth.filter;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import com.clickkart.auth.exception.RateLimitExceededException;
import com.clickkart.auth.security.CorrelationIdGenerator;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.web.ClientIpResolver;
import com.clickkart.auth.web.RequestMetadata;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Fixed-window, per-IP-per-path rate limit on the public, unauthenticated endpoints most
 * attractive to abuse - credential stuffing against {@code /login}, registration spam against
 * {@code /register}, and password-reset-email spam against {@code /forgot-password} are
 * otherwise unthrottled at this service's own layer. The Gateway may enforce its own limits, but
 * this service is independently reachable and must defend itself too - same reasoning already
 * applied to its own CORS config and security headers rather than trusting an upstream proxy.
 *
 * <p>Backed by Redis (already a dependency here, for the revoked-jti store) rather than an
 * in-memory counter, so the limit is shared correctly across every replica behind a load
 * balancer instead of resetting per-instance. {@code INCR} on a key that doesn't exist yet
 * atomically creates it at {@code 1}; only the request that observes the resulting value as
 * exactly {@code 1} sets the expiry, so concurrent first-requests from the same IP can't each
 * reset the window.
 *
 * <p>Fails closed, not open: if Redis is unreachable, the request is rejected with 503 rather
 * than let through unthrottled. Rate limiting is a required dependency here, not best-effort
 * defense in depth - see {@link DownstreamServiceUnavailableException}.
 */
@Slf4j(topic = LoggerNames.SECURITY)
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String REDIS_KEY_PREFIX = "ratelimit:";

    /** {@code AuditLogEntryEntity.actor} convention for flows with no resolvable {@code ClickKartUserEntity} - see that class's Javadoc. */
    private static final String SYSTEM_ACTOR = "system";

    private final StringRedisTemplate redisTemplate;
    private final AuthProperties authProperties;
    private final AuditTrailService auditTrailService;
    private final CorrelationIdGenerator correlationIdGenerator;
    private final HandlerExceptionResolver handlerExceptionResolver;
    private final ClientIpResolver clientIpResolver;
    private final List<String> limitedPaths;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getServletPath();
        if (!isLimitedPath(path)) {
            chain.doFilter(request, response);
            return;
        }

        String clientIp = clientIpResolver.resolve(request);
        String key = REDIS_KEY_PREFIX + path + ":" + clientIp;
        Long count;
        try {
            count = redisTemplate.opsForValue().increment(key);
            if (count != null && count == 1L) {
                redisTemplate.expire(key, Duration.ofSeconds(authProperties.getRateLimitWindowSeconds()));
            }
        } catch (DataAccessException e) {
            log.warn("RATE_LIMIT_CHECK_UNAVAILABLE path={} ipAddress={} cause={}", path, clientIp, e.toString());
            handlerExceptionResolver.resolveException(
                    request, response, null, new DownstreamServiceUnavailableException("Rate limiting (Redis)", e));
            return;
        }

        if (count != null && count > authProperties.getRateLimitMaxRequests()) {
            log.warn("RATE_LIMIT_EXCEEDED path={} ipAddress={} count={}", path, clientIp, count);
            // Only the request that first crosses the threshold gets a tamper-evident entry -
            // every later request in the same window would otherwise force one DB transaction
            // (serialized on the audit chain's single-row lock) per rejected request, which is
            // exactly the unbounded-cost-per-request the rate limiter itself exists to prevent.
            if (count == authProperties.getRateLimitMaxRequests() + 1L) {
                RequestMetadata requestMetadata = new RequestMetadata(clientIp, request.getHeader(HttpHeaders.USER_AGENT));
                auditTrailService.record(
                        correlationIdGenerator.generate(),
                        SYSTEM_ACTOR,
                        AuditAction.RATE_LIMIT_EXCEEDED,
                        AuditOutcome.FAILURE,
                        requestMetadata,
                        "path=" + path);
            }
            handlerExceptionResolver.resolveException(
                    request, response, null, new RateLimitExceededException("Too many requests - please try again later"));
            return;
        }

        chain.doFilter(request, response);
    }

    private boolean isLimitedPath(String path) {
        for (String pattern : limitedPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }
}
