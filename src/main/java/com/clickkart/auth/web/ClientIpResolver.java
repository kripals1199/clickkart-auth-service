// src/main/java/com/clickkart/auth/web/ClientIpResolver.java
package com.clickkart.auth.web;

import com.clickkart.auth.config.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

/**
 * Single source of truth for resolving a caller's IP - shared by {@code AuthController}/{@code
 * AuditController} (audit trail / {@code LoginAuditEntity} rows), {@code RateLimitFilter}
 * (per-IP throttling), and {@code JwtAuthenticationFilter}, so none of them can disagree about
 * which address a given request "came from".
 *
 * <p>Only honors {@code X-Forwarded-For} when the immediate {@code request.getRemoteAddr()}
 * matches a configured trusted-proxy CIDR ({@code auth.trusted-proxy-cidrs}) - otherwise a
 * client reaching this service directly (explicitly supported - see the class-level Javadoc on
 * {@code SecurityConfig}) could simply set that header to whatever it wants and defeat per-IP
 * rate limiting entirely. Converted from a static utility to a Spring bean specifically to take
 * this dependency on {@link AuthProperties} - uses Spring Security's {@link IpAddressMatcher}
 * (already on the classpath via {@code spring-boot-starter-security}) for CIDR matching rather
 * than hand-rolled subnet math.
 */
@Component
@RequiredArgsConstructor
public class ClientIpResolver {

    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";

    private final AuthProperties authProperties;

    public String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }
        return Optional.ofNullable(request.getHeader(X_FORWARDED_FOR_HEADER))
                .filter(header -> !header.isBlank())
                .map(header -> header.split(",")[0].trim())
                .orElse(remoteAddr);
    }

    private boolean isTrustedProxy(String remoteAddr) {
        List<String> trustedProxyCidrs = authProperties.getTrustedProxyCidrs();
        if (trustedProxyCidrs.isEmpty()) {
            return false;
        }
        for (String cidr : trustedProxyCidrs) {
            if (new IpAddressMatcher(cidr).matches(remoteAddr)) {
                return true;
            }
        }
        return false;
    }
}
