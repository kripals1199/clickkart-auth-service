// src/main/java/com/clickkart/auth/filter/MdcCleanupFilter.java
package com.clickkart.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs outermost (see {@code FilterRegistrationBean} in {@link com.clickkart.auth.config.WebConfig}), wrapping the entire
 * request - including the public register/login/refresh endpoints, which mint a correlationId
 * mid-request (see AuthServiceImpl) rather than having one handed to them by
 * JwtAuthenticationFilter. Guarantees MDC never leaks a correlationId onto a later, unrelated
 * request handled by the same pooled Tomcat thread, regardless of which code path put one there
 * or whether the request succeeded or threw.
 */
public class MdcCleanupFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }
}
