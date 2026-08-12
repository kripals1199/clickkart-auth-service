// src/main/java/com/clickkart/auth/security/RestAuthenticationEntryPoint.java
package com.clickkart.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Safety net only - {@link com.clickkart.auth.jwt.JwtAuthenticationFilter} already resolves every rejection case itself
 * (missing/malformed/invalid/revoked token, missing correlationId) before a request would ever
 * reach here; this only fires if some other part of the chain denies a request without an
 * {@code Authentication} ever having been set. Delegates to the same {@code
 * HandlerExceptionResolver}/{@code GlobalExceptionHandler} pipeline every other error in this
 * service goes through, rather than writing its own response body, so the shape never drifts.
 */
@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        handlerExceptionResolver.resolveException(
                request, response, null, new BadCredentialsException("Authentication required", authException));
    }
}
