// src/main/java/com/clickkart/auth/filter/AccessLogFilter.java
package com.clickkart.auth.filter;

import com.clickkart.auth.constant.LoggerNames;
import com.clickkart.auth.constant.MdcKeys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Feeds the dedicated "ACCESS" logger routed to logs/access.log by logback-spring.xml. Runs
 * just inside {@link MdcCleanupFilter} so it can still read the correlationId (if one has been
 * minted by this point) before that outer filter clears MDC.
 *
 * <p>Logs a matching REQUEST_START/REQUEST_END pair per request, not just a single after-the-fact
 * summary - REQUEST_START lets an operator see a request actually began (and, by its absence, spot
 * one that started but never produced a matching END - a hung handler, a thread pool exhausted
 * before it could even begin, etc.) without waiting for it to finish first.
 */
@Slf4j(topic = LoggerNames.ACCESS)
public class AccessLogFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        log.info(
                "REQUEST_START method={} uri={} remoteAddr={} correlationId={}",
                request.getMethod(),
                request.getRequestURI(),
                request.getRemoteAddr(),
                MDC.get(MdcKeys.CORRELATION_ID));

        long start = System.currentTimeMillis();
        try {
            chain.doFilter(request, response);
        } finally {
            long durationMs = System.currentTimeMillis() - start;
            log.info(
                    "REQUEST_END method={} uri={} status={} durationMs={} remoteAddr={} correlationId={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    durationMs,
                    request.getRemoteAddr(),
                    MDC.get(MdcKeys.CORRELATION_ID));
        }
    }
}
