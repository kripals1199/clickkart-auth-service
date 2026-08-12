// src/main/java/com/clickkart/auth/feign/AuditLogServiceClientFallbackFactory.java
package com.clickkart.auth.feign;

import com.clickkart.auth.exception.DownstreamServiceUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

/**
 * The Audit Log Service is a required dependency (Section 3 compliance rule: every write must
 * be durably audited) - on open-circuit/error, this logs locally at WARN with full detail (so
 * the failure isn't silently lost even though the request itself is about to fail too) and then
 * throws {@link DownstreamServiceUnavailableException}, which Feign's fallback-invocation
 * mechanism propagates to the caller exactly as if the underlying call had thrown it directly.
 * {@code AuthTrailServiceImpl.record()} does not catch this - it's meant to abort whatever write
 * it was called from, same as a database failure would.
 */
@Slf4j
@Component
public class AuditLogServiceClientFallbackFactory implements FallbackFactory<AuditLogServiceClient> {

    private static final String SERVICE_NAME = "Audit Log Service";

    @Override
    public AuditLogServiceClient create(Throwable cause) {
        return (correlationId, request) -> {
            log.warn(
                    "AUDIT_DISPATCH_FAILED correlationId={} actor={} action={} ipAddress={} timestamp={} details={} - audit-log-service unreachable, cause={}",
                    correlationId,
                    request.actor(),
                    request.action(),
                    request.ipAddress(),
                    request.timestamp(),
                    request.details(),
                    cause.toString());
            throw new DownstreamServiceUnavailableException(SERVICE_NAME, cause);
        };
    }
}
