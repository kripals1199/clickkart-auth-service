// src/main/java/com/clickkart/auth/config/AuthProperties.java
package com.clickkart.auth.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /** HMAC-SHA256 signing key shared with the Gateway, which validates tokens minted here. */
    private String jwtSecret;

    private long accessTokenTtlSeconds = 900;

    private long refreshTokenTtlSeconds = 604800;

    private int maxFailedLoginAttempts = 5;

    private long lockoutDurationMinutes = 15;

    private int passwordEncoderStrength = 12;

    /** Number of random bytes backing an opaque refresh token before base64url encoding. */
    private int refreshTokenBytes = 64;

    /** Must match the Gateway's own revoked-jti key prefix exactly. */
    private String revocationKeyPrefix = "revoked:jti:";

    /** How long a password reset token remains usable after being issued. */
    private long passwordResetTokenTtlSeconds = 1800;

    /** Number of random bytes backing an opaque password reset token before base64url encoding. */
    private int passwordResetTokenBytes = 32;

    /** How many of an account's most recent passwords a new password may not match. */
    private int passwordHistoryLimit = 5;

    /**
     * Comma-separated origins allowed to call this service's API directly (defense in depth -
     * the Gateway already has its own CORS config, but this service is independently reachable).
     */
    private String allowedOrigins = "http://localhost:4200";

    /** Max requests a single IP may make to a rate-limited public endpoint within {@link #rateLimitWindowSeconds}. */
    private int rateLimitMaxRequests = 10;

    /** Window size for {@link #rateLimitMaxRequests} - a fixed (not sliding) window, reset by Redis key TTL. */
    private long rateLimitWindowSeconds = 60;

    /** Digit length of a login OTP (e.g. 6 -> a code like "042817"). */
    private int otpLength = 6;

    /** How long an issued OTP remains usable. */
    private long otpTtlSeconds = 300;

    /** Wrong guesses a single issued OTP tolerates before it burns itself out, independent of the account-level lockout. */
    private int otpMaxVerifyAttempts = 5;

    /**
     * How long an issued email/mobile verification code remains usable - deliberately much more
     * generous than {@link #otpTtlSeconds} (5 minutes), since confirming a contact detail isn't
     * time-pressured the way logging in is.
     */
    private long verificationCodeTtlSeconds = 86400;

    /** Wrong guesses a single issued verification code tolerates before it burns itself out. */
    private int verificationCodeMaxVerifyAttempts = 5;

    /**
     * CIDRs (or bare IPs) of proxies allowed to set {@code X-Forwarded-For} - only a request
     * whose immediate {@code remoteAddr} matches one of these is trusted to have set that header
     * honestly; anyone else's claimed value is ignored. This service is independently reachable
     * (bypassing the Gateway is explicitly supported), so unconditionally trusting this header
     * would let a direct caller forge their apparent IP and defeat per-IP rate limiting entirely.
     * Empty by default (trust nothing but the immediate socket address) - dev sets a permissive
     * fallback, prod/qa/test must configure the real Gateway/ingress CIDR deliberately. See
     * {@code ClientIpResolver}.
     */
    private List<String> trustedProxyCidrs = List.of();
}
