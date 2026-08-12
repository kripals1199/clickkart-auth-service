// src/main/java/com/clickkart/auth/constant/ApiPaths.java
package com.clickkart.auth.constant;

/**
 * Single source of truth for this service's route strings - used both in {@code
 * AuthController}'s {@code @PostMapping}/{@code @GetMapping} annotations and in {@code
 * SecurityConfig}'s public-path allow-list, so the two can never silently drift apart (a route
 * added to the controller but forgotten in the security allow-list, or vice versa, would either
 * 404 or leave an endpoint unintentionally open/closed).
 */
public final class ApiPaths {

    private ApiPaths() {}

    public static final String BASE = "/api/v1/auth";

    public static final String REGISTER = BASE + "/register";
    public static final String LOGIN = BASE + "/login";
    public static final String REFRESH = BASE + "/refresh";
    public static final String LOGOUT = BASE + "/logout";
    public static final String FORGOT_PASSWORD = BASE + "/forgot-password";
    public static final String RESET_PASSWORD = BASE + "/reset-password";
    public static final String OTP_REQUEST = BASE + "/otp/request";
    public static final String OTP_VERIFY = BASE + "/otp/verify";
    public static final String CHANGE_PASSWORD = BASE + "/change-password";
    /** Authenticated self-service (Bearer required) - not in PUBLIC_PATHS/RATE_LIMITED_PATHS, unlike the OTP login endpoints above. */
    public static final String VERIFY_CONTACT_REQUEST = BASE + "/verify-contact/request";
    public static final String VERIFY_CONTACT_CONFIRM = BASE + "/verify-contact/confirm";
    
    public static final String ACCOUNTS = BASE + "/accounts";
    public static final String ACCOUNT_LOCK = ACCOUNTS + "/{publicId}/lock";
    public static final String ACCOUNT_UNLOCK = ACCOUNTS + "/{publicId}/unlock";
    public static final String ACCOUNT_DELETE = ACCOUNTS + "/{publicId}/delete";
    
    public static final String AUDIT = BASE + "/audit";
    public static final String AUDIT_VERIFY = AUDIT + "/verify";

    public static final String ACTUATOR_HEALTH = "/actuator/health";
    public static final String ACTUATOR_HEALTH_WILDCARD = "/actuator/health/**";
    /**
     * Same treatment as health: scraped by Prometheus over the internal cluster network, never
     * through the Gateway, and a scraper has no way to present a JWT bearer token - the real
     * access control here is "this port isn't reachable from outside the cluster/VPC", identical
     * to how the k8s health probes already work.
     */
    public static final String ACTUATOR_PROMETHEUS = "/actuator/prometheus";

    public static final String SWAGGER_UI = "/swagger-ui.html";
    public static final String SWAGGER_UI_WILDCARD = "/swagger-ui/**";
    public static final String API_DOCS_WILDCARD = "/v3/api-docs/**";
}
