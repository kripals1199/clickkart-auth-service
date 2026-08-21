// src/main/java/com/clickkart/auth/config/SecurityConfig.java
package com.clickkart.auth.config;

import com.clickkart.auth.constant.ApiPaths;
import com.clickkart.auth.filter.RateLimitFilter;
import com.clickkart.auth.jwt.JwtAuthenticationFilter;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.security.AuthenticatedPrincipal;
import com.clickkart.auth.security.ClickKartUserDetailsService;
import com.clickkart.auth.security.CorrelationIdGenerator;
import com.clickkart.auth.security.RestAccessDeniedHandler;
import com.clickkart.auth.security.RestAuthenticationEntryPoint;
import com.clickkart.auth.security.RevocationService;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.web.ClientIpResolver;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Auth Service independently validates every access token via
 * {@link JwtAuthenticationFilter} rather than trusting Gateway-forwarded
 * headers - see that class's Javadoc for why. Sessions are stateless (JWT
 * end-to-end, Rule 1); CSRF is disabled since there is no cookie-based session
 * to protect.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@EnableMethodSecurity
public class SecurityConfig {

    /** Audited as the actor for flows with no authenticated principal yet (register, a failed login attempt). */
    private static final String SYSTEM_ACTOR = "system";

    private static final List<String> PUBLIC_PATHS = List.of(
            ApiPaths.REGISTER,
            ApiPaths.LOGIN,
            ApiPaths.REFRESH,
            ApiPaths.FORGOT_PASSWORD,
            ApiPaths.RESET_PASSWORD,
            ApiPaths.OTP_REQUEST,
            ApiPaths.OTP_VERIFY,
            ApiPaths.ACTUATOR_HEALTH,
            ApiPaths.ACTUATOR_HEALTH_WILDCARD,
            ApiPaths.ACTUATOR_PROMETHEUS,
            ApiPaths.SWAGGER_UI,
            ApiPaths.SWAGGER_UI_WILDCARD,
            ApiPaths.API_DOCS_WILDCARD);

    /** The unauthenticated endpoints most attractive to abuse - see {@code RateLimitFilter} Javadoc. */
    private static final List<String> RATE_LIMITED_PATHS = List.of(
            ApiPaths.REGISTER,
            ApiPaths.LOGIN,
            ApiPaths.REFRESH,
            ApiPaths.FORGOT_PASSWORD,
            ApiPaths.RESET_PASSWORD,
            ApiPaths.OTP_REQUEST,
            ApiPaths.OTP_VERIFY);

    /** {@code HstsHeaderWriter.DEFAULT_MAX_AGE_SECONDS} is private - this is the same 365-day value, just accessible. */
    private static final long HSTS_MAX_AGE_SECONDS = Duration.ofDays(365).toSeconds();

    /** Stateless JSON API - no inline scripts, no framing, no third-party resource loading. */
    private static final String CONTENT_SECURITY_POLICY = "default-src 'self'; frame-ancestors 'none'";

    @Bean
    public PasswordEncoder passwordEncoder(AuthProperties authProperties) {
        return new BCryptPasswordEncoder(authProperties.getPasswordEncoderStrength());
    }

    /**
     * The real Spring Security authentication abstraction for "does this password match" -
     * {@code AuthServiceImpl} calls {@code authenticationManager.authenticate(...)} instead of
     * comparing hashes itself. Pre/post authentication checks are disabled deliberately:
     * {@code AuthServiceImpl} already resolves enabled/locked decisions itself, with time-based
     * auto-unlock semantics this provider has no knowledge of, *before* ever calling authenticate
     * - letting the provider independently re-check those same two flags would either be
     * redundant (it agrees) or wrong (a timing disagreement about whether the account just
     * auto-unlocked). This provider's only remaining job is the password check itself.
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            ClickKartUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setPreAuthenticationChecks(userDetails -> {});
        provider.setPostAuthenticationChecks(userDetails -> {});
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtService jwtService,
            RevocationService revocationService,
            AuditTrailService auditTrailService,
            HandlerExceptionResolver handlerExceptionResolver,
            ClientIpResolver clientIpResolver) {
        return new JwtAuthenticationFilter(
                jwtService, 
                revocationService, 
                auditTrailService, 
                handlerExceptionResolver, 
                clientIpResolver, 
                PUBLIC_PATHS
             );
    }

    @Bean
    public RateLimitFilter rateLimitFilter(
            StringRedisTemplate redisTemplate,
            AuthProperties authProperties,
            AuditTrailService auditTrailService,
            CorrelationIdGenerator correlationIdGenerator,
            HandlerExceptionResolver handlerExceptionResolver,
            ClientIpResolver clientIpResolver) {
        return new RateLimitFilter(
                redisTemplate,
                authProperties, 
                auditTrailService, 
                correlationIdGenerator, 
                handlerExceptionResolver,
                clientIpResolver, 
                RATE_LIMITED_PATHS
                );
    }

    /** Defense in depth - this service is independently reachable, bypassing the Gateway's own CORS config. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(AuthProperties authProperties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.stream(authProperties.getAllowedOrigins().split(",")).map(String::trim).toList());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            RateLimitFilter rateLimitFilter,
            CorsConfigurationSource corsConfigurationSource,
            RestAuthenticationEntryPoint restAuthenticationEntryPoint,
            RestAccessDeniedHandler restAccessDeniedHandler)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_PATHS.toArray(new String[0]))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                // Registration order matters here: addFilterBefore(x, y) requires y's Class to
                // already have a registered order, and a custom filter class only gets one once
                // it has itself been passed to an addFilter* call - jwtAuthenticationFilter must
                // therefore be registered (anchored to the well-known UsernamePasswordAuthenticationFilter)
                // before rateLimitFilter can anchor to JwtAuthenticationFilter.class.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(rateLimitFilter, JwtAuthenticationFilter.class)
                // Safety net only - see RestAuthenticationEntryPoint/RestAccessDeniedHandler Javadoc.
                .exceptionHandling(handler -> handler
                        .authenticationEntryPoint(restAuthenticationEntryPoint)
                        .accessDeniedHandler(restAccessDeniedHandler))
                // Explicit rather than relying silently on Spring Security's own defaults (Rule
                // 14) - even though several of these already match what it applies out of the
                // box. This is a stateless JSON API, never rendered in a frame, and every
                // response should be treated as non-cacheable by intermediaries.
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.deny())
                        .contentTypeOptions(contentTypeOptions -> {})
                        .cacheControl(cacheControl -> {})
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(HSTS_MAX_AGE_SECONDS)));
        return http.build();
    }

    /**
     * createdBy/updatedBy source (Rule 3). Unauthenticated flows (register, a failed login
     * attempt) have no SecurityContext yet, so they audit as {@value #SYSTEM_ACTOR} rather than
     * a spoofable client-supplied value.
     */
    @Bean
    public AuditorAware<String> auditorAware() {
        return () -> Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(authentication -> authentication.getPrincipal())
                .filter(AuthenticatedPrincipal.class::isInstance)
                .map(AuthenticatedPrincipal.class::cast)
                .map(principal -> principal.userId())
                .or(() -> Optional.of(SYSTEM_ACTOR));
    }
}
