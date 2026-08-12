// src/main/java/com/clickkart/auth/config/OpenApiConfig.java
package com.clickkart.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Backs the Swagger UI at {@code /swagger-ui.html} (see {@code SecurityConfig.PUBLIC_PATHS} for
 * why that path itself is public - the UI still requires a real Bearer token, obtained via
 * {@code POST /api/v1/auth/login}, to try any endpoint beyond register/login/refresh/
 * forgot-password/reset-password). The "Authorize" button this scheme adds lets a caller paste
 * that token once and have it applied to every subsequent try-it-out request.
 */
@Configuration
public class OpenApiConfig {

    private static final String BEARER_SCHEME_NAME = "bearerAuth";

    @Bean
    public OpenAPI authServiceOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("ClickKart Auth Service")
                        .version("1.0.0")
                        .description(
                                "Registration, login, JWT/refresh issuance, logout/token revocation, "
                                        + "forgot/reset/change password, and admin account management."))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME_NAME))
                .components(new Components()
                        .addSecuritySchemes(
                                BEARER_SCHEME_NAME,
                                new SecurityScheme()
                                        .name(BEARER_SCHEME_NAME)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")));
    }
}
