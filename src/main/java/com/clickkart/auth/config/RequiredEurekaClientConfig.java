// src/main/java/com/clickkart/auth/config/RequiredEurekaClientConfig.java
package com.clickkart.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * eureka.client.service-url.defaultZone binds into a Map<String,String>, which Spring's
 * relaxed Binder does not validate for unresolved placeholders the way scalar properties are
 * validated - an unset env var would otherwise boot "successfully" with a literal, unparseable
 * defaultZone instead of failing fast (Rule 14). These beans force the same eager resolution
 * failure @Value already provides for scalar properties - same issue already fixed in
 * clickkart-config-server's and clickkart-eureka-server's own copies of this class.
 */
@Configuration(proxyBeanMethods = false)
@Profile({"test", "qa", "prod"})
class RequiredEurekaCredentialsConfig {

    RequiredEurekaCredentialsConfig(
            @Value("${EUREKA_DASHBOARD_USERNAME}") String eurekaDashboardUsername,
            @Value("${EUREKA_DASHBOARD_PASSWORD}") String eurekaDashboardPassword) {
        require(eurekaDashboardUsername, "EUREKA_DASHBOARD_USERNAME");
        require(eurekaDashboardPassword, "EUREKA_DASHBOARD_PASSWORD");
    }

    static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must not be blank");
        }
    }
}

@Configuration(proxyBeanMethods = false)
@Profile("prod")
class RequiredProdEurekaHostConfig {

    RequiredProdEurekaHostConfig(@Value("${EUREKA_SERVER_HOST}") String eurekaServerHost) {
        RequiredEurekaCredentialsConfig.require(eurekaServerHost, "EUREKA_SERVER_HOST");
    }
}
