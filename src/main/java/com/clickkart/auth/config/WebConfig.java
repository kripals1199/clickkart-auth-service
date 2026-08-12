// src/main/java/com/clickkart/auth/config/WebConfig.java
package com.clickkart.auth.config;

import com.clickkart.auth.filter.AccessLogFilter;
import com.clickkart.auth.filter.MdcCleanupFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class WebConfig {

	@Bean
	public FilterRegistrationBean<MdcCleanupFilter> mdcCleanupFilter() {
		FilterRegistrationBean<MdcCleanupFilter> registration = new FilterRegistrationBean<>(new MdcCleanupFilter());
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
		registration.addUrlPatterns("/*");
		return registration;
	}

	@Bean
	public FilterRegistrationBean<AccessLogFilter> accessLogFilter() {
		FilterRegistrationBean<AccessLogFilter> registration = new FilterRegistrationBean<>(new AccessLogFilter());
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
		registration.addUrlPatterns("/*");
		return registration;
	}
}
