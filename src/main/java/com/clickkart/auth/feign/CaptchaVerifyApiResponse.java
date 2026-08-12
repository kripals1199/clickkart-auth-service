// src/main/java/com/clickkart/auth/feign/CaptchaVerifyApiResponse.java
package com.clickkart.auth.feign;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Minimal shape needed to pull {@code data} out of Captcha Service's full {@code ApiResponse}
 * envelope - {@code @JsonIgnoreProperties(ignoreUnknown = true)} so the other envelope fields
 * (timestamp/status/success/...) don't need a matching field here.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CaptchaVerifyApiResponse(CaptchaVerificationResult data) {}
