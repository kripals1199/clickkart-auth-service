// src/main/java/com/clickkart/auth/feign/VerifyCaptchaRequest.java
package com.clickkart.auth.feign;

/** Own copy of Captcha Service's request DTO (Rule 4: no shared library). */
public record VerifyCaptchaRequest(String challengeId, String answer) {}
