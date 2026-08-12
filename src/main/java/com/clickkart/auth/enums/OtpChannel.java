// src/main/java/com/clickkart/auth/enums/OtpChannel.java
package com.clickkart.auth.enums;

/** Where a requested login OTP is delivered - the caller's choice, see {@code RequestOtpRequest}. */
public enum OtpChannel {
    SMS,
    EMAIL
}
