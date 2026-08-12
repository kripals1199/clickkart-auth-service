// src/main/java/com/clickkart/auth/dto/response/ClickKartUserSummaryResponse.java
package com.clickkart.auth.dto.response;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.RoleEntity;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

public record ClickKartUserSummaryResponse(
        String publicId,
        String email,
        String mobileNumber,
        Set<String> roles,
        boolean enabled,
        boolean locked,
        boolean emailVerified,
        boolean mobileVerified,
        Instant lastLoginAt,
        Instant createdDate) {

    public static ClickKartUserSummaryResponse from(ClickKartUserEntity clickKartUser) {
        return new ClickKartUserSummaryResponse(
                clickKartUser.getPublicId(),
                clickKartUser.getEmail(),
                clickKartUser.getMobileNumber(),
                clickKartUser.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()),
                clickKartUser.isEnabled(),
                !clickKartUser.isAccountNonLocked(),
                clickKartUser.isEmailVerified(),
                clickKartUser.isMobileVerified(),
                clickKartUser.getLastLoginAt(),
                clickKartUser.getCreatedDate());
    }
}
