// src/main/java/com/clickkart/auth/security/ClickKartUserPrincipal.java
package com.clickkart.auth.security;

import com.clickkart.auth.entity.ClickKartUserEntity;
import java.util.Collection;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Spring Security's view of a {@link ClickKartUserEntity}, for {@link ClickKartUserDetailsService} /
 * the {@code DaoAuthenticationProvider} authentication flow (see {@code SecurityConfig}).
 * {@code isEnabled()}/{@code isAccountNonLocked()} reflect the entity's flags at the moment this
 * wrapper was built - {@code AuthServiceImpl} already resolves lock/enabled decisions itself
 * (with time-based auto-unlock semantics this class knows nothing about) before ever asking the
 * {@code AuthenticationManager} to check a password, so those two flags are informational here,
 * not re-enforced by the provider (its pre/post authentication checks are disabled - see
 * {@code SecurityConfig.daoAuthenticationProvider}).
 */
@Getter
@RequiredArgsConstructor
public class ClickKartUserPrincipal implements UserDetails {

    private final ClickKartUserEntity clickKartUser;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return clickKartUser.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public String getPassword() {
        return clickKartUser.getPasswordHash();
    }

    /** The account's {@code publicId} - never the internal PK, never an email/mobile number. */
    @Override
    public String getUsername() {
        return clickKartUser.getPublicId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return clickKartUser.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return clickKartUser.isEnabled();
    }
}
