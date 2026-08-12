// src/main/java/com/clickkart/auth/security/ClickKartUserDetailsService.java
package com.clickkart.auth.security;

import com.clickkart.auth.repository.ClickKartUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Looks up strictly by {@code publicId} - never email/mobile. By the time {@code
 * AuthServiceImpl.login} calls the {@code AuthenticationManager}, it has already resolved the
 * caller-supplied identifier (which may be an email, mobile number, or publicId) down to one
 * account and its {@code publicId}; this service's only job is turning that already-resolved
 * publicId back into a {@link ClickKartUserPrincipal} for the provider to check the password
 * against - it is not where identifier resolution happens.
 */
@Service
@RequiredArgsConstructor
public class ClickKartUserDetailsService implements UserDetailsService {

    private final ClickKartUserRepository clickKartUserRepository;

    @Override
    @Transactional(readOnly = true, rollbackFor = Exception.class)
    public UserDetails loadUserByUsername(String publicId) throws UsernameNotFoundException {
        return clickKartUserRepository
                .findByPublicIdWithRoles(publicId)
                .map(ClickKartUserPrincipal::new)
                .orElseThrow(() -> new UsernameNotFoundException("No account for publicId: " + publicId));
    }
}
