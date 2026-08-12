// src/main/java/com/clickkart/auth/jwt/JwtService.java
package com.clickkart.auth.jwt;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.util.Sha256;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

/**
 * Mints and validates the HMAC-SHA256-signed access tokens the Gateway (and
 * this service's own {@link JwtAuthenticationFilter}) validate. Refresh tokens
 * are deliberately NOT JWTs - they are opaque, high-entropy random strings
 * whose SHA-256 hash is the only thing persisted (see
 * {@link #generateOpaqueRefreshToken()} / {@link #hashToken(String)}), so a
 * refresh token can be revoked/rotated by a single row update rather than
 * needing a signature-based blocklist.
 *
 * <p>
 * Not a Lombok {@code @RequiredArgsConstructor} candidate - {@code signingKey}
 * is derived from {@code authProperties} at construction time, not just
 * assigned, and that derivation must run synchronously whether this is built by
 * Spring or directly via {@code new JwtService(...)} in a unit test (a
 * {@code @PostConstruct} hook would only fire under a Spring container).
 */
@Service
public class JwtService {

	private final AuthProperties authProperties;
	private final SecretKey signingKey;
	private final SecureRandom secureRandom = new SecureRandom();

	public JwtService(AuthProperties authProperties) {
		this.authProperties = authProperties;
		this.signingKey = Keys.hmacShaKeyFor(authProperties.getJwtSecret().getBytes(StandardCharsets.UTF_8));
	}

	public record MintedAccessToken(String token, String jti, Instant expiresAt) {
	}

	/**
	 * Mints an access token. {@code correlationId} is minted once at login and
	 * reused verbatim on every refresh. {@code publicId} (ClickKartUserEntity's
	 * external-facing identifier, never the internal Long PK) becomes the JWT
	 * subject. {@code roleNames} are the persisted {@code RoleEntity.name} values
	 * (e.g. {@code "ROLE_ADMIN"}) held by the account at mint time - plain strings,
	 * not the {@code RoleType} enum, since roles are now admin-manageable data.
	 */
	public MintedAccessToken mintAccessToken(String publicId, Set<String> roleNames, String correlationId) {
		Instant now = Instant.now();
		Instant expiresAt = now.plusSeconds(authProperties.getAccessTokenTtlSeconds());
		String jti = UUID.randomUUID().toString();
		String rolesClaim = String.join(",", roleNames);

		String token = Jwts.builder().subject(publicId).id(jti).issuedAt(Date.from(now))
				.expiration(Date.from(expiresAt)).claim(JwtClaimNames.ROLES, rolesClaim)
				.claim(JwtClaimNames.CORRELATION_ID, correlationId).signWith(signingKey).compact();

		return new MintedAccessToken(token, jti, expiresAt);
	}

	/**
	 * @throws JwtException if the token is malformed, expired, or has an invalid
	 *                      signature
	 */
	public Claims parseAndValidate(String token) throws JwtException {
		return Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
	}

	public String generateOpaqueRefreshToken() {
		return generateOpaqueToken(authProperties.getRefreshTokenBytes());
	}

	/**
	 * Generic opaque-token generator shared by refresh tokens and password reset
	 * tokens (see {@code PasswordResetService}).
	 */
	public String generateOpaqueToken(int numBytes) {
		byte[] bytes = new byte[numBytes];
		secureRandom.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * A zero-padded, uniformly-distributed numeric code of exactly {@code digits}
	 * length (e.g. {@code "042817"} for {@code digits=6}) - for {@code OtpService},
	 * where the code must be short enough for a human to type/read over SMS/email,
	 * unlike the opaque tokens above.
	 */
	public String generateNumericOtp(int digits) {
		int bound = (int) Math.pow(10, digits);
		int value = secureRandom.nextInt(bound);
		return String.format("%0" + digits + "d", value);
	}

	public String hashToken(String rawToken) {
		return Sha256.hex(rawToken);
	}
}
