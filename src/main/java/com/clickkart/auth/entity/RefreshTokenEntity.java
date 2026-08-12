// src/main/java/com/clickkart/auth/entity/RefreshTokenEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "refresh_tokens", uniqueConstraints = @UniqueConstraint(name = "uk_refresh_tokens_token_hash", columnNames = "token_hash"), indexes = {
		@Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
		@Index(name = "idx_refresh_tokens_token_hash", columnList = "token_hash") })
public class RefreshTokenEntity extends BaseEntity {

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "user_id", nullable = false)
	private ClickKartUserEntity clickKartUser;

	@Column(name = "token_hash", nullable = false, length = 64)
	private String tokenHash;

	@Column(name = "correlation_id", nullable = false, length = 36)
	private String correlationId;

	@Column(name = "issued_at", nullable = false)
	private Instant issuedAt;

	@Column(name = "expires_at", nullable = false)
	private Instant expiresAt;

	@Column(name = "revoked", nullable = false)
	private boolean revoked = false;

	@Column(name = "revoked_at")
	private Instant revokedAt;

	/**
	 * Set when this token is rotated away (see {@code AuthServiceImpl.refresh}) to the hash of
	 * the token that replaced it - lets Part 5's reuse-detection distinguish "this token is just
	 * expired" from "this exact, already-rotated-away token is being presented again", which is
	 * the signature of a stolen refresh token being replayed after the legitimate client already
	 * rotated past it. {@code correlationId} (shared across every rotation of one login session,
	 * per Rule 13) is what reuse-detection uses to find and revoke the rest of that session's
	 * chain once a reuse is confirmed.
	 */
	@Column(name = "replaced_by_token_hash", length = 64)
	private String replacedByTokenHash;

	public RefreshTokenEntity(ClickKartUserEntity clickKartUser, String tokenHash, String correlationId, Instant issuedAt,
			Instant expiresAt) {
		this.clickKartUser = clickKartUser;
		this.tokenHash = tokenHash;
		this.correlationId = correlationId;
		this.issuedAt = issuedAt;
		this.expiresAt = expiresAt;
	}

	public boolean isUsable(Instant now) {
		return !revoked && expiresAt.isAfter(now);
	}

	public void revoke(Instant now) {
		this.revoked = true;
		this.revokedAt = now;
	}

	public void revokeAsRotated(Instant now, String newTokenHash) {
		revoke(now);
		this.replacedByTokenHash = newTokenHash;
	}

	public boolean wasReplayedAfterRotation() {
		return revoked && replacedByTokenHash != null;
	}
}
