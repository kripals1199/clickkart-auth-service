// src/main/java/com/clickkart/auth/entity/ClickKartUserEntity.java
package com.clickkart.auth.entity;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLRestriction;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@SQLRestriction("deleted = false")
@Table(name = "click_kart_users", uniqueConstraints = {
		@UniqueConstraint(name = "uk_users_public_id", columnNames = "public_id"),
		@UniqueConstraint(name = "uk_users_email", columnNames = "email"),
		@UniqueConstraint(name = "uk_users_mobile_number", columnNames = "mobile_number") }, indexes = {
				@Index(name = "idx_users_public_id", columnList = "public_id"),
				@Index(name = "idx_users_email", columnList = "email"),
				@Index(name = "idx_users_mobile_number", columnList = "mobile_number") })
public class ClickKartUserEntity extends BaseEntity {

	private static final String PUBLIC_ID_PREFIX = "USR-";

	@Column(name = "public_id", nullable = false, updatable = false, length = 40)
	private String publicId;

	@Email
	@NotBlank
	@Size(max = 254)
	@Column(name = "email", nullable = false, length = 254)
	private String email;

	@NotBlank
	@Pattern(regexp = "^[6-9]\\d{9}$", message = "Mobile number must be a valid 10-digit Indian number starting with 6, 7, 8, or 9")
	@Column(name = "mobile_number", nullable = false, length = 20)
	private String mobileNumber;

	@NotBlank
	@Size(min = 60, max = 100)
	@Column(name = "password_hash", nullable = false, length = 100)
	private String passwordHash;

	@OneToMany(mappedBy = "clickKartUser", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
	private final Set<UserRoleEntity> userRoles = new HashSet<>();

	@Column(name = "enabled", nullable = false)
	private boolean enabled = true;

	@Column(name = "account_non_locked", nullable = false)
	private boolean accountNonLocked = true;

	@Column(name = "email_verified", nullable = false)
	private boolean emailVerified = false;

	@Column(name = "mobile_verified", nullable = false)
	private boolean mobileVerified = false;

	@Column(name = "failed_login_attempts", nullable = false)
	private int failedLoginAttempts = 0;

	@Column(name = "lock_time")
	private Instant lockTime;

	@Column(name = "last_login_at")
	private Instant lastLoginAt;

	@Column(name = "last_failed_login_at")
	private Instant lastFailedLoginAt;

	@Column(name = "last_password_changed_at")
	private Instant lastPasswordChangedAt;

	@Column(name = "deleted", nullable = false)
	private boolean deleted = false;

	@Column(name = "deleted_at")
	private Instant deletedAt;

	public ClickKartUserEntity(String email, String mobileNumber, String passwordHash, Set<RoleEntity> roles) {
		this.publicId = PUBLIC_ID_PREFIX + UUID.randomUUID();
		this.email = email;
		this.mobileNumber = mobileNumber;
		this.passwordHash = passwordHash;
		this.lastPasswordChangedAt = Instant.now();
		roles.forEach(this::assignRole);
	}

	public Set<RoleEntity> getRoles() {
		return userRoles.stream().map(UserRoleEntity::getRole).collect(Collectors.toUnmodifiableSet());
	}

	public void assignRole(RoleEntity role) {
		this.userRoles.add(new UserRoleEntity(this, role));
	}

	public void revokeRole(RoleEntity role) {
		this.userRoles.removeIf(userRole -> userRole.getRole().getId().equals(role.getId()));
	}

	public void increaseFailedAttempts() {
		this.failedLoginAttempts++;
		this.lastFailedLoginAt = Instant.now();
	}

	public void resetFailedAttempts() {
		this.failedLoginAttempts = 0;
	}

	public void lock() {
		this.accountNonLocked = false;
		this.lockTime = Instant.now();
	}

	public void unlock() {
		this.accountNonLocked = true;
		this.lockTime = null;
		this.failedLoginAttempts = 0;
	}

	public boolean isLockExpired(Instant now, Duration lockoutDuration) {
		return lockTime != null && now.isAfter(lockTime.plus(lockoutDuration));
	}

	public void recordSuccessfulLogin() {
		this.lastLoginAt = Instant.now();
	}

	public void changePassword(String newPasswordHash) {
		this.passwordHash = newPasswordHash;
		this.lastPasswordChangedAt = Instant.now();
	}

	public void markEmailVerified() {
		this.emailVerified = true;
	}

	public void markMobileVerified() {
		this.mobileVerified = true;
	}

	public void softDelete() {
		this.deleted = true;
		this.deletedAt = Instant.now();
		this.enabled = false;
	}
}
