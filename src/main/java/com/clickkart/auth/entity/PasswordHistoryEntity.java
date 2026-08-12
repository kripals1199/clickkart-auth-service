// src/main/java/com/clickkart/auth/entity/PasswordHistoryEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "password_histories",
        indexes = @Index(name = "idx_password_histories_user_id", columnList = "user_id"))
public class PasswordHistoryEntity extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private ClickKartUserEntity clickKartUser;

    @Column(name = "password_hash", nullable = false, updatable = false, length = 100)
    private String passwordHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public PasswordHistoryEntity(ClickKartUserEntity clickKartUser, String passwordHash) {
        this.clickKartUser = clickKartUser;
        this.passwordHash = passwordHash;
        this.createdAt = Instant.now();
    }
}
