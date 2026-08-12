// src/main/java/com/clickkart/auth/entity/RoleEntity.java
package com.clickkart.auth.entity;

import com.clickkart.auth.enums.RoleType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotBlank;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(
        name = "roles",
        uniqueConstraints = @UniqueConstraint(name = "uk_roles_name", columnNames = "name"),
        indexes = @Index(name = "idx_roles_name", columnList = "name"))
public class RoleEntity extends BaseEntity {

    @NotBlank
    @Column(name = "name", nullable = false, unique = true, updatable = false, length = 40)
    private String name;

    @NotBlank
    @Column(name = "description", nullable = false, length = 255)
    private String description;

    public RoleEntity(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public boolean isNamed(RoleType roleType) {
        return this.name.equals(roleType.name());
    }
}
