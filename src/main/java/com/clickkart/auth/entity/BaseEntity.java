// src/main/java/com/clickkart/auth/entity/BaseEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Parameter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.Setter;

/**
 * Compliance fields required on every entity (Rule 3). Populated by {@code
 * com.clickkart.auth.config.SecurityConfig}'s {@code auditorAware} bean - "system" for
 * unauthenticated flows (register, failed login) and the authenticated principal's publicId
 * otherwise. {@code id}/{@code version} are getter-only here - they're strictly
 * framework-managed (generated PK, optimistic-lock counter), never set directly by application
 * code - even {@code AuditChainHeadEntity}'s fixed singleton id is assigned by {@link
 * AssignedOrSequenceIdGenerator} at persist time, not by application code beforehand (see that
 * generator's Javadoc for why an application-assigned id here would break on a versioned entity).
 */
@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    @Id
    @GeneratedValue(generator = "user_seq_gen")
    @GenericGenerator(
            name = "user_seq_gen",
            type = AssignedOrSequenceIdGenerator.class,
            parameters = {
                @Parameter(name = "sequence_name", value = "user_seq"),
                @Parameter(name = "increment_size", value = "1")
            })
    private Long id;

    @Setter
    @CreatedBy
    @Column(name = "created_by", nullable = false, updatable = false, length = 100)
    private String createdBy;

    @Setter
    @CreatedDate
    @Column(name = "created_date", nullable = false, updatable = false)
    private Instant createdDate;

    @Setter
    @LastModifiedBy
    @Column(name = "updated_by", nullable = false, length = 100)
    private String updatedBy;

    @Setter
    @LastModifiedDate
    @Column(name = "updated_date", nullable = false)
    private Instant updatedDate;

    @Version
    @Column(name = "version", nullable = false)
    private Long version;
}
