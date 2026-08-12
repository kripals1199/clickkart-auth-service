// src/main/java/com/clickkart/auth/entity/AuditChainHeadEntity.java
package com.clickkart.auth.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "audit_chain_head")
public class AuditChainHeadEntity extends BaseEntity {

    /** There is exactly one row in this table, always with this id - see {@link AssignedOrSequenceIdGenerator}. */
    public static final long SINGLETON_ID = 1L;

    @Column(name = "last_entry_hash", nullable = false, length = 64)
    private String lastEntryHash;

    @Column(name = "entry_count", nullable = false)
    private long entryCount;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public AuditChainHeadEntity(String genesisHash) {
        this.lastEntryHash = genesisHash;
        this.entryCount = 0;
        this.updatedAt = Instant.now();
    }

    public void advance(String newEntryHash) {
        this.lastEntryHash = newEntryHash;
        this.entryCount++;
        this.updatedAt = Instant.now();
    }
}
