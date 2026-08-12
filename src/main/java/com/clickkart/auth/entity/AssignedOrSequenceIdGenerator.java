// src/main/java/com/clickkart/auth/entity/AssignedOrSequenceIdGenerator.java
package com.clickkart.auth.entity;

import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.enhanced.SequenceStyleGenerator;

/**
 * Every {@link BaseEntity} subclass gets its id from the shared sequence, except
 * {@code AuditChainHeadEntity}, which is a fixed-id singleton row (see that class's Javadoc).
 * The fixed id is special-cased here by entity type rather than by pre-assigning {@code id} in
 * the constructor before persist() - a non-null id on an entity that also carries {@code
 * BaseEntity}'s {@code @Version} makes Hibernate's own transient/detached determination treat it
 * as an inconsistent "detached entity with an uninitialized version" state and throw, since a
 * real detached (already-persisted) entity would never have a null version. Leaving {@code id}
 * null until this generator runs keeps that determination consistent (null id, null version -
 * genuinely new) for every entity, including this one.
 */
public class AssignedOrSequenceIdGenerator extends SequenceStyleGenerator {

    @Override
    public Object generate(SharedSessionContractImplementor session, Object owner) {
        if (owner instanceof AuditChainHeadEntity) {
            return AuditChainHeadEntity.SINGLETON_ID;
        }
        return super.generate(session, owner);
    }
}
