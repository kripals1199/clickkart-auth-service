// src/main/java/com/clickkart/auth/repository/ClickKartUserSpecifications.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.RoleEntity;
import com.clickkart.auth.entity.UserRoleEntity;
import com.clickkart.auth.enums.RoleType;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

/**
 * Real Specification-based filtering for the admin account-listing endpoint (Rule 12: no
 * hardcoded arrays pretending to be a paginated/filterable list).
 */
public final class ClickKartUserSpecifications {

    // JPA Criteria attribute names are inherently string-based (no static metamodel in this
    // project) - named as constants here rather than repeated inline literals, so a rename of
    // ClickKartUserEntity/UserRoleEntity/RoleEntity fields has exactly one place to fix in this class.
    private static final String ATTR_USER_ROLES = "userRoles";
    private static final String ATTR_ROLE = "role";
    private static final String ATTR_ROLE_NAME = "name";
    private static final String ATTR_ACCOUNT_NON_LOCKED = "accountNonLocked";
    private static final String ATTR_EMAIL = "email";

    private ClickKartUserSpecifications() {}

    public static Specification<ClickKartUserEntity> withFilters(RoleType roleType, Boolean locked, String emailContains) {
        return (root, query, cb) -> {
            Predicate predicate = cb.conjunction();

            if (roleType != null) {
                query.distinct(true);
                Join<ClickKartUserEntity, UserRoleEntity> userRoleJoin = root.join(ATTR_USER_ROLES);
                Join<UserRoleEntity, RoleEntity> roleJoin = userRoleJoin.join(ATTR_ROLE);
                predicate = cb.and(predicate, cb.equal(roleJoin.get(ATTR_ROLE_NAME), roleType.name()));
            }

            if (locked != null) {
                // accountNonLocked is the persisted flag - true means NOT locked.
                predicate = cb.and(predicate, cb.equal(root.get(ATTR_ACCOUNT_NON_LOCKED), !locked));
            }

            if (StringUtils.hasText(emailContains)) {
                predicate = cb.and(
                        predicate,
                        cb.like(cb.lower(root.get(ATTR_EMAIL)), "%" + emailContains.toLowerCase() + "%"));
            }

            return predicate;
        };
    }
}
