// src/main/java/com/clickkart/auth/repository/ClickKartUserRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.ClickKartUserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ClickKartUserRepository extends JpaRepository<ClickKartUserEntity, Long>, JpaSpecificationExecutor<ClickKartUserEntity> {

    Optional<ClickKartUserEntity> findByPublicId(String publicId);

    Optional<ClickKartUserEntity> findByEmail(String email);

    Optional<ClickKartUserEntity> findByMobileNumber(String mobileNumber);

    boolean existsByEmail(String email);

    boolean existsByMobileNumber(String mobileNumber);

    /**
     * Same account as {@link #findByPublicId}, but with {@code userRoles}/{@code role} fetched
     * eagerly in the same round trip via {@code left join fetch} - for call sites (logout
     * resolving {@code principal.userId()}, future role-management endpoints) that need the
     * roles immediately rather than tolerating a lazy load later in the same transaction.
     * {@code distinct} guards against row duplication from the join when an account has more
     * than one role.
     */
    @Query("select distinct u from ClickKartUserEntity u left join fetch u.userRoles ur left join fetch ur.role where u.publicId = :publicId")
    Optional<ClickKartUserEntity> findByPublicIdWithRoles(@Param("publicId") String publicId);
}
