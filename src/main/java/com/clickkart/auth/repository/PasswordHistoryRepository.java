// src/main/java/com/clickkart/auth/repository/PasswordHistoryRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.PasswordHistoryEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Backs the "cannot reuse your last N passwords" policy (Part 6). Extends full {@code
 * JpaRepository} - a documented retention job trimming very old rows for an account is a
 * legitimate operation here (see {@link PasswordHistoryEntity}'s own Javadoc), same reasoning as
 * {@code LoginAuditRepository}.
 */
@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistoryEntity, Long> {

    /**
     * "Give me only the last N password hashes for this user", not the whole history - a native
     * query with {@code LIMIT} beats fetching every row this account has ever had and truncating
     * in Java, which only gets worse the longer an account has existed. Standard JPQL has no
     * portable {@code LIMIT}; a native query is the beneficial case for it here.
     */
    @Query(
            value = "select * from password_histories where user_id = :userId order by created_at desc limit :limit",
            nativeQuery = true)
    List<PasswordHistoryEntity> findRecentByUserId(@Param("userId") Long userId, @Param("limit") int limit);

    @Query("select count(ph) from PasswordHistoryEntity ph where ph.clickKartUser.id = :userId")
    long countByUserId(@Param("userId") Long userId);
}
