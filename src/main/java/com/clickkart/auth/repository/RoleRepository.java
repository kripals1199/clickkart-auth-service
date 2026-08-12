// src/main/java/com/clickkart/auth/repository/RoleRepository.java
package com.clickkart.auth.repository;

import com.clickkart.auth.entity.RoleEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    Optional<RoleEntity> findByName(String name);

    boolean existsByName(String name);

    /** Stable, alphabetical order for anything admin-facing (a role picker, a management listing) - not insertion order. */
    List<RoleEntity> findAllByOrderByNameAsc();
}
