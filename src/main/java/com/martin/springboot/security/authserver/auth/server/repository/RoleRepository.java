package com.martin.springboot.security.authserver.auth.server.repository;

import com.martin.springboot.security.authserver.auth.server.models.Role;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends CrudRepository<Role, Long> {
    Optional<Role> findByName(String name);

    @Modifying
    @Query("INSERT INTO Role (name) VALUES (?1)")
    void save(String name);
}
