package com.martin.springboot.security.authserver.auth.server.services;

import com.martin.springboot.security.authserver.auth.server.models.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findByName(String name);
    void save(String name);
    // boolean getAdmin(Long userId);
}
