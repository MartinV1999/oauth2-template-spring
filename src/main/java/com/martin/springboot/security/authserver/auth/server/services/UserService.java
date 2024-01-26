package com.martin.springboot.security.authserver.auth.server.services;

import com.martin.springboot.security.authserver.auth.server.models.User;

import java.util.List;
import java.util.Optional;

public interface UserService {
    User save(User user);
    Optional<User> findById(Long id);
    List<User> findAll();
    Optional<User> getUserByEmail(String email);
}
