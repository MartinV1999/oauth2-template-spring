package com.martin.springboot.security.authserver.auth.server.services;

import com.martin.springboot.security.authserver.auth.server.models.Role;
import com.martin.springboot.security.authserver.auth.server.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
public class RoleServiceImpl implements RoleService{

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Optional<Role> findByName(String name) {
        return roleRepository.findByName(name);
    }

    @Override
    public void save(String name) {
        roleRepository.save(name);
    }
}
