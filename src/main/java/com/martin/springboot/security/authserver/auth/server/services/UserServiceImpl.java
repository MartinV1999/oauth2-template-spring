package com.martin.springboot.security.authserver.auth.server.services;

import com.martin.springboot.security.authserver.auth.server.models.User;
import com.martin.springboot.security.authserver.auth.server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User save(User user) {
        if(user.getPassword() != null){
            user.setPassword(user.getPassword());
        }
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public List<User> findAll() {
        return (List<User>) userRepository.findAll();
    }

    @Override
    public Optional<User> getUserByEmail(String email) {
        Optional<User> op = userRepository.getUserByEmail(email);
        return op;
    }
}
