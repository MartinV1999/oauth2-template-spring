package com.martin.springboot.security.authserver.auth.server.services;

import com.martin.springboot.security.authserver.auth.server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class JpaUserDetailsService implements UserDetailsService {
    @Autowired
    private UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<com.martin.springboot.security.authserver.auth.server.models.User> o = userService.getUserByEmail(username);
        if(!o.isPresent()){
            throw new UsernameNotFoundException(String.format("Username %s no existe en el sistema!", username));
        }

        com.martin.springboot.security.authserver.auth.server.models.User user = o.orElseThrow();
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList());


        return new User(user.getEmail(), user.getPassword(),true,true,true,true,authorities);

    }
}
