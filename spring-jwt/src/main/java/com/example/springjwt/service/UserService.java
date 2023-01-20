package com.example.springjwt.service;

import com.example.springjwt.dao.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.Optional;

public interface UserService extends UserDetailsService {

    List<User> getAllUser();

    Optional<User> findUserById(Long id);

    Optional<User> findUserByLogin(String login);

    User save(User bean);

    @Override
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
