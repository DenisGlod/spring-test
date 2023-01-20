package com.example.springjwt.dao;

import com.example.springjwt.dao.entity.ERole;
import com.example.springjwt.dao.entity.Role;
import com.example.springjwt.dao.entity.User;
import com.example.springjwt.dao.repository.RoleRepository;
import com.example.springjwt.dao.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Component
public class DatabaseLoader implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    @Override
    public void run(String... args) {
        if (roleRepository.count() == 0 &&
                userRepository.count() == 0) {
            List<Role> roles = saveRoles();
            saveUsers(roles);
        }
    }

    private void saveUsers(List<Role> roles) {
        this.userRepository.saveAll(
                Arrays.asList(
                        User.builder()
                                .login("superAdminLogin")
                                .username("Super Admin")
                                .password("$2a$10$tW0JXiCcfhKKUW2Con.zx.fa7WRJM045c213CrHoDkWkti52G13u2")
                                .authorities(List.of(roles.get(0)))
                                .enabled(true)
                                .accountNonExpired(true)
                                .accountNonLocked(true)
                                .credentialsNonExpired(true)
                                .build(),
                        User.builder()
                                .login("adminLogin")
                                .username("Admin Admin")
                                .password("$2a$10$1WsKJuJ7aDudveJRCpKRfeIijUD7jV4yANQu0opXAMLXJZYDiihtW")
                                .authorities(List.of(roles.get(1)))
                                .enabled(true)
                                .accountNonExpired(true)
                                .accountNonLocked(true)
                                .credentialsNonExpired(true)
                                .build(),
                        User.builder()
                                .login("moderator1Login")
                                .username("Moderator Moderator")
                                .password("$2a$10$bOSeVkAlyaWjh5DegjwWTeUbwfFP1/G44ubmzlYZBN5a5r4EiFz2y")
                                .authorities(List.of(roles.get(2)))
                                .enabled(true)
                                .accountNonExpired(true)
                                .accountNonLocked(true)
                                .credentialsNonExpired(true)
                                .build(),
                        User.builder()
                                .login("userWith2Roles")
                                .username("Full Name")
                                .password("$2a$10$DnFE40mqLnug4XSWW9zyv.QtFty0O3WFjjeXjfJptkQXtrOSdBLpe")
                                .authorities(List.of(roles.get(0), roles.get(1)))
                                .enabled(true)
                                .accountNonExpired(true)
                                .accountNonLocked(true)
                                .credentialsNonExpired(true)
                                .build()
                )
        );
    }

    private List<Role> saveRoles() {
        return this.roleRepository.saveAll(
                Arrays.asList(
                        Role.builder().authority(ERole.SUPER_ADMIN.toString()).build(),
                        Role.builder().authority(ERole.ADMIN.toString()).build(),
                        Role.builder().authority(ERole.MODERATOR.toString()).build(),
                        Role.builder().authority(ERole.USER.toString()).build()
                )
        );
    }
}
