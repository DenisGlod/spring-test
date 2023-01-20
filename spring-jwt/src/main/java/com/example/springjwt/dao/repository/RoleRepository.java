package com.example.springjwt.dao.repository;

import com.example.springjwt.dao.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
