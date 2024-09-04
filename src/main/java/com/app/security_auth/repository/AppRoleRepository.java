package com.app.security_auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.security_auth.entities.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRole(String role);
}
