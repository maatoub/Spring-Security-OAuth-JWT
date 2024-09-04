package com.app.security_auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.security_auth.entities.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
