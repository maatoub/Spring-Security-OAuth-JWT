package com.app.security_auth.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.security_auth.entities.AppRole;
import com.app.security_auth.entities.AppUser;
import com.app.security_auth.repository.AppRoleRepository;
import com.app.security_auth.repository.AppUserRepository;
import com.app.security_auth.service.intr.IAccountService;

@Service
@Transactional
public class AccountServiceImpl implements IAccountService {

    @Autowired
    private AppRoleRepository roleRepository;

    @Autowired
    private AppUserRepository userRepository;

    @Override
    public AppUser addUser(AppUser user) {
        if (user == null) {
            throw new IllegalArgumentException("User must not be null");
        }
        return userRepository.save(user);
    }

    @Override
    public AppRole addRole(AppRole role) {
        if (role == null) {
            throw new IllegalArgumentException("Role must not be null");
        }
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser user = userRepository.findByUsername(username);
        AppRole role = roleRepository.findByRole(roleName);
        user.getRoles().add(role);
    }

    @Override
    public AppUser loadUserByUserName(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> AllUsers() {
        return userRepository.findAll();
    }

}
