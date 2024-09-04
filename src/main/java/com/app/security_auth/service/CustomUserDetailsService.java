package com.app.security_auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.app.security_auth.entities.AppUser;
import com.app.security_auth.service.intr.IAccountService;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private IAccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = accountService.loadUserByUserName(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        String[] roles = user.getRoles().stream().map(u -> u.getRole()).toArray(String[]::new);
        UserDetails userDetails = User.withUsername(user.getUsername())
                .password(user.getPassword()).roles(roles).build();
        return userDetails;
    }

}
