package com.app.security_auth.service.intr;

import com.app.security_auth.entities.AppRole;
import com.app.security_auth.entities.AppUser;
import java.util.List;

public interface IAccountService {
    AppUser addUser(AppUser user);

    AppRole addRole(AppRole role);

    void addRoleToUser(String username, String roleName);

    AppUser loadUserByUserName(String username);

    List<AppUser> AllUsers();
}
