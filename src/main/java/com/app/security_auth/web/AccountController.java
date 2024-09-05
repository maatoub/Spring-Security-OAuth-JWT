package com.app.security_auth.web;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.app.security_auth.entities.AppRole;
import com.app.security_auth.entities.AppUser;
import com.app.security_auth.service.intr.IAccountService;

@RestController
@RequestMapping("/account")
@PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
public class AccountController {

    private IAccountService service;

    public AccountController(IAccountService service) {
        this.service = service;
    }

    @PostMapping("/user")
    public ResponseEntity<AppUser> createUser(@RequestBody AppUser user) {
        return new ResponseEntity<>(service.addUser(user), HttpStatus.CREATED);
    }

    @PostMapping("/role")
    public ResponseEntity<AppRole> createRole(@RequestBody AppRole role) {
        return new ResponseEntity<>(service.addRole(role), HttpStatus.CREATED);
    }

    @PostMapping("/assigned")
    public ResponseEntity<Void> addRoleToUser(@RequestParam String username, @RequestParam String role) {
        service.addRoleToUser(username, role);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<List<AppUser>> allUsers() {
        return new ResponseEntity<>(service.AllUsers(), HttpStatus.OK);
    }

}
