package com.app.security_auth.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.app.security_auth.entities.AppUser;
import com.app.security_auth.service.AuthenticationService;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;

@RestController
public class AuthController {

    private AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/home")
    public Map<String, Object> getMessages(Authentication auth) {
        return Map.of("message", "Welcome",
                "username", auth.getName(),
                "authorities", auth.getAuthorities());
    }

    @GetMapping("/pageAdmin")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public Map<String, String> pageAdmin() {
        return Map.of("message", "Welcome Admin");
    }

    /* ******************************* */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> jwtToken(
            @RequestBody AppUser user,
            @RequestParam String grantType,
            @RequestParam(required = false) String refreshToken,
            @RequestParam boolean withRefreshToken) {
        Map<String, String> tokens = authenticationService.generateTokens(user, grantType, refreshToken,
                withRefreshToken);
        return new ResponseEntity<>(tokens, HttpStatus.OK);
    }

}
