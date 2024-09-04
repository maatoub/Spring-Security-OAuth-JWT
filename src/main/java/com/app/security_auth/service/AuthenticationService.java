package com.app.security_auth.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.app.security_auth.entities.AppUser;

import java.util.Map;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    private JwtEncoder jwtEncoder;

    private JwtDecoder jwtDecoder;

    private UserDetailsService userDetailsService;

    private AuthenticationManager authManager;

    public AuthenticationService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService,
            AuthenticationManager authManager) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
        this.authManager = authManager;
    }

    public Map<String, String> generateTokens(
            AppUser user,
            String grantType,
            String refreshToken,
            boolean withRefreshToken) {

        String subject = null;
        String scope = null;

        // Vérifie le type de grant
        if (grantType.equals("password")) {
            // Authentifie l'utilisateur avec le nom d'utilisateur et le mot de passe
            Authentication authenticate = authManager
                    .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            // Récupère le nom et les roles
            subject = authenticate.getName();
            scope = authenticate.getAuthorities().stream().map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));

        } else if (grantType.equals("refreshToken")) {
            if (refreshToken == null) {
                throw new IllegalArgumentException("Refresh Tokon is required");
            }
            // Décode le refresh token pour obtenir les informations de l'utilisateur

            Jwt decodeJWT = jwtDecoder.decode(refreshToken);

            subject = decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            scope = userDetails.getAuthorities().stream().map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));
        }

        // map pour stocker les tokens
        Map<String, String> tokens = new HashMap<>();

        Instant instant = Instant.now();
        // les claims du JWT pour le token d'accès
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken ? 1 : 5, ChronoUnit.MINUTES))
                .issuer("security-auth")
                .claim("scope", scope)
                .build();
        // Encode les claims
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        tokens.put("jwtAccessToken", jwtAccessToken);

        // Crée les claims du JWT pour le refresh token
        if (withRefreshToken) {
            // Crée les claims du JWT pour le refresh token
            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                    .issuer("security-auth")
                    .build();

            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();

            tokens.put("jwtRefreshToken", jwtRefreshToken);
        }

        return tokens;
    }

    public String extractUsername(String token) {
        Jwt jwtDecode = jwtDecoder.decode(token);
        return jwtDecode.getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        Jwt jwtDecode = jwtDecoder.decode(token);
        String username = jwtDecode.getSubject();
        Date expiration = Date.from(jwtDecode.getExpiresAt());
        return (username.equals(userDetails.getUsername()) && !expiration.before(new Date(System.currentTimeMillis())));
    }
}
