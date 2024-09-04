package com.app.security_auth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.app.security_auth.config.RsaKeysConfig;
import com.app.security_auth.entities.AppRole;
import com.app.security_auth.entities.AppUser;
import com.app.security_auth.service.intr.IAccountService;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class SecurityAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityAuthApplication.class, args);
	}

	// @Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner start(IAccountService accountService) {
		return args -> {
			new AppRole();
			new AppUser();
			accountService.addRole(AppRole.builder().role("ADMIN").id(null).build());
			accountService.addRole(AppRole.builder().role("USER").id(null).build());

			accountService
					.addUser(AppUser.builder().id(null).username("Nasser").password(
							passwordEncoder().encode("1234")).roles(null)
							.email("nasser@email.com")
							.build());
			accountService
					.addUser(AppUser.builder().id(null).username("Ahmed").password(passwordEncoder()
							.encode("1234")).roles(null).email("ahmed@email.com").build());

			accountService.addRoleToUser("Nasser", "ADMIN");
			accountService.addRoleToUser("Nasser", "USER");
			accountService.addRoleToUser("Ahmed", "USER");
		};
	}

}