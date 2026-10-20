package com.example.api;

import io.openback.appauth.AppUser;
import io.openback.appauth.spring.OpenBackAppAuthFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * A Spring Boot 3 API accepting the pool's access tokens (see application.properties). Without the SecurityFilterChain
 * bean below, the starter registers a default one (every request needs an app user's token).
 */
@SpringBootApplication
@EnableMethodSecurity
public class ApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiApplication.class, args);
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http, OpenBackAppAuthFilter appAuth) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/admin/**").hasRole("admin")                     // ROLE_<role>
                        .requestMatchers("/invoices/**").hasAuthority("PERM_invoices.read")  // PERM_<permission>
                        .anyRequest().authenticated())
                .addFilterBefore(appAuth, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e.authenticationEntryPoint(OpenBackAppAuthFilter.ENTRY_POINT)
                        .accessDeniedHandler(OpenBackAppAuthFilter.ACCESS_DENIED))
                .build();
    }

    @RestController
    static class Api {
        @GetMapping("/health")
        Map<String, Object> health() {
            return Map.of("ok", true);
        }

        @GetMapping("/me")
        Map<String, Object> me(@AuthenticationPrincipal AppUser user) {
            return Map.of("id", user.getId(), "org", String.valueOf(user.getOrgId()), "roles", user.getRoles());
        }

        @GetMapping("/reports")
        @PreAuthorize("principal.hasPermission('reports.read')")   // wildcard-aware ("*")
        Map<String, Object> reports() {
            return Map.of("reports", java.util.List.of());
        }
    }
}
