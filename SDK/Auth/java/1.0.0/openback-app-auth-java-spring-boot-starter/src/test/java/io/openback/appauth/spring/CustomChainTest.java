package io.openback.appauth.spring;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = CustomChainTest.App.class)
@AutoConfigureMockMvc
class CustomChainTest {
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Api.class)
    static class App {
        @Bean
        SecurityFilterChain api(HttpSecurity http, OpenBackAppAuthFilter appAuth) throws Exception {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(a -> a
                            .requestMatchers("/public").permitAll()
                            .requestMatchers("/admin").hasRole("admin")
                            .requestMatchers("/invoices").hasAuthority("PERM_invoices.read")
                            .anyRequest().authenticated())
                    .addFilterBefore(appAuth, UsernamePasswordAuthenticationFilter.class)
                    .exceptionHandling(e -> e.authenticationEntryPoint(OpenBackAppAuthFilter.ENTRY_POINT)
                            .accessDeniedHandler(OpenBackAppAuthFilter.ACCESS_DENIED))
                    .build();
        }
    }

    @RestController
    static class Api {
        @GetMapping({"/public", "/admin", "/invoices"})
        Map<String, Object> ok() {
            return Map.of("ok", true);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("openback.app-auth.issuer", () -> TestPool.INSTANCE.issuer + "/");
        registry.add("openback.app-auth.client-ids", () -> "uapp_web");
        registry.add("openback.app-auth.allow-anonymous", () -> "true");
    }

    @Autowired
    MockMvc mvc;

    @Test
    void rolesAndPermissionsThroughSpringRules() throws Exception {
        mvc.perform(get("/public")).andExpect(status().isOk());
        mvc.perform(get("/admin")).andExpect(status().isUnauthorized());
        String member = TestPool.INSTANCE.token(List.of("member"), List.of("invoices.read"));
        mvc.perform(get("/admin").header("Authorization", "Bearer " + member))
                .andExpect(status().isForbidden())
                .andExpect(content().json("{\"error\":\"insufficient_scope\"}"));
        mvc.perform(get("/invoices").header("Authorization", "Bearer " + member)).andExpect(status().isOk());
        String admin = TestPool.INSTANCE.token(List.of("admin"), List.of());
        mvc.perform(get("/admin").header("Authorization", "Bearer " + admin)).andExpect(status().isOk());
        mvc.perform(get("/invoices").header("Authorization", "Bearer " + admin)).andExpect(status().isForbidden());
    }

    @Test
    void guestsAllowedByProperty() throws Exception {
        Map<String, Object> claims = TestPool.INSTANCE.claims("uapp_web", List.of(), List.of());
        claims.put("anon", true);
        mvc.perform(get("/public").header("Authorization", "Bearer " + TestPool.INSTANCE.token(claims))).andExpect(status().isOk());
    }
}
