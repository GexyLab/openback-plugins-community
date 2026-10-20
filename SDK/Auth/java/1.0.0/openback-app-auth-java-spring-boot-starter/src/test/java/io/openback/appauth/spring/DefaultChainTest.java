package io.openback.appauth.spring;

import io.openback.appauth.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = DefaultChainTest.App.class)
@AutoConfigureMockMvc
class DefaultChainTest {
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Api.class)
    static class App {
    }

    @RestController
    static class Api {
        @GetMapping("/whoami")
        Map<String, Object> whoami(Authentication authentication) {
            AppUser user = (AppUser) authentication.getPrincipal();
            return Map.of("id", user.getId(), "authorities",
                    authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().collect(Collectors.toList()));
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("openback.app-auth.issuer", () -> TestPool.INSTANCE.issuer);
        registry.add("openback.app-auth.client-ids", () -> "uapp_web,uapp_android");
    }

    @Autowired
    MockMvc mvc;

    @Test
    void noTokenIs401() throws Exception {
        mvc.perform(get("/whoami"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"invalid_token\""))
                .andExpect(content().json("{\"error\":\"invalid_token\"}"));
    }

    @Test
    void invalidTokenIs401() throws Exception {
        mvc.perform(get("/whoami").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().json("{\"error\":\"invalid_token\"}"));
        String otherApp = TestPool.INSTANCE.token(TestPool.INSTANCE.claims("uapp_other", List.of(), List.of()));
        mvc.perform(get("/whoami").header("Authorization", "Bearer " + otherApp)).andExpect(status().isUnauthorized());
    }

    @Test
    void validTokenGivesRoleAndPermissionAuthorities() throws Exception {
        String token = TestPool.INSTANCE.token(List.of("admin"), List.of("invoices.read"));
        mvc.perform(get("/whoami").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("usr_1"))
                .andExpect(jsonPath("$.authorities[0]").value("PERM_invoices.read"))
                .andExpect(jsonPath("$.authorities[1]").value("ROLE_admin"));
    }

    @Test
    void guestsAreRefusedByDefault() throws Exception {
        Map<String, Object> claims = TestPool.INSTANCE.claims("uapp_web", List.of(), List.of());
        claims.put("anon", true);
        mvc.perform(get("/whoami").header("Authorization", "Bearer " + TestPool.INSTANCE.token(claims)))
                .andExpect(status().isForbidden())
                .andExpect(content().json("{\"error\":\"insufficient_scope\"}"));
    }
}
