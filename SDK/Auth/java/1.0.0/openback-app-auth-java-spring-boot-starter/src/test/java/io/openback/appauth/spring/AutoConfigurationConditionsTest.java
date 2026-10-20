package io.openback.appauth.spring;

import io.openback.appauth.TokenVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AutoConfigurationConditionsTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OpenBackAppAuthAutoConfiguration.class));

    @Test
    void inactiveWithoutIssuer() {
        runner.run(ctx -> assertThat(ctx).doesNotHaveBean(TokenVerifier.class));
    }

    @Test
    void verifierFromProperties() {
        runner.withPropertyValues("openback.app-auth.issuer=https://api.example.com/gateway/shop/auth/main/",
                        "openback.app-auth.client-ids=uapp_a,uapp_b")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(TokenVerifier.class).hasSingleBean(OpenBackAppAuthFilter.class)
                            .hasSingleBean(AppUserAuthenticationProvider.class);
                    TokenVerifier v = ctx.getBean(TokenVerifier.class);
                    assertThat(v.getIssuer()).isEqualTo("https://api.example.com/gateway/shop/auth/main");
                    assertThat(v.getClientIds()).containsExactly("uapp_a", "uapp_b");
                });
    }

    @Test
    void clientIdsRequired() {
        runner.withPropertyValues("openback.app-auth.issuer=https://x").run(ctx -> assertThat(ctx).hasFailed());
    }
}
