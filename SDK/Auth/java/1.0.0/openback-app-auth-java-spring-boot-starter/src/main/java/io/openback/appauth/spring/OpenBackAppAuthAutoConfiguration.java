package io.openback.appauth.spring;

import io.openback.appauth.AppUserRequirements;
import io.openback.appauth.TokenVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Auto-configuration of OpenBack App Auth, active when {@code openback.app-auth.issuer} is set:
 * <ul>
 *   <li>{@link TokenVerifier} (issuer, client IDs, leeway, JWKS cache);</li>
 *   <li>{@link AppUserAuthenticationProvider} and {@link OpenBackAppAuthFilter} (kept out of the servlet container's
 *       filter list: it belongs in a Spring Security chain);</li>
 *   <li>without a {@link SecurityFilterChain} of yours, a default one: stateless, CSRF off, every request authenticated
 *       by an app user's token (disable with {@code openback.app-auth.default-security-filter-chain=false}).</li>
 * </ul>
 */
@AutoConfiguration(before = {SecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
@ConditionalOnProperty(prefix = "openback.app-auth", name = "issuer")
@EnableConfigurationProperties(OpenBackAppAuthProperties.class)
public class OpenBackAppAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public TokenVerifier openBackTokenVerifier(OpenBackAppAuthProperties properties) {
        if (properties.getClientIds() == null || properties.getClientIds().isEmpty()) {
            throw new IllegalStateException("openback.app-auth.client-ids is required (the client IDs whose tokens are accepted)");
        }
        TokenVerifier.Builder b = TokenVerifier.builder(properties.getIssuer())
                .clientIds(properties.getClientIds())
                .leeway(properties.getLeeway())
                .jwksCacheTtl(properties.getJwksCacheTtl());
        if (properties.getJwksUri() != null && !properties.getJwksUri().isBlank()) {
            b.jwksUri(properties.getJwksUri());
        }
        return b.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public AppUserAuthenticationProvider openBackAppUserAuthenticationProvider(TokenVerifier verifier, OpenBackAppAuthProperties properties) {
        return new AppUserAuthenticationProvider(verifier, AppUserRequirements.defaults()
                .requireVerifiedEmail(properties.isRequireVerifiedEmail())
                .allowAnonymous(properties.isAllowAnonymous()));
    }

    @Bean
    @ConditionalOnMissingBean
    public OpenBackAppAuthFilter openBackAppAuthFilter(AppUserAuthenticationProvider provider) {
        return new OpenBackAppAuthFilter(provider);
    }

    /** The filter runs inside Spring Security's chain only, never as a plain servlet filter too. */
    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public FilterRegistrationBean<OpenBackAppAuthFilter> openBackAppAuthFilterRegistration(OpenBackAppAuthFilter filter) {
        FilterRegistrationBean<OpenBackAppAuthFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(HttpSecurity.class)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @ConditionalOnProperty(prefix = "openback.app-auth", name = "default-security-filter-chain", havingValue = "true", matchIfMissing = true)
    static class DefaultSecurityFilterChainConfiguration {

        @Bean
        SecurityFilterChain openBackAppAuthSecurityFilterChain(HttpSecurity http, OpenBackAppAuthFilter filter) throws Exception {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                    .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
                    .exceptionHandling(e -> e.authenticationEntryPoint(OpenBackAppAuthFilter.ENTRY_POINT)
                            .accessDeniedHandler(OpenBackAppAuthFilter.ACCESS_DENIED))
                    .build();
        }
    }
}
