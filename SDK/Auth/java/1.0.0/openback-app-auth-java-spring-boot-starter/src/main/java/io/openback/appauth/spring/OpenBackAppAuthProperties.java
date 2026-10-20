package io.openback.appauth.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code openback.app-auth.*}: the user pool whose access tokens the application accepts.
 *
 * <pre>
 * openback.app-auth.issuer=https://api.example.com/gateway/shop/auth/main
 * openback.app-auth.client-ids=uapp_web,uapp_android
 * openback.app-auth.require-verified-email=false
 * openback.app-auth.allow-anonymous=false
 * </pre>
 */
@ConfigurationProperties(prefix = "openback.app-auth")
public class OpenBackAppAuthProperties {
    /** The pool's issuer URL (enables the auto-configuration). */
    private String issuer;

    /** The accepted audiences: the client IDs (uapp_...) of the apps whose tokens are accepted. Required. */
    private List<String> clientIds = new ArrayList<>();

    /** Refuse tokens whose email is not verified (403). */
    private boolean requireVerifiedEmail = false;

    /** Accept guest tokens (anon: true); refused (403) by default. */
    private boolean allowAnonymous = false;

    /** Clock leeway for exp/nbf/iat. */
    private Duration leeway = Duration.ofSeconds(60);

    /** How long the pool's JWKS is cached. */
    private Duration jwksCacheTtl = Duration.ofMinutes(10);

    /** The JWKS URL (default: issuer + /.well-known/jwks.json). */
    private String jwksUri;

    /**
     * Without a SecurityFilterChain of the application: register a default one (stateless, CSRF off, every request
     * authenticated with an app user's token). Set false to keep Spring Boot's default.
     */
    private boolean defaultSecurityFilterChain = true;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<String> getClientIds() {
        return clientIds;
    }

    public void setClientIds(List<String> clientIds) {
        this.clientIds = clientIds;
    }

    public boolean isRequireVerifiedEmail() {
        return requireVerifiedEmail;
    }

    public void setRequireVerifiedEmail(boolean requireVerifiedEmail) {
        this.requireVerifiedEmail = requireVerifiedEmail;
    }

    public boolean isAllowAnonymous() {
        return allowAnonymous;
    }

    public void setAllowAnonymous(boolean allowAnonymous) {
        this.allowAnonymous = allowAnonymous;
    }

    public Duration getLeeway() {
        return leeway;
    }

    public void setLeeway(Duration leeway) {
        this.leeway = leeway;
    }

    public Duration getJwksCacheTtl() {
        return jwksCacheTtl;
    }

    public void setJwksCacheTtl(Duration jwksCacheTtl) {
        this.jwksCacheTtl = jwksCacheTtl;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public boolean isDefaultSecurityFilterChain() {
        return defaultSecurityFilterChain;
    }

    public void setDefaultSecurityFilterChain(boolean defaultSecurityFilterChain) {
        this.defaultSecurityFilterChain = defaultSecurityFilterChain;
    }
}
