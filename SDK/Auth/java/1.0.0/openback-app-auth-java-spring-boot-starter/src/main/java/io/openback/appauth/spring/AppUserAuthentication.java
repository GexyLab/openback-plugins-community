package io.openback.appauth.spring;

import io.openback.appauth.AppUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * The Spring Security {@code Authentication} of an app user: principal {@link AppUser}, authorities {@code ROLE_<role>}
 * for each role and {@code PERM_<permission>} for each permission of the token's active organization (a {@code "*"}
 * permission becomes {@code PERM_*}: use {@link AppUser#hasPermission(String)} for wildcard-aware checks). The raw token
 * is the credential (never printed by {@link #toString()}).
 */
public class AppUserAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;

    private final AppUser user;
    private final String token;

    /** An unauthenticated bearer token, to be verified by {@link AppUserAuthenticationProvider}. */
    public static AppUserAuthentication unauthenticated(String token) {
        return new AppUserAuthentication(null, token, Collections.emptyList(), false);
    }

    /** A verified user. */
    public static AppUserAuthentication authenticated(AppUser user, String token) {
        return new AppUserAuthentication(user, token, authoritiesOf(user), true);
    }

    private AppUserAuthentication(AppUser user, String token, Collection<? extends GrantedAuthority> authorities, boolean authenticated) {
        super(authorities);
        this.user = user;
        this.token = token;
        super.setAuthenticated(authenticated);
    }

    /** {@code ROLE_<role>} and {@code PERM_<permission>}. */
    public static List<GrantedAuthority> authoritiesOf(AppUser user) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String role : user.getRoles()) {
            out.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        for (String permission : user.getPermissions()) {
            out.add(new SimpleGrantedAuthority("PERM_" + permission));
        }
        return out;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    /** The verified user (null before authentication). */
    public AppUser getUser() {
        return user;
    }

    @Override
    public String getName() {
        return user != null ? user.getId() : "";
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Use AppUserAuthentication.authenticated(user, token)");
        }
        super.setAuthenticated(false);
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
