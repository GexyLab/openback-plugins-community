package io.openback.appauth.spring;

import io.openback.appauth.AppUser;
import io.openback.appauth.AppUserRequirements;
import io.openback.appauth.TokenVerificationException;
import io.openback.appauth.TokenVerifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Verifies an {@link AppUserAuthentication#unauthenticated(String) unauthenticated bearer token} with the pool's keys
 * ({@link TokenVerifier}, local, no call to OpenBack) and the global requirements (verified email, guests).
 * Errors: {@link BadCredentialsException} (invalid token, 401), {@link AppUserRequirementsException} (403),
 * {@link AuthenticationServiceException} (the pool's keys unavailable, 503).
 */
public class AppUserAuthenticationProvider implements AuthenticationProvider {
    private final TokenVerifier verifier;
    private final AppUserRequirements requirements;

    public AppUserAuthenticationProvider(TokenVerifier verifier, AppUserRequirements requirements) {
        this.verifier = verifier;
        this.requirements = requirements != null ? requirements : AppUserRequirements.defaults();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        AppUser user;
        try {
            user = verifier.verify(token);
        } catch (TokenVerificationException e) {
            if (e.getStatus() == 503) {
                throw new AuthenticationServiceException("The user pool's keys are unavailable", e);
            }
            throw new BadCredentialsException("Invalid app user token: " + e.getCode());
        }
        if (!requirements.isSatisfiedBy(user)) {
            throw new AppUserRequirementsException("The app user does not meet the requirements");
        }
        return AppUserAuthentication.authenticated(user, token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AppUserAuthentication.class.isAssignableFrom(authentication);
    }

    /** A valid token whose user does not meet the requirements: answered 403 {@code insufficient_scope}. */
    public static class AppUserRequirementsException extends AuthenticationException {
        private static final long serialVersionUID = 1L;

        public AppUserRequirementsException(String message) {
            super(message);
        }
    }
}
