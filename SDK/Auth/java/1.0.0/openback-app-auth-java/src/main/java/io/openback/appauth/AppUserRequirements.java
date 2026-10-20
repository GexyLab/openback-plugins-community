package io.openback.appauth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * What a protected resource requires of a verified {@link AppUser}, like the gateway's "Authenticated app user" check:
 * {@code requireRoles} = at least ONE of them; {@code requirePermissions} = ALL of them ({@code "*"} grants everything);
 * {@code requireVerifiedEmail} (default false); {@code allowAnonymous} (default false: guest tokens refused).
 */
public final class AppUserRequirements {
    private List<String> roles = Collections.emptyList();
    private List<String> permissions = Collections.emptyList();
    private boolean requireVerifiedEmail;
    private boolean allowAnonymous;

    /** No requirement beyond a valid, non-guest token. */
    public static AppUserRequirements defaults() {
        return new AppUserRequirements();
    }

    /** At least one of these roles. */
    public AppUserRequirements requireRoles(String... value) {
        this.roles = new ArrayList<>(Arrays.asList(value));
        return this;
    }

    public AppUserRequirements requireRoles(List<String> value) {
        this.roles = value == null ? Collections.emptyList() : new ArrayList<>(value);
        return this;
    }

    /** All of these permissions. */
    public AppUserRequirements requirePermissions(String... value) {
        this.permissions = new ArrayList<>(Arrays.asList(value));
        return this;
    }

    public AppUserRequirements requirePermissions(List<String> value) {
        this.permissions = value == null ? Collections.emptyList() : new ArrayList<>(value);
        return this;
    }

    public AppUserRequirements requireVerifiedEmail(boolean value) {
        this.requireVerifiedEmail = value;
        return this;
    }

    public AppUserRequirements allowAnonymous(boolean value) {
        this.allowAnonymous = value;
        return this;
    }

    public List<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    public List<String> getPermissions() {
        return Collections.unmodifiableList(permissions);
    }

    public boolean isRequireVerifiedEmail() {
        return requireVerifiedEmail;
    }

    public boolean isAllowAnonymous() {
        return allowAnonymous;
    }

    /** True when {@code user} satisfies every requirement. */
    public boolean isSatisfiedBy(AppUser user) {
        if (user.isAnonymous() && !allowAnonymous) {
            return false;
        }
        if (requireVerifiedEmail && !user.isEmailVerified()) {
            return false;
        }
        if (!roles.isEmpty() && roles.stream().noneMatch(user::hasRole)) {
            return false;
        }
        return permissions.stream().allMatch(user::hasPermission);
    }
}
