package io.openback.appauth;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The user of a verified access token ({@link TokenVerifier#verify(String)}). Built from the token alone: no call to
 * OpenBack. An access token cannot be revoked before it expires (default lifetime 15 minutes).
 */
public final class AppUser implements Serializable {
    private static final long serialVersionUID = 1L;

    /** The request attribute under which {@link RequireAppUserFilter} puts the user. */
    public static final String REQUEST_ATTRIBUTE = "io.openback.appauth.AppUser";

    private final String id;
    private final String poolId;
    private final String clientId;
    private final String email;
    private final boolean emailVerified;
    private final boolean anonymous;
    private final String orgId;
    private final List<String> roles;
    private final List<String> permissions;
    private final Map<String, Object> attributes;
    private final String sessionId;
    private final List<String> amr;
    private final Map<String, Object> claims;

    AppUser(Map<String, Object> claims, String clientId) {
        this.claims = Collections.unmodifiableMap(claims);
        this.id = str(claims.get("sub"));
        this.poolId = str(claims.get("pool"));
        this.clientId = clientId;
        this.email = str(claims.get("email"));
        this.emailVerified = Boolean.TRUE.equals(claims.get("email_verified"));
        this.anonymous = Boolean.TRUE.equals(claims.get("anon"));
        this.orgId = str(claims.get("org_id"));
        this.roles = strings(claims.get("roles"));
        this.permissions = strings(claims.get("permissions"));
        Object attr = claims.get("attr");
        this.attributes = attr instanceof Map ? castMap(attr) : Collections.emptyMap();
        this.sessionId = str(claims.get("sid"));
        this.amr = strings(claims.get("amr"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return Collections.unmodifiableMap((Map<String, Object>) value);
    }

    private static String str(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static List<String> strings(Object v) {
        if (!(v instanceof List)) {
            return Collections.emptyList();
        }
        List<?> in = (List<?>) v;
        String[] out = new String[in.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = String.valueOf(in.get(i));
        }
        return List.of(out);
    }

    /** The user id ({@code sub}, {@code usr_...}). */
    public String getId() {
        return id;
    }

    /** The pool ({@code pool}). */
    public String getPoolId() {
        return poolId;
    }

    /** The app the token was issued to ({@code aud}). */
    public String getClientId() {
        return clientId;
    }

    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    /** A guest account ({@code anon: true}). */
    public boolean isAnonymous() {
        return anonymous;
    }

    /** The active organization ({@code org_id}; B2C: the pool's hidden default one). */
    public String getOrgId() {
        return orgId;
    }

    /** The roles in the active organization. */
    public List<String> getRoles() {
        return roles;
    }

    /** The permissions in the active organization ({@code "*"} = all). */
    public List<String> getPermissions() {
        return permissions;
    }

    /** The custom attributes ({@code attr}). */
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    /** The session ({@code sid}). */
    public String getSessionId() {
        return sessionId;
    }

    /** How the user signed in: pwd, email, anon, fed, otp, recovery, mfa. */
    public List<String> getAmr() {
        return amr;
    }

    /** Every claim of the token. */
    public Map<String, Object> getClaims() {
        return claims;
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** True if the permissions contain {@code permission} or {@code "*"}. */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission) || permissions.contains("*");
    }

    @Override
    public String toString() {
        return "AppUser{id=" + id + ", poolId=" + poolId + ", clientId=" + clientId + ", orgId=" + orgId + "}";
    }
}
