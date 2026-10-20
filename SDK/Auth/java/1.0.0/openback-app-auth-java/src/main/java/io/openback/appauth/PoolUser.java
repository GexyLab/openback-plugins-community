package io.openback.appauth;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A user of the pool as the user sees themselves ({@code PoolUser} of the JSON API). {@code GET /me} adds
 * {@link #getOrgId()}, {@link #getRoles()}, {@link #getProviders()} and {@link #getHasPassword()} (null elsewhere).
 */
public final class PoolUser {
    private String id;
    private String email;
    private boolean emailVerified;
    private String displayName;
    private String photoUrl;
    private String locale;
    private Map<String, Object> attributes;
    private boolean anonymous;
    private String createdAt;
    private String lastLoginAt;
    private Map<String, Object> mfa;
    private String orgId;
    private List<String> roles;
    private List<LinkedProvider> providers;
    private Boolean hasPassword;
    private final Map<String, Object> extra = new LinkedHashMap<>();

    /** The user id ({@code usr_...}). */
    public String getId() {
        return id;
    }

    /** The email address, null for a guest. */
    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPhotoUrl() {
        return photoUrl;
    }

    /** "it", "en" or null. */
    public String getLocale() {
        return locale;
    }

    /** The custom attributes (never null). */
    public Map<String, Object> getAttributes() {
        return attributes == null ? Collections.emptyMap() : Collections.unmodifiableMap(attributes);
    }

    /** True for a guest account ({@code signInAnonymously}). */
    public boolean isAnonymous() {
        return anonymous;
    }

    /** ISO-8601 timestamp. */
    public String getCreatedAt() {
        return createdAt;
    }

    /** ISO-8601 timestamp or null. */
    public String getLastLoginAt() {
        return lastLoginAt;
    }

    /** True when two-step verification (TOTP) is on. */
    public boolean isTotpEnabled() {
        return mfa != null && Boolean.TRUE.equals(mfa.get("totp"));
    }

    /** {@code GET /me} only: the active organization. */
    public String getOrgId() {
        return orgId;
    }

    /** {@code GET /me} only: the roles in the active organization (else empty). */
    public List<String> getRoles() {
        return roles == null ? Collections.emptyList() : Collections.unmodifiableList(roles);
    }

    /** {@code GET /me} only: the linked sign-in providers (else empty). */
    public List<LinkedProvider> getProviders() {
        return providers == null ? Collections.emptyList() : Collections.unmodifiableList(providers);
    }

    /** {@code GET /me} only: whether the user has a password (else null). */
    public Boolean getHasPassword() {
        return hasPassword;
    }

    /** Fields this version of the SDK does not know. */
    @JsonAnyGetter
    public Map<String, Object> getExtra() {
        return extra;
    }

    @JsonAnySetter
    void putExtra(String name, Object value) {
        extra.put(name, value);
    }

    @Override
    public String toString() {
        return "PoolUser{id=" + id + ", anonymous=" + anonymous + "}";
    }

    /** A sign-in provider linked to the user. */
    public static final class LinkedProvider {
        private String providerId;
        private String kind;

        public String getProviderId() {
            return providerId;
        }

        public String getKind() {
            return kind;
        }
    }
}
