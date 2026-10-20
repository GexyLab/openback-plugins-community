package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/** A member of an organization (organization owners and admins only). */
public final class Member {
    private String userId;
    private String email;
    private String displayName;
    private boolean disabled;
    private List<String> roles;
    private String createdAt;

    public String getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public List<String> getRoles() {
        return roles == null ? Collections.emptyList() : Collections.unmodifiableList(roles);
    }

    public String getCreatedAt() {
        return createdAt;
    }
}
