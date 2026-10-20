package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/** An organization the user belongs to (B2B pools). */
public final class Organization {
    private String id;
    private String name;
    private List<String> roles;
    private boolean disabled;

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    /** The user's roles in it. */
    public List<String> getRoles() {
        return roles == null ? Collections.emptyList() : Collections.unmodifiableList(roles);
    }

    public boolean isDisabled() {
        return disabled;
    }

    @Override
    public String toString() {
        return "Organization{id=" + id + ", name=" + name + "}";
    }
}
