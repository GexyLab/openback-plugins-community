package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/** The organization a session is signed in to (B2B pools; always null in B2C pools). */
public final class ActiveOrg {
    private String id;
    private String name;
    private List<String> roles;
    private int choices;

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

    /** How many organizations the user could sign in to (more than 1: offer a switch). */
    public int getChoices() {
        return choices;
    }

    @Override
    public String toString() {
        return "ActiveOrg{id=" + id + ", name=" + name + "}";
    }
}
