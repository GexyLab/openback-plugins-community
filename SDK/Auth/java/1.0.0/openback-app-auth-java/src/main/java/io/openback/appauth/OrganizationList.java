package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/** {@code GET /orgs}: the user's organizations and the active one's id (B2C pools: empty). */
public final class OrganizationList {
    private List<Organization> orgs;
    private String active;

    public List<Organization> getOrgs() {
        return orgs == null ? Collections.emptyList() : Collections.unmodifiableList(orgs);
    }

    /** The active organization's id, or null. */
    public String getActive() {
        return active;
    }
}
