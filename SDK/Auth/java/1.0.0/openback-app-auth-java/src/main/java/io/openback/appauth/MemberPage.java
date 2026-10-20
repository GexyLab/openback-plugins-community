package io.openback.appauth;

import java.util.Collections;
import java.util.List;

/** A page of an organization's members and the roles that can be granted. */
public final class MemberPage {
    private List<Member> items;
    private Integer total;
    private List<Role> roles;

    public List<Member> getItems() {
        return items == null ? Collections.emptyList() : Collections.unmodifiableList(items);
    }

    /** The total count, when the service answers it (else null). */
    public Integer getTotal() {
        return total;
    }

    /** The pool's organization roles. */
    public List<Role> getRoles() {
        return roles == null ? Collections.emptyList() : Collections.unmodifiableList(roles);
    }

    /** An organization role: key and label. */
    public static final class Role {
        private String key;
        private String label;

        public String getKey() {
            return key;
        }

        public String getLabel() {
            return label;
        }
    }
}
