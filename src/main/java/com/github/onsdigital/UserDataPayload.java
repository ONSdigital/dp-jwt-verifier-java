package com.github.onsdigital;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * UserDataPayload model contains the user detail fields from the JWT tokens.
 */
public final class UserDataPayload {

    private final String id;
    private final String email;
    private final List<String> groups;

    /**
     * Constructs a new {@link UserDataPayload}.
     *
     * @param id     the user's ID
     * @param email  the user's email
     * @param groups the list of group IDs for the groups the user is a member of
     */
    public UserDataPayload(String id, String email, List<String> groups) {
        this.id = id;
        this.email = email;

        if (groups == null) {
            this.groups = Collections.unmodifiableList(new ArrayList<>());
        } else {
            this.groups = Collections.unmodifiableList(new ArrayList<>(groups));
        }
    }

    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    /**
     * Gets the list of groups the user is a member of.
     *
     * @return the list of IDs of the groups the user is a member of as an unmodifiable list.
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "Constructor has made list unmodifiable")
    public List<String> getGroups() {
        return groups;
    }
}
