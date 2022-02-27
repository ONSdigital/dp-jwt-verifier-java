package com.github.onsdigital.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UserDataPayload {

    private final String username;
    private final List<String> groups;

    public UserDataPayload(String username, List<String> groups) {
        this.username = username;

        if (groups == null) {
            groups = new ArrayList<>();
        }
        this.groups = Collections.unmodifiableList(new ArrayList<>(groups));
    }

    public String getEmail() {
        return username;
    }

    public List<String> getGroups() {
        return groups;
    }
}