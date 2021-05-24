package com.github.onsdigital.impl;

import com.github.onsdigital.interfaces.UserData;

public class UserDataPayload implements UserData {

    private final String username;
    private final String[] groups;

    public UserDataPayload(String username, String[] groups) {
        this.username = username;
        this.groups = groups;
    }

    @Override
    public String getEmail() {
        return username;
    }

    @Override
    public String[] getGroups() {
        return groups;
    }
}
