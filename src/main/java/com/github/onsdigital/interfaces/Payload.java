package com.github.onsdigital.interfaces;

/**
 * Payload class - 2nd part of JWT.
 */
public interface Payload {

    Claim getClaim(String name);

}
