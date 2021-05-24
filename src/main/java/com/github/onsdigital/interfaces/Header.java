package com.github.onsdigital.interfaces;

/**
 * The Header class - 1st part of JWT.
 */
public interface Header {

    String getAlgorithm();

    String getType();

    String getContentType();

    String getKeyId();

    Claim getHeaderClaim(String name);

}
