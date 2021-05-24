package com.github.onsdigital.interfaces;

/**
 * Class that represents a Json Web Token that was decoded from it's string representation.
 */
public interface DecodedJWT extends Payload, Header {

    String getToken();

    String getHeader();

    String getPayload();

    String getSignature();

}
