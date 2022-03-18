package com.github.onsdigital;

import java.util.Map;

/**
 * JWTKeyProvider is the interface for a JWT key provider to fetch the signing keys used for decoding JWT tokens.
 */

public interface JWTKeyProvider {
    Map<String, String> getJwtKeys() throws Exception;
}

