package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;

/**
 * JWTVerifier is the interface for a JWT verifier for decoding and verifying signed JWT tokens.
 */
public interface JWTVerifier {
    UserDataPayload verify(String token) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException;
}
