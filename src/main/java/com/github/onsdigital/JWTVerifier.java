package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;

public interface JWTVerifier {
    UserDataPayload verify(String token) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException;
}
