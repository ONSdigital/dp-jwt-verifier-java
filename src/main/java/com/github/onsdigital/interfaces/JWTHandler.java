package com.github.onsdigital.interfaces;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;
import com.github.onsdigital.impl.UserDataPayload;

public interface JWTHandler {
    UserDataPayload verifyJWT(String token, String publicKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException;
}
