package com.github.onsdigital.interfaces;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;

public interface JWTHandler {
    public UserDataPayload verifyJWT(String token, String publicKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException;
}
