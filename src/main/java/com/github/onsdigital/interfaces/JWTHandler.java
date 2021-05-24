package com.github.onsdigital.interfaces;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;

public interface JWTHandler {
    public UserDataPayload verifyJWT(String token, String secretKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException;
}
