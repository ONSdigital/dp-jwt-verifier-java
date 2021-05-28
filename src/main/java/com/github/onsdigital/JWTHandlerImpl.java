package com.github.onsdigital;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;
import com.github.onsdigital.interfaces.JWTHandler;

public class JWTHandlerImpl implements JWTHandler {

    @Override
    public UserDataPayload verifyJWT(String token, String secretKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException {
        JWTVerifier verify = extracted();   
        return verify.verifyJWTToken(token, secretKey);
    }

    private JWTVerifier extracted() {
        return new JWTVerifier();
    }
}
