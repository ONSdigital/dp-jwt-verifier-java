package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;
import com.github.onsdigital.impl.UserDataPayload;
import com.github.onsdigital.interfaces.JWTHandler;

public class JWTHandlerImpl implements JWTHandler {

    @Override
    public UserDataPayload verifyJWT(String token, String publicKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException {
        JWTVerifier verify = extracted();
        return verify.verifyJWTToken(token, publicKey);
    }

    private JWTVerifier extracted() {
        return new JWTVerifier();
    }
}
