package com.github.onsdigital;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;
import com.github.onsdigital.interfaces.JWTHandler;

public class JWTHandlerImpl implements JWTHandler {

    @Override
    public UserDataPayload verifyJWT(String token, String secretKey) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException {
        try {
            JWTVerifier verify = extracted();   
            return verify.verifyJWTToken(token, secretKey);
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("Error: ", e);
        } catch (JWTDecodeException e) {
            throw new JWTDecodeException("Error: ", e);
        } catch (JWTTokenExpiredException e) {
            throw new JWTTokenExpiredException("Error: ", e);
        }
    }

    private JWTVerifier extracted() {
        return new JWTVerifier();
    }
}
