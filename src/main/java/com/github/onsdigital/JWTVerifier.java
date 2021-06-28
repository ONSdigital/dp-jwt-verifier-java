package com.github.onsdigital;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.interfaces.Header;
import com.github.onsdigital.interfaces.Payload;

import com.github.onsdigital.impl.JWTParser;
import com.github.onsdigital.impl.UserDataPayload;

import java.time.Instant;
import java.util.Base64;

import java.lang.NullPointerException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;

import java.security.KeyFactory;

/**
 * JWTVerifier - decodes and verifies an access token according to
 *               public key passed it.
 */
public class JWTVerifier {

    private final static int JWT_CHUNK_SIZE = 3;

    // class constructor
    JWTVerifier() {}

    public UserDataPayload verifyJWTToken(String token, String publicKey) throws JWTDecodeException, JWTVerificationException, JWTTokenExpiredException {

        // if publicKey not supplied, error immediately
        if (publicKey == "" || publicKey == null) {
            throw new JWTDecodeException("Public Key cannot be empty or null.");
        }

        String[] chunks;
        Header header;
        Payload payload;    

        JWTParser converter = new JWTParser();
        Base64.Decoder decoder = Base64.getDecoder();

        try {
            chunks = token.split("\\.");
        } catch (NullPointerException e) {
            throw new JWTDecodeException("Token cannot be null.", e);
        }
        // check token validity; throw error if []chunks doesn't contain 3 elements
        if (chunks.length != JWT_CHUNK_SIZE) {
            throw new JWTDecodeException("Token format not valid.");
        }

        String headerJson, payloadJson;
        try {
            headerJson = new String(decoder.decode(chunks[0]));
            payloadJson = new String(decoder.decode(chunks[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (IllegalArgumentException e){
            throw new JWTDecodeException("The input is not a valid base 64 encoded string.", e);
        }

        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
        
        // check to ensure token hasn't expired
        if (!payload.getClaim("exp").isNull() && payload.getClaim("exp").asLong() < Instant.now().toEpochMilli()/1000) {
            throw new JWTTokenExpiredException("Access token has expired.");
        } else if (payload.getClaim("exp").isNull()) {
            throw new JWTTokenExpiredException("Couldn't verify token expiry time.");
        }

        // ensure that the data we need is present in payload
        if (payload.getClaim("username").isNull() || payload.getClaim("cognito:groups").isNull()) {
            throw new JWTDecodeException("Required JWT payload claim not found [username or cognito:groups]."); 
        }

        String tokenWithoutSignature = chunks[0] + "." + chunks[1];
        String signature = chunks[2];

        SignatureAlgorithm sa = SignatureAlgorithm.forName(header.getAlgorithm());

        RSAPublicKey pubKey;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            byte[] encodedKey = decoder.decode(publicKey);
            pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encodedKey));
        } catch (Exception e) {
            throw new JWTDecodeException("Public key check failed - "+e.getMessage());
        }

        DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, pubKey);

        if (!validator.isValid(tokenWithoutSignature, signature)) {
            throw new JWTVerificationException("Verification of JWT token integrity failed.");
        }

        // build pojo object to return to caller
        return new UserDataPayload(
            payload.getClaim("username").toString(),
                payload.getClaim("cognito:groups").asStringArray()
        );
    }
}
