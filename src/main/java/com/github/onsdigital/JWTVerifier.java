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

    public final String CANNOT_VERIFY_ERROR   = "Verification of JWT token integrity failed.";
    public final String PUBLIC_KEY_ERROR      = "Public Key cannot be empty or null.";
    public final String INVALID_PAYLOAD_ERROR = "Required JWT payload claim not found [username or cognito:groups].";
    public final String EXPIRED_TOKEN_ERROR   = "Access token has expired.";
    public final String TOKEN_NOT_VALID_ERROR = "Token format not valid.";
    public final String TOKEN_NULL_ERROR      = "Token cannot be null.";
    public final String UTF8_CHARSET_ERROR    = "The UTF-8 Charset isn't initialized.";
    public final String BASE64_ENCODED_ERROR  = "The input is not a valid base 64 encoded string.";
    public final String TOKEN_TIME_ERROR      = "Couldn't verify token expiry time.";
    public final String PUBLICKEY_CHECK_ERROR = "Public key check failed - ";

    private final static int JWT_CHUNK_SIZE = 3;

    // class constructor
    JWTVerifier() {}

    public UserDataPayload verifyJWTToken(String token, String publicKey) throws JWTDecodeException, JWTVerificationException, JWTTokenExpiredException {

        // if publicKey not supplied, error immediately
        if (publicKey == "" || publicKey == null) {
            throw new JWTDecodeException(PUBLIC_KEY_ERROR);
        }

        String[] chunks;
        Header header;
        Payload payload;    

        JWTParser converter = new JWTParser();
        Base64.Decoder decoder = Base64.getDecoder();

        try {
            chunks = token.split("\\.");
        } catch (NullPointerException e) {
            throw new JWTDecodeException(TOKEN_NULL_ERROR, e);
        }
        // check token validity; throw error if []chunks doesn't contain 3 elements
        if (chunks.length != JWT_CHUNK_SIZE) {
            throw new JWTDecodeException(TOKEN_NOT_VALID_ERROR);
        }

        String headerJson, payloadJson;
        try {
            headerJson = new String(decoder.decode(chunks[0]));
            payloadJson = new String(decoder.decode(chunks[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException(UTF8_CHARSET_ERROR, e);
        } catch (IllegalArgumentException e){
            throw new JWTDecodeException(BASE64_ENCODED_ERROR, e);
        }

        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
        
        // check to ensure token hasn't expired
        if (!payload.getClaim("exp").isNull() && payload.getClaim("exp").asLong() < Instant.now().toEpochMilli()/1000) {
            throw new JWTTokenExpiredException(EXPIRED_TOKEN_ERROR);
        } else if (payload.getClaim("exp").isNull()) {
            throw new JWTTokenExpiredException(TOKEN_TIME_ERROR);
        }

        // ensure that the data we need is present in payload
        if (payload.getClaim("username").isNull() || payload.getClaim("cognito:groups").isNull()) {
            throw new JWTDecodeException(INVALID_PAYLOAD_ERROR); 
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
            throw new JWTDecodeException(PUBLICKEY_CHECK_ERROR+e.getMessage());
        }

        DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, pubKey);

        if (!validator.isValid(tokenWithoutSignature, signature)) {
            throw new JWTVerificationException(CANNOT_VERIFY_ERROR);
        }

        // build pojo object to return to caller
        return new UserDataPayload(
            payload.getClaim("username").toString(),
                payload.getClaim("cognito:groups").asStringArray()
        );
    }
}
