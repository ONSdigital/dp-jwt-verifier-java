package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SigningKeyResolverImpl extends SigningKeyResolverAdapter {

    static final String KEYS_REQUIRED_ERROR    = "Public signing keys are required";
    static final String PUBLIC_KEY_CHECK_ERROR = "Public key check failed: ";
    static final String PUBLIC_KEY_ERROR       = "Public Key not found matching 'kid'";
    private static final String RSA = "RSA";

    private final Map<String, Key> signingKeys = new HashMap<>();

    public SigningKeyResolverImpl(Map<String, String> signingKeys) {
        if (signingKeys == null || signingKeys.isEmpty()) {
            throw new IllegalArgumentException(KEYS_REQUIRED_ERROR);
        }

        Base64.Decoder decoder = Base64.getDecoder();
        for (Map.Entry<String, String> publicKey : signingKeys.entrySet()) {
            try {
                KeyFactory kf = KeyFactory.getInstance(RSA);
                byte[] encodedKey = decoder.decode(publicKey.getValue());
                PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(encodedKey));
                this.signingKeys.put(publicKey.getKey(), pubKey);
            } catch (Exception e) {
                throw new IllegalArgumentException(PUBLIC_KEY_CHECK_ERROR +e.getMessage());
            }
        }
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        Key key = signingKeys.get(jwsHeader.getKeyId());
        if (key == null) {
            throw new JWTDecodeException(PUBLIC_KEY_ERROR);
        }
        return key;
    }
}
