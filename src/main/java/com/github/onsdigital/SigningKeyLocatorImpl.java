package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link LocatorAdapter} implementation for determining the correct, configured signing key to use based
 * on the 'kid' field in a JWT header.
 */
public final class SigningKeyLocatorImpl extends LocatorAdapter<Key> {

    static final String KEYS_REQUIRED_ERROR = "Public signing keys are required";
    static final String PUBLIC_KEY_CHECK_ERROR = "Public key check failed: ";
    static final String PUBLIC_KEY_ERROR = "Public Key not found matching 'kid'";
    private static final String RSA = "RSA";

    private final Map<String, Key> signingKeys;

    /**
     * Construct a new {@link SigningKeyLocatorImpl}.
     *
     * @param signingKeys the {@link Map} of key IDs to base 64 encoded, DER formatted public signing keys
     */
    public SigningKeyLocatorImpl(Map<String, String> signingKeys) {
        if (signingKeys == null || signingKeys.isEmpty()) {
            throw new IllegalArgumentException(KEYS_REQUIRED_ERROR);
        }

        this.signingKeys = new HashMap<>();

        Base64.Decoder decoder = Base64.getDecoder();
        for (Map.Entry<String, String> publicKey : signingKeys.entrySet()) {
            try {
                KeyFactory kf = KeyFactory.getInstance(RSA);
                byte[] encodedKey = decoder.decode(publicKey.getValue());
                PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(encodedKey));
                this.signingKeys.put(publicKey.getKey(), pubKey);
            } catch (NoSuchAlgorithmException ignore) {
                // ignore this as the algorithm is specified as a constant so will be valid
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException(PUBLIC_KEY_CHECK_ERROR + e.getMessage());
            }
        }
    }

    /**
     * Returns the signing key that should be used to validate a digital signature for the JWS with the specified
     * header.
     *
     * @param jwsHeader the header of the JWS to validate
     * @return the signing key that should be used to validate a digital signature for the JWS with the specified
     * header.
     */
    @Override
    public Key locate(JwsHeader jwsHeader) {
        Key key = signingKeys.get(jwsHeader.getKeyId());
        if (key == null) {
            throw new JWTDecodeException(PUBLIC_KEY_ERROR);
        }
        return key;
    }
}
