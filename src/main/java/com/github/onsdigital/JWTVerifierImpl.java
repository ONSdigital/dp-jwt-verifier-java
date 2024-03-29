package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JWTVerifier - decodes and verifies an access token according to
 * public keys passed to it.
 */
public final class JWTVerifierImpl implements JWTVerifier {

    static final String SIGNATURE_VERIFICATION_ERROR = "JWT signature verification failed.";
    static final String ALGORITHM_ERROR = "JWT algorithm is not supported by the provided key.";
    static final String MISSING_USERNAME_ERROR = "JWT payload 'username' claim not found.";
    static final String MISSING_USER_ID_ERROR = "JWT payload 'sub' (i.e. user id) claim not found.";
    static final String EXPIRED_TOKEN_ERROR = "JWT token has expired.";
    static final String TOKEN_NOT_VALID_ERROR = "JWT format not valid.";

    private final JwtParser jwtParser;

    /**
     * Initialises a new instance of the {@link JWTVerifierImpl}.
     *
     * @param signingKeys the map of public signing key IDs to the base64 encoded public keys in DER format
     * @throws IllegalArgumentException if the public signing keys provided are invalid
     */
    public JWTVerifierImpl(Map<String, String> signingKeys) {
        final Locator<Key> signingKeyLocator = new SigningKeyLocatorImpl(signingKeys);

        this.jwtParser = Jwts.parser()
                .keyLocator(signingKeyLocator)
                .build();
    }


    JWTVerifierImpl(JWTKeyProvider jwtKeyProvider) throws Exception {
        Map<String, String> signingKeys = jwtKeyProvider.getJwtKeys();
        final Locator<Key> signingKeyLocator = new SigningKeyLocatorImpl(signingKeys);

        this.jwtParser = Jwts.parser()
                .keyLocator(signingKeyLocator)
                .build();
    }

    /**
     * Initialises a new instance of the {@link JWTVerifierImpl}.
     *
     * @param identityAPIURL  the identity api url to fetch jwt keys
     * @param initialInterval the initial interval in milliseconds to be used for exponential retries
     * @param maxElapsedTime  the max elapsed time in milliseconds to be used for exponential retries
     * @param maxInterval     the max interval in milliseconds to be used for exponential retries
     * @throws IllegalArgumentException if the public signing keys provided are invalid
     */
    public JWTVerifierImpl(String identityAPIURL, int initialInterval, int maxElapsedTime, int maxInterval) throws Exception {
        this(new JWTKeyProviderImpl(identityAPIURL, initialInterval, maxElapsedTime, maxInterval, new RequestBuilder()));
    }

    /**
     * Decodes and verifies the supplied JWT token, returning the user details if the token is valid.
     *
     * @param token the JWT token to verify
     * @return the {@link UserDataPayload} representing the user details from the JWT
     * @throws JWTVerificationException if the JWT signature is invalid or uses an unsupported algorithm
     * @throws JWTDecodeException       if the JWT is malformed or does not contain the user's username (i.e. email) or ID
     * @throws JWTTokenExpiredException if the JWT token has expired
     */
    @Override
    public UserDataPayload verify(String token) throws JWTVerificationException, JWTDecodeException, JWTTokenExpiredException {
        String userId;
        String username;
        List<String> groups;
        try {
            Claims claims = jwtParser.parseSignedClaims(token).getPayload();

            userId = claims.get("sub", String.class);
            username = claims.get("username", String.class);
            groups = convertGroupsToStrings(claims.get("cognito:groups", ArrayList.class));
        } catch (ExpiredJwtException e) {
            throw new JWTTokenExpiredException(EXPIRED_TOKEN_ERROR, e);
        } catch (UnsupportedJwtException e) {
            throw new JWTVerificationException(ALGORITHM_ERROR, e);
        } catch (MalformedJwtException e) {
            throw new JWTDecodeException(TOKEN_NOT_VALID_ERROR, e);
        } catch (SignatureException e) {
            throw new JWTVerificationException(SIGNATURE_VERIFICATION_ERROR, e);
        }

        if (username == null || username.isEmpty()) {
            throw new JWTDecodeException(MISSING_USERNAME_ERROR);
        }

        if (userId == null || userId.isEmpty()) {
            throw new JWTDecodeException(MISSING_USER_ID_ERROR);
        }

        // build pojo object to return to caller
        return new UserDataPayload(userId, username, groups);
    }

    private ArrayList<String> convertGroupsToStrings(ArrayList<?> in) {
        ArrayList<String> out = new ArrayList<>();

        if (in == null) {
            return out;
        }

        for (Object o : in) {
            if (o != null) {
                out.add(o.toString());
            }
        }
        return out;
    }
}
