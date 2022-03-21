package com.github.onsdigital;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.util.Data;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * JWTKeyProviderImpl - Fetches JWT signing keys from a service according to the configs passed to it.
 */
public class JWTKeyProviderImpl implements JWTKeyProvider {
    private RequestBuilder requestBuilder;
    private String identityApiUrl;
    private int initialInterval;
    private int maxElapsedTime;
    private int maxInterval;

    /**
     * Initialises a new instance of the {@link JWTKeyProviderImpl}.
     *
     * @param url             used to fetch the signing keys
     * @param initialInterval the initial interval in milliseconds to be used for exponential retries
     * @param maxElapsedTime  the max elapsed time in milliseconds to be used for exponential retries
     * @param maxInterval     the max interval in milliseconds to be used for exponential retries
     * @param requestBuilder  the http request builder to be used to fetch the keys
     * @throws IllegalArgumentException if the public signing keys provided are invalid
     */
    JWTKeyProviderImpl(String url, int initialInterval, int maxElapsedTime, int maxInterval, RequestBuilder requestBuilder) {
        this.identityApiUrl = url;
        this.initialInterval = initialInterval;
        this.maxElapsedTime = maxElapsedTime;
        this.maxInterval = maxInterval;
        this.requestBuilder = requestBuilder;
    }


    /**
     * Fetches singing keys from identity api server, returning valid signing keys on success api response.
     *
     * @return the singing keys used for decoding JWT tokens
     * @throws Exception if failed to fetch signing keys from the server
     */
    @Override
    public Map<String, String> getJwtKeys() throws Exception {
        HttpResponse response = null;
        try {
            HttpRequest request = requestBuilder.getRequest(identityApiUrl, initialInterval, maxElapsedTime, maxInterval);
            response = request.execute();

            if (response == null) {
                throw new Exception("Failed to get response from server:" + identityApiUrl);
            }

            if (response.getStatusCode() != HttpStatusCodes.STATUS_CODE_OK) {
                throw new Exception("Failed to get jwt keys:" + response.parseAsString());
            }
            Map<String, String> jwtKeys = getJwtKeysFromResponse(response);
            if (jwtKeys.isEmpty()) {
                throw new Exception("JWT keys not found in the response");
            }
            return jwtKeys;
        } finally {
            if (response != null) {
                response.disconnect();
            }
        }
    }

    private Map<String, String> getJwtKeysFromResponse(HttpResponse response) throws IOException {
        Map<String, String> signingKeys = new HashMap<>();
        response.parseAs(Data.newMapInstance(HashMap.class).getClass())
                .forEach((key, value) -> signingKeys.put(String.valueOf(key), String.valueOf(value)));
        return signingKeys;
    }

}
