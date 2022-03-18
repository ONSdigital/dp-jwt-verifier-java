package com.github.onsdigital;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Data;
import com.google.api.client.util.ExponentialBackOff;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * JWTKeyProviderImpl - Fetches JWT signing keys from a service according to the configs passed to it.
 */
public class JWTKeyProviderImpl implements JWTKeyProvider {
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
     * @throws IllegalArgumentException if the public signing keys provided are invalid
     */
    JWTKeyProviderImpl(String url, int initialInterval, int maxElapsedTime, int maxInterval) {
        identityApiUrl = url;
        this.initialInterval = initialInterval;
        this.maxElapsedTime = maxElapsedTime;
        this.maxInterval = maxInterval;
    }


    /**
     * Fetches singing keys from identity api server, returning valid signing keys on success api response.
     *
     * @return the singing keys used for decoding JWT tokens
     * @throws Exception if failed to fetch signing keys from the server
     */
    @Override
    public Map<String, String> getJwtKeys() throws Exception {
        HttpResponse response = getJwtKeysFromIdentityApi();
        if (response.getStatusCode() != HttpStatusCodes.STATUS_CODE_OK) {
            throw new Exception("Failed to get jet keys:" + response.parseAsString());
        }
        Map<String, String> jwtKeys = getJwtKeysFromResponse(response);
        if (jwtKeys.isEmpty()) {
            throw new Exception("JWT keys not found in the response");
        }
        return jwtKeys;
    }


    HttpResponse getJwtKeysFromIdentityApi() throws IOException {
        ExponentialBackOff backoff = new ExponentialBackOff.Builder()
                .setInitialIntervalMillis(initialInterval)
                .setMaxElapsedTimeMillis(maxElapsedTime)
                .setMaxIntervalMillis(maxInterval)
                .build();

        HttpRequest httpRequest = new NetHttpTransport()
                .createRequestFactory()
                .buildGetRequest(new GenericUrl(identityApiUrl))
                .setUnsuccessfulResponseHandler(new HttpBackOffUnsuccessfulResponseHandler(backoff));
        HttpResponse response = httpRequest.execute();
        return response;
    }

    private Map<String, String> getJwtKeysFromResponse(HttpResponse response) throws IOException {
        Map<String, String> signingKeys = new HashMap<>();
        try {
            response.parseAs(Data.newMapInstance(HashMap.class).getClass())
                    .forEach((key, value) -> signingKeys.put(String.valueOf(key), String.valueOf(value)));
        } finally {
            response.disconnect();
        }
        return signingKeys;
    }

}
