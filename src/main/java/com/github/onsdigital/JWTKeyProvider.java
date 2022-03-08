package com.github.onsdigital;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Data;
import com.google.api.client.util.ExponentialBackOff;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JWTKeyProvider {
    String identityApiUrl;
    int initialInterval, maxElapsedTime, maxInterval;

    JWTKeyProvider(String url, int initialInterval, int maxElapsedTime, int maxInterval) {
        identityApiUrl = url;
        this.initialInterval = initialInterval;
        this.maxElapsedTime = maxElapsedTime;
        this.maxInterval = maxInterval;
    }


    Map<String, String> getJwtKeys() throws Exception {
        HttpResponse response = getJwtKeysFromIdentityApi();
        if (response.getStatusCode() != 200) {
            throw new Exception("Failed to get jet keys:" + response.parseAsString());
        }
        HashMap<String, String> jwtKeys = getJwtKeysFromResponse(response);
        if(jwtKeys.isEmpty()) throw  new Exception("JWT keys not found in the response");
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

    private HashMap<String, String> getJwtKeysFromResponse(HttpResponse response) throws IOException {
        HashMap<String, String> signingKeys = new HashMap<>();
        response.parseAs(Data.newMapInstance(HashMap.class).getClass())
                .forEach((key, value) ->
                        signingKeys.put(String.valueOf(key), String.valueOf(value))
                );
        return signingKeys;
    }

}
